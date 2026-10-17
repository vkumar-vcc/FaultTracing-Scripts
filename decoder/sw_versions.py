"""Software version information per ECU, read from the decoded identification readouts.

Part numbers come from the standard identification DIDs each ECU answers:

* 22 F1 2E  ECU software part numbers (one line per software module)
* 22 F1 20  application diagnostic database part number
* 22 F1 2A  ECU core assembly part number
* 22 F1 2B  ECU delivery assembly part number
* 22 F1 2C  ECU software structure part number
* 22 F1 8C  ECU serial number
* 22 F1 F0  integrated diagnostic database part number
* 22 F8 04  calibration identifications
* 22 F1 84  application software fingerprint
* 22 ED A0  complete set of part/serial numbers (fallback for the three assembly/database numbers)

ECUs are matched by name (HIA, HIB, ...), not address, so the lookup also works on platforms where the
addresses differ.
"""

import re

SW_VERSION_ECUS = ["HIA", "HIB", "HPA", "SGA", "VESA", "VESB"]

_FIELD = re.compile(r"^\s*(.+?):\s*(.*?)\s*$")
_HEX_BYTE = re.compile(r"[0-9A-Fa-f]{2}")


def split_part_number(value):
    """Split '32 48 96 51 ACP' into ('32489651', 'ACP'); values that are not part numbers are returned as they are."""
    tokens = value.split()
    if len(tokens) >= 4 and all(_HEX_BYTE.fullmatch(token) for token in tokens[:4]):
        return "".join(tokens[:4]), " ".join(tokens[4:])
    return value.strip(), ""


def format_part_number(value):
    number, edition = split_part_number(value)
    return f"{number} {edition}".strip() if number else "N/A"


def _compact(value):
    tokens = value.split()
    if tokens and all(_HEX_BYTE.fullmatch(token) for token in tokens):
        return "".join(tokens)
    return value.strip()


def _fields(content):
    fields = []
    for line in content.splitlines():
        if not line.strip() or line.startswith(("#", "Tester ->", "Complete Response")):
            continue
        match = _FIELD.match(line)
        if match:
            fields.append((match.group(1), match.group(2)))
    return fields


def _first(fields, label_part):
    for label, value in fields:
        if label_part.lower() in label.lower() and value:
            return value
    return None


def _main_software(modules):
    """The SWLM module is the main software; otherwise the first application module."""
    for module in modules:
        if "SWLM" in module["module"]:
            return module
    for module in modules:
        if "application" in module["module"].lower():
            return module
    return modules[0] if modules else None


HARDWARE_ITEMS = [
    ("core", "ECU core assembly part number"),
    ("delivery", "ECU delivery assembly part number"),
    ("serial", "ECU serial number"),
]


def shared_hardware(records):
    """Hardware identification values that every present ECU reports identically, as (key, label, value)."""
    present = [record for record in records if record["present"]]
    if len(present) < 2:
        return []
    shared = []
    for key, label in HARDWARE_ITEMS:
        values = {record[key] for record in present}
        if len(values) == 1 and values != {"N/A"}:
            shared.append((key, label, values.pop()))
    return shared


def identification_items(record, shared_keys=()):
    """Identification values of one ECU as (label, value), leaving out anything already shown elsewhere.

    Skipped: values equal to one of the ECU's software module part numbers (for example a calibration ID that
    repeats a module), and hardware values that are shown once for all ECUs.
    """
    module_parts = {module["part"] for module in record["software"]}
    items = []

    def add(label, value):
        if not value or value == "N/A":
            return
        if value.split()[0] in module_parts:
            return
        items.append((label, value))

    add("Diagnostic database part number", record["diag_db"])
    add("Integrated diagnostic database part number", record["integrated_diag_db"])
    for key, label in HARDWARE_ITEMS:
        if key not in shared_keys:
            add(label, record[key])
    add("ECU software structure part number", record["structure"])
    for name, value in record["calibration"]:
        add(f"Calibration: {name}", value)
    add("Application software fingerprint", record["fingerprint"])
    return items


def ecu_software_info(blocks, ecu_names=None):
    """One record per requested ECU with its software and identification part numbers."""
    wanted = ecu_names or SW_VERSION_ECUS
    by_ecu = {}
    for block in blocks:
        did = block["readout"].replace(" ", "").upper()
        by_ecu.setdefault(block["ecu_name"], {}).setdefault(did, block)

    records = []
    for name in wanted:
        readouts = by_ecu.get(name)
        if not readouts:
            records.append({"ecu": name, "address": "", "present": False})
            continue
        any_block = next(iter(readouts.values()))
        sources = []

        def read(did):
            block = readouts.get(did)
            if block is None:
                return None
            sources.append(f"22 {did[2:4]} {did[4:]}")
            return _fields(block["content"])

        modules = []
        for label, value in read("22F12E") or []:
            if label.lower().startswith("total number") or not value:
                continue
            number, edition = split_part_number(value)
            modules.append({"module": label, "part": number, "edition": edition})

        complete = _fields(readouts["22EDA0"]["content"]) if "22EDA0" in readouts else []

        def identification(did, label_part):
            fields = read(did)
            value = _first(fields, label_part) if fields else None
            if value is None and complete:
                value = _first(complete, label_part)
                if value is not None and "22 ED A0" not in sources:
                    sources.append("22 ED A0")
            return value

        diag_db = identification("22F120", "Diagnostic Database Part Number")
        core = identification("22F12A", "Core Assembly Part Number")
        delivery = identification("22F12B", "Delivery Assembly Part Number")
        structure_fields = read("22F12C")
        serial_fields = read("22F18C")
        integrated_fields = read("22F1F0")
        fingerprint_fields = read("22F184")
        calibration_fields = read("22F804")
        main = _main_software(modules)

        records.append({
            "ecu": name,
            "address": any_block["ecu_id"],
            "present": True,
            "software": modules,
            "main": f"{main['part']} {main['edition']}".strip() if main else "N/A",
            "diag_db": format_part_number(diag_db) if diag_db else "N/A",
            "core": format_part_number(core) if core else "N/A",
            "delivery": format_part_number(delivery) if delivery else "N/A",
            "structure": format_part_number(_first(structure_fields, "Part") or "") if structure_fields else "",
            "serial": _compact(_first(serial_fields, "Serial") or "") or "N/A" if serial_fields else "N/A",
            "integrated_diag_db": (_first(integrated_fields, "Part Number") or "") if integrated_fields else "",
            "calibration": [(label, value) for label, value in (calibration_fields or []) if value],
            "fingerprint": (_first(fingerprint_fields, "Fingerprint") or "") if fingerprint_fields else "",
            "sources": sorted(set(sources)),
        })
    return records
