"""Decoder for the HIA/HIB ECU reset log (``22 FE 04``).

A Python port of ``resetLogs_parser_script.cls`` from the Safety-B "ResetLog parser sheet" (Excel/VBA, 14/11/2025).
The DID payload holds a 48-byte *Reset Common Data* record followed by *application context logs*. All
multi-byte fields are little-endian in the payload and are shown as the hex number, like the sheet does.

The application context is one raw area that the sheet decodes six ways (protection hook, error hook, SMU alarms,
panic hook, PMIC status, MCAL report error). The log does not say which decoding applies; ``CONTEXT_FOR_REASON``
picks the one that matches the reset reason, which is an assumption and is reported as such.
"""

import re

EXPECTED_HEADER = "B4B4B4B4"
EXPECTED_MAJOR = "0001"
EXPECTED_MINOR = "0002"  # the minor version the sheet was written for
COMMON_SIZE = 48
HISTORY_SIZE = 8

VALID_HEADER = {"B4B4B4B4": "VALID FLAG", "00000000": "NOT VALID FLAG"}
APP_FBL = {"AAAAAAAA": "STAY IN FBL", "00000000": "STAY IN APP", "55555555": "UDS CLEAR REQUESTED"}
EXCEPTIONAL = {"00": "NON-EXCEPTIONAL RESET", "01": "EXCEPTIONAL RESET"}

RESET_REASONS = {
    "00": "", "10": "COLDBOOT_VCU_SHUTDOWN", "11": "COLDBOOT_WDG_HARD", "12": "COLDBOOT_WDG_FAILSAFE",
    "13": "INTRA_CORE_ERROR",
    "20": "WARMBOOT_WDG_SOFT_PORST", "21": "WARMBOOT_WDG_SOFT_PORST_WWDGTOUT",
    "22": "WARMBOOT_WDG_SOFT_PORST_INITTOUT", "23": "WARMBOOT_PORST_DEBUGGER",
    "24": "WARMBOOT_WDG_AFTER_JUMPFROMFBL", "25": "WARMBOOT_WDG_AFTER_DIAG_SHELL_RESET",
    "30": "WARMBOOT_SMU", "31": "WARMBOOT_SMU_FSP_WDG_ERRMTR", "32": "WARMBOOT_SMU_SYS_APP",
    "33": "WARMBOOT_SMU_AFTER_JUMPFROMFBL", "34": "WARMBOOT_SMU_STARTUP_TEST",
    "35": "WARMBOOT_SMU_AFTER_DIAG_SHELL_RESET",
    "40": "WARMBOOT_SYS_APP_JTAG", "50": "STARTUP_TEST_LBIST", "51": "STARTUP_TEST_TLF",
    "7F": "UNKNOWN", "A0": "WARMBOOT_SYS_APP_JUMPFROMFBL", "FF": "WARMBOOT_APP_INVALID_APP_RESET_REASON",
    "80": "INIT_CHECK_FAILED", "81": "DIAG_REQ", "82": "IFX_CONSOLE_REQ", "83": "PROTECTION_HOOK",
    "84": "ERROR_HOOK", "85": "PANIC_HOOK", "86": "SHUTDOWN_FAILED", "87": "EMERGENCY_SHUTDOWN_FAILED",
    "88": "DMA_ADDRCRC_FAILURE", "89": "HIx_MEMPROT_FAILURE", "8A": "MCAL_SAFETY_ERROR", "8B": "ESM_STM",
    "8C": "ESM_CHECKSUM", "8D": "ESM_CONVCTRL", "8E": "ESM_SRI", "8F": "ESM_ISR", "90": "ESM_CLOCK",
    "91": "ESM_ADC_PLAUSIBILITY", "92": "AURIX_UNDERTEMP_FAULT", "93": "AURIX_OVERTEMP_FAULT",
    "94": "FOH_COMM_FAILURE", "95": "SMU_UNINTENDED_INTERRUPT", "96": "TLF_VOLTAGE_ERR",
    "97": "TLFERR_HIWDGM", "98": "SAFETPACK_FAULT", "99": "HIWDGM_ENABLE_ERRMON", "9A": "HIWDGM_SET_ALARM_FAIL",
    "9B": "SIZEOF",
}

# (name, size in bytes, value meanings or None); a name of None is padding
COMMON_FIELDS = [
    ("ValidHeader", 4, VALID_HEADER),
    ("RstLoop_ModeControl", 4, APP_FBL),
    ("RstLoop_ExcResetCounter", 4, None),
    ("StructVersionMajor", 2, None),
    ("StructVersionMinor", 2, None),
    ("LastExceptionalReset", 1, RESET_REASONS),
    ("LastReset", 1, RESET_REASONS),
    (None, 2, None),
    ("ResetCounter", 4, None),
    ("ResetTimestamp", 4, None),
    ("ScuRSTSTAT", 4, None),
    ("IsExceptionalReset", 1, EXCEPTIONAL),
    ("ResetHistoryIdx", 1, None),
    *[(f"ResetHistory[{index}]", 1, RESET_REASONS) for index in range(HISTORY_SIZE)],
    ("SwReasonCode", 1, None),
    ("SwReasonCoreId", 1, None),
    (None, 4, None),
]


def _array(prefix, count, size=4):
    return [(f"{prefix}[{index}]", size, None) for index in range(count)]


CONTEXT_FIELDS = {
    "Protection hook": [
        *_array("StackTrace", 17), *_array("AddressRegisters", 16), *_array("DataRegisters", 16),
        *[(name, 4, None) for name in (
            "Ra", "Psw", "ExceptionSource", "Pcpn", "Pie", "MpuRegionForStackLow", "MpuRegionForStackUpper", "RawPCXI",
        )],
        ("FatalError", 1, None), (None, 3, None), ("deadd_reg", 4, None),
    ],
    "Error hook": [*_array("StackTrace", 17), ("Service", 1, None), ("Error", 1, None), ("DetailedError", 2, None)],
    "SMU alarms": [(f"AD{index}", 4, None) for index in range(12)],
    "Panic hook": [*_array("StackTrace", 17), ("status", 1, None)],
    "PMIC status": [
        *[(name, 1, None) for name in (
            "TlfReadStatus", "RegSysfail", "RegIniterr", "RegIf", "RegSyssf", "RegWksf", "RegSpisf", "RegMonsf0",
            "RegMonsf1", "RegMonsf2", "RegMonsf3", "RegOtfail", "RegOtwrnsf", "RegDevstat", "RegVmonstat",
        )],
        (None, 1, None), ("RegId", 1, None), ("ExpectedValue", 1, None),
    ],
    "MCAL report error": [*_array("StackTrace", 17), ("ModuleId", 2, None), ("ApiId", 1, None), ("ErrorId", 1, None)],
}

# Assumption: the context decoding that matches the reset reason (not stored in the log itself).
CONTEXT_FOR_REASON = {
    "83": "Protection hook",
    "84": "Error hook",
    "85": "Panic hook",
    "8A": "MCAL report error",
    "30": "SMU alarms", "31": "SMU alarms", "32": "SMU alarms", "33": "SMU alarms", "34": "SMU alarms",
    "35": "SMU alarms", "95": "SMU alarms",
    "51": "PMIC status", "96": "PMIC status", "97": "PMIC status",
}

_HEX_BYTES = re.compile(r"^\s*(?:[0-9A-Fa-f]{2}\s*)+$")


def payload_from_readout(content):
    """Payload bytes (without ``62 FE 04``) of a translated 22 FE 04 readout, or None."""
    if not content:
        return None
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("Trace:"):
            parts = [line.split(":", 1)[1]]
            for follower in lines[index + 1:]:
                if not _HEX_BYTES.match(follower):
                    break
                parts.append(follower)
            digits = re.sub(r"\s+", "", "".join(parts))
            if digits and len(digits) % 2 == 0:
                return bytes.fromhex(digits)
    match = re.search(r"Complete Response:\s*[0-9A-Fa-f]{4}\s+62FE04((?:[0-9A-Fa-f]|\s)+)", content)
    if match:
        digits = re.sub(r"\s+", "", match.group(1))
        if len(digits) % 2 == 0:
            return bytes.fromhex(digits)
    return None


def _walk(data, fields, start=0):
    """[(name, size, hex value, meaning)] for the fields; missing bytes read as 00 like the sheet."""
    rows = []
    position = start
    for name, size, meanings in fields:
        chunk = bytes(data[position:position + size]).ljust(size, b"\x00")
        position += size
        if name is None:
            continue
        value = chunk[::-1].hex().upper()
        meaning = ""
        if meanings is not None:
            meaning = meanings.get(value, "unknown")
        rows.append((name, size, value, meaning))
    return rows


def parse_reset_log(payload):
    """Decode a reset log payload into the common record, the history and the application context views."""
    common = _walk(payload, COMMON_FIELDS)
    values = {name: (value, meaning) for name, _, value, meaning in common}
    index_text = values["ResetHistoryIdx"][0]
    history_index = int(index_text, 16)
    history = [
        {"index": index, "code": values[f"ResetHistory[{index}]"][0], "reason": values[f"ResetHistory[{index}]"][1],
         "current": index == history_index}
        for index in range(HISTORY_SIZE)
    ]
    context = {
        title: _walk(payload, fields, COMMON_SIZE) for title, fields in CONTEXT_FIELDS.items()
    }
    return {
        "common": common,
        "values": values,
        "history": history,
        "history_index": history_index,
        "context": context,
        "length": len(payload),
        "context_bytes": bytes(payload[COMMON_SIZE:]),
    }


def validation_notes(parsed):
    """Problems the sheet reports as message boxes: header, major version, minor version, size."""
    values = parsed["values"]
    notes = []
    if values["ValidHeader"][0] != EXPECTED_HEADER:
        notes.append(f"Reset log header is {values['ValidHeader'][0]}, not {EXPECTED_HEADER}: the log is not valid.")
    major, minor = values["StructVersionMajor"][0], values["StructVersionMinor"][0]
    if major != EXPECTED_MAJOR:
        notes.append(
            f"Structure version is {major}.{minor}, newer than the {EXPECTED_MAJOR}.{EXPECTED_MINOR} the parser sheet "
            "was written for. The common record is decoded as in the sheet (its reset counter can be checked against "
            "22 FE 02), but the application context layout is not verified for this version."
        )
    elif minor != EXPECTED_MINOR:
        notes.append(
            f"Structure version is {major}.{minor}; the parser sheet expects {EXPECTED_MAJOR}.{EXPECTED_MINOR}. "
            "Field layout beyond that version may differ."
        )
    if parsed["length"] < COMMON_SIZE:
        notes.append(f"Only {parsed['length']} bytes were read; the common record needs {COMMON_SIZE}.")
    return notes


def context_view(parsed):
    """(title, rows) of the application context that matches the reset reason, or None."""
    values = parsed["values"]
    for field in ("SwReasonCode", "LastReset"):
        title = CONTEXT_FOR_REASON.get(values[field][0])
        if title:
            return title, parsed["context"][title], field
    return None
