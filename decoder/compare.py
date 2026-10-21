"""Compare two decoded readouts of the same vehicle, node by node.

Readouts are matched by ECU and request (for example ``1D0D`` + ``22FE02``); inside a matched readout the decoded
``Label: value`` fields are compared. Multi-line values are joined, and repeated labels get a numeric suffix, so the
same field always lines up with itself.
"""

import re
from collections import Counter, OrderedDict
from datetime import datetime

from summary_report import table

_FIELD = re.compile(r"^\s*(.+?):\s*(.*?)\s*$")
_STAMP = re.compile(r"(\d{8}T\d{6})")
_NUMBER = re.compile(r"^(-?\d+(?:\.\d+)?)\s*([A-Za-z%/ ]*?)\s*$")
MISSING = "(not present)"

# Vehicle context that is stored next to many readouts and differs in every one; the UI can hide it.
VOLATILE_FIELDS = frozenset({
    "Global Real Time", "Total Distance", "Used by AS", "Vehicle Battery Voltage", "Outside temperature",
    "Vehicle Speed",
})


def readout_stamp(name):
    """Capture time encoded in a readout file name such as 20261016T103755_..., or None."""
    found = _STAMP.search(name or "")
    if not found:
        return None
    try:
        return datetime.strptime(found.group(1), "%Y%m%dT%H%M%S")
    except ValueError:
        return None


def parse_block_fields(content):
    """{label: value} of a decoded readout block; the raw response and request lines are left out."""
    fields = OrderedDict()
    seen = Counter()
    current = None
    for raw in content.splitlines():
        stripped = raw.strip()
        if not stripped:
            current = None
            continue
        if raw.startswith(("#", "Tester ->")) or stripped.startswith("Complete Response"):
            current = None
            continue
        match = _FIELD.match(raw)
        if match:
            label = match.group(1)
            seen[label] += 1
            if seen[label] > 1:
                label = f"{label} ({seen[label]})"
            fields[label] = match.group(2)
            current = label
        elif current is not None:
            fields[current] = f"{fields[current]} {stripped}".strip()
    return fields


def _readout_key(block):
    return block["ecu_id"], block["readout"].replace(" ", "").upper()


def _index(blocks, ecu_ids):
    """{(ecu id, request, occurrence): block} for the selected ECUs."""
    counts = Counter()
    indexed = OrderedDict()
    for block in sorted(blocks, key=lambda item: item["row_id"]):
        if block["ecu_id"] not in ecu_ids:
            continue
        key = _readout_key(block)
        counts[key] += 1
        indexed[(*key, counts[key])] = block
    return indexed


def change_text(older, newer):
    if older == MISSING:
        return "added"
    if newer == MISSING:
        return "removed"
    before, after = _NUMBER.match(older), _NUMBER.match(newer)
    if before and after and before.group(2) == after.group(2):
        delta = float(after.group(1)) - float(before.group(1))
        unit = f" {before.group(2)}" if before.group(2) else ""
        number = f"{int(delta):+d}" if delta == int(delta) else f"{delta:+.6g}"
        return f"{number}{unit}"
    return "changed"


def compare_blocks(older_blocks, newer_blocks, ecu_ids, ignore_fields=frozenset()):
    """Per ECU: counts, readouts present on one side only, and the changed fields (minus ``ignore_fields``)."""
    older = _index(older_blocks, ecu_ids)
    newer = _index(newer_blocks, ecu_ids)
    results = OrderedDict()

    def entry(block):
        return results.setdefault(block["ecu_id"], {
            "ecu_id": block["ecu_id"], "ecu_name": block["ecu_name"], "compared": 0, "unchanged": 0,
            "changed": 0, "fields": 0, "only_older": [], "only_newer": [], "rows": [],
            "changed_readouts": [], "unchanged_readouts": [],
        })

    for key in sorted(set(older) | set(newer), key=lambda item: (item[0], (newer.get(item) or older[item])["row_id"])):
        old_block, new_block = older.get(key), newer.get(key)
        block = new_block or old_block
        record = entry(block)
        label = f"{block['readout']}" + (f" | {block['description']}" if block["description"] != block["readout"] else "")
        if old_block is None:
            record["only_newer"].append(label)
            continue
        if new_block is None:
            record["only_older"].append(label)
            continue
        record["compared"] += 1
        old_fields, new_fields = parse_block_fields(old_block["content"]), parse_block_fields(new_block["content"])
        rows = []
        for field in [*old_fields, *[name for name in new_fields if name not in old_fields]]:
            if field in ignore_fields or re.sub(r" \(\d+\)$", "", field) in ignore_fields:
                continue
            before, after = old_fields.get(field, MISSING), new_fields.get(field, MISSING)
            if before != after:
                rows.append((label, field, before, after, change_text(before, after)))
        if rows:
            record["changed"] += 1
            record["fields"] += len(rows)
            record["rows"].extend(rows)
            record["changed_readouts"].append((label, len(rows)))
        else:
            record["unchanged"] += 1
            record["unchanged_readouts"].append(label)
    return list(results.values())


SUMMARY_HEADERS = ["Node", "Readouts compared", "Changed", "Unchanged", "Fields changed", "Only in older", "Only in newer"]


def summary_rows(results):
    return [
        {
            "Node": f"{item['ecu_name']} | {item['ecu_id']}",
            "Readouts compared": item["compared"],
            "Changed": item["changed"],
            "Unchanged": item["unchanged"],
            "Fields changed": item["fields"],
            "Only in older": len(item["only_older"]),
            "Only in newer": len(item["only_newer"]),
        }
        for item in results
    ]


ROW_HEADERS = ["Readout", "Field", "Older", "Newer", "Change"]
MARKDOWN_CELL_LIMIT = 300


def group_changed_rows(rows):
    """Group changed fields by readout label, preserving their original order."""
    grouped = {}
    for readout, *fields in rows:
        grouped.setdefault(readout, []).append(fields)
    return grouped


def comparison_markdown(older_name, newer_name, results, hidden_fields=()):
    """Markdown of the comparison. Per node: an index of changed readouts first, then the changed fields."""
    out = [
        "# Readout comparison", "",
        f"- **Older:** {older_name}", f"- **Newer:** {newer_name}",
        "- Capture times are the ones in the file names.",
        "- Long values are cut at "
        f"{MARKDOWN_CELL_LIMIT} characters here; the Compare readouts tab shows them in full.",
        "- Tables that act as ring buffers (error slots, shutdown records, histories) shift when a new entry is "
        "recorded, so slot-by-slot rows can show a change although the entry only moved.",
    ]
    if hidden_fields:
        out.append("- Hidden fields: " + ", ".join(sorted(hidden_fields)) + ".")
    out += ["", "## Summary", "", table(SUMMARY_HEADERS, summary_rows(results)), ""]
    for item in results:
        out += [f"## {item['ecu_name']} | {item['ecu_id']}", ""]
        if item["changed_readouts"]:
            out += [
                "### Changed readouts", "",
                table(["Readout", "Fields changed"], item["changed_readouts"]), "",
            ]
        if item["rows"]:
            out += ["### Changed fields", ""]
            for readout, rows in group_changed_rows(item["rows"]).items():
                out += [
                    f"#### {readout} ({len(rows):,} fields changed)", "",
                    table(ROW_HEADERS[1:], rows, MARKDOWN_CELL_LIMIT), "",
                ]
        else:
            out += ["No field changed in the readouts present in both.", ""]
        if item["only_older"]:
            out += ["### Only in the older readout", "", "; ".join(item["only_older"]), ""]
        if item["only_newer"]:
            out += ["### Only in the newer readout", "", "; ".join(item["only_newer"]), ""]
        if item["unchanged_readouts"]:
            out += [
                f"### Unchanged readouts ({len(item['unchanged_readouts'])}, present in both)", "",
                "; ".join(item["unchanged_readouts"]), "",
            ]
    return "\n".join(out).rstrip() + "\n"
