"""Markdown report of the Readout summary tab: findings, timeline and every recorded-data table."""

from datetime import datetime, timezone
from pathlib import Path

from interpretation import SEVERITY_ORDER, add_watchdog_columns, interpret_readout

SEVERITY_LABELS = {"issue": "ISSUE", "warning": "WARNING", "info": "INFO", "ok": "OK"}


def cell(value):
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def table(headers, rows):
    """Markdown table; rows are dicts keyed by header, or sequences in header order."""
    lines = [
        "| " + " | ".join(cell(header) for header in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        values = [row.get(header, "") for header in headers] if isinstance(row, dict) else list(row)
        values += [""] * (len(headers) - len(values))
        lines.append("| " + " | ".join(cell(value) for value in values) + " |")
    return "\n".join(lines)


def fenced(text):
    return "~~~text\n" + text.rstrip("\n") + "\n~~~"


def interpretation_markdown(findings, timeline, missing, errors):
    counts = {severity: sum(1 for item in findings if item["severity"] == severity) for severity in SEVERITY_ORDER}
    out = [
        "## Interpretation",
        "",
        f"Issues: {counts['issue']} · Warnings: {counts['warning']} · Info: {counts['info']} · OK: {counts['ok']}",
        "",
    ]
    if findings:
        out += [table(
            ["#", "Severity", "Category", "Finding"],
            [(index, SEVERITY_LABELS[item["severity"]], item["category"], item["headline"])
             for index, item in enumerate(findings, 1)],
        ), ""]
    for index, item in enumerate(findings, 1):
        out += [f"### {index}. {SEVERITY_LABELS[item['severity']]}: {item['headline']}", "", f"*{item['category']}*", ""]
        out += [f"- {detail}" for detail in item["details"]]
        if item["details"]:
            out.append("")
        if item["table"]:
            out += [table(*item["table"]), ""]
        elif item["evidence"]:
            out += [table(["Item", "Value"], item["evidence"]), ""]
        for title, headers, rows in item.get("extra_tables", []):
            out += [f"**{title}**", "", table(headers, rows), ""]
        if item["sources"]:
            out += ["Source readouts: " + " · ".join(item["sources"]), ""]
    if timeline:
        out += [
            f"### Timeline of recorded events ({len(timeline):,})", "",
            "Times are shown as stored by each source; they are UTC where the source states it.", "",
            table(["Time", "Source", "Event", "Detail"], timeline), "",
        ]
    if missing:
        out += ["Not present in this readout: " + ", ".join(missing) + ".", ""]
    out += [f"A rule could not be evaluated: {message}" for message in errors]
    if errors:
        out.append("")
    return out


def recorded_data_markdown(result, sections, notes, app_states):
    out = ["## Recorded data", ""]
    if result["standby_code"] != 0:
        out += ["The readout summary could not be built from this readout.", ""]
        if result.get("standby_error"):
            out += [fenced(result["standby_error"]), ""]
        if result.get("standby_output"):
            out += [fenced(result["standby_output"]), ""]
        return out
    if not sections:
        out += ["The readout summary did not contain any recognized tables.", ""]
    for section in sections:
        rows = section["rows"]
        suffix = (
            f" ({len(rows):,} row{'s' if len(rows) != 1 else ''})" if rows
            else (" (none)" if section["kind"] == "text" else " (0 rows)")
        )
        out += [f"### {section['heading']}{suffix}", ""]
        for description in section["description"]:
            out += [description, ""]
        if rows:
            headers, shown = section["headers"], rows
            if section["kind"] == "watchdog":
                headers, shown = add_watchdog_columns(headers, rows, app_states)
            out += [table(headers, shown), ""]
            if section["kind"] == "watchdog" and "Essential" in headers:
                out += [
                    "Essential and Restartable come from the HPx watchdog state (HPA 22 D9 45); "
                    "N/A means the application is not in that record.", "",
                ]
        elif section["kind"] != "text":
            out += ["No rows recorded.", ""]
        out += [f"- {footnote}" for footnote in section["footnotes"]]
        if section["footnotes"]:
            out.append("")
    if notes:
        out += ["### Additional notes", ""] + [f"- {note}" for note in notes] + [""]
    out += [
        "<details><summary>Raw summary output</summary>", "",
        fenced(result["standby_output"]), "", "</details>", "",
    ]
    return out


def build_summary_markdown(result, sections, notes):
    """The whole Readout summary tab as Markdown."""
    interpretation = result.get("interpretation")
    if not interpretation or "app_states" not in interpretation:
        interpretation = result["interpretation"] = interpret_readout(result["blocks"], sections)
    stem = Path(result["translated_filename"]).stem.removesuffix("_decoded")
    ecus = len({block["ecu_id"] for block in result["blocks"]})
    out = [
        "# Readout summary",
        "",
        f"- **Readout:** {stem}",
        f"- **Decoded readouts:** {len(result['blocks']):,} from {ecus} ECUs",
        f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC",
        "",
    ]
    out += interpretation_markdown(
        interpretation["findings"], interpretation["timeline"], interpretation["missing"], interpretation["errors"]
    )
    out += recorded_data_markdown(result, sections, notes, interpretation["app_states"])
    return "\n".join(out).rstrip() + "\n"
