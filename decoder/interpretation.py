"""Rule-based interpretation of a decoded vehicle readout.

The rules encode how the platform nodes relate to each other (see
.github/skills/decoder-summary-interpretation/SKILL.md):

* HPA is the high-performance QNX environment and is controlled by HIA.
* Hardware errors on HPA are reported to HIA as FSI errors; HIA then resets HPA.
* HPA can sleep or enter standby (SC7). When that fails, the reasons are stored in
  HIA and HPA is cold booted instead of resumed.
* HPA can fail during run when an essential application exceeds its restart limit,
  which makes HIA reset it.
* HIA stores the reset reasons of HPA, and a failure or reset of HIA can restart HPA.
* LPA stores standby failure/success history for the VCU nodes. An HPA standby failure
  does not show there, because HIA powers off anyway; LPA counts are meaningful for the
  other nodes (SGA, HIA, HIB).
* HIA and HIB can reset on their own and keep an error log (22 FE 04, decoded by ``reset_log.py``).

Every rule is a function ``rule_*(context)`` returning findings. Add a new rule by writing
one and listing it in ``RULES``; a rule that lacks its data returns nothing.
"""

import re
from collections import Counter
from datetime import datetime, timedelta, timezone

import reset_log

ECU_IDS = {"HIA": "1D0D", "HIB": "1D0E", "HPA": "1D12", "LPA": "1D1A"}

SEVERITY_ORDER = {"issue": 0, "warning": 1, "info": 2, "ok": 3}
CATEGORY_ORDER = [
    "HPA state",
    "HPA standby and resume",
    "HP restarts requested by HIA",
    "HPA runtime",
    "FSI errors reported to HIA",
    "HIA and HIB resets",
    "LPA node history",
]

_FIELD = re.compile(r"^\s*(.+?):\s*(.*?)\s*$")
_ISO = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d")


def finding(category, severity, headline, details=None, evidence=None, table=None, sources=None, extra_tables=None):
    return {
        "category": category,
        "severity": severity,
        "headline": headline,
        "details": details or [],
        "evidence": evidence or [],
        "table": table,
        "extra_tables": extra_tables or [],
        "sources": sources or [],
    }


def source_readout_blocks(blocks, source):
    """Resolve a finding's source label, including grouped requests such as 19 03 / 19 04."""
    ecu, _, requests = source.partition(" ")
    ecu_id = ECU_IDS.get(ecu)
    readouts = {re.sub(r"\s+", "", request).upper() for request in requests.split("/")}
    return [
        block for block in blocks
        if block["ecu_id"] == ecu_id
        and re.sub(r"\s+", "", block["readout"]).upper() in readouts
    ]


def to_int(value):
    """Leading number of a decoded value such as '3', '1 True' or '19 Seconds'; None if unreliable."""
    if value is None or "not reliable" in value.lower():
        return None
    match = re.match(r"\s*(-?\d+(?:\.\d+)?)", value)
    return int(float(match.group(1))) if match else None


def is_true(value):
    if value is None:
        return False
    lowered = value.lower()
    if "true" in lowered:
        return True
    if "false" in lowered:
        return False
    return (to_int(value) or 0) > 0


def parse_fields(content):
    fields = []
    for line in content.splitlines():
        if not line.strip() or line.startswith(("#", "Tester ->", "Complete Response")):
            continue
        match = _FIELD.match(line)
        if match:
            fields.append((match.group(1), match.group(2)))
    return fields


class Context:
    """Read access to the decoded readouts and the parsed summary tables."""

    def __init__(self, blocks, sections):
        self.sections = sections
        self.blocks = {}
        wanted = set(ECU_IDS.values())
        for block in blocks:
            if block["ecu_id"] not in wanted:
                continue
            key = (block["ecu_id"], block["readout"].replace(" ", "").upper())
            self.blocks.setdefault(key, block["content"])
        self.used = {}

    def raw(self, ecu, readout):
        content = self.blocks.get((ECU_IDS[ecu], readout.upper()))
        self.used[f"{ecu} {readout}"] = content is not None
        return content

    def fields(self, ecu, readout):
        content = self.raw(ecu, readout)
        return parse_fields(content) if content is not None else None

    def values(self, ecu, readout):
        fields = self.fields(ecu, readout)
        if fields is None:
            return None
        values = {}
        for label, value in fields:
            values.setdefault(label, value)
        return values

    def rows(self, kind, heading_prefix=None):
        rows = []
        for section in self.sections:
            if section["kind"] != kind:
                continue
            if heading_prefix and not section["heading"].upper().startswith(heading_prefix):
                continue
            rows.extend(section["rows"])
        return rows


def source_label(ecu, readout):
    return f"{ecu} {readout[:2]} {readout[2:4]} {readout[4:]}"


# --------------------------------------------------------------------- state now
def rule_current_state(context):
    state = context.values("HPA", "22D99B")
    requested = context.values("HIA", "22FE49")
    bootchain = context.values("HPA", "22EF58")
    crash = context.values("HPA", "22D132")
    if not any([state, requested, bootchain, crash]):
        return []
    evidence = []
    if state:
        evidence.append(("HPA platform state", state.get("Platform state", "N/A")))
    if requested:
        evidence.append(("State requested by HIA", requested.get("Platform State Request", "N/A")))
        evidence.append(("Request reason", requested.get("Request Reason", "N/A")))
    if bootchain:
        evidence.append(("Active boot chain", bootchain.get("Active bootchain read", "N/A")))
    crashed = crash and is_true(crash.get("CrashMode"))
    if crash:
        evidence.append(("Crash mode", crash.get("CrashMode", "N/A")))
    severity = "issue" if crashed else "info"
    headline = "HPA reports crash mode" if crashed else "HPA platform state at readout time"
    return [finding(
        "HPA state", severity, headline,
        details=["Crash mode is set, so HPA is in a crash/failure handling state."] if crashed else [],
        evidence=evidence,
        sources=[source_label("HPA", "22D99B"), source_label("HIA", "22FE49"),
                 source_label("HPA", "22EF58"), source_label("HPA", "22D132")],
    )]


# ------------------------------------------------------------- standby and resume
def rule_standby_records(context):
    rows = context.rows("events")
    if not rows:
        return []
    failed = [row for row in rows if row.get("Success", "").lower() == "no"]
    blockers = Counter(
        name.strip()
        for row in rows
        for name in row.get("Active ECUs", "").split(",")
        if name.strip() and name.strip() != "None"
    )
    times = [row.get("UTC Time", "") for row in rows if row.get("UTC Time")]
    details = [f"{len(rows)} standby records" + (f", from {min(times)} to {max(times)}." if times else ".")]
    types = Counter(row.get("Shutdown Type") or "unknown" for row in rows)
    intents = Counter(row.get("VCU Intent") or "unknown" for row in rows)
    details.append(
        "Shutdown types: " + ", ".join(f"{name} {count}x" for name, count in types.most_common())
        + ". Requested by the vehicle: " + ", ".join(f"{name} {count}x" for name, count in intents.most_common()) + "."
    )
    if blockers:
        details.append(
            "ECUs still active or requested when shutdown was forced: "
            + ", ".join(f"{name} ({count}x)" for name, count in blockers.most_common(5))
            + "."
        )
    if failed:
        details.append(
            "HPA did not complete these standby cycles: "
            + ", ".join(f"#{row['#']} ({row.get('UTC Time', 'N/A')})" for row in failed[:8])
            + ". When standby fails the reason is stored in HIA and HPA is cold booted instead of resumed."
        )
    restarts = [row for row in rows if (row.get("Shutdown Type") or "").lower() not in {"standby", "sleep", ""}]
    if restarts:
        details.append(
            "Not a standby or sleep: "
            + ", ".join(f"#{row['#']} {row.get('Shutdown Type')} ({row.get('UTC Time', 'N/A')})" for row in restarts[:8])
            + "."
        )
    return [finding(
        "HPA standby and resume",
        "issue" if failed else "ok",
        f"{len(failed)} of {len(rows)} recorded standby cycles were unsuccessful"
        if failed else f"All {len(rows)} recorded standby cycles were successful",
        details=details,
        sources=[source_label("HPA", "224721")],
    )]


def rule_shutdown_failures(context):
    values = context.values("HIA", "22FE14")
    if not values:
        return []
    counters = {label: to_int(value) for label, value in values.items() if "Counter" in label}
    unreliable = [label.replace(" Shutdown Failure Counter", "") for label, value in counters.items() if value is None]
    reliable = {label: value for label, value in counters.items() if value is not None}
    failing = {label: value for label, value in reliable.items() if value > 0}
    hpa_failing = {label: value for label, value in failing.items() if label.startswith("HPA")}
    details = []
    if hpa_failing:
        details.append(
            "HIA counted HPA standby/shutdown failures. The failure reasons are stored in HIA, "
            "and after a failed standby HPA gets a cold boot instead of a resume."
        )
    if unreliable:
        details.append("Not reliable (not populated): " + ", ".join(unreliable) + ".")
    severity = "issue" if hpa_failing else "warning" if failing else "ok"
    headline = (
        "HIA recorded HPA standby failures: "
        + ", ".join(f"{label.replace(' Counter', '')} = {value}" for label, value in hpa_failing.items())
        if hpa_failing else
        "HIA recorded shutdown failures on other nodes" if failing else
        "HIA shutdown failure counters are all zero"
    )
    return [finding(
        "HPA standby and resume", severity, headline, details=details,
        evidence=[(label, str(value)) for label, value in reliable.items()],
        sources=[source_label("HIA", "22FE14")],
    )]


def histogram_finding(context, ecu, readout, noun, severity_when_retry="warning"):
    values = context.values(ecu, readout)
    if not values:
        return []
    counts = {label: to_int(value) for label, value in values.items() if "Counter" in label}
    first = next((v for k, v in counts.items() if "1st try" in k), None)
    retried = sum(v or 0 for k, v in counts.items() if "2nd try" in k or "3rd try" in k)
    failed = next((v for k, v in counts.items() if "Not Succeeded" in k), None) or 0
    if first is None:
        return []
    total = (first or 0) + retried + failed
    if failed:
        severity, headline = "issue", f"HPA {noun} failed {failed} time(s)"
    elif retried:
        severity, headline = severity_when_retry, f"HPA {noun} needed a retry {retried} time(s) (none failed)"
    else:
        severity, headline = "ok", f"Every HPA {noun} succeeded on the first try"
    details = []
    if failed:
        details.append("A failed attempt makes HIA reset HPA; the reason is recorded in HIA.")
    if retried and total:
        details.append(f"{retried} of {total} attempts ({retried / total:.2%}) required more than one try.")
    return [finding(
        "HPA standby and resume", severity, headline, details=details,
        evidence=[(label, str(value)) for label, value in counts.items()],
        sources=[source_label(ecu, readout)],
    )]


def rule_wakeup_histogram(context):
    return histogram_finding(context, "HIA", "22FE18", "wake-up")


def rule_powerup_histogram(context):
    findings = histogram_finding(context, "HIA", "22FE17", "power-up")
    wakeups = context.values("HIA", "22FE18") or {}
    powerups = context.values("HIA", "22FE17") or {}
    first_power = to_int(powerups.get("HPA Power-up Succeeded 1st try Counter"))
    first_wake = to_int(wakeups.get("HPA Wakeup Succeeded 1st try Counter"))
    if findings and first_power and first_wake and first_power > 100 * first_wake:
        findings[0]["details"].append(
            f"The first-try power-up counter ({first_power:,}) is far larger than the wake-up counter "
            f"({first_wake:,}); treat this counter with caution, its decoding may be off."
        )
    return findings


# ------------------------------------------------------- HP restarts requested by HIA
RESTART_GROUPS = [
    ("Startup failure", "HP did not reach the expected state during startup, resume or cold boot"),
    ("Thermal", "Thermal mitigation: HPx too hot"),
    ("Safety supervision", "Safety supervision mitigation"),
    ("Failure operation", "Failure operation entered from the run state"),
    ("Heartbeat", "Heartbeat failure mitigation"),
    ("Power mitigation", "Power mitigation: rail, sequencer or board power domain"),
]


def exceptional_restart_time(context):
    """ISO timestamp stored in the HIA 'Reason for exceptional restart' record, if any."""
    raw = context.raw("HIA", "22FE4D") or ""
    response = re.search(r"Complete Response:\s*\w+\s+([0-9A-Fa-f ]+)", raw)
    if not response:
        return None
    try:
        text = bytes.fromhex(response.group(1).replace(" ", "")).decode("latin-1")
    except ValueError:
        return None
    found = _ISO.search(text)
    return found.group(0) if found else None


def rule_exceptional_restart(context):
    values = context.values("HIA", "22FE4D")
    if not values:
        return []
    recorded = exceptional_restart_time(context)
    active = [
        label for label, value in values.items()
        if "counter" not in label.lower() and "RESERVED" not in label and is_true(value)
    ]
    counter = to_int(values.get("HP Exceptional reset counter"))
    histogram = context.values("HIA", "22FE4E") or {}
    histogram_counts = {label: to_int(value) for label, value in histogram.items()}
    histogram_nonzero = {label: value for label, value in histogram_counts.items() if value}
    if not active and not histogram_nonzero:
        return [finding(
            "HP restarts requested by HIA", "ok", "No exceptional HP restart reason is recorded in HIA",
            sources=[source_label("HIA", "22FE4D"), source_label("HIA", "22FE4E")],
        )]
    details = [
        "HIA stores the reasons for every HP reset it triggers (HIA controls HPA), "
        "so these flags describe why HIA last restarted HP."
    ]
    if recorded:
        details.append(f"Recorded at {recorded} (as stored; the ECU does not state a timezone).")
    if counter is not None and counter > 0 and counter % (1 << 24) == 0:
        details.append(
            f"The exceptional reset counter reads {counter}; that is 0x{counter:08X}, "
            f"so the field is probably little-endian and means {counter >> 24}."
        )
    for prefix, meaning in RESTART_GROUPS:
        matching = [label for label in active if label.startswith(prefix)]
        if matching:
            reasons = [label.split(" - ", 1)[1] for label in matching if " - " in label]
            details.append(meaning + (": " + "; ".join(reasons) if reasons else "."))
    if any("Run state from standby" in label for label in active):
        details.append("Resume from standby did not reach Run in time, which leads to a cold boot.")
    if any("cold boot" in label for label in active):
        details.append("A cold boot did not reach Run or Failure within the allowed time.")
    evidence = [(label, "True") for label in active]
    evidence += [(f"Histogram: {label}", str(value)) for label, value in histogram_nonzero.items()]
    return [finding(
        "HP restarts requested by HIA", "issue",
        f"HIA restarted HP for {len(active)} recorded reason(s)" if active else "HIA histogram shows HP restart reasons",
        details=details, evidence=evidence,
        sources=[source_label("HIA", "22FE4D"), source_label("HIA", "22FE4E")],
    )]


def rule_cross_checks(context):
    """Relate lifetime counters to the recorded standby cycles and to FSI errors."""
    notes = []
    rows = context.rows("events")
    failed = [row for row in rows if row.get("Success", "").lower() == "no"]
    times = sorted(filter(None, (_normalize_time(row.get("UTC Time", "")) for row in rows)))
    counters = context.values("HIA", "22FE14") or {}
    transition_failures = sum(
        to_int(counters.get(label)) or 0
        for label in ("HPA Standby Transition Failure Counter", "HPA Standby HW Signal Failure Counter")
    )
    if rows and not failed and transition_failures:
        notes.append(
            f"HIA counts {transition_failures} HPA standby failure(s) over its lifetime, yet all {len(rows)} recorded "
            "standby cycles succeeded, so those failures are not among the recorded cycles (older, or not flagged in the records)."
        )
    lpa = context.values("LPA", "22FE17") or {}
    lpa_requests = to_int(lpa.get("Shutdown Request counter"))
    lpa_done = to_int(lpa.get("Successful Shutdown counter"))
    if transition_failures and lpa_requests is not None and lpa_requests == lpa_done:
        notes.append(
            f"LPA shows no failed shutdowns although HIA counts {transition_failures} HPA standby failure(s). That is "
            "expected: when HPA fails in standby, HIA powers off anyway, so LPA's counts stay clean for HPA and are "
            "only meaningful for the other nodes."
        )
    restart = exceptional_restart_time(context)
    if restart and times:
        notes.append(
            f"HIA restarted HP at {restart}, {'before' if restart < times[0] else 'within or after'} the recorded "
            f"standby cycles ({times[0]} to {times[-1]})."
        )
    quiet_states = re.compile(r"standby|resume|power off", re.I)
    around_standby = [
        row for row in context.rows("fe03_slots") if quiet_states.search(row.get("HP Operation State", ""))
    ]
    if around_standby:
        notes.append(
            f"{len(around_standby)} FSI error(s) were logged while HP was in Standby, Resume or Power Off, "
            "which is relevant to failed standby or resume."
        )
    if not notes:
        return []
    return [finding(
        "HPA standby and resume", "info", "Reading the standby evidence together", details=notes,
        sources=[source_label("HIA", "22FE14"), source_label("HIA", "22FE4D"), source_label("HPA", "224721")],
    )]


# ----------------------------------------------------------------------- HPA runtime
def watchdog_state_rows(raw):
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("System and software state:"):
            line = line.split(":", 1)[1].strip()
        parts = line.split(",")
        if len(parts) >= 7 and _ISO.fullmatch(parts[1]):
            rows.append({
                "application": parts[0], "time": parts[1], "event": parts[2],
                "criticality": parts[3], "restartable": parts[4],
                "abandoned": parts[5], "restarts": to_int(parts[6]) or 0,
                "state": parts[9] if len(parts) > 9 else "",
            })
    return rows


WATCHDOG_EXTRA_HEADERS = ["Essential", "Restartable"]


def application_states(context):
    """Per-application watchdog facts from HPA 22 D9 45: essential and restartable."""
    raw = context.raw("HPA", "22D945")
    if not raw:
        return {}
    states = {}
    for row in sorted(watchdog_state_rows(raw), key=lambda item: item["time"]):
        state = states.setdefault(row["application"], {
            "failures": 0, "essential": False, "restartable": False, "abandoned": False,
        })
        state["failures"] += 1
        state["essential"] = state["essential"] or row["criticality"] == "Essential"
        state["restartable"] = row["restartable"] == "Restartable"
        state["abandoned"] = row["abandoned"] == "Abandoned"
    return states


def watchdog_state_cells(state):
    if state is None:
        return ["N/A"] * len(WATCHDOG_EXTRA_HEADERS)
    return [
        "Yes" if state["essential"] else "No",
        "Yes" if state["restartable"] else "No",
    ]


def add_watchdog_columns(headers, rows, states):
    """Append Essential and Restartable to a table that has an Application column."""
    if "Application" not in headers or any(header in headers for header in WATCHDOG_EXTRA_HEADERS):
        return headers, rows
    enriched = []
    for row in rows:
        extra = dict(zip(WATCHDOG_EXTRA_HEADERS, watchdog_state_cells(states.get(row.get("Application")))))
        enriched.append({**row, **extra})
    return [*headers, *WATCHDOG_EXTRA_HEADERS], enriched


def rule_application_watchdog(context):
    raw = context.raw("HPA", "22D945")
    findings = []
    sources = [source_label("HPA", "22D945"), source_label("HPA", "22D99C"), source_label("HPA", "22EF82")]
    if raw:
        rows = watchdog_state_rows(raw)
        states = application_states(context)
        health = re.search(r"Data Health:\s*(.*)", raw)
        essential = [row for row in rows if row["criticality"] == "Essential"]
        essential_abandoned = [row for row in essential if row["abandoned"] == "Abandoned"]
        abandoned_apps = sorted({row["application"] for row in rows if row["abandoned"] == "Abandoned" and row["criticality"] != "Essential"})
        events = Counter(row["event"] for row in rows)
        details = []
        if essential:
            details.append(
                f"{len(essential)} failure record(s) belong to essential applications; "
                "an essential application that fails more often than its restart limit makes HIA reset HPA."
            )
        elif rows:
            details.append(
                "No essential application failed. Non-essential applications are restarted up to their "
                "limit and then abandoned; this does not by itself reset HPA."
            )
        if events:
            details.append("Failure types: " + ", ".join(f"{name} {count}x" for name, count in events.most_common()) + ".")
        if abandoned_apps:
            shown = ", ".join(abandoned_apps[:8]) + (f" and {len(abandoned_apps) - 8} more" if len(abandoned_apps) > 8 else "")
            details.append(f"Non-essential applications abandoned after failing: {shown}.")
        if health:
            details.append(f"Data health: {health.group(1).strip()} (the history may not be complete).")
        times = [row["time"] for row in rows if not row["time"].startswith("1970")]
        if times:
            details.append(f"Records span {min(times)} to {max(times)} (as recorded).")
        if essential_abandoned:
            severity = "issue"
            headline = (
                "Essential application(s) abandoned after exceeding the restart limit: "
                + ", ".join(sorted({row['application'] for row in essential_abandoned}))
            )
        elif essential:
            severity, headline = "warning", f"{len(essential)} essential application failure(s) recorded"
        elif rows:
            severity = "warning"
            headline = f"{len(rows)} non-essential application failures, {len(abandoned_apps)} application(s) abandoned"
        else:
            severity, headline = "ok", "No application failures recorded in the watchdog state"
        table = None
        if states:
            table = (
                ["Application", "Failures in state record", *WATCHDOG_EXTRA_HEADERS],
                [
                    [application, str(state["failures"]), *watchdog_state_cells(state)]
                    for application, state in sorted(states.items(), key=lambda item: (-item[1]["failures"], item[0]))
                ],
            )
        findings.append(finding(
            "HPA runtime", severity, headline, details=details, table=table,
            sources=sources,
        ))
    record = context.values("HPA", "22EF82")
    if record:
        application = record.get("Application Name", "N/A")
        reason = record.get("Executable Failure Reason", "N/A")
        if "No Application Crash" not in application:
            findings.append(finding(
                "HPA runtime", "warning", f"Latest watchdog failure record: {application}",
                details=[f"Executable failure reason: {reason}."],
                sources=[source_label("HPA", "22EF82")],
            ))
    return findings


# ---------------------------------------------------------------------- FSI errors
def error_origin(reference):
    prefix = (reference or "").split("_", 1)[0].strip().upper()
    return prefix if prefix in {"HW", "SW"} else "Unknown"


def rule_fsi_errors(context):
    slots = context.rows("fe03_slots")
    if context.raw("HIA", "22FE03") is None and not slots:
        return []
    if not slots:
        return [finding(
            "FSI errors reported to HIA", "ok", "No FSI errors are recorded in HIA",
            sources=[source_label("HIA", "22FE03")],
        )]
    details_by_slot = {row.get("Slot"): row for row in context.rows("fe03_details")}
    enriched = []
    for row in slots:
        detail = details_by_slot.get(row.get("Slot"), {})
        reference = detail.get("Reference", "")
        action = detail.get("HI Action", "")
        enriched.append({
            "slot": row.get("Slot", ""),
            "time": row.get("Time", ""),
            "state": row.get("HP Operation State", ""),
            "name": row.get("Error Name") or detail.get("Description", ""),
            "origin": error_origin(reference),
            "reset": bool(re.search(r"reset|reboot", action, re.I)),
            "soc": is_true(row.get("SOC_ERROR", "")),
        })
    origin = Counter(item["origin"] for item in enriched)
    resets = [item for item in enriched if item["reset"]]
    states = Counter((item["state"] if item["state"].strip() not in {"", "0"} else "0 (not recorded)") for item in enriched)
    names = Counter(item["name"] for item in enriched if item["name"])
    details = [
        "A hardware error on HPA is reported to HIA as an FSI error, and HIA then resets HPA.",
        "Origin of the recorded errors: " + ", ".join(f"{name} {count}" for name, count in origin.most_common()) + ".",
        "HP operation state when the error was recorded: "
        + ", ".join(f"{name or 'N/A'} ({count})" for name, count in states.most_common()) + ".",
    ]
    if resets:
        details.append(
            f"{len(resets)} error(s) have a HIA action that resets or reboots HPA: "
            + ", ".join(sorted({item['name'] or item['slot'] for item in resets})[:6]) + "."
        )
    if names:
        details.append("Most frequent: " + ", ".join(f"{name} ({count}x)" for name, count in names.most_common(4)) + ".")
    unstamped = [item for item in enriched if item["time"].startswith("1970") or not item["time"]]
    if unstamped:
        details.append(f"{len(unstamped)} slot(s) have no timestamp.")
    if origin.get("HW") or resets:
        severity = "issue"
    else:
        severity = "warning"
    headline = f"{len(enriched)} FSI error slots in HIA ({origin.get('HW', 0)} hardware, {origin.get('SW', 0)} software)"
    table = (
        ["Slot", "Time", "HP state", "Error", "Origin", "HIA resets HPA"],
        [[item["slot"], item["time"], item["state"], item["name"], item["origin"], "Yes" if item["reset"] else "No"]
         for item in sorted(enriched, key=lambda item: item["time"], reverse=True)[:25]],
    )
    return [finding(
        "FSI errors reported to HIA", severity, headline, details=details, table=table,
        sources=[source_label("HIA", "22FE03")],
    )]


# ------------------------------------------------------------------ HIA/HIB resets
RESET_FLAGS = [
    "RAM Uncorrectable ECC Failure Detected", "Pflash uncorrectable ECC Failure Detected",
    "Dflash uncorrectable ECC Failure Detected", "Thermal Reset Reason PCB Over Temperature",
    "Thermal Reset Reason MCU Over Temperature", "Thermal Reset Reason PMIC Over temperature",
]


def rule_own_resets(context):
    findings = []
    for ecu in ("HIA", "HIB"):
        values = context.values(ecu, "22FE02")
        if not values:
            continue
        causes = [label for label in RESET_FLAGS if is_true(values.get(label))]
        trap = values.get("Trap class", "00")
        trap_set = (to_int(trap) or 0) != 0 or (to_int(values.get("Trap ID", "0")) or 0) != 0
        reset_type = values.get("Reset Type", "N/A")
        counter = values.get("Reset Counter", "N/A")
        log = context.raw(ecu, "22FE04")
        has_log = bool(log and re.search(r"Trace:\s*(?:[0-9A-F]{2} ?)*[1-9A-F]", log))
        details = [
            f"{ecu} can reset on its own and keeps an error log."
            + (" A failure or reset of HIA can restart HPA, since HIA controls HPA." if ecu == "HIA" else "")
        ]
        if causes:
            details.append("Hardware cause flagged: " + ", ".join(label.replace("Thermal Reset Reason ", "thermal: ") for label in causes) + ".")
        if trap_set:
            details.append(f"A CPU trap was recorded (class {trap}, ID {values.get('Trap ID', 'N/A')}, address {values.get('Trap Triggering Address', 'N/A')}).")
        if not causes and not trap_set:
            details.append("No ECC failure, thermal reason or trap is flagged: a software-requested reset whose trigger this record does not identify.")
        if has_log:
            details.append(f"A reset log trace is stored ({ecu} 22 FE 04) for deeper analysis.")
        severity = "issue" if causes or trap_set else "info"
        findings.append(finding(
            "HIA and HIB resets", severity,
            f"{ecu} last reset: {reset_type} (reset counter {counter})",
            details=details,
            evidence=[
                ("Reset type", reset_type), ("Reset counter", counter),
                ("Reset timestamp (ECU ticks)", values.get("Reset TimeStamp", "N/A")),
                ("Triggering core", values.get("Reset Triggering core", "N/A")),
                ("MCU reset register", values.get("MCU Reset Register value", "N/A")),
            ],
            sources=[source_label(ecu, "22FE02"), source_label(ecu, "22FE04")],
        ))
    for ecu in ("HIA", "HIB", "HPA"):
        events = [
            row for row in context.rows("dtc", ecu)
            if re.search(r"RESET", row.get("Latest Event", ""), re.I)
        ]
        if events:
            findings.append(finding(
                "HIA and HIB resets", "warning",
                f"{ecu} DTC events point to a reset: " + ", ".join(sorted({row['Latest Event'] for row in events})[:3]),
                details=[f"{row['DTC']} at {row['UTC Time']}: {row['Description']}" for row in events[:6]],
                sources=[f"{ecu} 19 03 / 19 04"],
            ))
    return findings


# ---------------------------------------------------------- HIA/HIB reset log (22 FE 04)
def reason_text(code, reason):
    return f"{reason} (0x{code})" if reason else ("none (00)" if code == "00" else f"unknown (0x{code})")


def rule_reset_logs(context):
    """HIA and HIB reset log, decoded like the Safety-B ResetLog parser sheet (see reset_log.py)."""
    findings = []
    for ecu in ("HIA", "HIB"):
        payload = reset_log.payload_from_readout(context.raw(ecu, "22FE04"))
        if payload is None:
            continue
        parsed = reset_log.parse_reset_log(payload)
        values = parsed["values"]
        notes = reset_log.validation_notes(parsed)
        valid = values["ValidHeader"][0] == reset_log.EXPECTED_HEADER
        exceptional = values["IsExceptionalReset"][0] == "01"
        last_code, last_reason = values["LastReset"]
        last_exc_code, last_exc_reason = values["LastExceptionalReset"]
        history = [
            f"{item['reason'] or item['code']}" + (" (current)" if item["current"] else "")
            for item in parsed["history"] if item["code"] != "00" or item["current"]
        ]
        details = [
            f"Last reset: {reason_text(last_code, last_reason)}; last exceptional reset: "
            f"{reason_text(last_exc_code, last_exc_reason)}.",
            f"Reset counter {int(values['ResetCounter'][0], 16)}, exceptional reset counter "
            f"{int(values['RstLoop_ExcResetCounter'][0], 16)}; "
            f"{values['IsExceptionalReset'][1].lower() or 'exceptional flag unknown'} was the last one.",
            f"Reset history (index {parsed['history_index']} is current): " + (", ".join(history) or "empty") + ".",
            f"Software reason code 0x{values['SwReasonCode'][0]} on core {int(values['SwReasonCoreId'][0], 16)}; "
            f"SCU reset status {values['ScuRSTSTAT'][0]}.",
        ]
        if not valid:
            details.insert(0, "The reset log header is not B4B4B4B4, so the log is not valid.")
        details.extend(notes[1:] if not valid and notes else notes)

        extra = [(
            "Reset history",
            ["Index", "Reset reason code", "Reset reason", "Current"],
            [
                (str(item["index"]), item["code"], item["reason"] or "-", "current index" if item["current"] else "")
                for item in parsed["history"]
            ],
        )]
        view = reset_log.context_view(parsed)
        if view:
            title, rows, field = view
            details.append(
                f"Application context shown as {title}, the decoding that matches the reset reason "
                f"({field} 0x{values[field][0]}). The log does not store which decoding applies, so this is an assumption."
            )
            extra.append((f"Application context: {title}", ["Field", "Size", "Value"],
                          [(name, f"{size} byte{'s' if size > 1 else ''}", value) for name, size, value, _ in rows]))
        else:
            nonzero = [
                (title, name, value)
                for title, rows in parsed["context"].items()
                for name, _, value, _ in rows if value.strip("0")
            ]
            if nonzero:
                details.append(
                    "No application context decoding matches the reset reason; the non-zero fields of every "
                    "decoding the sheet defines are listed (the same bytes appear in several of them)."
                )
                extra.append(("Application context: non-zero fields of every decoding", ["Decoding", "Field", "Value"], nonzero))
        severity = "warning" if not valid else ("issue" if exceptional else "info")
        findings.append(finding(
            "HIA and HIB resets", severity,
            f"{ecu} reset log: last reset {last_reason or last_code}"
            + (", exceptional" if exceptional else "") + f" (reset counter {int(values['ResetCounter'][0], 16)})",
            details=details,
            table=(
                ["Data name", "Size", "Value", "Interpretation"],
                [(name, f"{size} byte{'s' if size > 1 else ''}", value, meaning) for name, size, value, meaning in parsed["common"]],
            ),
            extra_tables=extra,
            sources=[source_label(ecu, "22FE04")],
        ))
    return findings
def rule_lpa_shutdowns(context):
    values = context.values("LPA", "22FE17")
    if not values:
        return []
    requests = to_int(values.get("Shutdown Request counter"))
    done = to_int(values.get("Successful Shutdown counter"))
    nodes = {
        label.rsplit(" ", 1)[-1]: to_int(value)
        for label, value in values.items() if label.startswith("Successful Shutdown counter ")
    }
    short = {node: requests - count for node, count in nodes.items() if requests is not None and count is not None and count < requests}
    if requests is None or done is None:
        return []
    failed = requests - done
    covered = ", ".join(node for node in nodes) or "HIA, HIB, SGA"
    details = [
        f"LPA keeps the standby failure and success history for the VCU nodes it counts ({covered}).",
        "It does not show HPA standby failures: when HPA fails to enter standby, HIA powers off anyway, so LPA "
        "still counts a successful shutdown. HPA standby failures are visible in HIA (22 FE 14, 22 FE 4D).",
    ]
    if short:
        details.append("Nodes that did not acknowledge every shutdown: " + ", ".join(f"{node} (missing {gap})" for node, gap in short.items()) + ".")
    if values.get("Maximum Successful Shutdown Time"):
        details.append(f"Slowest successful shutdown: {values['Maximum Successful Shutdown Time']} (unit as reported by LPA).")
    severity = "issue" if failed > 0 or short else "ok"
    headline = (
        f"LPA: {done} of {requests} shutdown requests succeeded ({failed} did not)"
        if failed > 0 else f"LPA: all {requests} shutdown requests succeeded for {covered}"
    )
    return [finding(
        "LPA node history", severity, headline, details=details,
        evidence=[(label, value) for label, value in values.items()],
        sources=[source_label("LPA", "22FE17"), source_label("LPA", "22FE16")],
    )]


def rule_lpa_wakeups(context):
    values = context.values("LPA", "22FE18")
    if not values:
        return []
    total = to_int(values.get("Wakeup Counter"))
    ok = to_int(values.get("Successful Wakeup Counter"))
    failures = {label: to_int(value) for label, value in values.items() if "Failure" in label and "counter" in label}
    failing = {label: value for label, value in failures.items() if value}
    timeouts = context.values("LPA", "22D902") or {}
    fatal = context.values("LPA", "22D908") or {}
    timeout_nodes = [label.split(" ")[0] for label, value in timeouts.items() if (to_int(value) or 0) > 0 or "no fault" not in value.lower()]
    fatal_nodes = [label.split(" ")[0] for label, value in fatal.items() if (to_int(value) or 0) > 0 or "no fault" not in value.lower()]
    details = []
    if failing:
        details.append("Wake-up failures: " + ", ".join(f"{label.replace(' counter', '')} = {value}" for label, value in failing.items()) + ".")
    if timeout_nodes:
        details.append("Wake-up timeout in the current cycle: " + ", ".join(timeout_nodes) + ".")
    if fatal_nodes:
        details.append("Fatal wake-up failure: " + ", ".join(fatal_nodes) + ".")
    if total is not None and ok is not None and total > ok:
        details.append(f"{total - ok} wake-up(s) are not counted as successful yet (possibly the current one).")
    severity = "issue" if failing or timeout_nodes or fatal_nodes else "ok"
    headline = (
        "LPA recorded wake-up failures" if severity == "issue"
        else f"LPA: {ok} of {total} VCU wake-ups succeeded, no node failed" if None not in (ok, total)
        else "LPA wake-up statistics show no failures"
    )
    evidence = [(label, value) for label, value in values.items()]
    evidence += [(f"Timeout in current cycle: {label}", value) for label, value in timeouts.items()]
    evidence += [(f"Fatal wake-up failure: {label}", value) for label, value in fatal.items()]
    return [finding(
        "LPA node history", severity, headline, details=details, evidence=evidence,
        sources=[source_label("LPA", "22FE18"), source_label("LPA", "22D902"), source_label("LPA", "22D908")],
    )]


def rule_lpa_resets(context):
    findings = []
    stats = context.values("LPA", "22D90A")
    if stats:
        counts = {label.replace(" Counter", ""): to_int(value) for label, value in stats.items()}
        abnormal = {label: value for label, value in counts.items() if value and re.search(r"Watchdog|Brown Out|External", label)}
        severity = "warning" if abnormal else "info"
        findings.append(finding(
            "LPA node history", severity,
            "LPA reset reasons: " + (", ".join(f"{label} = {value}" for label, value in abnormal.items()) if abnormal
                                      else "no watchdog, brown-out or external resets"),
            details=["Power-on, NVM and system-reset-request counters are normal for ordinary shutdown and wake-up cycles."],
            evidence=[(label, str(value)) for label, value in counts.items()],
            sources=[source_label("LPA", "22D90A")],
        ))
    exceptional = context.values("LPA", "22FE03")
    if exceptional:
        counts = {label.replace(" Counter", ""): to_int(value) for label, value in exceptional.items()}
        active = {label: value for label, value in counts.items() if value}
        findings.append(finding(
            "LPA node history", "issue" if active else "ok",
            "LPA exceptional resets: " + ", ".join(f"{label} = {value}" for label, value in active.items())
            if active else "LPA has no exceptional resets (stack overflow, hard fault, watchdog, panic)",
            evidence=[(label, str(value)) for label, value in counts.items()],
            sources=[source_label("LPA", "22FE03"), source_label("LPA", "22FE02")],
        ))
    timeout = context.values("LPA", "22FE0B")
    if timeout:
        findings.append(finding(
            "LPA node history", "info",
            f"HPA boot chain confirmation timeout: {timeout.get('HPA boot chain confirmation timeout threshold', 'N/A')}",
            details=["If HPA does not confirm its boot chain within this time LPA treats the boot as failed."],
            sources=[source_label("LPA", "22FE0B")],
        ))
    return findings


RULES = [
    rule_current_state,
    rule_standby_records,
    rule_shutdown_failures,
    rule_wakeup_histogram,
    rule_powerup_histogram,
    rule_exceptional_restart,
    rule_cross_checks,
    rule_application_watchdog,
    rule_fsi_errors,
    rule_own_resets,
    rule_reset_logs,
    rule_lpa_wakeups,
    rule_lpa_resets,
]


# ------------------------------------------------------------------------ timeline
def _normalize_time(text):
    """Return an ISO string for sorting, or None when the value is not a usable timestamp."""
    if not text or text.startswith("1970") or text in {"N/A", "No timestamp"}:
        return None
    cleaned = text.replace("Z", "").replace(" UTC", "").replace(" ", "T")
    try:
        return datetime.fromisoformat(cleaned).replace(tzinfo=None).isoformat(timespec="seconds")
    except ValueError:
        return None


def build_timeline(context):
    events = []
    for row in context.rows("events"):
        when = _normalize_time(row.get("UTC Time", ""))
        if when:
            outcome = "successful" if row.get("Success", "").lower() == "yes" else "UNSUCCESSFUL"
            kind = row.get("Shutdown Type") or "shutdown"
            events.append((when, "HPA standby records", f"{kind} cycle #{row.get('#', '')} {outcome}",
                           f"Active ECUs at shutdown: {row.get('Active ECUs', 'N/A')}"))
    details_by_slot = {row.get("Slot"): row for row in context.rows("fe03_details")}
    for row in context.rows("fe03_slots"):
        when = _normalize_time(row.get("Time", ""))
        if when:
            detail = details_by_slot.get(row.get("Slot"), {})
            events.append((when, "FSI error (HIA)", row.get("Error Name") or f"Slot {row.get('Slot')}",
                           f"{error_origin(detail.get('Reference'))} error while HP state {row.get('HP Operation State', 'N/A')}"))
    for row in context.rows("transitions"):
        when = _normalize_time(row.get("Timestamp (UTC)", ""))
        if when:
            events.append((when, "HPA platform state", row.get("State", ""), f"Time taken {row.get('Time taken (HH:MM:SS.mmm)', 'N/A')}"))
    for section in context.sections:
        if section["kind"] != "dtc":
            continue
        ecu = section["heading"].split(" ")[0]
        for row in section["rows"]:
            when = _normalize_time(row.get("UTC Time", ""))
            if when:
                latest = row.get("Latest Event", "")
                latest = "" if latest in {"N/A", "-"} else latest
                events.append((when, f"{ecu} DTC", f"{row.get('DTC', '')} {latest}".strip(), row.get("Description", "")))
    restart = exceptional_restart_time(context)
    if restart:
        events.append((restart, "HIA exceptional restart", "HIA restarted HP", "Reasons: HIA 22 FE 4D (time as stored)"))
    events.sort(key=lambda item: item[0])
    return events


def interpret_readout(blocks, sections):
    """Evaluate every rule; return findings, the merged timeline, and bookkeeping about data coverage."""
    context = Context(blocks, sections)
    findings = []
    errors = []
    for rule in RULES:
        try:
            findings.extend(rule(context))
        except Exception as error:  # a broken rule must not hide the other results
            errors.append(f"{rule.__name__}: {error}")
    try:
        timeline = build_timeline(context)
    except Exception as error:
        timeline = []
        errors.append(f"build_timeline: {error}")
    findings.sort(key=lambda item: (
        SEVERITY_ORDER[item["severity"]],
        CATEGORY_ORDER.index(item["category"]) if item["category"] in CATEGORY_ORDER else len(CATEGORY_ORDER),
    ))
    return {
        "findings": findings,
        "timeline": timeline,
        "app_states": application_states(context),
        "missing": sorted(source for source, present in context.used.items() if not present),
        "errors": errors,
    }
