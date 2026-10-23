"""Folder-based job queue shared by the investigation UI and the local worker.

Each job is a folder below the jobs root containing:
    request.json   what the engineer submitted (never changed afterwards)
    status.json    queued -> collecting -> analysing -> done | failed
    collected/     logs and summaries gathered by collect.py
    report.md      the agent's root-cause report
    worker.log     what the worker did
    feedback.json  engineers' corrections and extra information, oldest first
    feedback.md    the same as Markdown, for the agent
    report_v<N>.md earlier reports, archived when a re-analysis is queued
    reanalyse      marker: analyse again with the feedback, without collecting logs again
"""

import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

VIN_PATTERN = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
JOB_ID_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}_[A-Z0-9]{17}_[0-9a-f]{6}$")
STATUSES = ("queued", "collecting", "analysing", "done", "failed")
ACTIVE_STATUSES = ("collecting", "analysing")
ALL_SOURCES = ("readouts", "dlt", "uart", "pcap")
HEARTBEAT_FILE = "worker.heartbeat"
CLAIM_FILE = "claim.lock"
FEEDBACK_FILE = "feedback.json"
FEEDBACK_MARKDOWN = "feedback.md"
REANALYSE_MARKER = "reanalyse"
MAX_FEEDBACK = 20000
REPORT_VERSION_PATTERN = re.compile(r"^report_v([0-9]+)\.md$")


def jobs_root():
    configured = os.environ.get("FAULT_TRACING_INVESTIGATIONS")
    if configured:
        root = Path(configured).expanduser()
    else:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".cache")
        root = Path(base) / "FaultTracing-Scripts" / "investigations"
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def utc_now():
    return datetime.now(timezone.utc)


def iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def normalize_vin(vin):
    value = (vin or "").strip().upper()
    if not VIN_PATTERN.match(value):
        raise ValueError("A VIN has 17 letters and digits (no I, O or Q).")
    return value


def write_json(path, data):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def read_json(path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def job_dir(job_id, root=None):
    if not JOB_ID_PATTERN.match(job_id or ""):
        raise ValueError(f"Not a job id: {job_id!r}")
    return (root or jobs_root()) / job_id


def create_job(
    vin,
    event_time,
    problem,
    notes="",
    submitted_by="",
    sources=ALL_SOURCES,
    minutes_before=5,
    minutes_after=5,
    sddb="",
    root=None,
):
    """Queue an investigation and return its id. ``event_time`` must be timezone-aware."""
    vin = normalize_vin(vin)
    if event_time.tzinfo is None:
        raise ValueError("The event time needs a time zone.")
    problem = (problem or "").strip()
    if not problem:
        raise ValueError("Describe the problem.")
    sources = [source for source in ALL_SOURCES if source in set(sources)]
    if not sources:
        raise ValueError("Choose at least one log source.")
    if minutes_before < 0 or minutes_after < 0 or minutes_before + minutes_after <= 0:
        raise ValueError("The time window must be longer than zero.")

    created = utc_now()
    job_id = f"{created.strftime('%Y%m%dT%H%M%S')}_{vin}_{secrets.token_hex(3)}"
    folder = job_dir(job_id, root or jobs_root())
    folder.mkdir(parents=True)
    write_json(folder / "request.json", {
        "id": job_id,
        "vin": vin,
        "event_time_utc": iso(event_time),
        "event_time_entered": event_time.isoformat(),
        "problem": problem,
        "notes": (notes or "").strip(),
        "submitted_by": (submitted_by or "").strip(),
        "sources": sources,
        "minutes_before": float(minutes_before),
        "minutes_after": float(minutes_after),
        "sddb": (sddb or "").strip(),
        "created_utc": iso(created),
    })
    set_status(folder, "queued", "Waiting for the investigation worker.")
    return job_id


def set_status(folder, status, message=""):
    if status not in STATUSES:
        raise ValueError(f"Unknown status: {status}")
    write_json(Path(folder) / "status.json", {
        "status": status,
        "message": message,
        "updated_utc": iso(utc_now()),
    })


def load_job(folder):
    folder = Path(folder)
    request = read_json(folder / "request.json")
    if request is None:
        return None
    status = read_json(folder / "status.json", {"status": "queued", "message": "", "updated_utc": ""})
    report = folder / "report.md"
    return {
        "folder": folder,
        "request": request,
        "status": status,
        "report": report.read_text(encoding="utf-8") if report.is_file() else None,
        "feedback": read_json(folder / FEEDBACK_FILE, []),
        "previous_reports": previous_reports(folder),
    }


def previous_reports(folder):
    """Archived reports as ``(version, path)``, oldest first."""
    found = []
    for path in Path(folder).glob("report_v*.md"):
        match = REPORT_VERSION_PATTERN.match(path.name)
        if match:
            found.append((int(match.group(1)), path))
    return sorted(found)


def write_feedback_markdown(folder, entries):
    lines = [
        "# Engineer feedback on earlier reports",
        "",
        "Oldest first. Each entry names the report version it refers to "
        "(`report_v<N>.md` in this folder).",
    ]
    for number, entry in enumerate(entries, 1):
        who = f" by {entry['submitted_by']}" if entry.get("submitted_by") else ""
        about = f"on report v{entry['report_version']}" if entry["report_version"] else "before any report"
        lines += [
            "",
            f"## Feedback {number}: {entry['created_utc']}{who}, {about}",
            "",
            entry["text"],
        ]
        if entry.get("knowledge"):
            lines += ["", f"Saved as team knowledge: `.github/skills/{entry['knowledge']}/SKILL.md`."]
    (Path(folder) / FEEDBACK_MARKDOWN).write_text("\n".join(lines) + "\n", encoding="utf-8")


def add_feedback(folder, text, submitted_by="", reanalyse=True, knowledge=""):
    """Record an engineer's correction; with ``reanalyse`` queue the job to be analysed again.

    Returns True when a re-analysis was queued. Collected logs are kept; the agent can still collect more.
    """
    folder = Path(folder)
    job = load_job(folder)
    if job is None:
        raise ValueError("Unknown investigation.")
    text = (text or "").strip()
    if not text:
        raise ValueError("Write what is wrong or what the agent should know.")
    if len(text) > MAX_FEEDBACK:
        raise ValueError(f"The feedback is too long ({len(text):,} characters, at most {MAX_FEEDBACK:,}).")
    state = job["status"]["status"]
    if reanalyse and state in ACTIVE_STATUSES:
        raise ValueError("The investigation is running. Add feedback when it has finished.")

    versions = previous_reports(folder)
    version = (versions[-1][0] if versions else 0) + (1 if job["report"] is not None else 0)
    entries = job["feedback"] + [{
        "text": text,
        "submitted_by": (submitted_by or "").strip(),
        "created_utc": iso(utc_now()),
        "report_version": version,
        "knowledge": knowledge or "",
    }]
    if reanalyse and job["report"] is not None:
        os.replace(folder / "report.md", folder / f"report_v{version}.md")
    write_json(folder / FEEDBACK_FILE, entries)
    write_feedback_markdown(folder, entries)
    if not reanalyse or state == "queued":
        return False
    (folder / REANALYSE_MARKER).write_text(iso(utc_now()) + "\n", encoding="utf-8")
    (folder / CLAIM_FILE).unlink(missing_ok=True)
    set_status(folder, "queued", "Re-analysis with your feedback is waiting for the worker.")
    return True


def list_jobs(root=None, limit=None):
    root = root or jobs_root()
    folders = sorted(
        (entry for entry in root.iterdir() if entry.is_dir() and JOB_ID_PATTERN.match(entry.name)),
        key=lambda entry: entry.name,
        reverse=True,
    )
    jobs = []
    for folder in folders[:limit] if limit else folders:
        job = load_job(folder)
        if job is not None:
            jobs.append(job)
    return jobs


def claim_next_job(root=None):
    """Atomically take the oldest queued job; returns its folder or None."""
    root = root or jobs_root()
    for job in reversed(list_jobs(root)):
        if job["status"]["status"] != "queued":
            continue
        try:
            descriptor = os.open(job["folder"] / CLAIM_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            continue
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"{os.getpid()} {iso(utc_now())}\n")
        set_status(job["folder"], "collecting", "Collecting logs.")
        return job["folder"]
    return None


def requeue_interrupted_jobs(root=None):
    """Return jobs a stopped worker left half done to the queue. Run with a single worker only."""
    requeued = []
    for job in list_jobs(root or jobs_root()):
        if job["status"]["status"] in ACTIVE_STATUSES:
            (job["folder"] / CLAIM_FILE).unlink(missing_ok=True)
            set_status(job["folder"], "queued", "Requeued after the worker restarted.")
            requeued.append(job["folder"])
    return requeued


def write_heartbeat(root=None, state="idle"):
    write_json((root or jobs_root()) / HEARTBEAT_FILE, {"updated_utc": iso(utc_now()), "state": state})


def worker_heartbeat(root=None):
    data = read_json((root or jobs_root()) / HEARTBEAT_FILE)
    if not data:
        return None, None
    try:
        return parse_iso(data["updated_utc"]), data.get("state", "")
    except (KeyError, ValueError):
        return None, None
