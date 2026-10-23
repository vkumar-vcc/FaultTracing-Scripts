"""Team front end: submit a VIN problem and read the root-cause report from the local worker."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import streamlit as st

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import evidence  # noqa: E402
import jobs  # noqa: E402
import knowledge  # noqa: E402
from collect import available_sddbs  # noqa: E402

TIME_ZONES = ["Europe/Stockholm", "UTC", "Asia/Kolkata", "Asia/Shanghai", "America/New_York"]
SOURCE_LABELS = {
    "readouts": "SAT readouts (decoded + interpreted)",
    "dlt": "NUC DLT logs",
    "uart": "NUC UART logs",
    "pcap": "NUC Ethernet PCAP",
}
STATUS_BADGES = {
    "queued": ("Queued", "gray", ":material/schedule:"),
    "collecting": ("Collecting logs", "blue", ":material/download:"),
    "analysing": ("Analysing", "violet", ":material/psychology:"),
    "done": ("Report ready", "green", ":material/check_circle:"),
    "failed": ("Failed", "red", ":material/error:"),
}
WORKER_STALE = timedelta(minutes=2)
DONT_SAVE = ""
NEW_KNOWLEDGE = "+ new"


@st.cache_data(ttl=600)
def sddb_choices():
    return [str(path) for path in available_sddbs()]


def status_badge(status):
    label, color, icon = STATUS_BADGES.get(status, (status, "gray", None))
    st.badge(label, color=color, icon=icon)


def worker_state():
    seen, state = jobs.worker_heartbeat()
    if seen is None:
        st.warning("The investigation worker has never run. Requests will wait in the queue.", icon=":material/power_off:")
    elif jobs.utc_now() - seen > WORKER_STALE:
        st.warning(
            f"The investigation worker was last seen {seen:%Y-%m-%d %H:%M} UTC. "
            "Requests will wait in the queue until it is back.",
            icon=":material/power_off:",
        )
    else:
        st.caption(f":material/smart_toy: Worker online, {state or 'idle'}.")


st.set_page_config(page_title="Root-cause investigation", page_icon=":material/troubleshoot:", layout="wide")
st.title("Root-cause investigation")
st.caption(
    "Describe a vehicle problem. A worker collects the VIN's readouts and NUC logs around the event time, "
    "and an AI agent proposes a possible root cause. Treat the report as a starting point and check the evidence it cites."
)
worker_state()

with st.form("new_investigation", clear_on_submit=False):
    vin = st.text_input("VIN", max_chars=17, placeholder="YV1...")
    if "event_date" not in st.session_state:
        # Defaults are set once per session: a default that changed between reruns would reset the widget.
        now = jobs.utc_now().astimezone(ZoneInfo(TIME_ZONES[0]))
        st.session_state["event_date"] = now.date()
        st.session_state["event_clock"] = now.time().replace(second=0, microsecond=0)
    with st.container(horizontal=True):
        event_date = st.date_input("Event date", key="event_date")
        event_clock = st.time_input("Event time", key="event_clock", step=60)
        zone = st.selectbox("Time zone", TIME_ZONES, help="Time zone of the date and time you entered.")
    problem = st.text_area(
        "Problem description",
        placeholder="What did the driver or the test see? For example: centre display black for 2 minutes after wake-up.",
    )
    notes = st.text_area("Additional notes", placeholder="Software version, test case, how often it happens, ...")
    submitted_by = st.text_input("Your name or e-mail", placeholder="So the team knows who to ask")
    with st.expander("Collection options"):
        sources = st.pills(
            "Log sources",
            list(SOURCE_LABELS),
            selection_mode="multi",
            default=list(SOURCE_LABELS),
            format_func=SOURCE_LABELS.get,
        )
        with st.container(horizontal=True):
            minutes_before = st.number_input("Minutes before the event", 0, 720, 5)
            minutes_after = st.number_input("Minutes after the event", 0, 720, 5)
        st.caption("The agent widens the window by itself when it finds no evidence close to the event.")
        sddb = st.selectbox(
            "SDDB for decoding readouts",
            [""] + sddb_choices(),
            format_func=lambda value: Path(value).name if value else "Automatic (newest on the worker)",
        )
    submit = st.form_submit_button("Start investigation", type="primary", icon=":material/play_arrow:")

if submit:
    try:
        event_time = datetime.combine(event_date, event_clock).replace(tzinfo=ZoneInfo(zone))
        if event_time > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("The event time is in the future. Check the date, time and time zone.")
        job_id = jobs.create_job(
            vin, event_time, problem, notes, submitted_by, sources or [], minutes_before, minutes_after, sddb,
        )
    except ValueError as error:
        st.error(str(error), icon=":material/error:")
    else:
        st.session_state["selected_job"] = job_id
        st.success(
            f"Investigation queued for {job_id.split('_')[1]} at {jobs.iso(event_time)}. "
            "It appears below and refreshes automatically.",
            icon=":material/check:",
        )


def job_label(job):
    request = job["request"]
    label, _, _ = STATUS_BADGES.get(job["status"]["status"], (job["status"]["status"], None, None))
    problem = request["problem"].splitlines()[0][:60]
    return f"{request['created_utc'][:16].replace('T', ' ')} · {request['vin']} · {label} · {problem}"


def show_file(folder, name, title):
    path = folder / name
    if path.is_file():
        with st.expander(title):
            st.code(path.read_text(encoding="utf-8", errors="replace")[-20000:], language="text", wrap_lines=True)


def knowledge_target_label(value):
    if value == DONT_SAVE:
        return "Don't save as knowledge"
    if value == NEW_KNOWLEDGE:
        return "Save as new knowledge"
    return f"Add to existing: {value}"


def knowledge_inputs(key, include_dont_save):
    """Widgets for choosing where knowledge goes; returns (target, title, applies_when)."""
    names = [entry["name"] for entry in knowledge.list_knowledge()]
    options = ([DONT_SAVE] if include_dont_save else []) + [NEW_KNOWLEDGE] + names
    target = st.selectbox(
        "Team knowledge",
        options,
        key=f"{key}_target",
        format_func=knowledge_target_label,
        help="Saved as a skill in the repository (.github/skills). The agent uses it in every later investigation.",
    )
    with st.container(horizontal=True):
        title = st.text_input("Title of new knowledge", key=f"{key}_title",
                              placeholder="For example: DHU system communication fault")
        applies_when = st.text_input(
            "Use it when", key=f"{key}_applies",
            placeholder="Symptom, ECU, log pattern or keywords that should make the agent read it",
        )
    st.caption("Title and *Use it when* are needed only for new knowledge.")
    return target, title, applies_when


def store_knowledge(target, title, applies_when, content, submitted_by, job_id=""):
    """Save or append knowledge; returns the skill name, or '' when not saving."""
    if target == DONT_SAVE:
        return ""
    if target == NEW_KNOWLEDGE:
        path = knowledge.save_knowledge(title, applies_when, content, submitted_by, job_id)
    else:
        path = knowledge.append_knowledge(target, content, submitted_by, job_id)
    return path.parent.name


def finish_form(keys, message, flash_key):
    """Clear the submitted fields and show ``message`` after the rerun."""
    for key in keys:
        st.session_state.pop(key, None)
    st.session_state[flash_key] = message
    st.rerun()


def show_flash(flash_key):
    message = st.session_state.pop(flash_key, None)
    if message:
        st.success(message, icon=":material/check:")


def feedback_section(job):
    request, status, folder = job["request"], job["status"], job["folder"]
    job_id = request["id"]
    if job["feedback"]:
        with st.expander(f"Feedback given ({len(job['feedback'])})", icon=":material/forum:"):
            for entry in job["feedback"]:
                who = f" by {entry['submitted_by']}" if entry.get("submitted_by") else ""
                about = f"on report v{entry['report_version']}" if entry.get("report_version") else "before any report"
                st.markdown(f"**{entry['created_utc'].replace('T', ' ').rstrip('Z')} UTC{who}, {about}**")
                st.text(entry["text"])
                if entry.get("knowledge"):
                    st.caption(f"Saved as team knowledge `{entry['knowledge']}`.")
    for version, path in reversed(job["previous_reports"]):
        with st.expander(f"Earlier report v{version}", icon=":material/history:"):
            st.markdown(path.read_text(encoding="utf-8", errors="replace"))

    show_flash("flash_feedback")
    running = status["status"] in jobs.ACTIVE_STATUSES
    with st.form(f"feedback_{job_id}"):
        st.markdown("**Correct or add to this finding**")
        st.caption(
            "Tell the agent what is wrong or what it missed, for example the procedure an expert follows for this "
            "symptom. It analyses the same logs again with your input. Save the input as team knowledge to have "
            "the agent use it in future investigations too."
        )
        text = st.text_area(
            "What is wrong, or what should the agent know?",
            key=f"{job_id}_feedback",
            placeholder="For example: the finding is wrong. First check for an HPA reset: in HPA DLT the hardware "
                        "timestamp restarts from zero ...",
        )
        reanalyse = st.checkbox(
            "Analyse again with this feedback",
            value=not running,
            key=f"{job_id}_reanalyse",
            disabled=running,
            help="Keeps the collected logs and the current report (archived as an earlier version).",
        )
        target, title, applies_when = knowledge_inputs(f"{job_id}_knowledge", include_dont_save=True)
        knowledge_text = st.text_area(
            "Knowledge text (optional)",
            key=f"{job_id}_knowledge_text",
            placeholder="Leave empty to save the feedback above. Write it generally, so it helps for other vehicles.",
        )
        by = st.text_input("Your name or e-mail", key=f"{job_id}_by")
        send = st.form_submit_button("Send feedback", icon=":material/send:")
    if send:
        try:
            if not text.strip():
                raise ValueError("Write what is wrong or what the agent should know.")
            if reanalyse and running:
                raise ValueError("The investigation is running. Add feedback when it has finished.")
            saved = store_knowledge(target, title, applies_when, knowledge_text.strip() or text, by, job_id)
            queued = jobs.add_feedback(folder, text, by, reanalyse=reanalyse, knowledge=saved)
        except ValueError as error:
            st.error(str(error), icon=":material/error:")
        else:
            parts = ["Feedback saved."]
            if saved:
                parts.append(f"Team knowledge `{saved}` saved in .github/skills; commit it to share it.")
            if queued:
                parts.append("The re-analysis is queued; the new report appears here.")
            knowledge_key = f"{job_id}_knowledge"
            finish_form(
                [f"{job_id}_feedback", f"{job_id}_knowledge_text", f"{knowledge_key}_target",
                 f"{knowledge_key}_title", f"{knowledge_key}_applies"],
                " ".join(parts),
                "flash_feedback",
            )


@st.fragment(run_every=10)
def investigations():
    st.subheader("Investigations")
    all_jobs = jobs.list_jobs(limit=100)
    if not all_jobs:
        st.info("No investigations yet.", icon=":material/inbox:")
        return
    by_id = {job["request"]["id"]: job for job in all_jobs}
    ids = list(by_id)
    selected = st.session_state.get("selected_job")
    chosen = st.selectbox(
        "Investigation",
        ids,
        index=ids.index(selected) if selected in by_id else 0,
        format_func=lambda job_id: job_label(by_id[job_id]),
    )
    st.session_state["selected_job"] = chosen
    if selected is not None and chosen != selected:
        st.rerun()  # the evidence viewer outside this fragment must follow the new job
    job = by_id[chosen]
    request, status = job["request"], job["status"]

    with st.container(border=True):
        with st.container(horizontal=True, vertical_alignment="center"):
            status_badge(status["status"])
            st.caption(f"{status.get('message', '')} Updated {status.get('updated_utc', '')}.")
        with st.container(horizontal=True):
            st.metric("VIN", request["vin"])
            st.metric("Event (UTC)", request["event_time_utc"].replace("T", " ").rstrip("Z"))
            st.metric("Window", f"-{request['minutes_before']:g} / +{request['minutes_after']:g} min")
        st.markdown("**Problem**")
        st.text(request["problem"])
        if request.get("notes"):
            st.markdown("**Notes**")
            st.text(request["notes"])
        if request.get("submitted_by"):
            st.caption(f"Submitted by {request['submitted_by']}")

    if job["report"]:
        st.download_button(
            "Download report",
            job["report"],
            file_name=f"{chosen}_root_cause.md",
            mime="text/markdown",
            icon=":material/download:",
        )
        with st.container(border=True):
            st.markdown(job["report"])
    elif status["status"] in ("queued", "collecting", "analysing"):
        st.info("The report appears here when the agent finishes. Collection and analysis can take 10-30 minutes.",
                icon=":material/hourglass_top:")

    if job["report"] or status["status"] in ("done", "failed") or job["feedback"]:
        feedback_section(job)

    folder = job["folder"]
    show_file(folder, "collected/manifest.md", "Collected data")
    show_file(folder, "worker.log", "Worker log")
    show_file(folder, "collect.log", "Collector output")


def size_label(size):
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:,.0f} {unit}"
        size /= 1024
    return f"{size:,.1f} GB"


@st.cache_data(max_entries=20, show_spinner=False)
def cached_lines(path, stamp, start, count):
    return evidence.read_lines(path, start, count)


@st.cache_data(max_entries=20, show_spinner=False)
def cached_search(path, stamp, text, regex, ignore_case, start, limit):
    return evidence.search(path, evidence.compile_pattern(text, regex, ignore_case), limit, start)


@st.fragment
def evidence_viewer():
    job_id = st.session_state.get("selected_job")
    if not job_id:
        return
    try:
        folder = jobs.job_dir(job_id)
    except ValueError:
        return
    files = evidence.list_files(folder) if folder.is_dir() else []
    if not files:
        return
    st.subheader("Evidence")
    st.caption(
        "Open the files the report cites. Choose the file, then go to the line number the report gives, or search "
        f"for a time (`12:25:43`), an application or a message. Files are in `{folder}` on the worker computer."
    )
    by_name = {item["name"]: item for item in files}
    name = st.selectbox(
        "File",
        list(by_name),
        key=f"{job_id}_evidence_file",
        format_func=lambda value: f"{value} ({size_label(by_name[value]['size'])})",
    )
    item = by_name[name]
    path = str(item["path"])
    stat = item["path"].stat()
    stamp = (stat.st_mtime_ns, stat.st_size)

    views = ["Go to line", "Search"]
    if name.endswith(".md") and item["size"] < 2_000_000:
        views.append("Formatted")
    view = st.segmented_control("View", views, default=views[0], key=f"{job_id}_evidence_view") or views[0]

    if view == "Formatted":
        with st.container(border=True, height=700):
            st.markdown(item["path"].read_text(encoding="utf-8", errors="replace"))
    elif view == "Go to line":
        with st.container(horizontal=True):
            line = st.number_input("Line", min_value=1, value=1, step=1, key=f"{job_id}_evidence_line")
            around = st.number_input("Lines before and after", min_value=0, max_value=500, value=30, step=10,
                                     key=f"{job_id}_evidence_around")
        start = max(1, int(line) - int(around))
        with st.spinner("Reading the file..."):
            lines = cached_lines(path, stamp, start, int(line) - start + int(around) + 1)
        if lines:
            st.caption("The line you asked for is marked with `>`.")
            st.code(evidence.format_lines(lines, mark=int(line)), language=None, wrap_lines=True)
        else:
            st.info("The file has fewer lines than that.", icon=":material/info:")
    else:
        with st.form(f"{job_id}_evidence_search", border=False):
            text = st.text_input("Search for", key=f"{job_id}_evidence_text",
                                 placeholder="For example 12:25:4, VDVA, vehicledataviewadapter, fatal")
            with st.container(horizontal=True, vertical_alignment="bottom"):
                regex = st.checkbox("Regular expression", key=f"{job_id}_evidence_regex")
                ignore_case = st.checkbox("Ignore case", value=True, key=f"{job_id}_evidence_case")
                start = st.number_input("From line", min_value=1, value=1, step=1, key=f"{job_id}_evidence_from")
                limit = st.number_input("Max. matches", min_value=1, max_value=evidence.MAX_MATCHES, value=200,
                                        key=f"{job_id}_evidence_limit")
            st.form_submit_button("Search", icon=":material/search:")
        if text:
            try:
                with st.spinner(f"Searching {size_label(item['size'])}..."):
                    matches, truncated = cached_search(path, stamp, text, regex, ignore_case, int(start), int(limit))
            except ValueError as error:
                st.error(str(error), icon=":material/error:")
            else:
                if not matches:
                    st.info("No matches.", icon=":material/search_off:")
                else:
                    more = (f" Showing the first {len(matches)}; set *From line* to {matches[-1][0] + 1} for the next ones."
                            if truncated else "")
                    st.caption(f"{len(matches)} matching line(s).{more} Use *Go to line* to see the lines around one.")
                    st.code(evidence.format_lines(matches), language=None, wrap_lines=True)

    if item["size"] <= 50_000_000:
        st.download_button("Download file", data=item["path"].read_bytes(), file_name=item["path"].name,
                           icon=":material/download:", key=f"{job_id}_evidence_download")
    else:
        st.caption("Too large to download here; use search and line ranges.")


def knowledge_base():
    st.subheader("Team knowledge")
    entries = knowledge.list_knowledge()
    st.caption(
        f"{len(entries)} skill(s) in .github/skills. The agent reads every description and loads the ones that match "
        "the problem. Add knowledge for an issue here or with the feedback form of an investigation."
    )
    with st.expander("Browse knowledge", icon=":material/menu_book:"):
        for entry in entries:
            st.markdown(f"**{entry['name']}**: {entry['description']}")
    with st.expander("Add knowledge", icon=":material/add:"):
        with st.form("add_knowledge"):
            target, title, applies_when = knowledge_inputs("standalone", include_dont_save=False)
            content = st.text_area(
                "Knowledge",
                key="standalone_content",
                placeholder="What to check, in which order, which logs or signals show it, and what it means.",
                height=200,
            )
            by = st.text_input("Your name or e-mail", key="standalone_by")
            save = st.form_submit_button("Save knowledge", icon=":material/save:")
        if save:
            try:
                name = store_knowledge(target, title, applies_when, content, by)
            except ValueError as error:
                st.error(str(error), icon=":material/error:")
            else:
                finish_form(
                    ["standalone_target", "standalone_title", "standalone_applies", "standalone_content"],
                    f"Saved `{name}` in .github/skills; commit it to share it.",
                    "flash_knowledge",
                )
    show_flash("flash_knowledge")


investigations()
evidence_viewer()
knowledge_base()
