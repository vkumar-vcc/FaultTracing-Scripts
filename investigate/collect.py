"""Collect every log for one investigation job into ``<job>/collected``.

The worker runs this once per job; the root-cause agent may run it again with a
wider window, other sources, another SDDB or specific readouts. Downloads that
already exist are skipped, so reruns only fetch what is new.

    python investigate/collect.py --job <job folder> [--minutes-before 30] [--minutes-after 30]
        [--sources readouts,dlt,uart,pcap] [--ecus HPA,SGA] [--sddb PATH] [--readout PATH ...]
"""

import argparse
import contextlib
import io
import json
import os
import re
import sys
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
# Importing the submodules must not leave __pycache__ folders in their checkouts.
sys.dont_write_bytecode = True
for folder in (HERE, ROOT, ROOT / "decoder", ROOT / "download_combine_NUC_dlt"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import jobs  # noqa: E402

# NUC archive files are named by a single time stamp (for DLT: when the chunk was closed) and a
# chunk can span over an hour, so list this far around the window to find the chunks at its edges.
CHUNK_LOOKAROUND = timedelta(hours=6)
MAX_DLT_TEXT_LINES = 1_500_000
EVENT_FOCUS = timedelta(minutes=2)
MAX_READOUTS = 3


def utc_naive(moment):
    return moment.astimezone(timezone.utc).replace(tzinfo=None)


def file_name(path):
    """Last component of a local, UNC or share path."""
    return str(path).replace("/", "\\").split("\\")[-1]


def select_covering_files(files, start, end, group_key, timestamp_of):
    """Files named inside [start, end], plus per group the nearest file named before and after it.

    NUC DLT chunks are named by the time they were closed (their last message), so the chunk named
    after ``end`` holds the end of the window. Keeping the one before as well makes the selection
    correct if a source names files by their start instead. ``start``/``end`` are naive UTC;
    files without a parsable timestamp are kept.
    """
    chosen, latest_before, first_after = [], {}, {}
    for item in files:
        stamp = timestamp_of(item["name"])
        if stamp is None or start <= stamp <= end:
            chosen.append(item)
            continue
        key = group_key(item)
        if stamp < start:
            current = latest_before.get(key)
            if current is None or stamp > current[0]:
                latest_before[key] = (stamp, item)
        else:
            current = first_after.get(key)
            if current is None or stamp < current[0]:
                first_after[key] = (stamp, item)
    edges = [item for _, item in latest_before.values()] + [item for _, item in first_after.values()]
    return edges + chosen


SIGNATURE_NUMBERS = re.compile(r"0x[0-9a-fA-F]+|\d+")


def message_signature(payload):
    """Payload with numbers masked, so repeats of the same log statement group together."""
    return SIGNATURE_NUMBERS.sub("#", payload.strip())[:160]


class DltDigest:
    """Compact overview of one ECU's DLT messages in the window, small enough for an agent to read."""

    GAP_SECONDS = 10
    MAX_SIGNATURES = 50_000

    def __init__(self, ecu, event):
        self.ecu = ecu
        self.event = event
        self.levels = Counter()
        self.per_minute = defaultdict(Counter)
        self.sources = {}
        self.signatures = {}
        self.dropped_signatures = 0
        self.gaps = []
        self.restarts = []
        self.previous_time = None
        self.first_time = None
        self.previous_uptime = {}

    def add(self, moment, level, apid, ctid, uptime, payload):
        minute = moment.replace(second=0, microsecond=0)
        self.per_minute[minute]["all"] += 1
        if self.first_time is None:
            self.first_time = moment
        if self.previous_time is not None and (moment - self.previous_time).total_seconds() > self.GAP_SECONDS:
            self.gaps.append((self.previous_time, moment))
        self.previous_time = moment
        if uptime is not None and level is not None:
            previous = self.previous_uptime.get(apid)
            if previous is not None and uptime < 60 and previous > uptime + 30:
                self.restarts.append((moment, apid, previous, uptime))
            self.previous_uptime[apid] = uptime
        if level is None:
            return
        self.levels[level] += 1
        if level not in ("fatal", "error", "warn"):
            return
        self.per_minute[minute][level] += 1
        source = self.sources.setdefault((apid, ctid, level), [0, moment, moment, payload[:200]])
        source[0] += 1
        source[2] = moment
        key = (apid, ctid, level, message_signature(payload))
        entry = self.signatures.get(key)
        if entry is None:
            if len(self.signatures) >= self.MAX_SIGNATURES:
                self.dropped_signatures += 1
                return
            self.signatures[key] = entry = [0, moment, moment, payload[:240]]
        entry[0] += 1
        entry[2] = moment

    def coverage(self, start, end):
        """One line saying which part of the window has messages."""
        if self.first_time is None:
            return "No messages in the window: the ECU was not logging (asleep, off, or the logger missed it)."
        parts = [f"Messages from {self.first_time:%H:%M:%S} to {self.previous_time:%H:%M:%S}."]
        if (self.first_time - start).total_seconds() > self.GAP_SECONDS:
            parts.append(f"Silent from the window start {start:%H:%M:%S} until {self.first_time:%H:%M:%S}.")
        if (end - self.previous_time).total_seconds() > self.GAP_SECONDS:
            parts.append(f"Silent from {self.previous_time:%H:%M:%S} until the window end {end:%H:%M:%S}.")
        return " ".join(parts)

    def restart_clusters(self):
        clusters = []
        for moment, apid, before, _ in sorted(self.restarts, key=lambda item: item[0]):
            if clusters and (moment - clusters[-1][0]).total_seconds() <= 60:
                clusters[-1][1].add(apid)
                clusters[-1][2] = max(clusters[-1][2], before)
            else:
                clusters.append([moment, {apid}, before])
        return clusters

    def markdown(self, start, end, files):
        lines = [
            f"# DLT digest: {self.ecu}",
            "",
            f"Window (UTC): {start:%Y-%m-%d %H:%M:%S} to {end:%Y-%m-%d %H:%M:%S}; event {self.event:%H:%M:%S}. "
            "Times are the logger's storage time (UTC). Built from all messages in the window (no cap).",
            "",
            "Files: " + (", ".join(f"`{Path(path).name}`" for path in files) or "none"),
            "",
            f"Coverage: {self.coverage(start, end)}",
            "",
            "## Totals by log level",
            "",
            "| Level | Messages |",
            "| --- | --- |",
        ]
        lines += [f"| {level} | {count:,} |" for level, count in self.levels.most_common()]
        lines += [
            "",
            "## ECU uptime restarts",
            "",
            "Applications whose DLT uptime fell back near zero (reset, reboot or wake-up), grouped within 60 s.",
            "",
        ]
        lines += [
            f"- {first:%H:%M:%S.%f}: {len(apids)} application(s), uptime before up to {before:,.1f} s: "
            + ", ".join(sorted(apids)[:30])
            for first, apids, before in self.restart_clusters()
        ] or ["- none"]
        lines += ["", f"## Logging gaps longer than {self.GAP_SECONDS} s (ECU silent, asleep or logger stopped)", ""]
        lines += [
            f"- {first:%H:%M:%S} -> {last:%H:%M:%S} ({(last - first).total_seconds():,.0f} s)" for first, last in self.gaps[:200]
        ] or ["- none"]
        lines += ["", "## Messages per minute", "", "| Minute | All | Fatal | Error | Warn |", "| --- | --- | --- | --- | --- |"]
        for minute in sorted(self.per_minute):
            counts = self.per_minute[minute]
            marker = " **event**" if minute == self.event.replace(second=0, microsecond=0) else ""
            lines.append(
                f"| {minute:%H:%M}{marker} | {counts['all']:,} | {counts['fatal']:,} | {counts['error']:,} | {counts['warn']:,} |"
            )
        lines += ["", "## Top fatal/error/warning sources", "",
                  "| APID | CTID | Level | Count | First | Last | Example |", "| --- | --- | --- | --- | --- | --- | --- |"]
        top = sorted(self.sources.items(), key=lambda item: (-LEVEL_RANK[item[0][2]], -item[1][0]))
        top = [item for item in top if item[0][2] != "warn"][:40] + [item for item in top if item[0][2] == "warn"][:25]
        for (apid, ctid, level), (count, first, last, example) in top:
            lines.append(
                f"| {apid} | {ctid} | {level} | {count:,} | {first:%H:%M:%S} | {last:%H:%M:%S} | {markdown_cell(example)} |"
            )
        lines += ["", "## Fatal/error messages by first appearance",
                  "", "Numbers are masked so repeats group together. New signatures close to the event are the best leads.",
                  "", "| First | Last | Count | APID | CTID | Level | Example |", "| --- | --- | --- | --- | --- | --- | --- |"]
        errors = sorted(
            ((key, value) for key, value in self.signatures.items() if key[2] != "warn"), key=lambda item: item[1][1]
        )
        for (apid, ctid, level, _), (count, first, last, example) in errors[:400]:
            lines.append(
                f"| {first:%H:%M:%S} | {last:%H:%M:%S} | {count:,} | {apid} | {ctid} | {level} | {markdown_cell(example)} |"
            )
        if len(errors) > 400:
            lines.append(f"\n{len(errors) - 400:,} more fatal/error signatures not listed; grep the text files.")
        if self.dropped_signatures:
            lines.append(f"\n{self.dropped_signatures:,} messages had signatures beyond the {self.MAX_SIGNATURES:,} tracked.")
        return "\n".join(lines) + "\n"


LEVEL_RANK = {"fatal": 3, "error": 2, "warn": 1}


def markdown_cell(text):
    return text.replace("|", "\\|").replace("\n", " ").strip()


def select_readouts(readouts, event, limit=MAX_READOUTS):
    """First readout after the event (it holds the post-event history), the last one before, and the newest."""
    stamped = [item for item in readouts if item.get("timestamp") is not None]
    after = [item for item in stamped if item["timestamp"] >= event]
    before = [item for item in stamped if item["timestamp"] < event]
    picks = [
        min(after, key=lambda item: item["timestamp"]) if after else None,
        max(before, key=lambda item: item["timestamp"]) if before else None,
        max(stamped, key=lambda item: item["timestamp"]) if stamped else None,
    ]
    selected = []
    for item in picks:
        if item is not None and item not in selected:
            selected.append(item)
    return selected[:limit]


def resolve_sddb(explicit=""):
    candidates = [explicit, os.environ.get("SAT_SDDB", "")]
    for candidate in candidates:
        if candidate:
            path = Path(candidate).expanduser()
            if not path.is_file():
                raise FileNotFoundError(f"SDDB not found: {path}")
            return path
    folders = [os.environ.get("SAT_SDDB_DIR", ""), str(Path.home() / "Downloads" / "sddb")]
    found = []
    for folder in folders:
        if folder and Path(folder).expanduser().is_dir():
            found += list(Path(folder).expanduser().glob("*.sddb"))
    if not found:
        return None
    return max(found, key=lambda item: item.stat().st_mtime)


def available_sddbs():
    folders = [os.environ.get("SAT_SDDB_DIR", ""), str(Path.home() / "Downloads" / "sddb")]
    found = {}
    for folder in folders:
        if folder and Path(folder).expanduser().is_dir():
            for path in Path(folder).expanduser().glob("*.sddb"):
                found[str(path.resolve())] = path.resolve()
    return sorted(found.values(), key=lambda item: item.stat().st_mtime, reverse=True)


class Collector:
    def __init__(self, folder, request, start, end, out=None):
        self.folder = Path(folder)
        self.request = request
        self.vin = request["vin"]
        self.event = utc_naive(jobs.parse_iso(request["event_time_utc"]))
        self.start, self.end = start, end
        self.out = out or self.folder / "collected"
        self.out.mkdir(parents=True, exist_ok=True)
        self.notes = []

    def note(self, text):
        print(text, flush=True)
        self.notes.append(text)

    # --- SAT readouts -------------------------------------------------------------------------

    def readouts(self, sddb="", explicit_readouts=()):
        from SAT_Readout_decoder.SAT_Readout_decoder import DidDecoderApp
        from streamlit_workflow import discover_vin_readouts

        target = self.out / "readouts"
        target.mkdir(exist_ok=True)
        parser = object.__new__(DidDecoderApp)
        if explicit_readouts:
            readouts = [
                {"label": file_name(path), "path": path, "timestamp": parser._parse_readout_timestamp(file_name(path))}
                for path in explicit_readouts
            ]
        else:
            items = discover_vin_readouts(self.vin, progress=lambda message: print(message, flush=True))
            readouts = [
                {**item, "timestamp": parser._parse_readout_timestamp(file_name(item["path"]))}
                for item in items
            ]
            index = ["# Readouts on the share", "", f"VIN {self.vin}: {len(readouts):,} readouts, newest first. "
                     "Capture times come from the file names (assumed UTC).", "",
                     "| Capture time | Path |", "| --- | --- |"]
            index += [
                f"| {item['timestamp'] or '?'} | `{item['path']}` |" for item in readouts
            ]
            (target / "index.md").write_text("\n".join(index) + "\n", encoding="utf-8")
            self.note(f"Readouts: {len(readouts):,} found on the share; list in `readouts/index.md`.")
            readouts = select_readouts(readouts, self.event)

        sddb_path = resolve_sddb(sddb)
        if sddb_path is None:
            self.note("Readouts: no SDDB found (set SAT_SDDB_DIR or pass --sddb), so nothing was decoded.")
            return
        self.note(f"Readouts: decoding {len(readouts)} with SDDB `{sddb_path.name}`.")
        for item in readouts:
            try:
                self._decode_readout(item, sddb_path, target)
            except Exception as error:  # one bad readout must not stop the others
                self.note(f"Readouts: could not decode `{item['path']}`: {error}")

    def _decode_readout(self, item, sddb_path, target):
        from streamlit_workflow import decode_sat_readout, parse_standby_report, read_selected_log, run_standby_summary
        from summary_report import build_summary_markdown

        name = file_name(item["path"])
        stem = Path(name).stem
        summary_file = target / f"{stem}_readout_summary.md"
        if summary_file.is_file() and (target / f"{stem}_decoded.log").is_file():
            self.note(f"Readouts: `{name}` already decoded.")
            return
        content = read_selected_log(item["path"])
        translated, blocks, _ = decode_sat_readout(content, name, str(sddb_path), sddb_path.name)
        (target / f"{stem}_decoded.log").write_text(translated, encoding="utf-8")
        code, output, error = run_standby_summary(translated)
        sections, notes = parse_standby_report(output) if code == 0 else ([], [])
        result = {
            "blocks": blocks,
            "translated_filename": f"{stem}_decoded.log",
            "standby_code": code,
            "standby_output": output,
            "standby_error": error,
        }
        summary_file.write_text(build_summary_markdown(result, sections, notes), encoding="utf-8")
        relation = "after" if item["timestamp"] and item["timestamp"] >= self.event else "before"
        self.note(
            f"Readouts: `{name}` (captured {item['timestamp']}, {relation} the event): {len(blocks):,} blocks; "
            f"summary `readouts/{summary_file.name}`, decoded `readouts/{stem}_decoded.log`."
        )

    # --- NUC archive (DLT, UART, Ethernet) ----------------------------------------------------

    def _nuc(self):
        with contextlib.redirect_stdout(io.StringIO()):
            import download_combine_NUC_dlt as nuc
        nuc.LOG_FILE = None
        nuc.VIN = self.vin
        list_start = self.start - CHUNK_LOOKAROUND
        list_end = self.end + CHUNK_LOOKAROUND
        nuc.START_DT, nuc.END_DT = list_start, list_end
        nuc.START_DATE = list_start.strftime("%Y-%m-%d")
        nuc.END_DATE = list_end.strftime("%Y-%m-%d")
        return nuc

    def _list(self, nuc, list_function, *args):
        files = []
        for day in nuc.iter_dates(nuc.START_DT, nuc.END_DT):
            files += list_function(*args, day)
        unique = {item["blob_path"]: item for item in files}
        return list(unique.values())

    def dlt(self, ecus=None):
        nuc = self._nuc()
        available = nuc.discover_available_ecus(self.vin)
        selected = [ecu for ecu in (ecus or available) if ecu in available]
        if not selected:
            self.note(f"DLT: no matching ECUs in the NUC archive (available: {', '.join(available) or 'none'}).")
            return
        files = []
        for ecu in selected:
            files += self._list(nuc, nuc.list_blob_files, ecu)
        files = select_covering_files(
            files, self.start, self.end, lambda item: item["ecu"], nuc.parse_file_timestamp_from_name
        )
        with_files = sorted({item["ecu"] for item in files})
        without = ", ".join(ecu for ecu in selected if ecu not in with_files)
        self.note(
            f"DLT: {len(files)} chunk(s) around the window for ECUs {', '.join(with_files) or 'none'}"
            + (f"; no chunks for {without}" if without else "")
            + ". Chunk file names are the chunk's last message time (UTC)."
        )
        dest = self.out / "nuc"
        for index, item in enumerate(files, 1):
            nuc.process_file(index, len(files), item, str(dest))
        text_dir = self.out / "dlt_text"
        text_dir.mkdir(exist_ok=True)
        for ecu in selected:
            dlt_files = sorted((dest / self.vin).glob(f"*/{ecu}/*.dlt"))
            if dlt_files:
                self._export_dlt(dlt_files, text_dir, ecu)

    def _export_dlt(self, dlt_files, text_dir, ecu):
        from pydlt.header import MessageLogInfo, MessageType
        import download_combine_NUC_dlt as nuc

        level_names = {
            MessageLogInfo.DLT_LOG_FATAL: "fatal",
            MessageLogInfo.DLT_LOG_ERROR: "error",
            MessageLogInfo.DLT_LOG_WARN: "warn",
            MessageLogInfo.DLT_LOG_INFO: "info",
            MessageLogInfo.DLT_LOG_DEBUG: "debug",
            MessageLogInfo.DLT_LOG_VERBOSE: "verbose",
        }
        start_seconds = self.start.replace(tzinfo=timezone.utc).timestamp()
        end_seconds = self.end.replace(tzinfo=timezone.utc).timestamp()
        event_seconds = self.event.replace(tzinfo=timezone.utc).timestamp()
        focus = EVENT_FOCUS.total_seconds()
        tag = f"{self.start:%Y%m%dT%H%M%S}-{self.end:%Y%m%dT%H%M%S}"
        all_path = text_dir / f"{ecu}_{tag}.txt"
        problems_path = text_dir / f"{ecu}_{tag}_errors.txt"
        focus_path = text_dir / f"{ecu}_event_{self.event:%H%M%S}_pm{int(focus // 60)}min.txt"
        digest_path = text_dir / f"{ecu}_{tag}_digest.md"
        (text_dir / f"{ecu}_{tag}_warnings_errors.txt").unlink(missing_ok=True)
        digest = DltDigest(ecu, self.event)
        total = written = problems = focused = 0
        # Chunks are processed oldest first and messages are streamed, never held in memory.
        with open(all_path, "w", encoding="utf-8") as all_file, open(
            problems_path, "w", encoding="utf-8"
        ) as bad_file, open(focus_path, "w", encoding="utf-8") as focus_file:
            for path in dlt_files:
                for message in nuc.safe_read_messages(path):
                    header = message.str_header
                    if header is None:
                        continue
                    seconds = header.seconds + header.microseconds / 1e6
                    if not start_seconds <= seconds <= end_seconds:
                        continue
                    total += 1
                    line = str(message)
                    if written < MAX_DLT_TEXT_LINES:
                        all_file.write(line + "\n")
                        written += 1
                    if abs(seconds - event_seconds) <= focus:
                        focus_file.write(line + "\n")
                        focused += 1
                    extended = message.ext_header
                    level = None
                    apid = ctid = ""
                    if extended is not None:
                        apid, ctid = extended.application_id, extended.context_id
                        if extended.message_type == MessageType.DLT_TYPE_LOG:
                            level = level_names.get(extended.message_log_info, "unknown")
                    if level in ("fatal", "error"):
                        bad_file.write(line + "\n")
                        problems += 1
                    uptime = message.std_header.timestamp
                    payload = ""
                    if level in ("fatal", "error", "warn") and message.payload is not None:
                        payload = str(message.payload)
                    digest.add(
                        datetime.fromtimestamp(seconds, timezone.utc).replace(tzinfo=None),
                        level,
                        apid,
                        ctid,
                        None if uptime is None else uptime / 10000,
                        payload,
                    )
        digest_path.write_text(digest.markdown(self.start, self.end, dlt_files), encoding="utf-8")
        self.note(
            f"DLT {ecu}: {total:,} messages in the window. {digest.coverage(self.start, self.end)} "
            f"Read the digest first: `dlt_text/{digest_path.name}` "
            f"({len(digest.restart_clusters())} uptime restart group(s), {len(digest.gaps)} logging gap(s)). "
            f"Event ±{int(focus // 60)} min: {focused:,} messages -> `dlt_text/{focus_path.name}`. "
            f"Fatal/error: {problems:,} -> `dlt_text/{problems_path.name}`. "
            f"All: `dlt_text/{all_path.name}`{f' (first {written:,} only)' if written < total else ''}. "
            "Times are the logger's storage time (UTC)."
        )

    def uart(self):
        nuc = self._nuc()
        files = self._list(nuc, nuc.list_uart_blob_files)
        files = select_covering_files(
            files, self.start, self.end,
            lambda item: nuc.parse_uart_usb_number(item["name"]) or "",
            nuc.parse_file_timestamp_from_name,
        )
        self.note(f"UART: {len(files)} file(s) cover the window.")
        if files:
            paths = nuc.download_selected_blob_files(files, str(self.out / "nuc"), "UART", decompress_zst=True)
            self.note("UART: saved " + ", ".join(f"`{Path(path).relative_to(self.out)}`" for path in paths))

    def pcap(self):
        nuc = self._nuc()
        files = self._list(nuc, nuc.list_eth_blob_files)
        files = select_covering_files(files, self.start, self.end, lambda item: "", nuc.parse_file_timestamp_from_name)
        self.note(f"Ethernet PCAP: {len(files)} file(s) cover the window.")
        if files:
            paths = nuc.download_selected_blob_files(files, str(self.out / "nuc"), "ETH")
            self.note(
                "Ethernet PCAP: saved " + ", ".join(f"`{Path(path).relative_to(self.out)}`" for path in paths)
                + ". Decode them with the PCAP decoder (WSL) or SOME/IP analyzer if needed."
            )

    # --- manifest ------------------------------------------------------------------------------

    def write_manifest(self):
        runs = self.out / "runs"
        runs.mkdir(exist_ok=True)
        number = len(list(runs.glob("*.md"))) + 1
        (runs / f"{number:03d}.md").write_text(
            f"## Collection run {number} ({jobs.iso(jobs.utc_now())})\n\n"
            f"Window (UTC): {self.start:%Y-%m-%d %H:%M:%S} to {self.end:%Y-%m-%d %H:%M:%S}\n\n"
            + "\n".join(f"- {note}" for note in self.notes) + "\n",
            encoding="utf-8",
        )
        lines = [
            "# Collected data", "",
            f"- VIN: {self.vin}",
            f"- Event time (UTC): {self.event:%Y-%m-%d %H:%M:%S}",
            "", "## Files", "", "| File | Size (bytes) |", "| --- | --- |",
        ]
        for path in sorted(self.out.rglob("*")):
            if path.is_file() and path.name != "manifest.md" and runs not in path.parents:
                lines.append(f"| `{path.relative_to(self.out).as_posix()}` | {path.stat().st_size:,} |")
        lines += [""]
        for run in sorted(runs.glob("*.md")):
            lines += [run.read_text(encoding="utf-8"), ""]
        (self.out / "manifest.md").write_text("\n".join(lines), encoding="utf-8")


def run(folder, minutes_before=None, minutes_after=None, sources=None, ecus=None, sddb=None, readouts=()):
    folder = Path(folder).resolve()
    root = jobs.jobs_root()
    if root not in folder.parents or not jobs.JOB_ID_PATTERN.match(folder.name):
        raise ValueError(f"{folder} is not a job folder below {root}.")
    request = jobs.read_json(folder / "request.json")
    if request is None:
        raise FileNotFoundError(f"No request.json in {folder}")
    event = utc_naive(jobs.parse_iso(request["event_time_utc"]))
    before = request["minutes_before"] if minutes_before is None else minutes_before
    after = request["minutes_after"] if minutes_after is None else minutes_after
    collector = Collector(folder, request, event - timedelta(minutes=before), event + timedelta(minutes=after))
    chosen = sources or request["sources"]
    steps = {
        "readouts": lambda: collector.readouts(sddb if sddb is not None else request.get("sddb", ""), readouts),
        "dlt": lambda: collector.dlt(ecus),
        "uart": collector.uart,
        "pcap": collector.pcap,
    }
    failures = 0
    for source in jobs.ALL_SOURCES:
        if source not in chosen:
            continue
        try:
            steps[source]()
        except Exception as error:  # report and continue with the other sources
            failures += 1
            collector.note(f"{source}: failed: {error}")
            traceback.print_exc()
    collector.write_manifest()
    return failures, len([source for source in chosen if source in steps])


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--job", required=True, help="Job folder (below the investigations root)")
    parser.add_argument("--minutes-before", type=float, help="Minutes before the event (default: from the request)")
    parser.add_argument("--minutes-after", type=float, help="Minutes after the event (default: from the request)")
    # nargs="+": PowerShell passes "dlt,uart" as two arguments, so accept spaces as well as commas.
    parser.add_argument("--sources", nargs="+", help=f"Subset of {','.join(jobs.ALL_SOURCES)} (comma or space separated)")
    parser.add_argument("--ecus", nargs="+", help="DLT ECUs, e.g. HPA,SGA (default: all in the archive)")
    parser.add_argument("--sddb", help="SDDB file used to decode readouts")
    parser.add_argument("--readout", action="append", default=[], help="Decode this readout path (repeatable)")
    args = parser.parse_args(argv)
    if args.sources:
        args.sources = [item.strip().lower() for item in ",".join(args.sources).split(",") if item.strip()]
        unknown = set(args.sources) - set(jobs.ALL_SOURCES)
        if unknown:
            parser.error(f"Unknown source(s): {', '.join(sorted(unknown))}")
    if args.ecus:
        args.ecus = [item.strip().upper() for item in ",".join(args.ecus).split(",") if item.strip()]
    for name in ("minutes_before", "minutes_after"):
        value = getattr(args, name)
        if value is not None and not 0 <= value <= 24 * 60:
            parser.error(f"--{name.replace('_', '-')} must be between 0 and 1440")
    return args


def main(argv=None):
    args = parse_args(argv)
    failures, attempted = run(
        args.job, args.minutes_before, args.minutes_after, args.sources, args.ecus, args.sddb, args.readout
    )
    print(json.dumps({"failed_sources": failures, "attempted_sources": attempted}))
    return 1 if attempted and failures == attempted else 0


if __name__ == "__main__":
    sys.exit(main())
