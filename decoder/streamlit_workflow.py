import contextlib
import hashlib
import io
import os
import pickle
import re
import subprocess
import sys
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import RLock

# The app lives in decoder/; the SAT decoder package and standby decoder are at the repository root.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import smbclient  # noqa: E402
from smbprotocol.exceptions import SMBException  # noqa: E402

from SAT_Readout_decoder import SAT_Readout_decoder as sat_module  # noqa: E402
from SAT_Readout_decoder.SAT_Readout_decoder import (  # noqa: E402
    APP_VERSION,
    DidDecoderApp,
    FolderMemory,
    VIN_READOUT_ROOT,
    build_full_sddb_data,
    decode_readout_content,
    ntpath,
    readout_isdir,
)


STANDBY_DECODER = ROOT / "standby-decoder" / "hpa_stanby_decoder.py"

# Changes whenever the decoder code changes, so cached results never outlive the logic that made them.
DECODER_STAMP = f"{APP_VERSION}|{Path(sat_module.__file__).stat().st_mtime_ns}"
SDDB_INDEX_CACHE_VERSION = 1
SDDB_INDEX_FILES_TO_KEEP = 6

_CACHE_LOCK = RLock()
_SDDB_INDEXES = OrderedDict()
_TRANSLATIONS = OrderedDict()
_STANDBY_SUMMARIES = OrderedDict()


def _remember(store, key, value, limit):
    store[key] = value
    store.move_to_end(key)
    while len(store) > limit:
        store.popitem(last=False)


def sddb_cache_directory():
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".cache")
    directory = Path(base) / "FaultTracing-Scripts" / "sddb-index"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def sddb_file_identity(path):
    resolved = Path(path).resolve()
    stat = resolved.stat()
    return f"{resolved}|{stat.st_size}|{stat.st_mtime_ns}"


def load_sddb_index(sddb_path, identity=None, progress=None):
    """Return a fully parsed SDDB index and where it came from: memory, disk, or newly built.

    The index covers every ECU, DID, and DTC in the file, so it is parsed once per SDDB
    and then reused for any readout.
    """
    report = progress or (lambda message: None)
    identity = identity or sddb_file_identity(sddb_path)
    key = uploaded_signature("sddb-index", SDDB_INDEX_CACHE_VERSION, DECODER_STAMP, identity)

    with _CACHE_LOCK:
        if key in _SDDB_INDEXES:
            _SDDB_INDEXES.move_to_end(key)
            return _SDDB_INDEXES[key], "in-memory"

        cache_file = sddb_cache_directory() / f"{key}.pkl"
        if cache_file.is_file():
            report("Loading the cached SDDB index from disk...")
            started = time.monotonic()
            try:
                with open(cache_file, "rb") as handle:
                    index = pickle.load(handle)
            except (OSError, EOFError, pickle.PickleError, AttributeError, ImportError):
                cache_file.unlink(missing_ok=True)
            else:
                _remember(_SDDB_INDEXES, key, index, 2)
                os.utime(cache_file)
                report(f"Cached SDDB index loaded in {time.monotonic() - started:.1f} s.")
                return index, "cached"

        report(
            "First use of this SDDB: indexing every ECU, DID, and DTC once "
            "(about 30 s for a large file). Later readouts will reuse it."
        )
        started = time.monotonic()
        with contextlib.redirect_stdout(io.StringIO()):
            index = build_full_sddb_data(sddb_path)
        report(f"SDDB indexed in {time.monotonic() - started:.1f} s; saving it for next time.")
        temporary = cache_file.with_suffix(".tmp")
        try:
            with open(temporary, "wb") as handle:
                pickle.dump(index, handle, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(temporary, cache_file)
            for stale in sorted(
                cache_file.parent.glob("*.pkl"),
                key=lambda item: item.stat().st_mtime,
                reverse=True,
            )[SDDB_INDEX_FILES_TO_KEEP:]:
                stale.unlink(missing_ok=True)
        except OSError:
            temporary.unlink(missing_ok=True)
        _remember(_SDDB_INDEXES, key, index, 2)
        return index, "newly built"


def uploaded_signature(*parts):
    digest = hashlib.sha256()
    for part in parts:
        if isinstance(part, bytes):
            digest.update(part)
        else:
            digest.update(str(part).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


READOUT_SUFFIXES = ("_responses.yaml", "_responses.yml", "_responses.log")
READOUT_EXTENSION_RANK = {".log": 0, ".yaml": 1, ".yml": 2}
SCAN_WORKERS = 16


def _scan_directory(path):
    return [(entry.name, entry.is_dir()) for entry in smbclient.scandir(path)]


def _scan_directory_or_empty(path):
    try:
        return _scan_directory(path)
    except (OSError, SMBException):
        return []


def _collect_readouts_parallel(vin_folder, top_level, decoder, report):
    """Walk the VIN folder one level at a time, listing each level's folders concurrently."""
    grouped = {}
    directories = []

    def handle(directory, entries):
        for name, is_directory in entries:
            path = ntpath.join(directory, name)
            if is_directory:
                directories.append(path)
                continue
            if not name.lower().endswith(READOUT_SUFFIXES):
                continue
            base_name, extension = ntpath.splitext(name)
            rank = READOUT_EXTENSION_RANK.get(extension.lower(), 99)
            current = grouped.get(base_name)
            if current is None or rank < current["rank"]:
                timestamp = decoder._parse_readout_timestamp(name)
                grouped[base_name] = {
                    "path": path,
                    "timestamp": timestamp,
                    "rank": rank,
                    "sort_key": timestamp or datetime.min,
                }

    handle(vin_folder, top_level)
    scanned = 1
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        while directories:
            level = directories
            directories = []
            report(
                f"Scanning {len(level):,} folders in parallel "
                f"({scanned:,} done, {len(grouped):,} readouts found)..."
            )
            for directory, entries in zip(level, pool.map(_scan_directory_or_empty, level)):
                handle(directory, entries)
            scanned += len(level)

    return sorted(
        grouped.values(),
        key=lambda item: (item["sort_key"], item["path"]),
        reverse=True,
    )


def discover_vin_readouts(
    vin, username="", password="", remember_credentials=False, progress=None
):
    normalized_vin = vin.strip().upper()
    if not normalized_vin:
        raise ValueError("Enter a VIN before loading readouts.")
    if bool(username) != bool(password):
        raise ValueError("Enter both an SMB username and password, or leave both blank.")

    started = time.monotonic()
    report = progress or (lambda message: None)
    report("Checking saved share credentials...")
    folder_memory = FolderMemory()
    saved_username, saved_password = folder_memory.get_smb_credentials()
    selected_username = username or saved_username
    selected_password = password or saved_password

    if selected_username and selected_password:
        report(f"Signing in to the readout share as {selected_username}...")
        server = VIN_READOUT_ROOT.lstrip("\\").split("\\")[0]
        try:
            smbclient.register_session(
                server,
                username=selected_username,
                password=selected_password,
            )
        except Exception as error:
            raise RuntimeError(f"Could not authenticate to the readout share: {error}") from error

    vin_folder = ntpath.join(VIN_READOUT_ROOT, normalized_vin)
    try:
        report(f"Opening the VIN folder `{normalized_vin}` on the readout share...")
        try:
            top_level = _scan_directory(vin_folder)
        except (OSError, SMBException):
            if not readout_isdir(VIN_READOUT_ROOT):
                raise FileNotFoundError(
                    f"Readout share is not accessible: {VIN_READOUT_ROOT}"
                ) from None
            raise FileNotFoundError(
                f"No readout folder was found for VIN {normalized_vin}."
            ) from None
        decoder = object.__new__(DidDecoderApp)
        readouts = _collect_readouts_parallel(
            vin_folder, top_level, decoder, report
        )
    except FileNotFoundError:
        raise
    except (OSError, SMBException) as error:
        raise RuntimeError(f"Could not load readouts from the network share: {error}") from error

    if remember_credentials and username and password:
        folder_memory.save_smb_credentials(username, password)

    items = []
    for readout in readouts:
        label = decoder._build_readout_label(
            readout["path"], readout["timestamp"]
        )
        items.append({"label": label, "path": readout["path"]})
    if not items:
        raise FileNotFoundError(f"No readout files were found for VIN {normalized_vin}.")
    report(
        f"Found {len(items):,} readouts in {time.monotonic() - started:.1f} s."
    )
    return items


def decode_sat_readout(
    log_content,
    log_filename,
    sddb_path,
    sddb_filename,
    sddb_identity=None,
    progress=None,
):
    report = progress or (lambda message: None)
    identity = sddb_identity or sddb_file_identity(sddb_path)
    result_key = uploaded_signature(
        "translation", DECODER_STAMP, log_filename, log_content, identity
    )
    with _CACHE_LOCK:
        cached = _TRANSLATIONS.get(result_key)
        if cached is not None:
            _TRANSLATIONS.move_to_end(result_key)
    if cached is not None:
        report("Using the cached translation of this readout (nothing to recompute).")
        return cached

    sddb_data, source = load_sddb_index(sddb_path, identity, report)
    report(
        f"Translating the readout with the {source} SDDB index..."
    )
    started = time.monotonic()
    diagnostics = io.StringIO()
    with contextlib.redirect_stdout(diagnostics):
        output, blocks = decode_readout_content(
            log_content, log_filename, sddb_path, sddb_filename, sddb_data=sddb_data
        )
    report(f"Translation finished in {time.monotonic() - started:.1f} s.")
    result = (output, blocks, diagnostics.getvalue())
    with _CACHE_LOCK:
        _remember(_TRANSLATIONS, result_key, result, 6)
    return result


def run_standby_summary(
    translated_log,
    watchdog_details=False,
    no_error_reference=False,
):
    summary_key = uploaded_signature(
        "standby", translated_log, watchdog_details, no_error_reference,
        STANDBY_DECODER.stat().st_mtime_ns,
    )
    with _CACHE_LOCK:
        cached = _STANDBY_SUMMARIES.get(summary_key)
        if cached is not None:
            _STANDBY_SUMMARIES.move_to_end(summary_key)
    if cached is not None:
        return cached

    with TemporaryDirectory(prefix="faulttracing-standby-") as directory:
        log_path = Path(directory) / "sat_readout_decoded.log"
        log_path.write_text(translated_log, encoding="utf-8")
        command = [
            sys.executable,
            str(STANDBY_DECODER),
            "--input-file",
            str(log_path),
        ]
        if watchdog_details:
            command.append("--watchdog-details")
        if no_error_reference:
            command.append("--no-error-reference")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
                # A very wide virtual terminal keeps every table row on a single line.
                env={**os.environ, "COLUMNS": "100000"},
            )
        except subprocess.TimeoutExpired as error:
            raise TimeoutError(
                "Readout summary exceeded the 5-minute time limit."
            ) from error
        except OSError as error:
            raise RuntimeError(f"Could not start the readout summary decoder: {error}") from error
    outcome = (result.returncode, result.stdout, result.stderr)
    if result.returncode == 0:
        with _CACHE_LOCK:
            _remember(_STANDBY_SUMMARIES, summary_key, outcome, 6)
    return outcome


def _table_cells(line, boundaries):
    return [
        line[left + 2:right - 1].strip()
        for left, right in zip(boundaries, boundaries[1:])
    ]


def _merge_wrapped_cells(lines, boundaries):
    rows = [_table_cells(line, boundaries) for line in lines if line.startswith("|")]
    if not rows:
        return []
    return [
        " ".join(row[column] for row in rows if row[column]).strip()
        for column in range(len(rows[0]))
    ]


def _is_table_border(line):
    return re.fullmatch(r"\+(?:-+\+)+", line) is not None


def _table_kind(headers):
    normalized = " ".join(headers).lower()
    if headers and headers[0] == "#":
        return "events"
    if headers and headers[0] == "Slot":
        return "fe03_slots" if "reporter id" in normalized else "fe03_details"
    if "timestamp (utc)" in normalized and "state" in normalized:
        return "transitions"
    if "latest event" in normalized and "dtc" in normalized:
        return "dtc"
    if "application" in normalized and "failures" in normalized:
        return "watchdog"
    if "application" in normalized and "timestamp" in normalized:
        return "watchdog"
    return "other"


def _parse_table_block(block_lines):
    """Turn one bordered ASCII table (possibly with wrapped rows) into headers and row dicts."""
    boundaries = [position for position, char in enumerate(block_lines[0]) if char == "+"]
    groups = []
    current = []
    for line in block_lines:
        if _is_table_border(line):
            if current:
                groups.append(current)
            current = []
        elif line.startswith("|"):
            current.append(line)
    if current:
        groups.append(current)
    if not groups or len(boundaries) < 2:
        return [], []

    headers = _merge_wrapped_cells(groups[0], boundaries)
    body_groups = groups[1:]
    row_groups = []
    if len(body_groups) > 1:
        row_groups = body_groups
    else:
        for line in (body_groups[0] if body_groups else []):
            if _table_cells(line, boundaries)[0] or not row_groups:
                row_groups.append([line])
            else:
                row_groups[-1].append(line)

    rows = []
    for group in row_groups:
        values = _merge_wrapped_cells(group, boundaries)
        if values and values[0]:
            rows.append({
                header: values[position] if position < len(values) else ""
                for position, header in enumerate(headers)
            })
    return headers, rows


def _section_title(context):
    for position, line in enumerate(context):
        if line.endswith(":"):
            title = re.sub(r"\s*\(non-empty\)\s*$", "", line[:-1]).strip()
            return title, context[:position] + context[position + 1:]
    return "", context


def parse_standby_report(report):
    """Split the report into titled sections, rendering each ASCII table as rows of data."""
    lines = [line.rstrip() for line in report.splitlines()]
    sections = []
    notes = []
    context = []
    index = 0

    def flush_text(text_lines):
        if not text_lines:
            return
        title, rest = _section_title(text_lines)
        if title:
            sections.append({
                "heading": title,
                "kind": "text",
                "description": rest,
                "headers": [],
                "rows": [],
                "footnotes": [],
            })
        else:
            notes.extend(rest)

    while index < len(lines):
        line = lines[index]
        if _is_table_border(line):
            end = index
            while end < len(lines) and lines[end].startswith(("+", "|")):
                end += 1
            headers, rows = _parse_table_block(lines[index:end])
            title, description = _section_title(context)
            context = []
            footnotes = []
            while end < len(lines) and lines[end].strip() and not _is_table_border(lines[end]):
                footnotes.append(lines[end].strip())
                end += 1
            kind = _table_kind(headers)
            if not title:
                title = "Standby events" if kind == "events" else "Details"
            sections.append({
                "heading": title,
                "kind": kind,
                "description": description,
                "headers": headers,
                "rows": rows,
                "footnotes": footnotes,
            })
            index = end
            continue
        if line.strip():
            context.append(line.strip())
        else:
            flush_text(context)
            context = []
        index += 1
    flush_text(context)
    return sections, notes


def read_selected_log(path):
    from SAT_Readout_decoder.SAT_Readout_decoder import readout_open

    with readout_open(path, "r", encoding="utf-8", errors="ignore") as log_file:
        return log_file.read()
