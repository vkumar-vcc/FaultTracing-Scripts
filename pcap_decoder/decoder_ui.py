from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parent
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".pcap.zst", ".pcapng.zst")
SDB_PROJECTS = {"SPA2": "p519", "SPA3": "gpa"}
ARTIFACTORY_HOST = "ara-artifactory.volvocars.biz"
TOKEN_UPDATER = Path.home() / ".local" / "TokenUpdater" / "TokenUpdater"


def _netrc_token(host: str = ARTIFACTORY_HOST) -> str:
    """Password/token for ``host`` from ~/.netrc (kept fresh by Artifactory TokenUpdater).

    Parsed tolerantly to avoid netrc's file-permission SecurityError.
    """
    for name in (".netrc", "_netrc"):
        path = Path.home() / name
        if not path.is_file():
            continue
        try:
            words = path.read_text(encoding="utf-8", errors="ignore").split()
        except OSError:
            return ""
        current = None
        index = 0
        while index < len(words):
            word = words[index]
            if word == "machine" and index + 1 < len(words):
                current = words[index + 1]
                index += 2
                continue
            if word == "default":
                current = host  # default entry applies to any host
                index += 1
                continue
            if word == "password" and index + 1 < len(words) and current == host:
                return words[index + 1].strip()
            index += 1
    return ""


def resolve_configured_token() -> str:
    """Server-side Artifactory token: env var, then token file, then ~/.netrc."""
    token = (os.environ.get("ARTIFACTORY_TOKEN")
             or os.environ.get("ARTIFACTORY_API_KEY") or "").strip()
    if token:
        return token
    path = (os.environ.get("ARTIFACTORY_TOKEN_FILE") or "").strip()
    if path:
        try:
            return Path(path).expanduser().read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return _netrc_token()


def refresh_artifactory_token(timeout: int = 45) -> str:
    """Run Artifactory TokenUpdater to renew ~/.netrc, then return the fresh token."""
    if not TOKEN_UPDATER.is_file():
        raise FileNotFoundError(f"TokenUpdater not found at {TOKEN_UPDATER}")
    env = os.environ.copy()
    env.setdefault("GCM_CREDENTIAL_STORE", "gpg")
    result = subprocess.run([str(TOKEN_UPDATER), "refresh"], capture_output=True,
                            text=True, timeout=timeout, env=env)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "TokenUpdater refresh failed").strip())
    token = resolve_configured_token()
    if not token:
        raise RuntimeError("Token refreshed but no credential found in ~/.netrc.")
    return token


def list_sdb_versions(platform: str, token: str) -> list[str]:
    from mrc_decoder.python.sdb_fetcher import SdbFetcher

    fetcher = SdbFetcher(token)
    try:
        return fetcher.list_versions(SDB_PROJECTS[platform])
    finally:
        fetcher._session.close()


def download_sdb(platform: str, version: str, token: str) -> tuple[Path, Path]:
    from mrc_decoder.python.sdb_fetcher import ArtifactoryError, fetch_sdb
    from mrc_decoder.python.sdb_fetcher.gpa_complete import fetch_databases

    if not token.strip():
        raise ValueError("Enter your Artifactory API key before downloading an SDB.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version):
        raise ValueError("Choose a valid SDB version.")
    project = SDB_PROJECTS[platform]
    if project == "gpa":
        db_dir, files = fetch_databases(project, version, token)
        manifest = db_dir.parent / "manifest.yaml"
    else:
        result = fetch_sdb(version, token, project=project)
        db_dir, files, manifest = result.db_dir, result.db_files, result.manifest_path
    if not files or not manifest or not manifest.is_file():
        raise ArtifactoryError("The SDB download returned no databases or manifest.")
    return db_dir, manifest


def list_pdu_config_versions() -> list[str]:
    """SPA3 versions that already have a generated PDU config or extracted sources."""
    from mrc_decoder.python.sdb_fetcher.gpa_complete import PDU_SOURCE_PATTERNS
    from mrc_decoder.python.spa2_decoder.pdu_generate import OUTPUT_FILES

    root = Path.home() / ".cache" / "mrc_decoder" / "sdb"
    versions = []
    for path in sorted(root.glob("gpa_*")) if root.exists() else []:
        pdu = path / "pdu"
        source = path / "source"
        has_pdu = all((pdu / name).is_file() for name in OUTPUT_FILES)
        has_source = source.is_dir() and all(
            any(pattern.search(item.name) for item in source.glob("*"))
            for pattern in PDU_SOURCE_PATTERNS.values())
        if has_pdu or has_source:
            versions.append(path.name.removeprefix("gpa_"))
    return sorted(set(versions),
                  key=lambda value: tuple(map(int, re.findall(r"\d+", value))), reverse=True)


def _count_pdu_config(target: Path) -> dict:
    def data_lines(name: str) -> int:
        return sum(1 for line in (target / name).read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.lstrip().startswith("#"))
    ports = sum(1 for line in (target / "decode_as_entries").read_text(encoding="utf-8").splitlines()
                if "PDU Transport" in line)
    return {"pdus": data_lines("Signal_PDU_Binding_PDU_Transport_ETH"),
            "signals": data_lines("Signal_PDU_signal_list_ETH"), "ports": ports}


def generate_pdu_config(version: str, token: str = "", out_dir: str | Path | None = None) -> dict:
    """Ensure a SPA3 PDU config exists, downloading and generating only when missing."""
    from mrc_decoder.python.sdb_fetcher.gpa_complete import PDU_SOURCE_PATTERNS, fetch_pdu_sources
    from mrc_decoder.python.spa2_decoder.pdu_generate import OUTPUT_FILES, generate

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version):
        raise ValueError("Choose a valid SDB version.")
    root = Path.home() / ".cache" / "mrc_decoder" / "sdb" / f"gpa_{version}"
    target = Path(out_dir) if out_dir else root / "pdu"
    cached = all((target / name).is_file() for name in OUTPUT_FILES)
    if not cached:
        source = root / "source"
        items = list(source.glob("*")) if source.is_dir() else []
        have_sources = all(any(pattern.search(item.name) for item in items)
                           for pattern in PDU_SOURCE_PATTERNS.values())
        if not have_sources and not token.strip():
            raise ValueError("Enter your Artifactory API key to download SDB sources "
                             "for first-time PDU generation.")
        arxml, backbone_csv = fetch_pdu_sources("gpa", version, token)
        generate(arxml, backbone_csv, target)
    result = _count_pdu_config(target)
    result.update(out_dir=str(target), version=version, cached=cached)
    return result


def linux_path(value: str) -> Path:
    value = value.strip().strip('"')
    if re.match(r"^[A-Za-z]:[\\/]", value):
        value = f"/mnt/{value[0].lower()}/{value[3:].replace(chr(92), '/')}"
    path = Path(value).expanduser()
    return path if path.is_absolute() else ROOT / path


def collect_inputs(value: str) -> list[Path]:
    files = set()
    for line in value.splitlines():
        if not line.strip():
            continue
        path = linux_path(line)
        if path.is_dir():
            files.update(
                item for item in path.iterdir()
                if item.is_file() and item.name.endswith(CAPTURE_SUFFIXES)
            )
        elif path.is_file() and path.name.endswith(CAPTURE_SUFFIXES):
            files.add(path)
        else:
            raise ValueError(f"Capture not found or unsupported: {path}")
    if not files:
        raise ValueError("Select at least one PCAP/PCAPNG capture or capture directory.")
    return sorted(files)


def build_command(inputs: str, db: str, manifest: str, output: Path,
                  someip: bool, per_file: bool, keep_all: bool, csv: bool,
                  routing_table: str | None, max_packets: int,
                  pdu_config: str | None = None, mrc_enabled: bool = True) -> list[str]:
    files = collect_inputs(inputs)
    db_dir = linux_path(db)
    manifest_path = linux_path(manifest)
    if mrc_enabled and (not db.strip() or not db_dir.is_dir()):
        raise ValueError(f"SDB database directory not found: {db_dir}")
    if mrc_enabled and (not manifest.strip() or not manifest_path.is_file()):
        raise ValueError(f"SDB manifest not found: {manifest_path}")
    if any(path.name.endswith(".zst") for path in files) and not shutil.which("zstd"):
        raise ValueError("Compressed captures require zstd. Install it in WSL: sudo apt install zstd")
    if not (mrc_enabled or someip or pdu_config):
        raise ValueError("Enable at least one decoder: MRC, PDU, or SOME/IP.")
    command = [sys.executable, "-u", "-m", "spa2_decoder", *map(str, files), "-o", str(output)]
    if mrc_enabled:
        command.extend(["--db-dir", str(db_dir), "--manifest", str(manifest_path),
                        "--routing-dir", str(ROOT / "SPA2_MRC_routing")])
    else:
        command.append("--no-mrc")
    if pdu_config is not None:
        if not pdu_config.strip():
            raise ValueError("PDU configuration directory cannot be empty.")
        config_dir = linux_path(pdu_config)
        required = ("Signal_PDU_identifiers_ETH", "Signal_PDU_Binding_PDU_Transport_ETH",
                    "Signal_PDU_signal_list_ETH", "decode_as_entries")
        if any(not (config_dir / name).is_file() for name in required):
            raise ValueError(f"PDU configuration files are missing: {config_dir}")
        command.extend(["--pdu-config", str(config_dir)])
    for enabled, flag in ((someip, "--someip"), (per_file, "--per-file"),
                          (keep_all, "--keep-all"), (csv, "--csv")):
        if enabled:
            command.append(flag)
    if someip:
        services = ROOT / "rim_ecu_signals/interfaces/services"
        pb2 = ROOT / "rim_ecu_signals/python_bindings/rim_ecu_signals/proto"
        if not services.is_dir() or not pb2.is_dir():
            raise ValueError("Bundled SOME/IP service definitions or protobuf bindings are missing.")
        command.extend(["--someip-services-dir", str(services),
                        "--someip-pb2-dir", str(pb2)])
    if routing_table:
        command.extend(["--routing-table", routing_table])
    if max_packets:
        command.extend(["--max-packets", str(max_packets)])
    return command


class DecodeJob:
    def __init__(self, command: list[str], output: Path):
        self.output = output
        self.output.mkdir(parents=True, exist_ok=True)
        self.log_path = output / "decode.log"
        self.temp_dir = tempfile.mkdtemp(prefix="pcap_ui_")
        self.started = time.monotonic()
        self.finished = None
        self.cancelled = False
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(filter(None, (
            str(ROOT / "mrc_decoder/python"), env.get("PYTHONPATH"))))
        env["TMPDIR"] = self.temp_dir
        try:
            with self.log_path.open("wb") as log:
                self.process = subprocess.Popen(
                    command, cwd=ROOT, env=env, stdout=log,
                    stderr=subprocess.STDOUT, start_new_session=True,
                )
        except Exception:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            raise

    def poll(self) -> int | None:
        code = self.process.poll()
        if code is not None and self.finished is None:
            self.finished = time.monotonic()
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        return code

    def cancel(self) -> None:
        if self.poll() is None:
            self.cancelled = True
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
            except ProcessLookupError:
                self.process.wait()
            self.poll()

    def log_tail(self) -> str:
        with self.log_path.open("rb") as log:
            log.seek(max(0, self.log_path.stat().st_size - 32768))
            return log.read().decode("utf-8", errors="replace")

    def elapsed(self) -> int:
        return int((self.finished or time.monotonic()) - self.started)


def new_output_dir(value: str) -> Path:
    if not value.strip():
        raise ValueError("Output directory cannot be empty.")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    return linux_path(value) / f"decode_{stamp}_{uuid4().hex[:8]}"


def save_uploaded_files(files, dest_dir: str | Path | None = None) -> str:
    """Persist uploaded captures server-side; return newline-joined paths for decoding."""
    if not files:
        return ""
    target = Path(dest_dir) if dest_dir else Path(tempfile.gettempdir()) / "pcap_ui_uploads"
    target.mkdir(parents=True, exist_ok=True)
    saved = []
    for item in files:
        data = item.getbuffer() if hasattr(item, "getbuffer") else item.read()
        dest = target / os.path.basename(item.name)
        if not dest.exists() or dest.stat().st_size != len(data):
            dest.write_bytes(bytes(data))
        saved.append(str(dest))
    return "\n".join(saved)