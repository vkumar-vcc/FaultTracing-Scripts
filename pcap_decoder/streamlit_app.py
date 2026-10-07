from pathlib import Path
import re
import shlex
import warnings

# WSL emulates numpy.longdouble; its import-time probe emits a benign UserWarning.
warnings.filterwarnings("ignore", message=r"Signature .* for <class 'numpy\.longdouble'>",
                        category=UserWarning)

import pandas as pd  # noqa: E402
import requests  # noqa: E402
import streamlit as st  # noqa: E402
from streamlit.errors import StreamlitSecretNotFoundError  # noqa: E402

from decoder_ui import (ROOT, SDB_PROJECTS, DecodeJob, build_command, download_sdb,  # noqa: E402
                        generate_pdu_config, list_pdu_config_versions, list_sdb_versions,
                        new_output_dir, refresh_artifactory_token, resolve_configured_token,
                        save_uploaded_files)
from mrc_decoder.python.sdb_fetcher import ArtifactoryError  # noqa: E402


st.set_page_config(page_title="PCAP decoder", page_icon=":material/lan:", layout="wide")
st.session_state.setdefault("job", None)

st.title("PCAP decoder")
st.badge("WSL / Ethernet", icon=":material/lan:")

cached_sdbs = sorted((Path.home() / ".cache/mrc_decoder/sdb").glob("*/manifest.yaml"))
st.session_state.setdefault("sdb_db", "")
st.session_state.setdefault("sdb_manifest", "")
st.session_state.setdefault("sdb_versions", {})
st.session_state.setdefault("sdb_version_errors", {})
pending_selection = st.session_state.pop("sdb_pending_selection", None)
if pending_selection:
    pending_platform, pending_version = pending_selection
    st.session_state[f"existing_sdb_version_{pending_platform}"] = pending_version
    st.session_state.pop("sdb_existing_selection", None)
job = st.session_state.job
running = job is not None and job.poll() is None
st.session_state.setdefault("pdu_config_dir", str(ROOT / "SPA3_PDU"))
pending_pdu_config = st.session_state.pop("pdu_config_pending", None)
if pending_pdu_config:
    st.session_state["pdu_config_dir"] = pending_pdu_config

with st.sidebar:
    st.header("Decode settings")
    platform = st.selectbox("SDB platform", list(SDB_PROJECTS), key="sdb_platform",
                            disabled=running)
    mrc_enabled = platform == "SPA2"
    pdu_enabled = platform == "SPA3"
    st.caption("Decoding " + ("MRC CAN/LIN" if mrc_enabled else "SPA3 signal PDUs")
               + " (set by platform)")
    someip = st.toggle("Also decode SOME/IP", value=True, disabled=running)
    mode = st.segmented_control("Output mode", ["Merged", "Per capture"],
                                default="Merged", disabled=running)
    keep_all = st.toggle("Keep unchanged samples", disabled=running)
    csv_output = st.toggle("Export long-format CSV", disabled=running)
    if mrc_enabled:
        tables = sorted(path.name for path in (ROOT / "SPA2_MRC_routing").glob("*.yml"))
        routing = st.selectbox("Routing table", ["Automatic", *tables], disabled=running)
    else:
        routing = "Automatic"
    max_packets = st.number_input("Packet limit (0 = all)", min_value=0,
                                  value=0, step=10000, disabled=running)

st.subheader("Captures")
capture_source = st.segmented_control("Capture source", ["Server path", "Upload"],
                                     default="Server path", disabled=running)
if capture_source == "Upload":
    uploaded = st.file_uploader("Upload captures", type=["pcap", "pcapng", "zst"],
                                accept_multiple_files=True, disabled=running,
                                help="For deployed use. Large captures upload slowly; "
                                     "prefer a server path when running locally.")
    inputs = save_uploaded_files(uploaded)
    if inputs:
        st.caption(f"{len(inputs.splitlines())} capture(s) uploaded.")
else:
    inputs = st.text_area("Capture files or directories", height=110, disabled=running,
                          placeholder="/mnt/c/workspace/logs/capture.pcapng.zst",
                          help="Path(s) on the machine running this app, one per line. "
                               "Directories are decoded non-recursively.")
st.subheader("Database and output")
configured_token = resolve_configured_token()
if not configured_token:
    try:
        configured_token = (st.secrets.get("ARTIFACTORY_TOKEN")
                            or st.secrets.get("ARTIFACTORY_API_KEY") or "").strip()
    except StreamlitSecretNotFoundError:
        configured_token = ""
if configured_token:
    with st.container(horizontal=True):
        st.caption("Using Artifactory TokenUpdater credential; no API key needed.")
        if st.button("Refresh token", icon=":material/key:", disabled=running):
            try:
                with st.spinner("Refreshing Artifactory token..."):
                    refresh_artifactory_token()
                st.rerun()
            except Exception as exc:  # noqa: BLE001 - surface any TokenUpdater failure
                st.error(str(exc))

if platform == "SPA2":
    existing_column, download_column = st.columns(2, gap="large")
    with existing_column:
        st.subheader("Existing SDB")
        local_versions = [path.parent.name.removeprefix("p519_")
                          for path in cached_sdbs
                          if path.parent.name.startswith("p519_")
                          and (path.parent / "db").is_dir()]
        local_versions = sorted(set(local_versions),
                                key=lambda value: tuple(map(int, re.findall(r"\d+", value))),
                                reverse=True)
        existing_version = st.selectbox("Installed version", local_versions,
                                        index=0 if local_versions else None,
                                        key="existing_sdb_version_SPA2",
                                        disabled=running or not local_versions,
                                        placeholder="No installed versions")
        selection = ("SPA2", existing_version)
        if not running and selection != st.session_state.get("sdb_existing_selection"):
            st.session_state.sdb_existing_selection = selection
            if existing_version:
                cached = Path.home() / ".cache/mrc_decoder/sdb" / f"p519_{existing_version}"
                st.session_state.sdb_db = str(cached / "db")
                st.session_state.sdb_manifest = str(cached / "manifest.yaml")
            else:
                st.session_state.sdb_db = ""
                st.session_state.sdb_manifest = ""
        if not local_versions:
            st.info("No installed SDB versions for this platform.")
    with download_column:
        st.subheader("Download SDB")
        entered_token = st.text_input("Artifactory API key", type="password",
                                      key="sdb_api_key", disabled=running,
                                      placeholder="Using TokenUpdater credential" if configured_token else "Enter API key")
        token = entered_token.strip() or configured_token
        refresh = st.button("Refresh versions", icon=":material/refresh:",
                            disabled=running or not token)
        if token and not running and (refresh or "SPA2" not in st.session_state.sdb_versions):
            try:
                with st.spinner("Loading SDB versions..."):
                    st.session_state.sdb_versions["SPA2"] = list_sdb_versions("SPA2", token)
                st.session_state.sdb_version_errors.pop("SPA2", None)
            except (ArtifactoryError, requests.RequestException, ValueError) as exc:
                st.session_state.sdb_versions["SPA2"] = []
                st.session_state.sdb_version_errors["SPA2"] = str(exc)
        versions = sorted(set(st.session_state.sdb_versions.get("SPA2", [])),
                          key=lambda value: tuple(map(int, re.findall(r"\d+", value))),
                          reverse=True)
        version = st.selectbox("Available version", versions, index=None,
                               key="download_sdb_version_SPA2",
                               disabled=running or not versions,
                               placeholder="Choose an available version")
        if "SPA2" in st.session_state.sdb_version_errors:
            st.warning(st.session_state.sdb_version_errors["SPA2"])
        if st.button("Download SDB", icon=":material/download:", disabled=running or not version):
            try:
                with st.spinner(f"Downloading SPA2 SDB {version}..."):
                    db_dir, manifest_path = download_sdb("SPA2", version, token)
                st.session_state.sdb_db = str(db_dir)
                st.session_state.sdb_manifest = str(manifest_path)
                st.session_state.sdb_pending_selection = ("SPA2", version)
                st.session_state.sdb_download_message = f"Selected SPA2 SDB {version}."
                st.rerun()
            except (ArtifactoryError, requests.RequestException, ValueError, OSError) as exc:
                st.error(str(exc))
        if not token:
            st.info("Enter an Artifactory API key to load available versions.")
        if message := st.session_state.pop("sdb_download_message", None):
            st.success(message)
    with st.expander("Selected SDB paths"):
        st.text_input("SDB database directory", disabled=True, key="sdb_db")
        st.text_input("SDB manifest", disabled=True, key="sdb_manifest")
else:
    st.subheader("PDU configuration")
    entered_token = st.text_input("Artifactory API key", type="password",
                                  key="sdb_api_key", disabled=running,
                                  placeholder="Using TokenUpdater credential" if configured_token
                                  else "Enter API key (first-time download only)")
    token = entered_token.strip() or configured_token
    version_column, refresh_column = st.columns([3, 1], vertical_alignment="bottom")
    with refresh_column:
        refresh = st.button("Refresh", icon=":material/refresh:", width="stretch",
                            disabled=running or not token)
    if token and not running and (refresh or "SPA3" not in st.session_state.sdb_versions):
        try:
            with st.spinner("Loading SDB versions..."):
                st.session_state.sdb_versions["SPA3"] = list_sdb_versions("SPA3", token)
            st.session_state.sdb_version_errors.pop("SPA3", None)
        except (ArtifactoryError, requests.RequestException, ValueError) as exc:
            st.session_state.sdb_versions["SPA3"] = []
            st.session_state.sdb_version_errors["SPA3"] = str(exc)
    cached_configs = set(list_pdu_config_versions())
    pdu_versions = sorted(set(st.session_state.sdb_versions.get("SPA3", [])) | cached_configs,
                          key=lambda value: tuple(map(int, re.findall(r"\d+", value))),
                          reverse=True)
    with version_column:
        version = st.selectbox("SDB version", pdu_versions,
                               index=0 if cached_configs and not st.session_state.sdb_versions.get("SPA3") else None,
                               key="pdu_sdb_version", disabled=running or not pdu_versions,
                               placeholder="Choose a version")
    if "SPA3" in st.session_state.sdb_version_errors:
        st.warning(st.session_state.sdb_version_errors["SPA3"])
    button_label = "Use PDU config" if version in cached_configs else "Generate PDU config"
    if st.button(button_label, icon=":material/build:", disabled=running or not version):
        try:
            with st.spinner(f"Preparing PDU config for SPA3 {version}..."):
                result = generate_pdu_config(version, token)
            st.session_state.pdu_config_pending = result["out_dir"]
            verb = "Using cached" if result.get("cached") else "Generated"
            st.session_state.pdu_generate_message = (
                f"{verb} PDU config for {version}: {result['pdus']} PDUs, {result['ports']} ports.")
            st.rerun()
        except (ArtifactoryError, requests.RequestException, ValueError, OSError,
                FileNotFoundError) as exc:
            st.error(str(exc))
    if not token and not cached_configs:
        st.info("Enter an Artifactory API key to download SDB sources the first time.")
    if message := st.session_state.pop("pdu_generate_message", None):
        st.success(message)
    st.caption(f"Active PDU config: {st.session_state.pdu_config_dir}")

db = st.session_state.get("sdb_db", "")
manifest = st.session_state.get("sdb_manifest", "")
pdu_config = st.session_state.get("pdu_config_dir") if pdu_enabled else None
destination = st.text_input("Output directory", value=str(ROOT / "out"), disabled=running)

if st.button("Decode", type="primary", icon=":material/play_arrow:", disabled=running):
    try:
        output = new_output_dir(destination)
        command = build_command(inputs, db, manifest, output, someip,
                                mode == "Per capture", keep_all, csv_output,
                                None if routing == "Automatic" else routing,
                                int(max_packets), pdu_config=pdu_config,
                                mrc_enabled=mrc_enabled)
        st.session_state.job = DecodeJob(command, output)
        st.session_state.command = shlex.join(command)
        st.rerun()
    except (ValueError, OSError) as exc:
        st.error(str(exc))


@st.cache_data(ttl=60, max_entries=8)
def read_summary(path: str, modified: int) -> pd.DataFrame:
    return pd.read_csv(path, nrows=5000)


@st.cache_data(max_entries=4, show_spinner="Preparing download...")
def read_output_bytes(path: str, modified: int, size: int) -> bytes:
    return Path(path).read_bytes()


@st.fragment(run_every="1s" if running else None)
def show_run():
    current = st.session_state.job
    if current is None:
        return
    code = current.poll()
    st.divider()
    with st.container(horizontal=True):
        st.subheader("Run")
        if code is None:
            st.badge("Decoding", color="blue")
            if st.button("Cancel", icon=":material/stop:"):
                current.cancel()
                st.rerun()
        elif current.cancelled:
            st.badge("Cancelled", color="orange")
        elif code:
            st.badge(f"Failed / exit {code}", color="red")
        else:
            st.badge("Finished", color="green")
        st.caption(f"{current.elapsed()} seconds")

    st.code(str(current.output), language=None)
    with st.expander("Decoder command"):
        st.code(st.session_state.command, language="bash")
    st.code(current.log_tail() or "Starting decoder...", language=None, height=280)
    if code is None:
        return
    if running:
        st.rerun()
    outputs = sorted(path for path in current.output.iterdir()
                     if path.suffix in (".mf4", ".csv"))
    if not current.cancelled and code == 0 and not any(path.suffix == ".mf4" for path in outputs):
        st.warning("No MF4 was produced. Check the decoder log for missing signals or writer errors.")
    if outputs:
        st.subheader("Output files")
        st.dataframe([{"File": path.name, "Size (MB)": round(path.stat().st_size / 1024**2, 2),
                       "Path": str(path)} for path in outputs], hide_index=True)
        with st.container(horizontal=True):
            for path in outputs:
                info = path.stat()
                st.download_button(
                    f"Download {path.name}",
                    data=read_output_bytes(str(path), info.st_mtime_ns, info.st_size),
                    file_name=path.name,
                    mime="text/csv" if path.suffix == ".csv" else "application/octet-stream",
                    icon=":material/download:", key=f"download_{path.name}")
        summaries = [path for path in outputs if path.name.endswith("_signals.csv")]
        if summaries:
            selected = st.selectbox("Signal summary", summaries, format_func=lambda path: path.name)
            try:
                data = read_summary(str(selected), selected.stat().st_mtime_ns)
                search = st.text_input("Filter signals")
                if search:
                    mask = data.astype(str).apply(
                        lambda column: column.str.contains(search, case=False, regex=False)).any(axis=1)
                    data = data[mask]
                st.dataframe(data, hide_index=True, height=320)
            except (OSError, ValueError, pd.errors.ParserError) as exc:
                st.error(f"Cannot read signal summary: {exc}")


show_run()