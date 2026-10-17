import html
import os
import re
import tempfile
from collections import Counter
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from streamlit_explorer import FilePicker

from streamlit_workflow import (
    decode_sat_readout,
    discover_vin_readouts,
    parse_standby_report,
    read_selected_log,
    run_standby_summary,
    uploaded_signature,
)
from interpretation import add_watchdog_columns, interpret_readout
from summary_report import build_summary_markdown
from sw_versions import ecu_software_info, identification_items, shared_hardware
from baselines import LoginRequired, connect, lookup_main_int_baselines, stored_username


st.set_page_config(
    page_title="Vehicle readout analysis",
    page_icon=":material/car_crash:",
    layout="wide",
)
st.title("Vehicle readout analysis")
st.caption("Load a vehicle readout, translate it with its SDDB, then inspect the readout summary.")

with st.form("load_vin_readouts"):
    vin = st.text_input("VIN", key="vin")
    with st.expander("Network share credentials (optional)"):
        smb_username = st.text_input("SMB username", key="smb_username")
        smb_password = st.text_input("SMB password", type="password", key="smb_password")
        remember_credentials = st.checkbox(
            "Save credentials in the OS keychain",
            key="remember_smb_credentials",
        )
    load_readouts = st.form_submit_button(
        "Load readouts",
        type="primary",
        icon=":material/folder_open:",
    )

if load_readouts:
    try:
        with st.status(
            f"Finding readouts for {vin.strip().upper() or 'VIN'}...", expanded=True
        ) as load_status:
            st.session_state["vin_readouts"] = discover_vin_readouts(
                vin,
                smb_username,
                smb_password,
                remember_credentials,
                progress=load_status.write,
            )
            st.session_state["loaded_vin"] = vin.strip().upper()
            load_status.update(
                label=(
                    f"Loaded {len(st.session_state['vin_readouts']):,} readouts for "
                    f"{st.session_state['loaded_vin']}."
                ),
                state="complete",
                expanded=False,
            )
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        st.session_state["vin_readouts"] = []
        st.error(str(error))

readouts = st.session_state.get("vin_readouts", [])
readout_source = st.selectbox(
    "Readout source",
    ["VIN readout", "Upload or server path"],
    key="readout_source",
)

uploaded_log = None
log_path = ""
selected_readout = None
if readout_source == "VIN readout":
    if readouts:
        readout_by_label = {item["label"]: item for item in readouts}
        selected_readout = st.selectbox(
            f"Readout for {st.session_state.get('loaded_vin', 'VIN')}",
            options=list(readout_by_label),
            key="selected_vin_readout",
        )
        selected_readout = readout_by_label[selected_readout]
    else:
        st.info("Enter a VIN and load readouts to use this source.")
else:
    uploaded_log = st.file_uploader(
        "Log or YAML readout",
        type=["log", "yaml", "yml"],
        key="readout_upload",
    )
    log_path = st.text_input(
        "Or use a server-side log/YAML path",
        help="The path must be readable by the machine running this app.",
        key="readout_path",
    )

def default_sddb_folder():
    configured = os.environ.get("SAT_SDDB_DIR")
    candidates = [
        Path(configured).expanduser() if configured else None,
        Path.home() / "Downloads" / "sddb",
        Path.home() / "Downloads",
        Path.home(),
    ]
    return next(
        (str(path.resolve()) for path in candidates if path and path.is_dir()),
        str(Path.home()),
    )


st.markdown("**SDDB file**")
picked_sddb = FilePicker(
    key="server_sddb_picker",
    start_path=default_sddb_folder(),
    file_extensions=[".sddb", ".xml"],
)
with st.expander("Or upload an SDDB file"):
    uploaded_sddb = st.file_uploader(
        "SDDB file",
        type=["sddb", "xml"],
        key="sddb_upload",
        label_visibility="collapsed",
    )

with st.expander("Readout summary options"):
    watchdog_details = st.checkbox(
        "Include the full watchdog timeline",
        key="watchdog_details",
    )
    no_error_reference = st.checkbox(
        "Disable FE03 error-reference enrichment",
        key="no_error_reference",
    )


def selected_log_details(load_content):
    if readout_source == "VIN readout":
        if selected_readout is None:
            raise ValueError("Select a VIN readout or load readouts for a VIN.")
        path = selected_readout["path"]
        return (
            read_selected_log(path) if load_content else None,
            Path(path).name,
            ("vin", path),
        )
    if log_path.strip():
        path = Path(normalize_path(log_path))
        if not path.is_file():
            raise FileNotFoundError(f"Log/YAML file does not exist: {path}")
        stat = path.stat()
        return (
            read_selected_log(str(path)) if load_content else None,
            path.name,
            ("path", str(path), stat.st_size, stat.st_mtime_ns),
        )
    if uploaded_log is not None:
        contents = uploaded_log.getvalue()
        return (
            contents.decode("utf-8", errors="ignore") if load_content else None,
            uploaded_log.name,
            ("upload", uploaded_log.name, contents),
        )
    raise ValueError("Upload a log/YAML file or provide a server-side path.")


def get_selected_sddb():
    if picked_sddb:
        path = Path(normalize_path(picked_sddb))
        if not path.is_file():
            raise FileNotFoundError(f"SDDB file does not exist: {path}")
        return str(path), path.name, None
    if uploaded_sddb is not None:
        return None, uploaded_sddb.name, uploaded_sddb.getvalue()
    raise ValueError("Select an SDDB file on the server or upload one.")


def normalize_path(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def sddb_identity(path, contents):
    if contents is not None:
        return contents
    file_stat = Path(path).stat()
    return path, file_stat.st_size, file_stat.st_mtime_ns


WRAP_TABLE_CSS = """
<style>
.rw-table-wrap { width: 100%; overflow-x: auto; margin-bottom: 0.75rem;
  border: 1px solid rgba(128,128,128,0.35); border-radius: 6px; }
.rw-table { border-collapse: collapse; width: 100%; font-size: 0.875rem;
  line-height: 1.35; }
.rw-table th, .rw-table td { padding: 6px 10px; text-align: left;
  vertical-align: top; border-bottom: 1px solid rgba(128,128,128,0.2); }
.rw-table th { font-weight: 600; background: rgba(128,128,128,0.18);
  white-space: nowrap; }
.rw-table tr:last-child td { border-bottom: none; }
.rw-table tbody tr:nth-child(even) td { background: rgba(128,128,128,0.07); }
.rw-table td.rw-short { white-space: nowrap; }
.rw-table td.rw-long { white-space: normal; overflow-wrap: anywhere;
  min-width: 14rem; }
</style>
"""

SHORT_CELL_LIMIT = 28


def cell_text(value):
    """Plain text of a cell; a cell may also be a list of (text, url) links."""
    if isinstance(value, list):
        return ", ".join(text for text, _ in value)
    return str(value)


def cell_html(value):
    if isinstance(value, list):
        return ", ".join(
            f'<a href="{html.escape(url, quote=True)}" target="_blank" rel="noopener">{html.escape(text)}</a>'
            for text, url in value
        )
    return html.escape(str(value))


def render_wrapped_table(headers, rows):
    """Show a table whose long cells word-wrap to the cell width while short cells stay on one line."""
    long_columns = {
        header for header in headers
        if max([len(header)] + [len(cell_text(row.get(header, ""))) for row in rows])
        > SHORT_CELL_LIMIT
    }
    head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(
            f'<td class="{"rw-long" if header in long_columns else "rw-short"}">'
            f"{cell_html(row.get(header, ''))}</td>"
            for header in headers
        ) + "</tr>"
        for row in rows
    )
    st.html(
        f'{WRAP_TABLE_CSS}<div class="rw-table-wrap"><table class="rw-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


SEVERITY_LABELS = {
    "issue": (":red[ISSUE]", ":material/error:"),
    "warning": (":orange[WARNING]", ":material/warning:"),
    "info": (":blue[INFO]", ":material/info:"),
    "ok": (":green[OK]", ":material/check_circle:"),
}


def render_interpretation(result, sections):
    """Show the rule-based findings and the merged timeline for the decoded readout."""
    if "app_states" not in result.get("interpretation", {}):
        result["interpretation"] = interpret_readout(result["blocks"], sections)
    interpretation = result["interpretation"]
    findings = interpretation["findings"]

    st.subheader("Interpretation")
    st.caption(
        "A rule-based reading of this readout using how the nodes relate: HIA controls HPA and keeps "
        "its reset reasons, HPA hardware errors reach HIA as FSI errors, and LPA keeps the standby "
        "history of the VCU nodes. Open a finding to see the evidence."
    )
    counts = Counter(finding["severity"] for finding in findings)
    columns = st.columns(4)
    columns[0].metric("Issues", counts.get("issue", 0))
    columns[1].metric("Warnings", counts.get("warning", 0))
    columns[2].metric("Info", counts.get("info", 0))
    columns[3].metric("OK", counts.get("ok", 0))

    for finding in findings:
        badge, icon = SEVERITY_LABELS[finding["severity"]]
        with st.expander(f"{badge} · {finding['headline']}", icon=icon, expanded=False):
            st.caption(finding["category"])
            for detail in finding["details"]:
                st.markdown(f"- {detail}")
            if finding["table"]:
                headers, rows = finding["table"]
                render_wrapped_table(headers, [dict(zip(headers, row)) for row in rows])
            elif finding["evidence"]:
                render_wrapped_table(
                    ["Item", "Value"],
                    [{"Item": label, "Value": value} for label, value in finding["evidence"]],
                )
            for title, extra_headers, extra_rows in finding["extra_tables"]:
                st.markdown(f"**{title}**")
                render_wrapped_table(extra_headers, [dict(zip(extra_headers, row)) for row in extra_rows])
            if finding["sources"]:
                st.caption("Source readouts: " + " · ".join(finding["sources"]))

    timeline = interpretation["timeline"]
    if timeline:
        with st.expander(f"Timeline of recorded events ({len(timeline):,})", icon=":material/timeline:", expanded=False):
            st.caption(
                "Standby cycles, FSI errors, platform states, DTCs and the HIA exceptional restart merged by time. "
                "Times are shown as stored by each source; they are UTC where the source states it."
            )
            render_wrapped_table(
                ["Time", "Source", "Event", "Detail"],
                [
                    {"Time": when, "Source": source, "Event": event, "Detail": detail}
                    for when, source, event, detail in timeline
                ],
            )
    if interpretation["missing"]:
        st.caption("Not present in this readout: " + ", ".join(interpretation["missing"]) + ".")
    for message in interpretation["errors"]:
        st.caption(f"A rule could not be evaluated: {message}")


def render_baselines(result, records):
    """Look up and show the MAIN_INT baseline of each position's software part numbers (ConfigHub)."""
    st.markdown("**Baselines (MAIN_INT) from ConfigHub**")
    with st.expander("ConfigHub login (only needed when no login is saved)"):
        try:
            saved_user = stored_username()
        except Exception:
            saved_user = ""
        st.text_input("ConfigHub username", value=saved_user, key="confighub_username")
        st.text_input("ConfigHub password", type="password", key="confighub_password")
        st.checkbox("Save these credentials in the OS keychain", key="confighub_remember")
        st.caption(
            "Leave both fields as they are to use the login saved by confighub_lookup.py, "
            "or the CONFIGHUB_TOKEN environment variable."
        )

    if st.button(
        "Look up MAIN_INT baselines",
        key="lookup_baselines",
        icon=":material/account_tree:",
    ):
        try:
            with st.status("Looking up baselines in ConfigHub...", expanded=True) as status:
                status.write("Signing in to ConfigHub...")
                client = connect(
                    st.session_state.get("confighub_username", ""),
                    st.session_state.get("confighub_password", ""),
                    st.session_state.get("confighub_remember", False),
                )
                result["baselines"] = lookup_main_int_baselines(client, records, progress=status.write)
                status.update(
                    label=(
                        f"Baselines found for {len(result['baselines']['rows'])} positions in "
                        f"{result['baselines']['seconds']:.0f} s."
                    ),
                    state="complete",
                    expanded=False,
                )
        except LoginRequired:
            st.warning(
                "No ConfigHub login is available. Enter your username and password in the login section above "
                "(or run confighub_lookup.py once to save them)."
            )
        except requests.HTTPError as error:
            code = error.response.status_code if error.response is not None else None
            st.error(
                "ConfigHub rejected the login." if code in (400, 401, 403)
                else f"ConfigHub returned an error: {error}"
            )
        except (requests.ConnectionError, requests.Timeout) as error:
            st.error(f"Could not reach ConfigHub (check the VPN or network): {error}")

    baselines = result.get("baselines")
    if not baselines:
        st.caption(
            "Finds the *_MAIN_INT baselines that contain the software part numbers of each ECU "
            "(about 5-10 s; repeated lookups of the same parts are cached)."
        )
        return
    render_wrapped_table(
        ["Position", "Baseline", "Version(s)", "ConfigHub", "Download", "Parts"], baselines["rows"]
    )
    st.caption(
        f"Matched {baselines['looked_up']} software part numbers in {baselines['seconds']:.0f} s. Only *_MAIN_INT "
        "baselines are shown. ConfigHub reports HPA's platform parts (HPA) and application parts (HPAA) as separate "
        "positions; Parts lists the part types of each. ConfigHub returns the three best matches, so several "
        "versions mean that more than one MAIN_INT baseline contains every part and the part numbers alone cannot "
        "tell which of them the software came from; only the newest are listed. Download opens the software file "
        "(.vbf) of each part from Artifactory in a new tab; the browser asks you to sign in there."
    )
    if baselines["ignored"]:
        st.caption(
            "Ignored certificate and placeholder parts: "
            + ", ".join(f"{item['ecu']} {item['module']}" for item in baselines["ignored"]) + "."
        )
    if baselines["not_found"]:
        st.caption("Not found in ConfigHub: " + ", ".join(baselines["not_found"]) + ".")


def render_sw_versions(result):
    """Software and identification part numbers of HIA, HIB, HPA, SGA, VESA and VESB."""
    if "sw_versions" not in result:
        result["sw_versions"] = ecu_software_info(result["blocks"])
    records = result["sw_versions"]
    present = [record for record in records if record["present"]]

    st.subheader("Software versions")
    shared = shared_hardware(records)
    shared_keys = {key for key, _, _ in shared}
    if shared:
        st.caption(
            "Reported identically by all ECUs: "
            + " · ".join(f"{label.replace('ECU ', '')} {value}" for _, label, value in shared)
        )
    missing = [record["ecu"] for record in records if not record["present"]]
    if missing:
        st.caption("Not present in this readout: " + ", ".join(missing) + ".")

    render_baselines(result, records)

    for record in present:
        label = f"{record['ecu']} ({record['address']}) · {record['main']} · {len(record['software'])} software module(s)"
        with st.expander(label, expanded=False):
            if record["software"]:
                render_wrapped_table(
                    ["Module", "Part number"],
                    [
                        {
                            "Module": module["module"],
                            "Part number": f"{module['part']} {module['edition']}".strip(),
                        }
                        for module in record["software"]
                    ],
                )
            else:
                st.info("No software part numbers (22 F1 2E) in this readout.")
            items = identification_items(record, shared_keys)
            if items:
                render_wrapped_table(
                    ["Item", "Value"],
                    [{"Item": name, "Value": value} for name, value in items],
                )
            st.caption("Source readouts: " + " · ".join(record["sources"]))


def render_translated_output(content, search_terms):
    terms = sorted(
        {
            variant
            for term in search_terms if term
            for variant in (
                term,
                " ".join(term[index:index + 2] for index in range(0, len(term), 2))
                if (
                    len(term) >= 4
                    and len(term) % 2 == 0
                    and all(character in "0123456789ABCDEF" for character in term)
                )
                else term,
            )
        },
        key=len,
        reverse=True,
    )
    matcher = re.compile("|".join(re.escape(term) for term in terms), re.IGNORECASE) if terms else None
    if matcher:
        highlighted = []
        previous_end = 0
        for match in matcher.finditer(content):
            highlighted.append(html.escape(content[previous_end:match.start()]))
            highlighted.append(
                '<mark style="background:#ffff00;color:#000">'
                f"{html.escape(match.group(0))}</mark>"
            )
            previous_end = match.end()
        highlighted.append(html.escape(content[previous_end:]))
        display = "".join(highlighted)
    else:
        display = html.escape(content)
    st.html(
        f"""
        <div style="width:100%;height:64vh;min-height:420px;overflow:auto;
                    box-sizing:border-box;background:#000;color:#fff;
                    border:1px solid #555;border-radius:4px;padding:12px">
          <pre style="margin:0;white-space:pre-wrap;overflow-wrap:anywhere;
                      font-family:Consolas,'Courier New',monospace;
                      font-size:13px;line-height:1.35">{display}</pre>
        </div>
        """
    )


def parse_content_search(query):
    tokens = query.strip().upper().split()
    search_parts = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if all(character in "0123456789ABCDEF" for character in token) and len(token) <= 2:
            end = index + 1
            while (
                end < len(tokens)
                and len(tokens[end]) <= 2
                and all(character in "0123456789ABCDEF" for character in tokens[end])
            ):
                end += 1
            if end - index > 1:
                search_parts.append("".join(tokens[index:end]))
            else:
                search_parts.append(token)
            index = end
        else:
            search_parts.append(token)
            index += 1
    return search_parts


def block_matches_content_search(block, search_parts):
    if not search_parts:
        return True
    content = block["content"].upper()
    content_without_spaces = content.replace(" ", "")
    for part in search_parts:
        if part in content:
            continue
        if (
            all(character in "0123456789ABCDEF" for character in part)
            and part.replace(" ", "") in content_without_spaces
        ):
            continue
        return False
    return True


def apply_readout_lookup():
    st.session_state["active_readout_lookup"] = st.session_state.get(
        "readout_lookup_input", ""
    )


def clear_readout_lookup():
    st.session_state["readout_lookup_input"] = ""
    st.session_state["active_readout_lookup"] = ""


TREE_COLUMNS = ["Open", "Show", "ECU / Readout"]


def readout_label(block):
    readout = block["readout"]
    description = block["description"]
    if description and description != readout:
        return f"{readout} | {description}"
    return readout


def build_tree_frame(grouped, expanded, selected):
    records = []
    nodes = []
    for ecu_id, ecu_blocks in grouped.items():
        row_ids = [block["row_id"] for block in ecu_blocks]
        selected_count = sum(row_id in selected for row_id in row_ids)
        is_open = ecu_id in expanded
        records.append({
            "Open": "▾" if is_open else "▸",
            "Show": selected_count == len(row_ids),
            "ECU / Readout": (
                f"{ecu_blocks[0]['ecu_name']} | {ecu_id} "
                f"({selected_count}/{len(row_ids)})"
            ),
        })
        nodes.append(("ecu", ecu_id, None))
        if is_open:
            for block in ecu_blocks:
                records.append({
                    "Open": "",
                    "Show": block["row_id"] in selected,
                    "ECU / Readout": f"      {readout_label(block)}",
                })
                nodes.append(("readout", ecu_id, block["row_id"]))
    return pd.DataFrame(records, columns=TREE_COLUMNS), nodes


def rebuild_tree():
    state = st.session_state
    state["rt_base"], state["rt_nodes"] = build_tree_frame(
        state["rt_grouped"], state["rt_expanded"], state["rt_selected"]
    )
    state["rt_key"] = state.get("rt_key", 0) + 1


def mark_tree_dirty():
    st.session_state["rt_dirty"] = True


def toggle_ecu_click():
    click = st.session_state.get("rt_open_click")
    if click is None:
        return
    nodes = st.session_state["rt_nodes"]
    if not 0 <= click.row < len(nodes) or nodes[click.row][0] != "ecu":
        return
    ecu_id = nodes[click.row][1]
    expanded = st.session_state["rt_expanded"]
    expanded.symmetric_difference_update({ecu_id})
    mark_tree_dirty()


def expand_all_ecus():
    st.session_state["rt_expanded"] = set(st.session_state["rt_grouped"])
    mark_tree_dirty()


def collapse_all_ecus():
    st.session_state["rt_expanded"] = set()
    mark_tree_dirty()


def select_all_readouts():
    st.session_state["rt_selected"] = set(st.session_state["rt_visible_ids"])
    mark_tree_dirty()


def clear_selected_readouts():
    st.session_state["rt_selected"] = set()
    mark_tree_dirty()


@st.fragment
def render_translated_browser(result):
    all_blocks = result["blocks"]
    search_col, lookup_col = st.columns([3, 2])
    with search_col:
        with st.form("translated_content_search", border=False):
            search_col, search_button_col, clear_button_col = st.columns([6, 1, 1])
            with search_col:
                st.text_input(
                    "Search/Filter",
                    placeholder="Search decoded text, ECU, DID, or DTC",
                    key="readout_search_input",
                    type="search",
                )
            with search_button_col:
                st.form_submit_button(
                    "Search",
                    use_container_width=True,
                    on_click=lambda: st.session_state.update(
                        active_readout_search=st.session_state.readout_search_input
                    ),
                )
            with clear_button_col:
                st.form_submit_button(
                    "Clear",
                    use_container_width=True,
                    on_click=lambda: st.session_state.update(
                        readout_search_input="",
                        active_readout_search="",
                    ),
                )
    with lookup_col:
        with st.form("translated_metadata_lookup", border=False):
            st.text_input(
                "Lookup",
                placeholder="ECU, service, DID",
                key="readout_lookup_input",
            )
            lookup_button_col, reset_button_col = st.columns(2)
            with lookup_button_col:
                st.form_submit_button(
                    "Lookup",
                    use_container_width=True,
                    on_click=apply_readout_lookup,
                )
            with reset_button_col:
                st.form_submit_button(
                    "Reset",
                    use_container_width=True,
                    on_click=clear_readout_lookup,
                )

    active_lookup = st.session_state.get("active_readout_lookup", "").strip().upper()
    lookup_tokens = active_lookup.split()
    search_parts = parse_content_search(
        st.session_state.get("active_readout_search", "")
    )
    if "ecu_names" not in result:
        result["ecu_names"] = {}
        for block in all_blocks:
            result["ecu_names"].setdefault(block["ecu_id"], block["ecu_name"])
    if "blocks_by_id" not in result:
        result["blocks_by_id"] = {block["row_id"]: block for block in all_blocks}
    ecu_names = result["ecu_names"]
    all_ecus = list(ecu_names)
    selected_ecus = st.multiselect(
        "Filter by ECU",
        options=all_ecus,
        format_func=lambda ecu_id: (
            f"{ecu_names[ecu_id]} | {ecu_id}"
        ),
        key="readout_ecu_filter",
        placeholder="All ECUs",
    )
    filter_signature = (
        result["signature"],
        tuple(lookup_tokens),
        tuple(search_parts),
        tuple(selected_ecus),
    )
    if (
        st.session_state.get("readout_filter_signature") != filter_signature
        or "rt_grouped" not in st.session_state
    ):
        visible_blocks = [
            block for block in all_blocks
            if (
                (not selected_ecus or block["ecu_id"] in selected_ecus)
                and all(token in block["lookup_text"] for token in lookup_tokens)
                and block_matches_content_search(block, search_parts)
            )
        ]
        grouped = {}
        for block in visible_blocks:
            grouped.setdefault(block["ecu_id"], []).append(block)
        visible_id_set = {block["row_id"] for block in visible_blocks}
        st.session_state["readout_filter_signature"] = filter_signature
        st.session_state["rt_grouped"] = grouped
        st.session_state["rt_visible_ids"] = [
            block["row_id"] for block in visible_blocks
        ]
        st.session_state["rt_selected"] = (
            st.session_state.get("rt_selected", set()) & visible_id_set
        )
        st.session_state["rt_expanded"] = set()
        rebuild_tree()
    elif st.session_state.pop("rt_dirty", False):
        rebuild_tree()

    visible_ids = st.session_state["rt_visible_ids"]
    if not visible_ids:
        st.info("No readouts match the current filters.")
        return

    st.caption(
        f"Display complete: {len(all_blocks):,} readouts · "
        f"{len(visible_ids):,} matching readouts · "
        f"{len(st.session_state['rt_grouped']):,} ECUs"
    )
    left_pane, right_pane = st.columns([1, 2], gap="small")
    with left_pane:
        expand_col, collapse_col, select_col, clear_col = st.columns(4)
        with expand_col:
            st.button(
                "Expand all",
                key="rt_expand_all",
                on_click=expand_all_ecus,
                use_container_width=True,
            )
        with collapse_col:
            st.button(
                "Collapse all",
                key="rt_collapse_all",
                on_click=collapse_all_ecus,
                use_container_width=True,
            )
        with select_col:
            st.button(
                "Select all",
                key="rt_select_all",
                on_click=select_all_readouts,
                use_container_width=True,
            )
        with clear_col:
            st.button(
                "Clear",
                key="rt_clear_selection",
                on_click=clear_selected_readouts,
                use_container_width=True,
            )

        base_tree = st.session_state["rt_base"]
        tree_nodes = st.session_state["rt_nodes"]
        edited_tree = st.data_editor(
            base_tree,
            hide_index=True,
            width="stretch",
            height=560,
            num_rows="fixed",
            key=f"rt_editor_{st.session_state['rt_key']}",
            disabled=["ECU / Readout"],
            column_config={
                "Open": st.column_config.ButtonColumn(
                    " ",
                    width="small",
                    on_click=toggle_ecu_click,
                    key="rt_open_click",
                ),
                "Show": st.column_config.CheckboxColumn("Show", width="small"),
                "ECU / Readout": st.column_config.TextColumn(
                    "ECU / Readout", width="large"
                ),
            },
        )

        old_show = base_tree["Show"].tolist()
        new_show = edited_tree["Show"].fillna(False).astype(bool).tolist()
        selected = set(st.session_state["rt_selected"])
        visible_children = {
            node[2] for node in tree_nodes if node[0] == "readout"
        }
        selected -= visible_children
        selected.update(
            node[2]
            for node, checked in zip(tree_nodes, new_show)
            if node[0] == "readout" and checked
        )
        toggled_ecus = [
            (node[1], checked)
            for node, checked, was_checked in zip(tree_nodes, new_show, old_show)
            if node[0] == "ecu" and checked != was_checked
        ]
        for ecu_id, checked in toggled_ecus:
            ecu_row_ids = [
                block["row_id"] for block in st.session_state["rt_grouped"][ecu_id]
            ]
            if checked:
                selected.update(ecu_row_ids)
            else:
                selected.difference_update(ecu_row_ids)
        st.session_state["rt_selected"] = selected
        if toggled_ecus:
            rebuild_tree()
            st.rerun(scope="fragment")
        st.caption(f"{len(selected):,} readouts selected")

    with right_pane:
        blocks_by_id = result["blocks_by_id"]
        selected_blocks = sorted(
            (blocks_by_id[row_id] for row_id in selected),
            key=lambda block: block["row_id"],
        )
        render_translated_output(
            "\n\n\n".join(block["content"] for block in selected_blocks),
            search_parts,
        )


if st.button(
    "Translate readout and build readout summary",
    type="primary",
    icon=":material/play_arrow:",
    key="translate_readout",
):
    progress = None
    try:
        with st.status("Preparing vehicle readout analysis...", expanded=True) as progress:
            progress.write("1. Loading the selected readout and SDDB.")
            log_content, log_filename, log_identity = selected_log_details(True)
            sddb_server_path, sddb_filename, sddb_bytes = get_selected_sddb()
            progress.write(
                f"Readout: `{log_filename}` "
                f"({len(log_content.encode('utf-8')):,} bytes)."
            )
            progress.write(f"SDDB: `{sddb_filename}`.")

            with tempfile.TemporaryDirectory(prefix="faulttracing-sat-") as directory:
                if sddb_server_path is None:
                    sddb_server_path = str(Path(directory) / Path(sddb_filename).name)
                    Path(sddb_server_path).write_bytes(sddb_bytes)
                progress.write(
                    "2. Translating the readout (the parsed SDDB is cached, so "
                    "repeat runs with the same SDDB skip the slow indexing step)."
                )
                translated, blocks, sat_diagnostics = decode_sat_readout(
                    log_content,
                    log_filename,
                    sddb_server_path,
                    sddb_filename,
                    sddb_identity=(
                        uploaded_signature(sddb_bytes)
                        if sddb_bytes is not None else None
                    ),
                    progress=progress.write,
                )

            ecu_count = len({block["ecu_id"] for block in blocks})
            progress.write(
                f"3. SAT translation complete: {len(blocks):,} readout blocks "
                f"across {ecu_count:,} ECUs."
            )
            progress.write(
                "4. Building the readout summary from the translated log: "
                "standby events, FE03 errors, ECU DTCs, and watchdog data."
            )
            standby_code, standby_output, standby_error = run_standby_summary(
                translated,
                watchdog_details=watchdog_details,
                no_error_reference=no_error_reference,
            )
            if standby_code == 0:
                progress.update(
                    label=(
                        f"Analysis complete: {len(blocks):,} readout blocks "
                        f"decoded; readout summary ready."
                    ),
                    state="complete",
                    expanded=False,
                )
            else:
                progress.update(
                    label=(
                        f"SAT translation complete ({len(blocks):,} readout blocks), "
                        "but the readout summary could not be generated."
                    ),
                    state="error",
                    expanded=True,
                )
    except (FileNotFoundError, OSError, RuntimeError, TimeoutError, UnicodeError, ValueError) as error:
        if progress is not None:
            progress.update(
                label="Readout analysis stopped before completion.",
                state="error",
                expanded=True,
            )
        st.error(f"Readout processing failed: {error}")
    else:
        current_signature = uploaded_signature(
            *log_identity,
            sddb_filename,
            sddb_identity(sddb_server_path, sddb_bytes),
            watchdog_details,
            no_error_reference,
        )
        ecu_names = {}
        for block in blocks:
            ecu_names.setdefault(block["ecu_id"], block["ecu_name"])
        st.session_state["analysis_result"] = {
            "signature": current_signature,
            "translated": translated,
            "blocks": blocks,
            "ecu_names": ecu_names,
            "blocks_by_id": {
                block["row_id"]: block for block in blocks
            },
            "sat_diagnostics": sat_diagnostics,
            "standby_code": standby_code,
            "standby_output": standby_output,
            "standby_error": standby_error,
            "translated_filename": f"{Path(log_filename).stem}_decoded.log",
            "summary_filename": f"{Path(log_filename).stem}_readout_summary.md",
        }
        st.session_state["rt_selected"] = set()
        st.session_state.pop("rt_grouped", None)

current_result = st.session_state.get("analysis_result")
if current_result is not None:
    try:
        _, current_log_filename, current_log_identity = selected_log_details(False)
        current_sddb_path, current_sddb_filename, current_sddb_bytes = get_selected_sddb()
    except (FileNotFoundError, OSError, ValueError):
        current_result = None
    else:
        expected_signature = uploaded_signature(
            *current_log_identity,
            current_sddb_filename,
            sddb_identity(current_sddb_path, current_sddb_bytes),
            watchdog_details,
            no_error_reference,
        )
        if current_result["signature"] != expected_signature:
            current_result = None

if current_result is not None:
    st.download_button(
        "Download translated readout",
        data=current_result["translated"],
        file_name=current_result["translated_filename"],
        mime="text/plain",
        key="download_translated_readout",
    )
    st.metric("Decoded readouts", len(current_result["blocks"]))
    translated_tab, summary_tab, versions_tab = st.tabs(
        ["Translated readout", "Readout summary", "SW versions"]
    )

    with versions_tab:
        render_sw_versions(current_result)

    with translated_tab:
        render_translated_browser(current_result)
        if current_result["sat_diagnostics"]:
            with st.expander("SAT decoder diagnostics"):
                st.code(current_result["sat_diagnostics"], language="text")

    with summary_tab:
        summary_available = current_result["standby_code"] == 0
        sections, notes = (
            parse_standby_report(current_result["standby_output"])
            if summary_available else ([], [])
        )
        st.download_button(
            "Download readout summary (Markdown)",
            data=lambda: build_summary_markdown(current_result, sections, notes),
            file_name=current_result["summary_filename"],
            mime="text/markdown",
            icon=":material/download:",
            key="download_readout_summary",
        )
        render_interpretation(current_result, sections)
        if summary_available:
            st.subheader("Recorded data")
            if sections:
                def rows_of(kind):
                    return sum(
                        len(section["rows"])
                        for section in sections if section["kind"] == kind
                    )

                metrics = st.columns(4)
                metrics[0].metric("Standby events", rows_of("events"))
                metrics[1].metric("FE03 error slots", rows_of("fe03_slots"))
                metrics[2].metric("DTC snapshots", rows_of("dtc"))
                metrics[3].metric("State transitions", rows_of("transitions"))
                for section in sections:
                    row_count = len(section["rows"])
                    if section["rows"]:
                        label = f"{section['heading']} ({row_count:,} rows)"
                    elif section["kind"] == "text":
                        label = f"{section['heading']} (none)"
                    else:
                        label = f"{section['heading']} (0 rows)"
                    with st.expander(label, expanded=False):
                        for description in section["description"]:
                            st.caption(description)
                        if section["rows"]:
                            headers, rows = section["headers"], section["rows"]
                            if section["kind"] == "watchdog":
                                headers, rows = add_watchdog_columns(
                                    headers, rows,
                                    current_result["interpretation"]["app_states"],
                                )
                            render_wrapped_table(headers, rows)
                            if section["kind"] == "watchdog" and "Essential" in headers:
                                st.caption(
                                    "Essential and Restartable come from the HPx watchdog state "
                                    "(HPA 22 D9 45); N/A means the application is not in that record."
                                )
                        elif section["kind"] != "text":
                            st.info("No rows recorded.")
                        for footnote in section["footnotes"]:
                            st.caption(footnote)
            else:
                st.warning(
                    "The readout summary did not contain any recognized tables."
                )
            if notes:
                with st.expander("Additional notes"):
                    for note in notes:
                        st.write(note)
            with st.expander("Raw summary output"):
                st.text(current_result["standby_output"])
        else:
            st.error(
                "The SAT translation completed, but the readout summary could not "
                "be built from this readout."
            )
            if current_result["standby_error"]:
                st.code(current_result["standby_error"], language="text")
            if current_result["standby_output"]:
                st.code(current_result["standby_output"], language="text")
