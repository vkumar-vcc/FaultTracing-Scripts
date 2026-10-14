"""Streamlit UI for someip_comm_analyzer: run with `streamlit run streamlit_app.py`."""
from __future__ import annotations

import os
import pickle
import subprocess
import sys
import tempfile
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

SCRIPT = Path(__file__).resolve().parent / "someip_comm_analyzer.py"
sys.path.insert(0, str(SCRIPT.parent))
import someip_comm_analyzer as sca  # noqa: E402

st.set_page_config(page_title="SOME/IP communication analyzer", page_icon=":material/lan:", layout="wide")

SEV_COLORS = alt.Scale(domain=["ERROR", "WARN", "STATE"], range=["#d62728", "#ff7f0e", "#2ca02c"])
DEFAULTS = vars(sca.build_parser().parse_args(["_"]))


@st.cache_data(max_entries=4, show_spinner=False)
def run_analysis(path: str, mtime: float, size: int, opts: tuple, services: tuple, profile: str) -> dict:
    # Separate process: multiprocessing spawn would otherwise re-execute this Streamlit script in each worker
    cmd = [sys.executable, str(SCRIPT), path, "--profile", profile]
    for k, v in opts:
        cmd += [f"--{k.replace('_', '-')}", str(v)]
    for sid in services:
        cmd += ["--service", hex(sid)]
    fd, out = tempfile.mkstemp(suffix=".pkl")
    os.close(fd)
    try:
        proc = subprocess.run(cmd + ["--pickle", out], capture_output=True, text=True)
        if proc.returncode:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}")
        with open(out, "rb") as f:
            return pickle.load(f)
    finally:
        os.unlink(out)


def parse_services(text: str) -> list[int] | None:
    vals = [s.strip() for s in text.replace(";", ",").split(",") if s.strip()]
    return [int(v, 0) if v.lower().startswith("0x") else int(v, 16) for v in vals] or None


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.header(":material/lan: SOME/IP analyzer")
    with st.form("run"):
        path = st.text_input("Capture file", placeholder=r"C:\logs\capture.pcapng.zst",
                             help=".pcapng / .pcap, optionally .zst or .gz compressed")
        uploaded = st.file_uploader("Or upload a capture", type=["pcapng", "pcap", "zst", "gz"],
                                    max_upload_size=4096,
                                    help="Large uploads may also be limited by the web server or reverse proxy.")
        profile = st.selectbox("Vehicle profile", options=list(sca.PROFILE_FILES),
                               index=list(sca.PROFILE_FILES).index(DEFAULTS["profile"]),
                               help="Select the bundled ECU name data for SPA2 or SPA3.")
        services = st.text_input("Service filter (hex, comma separated)", placeholder="0x00d8, 0x022b")
        with st.expander("Thresholds", icon=":material/tune:"):
            req_timeout = st.number_input("Request -> response timeout (s)", 0.01, 60.0, DEFAULTS["req_timeout"])
            sd_timeout = st.number_input("Subscribe -> ack timeout (s)", 0.01, 60.0, DEFAULTS["sd_timeout"])
            find_timeout = st.number_input("Find -> offer timeout (s)", 0.01, 60.0, DEFAULTS["find_timeout"])
            event_timeout = st.number_input("Subscribe ack -> first event (s)", 0.01, 60.0,
                                            DEFAULTS["event_timeout"])
            gap_factor = st.number_input("Stream gap factor (x median period)", 1.0, 100.0, DEFAULTS["gap_factor"])
            min_gap = st.number_input("Minimum stream gap (s)", 0.0, 60.0, DEFAULTS["min_gap"])
            host_gap = st.number_input("Host silence threshold (s)", 0.1, 600.0, DEFAULTS["host_gap"])
            grace = st.number_input("Start/end grace period (s)", 0.0, 60.0, DEFAULTS["grace"])
            workers = st.slider("Parser processes", 1, os.cpu_count() or 1, DEFAULTS["workers"])
        submitted = st.form_submit_button("Analyse", icon=":material/play_arrow:", type="primary", width="stretch")

if submitted:
    capture_path = path.strip().strip('"')
    display_name = Path(capture_path).name if capture_path else ""
    previous = st.session_state.get("run_cfg", {}).get("uploaded_path")
    if uploaded is not None:
        if previous:
            Path(previous).unlink(missing_ok=True)
        display_name = uploaded.name
        suffix = "".join(Path(uploaded.name).suffixes) or ".pcapng"
        fd, capture_path = tempfile.mkstemp(prefix="someip_capture_", suffix=suffix)
        with os.fdopen(fd, "wb") as target:
            target.write(uploaded.getbuffer())
    elif previous:
        Path(previous).unlink(missing_ok=True)
    st.session_state.run_cfg = dict(path=capture_path, display_name=display_name,
                                uploaded_path=capture_path if uploaded is not None else None,
                                profile=profile,
                                services=services, opts=(("req_timeout", req_timeout), ("sd_timeout", sd_timeout),
                                                         ("find_timeout", find_timeout),
                                                         ("event_timeout", event_timeout), ("gap_factor", gap_factor),
                                                         ("min_gap", min_gap), ("host_gap", host_gap),
                                                         ("grace", grace), ("workers", workers)))

st.title("SOME/IP communication analyzer")
cfg = st.session_state.get("run_cfg")
if not cfg or not cfg["path"]:
    st.info("Enter a capture path or upload a capture in the sidebar, then press **Analyse**.",
            icon=":material/info:")
    st.stop()

p = Path(cfg["path"])
capture_name = cfg.get("display_name") or p.name
if not p.is_file():
    st.error(f"File not found: `{p}`", icon=":material/error:")
    st.stop()
try:
    svc = parse_services(cfg["services"])
except ValueError:
    st.error("Service filter must be hex ids, e.g. `0x00d8, 22b`.", icon=":material/error:")
    st.stop()

stat = p.stat()
try:
    with st.spinner(f"Analysing {capture_name} ({stat.st_size / 2**20:.0f} MB)..."):
        res = run_analysis(str(p), stat.st_mtime, stat.st_size, cfg["opts"], tuple(svc or ()),
                           cfg["profile"])
except RuntimeError as exc:
    st.error(f"Analysis failed:\n\n```\n{exc}\n```", icon=":material/error:")
    st.stop()

if res["empty"]:
    st.warning("No IPv4 traffic found in this capture.", icon=":material/warning:")
    st.stop()

s = res["stats"]
ev: pd.DataFrame = res["events"]
out: pd.DataFrame = res["outages"]
st.caption(f"`{capture_name}` · {sca._utc(s['t_first'])} → {sca._utc(s['t_last'])} UTC · parsed in {s['parse_s']:.1f}s"
           f" · ECU names: {res['profile']} bundled profile")

with st.container(horizontal=True):
    st.metric("Duration", f"{s['duration_s']:.1f} s", border=True)
    st.metric("Frames", f"{s['frames']:,}", border=True)
    st.metric("SOME/IP messages", f"{s.get('someip_msgs', 0):,}", border=True)
    st.metric("SD messages", f"{s.get('sd_msgs', 0):,}", border=True)
    st.metric("Errors", int((ev.severity == "ERROR").sum()), border=True)
    st.metric("Warnings", int((ev.severity == "WARN").sum()), border=True)
    st.metric("Unresolved outages", int((~out.resolved).sum()), border=True)

# ---------------------------------------------------------------- global filters
ecus = sorted(set(ev.src_name[ev.src_name != ""]) | set(ev.dst_name[ev.dst_name != ""])
              | set(res["hosts"].name.dropna()[lambda x: x != ""]))
with st.container(horizontal=True, vertical_alignment="bottom"):
    sel_ecus = st.multiselect("ECU", ecus, placeholder="All ECUs", width=420)
    svc_q = st.text_input("Service id contains", placeholder="e.g. 022b", width=200)
    t_range = st.slider("Time window (s)", 0.0, max(float(s["duration_s"]), 0.001),
                        (0.0, max(float(s["duration_s"]), 0.001)), width=500)


def apply_filters(df: pd.DataFrame, t0: str, t1: str | None = None) -> pd.DataFrame:
    m = pd.Series(True, index=df.index)
    if sel_ecus:
        m &= df.src_name.isin(sel_ecus) | df.dst_name.isin(sel_ecus)
    if svc_q:
        m &= df.service.str.contains(svc_q.strip().lower().removeprefix("0x"), regex=False)
    end_col = t1 or t0
    m &= (df[end_col] >= t_range[0]) & (df[t0] <= t_range[1])
    return df[m]


def filtered_table(df: pd.DataFrame, key: str, alt_text: str, **kwargs) -> None:
    """st.dataframe with per-column filters (values, numeric range or text contains)."""
    n_active = len(st.session_state.get(f"{key}_cols", []))
    with st.container(horizontal=True, vertical_alignment="center"):
        with st.popover(f"Filter columns{f' ({n_active})' if n_active else ''}", icon=":material/filter_list:"):
            cols = st.multiselect("Columns to filter", list(df.columns), key=f"{key}_cols")
            for col in cols:
                s = df[col]
                k = f"{key}_f_{col}"
                if pd.api.types.is_bool_dtype(s):
                    vals = st.multiselect(col, [True, False], default=[True, False], key=k)
                    df = df[df[col].isin(vals)]
                elif pd.api.types.is_numeric_dtype(s):
                    lo, hi = float(s.min()) if s.notna().any() else 0.0, float(s.max()) if s.notna().any() else 0.0
                    with st.container(horizontal=True):
                        a = st.number_input(f"{col} min", value=lo, key=f"{k}_lo", format="%.6g")
                        b = st.number_input(f"{col} max", value=hi, key=f"{k}_hi", format="%.6g")
                    if (a, b) != (lo, hi):
                        df = df[df[col].between(a, b)]
                elif s.nunique(dropna=True) <= 100:
                    opts = sorted(s.dropna().astype(str).unique())
                    vals = st.multiselect(col, opts, placeholder="All values", key=k)
                    if vals:
                        df = df[df[col].astype(str).isin(vals)]
                else:
                    txt = st.text_input(f"{col} contains", key=k, placeholder="text, comma = OR, prefix ! = NOT")
                    terms = [t.strip() for t in txt.split(",") if t.strip()]
                    if terms:
                        sv = df[col].fillna("").astype(str)
                        inc = [t for t in terms if not t.startswith("!")]
                        exc = [t[1:] for t in terms if t.startswith("!") and len(t) > 1]
                        m = pd.Series(not inc, index=df.index)
                        for t in inc:
                            m |= sv.str.contains(t, case=False, regex=False)
                        for t in exc:
                            m &= ~sv.str.contains(t, case=False, regex=False)
                        df = df[m]
        st.caption(f"{len(df):,} rows")
    st.dataframe(df, hide_index=True, alt=alt_text, **kwargs)


tab_sum, tab_ecu, tab_out, tab_ev, tab_svc, tab_str = st.tabs([
    ":material/description: Summary", ":material/memory: ECUs", ":material/timeline: Outages",
    ":material/list: Events", ":material/hub: Services", ":material/stacked_line_chart: Streams"])

summary_md = sca.summary_markdown(res, capture_name)
with tab_sum:
    with st.container(horizontal=True):
        st.download_button("Download summary.md", summary_md.encode(), f"{Path(capture_name).stem}_summary.md", "text/markdown",
                           icon=":material/download:", key="dl_md_tab")
        st.caption("Covers the whole capture; table filters are not applied.")
    with st.container(border=True):
        st.markdown(summary_md)

with tab_ecu:
    hosts: pd.DataFrame = res["hosts"]
    conv: pd.DataFrame = res["conversations"]
    q = st.text_input("ECU name or IP contains", placeholder="e.g. SGA, HPA, 198.19.0.", key="ecu_q").strip()
    if q:
        hm = hosts.name.fillna("").str.contains(q, case=False, regex=False) | hosts.ip.str.contains(q, regex=False)
    elif sel_ecus:
        hm = hosts.name.isin(sel_ecus)
    else:
        hm = pd.Series(True, index=hosts.index)
    h = hosts[hm]
    ips = set(h.ip)

    if q or sel_ecus:
        tx = h[h.tx_frames > 0]
        with st.container(horizontal=True):
            if len(tx):
                f = tx.loc[tx.first_tx_s.idxmin()]
                st.metric("First alive (transmit)", f"{f.first_tx_s:.3f} s", border=True,
                          help=f"{f['name']} {f.ip} at {f.first_tx_utc} UTC")
                st.metric("Last transmit", f"{tx.last_tx_s.max():.3f} s", border=True)
            else:
                st.metric("First alive (transmit)", "never", border=True)
            st.metric("Addresses transmitting", f"{len(tx)} / {len(h)}", border=True)
            st.metric("Silent but addressed", int((h.state == "silent (addressed only)").sum()), border=True)
        for r in h.itertuples(index=False):
            if r.tx_frames:
                st.markdown(f"- **{r.name or r.ip}** `{r.ip}`: first transmit **{r.first_tx_s:.3f} s** "
                            f"({r.first_tx_utc} UTC), {r.state}; sends {r.tx_protocols}")
            elif pd.notna(r.first_rx_s):
                what = "multicast group" if r.state == "multicast group" else ":orange[never transmits]"
                st.markdown(f"- **{r.name or r.ip}** `{r.ip}`: {what}, receives {r.rx_protocols} "
                            f"from {r.rx_from} since {r.first_rx_s:.3f} s")
            else:
                st.markdown(f"- **{r.name or r.ip}** `{r.ip}`: :gray[not present in capture]")

    act = res["activity"]
    act = act[act.ip.isin(ips)].assign(kind="transmitting")
    rx_only = h[(h.tx_frames == 0) & h.first_rx_s.notna()]
    act = pd.concat([act, pd.DataFrame({"ip": rx_only.ip, "name": rx_only.name, "start_s": rx_only.first_rx_s,
                                        "end_s": rx_only.last_rx_s, "kind": "only receiving"})])
    if not act.empty:
        act = act.assign(lane=act.name.fillna("").where(act.name.fillna("") != "", act.ip) + " (" + act.ip + ")")
        lanes = act.groupby("lane").start_s.min().nsmallest(150).index
        act = act[act.lane.isin(lanes)]
        st.altair_chart(alt.Chart(act).mark_bar(minBandSize=2).encode(
            x=alt.X("start_s:Q", title="Capture time (s)", scale=alt.Scale(domain=list(t_range))),
            x2="end_s:Q",
            y=alt.Y("lane:N", title=None, sort=alt.EncodingSortField("start_s", op="min"),
                    axis=alt.Axis(labelLimit=320)),
            color=alt.Color("kind:N", title=None, scale=alt.Scale(domain=["transmitting", "only receiving"],
                                                                  range=["#2ca02c", "#ff7f0e"])),
            tooltip=["name", "ip", "kind", "start_s", "end_s"],
        ).properties(height=max(120, 18 * act.lane.nunique())),
            alt="Per-address activity: when each ECU address was transmitting or only being addressed")
        st.caption("Green: address is transmitting (bars split at abnormal silences). "
                   "Orange: address only receives traffic and never transmits.")

    st.subheader("Addresses")
    filtered_table(h, "t_hosts", "Per-address liveness summary")
    st.subheader("Conversations")
    c = conv if not (q or sel_ecus) else conv[conv.src_ip.isin(ips) | conv.dst_ip.isin(ips)]
    c = c[(c.last_s >= t_range[0]) & (c.first_s <= t_range[1])]
    filtered_table(c, "t_conv", "IP conversations with VLAN, protocol and first/last time")

with tab_out:
    cats = sorted(out.category.unique())
    default_cats = [c for c in cats if "not yet" not in c] or cats
    sel_cats = st.pills("Category", cats, selection_mode="multi", default=default_cats, key="cats")
    o = apply_filters(out, "start_s", "end_s")
    o = o[o.category.isin(sel_cats or [])]
    if o.empty:
        st.info("No outages match the filters.", icon=":material/check_circle:")
    else:
        o = o.assign(lane=o.category + " · " + o.service.where(o.service != "", "-") + " · " + o.src_name.where(
            o.src_name != "", o.src_ip) + o.dst_name.where(o.dst_name == "", " → " + o.dst_name))
        max_lanes = st.number_input("Max lanes", 10, 2000, 150, step=10)
        top = o.groupby("lane").duration_s.sum().nlargest(int(max_lanes)).index
        g = o[o.lane.isin(top)]
        chart = alt.Chart(g).mark_bar(minBandSize=2).encode(
            x=alt.X("start_s:Q", title="Capture time (s)", scale=alt.Scale(domain=list(t_range))),
            x2="end_s:Q",
            y=alt.Y("lane:N", title=None, sort=alt.EncodingSortField("start_s", op="min"),
                    axis=alt.Axis(labelLimit=420)),
            color=alt.Color("category:N", title="Category"),
            opacity=alt.condition("datum.resolved", alt.value(0.9), alt.value(0.45)),
            tooltip=["category", "start_s", "end_s", "duration_s", "resolved", "service", "instance",
                     "method_or_eventgroup", "src_name", "src_ip", "dst_name", "dst_ip", "detail"],
        ).properties(height=max(200, 18 * g.lane.nunique()))
        st.altair_chart(chart, alt="Gantt chart of communication outages from stop to resume")
        st.caption("Bars run from the moment communication stopped to when it resumed. "
                   "Faded bars were still unresolved at capture end.")
        filtered_table(o.drop(columns="lane"), "t_out", "Outage intervals",
                       column_config={"duration_s": st.column_config.NumberColumn("duration_s", format="%.3f")})

with tab_ev:
    sevs = ["ERROR", "WARN", "STATE"]
    with st.container(horizontal=True):
        sel_sev = st.pills("Severity", sevs, selection_mode="multi", default=["ERROR", "WARN"], key="sev")
        kinds = sorted(ev.event.unique())
        sel_kinds = st.multiselect("Event type", kinds, placeholder="All event types")
    e = apply_filters(ev, "t_rel_s")
    e = e[e.severity.isin(sel_sev or [])]
    if sel_kinds:
        e = e[e.event.isin(sel_kinds)]
    if not e.empty:
        st.altair_chart(alt.Chart(e.head(20000)).mark_tick(thickness=2).encode(
            x=alt.X("t_rel_s:Q", title="Capture time (s)", scale=alt.Scale(domain=list(t_range))),
            y=alt.Y("event:N", title=None),
            color=alt.Color("severity:N", scale=SEV_COLORS),
            tooltip=["time_utc", "t_rel_s", "event", "service", "instance", "method_or_eventgroup",
                     "src_name", "dst_name", "detail"],
        ).properties(height=max(150, 22 * e.event.nunique())), alt="Event occurrences over capture time")
    filtered_table(e, "t_ev", "Detected events", height=500)

with tab_svc:
    sv = res["services"]
    if sel_ecus:
        sv = sv[sv.provider_name.isin(sel_ecus)]
    if svc_q:
        sv = sv[sv.service.str.contains(svc_q.strip().lower().removeprefix("0x"), regex=False)]
    only_bad = st.toggle("Only services with problems", value=True)
    if only_bad:
        sv = sv[(sv.final_state != "offered") | (sv.subs_failing > 0) | (sv.unanswered > 0) | (sv.stop_offers > 0)
                | (sv.sub_nack_total > 0) | (sv.sub_noack_total > 0)]
    filtered_table(sv, "t_svc", "Offered service instances with subscription and RPC health")

with tab_str:
    sr = res["streams"]
    if sel_ecus:
        sr = sr[sr.src_name.isin(sel_ecus) | sr.dst_name.isin(sel_ecus)]
    if svc_q:
        sr = sr[sr.service.str.contains(svc_q.strip().lower().removeprefix("0x"), regex=False)]
    if st.toggle("Only streams with gaps", value=False):
        sr = sr[sr.gaps > 0]
    filtered_table(sr, "t_str", "SOME/IP message streams with period and gap statistics")

with st.sidebar:
    st.divider()
    st.subheader("Export")
    st.download_button("summary.md", summary_md.encode(), f"{Path(capture_name).stem}_summary.md", "text/markdown",
                       icon=":material/description:", width="stretch", type="primary", key="dl_md")
    for name in ("events", "outages", "services", "streams", "hosts", "conversations"):
        st.download_button(f"{name}.csv", res[name].to_csv(index=False).encode(),
                   f"{Path(capture_name).stem}_{name}.csv",
                           "text/csv", icon=":material/download:", width="stretch", key=f"dl_{name}")
