"""Analysis result dataframes, Markdown summaries, and CSV report output."""
from __future__ import annotations

import ipaddress
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from .common import EVENT_COLS, MT_NAMES, pd
from .engine import Analyzer, _dedup
from .profiles import Names, ip_str

# ---------------------------------------------------------------- output
def _hx(v, w=4):
    return '' if v is None else f'0x{v:0{w}x}'


def _name(names: Names, ip):
    return names(ip) if ip is not None else ''


def events_frame(an: Analyzer, names: Names) -> pd.DataFrame:
    t0 = an.t_first or 0.0
    rows = [(_utc(ts), round(ts - t0, 6), sev, kind, _hx(sid), _hx(inst), _hx(sub),
             ip_str(src), _name(names, src), ip_str(dst), _name(names, dst), detail)
            for ts, kind, sev, sid, inst, sub, src, dst, detail in an.ev]
    return pd.DataFrame(rows, columns=EVENT_COLS)


def streams_frame(an: Analyzer, names: Names) -> pd.DataFrame:
    rows = [(ip_str(r['src']), names(r['src']), ip_str(r['dst']), names(r['dst']), _hx(r['sid']), _hx(r['mid']),
             MT_NAMES[r['mt']], r['count'], round(r['first'], 3), round(r['last'], 3),
             r['median_ms'] if r['median_ms'] != '' else None, r['p90_ms'] if r['p90_ms'] != '' else None,
             r['periodic'], r['gaps'], r['max_gap'])
            for r in sorted(an.stream_rows, key=lambda r: (r['sid'], r['mid'], r['src'], r['dst']))]
    return pd.DataFrame(rows, columns=['src_ip', 'src_name', 'dst_ip', 'dst_name', 'service', 'method', 'msg_type',
                                       'count', 'first_rel_s', 'last_rel_s', 'median_period_ms', 'p90_period_ms',
                                       'periodic', 'gaps', 'max_gap_s'])


PORT_NAMES = {30490: 'SOME/IP-SD', 3490: 'DLT', 13400: 'DoIP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP',
              319: 'PTP', 320: 'PTP', 514: 'syslog', 5353: 'mDNS', 5555: 'XCP'}
IP_PROTOS = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP'}


def _proto_label(proto, sp, dp, someip_n):
    lbl = PORT_NAMES.get(dp) or PORT_NAMES.get(sp)
    if lbl:
        return lbl
    if someip_n:
        return 'SOME/IP'
    return IP_PROTOS.get(proto, f'IP{proto}')


def conversations_frame(an: Analyzer, names: Names) -> pd.DataFrame:
    t0 = an.t_first or 0.0
    rows = [(round(c[1] - t0, 6), round(c[2] - t0, 6), _utc(c[1]), ip_str(src), names(src), ip_str(dst), names(dst),
             f'0x{vlan:03x}' if vlan else '', _proto_label(proto, sp, dp, c[4]), IP_PROTOS.get(proto, str(proto)),
             sp, dp, c[0], c[3], c[4])
            for (src, dst, vlan, proto, sp, dp), c in an.conv.items()]
    df = pd.DataFrame(rows, columns=['first_s', 'last_s', 'first_utc', 'src_ip', 'src_name', 'dst_ip', 'dst_name',
                                     'vlan', 'protocol', 'transport', 'sport', 'dport', 'frames', 'bytes',
                                     'someip_msgs'])
    return df.sort_values(['first_s', 'src_ip']).reset_index(drop=True)


def hosts_frame(an: Analyzer, names: Names, conv: pd.DataFrame) -> pd.DataFrame:
    """Per-address liveness: when it first/last transmitted, silences, what it received, and profile ECUs never seen."""
    t0, dur, grace = an.t_first or 0.0, an.t_last - (an.t_first or 0.0), an.a.grace
    tx = conv.groupby('src_ip').agg(vlans=('vlan', lambda s: ' '.join(sorted(set(s) - {''}))),
                                    tx_protocols=('protocol', lambda s: ', '.join(sorted(set(s)))),
                                    tx_peers=('dst_ip', 'nunique'), someip_tx=('someip_msgs', 'sum'),
                                    tx_frames=('frames', 'sum'))
    rx = conv.groupby('dst_ip').agg(first_rx_s=('first_s', 'min'), last_rx_s=('last_s', 'max'),
                                    rx_frames=('frames', 'sum'), rx_from=('src_name', lambda s: ', '.join(
                                        sorted(set(s) - {''})[:8])),
                                    rx_protocols=('protocol', lambda s: ', '.join(sorted(set(s)))),
                                    rx_vlans=('vlan', lambda s: ' '.join(sorted(set(s) - {''}))))
    rows = []
    for ip in set(an.hosts) | {int(ipaddress.IPv4Address(x)) for x in rx.index}:
        s = ip_str(ip)
        mc = ip >> 28 == 0xE
        arr = an.hosts.get(ip)
        segs = an.host_segments.get(ip) or ([(float(arr.min()), float(arr.max()))] if arr is not None else [])
        r = dict(ip=s, name=names(ip), first_tx_s=None, first_tx_utc='', last_tx_s=None, tx_frames=0,
                 active_segments=len(segs), longest_silence_s=None)
        if arr is not None and not mc:
            first, last = segs[0][0], segs[-1][1]
            gaps = [b[0] - a[1] for a, b in zip(segs, segs[1:])]
            r.update(first_tx_s=round(first - t0, 3), first_tx_utc=_utc(first), last_tx_s=round(last - t0, 3),
                     tx_frames=len(arr), longest_silence_s=round(max(gaps), 3) if gaps else None)
            st = []
            if first - t0 > grace:
                st.append('appeared late')
            if len(segs) > 1:
                st.append(f'interrupted x{len(segs) - 1}')
            if dur - (last - t0) > grace:
                st.append('stopped early')
            state = ', '.join(st) or 'active whole capture'
        else:
            state = 'multicast group' if mc else 'silent (addressed only)'
        r['state'] = state
        if s in tx.index:
            r.update(tx.loc[s].to_dict())
        if s in rx.index:
            r.update(rx.loc[s].to_dict())
        rows.append(r)
    seen = {r['ip'] for r in rows}
    for ip, name in names.hosts.items():
        s = ip_str(ip)
        if ip and s not in seen:
            rows.append(dict(ip=s, name=name, state='never seen', tx_frames=0, active_segments=0))
    cols = ['ip', 'name', 'state', 'vlans', 'first_tx_s', 'first_tx_utc', 'last_tx_s', 'tx_frames', 'active_segments',
            'longest_silence_s', 'tx_protocols', 'tx_peers', 'someip_tx', 'first_rx_s', 'last_rx_s', 'rx_frames',
            'rx_vlans', 'rx_protocols', 'rx_from']
    df = pd.DataFrame(rows).reindex(columns=cols)
    order = {'never seen': 3, 'multicast group': 2, 'silent (addressed only)': 1}
    df['_o'] = df.state.map(order).fillna(0)
    return df.sort_values(['_o', 'first_tx_s', 'first_rx_s', 'ip']).drop(columns='_o').reset_index(drop=True)


def activity_frame(an: Analyzer, names: Names) -> pd.DataFrame:
    """Transmit-activity intervals per unicast host (split at abnormal silences)."""
    t0 = an.t_first or 0.0
    rows = []
    for ip, arr in an.hosts.items():
        if ip >> 28 == 0xE:
            continue
        segs = an.host_segments.get(ip) or [(float(arr.min()), float(arr.max()))]
        for a, b in segs:
            rows.append((ip_str(ip), names(ip), round(a - t0, 3), round(b - t0, 3)))
    return pd.DataFrame(rows, columns=['ip', 'name', 'start_s', 'end_s'])


def services_frame(an: Analyzer, names: Names) -> pd.DataFrame:
    """One row per offered service instance with subscription and RPC health."""
    t0 = an.t_first or 0.0
    subs: dict[tuple, Counter] = {}
    for (subr, prov, sid, inst, eg), st in an.sub_state.items():
        c = subs.setdefault((prov, sid, inst), Counter())
        c[st[0]] += 1
        c['noack_total'] += st[2]
        c['nack_total'] += st[3]
    rpc: dict[tuple, list] = {}
    for (cli, srv, sid, mid), st in an.req_state.items():
        r = rpc.setdefault((srv, sid), [0, 0, 0])
        r[0] += st[4]
        r[1] += st[5]
        r[2] += st[2]
    rows = []
    for (prov, sid, inst), st in an.offers.items():
        c = subs.get((prov, sid, inst), Counter())
        req, resp, unans = rpc.get((prov, sid), (0, 0, 0))
        rows.append((ip_str(prov), names(prov), _hx(sid), _hx(inst), 'offered' if st[0] else 'stopped',
                     round(st[1] - t0, 3), round(st[2] - t0, 3), st[3], st[4], st[5],
                     c['acked'], c['noack'] + c['nack'], c['noack_total'], c['nack_total'], req, resp, unans))
    return pd.DataFrame(rows, columns=['provider_ip', 'provider_name', 'service', 'instance', 'final_state',
                                       'first_offer_s', 'last_offer_s', 'ttl_s', 'offers', 'stop_offers',
                                       'subs_acked', 'subs_failing', 'sub_noack_total', 'sub_nack_total',
                                       'requests', 'responses', 'unanswered'])


# start event -> (end events, outage category); key fields are normalised to (svc, inst, id, endpoint A, endpoint B)
_OUTAGE_PAIRS = {
    'STREAM_STOPPED': (('STREAM_RESUMED',), 'stream gap'),
    'STREAM_ENDED': ((), 'stream ended'),
    'HOST_SILENT': (('HOST_ACTIVE',), 'host silent'),
    'HOST_LAST_SEEN': ((), 'host gone'),
    'OFFER_STOPPED': (('OFFER_RESUMED',), 'offer stopped'),
    'OFFER_EXPIRED': (('OFFER_RESUMED',), 'offer expired'),
    'REQUEST_NO_RESPONSE': (('RESPONSE_RESUMED',), 'no response'),
    'SUBSCRIBE_NO_ACK': (('SUBSCRIBED',), 'subscribe no ack'),
    'SUBSCRIBE_NACK': (('SUBSCRIBED',), 'subscribe nack'),
    'FIND_NO_OFFER': (('SERVICE_FOUND',), 'find no offer'),
}
_LATE_START = {'STREAM_STARTED': 'stream not yet started', 'HOST_FIRST_SEEN': 'host not yet seen',
               'OFFER_STARTED': 'service not yet offered'}


def _outage_key(kind, r):
    if kind.startswith('HOST'):
        return (r.src_ip,)
    if kind.startswith('OFFER'):
        return (r.service, r.instance, r.src_ip)
    if kind.startswith('STREAM'):
        return (r.service, r.method_or_eventgroup, r.src_ip, r.dst_ip)
    if kind == 'REQUEST_NO_RESPONSE':
        return (r.service, r.method_or_eventgroup, r.src_ip, r.dst_ip)
    if kind == 'RESPONSE_RESUMED':
        return (r.service, r.method_or_eventgroup, r.dst_ip, r.src_ip)
    if kind == 'SUBSCRIBE_NO_ACK':
        return (r.service, r.instance, r.method_or_eventgroup, r.dst_ip, r.src_ip)
    if kind in ('SUBSCRIBE_NACK', 'SUBSCRIBED'):
        return (r.service, r.instance, r.method_or_eventgroup, r.src_ip, r.dst_ip)
    if kind == 'FIND_NO_OFFER':
        return (r.service, r.src_ip)
    if kind == 'SERVICE_FOUND':
        return (r.service, r.dst_ip)
    return None


def outages_frame(ev: pd.DataFrame, duration: float) -> pd.DataFrame:
    """Pair stop/resume events into [start, end] intervals (open intervals end at capture end)."""
    open_: dict[tuple, list] = {}
    ends: dict[str, list[str]] = {}
    for s, (es, _) in _OUTAGE_PAIRS.items():
        for e in es:
            ends.setdefault(e, []).append(s)
    rows = []
    for r in ev.itertuples(index=False):
        k = r.event
        if k in _LATE_START:
            rows.append((_LATE_START[k], 0.0, r.t_rel_s, r, True))
        if k in _OUTAGE_PAIRS:
            key = (k, _outage_key(k, r))
            if key not in open_:
                open_[key] = [r]
        for s in ends.get(k, ()):
            start = open_.pop((s, _outage_key(k, r)), None)
            if start:
                rows.append((_OUTAGE_PAIRS[s][1], start[0].t_rel_s, r.t_rel_s, start[0], True))
    for (s, _), (r,) in open_.items():
        rows.append((_OUTAGE_PAIRS[s][1], r.t_rel_s, duration, r, False))
    out = [(cat, st, en, round(en - st, 6), resolved, r.service, r.instance, r.method_or_eventgroup,
            r.src_ip, r.src_name, r.dst_ip, r.dst_name, r.detail) for cat, st, en, r, resolved in rows]
    df = pd.DataFrame(out, columns=['category', 'start_s', 'end_s', 'duration_s', 'resolved', 'service', 'instance',
                                    'method_or_eventgroup', 'src_ip', 'src_name', 'dst_ip', 'dst_name', 'detail'])
    return df.sort_values('start_s', kind='stable').reset_index(drop=True)


def analyze(path: str, opts, names: Names) -> dict:
    """Run the full analysis and return DataFrames + run statistics."""
    t = time.perf_counter()
    an = Analyzer(opts, names)
    an.run(path, opts.workers)
    t_parse = time.perf_counter() - t
    an.finish()
    if an.t_first is None:
        return {'empty': True, 'stats': dict(an.stats)}
    ev = events_frame(an, names)
    duration = an.t_last - an.t_first
    conv = conversations_frame(an, names)
    return {
        'empty': False,
        'events': ev,
        'streams': streams_frame(an, names),
        'services': services_frame(an, names),
        'outages': outages_frame(ev, duration),
        'hosts': hosts_frame(an, names, conv),
        'conversations': conv,
        'activity': activity_frame(an, names),
        'stats': {**an.stats, 'streams': len(an.streams), 'hosts': len(an.hosts), 't_first': an.t_first,
                  't_last': an.t_last, 'duration_s': duration, 'parse_s': t_parse,
                  'analyse_s': time.perf_counter() - t - t_parse},
    }


def _md_table(df: pd.DataFrame, cols: list[str], limit: int = 50) -> str:
    if df.empty:
        return '_None._\n'
    def cell(v):
        if v is None or (isinstance(v, float) and np.isnan(v)):
            return ''
        if isinstance(v, float):
            v = f'{v:.3f}'
        return str(v).replace('|', '\\|').replace('\n', ' ')
    lines = ['| ' + ' | '.join(cols) + ' |', '|' + '---|' * len(cols)]
    lines += ['| ' + ' | '.join(cell(v) for v in row) + ' |' for row in df[cols].head(limit).itertuples(index=False)]
    if len(df) > limit:
        lines.append(f'\n_{len(df) - limit} more rows not shown (see CSV export)._')
    return '\n'.join(lines) + '\n'


def _ecu(name, ip):
    return f'{name} ({ip})' if isinstance(name, str) and name else (ip or '')


def summary_markdown(res: dict, capture: str, limit: int = 50) -> str:
    """Human-readable Markdown report of the analysis result."""
    st, ev, out = res['stats'], res['events'], res['outages']
    hosts, svc, streams = res['hosts'], res['services'], res['streams']
    errs, warns = int((ev.severity == 'ERROR').sum()), int((ev.severity == 'WARN').sum())
    md = ['# SOME/IP communication summary', '',
          f'- **Capture:** `{Path(capture).name}`',
          f'- **Time:** {_utc(st["t_first"])} → {_utc(st["t_last"])} UTC ({st["duration_s"]:.1f} s)',
          f'- **Traffic:** {st["frames"]:,} frames, {st.get("someip_msgs", 0):,} SOME/IP messages, '
          f'{st.get("sd_msgs", 0):,} SD messages, {st["streams"]} SOME/IP streams',
          f'- **Findings:** {errs} errors, {warns} warnings, {int((~out.resolved).sum())} unresolved outages',
          f'- **ECU names:** `{res["profile"]} bundled profile`', '']

    # key findings in plain words
    kf = []
    late = hosts[hosts.state.str.contains('appeared late', na=False)]
    if len(late):
        f = late.sort_values('first_tx_s').iloc[0]
        kf.append(f'{len(late)} address(es) started transmitting after capture start; first: '
                  f'**{_ecu(f["name"], f.ip)}** at {f.first_tx_s:.3f} s ({f.first_tx_utc} UTC).')
    for r in hosts[hosts.state.str.contains('interrupted|stopped early', na=False)].itertuples(index=False):
        kf.append(f'**{_ecu(r.name, r.ip)}**: {r.state} (last transmit {r.last_tx_s:.3f} s'
                  + (f', longest silence {r.longest_silence_s:.3f} s' if pd.notna(r.longest_silence_s) else '') + ').')
    for r in hosts[hosts.state == 'silent (addressed only)'].itertuples(index=False):
        kf.append(f'**{_ecu(r.name, r.ip)}** never transmits but receives {r.rx_protocols} from {r.rx_from} '
                  f'since {r.first_rx_s:.3f} s.')
    for r in ev[ev.event == 'ECU_REBOOT'].itertuples(index=False):
        kf.append(f'ECU reboot detected: **{_ecu(r.src_name, r.src_ip)}** at {r.t_rel_s:.3f} s ({r.detail}).')
    for cat, g in out[~out.resolved & ~out.category.str.contains('not yet')].groupby('category'):
        kf.append(f'{len(g)} unresolved **{cat}** outage(s) at capture end.')
    bad = svc[(svc.final_state != 'offered') | (svc.subs_failing > 0) | (svc.unanswered > 0)]
    if len(bad):
        kf.append(f'{len(bad)} offered service instance(s) with stop-offer, failing subscriptions or unanswered '
                  f'requests (see Services).')
    md += ['## Key findings', ''] + ([f'- {k}' for k in kf] or ['- No anomalies detected.']) + ['']

    md += ['## ECU liveness', '',
           'Addresses that were not transmitting for the whole capture, plus addressed-but-silent ones.', '']
    hl = hosts[~hosts.state.isin(['active whole capture', 'never seen'])]
    md.append(_md_table(hl, ['ip', 'name', 'state', 'vlans', 'first_tx_s', 'first_tx_utc', 'last_tx_s',
                             'longest_silence_s', 'tx_protocols', 'first_rx_s', 'rx_protocols', 'rx_from'], limit))
    act = hosts[hosts.state == 'active whole capture']
    if len(act):
        md += [f'Active for the whole capture ({len(act)}): ' +
               ', '.join(_ecu(n, i) for n, i in zip(act.name, act.ip)), '']
    never = hosts[hosts.state == 'never seen']
    if len(never):
        names_ = [_ecu(n, i) for n, i in zip(never.name, never.ip)]
        md += [f'Known in profile but never seen ({len(never)}): ' + ', '.join(names_[:30])
               + (f', … and {len(names_) - 30} more (see hosts.csv)' if len(names_) > 30 else ''), '']

    md += ['## Event counts', '']
    cnt = ev.groupby(['severity', 'event']).size().reset_index(name='count')
    md.append(_md_table(cnt, ['severity', 'event', 'count'], 100))

    md += ['## Communication stopped / resumed', '',
           'Intervals from the moment communication stopped to when it resumed '
           '(start-up "not yet" intervals excluded).', '']
    o = out[~out.category.str.contains('not yet')].sort_values(['resolved', 'start_s'])
    md.append(_md_table(o, ['category', 'start_s', 'end_s', 'duration_s', 'resolved', 'service', 'instance',
                            'method_or_eventgroup', 'src_name', 'dst_name', 'detail'], limit))

    md += ['## Start-up order', '', 'When services, streams and hosts first appeared after capture start.', '']
    su = out[out.category.str.contains('not yet')].sort_values('end_s')
    md.append(_md_table(su.rename(columns={'end_s': 'first_seen_s'}),
                        ['first_seen_s', 'category', 'service', 'instance', 'method_or_eventgroup', 'src_name',
                         'dst_name'], limit))

    md += ['## Services with problems', '']
    md.append(_md_table(bad, ['provider_name', 'provider_ip', 'service', 'instance', 'final_state', 'offers',
                              'stop_offers', 'subs_acked', 'subs_failing', 'requests', 'responses', 'unanswered'],
                        limit))

    md += ['## SOME/IP streams with gaps', '']
    md.append(_md_table(streams[streams.gaps > 0].sort_values('max_gap_s', ascending=False),
                        ['src_name', 'dst_name', 'service', 'method', 'msg_type', 'count', 'median_period_ms',
                         'gaps', 'max_gap_s'], limit))

    md += ['## Errors and warnings', '']
    md.append(_md_table(ev[ev.severity != 'STATE'], ['t_rel_s', 'time_utc', 'severity', 'event', 'service',
                                                     'instance', 'method_or_eventgroup', 'src_name', 'dst_name',
                                                     'detail'], limit * 2))
    return '\n'.join(md)


def write_outputs(res: dict, outdir: Path, max_print: int, capture: str = ''):
    outdir.mkdir(parents=True, exist_ok=True)
    for name in ('events', 'streams', 'services', 'outages', 'hosts', 'conversations'):
        res[name].to_csv(outdir / f'{name}.csv', index=False)
    (outdir / 'summary.md').write_text(summary_markdown(res, capture), encoding='utf-8')
    st, ev = res['stats'], res['events']
    print(f'\nCapture: {_utc(st["t_first"])} .. {_utc(st["t_last"])} ({st["duration_s"]:.1f}s)')
    print('Event counts:')
    for (sev, kind), n in ev.groupby(['severity', 'event']).size().items():
        print(f'  {sev:5} {kind:26} {n}')
    shown = ev[(ev.severity != 'STATE') | ~ev.event.str.startswith(('STREAM_', 'HOST_'))].head(max_print)
    hs = res['hosts']
    hs = hs[~hs.state.isin(['active whole capture', 'never seen', 'multicast group'])]
    if len(hs):
        print('\nHost liveness (not active for the whole capture):')
        for r in hs.itertuples(index=False):
            when = f'first tx {r.first_tx_s:9.3f}s' if r.tx_frames else f'first rx {r.first_rx_s:9.3f}s'
            print(f'  {r.ip:16} {str(r.name):24} {when}  {r.state}')
    if len(shown):
        print(f'\nFirst {len(shown)} SD/RPC/state events (full list in events.csv):')
        for r in shown.itertuples(index=False):
            s = f'{r.src_ip}({r.src_name})' if r.src_ip else ''
            d = f' -> {r.dst_ip}({r.dst_name})' if r.dst_ip else ''
            print(f'  {r.t_rel_s:10.3f}s {r.severity:5} {r.event:24} svc={r.service} inst={r.instance} '
                  f'id={r.method_or_eventgroup} {s}{d} {r.detail}')
    print(f'\nWritten: {outdir} (summary.md + events, streams, services, outages, hosts, conversations .csv)')


def _utc(ts):
    return '' if ts is None else datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
