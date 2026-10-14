"""Stateful SOME/IP service, RPC, stream, and host analysis."""
from __future__ import annotations

from array import array
from collections import Counter

import numpy as np

from .capture import CaptureReader
from .common import MT_NAMES, SD_INFINITE_TTL
from .profiles import Names

# ---------------------------------------------------------------- analysis
class Analyzer:
    def __init__(self, a, names: Names):
        self.a = a
        self.name = names
        self.services = set(a.service) if a.service else None
        self.ev: list[tuple] = []
        self.streams: dict[tuple, array] = {}
        self.hosts: dict[int, np.ndarray] = {}
        self.conv: dict[tuple, list] = {}
        self.host_segments: dict[int, list] = {}
        self.pending_req: dict[tuple, float] = {}
        self.req_state: dict[tuple, list] = {}     # [streak_start, streak_n, unanswered_total, last_rc, n_req, n_resp]
        self.sd_sess: dict[tuple, tuple] = {}
        self.offers: dict[tuple, list] = {}        # [offered, first, last, ttl, n_offer, n_stop]
        self.offer_by_ps: dict[tuple, list] = {}
        self.pending_sub: dict[tuple, float] = {}
        self.sub_state: dict[tuple, list] = {}     # [state, since, noack_total, nack_total]
        self.pending_find: dict[tuple, float] = {}
        self.find_unans: dict[tuple, float] = {}
        self.evt_wait: dict[tuple, dict] = {}
        self.last_notif: dict[tuple, float] = {}
        self.t_first = None
        self.t_last = 0.0
        self.stats = Counter()

    def emit(self, ts, kind, sev, sid=None, inst=None, sub=None, src=None, dst=None, detail=''):
        self.ev.append((ts, kind, sev, sid, inst, sub, src, dst, detail))

    # ---------------- record loop
    def run(self, path: str, workers: int):
        host_parts: dict[int, list] = {}
        conv = self.conv
        svc = self.services
        msg, sd = self._msg, self._sd
        next_sweep = 0.0
        for recs, hosts, cv, n_frames in CaptureReader(path, workers):
            self.stats['frames'] += n_frames
            for ip, b in hosts.items():
                host_parts.setdefault(ip, []).append(b)
            for k, v in cv.items():
                c = conv.get(k)
                if c is None:
                    conv[k] = v
                else:
                    c[0] += v[0]
                    c[1] = min(c[1], v[1])
                    c[2] = max(c[2], v[2])
                    c[3] += v[3]
                    c[4] += v[4]
            for r in recs:
                ts = r[1]
                if ts > self.t_last:
                    self.t_last = ts
                    if ts >= next_sweep:
                        if self.t_first is None:
                            self.t_first = ts
                        self._sweep(ts)
                        next_sweep = ts + 0.05
                if r[0]:
                    sd(*r[1:])
                elif svc is None or r[4] in svc:
                    msg(*r[1:])
        self.hosts = {ip: np.frombuffer(b''.join(parts), dtype=np.float64) for ip, parts in host_parts.items()}
        if self.hosts:
            first = min(float(a.min()) for a in self.hosts.values())
            self.t_first = first if self.t_first is None else min(self.t_first, first)
            self.t_last = max(self.t_last, max(float(a.max()) for a in self.hosts.values()))

    def _msg(self, ts, src, dst, sid, mid, cid, ses, bmt, rc):
        self.stats['someip_msgs'] += 1
        k = (src, dst, sid, mid, bmt)
        a = self.streams.get(k)
        if a is None:
            a = self.streams[k] = array('d')
        a.append(ts)
        if bmt == 0x02:
            self.last_notif[(src, sid, dst)] = ts
            if self.evt_wait:
                w = self.evt_wait.get((src, sid))
                if w:
                    if dst >> 28 == 0xE:
                        w.clear()
                    else:
                        w.pop(dst, None)
        elif bmt == 0x00:
            self.pending_req[(src, dst, sid, mid, cid, ses)] = ts
            st = self.req_state.get((src, dst, sid, mid))
            if st is None:
                st = self.req_state[(src, dst, sid, mid)] = [None, 0, 0, 0, 0, 0]
            st[4] += 1
        elif bmt >= 0x80:
            mk = (dst, src, sid, mid)
            self.pending_req.pop((dst, src, sid, mid, cid, ses), None)
            st = self.req_state.get(mk)
            if st is None:
                return
            st[5] += 1
            if st[0] is not None:
                self.emit(ts, 'RESPONSE_RESUMED', 'STATE', sid, None, mid, src, dst,
                          f'after {st[1]} unanswered request(s) over {ts - st[0]:.3f}s')
                st[0] = None
                st[1] = 0
            code = rc if bmt == 0x80 else (rc or -1)
            if code != st[3]:
                if code:
                    self.emit(ts, 'ERROR_RESPONSE', 'ERROR', sid, None, mid, src, dst,
                              f'msg_type={MT_NAMES[bmt]} return_code=0x{rc:02x}')
                else:
                    self.emit(ts, 'RESPONSE_OK_AGAIN', 'STATE', sid, None, mid, src, dst, '')
                st[3] = code

    def _sd(self, ts, src, dst, sport, ses, reboot, ents):
        self.stats['sd_msgs'] += 1
        mc = dst >> 28 == 0xE
        sk = (src, sport, None if mc else dst)  # session counters are per sender port and per unicast peer
        prev = self.sd_sess.get(sk)
        if prev is None:
            if reboot and ses <= 2 and ts - (self.t_first or ts) > self.a.grace:
                self.emit(ts, 'ECU_SD_STARTUP', 'STATE', src=src, dst=dst, detail=f'first SD with reboot flag, session={ses}')
        elif reboot and (not prev[1] or prev[0] - ses > 2):  # tolerate tap duplicates/reordering
            self.emit(ts, 'ECU_REBOOT', 'ERROR', src=src, dst=dst,
                      detail=f'SD reboot detected ({"multicast" if mc else "unicast"}) session {prev[0]} -> {ses}')
        self.sd_sess[sk] = (ses, reboot)

        svc = self.services
        for typ, sid, inst, major, ttl, eg in ents:
            if svc is not None and sid not in svc:
                continue
            if typ == 0x01:
                self._offer(ts, src, dst, sid, inst, major, ttl)
            elif typ == 0x06:
                self._subscribe(ts, src, dst, sid, inst, eg, ttl)
            elif typ == 0x07:
                self._sub_ack(ts, src, dst, sid, inst, eg, ttl)
            elif typ == 0x00:
                k = (src, sid, inst)
                if k not in self.pending_find and k not in self.find_unans:
                    self.pending_find[k] = ts

    def _offer(self, ts, prov, dst, sid, inst, major, ttl):
        k = (prov, sid, inst)
        st = self.offers.get(k)
        if ttl == 0:
            if st is not None:
                st[5] += 1
                if st[0]:
                    st[0] = False
                    self.emit(ts, 'OFFER_STOPPED', 'STATE', sid, inst, None, prov, dst, 'StopOfferService')
            return
        if st is None:
            st = self.offers[k] = [True, ts, ts, ttl, 0, 0]
            self.offer_by_ps[(prov, sid)] = st
            late = ts - (self.t_first or ts)
            if late > self.a.grace:
                self.emit(ts, 'OFFER_STARTED', 'STATE', sid, inst, None, prov, dst,
                          f'first offer {late:.3f}s after capture start, major={major} ttl={ttl}')
        elif not st[0]:
            st[0] = True
            self.emit(ts, 'OFFER_RESUMED', 'STATE', sid, inst, None, prov, dst, f'after StopOffer, down {ts - st[2]:.3f}s')
        elif st[3] != SD_INFINITE_TTL and ts - st[2] > st[3]:
            self.emit(st[2] + st[3], 'OFFER_EXPIRED', 'ERROR', sid, inst, None, prov, None,
                      f'TTL {st[3]}s elapsed without re-offer')
            self.emit(ts, 'OFFER_RESUMED', 'STATE', sid, inst, None, prov, dst, f'gap {ts - st[2]:.3f}s')
        st[2] = ts
        st[3] = ttl
        st[4] += 1
        if self.find_unans or self.pending_find:
            for fk in [fk for fk in self.pending_find if fk[1] == sid and fk[2] in (inst, 0xFFFF)]:
                del self.pending_find[fk]
            for fk in [fk for fk in self.find_unans if fk[1] == sid and fk[2] in (inst, 0xFFFF)]:
                t0 = self.find_unans.pop(fk)
                self.emit(ts, 'SERVICE_FOUND', 'STATE', sid, inst, None, prov, fk[0],
                          f'offer seen {ts - t0:.3f}s after unanswered FindService')

    def _subscribe(self, ts, subr, prov, sid, inst, eg, ttl):
        k = (subr, prov, sid, inst, eg)
        if ttl == 0:
            self.pending_sub.pop(k, None)
            st = self.sub_state.get(k)
            if st is not None and st[0] != 'stopped':
                st[0], st[1] = 'stopped', ts
                self.emit(ts, 'SUBSCRIBE_STOPPED', 'STATE', sid, inst, eg, subr, prov, 'StopSubscribeEventgroup')
            return
        if k not in self.pending_sub:
            self.pending_sub[k] = ts

    def _sub_ack(self, ts, prov, subr, sid, inst, eg, ttl):
        k = (subr, prov, sid, inst, eg)
        t0 = self.pending_sub.pop(k, None)
        st = self.sub_state.get(k)
        if st is None:
            st = self.sub_state[k] = ['none', ts, 0, 0]
        if ttl == 0:
            st[3] += 1
            if st[0] != 'nack':
                st[0], st[1] = 'nack', ts
                self.emit(ts, 'SUBSCRIBE_NACK', 'ERROR', sid, inst, eg, prov, subr, 'SubscribeEventgroupNack')
            return
        if st[0] != 'acked':
            prev = st[0]
            st[0], st[1] = 'acked', ts
            if prev != 'none' or ts - (self.t_first or ts) > self.a.grace:
                lat = f', ack latency {(ts - t0) * 1e3:.1f}ms' if t0 is not None else ''
                self.emit(ts, 'SUBSCRIBED', 'STATE', sid, inst, eg, prov, subr, f'previous state: {prev}{lat}')
            last = max(self.last_notif.get((prov, sid, subr), 0.0), 0.0)
            if ts - last > self.a.event_timeout:
                self.evt_wait.setdefault((prov, sid), {}).setdefault(subr, ts)

    def _sweep(self, now):
        if self.pending_req:
            lim = now - self.a.req_timeout
            for k in [k for k, t in self.pending_req.items() if t < lim]:
                t = self.pending_req.pop(k)
                st = self.req_state[k[:4]]
                st[2] += 1
                if st[0] is None:
                    st[0] = t
                    cli, srv, sid, mid = k[:4]
                    o = self.offer_by_ps.get((srv, sid))
                    offered = 'yes' if o and o[0] else ('stopped' if o else 'never seen')
                    self.emit(t, 'REQUEST_NO_RESPONSE', 'ERROR', sid, None, mid, cli, srv,
                              f'no response within {self.a.req_timeout}s (client_id=0x{k[4]:04x} '
                              f'session=0x{k[5]:04x}); service offered by server: {offered}')
                st[1] += 1
        if self.pending_sub:
            lim = now - self.a.sd_timeout
            for k in [k for k, t in self.pending_sub.items() if t < lim]:
                t = self.pending_sub.pop(k)
                st = self.sub_state.get(k)
                if st is None:
                    st = self.sub_state[k] = ['none', t, 0, 0]
                st[2] += 1
                if st[0] != 'noack':
                    st[0], st[1] = 'noack', t
                    subr, prov, sid, inst, eg = k
                    o = self.offers.get((prov, sid, inst))
                    self.emit(t, 'SUBSCRIBE_NO_ACK', 'ERROR', sid, inst, eg, subr, prov,
                              f'no Ack/Nack within {self.a.sd_timeout}s; provider offering: '
                              f'{"yes" if o and o[0] else "no"}')
        if self.pending_find:
            lim = now - self.a.find_timeout
            for k in [k for k, t in self.pending_find.items() if t < lim]:
                t = self.pending_find.pop(k)
                self.find_unans[k] = t
                self.emit(t, 'FIND_NO_OFFER', 'WARN', k[1], k[2], None, k[0], None,
                          f'no OfferService within {self.a.find_timeout}s')
        if self.evt_wait:
            lim = now - self.a.event_timeout
            for (prov, sid), w in self.evt_wait.items():
                for subr in [s for s, t in w.items() if t < lim]:
                    t = w.pop(subr)
                    self.emit(t, 'SUBSCRIBED_NO_EVENTS', 'WARN', sid, None, None, prov, subr,
                              f'SubscribeAck but no notification of service within {self.a.event_timeout}s')

    # ---------------- end-of-capture analysis
    def finish(self):
        if self.t_first is None:
            return
        a, t0, t1 = self.a, self.t_first, self.t_last
        self._sweep(t1)
        for (cli, srv, sid, mid), st in self.req_state.items():
            if st[0] is not None:
                self.emit(t1, 'REQUEST_NO_RESPONSE_END', 'ERROR', sid, None, mid, cli, srv,
                          f'{st[1]} request(s) still unanswered at end of capture (since {st[0] - t0:.3f}s)')
        for (prov, sid, inst), st in self.offers.items():
            if st[0] and st[3] != SD_INFINITE_TTL and t1 - st[2] > st[3]:
                self.emit(st[2] + st[3], 'OFFER_EXPIRED', 'ERROR', sid, inst, None, prov, None,
                          f'TTL {st[3]}s elapsed, not re-offered until end of capture')
        for (subr, prov, sid, inst, eg), st in self.sub_state.items():
            if st[0] in ('noack', 'nack'):
                self.emit(t1, 'SUBSCRIPTION_FAILED_END', 'ERROR', sid, inst, eg, subr, prov,
                          f'still {st[0]} at end of capture (since {st[1] - t0:.3f}s)')

        self.stream_rows = []
        for (src, dst, sid, mid, mt), arr in self.streams.items():
            t = _dedup(np.frombuffer(arr, dtype=np.float64))
            row = dict(src=src, dst=dst, sid=sid, mid=mid, mt=mt, count=len(arr), first=t[0] - t0, last=t[-1] - t0,
                       median_ms='', p90_ms='', periodic=False, gaps=0, max_gap=0.0)
            if len(t) >= a.min_count:
                dt = np.diff(t)
                med, p90 = float(np.median(dt)), float(np.percentile(dt, 90))
                row.update(median_ms=round(med * 1e3, 3), p90_ms=round(p90 * 1e3, 3), max_gap=round(float(dt.max()), 3))
                if med > 0 and p90 <= 3 * med:
                    row['periodic'] = True
                    thr = max(a.min_gap, a.gap_factor * med)
                    idx = np.nonzero(dt > thr)[0]
                    row['gaps'] = len(idx)
                    for i in idx:
                        self.emit(t[i], 'STREAM_STOPPED', 'ERROR', sid, None, mid, src, dst,
                                  f'{MT_NAMES[mt]} period {med * 1e3:.1f}ms, silent {dt[i]:.3f}s')
                        self.emit(t[i + 1], 'STREAM_RESUMED', 'STATE', sid, None, mid, src, dst,
                                  f'{MT_NAMES[mt]} after {dt[i]:.3f}s gap')
                    grace = max(thr, a.grace)
                    if t[0] - t0 > grace:
                        self.emit(t[0], 'STREAM_STARTED', 'STATE', sid, None, mid, src, dst,
                                  f'{MT_NAMES[mt]} first seen {t[0] - t0:.3f}s after capture start')
                    if t1 - t[-1] > grace:
                        self.emit(t[-1], 'STREAM_ENDED', 'ERROR', sid, None, mid, src, dst,
                                  f'{MT_NAMES[mt]} last seen {t1 - t[-1]:.3f}s before capture end')
            self.stream_rows.append(row)

        for ip, arr in self.hosts.items():
            if ip >> 28 == 0xE:
                continue
            t = _dedup(arr)
            if len(t) < a.min_count:
                continue
            dt = np.diff(t)
            # only gaps that are abnormal for this host's own sending pattern
            thr = max(a.host_gap, a.gap_factor * float(np.percentile(dt, 99)))
            idx = np.nonzero(dt > thr)[0]
            bounds = np.concatenate(([t[0]], t[idx + 1])), np.concatenate((t[idx], [t[-1]]))
            self.host_segments[ip] = list(zip(bounds[0].tolist(), bounds[1].tolist()))
            for i in idx:
                self.emit(t[i], 'HOST_SILENT', 'ERROR', src=ip, detail=f'no IP traffic sent for {dt[i]:.3f}s')
                self.emit(t[i + 1], 'HOST_ACTIVE', 'STATE', src=ip, detail=f'transmitting again after {dt[i]:.3f}s')
            if t[0] - t0 > max(a.host_gap, a.grace):
                self.emit(t[0], 'HOST_FIRST_SEEN', 'STATE', src=ip, detail=f'{t[0] - t0:.3f}s after capture start')
            if t1 - t[-1] > max(a.host_gap, a.grace):
                self.emit(t[-1], 'HOST_LAST_SEEN', 'ERROR', src=ip, detail=f'{t1 - t[-1]:.3f}s before capture end')
        self.ev.sort(key=lambda e: e[0])


def _dedup(t: np.ndarray) -> np.ndarray:
    """Sort and drop copies of the same frame captured on several taps (<200us apart)."""
    t = np.sort(t)
    if len(t) > 1:
        t = t[np.concatenate(([True], np.diff(t) > 2e-4))]
    return t
