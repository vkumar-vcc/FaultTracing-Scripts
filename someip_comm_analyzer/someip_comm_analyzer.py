#!/usr/bin/env python3
"""SOME/IP communication-pattern analyser for automotive Ethernet captures.

Streams .pcapng/.pcap (optionally .zst/.gz) without tshark, unwraps ASAM CMP (0x99FE)
and reports, as a timeline:
  * SD: offer start / stop / TTL expiry / resume, ECU reboot (SD reboot flag),
        FindService without offer, Subscribe without Ack, Nack, StopSubscribe,
        SubscribeAck without any following notification
  * RPC: requests without response (episodes), error return codes, recovery
  * Streams: periodic SOME/IP streams that stop / resume / start late / end early
  * Hosts: ECUs going silent / coming back
ECU names come from the Wireshark profile's `hosts` and `subnets` files.

Usage:
  python someip_comm_analyzer.py capture.pcapng.zst [--profile VCC-SPA3-SDB17] [-o outdir]
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import os
import pickle
import queue
import socket
import struct
import sys
import threading
import time
from array import array
from collections import Counter, deque
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from multiprocessing import shared_memory
from pathlib import Path

import numpy as np


class _LazyPandas:
    """Defer the pandas import: parser worker processes never need it and spawn much faster without it."""

    def __getattr__(self, name):
        import pandas
        globals()['pd'] = pandas
        return getattr(pandas, name)


pd = _LazyPandas()

S_II_LE = struct.Struct('<II')
S_PCAP_REC_LE = struct.Struct('<IIII')
S_PCAP_REC_BE = struct.Struct('>IIII')
S_SOMEIP = struct.Struct('>HHIHHBBBB')
S_SD_ENT = struct.Struct('>B3xHHIxxH')  # type, service, instance, major<<24|ttl, eventgroup
S_U32 = struct.Struct('>I')

CHUNK = 64 << 20
JOB_SIZE = 16 << 20
OVERLAP = 4 << 20       # > largest pcapng block, so a block straddling a job boundary is complete
HOST_TS_RES = 0.005     # host liveness timestamps are kept at 5 ms resolution
S_U32_LE = struct.Struct('<I')
MT_NAMES = {0x00: 'REQUEST', 0x01: 'REQUEST_NO_RETURN', 0x02: 'NOTIFICATION', 0x80: 'RESPONSE', 0x81: 'ERROR'}
VALID_MT = frozenset(MT_NAMES)
# Well-known non-SOME/IP UDP/TCP ports (DNS, DHCP, NTP, PTP, syslog, DLT, DoIP, XCP)
EXCLUDED_PORTS = frozenset({53, 67, 68, 123, 319, 320, 514, 3490, 5353, 13400, 5555})
SD_INFINITE_TTL = 0xFFFFFF
EVENT_COLS = ['time_utc', 't_rel_s', 'severity', 'event', 'service', 'instance', 'method_or_eventgroup',
              'src_ip', 'src_name', 'dst_ip', 'dst_name', 'detail']


# ---------------------------------------------------------------- name resolution
def find_profile_dir(name: str) -> Path | None:
    cands = []
    if os.environ.get('APPDATA'):
        cands.append(Path(os.environ['APPDATA']) / 'Wireshark' / 'profiles' / name)
    cands.append(Path.home() / '.config' / 'wireshark' / 'profiles' / name)
    if Path('/mnt/c/Users').is_dir():
        cands += sorted(Path('/mnt/c/Users').glob(f'*/AppData/Roaming/Wireshark/profiles/{name}'))
    return next((c for c in cands if c.is_dir()), None)


class Names:
    def __init__(self, profile_dir: Path | None):
        self.hosts: dict[int, str] = {0: 'unconfigured (no IP yet)'}
        self.subnets: list[tuple[int, int, str]] = []
        self.cache: dict[int, str] = {}
        if not profile_dir:
            return
        for line in _read_lines(profile_dir / 'hosts'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    self.hosts[int(ipaddress.IPv4Address(parts[0]))] = parts[1]
                except ValueError:
                    pass
        nets = []
        for line in _read_lines(profile_dir / 'subnets'):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                try:
                    net = ipaddress.IPv4Network(parts[0], strict=False)
                except ValueError:
                    continue
                nets.append((net.prefixlen, int(net.network_address), int(net.netmask), parts[1].strip()))
        self.subnets = [(a, m, n) for _, a, m, n in sorted(nets, reverse=True)]

    def __call__(self, ip: int) -> str:
        n = self.cache.get(ip)
        if n is None:
            n = self.hosts.get(ip)
            if n is None:
                n = next((f'{name}.{ip & ~mask & 0xFFFFFFFF}' for net, mask, name in self.subnets
                          if ip & mask == net), '')
            self.cache[ip] = n
        return n


def _read_lines(p: Path):
    if not p.is_file():
        return []
    out = []
    raw = p.read_bytes()
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('cp1252', errors='replace')
    for line in text.splitlines():
        line = ''.join(ch for ch in line.split('#', 1)[0] if ch.isprintable()).strip()
        if line:
            out.append(line)
    return out


_ip_cache: dict[int, str] = {}


def ip_str(ip: int | None) -> str:
    if ip is None:
        return ''
    s = _ip_cache.get(ip)
    if s is None:
        s = _ip_cache[ip] = socket.inet_ntoa(S_U32.pack(ip))
    return s


# ---------------------------------------------------------------- capture reading
def open_capture(path: str):
    f = open(path, 'rb')
    low = path.lower()
    if low.endswith('.zst') or low.endswith('.zstd'):
        import zstandard
        return zstandard.ZstdDecompressor().stream_reader(f, read_size=1 << 22)
    if low.endswith('.gz'):
        return gzip.GzipFile(fileobj=f)
    return f


PCAP_MAGICS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')


class _PrefetchReader:
    """Decompress on a background thread (zstd/gzip release the GIL) so parsing overlaps decompression."""

    def __init__(self, r, size=CHUNK, depth=3):
        self.q: queue.Queue = queue.Queue(depth)
        threading.Thread(target=self._run, args=(r, size), daemon=True).start()

    def _run(self, r, size):
        try:
            while True:
                b = r.read(size)
                self.q.put(b)
                if not b:
                    return
        except BaseException as e:  # re-raised in the consumer
            self.q.put(e)

    def read(self, _size=None):
        b = self.q.get()
        if isinstance(b, BaseException):
            raise b
        if not b:
            self.q.put(b)
        return b


def iter_jobs(path: str):
    """Split the decompressed capture into independent jobs: (kind, data, meta, resync, limit).

    pcapng jobs are raw byte ranges (plus an overlap tail); workers re-synchronise on block boundaries,
    so the main process never walks the 5M+ blocks itself.
    """
    r = _PrefetchReader(open_capture(path))
    buf = r.read()
    if len(buf) < 24:
        return
    magic = buf[:4]
    if magic == b'\x0a\x0d\x0d\x0a':
        if buf[8:12] != b'\x4d\x3c\x2b\x1a':
            raise SystemExit('big-endian pcapng is not supported')
        yield from _pcapng_jobs(r, buf)
    elif magic in PCAP_MAGICS:
        yield from _pcap_jobs(r, buf)
    else:
        raise SystemExit(f'{path}: not a pcap/pcapng file')


def _pcapng_jobs(r, buf):
    links: list[int] = []
    scale: list[float] = []
    off = 0
    while off + 12 <= len(buf):  # interface descriptions precede the first packet
        bt, bl = S_II_LE.unpack_from(buf, off)
        if bt == 6 or bl < 12:
            break
        if bt == 1:
            links.append(struct.unpack_from('<H', buf, off + 8)[0])
            scale.append(_idb_tsresol(buf, off + 16, off + bl - 4))
        off += bl
    meta = (tuple(links), tuple(scale))
    pos, first, eof = 0, True, False
    while True:
        while not eof and len(buf) - pos < JOB_SIZE + OVERLAP:
            more = r.read()
            if more:
                buf = buf[pos:] + more
                pos = 0
            else:
                eof = True
        rest = len(buf) - pos
        if rest <= 0:
            return
        if eof and rest <= JOB_SIZE + OVERLAP:
            yield 'ng', buf[pos:], meta, not first, rest
            return
        yield 'ng', buf[pos:pos + JOB_SIZE + OVERLAP], meta, not first, JOB_SIZE
        pos += JOB_SIZE
        first = False


def _pcap_jobs(r, buf):
    magic = buf[:4]
    le = magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1')
    frac = 1e-9 if magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1e-6
    link = struct.unpack_from('<I' if le else '>I', buf, 20)[0]
    if link != 1:
        raise SystemExit(f'unsupported pcap link type {link}')
    unpack = (S_PCAP_REC_LE if le else S_PCAP_REC_BE).unpack_from
    meta = (le, frac)
    off = start = 24
    while True:
        n = len(buf)
        while off + 16 <= n:
            cap = unpack(buf, off)[2]
            if off + 16 + cap > n:
                break
            off += 16 + cap
            if off - start >= JOB_SIZE:
                yield 'pcap', buf[start:off], meta, False, off - start
                start = off
        more = r.read()
        if not more:
            if off > start:
                yield 'pcap', buf[start:off], meta, False, off - start
            return
        buf = buf[start:] + more
        off -= start
        start = 0


_PCAPNG_TYPES = frozenset({1, 2, 3, 4, 5, 6, 7, 9, 10, 0xA, 0xB, 0xBAD, 0x40000BAD, 0x0A0D0D0A})


def _valid_block_chain(buf, off, n, depth=4) -> bool:
    unpack = S_II_LE.unpack_from
    for _ in range(depth):
        if off + 12 > n:
            return True
        bt, bl = unpack(buf, off)
        if bt not in _PCAPNG_TYPES or bl < 12 or bl & 3 or off + bl > n or S_U32_LE.unpack_from(buf, off + bl - 4)[0] != bl:
            return False
        off += bl
    return True


def _resync_pcapng(buf, limit):
    """First offset < limit where a valid chain of pcapng blocks starts (EPB-anchored), or None."""
    n = len(buf)
    i = 0
    while True:
        i = buf.find(b'\x06\x00\x00\x00', i, limit + 4)
        if i < 0 or i >= limit:
            return None
        if i & 3 == 0 and _valid_block_chain(buf, i, n):
            return i
        i += 1


def _walk(kind, buf, meta, resync, limit):
    """Record offsets of all packets starting before `limit` -> (data_start, caplen, ts) numpy arrays."""
    n = len(buf)
    if kind == 'pcap':
        le, frac = meta
        unpack = (S_PCAP_REC_LE if le else S_PCAP_REC_BE).unpack_from
        offs = []
        off = 0
        while off + 16 <= limit:
            offs.append(off)
            off += 16 + unpack(buf, off)[2]
        o = np.array(offs, dtype=np.int64)
        a = np.frombuffer(buf, np.uint8)
        sec, sub, cap = _u32(a, o, le), _u32(a, o + 4, le), _u32(a, o + 8, le)
        return o + 16, cap, sec + sub * frac
    off = 0
    if resync:
        off = _resync_pcapng(buf, limit)
        if off is None:
            return None
        links, scale = list(meta[0]), list(meta[1])
    else:
        links, scale = [], []
    unpack = S_II_LE.unpack_from
    offs = []
    while off < limit and off + 12 <= n:
        bt, bl = unpack(buf, off)
        if bl < 12 or off + bl > n:
            break
        if bt == 6:
            offs.append(off)
        elif bt == 1:
            links.append(struct.unpack_from('<H', buf, off + 8)[0])
            scale.append(_idb_tsresol(buf, off + 16, off + bl - 4))
        elif bt == 0x0A0D0D0A:
            links, scale = [], []
        off += bl
    a = np.frombuffer(buf, np.uint8)
    o = np.array(offs, dtype=np.int64)
    iid = _u32(a, o + 8, True)
    lk = np.array(links or [1], dtype=np.int64)
    sc = np.array(scale or [1e-6], dtype=np.float64)
    iid = np.minimum(iid, len(lk) - 1)  # interfaces declared mid-file: assume like the last known one
    keep = lk[iid] == 1
    o, iid = o[keep], iid[keep]
    ts = (_u32(a, o + 12, True).astype(np.float64) * 4294967296.0 + _u32(a, o + 16, True)) * sc[iid]
    return o + 28, _u32(a, o + 20, True), ts


def _g(a, pos):
    return a[np.minimum(pos, len(a) - 1)].astype(np.int64)


def _u16(a, pos):
    return (_g(a, pos) << 8) | _g(a, pos + 1)


def _u32(a, pos, le=False):
    if le:
        return _g(a, pos) | (_g(a, pos + 1) << 8) | (_g(a, pos + 2) << 16) | (_g(a, pos + 3) << 24)
    return (_u16(a, pos) << 16) | _u16(a, pos + 2)


_EXCL_ARR = np.array(sorted(EXCLUDED_PORTS), dtype=np.int64)
_MT_ARR = np.array(sorted(VALID_MT), dtype=np.int64)


def extract(job):
    """Worker: parse one job into SOME/IP records, per-host tx timestamps and conversation stats.

    Header fields are decoded vectorised with numpy; only frames that look like SOME/IP go through Python.
    Records (capture order): (0, ts, src, dst, sid, mid, cid, ses, msg_type, rc)
                             (1, ts, src, dst, sport, ses, reboot, ((type, sid, inst, major, ttl, eg), ...))
    """
    kind, buf, meta, resync, limit = job
    w = _walk(kind, buf, meta, resync, limit)
    if w is None or not len(w[0]):
        return [], {}, {}, 0
    p, cap, fts = w
    n_frames = len(p)
    a = np.frombuffer(buf, np.uint8)
    end = np.minimum(p + cap, len(a))

    # ---- unwrap ASAM CMP (ethertype 0x99FE); one frame may carry several Ethernet entries
    et0 = _u16(a, p + 12)
    is_cmp = et0 == 0x99FE
    plain = np.nonzero(~is_cmp)[0]
    e_fi, e_k, e_ts, e_s, e_end = [plain], [np.zeros(len(plain), np.int64)], [fts[plain]], [p[plain]], [end[plain]]
    idx = np.nonzero(is_cmp & (_g(a, p + 14) == 1) & (_g(a, p + 18) == 1))[0]
    if len(idx):
        q = p[idx] + 22
        c_fi, c_k, c_cts, c_s, c_end = [], [], [], [], []
        k = 0
        while len(idx):
            m = q + 16 <= end[idx]
            idx, q = idx[m], q[m]
            if not len(idx):
                break
            plen = _u16(a, q + 14)
            d = q + 16
            qn = d + plen
            ok = (_g(a, q + 13) == 0x08) & (qn <= end[idx])
            if ok.any():
                fi = idx[ok]
                c_fi.append(fi)
                c_k.append(np.full(len(fi), k, np.int64))
                c_cts.append((_u32(a, q[ok]) << 32) | _u32(a, q[ok] + 4))
                es = d[ok] + 6
                c_s.append(es)
                c_end.append(np.minimum(es + _u16(a, d[ok] + 4), end[fi]))
            q = qn
            k += 1
        if c_fi:
            fi = np.concatenate(c_fi)
            cts = np.concatenate(c_cts)
            ref = np.full(n_frames, np.iinfo(np.int64).min, np.int64)
            np.maximum.at(ref, fi, cts)
            # anchor relative CMP timestamps to the capture timestamp of the carrying frame
            e_fi.append(fi)
            e_k.append(np.concatenate(c_k))
            e_ts.append(fts[fi] + (cts - ref[fi]) * 1e-9)
            e_s.append(np.concatenate(c_s))
            e_end.append(np.concatenate(c_end))
    fi = np.concatenate(e_fi)
    order = np.argsort(fi * 256 + np.concatenate(e_k), kind='stable')
    ts = np.concatenate(e_ts)[order]
    e = np.concatenate(e_s)[order]
    eend = np.concatenate(e_end)[order]

    # ---- Ethernet / VLAN / IPv4 / UDP / TCP
    et = _u16(a, e + 12)
    h = e + 14
    vlan = np.zeros(len(e), np.int64)
    for _ in range(2):
        m = (et == 0x8100) | (et == 0x88A8)
        if not m.any():
            break
        vlan[m] = _u16(a, h[m]) & 0xFFF
        et[m] = _u16(a, h[m] + 2)
        h[m] += 4
    m = (et == 0x0800) & (h + 20 <= eend)
    ts, h, eend, vlan = ts[m], h[m], eend[m], vlan[m]
    vihl = _g(a, h)
    tot = _u16(a, h + 2)
    frag = _u16(a, h + 6)
    proto = _g(a, h + 9)
    src = _u32(a, h + 12)
    dst = _u32(a, h + 16)
    l4 = h + (vihl & 15) * 4
    ipend = np.minimum(h + tot, eend)
    first = (frag & 0x1FFF) == 0
    udp = first & (proto == 17) & (l4 + 8 <= ipend)
    tcp = first & (proto == 6) & (l4 + 13 <= ipend)
    l4ok = udp | tcp
    sp = np.where(l4ok, _u16(a, l4), 0)
    dp = np.where(l4ok, _u16(a, l4 + 2), 0)
    pl = np.where(udp, l4 + 8, np.where(tcp, l4 + (_g(a, l4 + 12) >> 4) * 4, 0))
    plend = np.where(udp, np.where(frag & 0x2000, ipend, np.minimum(l4 + _u16(a, l4 + 4), ipend)),
                     np.where(tcp, ipend, 0))

    # ---- SOME/IP candidates (first header must look valid); the rest is parsed in Python
    cand = l4ok & (plend - pl >= 16) & ~np.isin(sp, _EXCL_ARR) & ~np.isin(dp, _EXCL_ARR)
    cand &= (_g(a, pl + 12) == 1) & np.isin(_g(a, pl + 14) & 0x9F, _MT_ARR) & (_u16(a, pl) != 0)
    cand &= _u32(a, pl + 4) >= 8
    ci = np.nonzero(cand)[0]
    som = np.zeros(len(ts), np.int64)
    recs = []
    unpack_someip, unpack_ent, unpack_u32 = S_SOMEIP.unpack_from, S_SD_ENT.unpack_from, S_U32.unpack_from
    valid_mt = VALID_MT
    for i, t, s, d, port, p0, p1 in zip(ci.tolist(), ts[ci].tolist(), src[ci].tolist(), dst[ci].tolist(),
                                         sp[ci].tolist(), pl[ci].tolist(), plend[ci].tolist()):
        cnt = 0
        while p0 + 16 <= p1:
            sid, mid, ln, cid, ses, pv, _iv, mt, rc = unpack_someip(buf, p0)
            bmt = mt & 0x9F
            # service 0x0000 is reserved: these are AUTOSAR SoAd PDU-header frames (4B PDU id + 4B length)
            if pv != 1 or ln < 8 or bmt not in valid_mt or sid == 0:
                break
            cnt += 1
            if sid == 0xFFFF and mid == 0x8100:
                sp0 = p0 + 16
                send = min(p0 + 8 + ln, p1)
                if sp0 + 8 <= send:
                    ee = sp0 + 8
                    xend = min(ee + unpack_u32(buf, sp0 + 4)[0], send)
                    ents = []
                    while ee + 16 <= xend:
                        typ, sv, inst, mttl, eg = unpack_ent(buf, ee)
                        ents.append((typ, sv, inst, mttl >> 24, mttl & 0xFFFFFF, eg))
                        ee += 16
                    recs.append((1, t, s, d, port, ses, buf[sp0] & 0x80, tuple(ents)))
            else:
                recs.append((0, t, s, d, sid, mid, cid, ses, bmt, rc))
            p0 += 8 + ln
        som[i] = cnt

    # ---- conversation aggregation
    conv = {}
    if len(ts):
        k1 = (src.astype(np.uint64) << np.uint64(32)) | dst.astype(np.uint64)
        k2 = ((vlan << 40) | (proto << 32) | (sp << 16) | dp).astype(np.uint64)
        o = np.lexsort((k2, k1))
        k1s, k2s = k1[o], k2[o]
        b = np.concatenate(([0], np.nonzero((k1s[1:] != k1s[:-1]) | (k2s[1:] != k2s[:-1]))[0] + 1))
        tso = ts[o]
        cnt = np.diff(np.append(b, len(o)))
        tmin, tmax = np.minimum.reduceat(tso, b), np.maximum.reduceat(tso, b)
        nbytes, nsom = np.add.reduceat(tot[o], b), np.add.reduceat(som[o], b)
        for x1, x2, c, t0, t1, nb, ns in zip(k1s[b].tolist(), k2s[b].tolist(), cnt.tolist(), tmin.tolist(),
                                             tmax.tolist(), nbytes.tolist(), nsom.tolist()):
            conv[(x1 >> 32, x1 & 0xFFFFFFFF, x2 >> 40, (x2 >> 32) & 0xFF, (x2 >> 16) & 0xFFFF, x2 & 0xFFFF)] = \
                [c, t0, t1, nb, ns]

    # ---- per-host transmit timestamps, thinned to one per HOST_TS_RES bucket (enough for silence detection)
    hosts = {}
    if len(ts):
        o = np.lexsort((ts, src))
        ss, tt = src[o], ts[o]
        bk = np.floor(tt / HOST_TS_RES).astype(np.int64)
        keep = np.concatenate(([True], (ss[1:] != ss[:-1]) | (bk[1:] != bk[:-1])))
        ss, tt = ss[keep], tt[keep]
        cuts = np.nonzero(ss[1:] != ss[:-1])[0] + 1
        for ip, part in zip(ss[np.concatenate(([0], cuts))].tolist(), np.split(tt, cuts)):
            hosts[ip] = part.tobytes()
    return recs, hosts, conv, n_frames


_SHM_CACHE: dict = {}


def _extract_shm(kind, name, size, meta, resync, limit):
    shm = _SHM_CACHE.get(name)
    if shm is None:
        shm = _SHM_CACHE[name] = _attach_shm(name)
    return extract((kind, bytes(shm.buf[:size]), meta, resync, limit))


def _attach_shm(name):
    try:
        return shared_memory.SharedMemory(name=name, track=False)
    except TypeError:  # Python < 3.13
        return shared_memory.SharedMemory(name=name)


def _fill_ring(path, free: queue.Queue, ready: queue.Queue):
    """Producer thread: decompress straight into reusable shared-memory buffers and queue them as jobs."""
    try:
        r = open_capture(path)
        size = JOB_SIZE + OVERLAP
        head = r.read(24)
        if head[:4] != b'\x0a\x0d\x0d\x0a':
            r.close()
            for kind, data, meta, resync, limit in iter_jobs(path):  # legacy pcap / unusual files
                shm = free.get()
                shm.buf[:len(data)] = data
                ready.put((shm, len(data), kind, meta, resync, limit))
            return
        if head[8:12] != b'\x4d\x3c\x2b\x1a':
            raise SystemExit('big-endian pcapng is not supported')
        prev, meta, first = None, ((), ()), True
        while True:
            shm = free.get()
            mv = shm.buf
            if first:
                mv[:24] = head
                filled = 24
            else:
                mv[:OVERLAP] = prev.buf[JOB_SIZE:size]
                filled = OVERLAP
            while filled < size:
                k = r.readinto(mv[filled:size])
                if not k:
                    break
                filled += k
            if first:
                meta = _idb_meta(bytes(mv[:filled]))
            final = filled < size
            # a final buffer may hold only the overlap tail: blocks starting there were not parsed yet
            ready.put((shm, filled, 'ng', meta, not first, filled if final else JOB_SIZE))
            if final:
                return
            prev, first = shm, False
    except BaseException as e:  # re-raised in the consumer
        ready.put(e)
    finally:
        ready.put(None)


def _idb_meta(buf):
    links, scale = [], []
    off = 0
    while off + 12 <= len(buf):
        bt, bl = S_II_LE.unpack_from(buf, off)
        if bt == 6 or bl < 12:
            break
        if bt == 1:
            links.append(struct.unpack_from('<H', buf, off + 8)[0])
            scale.append(_idb_tsresol(buf, off + 16, off + bl - 4))
        off += bl
    return tuple(links), tuple(scale)


def iter_extracted(path: str, workers: int):
    """Yield extract() results in capture order, parsing jobs on `workers` processes."""
    if workers <= 1:
        for job in iter_jobs(path):
            yield extract(job)
        return
    # A ring of shared-memory buffers: no pickling of bulk data, no per-job mapping/page-fault cost
    ring = [shared_memory.SharedMemory(create=True, size=JOB_SIZE + OVERLAP) for _ in range(workers + 3)]
    free: queue.Queue = queue.Queue()
    for shm in ring:
        free.put(shm)
    ready: queue.Queue = queue.Queue()
    try:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for _ in range(workers):
                ex.submit(int)  # start worker processes while the first job is being decompressed
            threading.Thread(target=_fill_ring, args=(path, free, ready), daemon=True).start()
            pending: deque = deque()

            def pop():
                fut, shm = pending.popleft()
                try:
                    return fut.result()
                finally:
                    free.put(shm)

            while True:
                item = ready.get()
                if item is None:
                    break
                if isinstance(item, BaseException):
                    raise item
                shm, n, kind, meta, resync, limit = item
                pending.append((ex.submit(_extract_shm, kind, shm.name, n, meta, resync, limit), shm))
                while pending and (pending[0][0].done() or free.empty()):
                    yield pop()
            while pending:
                yield pop()
    finally:
        for shm in ring:
            try:
                shm.close()
            except BufferError:  # producer thread still holds a view after an early exit
                pass
            shm.unlink()


def _idb_tsresol(buf, o, end) -> float:
    while o + 4 <= end:
        code, ln = struct.unpack_from('<HH', buf, o)
        if code == 0:
            break
        if code == 9 and ln >= 1:
            v = buf[o + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        o += 4 + ((ln + 3) & ~3)
    return 1e-6


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
        for recs, hosts, cv, n_frames in iter_extracted(path, workers):
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
          f'- **ECU names:** `{res.get("profile_dir") or "Wireshark profile not found"}`', '']

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


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('pcap', nargs='+', help='.pcapng/.pcap, optionally .zst/.gz compressed')
    ap.add_argument('--profile', default='VCC-SPA3-SDB17', help='Wireshark profile name for hosts/subnets')
    ap.add_argument('--profile-dir', type=Path, help='explicit Wireshark profile directory')
    ap.add_argument('-o', '--outdir', type=Path, help='output directory (default: <capture>_someip_report)')
    ap.add_argument('--service', type=lambda s: int(s, 0), action='append', help='only this service id (repeatable)')
    ap.add_argument('--req-timeout', type=float, default=1.0, help='request->response timeout s (default 1.0)')
    ap.add_argument('--sd-timeout', type=float, default=1.0, help='Subscribe->Ack timeout s (default 1.0)')
    ap.add_argument('--find-timeout', type=float, default=2.0, help='Find->Offer timeout s (default 2.0)')
    ap.add_argument('--event-timeout', type=float, default=2.0, help='SubscribeAck->first event timeout s')
    ap.add_argument('--gap-factor', type=float, default=5.0, help='periodic stream gap = factor x median period')
    ap.add_argument('--min-gap', type=float, default=0.5, help='minimum stream gap s (default 0.5)')
    ap.add_argument('--min-count', type=int, default=5, help='min messages for stream period analysis')
    ap.add_argument('--host-gap', type=float, default=2.0, help='host silence threshold s (default 2.0)')
    ap.add_argument('--grace', type=float, default=3.0, help='ignore start/end effects within this many s')
    ap.add_argument('--print', dest='max_print', type=int, default=60, help='events printed to console')
    ap.add_argument('-j', '--workers', type=int, default=max(1, min(8, (os.cpu_count() or 2) - 1)),
                    help='parser processes (default: CPUs-1, max 8)')
    ap.add_argument('--pickle', type=Path, help=argparse.SUPPRESS)  # used by the Streamlit UI
    return ap


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(errors='replace')  # redirected Windows consoles use cp1252
    a = build_parser().parse_args()
    pdir = a.profile_dir or find_profile_dir(a.profile)
    if pdir is None:
        print(f'warning: Wireshark profile "{a.profile}" not found, names unresolved', file=sys.stderr)
    names = Names(pdir)
    if a.pickle:
        res = analyze(a.pcap[0], a, names)
        res['profile_dir'] = str(pdir) if pdir else ''
        with a.pickle.open('wb') as f:
            pickle.dump(res, f, protocol=pickle.HIGHEST_PROTOCOL)
        return
    for path in a.pcap:
        res = analyze(path, a, names)
        st = res['stats']
        if res['empty']:
            print(f'{path}: no IPv4 traffic found')
            continue
        print(f'{path}: {st["frames"]} frames, {st.get("someip_msgs", 0)} SOME/IP msgs, '
              f'{st.get("sd_msgs", 0)} SD msgs, {st["streams"]} streams, parsed in {st["parse_s"]:.1f}s, '
              f'analysed in {st["analyse_s"]:.1f}s')
        name = Path(path).name.split('.')[0]
        res['profile_dir'] = str(pdir) if pdir else ''
        write_outputs(res, a.outdir or Path(path).parent / f'{name}_someip_report', a.max_print, path)


if __name__ == '__main__':
    main()
