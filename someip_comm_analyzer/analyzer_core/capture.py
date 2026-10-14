"""Capture streaming, frame decoding, and parallel packet extraction."""
from __future__ import annotations

import gzip
import queue
import struct
import threading
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import shared_memory

import numpy as np

from .common import (
    CHUNK, EXCLUDED_PORTS, HOST_TS_RES, JOB_SIZE, MT_NAMES, OVERLAP,
    S_PCAP_REC_BE, S_PCAP_REC_LE, S_SD_ENT, S_SOMEIP, S_U32, S_U32_LE,
    VALID_MT,
)

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


class CaptureReader:
    """Iterate parsed capture jobs in order, optionally using worker processes."""

    def __init__(self, path: str, workers: int):
        self.path = path
        self.workers = workers

    def __iter__(self):
        if self.workers <= 1:
            for job in iter_jobs(self.path):
                yield extract(job)
            return
        # A ring of shared-memory buffers avoids pickling capture chunks between processes.
        ring = [shared_memory.SharedMemory(create=True, size=JOB_SIZE + OVERLAP)
                for _ in range(self.workers + 3)]
        free: queue.Queue = queue.Queue()
        for shm in ring:
            free.put(shm)
        ready: queue.Queue = queue.Queue()
        try:
            with ProcessPoolExecutor(max_workers=self.workers) as ex:
                for _ in range(self.workers):
                    ex.submit(int)  # start workers while the first job is being decompressed
                threading.Thread(target=_fill_ring, args=(self.path, free, ready), daemon=True).start()
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
                except BufferError:  # producer thread may still hold a view after an early exit
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
