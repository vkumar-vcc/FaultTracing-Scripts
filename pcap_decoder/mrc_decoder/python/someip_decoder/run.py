"""Reusable SOME/IP decode-into-signals helper, shared by the standalone CLI and
the combined SPA2+SOME/IP run."""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

from spa2_decoder.decode import SignalSeries  # shared sample container

from .decode import DecodeStats, SomeipDecoder
from .extract import ensure_plain_pcap, iter_someip_messages


def _handle(decoder, ts, sid, mid, mt, payload, signals, stats, frame_counts, emit_fu):
    """Decode one SOME/IP message and append its samples to `signals`."""
    stats.messages += 1
    try:
        res = decoder.decode(sid, mid, mt, payload)
    except Exception:  # noqa: BLE001 - one bad message must not abort the run
        stats.errors += 1
        return
    if res is None:
        stats.skipped_unmapped += 1
        stats.unmapped_services[sid] = stats.unmapped_services.get(sid, 0) + 1
        return
    header, samples = res
    stats.decoded += 1
    for s in samples:
        ser = signals.get(s.name)
        if ser is None:
            ser = SignalSeries()
            signals[s.name] = ser
        ser.timestamps.append(ts)
        ser.values.append(s.value)
        stats.sample_rows += 1
    if emit_fu:
        c = frame_counts.get(header, 0) + 1
        frame_counts[header] = c
        fu = f"{header}::FrameUpdated"
        ser = signals.get(fu)
        if ser is None:
            ser = SignalSeries()
            signals[fu] = ser
        ser.timestamps.append(ts)
        ser.values.append(float(c))


def accumulate(pcap, decoder, signals, stats, emit_frame_updated=True) -> None:
    """Decode one capture's SOME/IP messages (via tshark) into `signals`."""
    plain, cleanup = ensure_plain_pcap(pcap)
    frame_counts: Dict[str, int] = {}
    try:
        for m in iter_someip_messages(plain):
            _handle(
                decoder,
                m.timestamp,
                m.service_id,
                m.method_id,
                m.msgtype,
                m.payload,
                signals,
                stats,
                frame_counts,
                emit_frame_updated,
            )
    finally:
        if cleanup and os.path.exists(cleanup):
            os.remove(cleanup)


def accumulate_from_arrays(
    arr, decoder, signals, stats, emit_frame_updated=True
) -> None:
    """Decode SOME/IP messages extracted by the C++ engine (`extract_all`) into
    `signals`. `arr` holds numpy arrays someip_service/method/msgtype/timestamp
    plus a flat payload buffer with per-message offset/length."""
    svc = arr["someip_service"]
    meth = arr["someip_method"]
    mt = arr["someip_msgtype"]
    tss = arr["someip_timestamp"]
    off = arr["someip_payload_off"]
    ln = arr["someip_payload_len"]
    flat = arr["someip_payload"].tobytes()
    frame_counts: Dict[str, int] = {}
    for i in range(len(svc)):
        o = int(off[i])
        payload = flat[o : o + int(ln[i])]
        _handle(
            decoder,
            float(tss[i]),
            int(svc[i]),
            int(meth[i]),
            int(mt[i]),
            payload,
            signals,
            stats,
            frame_counts,
            emit_frame_updated,
        )


def decode_someip_signals(
    files: List[str], services_dir, proto_dir, pb2_dir, emit_frame_updated=True
) -> Tuple[Dict[str, SignalSeries], DecodeStats]:
    """Decode SOME/IP signals from one or more captures into one signals dict."""
    decoder = SomeipDecoder(services_dir, proto_dir, pb2_dir)
    signals: Dict[str, SignalSeries] = {}
    stats = DecodeStats()
    for f in files:
        accumulate(f, decoder, signals, stats, emit_frame_updated)
    return signals, stats


def format_stats(stats: DecodeStats) -> str:
    lines = [
        f"  someip_msgs      : {stats.messages}",
        f"  someip_decoded   : {stats.decoded}",
        f"  someip_skipped   : {stats.skipped_unmapped}",
        f"  someip_errors    : {stats.errors}",
        f"  someip_rows      : {stats.sample_rows}",
    ]
    if stats.unmapped_services:
        top = sorted(stats.unmapped_services.items(), key=lambda kv: -kv[1])[:12]
        lines.append(f"  someip_unmapped  : {dict(top)}")
    return "\n".join(lines)
