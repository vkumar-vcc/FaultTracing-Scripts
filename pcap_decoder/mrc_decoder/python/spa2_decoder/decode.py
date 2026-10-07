"""SPA2 decode orchestrator: pcap -> routed CAN/LIN decode -> per-signal samples.

The pcap read, Ethernet/VLAN/IP/UDP dissection, MRC framing and endpoint routing all
run in the C++ `mrc_engine` module; only the DBC/LDF signal decode stays in Python.
"""

from __future__ import annotations

import glob
import os
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import cantools
import ldfparser

from .dbmatch import assign_databases, load_db_metadata
from .routing import Bus, parse_routing_table


def load_engine():
    """Import the C++ `mrc_engine` module (adds build/ to sys.path if needed)."""
    try:
        import mrc_engine  # type: ignore

        return mrc_engine
    except ImportError:
        build = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "build")
        )
        if build not in sys.path:
            sys.path.insert(0, build)
        try:
            import mrc_engine  # type: ignore

            return mrc_engine
        except ImportError:
            return None


def _ip_str(ip_u32: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", ip_u32))


def _ip_u32(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


@dataclass
class SignalSeries:
    timestamps: List[float] = field(default_factory=list)
    values: List[float] = field(default_factory=list)
    unit: str = ""


@dataclass
class DecodeStats:
    packets: int = 0
    udp_packets: int = 0
    routed_frames: int = 0
    decoded_frames: int = 0
    unknown_frame_ids: int = 0
    decode_errors: int = 0


class _BusDecoder:
    """Holds the loaded database and frame_id lookup for one routed bus."""

    def __init__(self, bus: Bus, db_dir: str):
        self.bus = bus
        self.bus_type = bus.bus_type
        self.can_by_id: Dict[int, object] = {}
        self.lin_by_id: Dict[int, object] = {}
        path = os.path.join(db_dir, bus.database)
        if bus.bus_type == "CAN":
            db = cantools.database.load_file(path)
            for m in db.messages:
                self.can_by_id.setdefault(m.frame_id, m)
        else:
            ldf = ldfparser.parse_ldf(path)
            for f in ldf.get_unconditional_frames():
                self.lin_by_id[f.frame_id] = f


def _fit(data: bytes, length: int) -> bytes:
    if len(data) == length:
        return data
    if len(data) > length:
        return data[:length]
    return data + b"\x00" * (length - len(data))


def select_routing_table(routing_dir: str, observed: Dict[Tuple[str, int], int]) -> str:
    """Pick the TC-*.yml whose (viu_address, viu_port) set best covers the
    observed (src_ip, src_port) traffic."""
    best_path, best_score = None, -1
    for path in sorted(glob.glob(os.path.join(routing_dir, "*_routing_table.yml"))):
        buses, _ = parse_routing_table(path)
        bus_pairs = {(b.viu_address, b.viu_port) for b in buses.values()}
        score = sum(cnt for pair, cnt in observed.items() if pair in bus_pairs)
        if score > best_score:
            best_path, best_score = path, score
    return best_path


def _lin_numeric(frame, data: bytes) -> Dict[str, float]:
    """Decode a LIN frame to numeric values (enum labels -> raw code)."""
    phys = frame.decode(data)
    raw = None
    out: Dict[str, float] = {}
    for name, val in phys.items():
        if isinstance(val, (int, float)):
            out[name] = float(val)
        else:
            if raw is None:
                raw = frame.decode_raw(data)
            rv = raw.get(name)
            if isinstance(rv, (int, float)):
                out[name] = float(rv)
    return out


# Emit one CONNECTOR::Message::FrameUpdated channel per message, carrying a
# monotonic update counter (every frame arrival is a distinct sample that survives
# reduce_unchanged). Recovers exact update timing while value channels stay reduced.
EMIT_FRAME_UPDATED = True


def _decode_one(dec, fid, data, ts, signals, stats):
    """Decode one routed MRC frame into per-signal series."""
    try:
        if dec.bus_type == "CAN":
            msg = dec.can_by_id.get(fid)
            if msg is None:
                stats.unknown_frame_ids += 1
                return
            values = msg.decode(
                _fit(data, msg.length),
                decode_choices=False,
                scaling=True,
                allow_truncated=True,
            )
            msg_name = msg.name
        else:
            lf = dec.lin_by_id.get(fid)
            if lf is None:
                stats.unknown_frame_ids += 1
                return
            values = _lin_numeric(lf, _fit(data, lf.length))
            msg_name = lf.name
    except Exception:  # noqa: BLE001 - skip undecodable frame, keep going
        stats.decode_errors += 1
        return

    stats.decoded_frames += 1
    # Reference (MRC_Decoding) names signals CONNECTOR::Message::Signal.
    prefix = f"{dec.bus.viu_name}::{msg_name}::"
    for sname, val in values.items():
        if not isinstance(val, (int, float)):
            continue
        full = prefix + sname
        series = signals.get(full)
        if series is None:
            series = signals[full] = SignalSeries()
        series.timestamps.append(ts)
        series.values.append(float(val))

    if EMIT_FRAME_UPDATED:
        fu = signals.get(prefix + "FrameUpdated")
        if fu is None:
            fu = signals[prefix + "FrameUpdated"] = SignalSeries()
        fu.timestamps.append(ts)
        fu.values.append(float(len(fu.values) + 1))  # monotonic update count


def _require_engine():
    engine = load_engine()
    if engine is None:
        raise RuntimeError(
            "mrc_engine C++ module not found. Build it first:\n"
            "  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"
        )
    return engine


def _select_routing(engine, pcap_path: str, routing_dir: str, cap: int) -> str:
    """A prefix of the capture is enough to identify the routing table."""
    d = engine.endpoint_counts(pcap_path, cap or 500000)
    observed = {
        (_ip_str(ip), port): int(c)
        for ip, port, c in zip(
            d["ip"].tolist(), d["port"].tolist(), d["count"].tolist()
        )
    }
    return select_routing_table(routing_dir, observed)


def _build_decoders(routing_table: str, db_dir: str, manifest_files):
    """Match buses to databases and load a decoder per mapped bus (loaded once)."""
    buses, pref = parse_routing_table(routing_table)
    db_meta = load_db_metadata(db_dir, manifest_files)
    assign_databases(buses, db_meta, pref)
    decoders: List[_BusDecoder] = []
    routes: List[Tuple[int, int, int]] = []
    for bus in buses.values():
        if not bus.database:
            continue
        try:
            dec = _BusDecoder(bus, db_dir)
        except Exception as exc:  # noqa: BLE001
            print(f"  load error {bus.key} ({bus.database}): {exc}")
            continue
        routes.append((_ip_u32(bus.viu_address), bus.viu_port, len(decoders)))
        decoders.append(dec)
    return buses, decoders, routes


_SOMEIP_KEYS = (
    "someip_timestamp",
    "someip_service",
    "someip_method",
    "someip_msgtype",
    "someip_payload",
    "someip_payload_off",
    "someip_payload_len",
)


def _extract_and_decode(
    engine,
    pcap_path,
    routes,
    decoders,
    cap,
    signals,
    stats,
    someip_ports=None,
    someip_sink=None,
    pdu_layouts=None,
    pdu_ports=None,
    pdu_stats=None,
    keep_all=False,
):
    """Extract routed frames in C++ and decode their signals into ``signals``.

    When ``someip_ports`` is given, a single ``extract_all`` pass also reassembles
    SOME/IP-over-TCP messages; the raw arrays are appended to ``someip_sink`` for
    the caller to decode (keeps this module free of a someip_decoder import)."""
    if someip_ports is not None or pdu_ports:
        if pdu_ports:
            arr = engine.extract_all(pcap_path, routes, list(someip_ports or []), cap,
                                     sorted(pdu_ports))
        else:
            arr = engine.extract_all(pcap_path, routes, list(someip_ports), cap)
        if arr["error"]:
            raise RuntimeError(f"Capture reader failed: {arr['error']}")
        if someip_sink is not None:
            someip_sink.append({k: arr[k] for k in _SOMEIP_KEYS})
        if pdu_ports:
            from .pdu import accumulate

            accumulate(arr, pdu_layouts, signals, pdu_stats, keep_all)
    else:
        arr = engine.extract_frames(pcap_path, routes, cap)
        if arr["error"]:
            raise RuntimeError(f"Capture reader failed: {arr['error']}")
    bus_index = arr["bus_index"].tolist()
    frame_id = arr["frame_id"].tolist()
    length = arr["length"].tolist()
    tstamps = arr["timestamp"].tolist()
    payload = arr["payload"].tobytes()
    width = arr["payload"].shape[1]
    stats.routed_frames += len(bus_index)
    for i in range(len(bus_index)):
        base = i * width
        _decode_one(
            decoders[bus_index[i]],
            frame_id[i],
            payload[base : base + length[i]],
            tstamps[i],
            signals,
            stats,
        )


def decode_pcap(
    pcap_path: str,
    db_dir: str,
    routing_dir: str,
    manifest_files,
    routing_table: Optional[str] = None,
    max_packets: Optional[int] = None,
    someip_ports=None,
    someip_sink=None,
    pdu_config=None,
    pdu_stats=None,
    mrc_enabled=True,
    keep_all=False,
) -> Tuple[Dict[str, SignalSeries], DecodeStats, Dict[str, Bus]]:
    """Decode a SPA2 pcap into {signal_full_name: SignalSeries}."""
    stats = DecodeStats()
    engine = _require_engine()
    cap = int(max_packets) if max_packets else 0

    buses, decoders, routes = {}, [], []
    if mrc_enabled:
        if routing_table is None:
            routing_table = _select_routing(engine, pcap_path, routing_dir, cap)
        print(f"Routing table: {os.path.basename(routing_table)}")
        buses, decoders, routes = _build_decoders(routing_table, db_dir, manifest_files)
        mapped = sum(1 for bus in buses.values() if bus.database)
        print(f"Buses mapped to databases: {mapped}/{len(buses)}; routed endpoints: {len(decoders)}")
    pdu_layouts, pdu_ports = {}, set()
    if pdu_config:
        from .pdu import PduStats, load_config

        pdu_layouts, pdu_ports = load_config(pdu_config)
        pdu_stats = pdu_stats or PduStats()

    signals: Dict[str, SignalSeries] = {}
    _extract_and_decode(
        engine,
        pcap_path,
        routes,
        decoders,
        cap,
        signals,
        stats,
        someip_ports=someip_ports,
        someip_sink=someip_sink,
        pdu_layouts=pdu_layouts,
        pdu_ports=pdu_ports,
        pdu_stats=pdu_stats,
        keep_all=keep_all,
    )
    return signals, stats, buses


def decode_pcaps(
    pcaps: List[str],
    db_dir: str,
    routing_dir: str,
    manifest_files,
    routing_table: Optional[str] = None,
    max_packets: Optional[int] = None,
    reduce_between: bool = True,
    someip_ports=None,
    someip_sink=None,
    pdu_config=None,
    pdu_stats=None,
    mrc_enabled=True,
) -> Tuple[Dict[str, SignalSeries], DecodeStats, Dict[str, Bus]]:
    """Decode several pcaps and merge them into one {name: SignalSeries}.

    Databases/decoders are built once and reused; files are decoded in the given
    order (sort chronologically first). Each file is reduced before merging to
    keep memory bounded, so pass ``reduce_between=False`` only for --keep-all.
    """
    from .writer import reduce_unchanged  # deferred: writer imports from this module

    engine = _require_engine()
    cap = int(max_packets) if max_packets else 0

    buses, decoders, routes = {}, [], []
    if mrc_enabled:
        if routing_table is None:
            routing_table = _select_routing(engine, pcaps[0], routing_dir, cap)
        print(f"Routing table: {os.path.basename(routing_table)}")
        buses, decoders, routes = _build_decoders(routing_table, db_dir, manifest_files)
        mapped = sum(1 for bus in buses.values() if bus.database)
        print(f"Buses mapped to databases: {mapped}/{len(buses)}; routed endpoints: {len(decoders)}")
    pdu_layouts, pdu_ports = {}, set()
    if pdu_config:
        from .pdu import PduStats, load_config

        pdu_layouts, pdu_ports = load_config(pdu_config)
        pdu_stats = pdu_stats or PduStats()

    merged: Dict[str, SignalSeries] = {}
    agg = DecodeStats()
    for idx, pcap_path in enumerate(pcaps, 1):
        signals: Dict[str, SignalSeries] = {}
        st = DecodeStats()
        _extract_and_decode(
            engine,
            pcap_path,
            routes,
            decoders,
            cap,
            signals,
            st,
            someip_ports=someip_ports,
            someip_sink=someip_sink,
            pdu_layouts=pdu_layouts,
            pdu_ports=pdu_ports,
            pdu_stats=pdu_stats,
            keep_all=not reduce_between,
        )
        if reduce_between:
            reduce_unchanged(signals)
        for name, s in signals.items():
            m = merged.get(name)
            if m is None:
                merged[name] = s
            else:
                m.timestamps.extend(s.timestamps)
                m.values.extend(s.values)
        agg.routed_frames += st.routed_frames
        agg.decoded_frames += st.decoded_frames
        agg.unknown_frame_ids += st.unknown_frame_ids
        agg.decode_errors += st.decode_errors
        print(
            f"  [{idx}/{len(pcaps)}] {os.path.basename(pcap_path)}: "
            f"{st.decoded_frames} frames, {len(signals)} signals "
            f"(merged total: {len(merged)})"
        )
    return merged, agg, buses
