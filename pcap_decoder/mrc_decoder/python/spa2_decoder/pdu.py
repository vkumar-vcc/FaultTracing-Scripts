"""SPA3 signal-PDU layouts and decoding, independent of SPA2 bus routing."""

from __future__ import annotations

import csv
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .decode import SignalSeries


DEFAULT_PDU_CONFIG = Path(__file__).resolve().parents[3] / "SPA3_PDU"
CONFIG_FILES = ("Signal_PDU_identifiers_ETH", "Signal_PDU_Binding_PDU_Transport_ETH",
                "Signal_PDU_signal_list_ETH", "decode_as_entries")


@dataclass(frozen=True)
class PduSignal:
    name: str
    bit_offset: int
    width: int
    big_endian: bool
    signed: bool
    factor: float
    offset: float


@dataclass(frozen=True)
class PduLayout:
    name: str
    min_bytes: int
    signals: tuple[PduSignal, ...]


@dataclass
class PduStats:
    records: int = 0
    decoded: int = 0
    unknown: int = 0
    errors: int = 0
    duplicates: int = 0
    samples: int = 0
    unknown_ids: Counter = field(default_factory=Counter)


def _rows(path: Path):
    with path.open(newline="", encoding="utf-8-sig") as source:
        yield from csv.reader(line for line in source
                              if line.strip() and not line.lstrip().startswith("#"))


def load_config(directory: str | Path) -> tuple[dict[int, PduLayout], set[int]]:
    directory = Path(directory)
    for name in CONFIG_FILES:
        if not (directory / name).is_file():
            raise ValueError(f"PDU configuration file not found: {directory / name}")
    names = {int(row[0], 16): row[1].split(".")[0]
             for row in _rows(directory / CONFIG_FILES[0])}
    definitions = {}
    offsets = {}
    for row in _rows(directory / CONFIG_FILES[2]):
        if len(row) < 11:
            raise ValueError("Invalid PDU signal-layout row")
        identifier, width = int(row[0], 16), int(row[8])
        if width < 0:
            raise ValueError("PDU signal widths cannot be negative")
        bit_offset = offsets.get(identifier, 0)
        padding = row[13] == "TRUE" if len(row) > 13 else "__padding" in row[3].lower()
        definitions.setdefault(identifier, [])
        if not padding and 0 < width <= 64:
            definitions[identifier].append(PduSignal(
                row[3], bit_offset, width, row[6] == "TRUE", row[5] == "sint",
                float(row[9]), float(row[10])))
        offsets[identifier] = bit_offset + width
    layouts = {}
    for row in _rows(directory / CONFIG_FILES[1]):
        transport, identifier = int(row[0], 16), int(row[1], 16)
        if identifier in names and definitions.get(identifier):
            layouts[transport] = PduLayout(names[identifier],
                                          (offsets[identifier] + 7) // 8,
                                          tuple(definitions[identifier]))
    text = (directory / CONFIG_FILES[3]).read_text(encoding="utf-8")
    ports = {int(port) for port in re.findall(
        r"decode_as_entry:\s*udp\.port,(\d+),[^,]*,PDU Transport\s*$", text, re.MULTILINE)}
    if not layouts or not ports or any(not 0 < port <= 65535 for port in ports):
        raise ValueError("PDU configuration contains no usable layouts or UDP ports")
    return layouts, ports


def decode_record(layout: PduLayout, payload: bytes, timestamp: float,
                  signals: dict[str, SignalSeries], keep_all: bool = False) -> bool:
    if len(payload) < layout.min_bytes:
        return False
    for spec in layout.signals:
        start, relative = divmod(spec.bit_offset, 8)
        size = (relative + spec.width + 7) // 8
        chunk = payload[start:start + size]
        raw = int.from_bytes(chunk, "big" if spec.big_endian else "little")
        shift = size * 8 - relative - spec.width if spec.big_endian else relative
        raw = (raw >> shift) & ((1 << spec.width) - 1)
        if spec.signed and raw & (1 << (spec.width - 1)):
            raw -= 1 << spec.width
        value = float(raw * spec.factor + spec.offset)
        name = f"PDU::{layout.name}::{spec.name}"
        series = signals.get(name)
        if series is None:
            series = signals[name] = SignalSeries()
        if (not keep_all and len(series.values) >= 2
                and series.values[-1] == value == series.values[-2]):
            series.timestamps[-1] = timestamp
        else:
            series.timestamps.append(timestamp)
            series.values.append(value)
    return True


def accumulate(arrays, layouts, signals, stats: PduStats, keep_all: bool):
    stats.errors += int(arrays["pdu_errors"])
    stats.duplicates += int(arrays["pdu_duplicates"])
    payload = memoryview(arrays["pdu_payload"])
    for identifier, timestamp, offset, length in zip(
            arrays["pdu_id"].tolist(), arrays["pdu_timestamp"].tolist(),
            arrays["pdu_payload_off"].tolist(), arrays["pdu_payload_len"].tolist()):
        stats.records += 1
        layout = layouts.get(identifier)
        if layout is None:
            stats.unknown += 1
            stats.unknown_ids[identifier] += 1
        elif decode_record(layout, payload[offset:offset + length], timestamp, signals, keep_all):
            stats.decoded += 1
            stats.samples += len(layout.signals)
        else:
            stats.errors += 1


def print_stats(stats: PduStats, signals):
    print("--- PDU ---")
    for name in ("records", "decoded", "unknown", "errors", "duplicates", "samples"):
        print(f"  pdu_{name:12}: {getattr(stats, name)}")
    print(f"  pdu_signals     : {sum(name.startswith('PDU::') for name in signals)}")
    if stats.unknown_ids:
        print(f"  pdu_unmapped    : {dict(stats.unknown_ids.most_common(10))}")