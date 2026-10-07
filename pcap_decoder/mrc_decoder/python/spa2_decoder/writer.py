"""Write decoded SPA2 signals to MF4 (asammdf), with a CSV fallback."""

from __future__ import annotations

import csv
from typing import Dict

import numpy as np

from .decode import SignalSeries


def reduce_unchanged(signals: Dict[str, SignalSeries]) -> Dict[str, SignalSeries]:
    """Drop consecutive samples whose value is unchanged, keeping each change
    point and the sample immediately before it (step edges preserved). Mirrors
    MRC_Decoding.drop_is_changed_polars so file sizes match the reference."""
    for series in signals.values():
        n = len(series.values)
        if n <= 2:
            continue
        v = np.asarray(series.values, dtype=np.float64)
        diff = v[1:] != v[:-1]  # diff[i] = sample i+1 differs from i
        keep = np.zeros(n, dtype=bool)
        keep[0] = keep[-1] = True
        keep[1:] |= diff  # differs from previous
        keep[:-1] |= diff  # about to change
        if keep.all():
            continue
        t = np.asarray(series.timestamps, dtype=np.float64)
        series.timestamps = t[keep].tolist()
        series.values = v[keep].tolist()
    return signals


def write_mf4(signals: Dict[str, SignalSeries], out_path: str) -> str:
    """One channel group per signal (each signal keeps its own time base)."""
    from asammdf import MDF, Signal

    mdf = MDF()
    sigs = []
    for name, series in signals.items():
        if not series.values:
            continue
        sigs.append(
            Signal(
                samples=np.asarray(series.values, dtype=np.float64),
                timestamps=np.asarray(series.timestamps, dtype=np.float64),
                name=name,
                unit=series.unit,
            )
        )
    # Append each signal as its own group to preserve independent time bases.
    for s in sigs:
        mdf.append([s], comment=s.name, common_timebase=True)
    # compression=2 = transposed deflate (best for numeric channel arrays).
    mdf.save(out_path, overwrite=True, compression=2)
    return out_path


def write_csv(signals: Dict[str, SignalSeries], out_path: str) -> str:
    """Long-format CSV: signal,timestamp,value."""
    with open(out_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["signal", "timestamp", "value"])
        for name, series in signals.items():
            for ts, val in zip(series.timestamps, series.values):
                w.writerow([name, f"{ts:.6f}", val])
    return out_path


def write_summary(signals: Dict[str, SignalSeries], out_path: str) -> str:
    """Per-signal sample count + value range for a quick sanity check."""
    with open(out_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["signal", "samples", "min", "max", "first", "last"])
        for name in sorted(signals):
            s = signals[name]
            if not s.values:
                continue
            w.writerow(
                [
                    name,
                    len(s.values),
                    min(s.values),
                    max(s.values),
                    s.values[0],
                    s.values[-1],
                ]
            )
    return out_path
