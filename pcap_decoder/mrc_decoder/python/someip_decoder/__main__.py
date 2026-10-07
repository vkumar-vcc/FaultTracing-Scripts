"""CLI: decode SOME/IP-over-TCP pcap(s) into named signals, merged into one MF4.

    python -m someip_decoder <pcap|.zst|dir> [more ...] [-o OUTDIR] [--csv]
        [--keep-all] [--per-file] [--services-dir D] [--proto-dir D] [--pb2-dir D]

Service/event -> protobuf mapping comes from rim_ecu_signals. Multiple inputs are
decoded in chronological order and merged into one {vin}_SOMEIP_{n}logs MF4 by
default (use --per-file for one MF4 each). Unchanged-sample reduction is on by
default (use --keep-all to keep every sample).
"""

from __future__ import annotations

import argparse
import glob
import os
import sys

# Allow running both as a module (python -m someip_decoder) and as a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spa2_decoder.writer import reduce_unchanged, write_csv, write_mf4, write_summary

from someip_decoder.decode import DecodeStats, SomeipDecoder
from someip_decoder.run import accumulate

_RIM = "/mnt/c/Users/VKUMAR36/workspace/super/interfaces/rim_ecu_signals"
DEFAULT_SERVICES_DIR = os.path.join(_RIM, "interfaces", "services")
DEFAULT_PROTO_DIR = os.path.join(_RIM, "interfaces", "proto")
DEFAULT_PB2_DIR = os.path.join(_RIM, "python_bindings", "rim_ecu_signals", "proto")


def _expand_inputs(inputs):
    files = []
    for inp in inputs:
        if os.path.isdir(inp):
            for pat in ("*.pcapng", "*.pcap", "*.pcapng.zst", "*.pcap.zst"):
                files.extend(glob.glob(os.path.join(inp, pat)))
        elif os.path.isfile(inp):
            files.append(inp)
        else:
            print(f"skip (not found): {inp}", file=sys.stderr)
    return sorted(files)


def _vin_from(path):
    base = os.path.basename(path).split("_")
    return base[1] if len(base) > 1 and len(base[1]) == 17 else "combined"


def _accumulate(pcap, decoder, signals, stats, emit_frame_updated):
    accumulate(pcap, decoder, signals, stats, emit_frame_updated)


def _finalize(signals, out_dir, stem, want_csv, keep_all):
    os.makedirs(out_dir, exist_ok=True)
    if not keep_all:
        reduce_unchanged(signals)
    mf4 = os.path.join(out_dir, stem + ".mf4")
    write_mf4(signals, mf4)
    write_summary(signals, os.path.join(out_dir, stem + "_signals.csv"))
    if want_csv:
        write_csv(signals, os.path.join(out_dir, stem + "_long.csv"))
    return mf4


def _print_stats(stats: DecodeStats):
    print(
        f"[=] someip_msgs={stats.messages} decoded={stats.decoded} "
        f"skipped={stats.skipped_unmapped} errors={stats.errors} "
        f"sample_rows={stats.sample_rows}"
    )
    if stats.unmapped_services:
        top = sorted(stats.unmapped_services.items(), key=lambda kv: -kv[1])[:12]
        print(f"[=] top unmapped service_ids: {dict(top)}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="someip_decoder")
    p.add_argument("inputs", nargs="+", help="pcap/.zst file(s) or a directory")
    p.add_argument("--services-dir", default=DEFAULT_SERVICES_DIR)
    p.add_argument("--proto-dir", default=DEFAULT_PROTO_DIR)
    p.add_argument("--pb2-dir", default=DEFAULT_PB2_DIR)
    p.add_argument("-o", "--out-dir", default="someip_out")
    p.add_argument("--csv", action="store_true", help="also write long-format CSV")
    p.add_argument("--keep-all", action="store_true", help="keep every sample")
    p.add_argument("--per-file", action="store_true", help="one MF4 per input file")
    p.add_argument(
        "--no-frame-updated",
        action="store_true",
        help="omit per-event FrameUpdated cadence channels",
    )
    args = p.parse_args(argv)

    files = _expand_inputs(args.inputs)
    if not files:
        print("no input files", file=sys.stderr)
        return 2
    emit_fu = not args.no_frame_updated

    decoder = SomeipDecoder(args.services_dir, args.proto_dir, args.pb2_dir)
    print(f"[+] catalog: {len(decoder.catalog)} (service,event) definitions")

    if args.per_file:
        for f in files:
            signals, stats = {}, DecodeStats()
            print(f"[+] decoding {os.path.basename(f)} ...")
            _accumulate(f, decoder, signals, stats, emit_fu)
            _print_stats(stats)
            stem = os.path.splitext(
                os.path.basename(f).replace(".pcapng", "").replace(".pcap", "")
            )[0]
            mf4 = _finalize(
                signals, args.out_dir, stem + "_SOMEIP", args.csv, args.keep_all
            )
            print(f"[=] wrote {mf4} ({len(signals)} signals)")
        return 0

    signals, stats = {}, DecodeStats()
    for f in files:
        print(f"[+] decoding {os.path.basename(f)} ...")
        _accumulate(f, decoder, signals, stats, emit_fu)
    _print_stats(stats)
    vin = _vin_from(files[0])
    stem = f"{vin}_SOMEIP_{len(files)}logs"
    mf4 = _finalize(signals, args.out_dir, stem, args.csv, args.keep_all)
    print(f"[=] wrote {mf4} ({len(signals)} signals)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
