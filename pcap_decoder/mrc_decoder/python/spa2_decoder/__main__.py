"""CLI: decode SPA2 MRC pcap(s) into named signals, merged into one MF4 by default.

    python -m spa2_decoder <pcap|dir> [<pcap> ...] [--db-dir DIR] [--routing-dir DIR]
        [--manifest FILE] [--routing-table TC-XX_routing_table.yml]
        [--max-packets N] [-o OUTDIR] [--csv] [--keep-all] [--per-file]

Multiple files (or a directory of *.pcapng) are decoded in chronological order and
merged into a single {vin}_COMBINED_{n}logs MF4. Use --per-file for one MF4 each.
"""

from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys
import tempfile

import yaml

from .decode import decode_pcap, decode_pcaps
from .pdu import DEFAULT_PDU_CONFIG, PduStats, load_config, print_stats
from .writer import reduce_unchanged, write_csv, write_mf4, write_summary

DEFAULT_DB_DIR = os.path.expanduser("~/.cache/mrc_decoder/sdb/p519_2026.26.1/db")
DEFAULT_MANIFEST = os.path.expanduser(
    "~/.cache/mrc_decoder/sdb/p519_2026.26.1/manifest.yaml"
)
DEFAULT_ROUTING_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
        "nuc-logger",
        "logger",
        "can_decoding",
        "SPA2_MRC",
        "routing",
    )
)

# rim_ecu_signals definitions for the optional merged SOME/IP decode.
_RIM = "/mnt/c/Users/VKUMAR36/workspace/super/interfaces/rim_ecu_signals"
SOMEIP_SERVICES_DIR = os.path.join(_RIM, "interfaces", "services")
SOMEIP_PROTO_DIR = os.path.join(_RIM, "interfaces", "proto")
SOMEIP_PB2_DIR = os.path.join(_RIM, "python_bindings", "rim_ecu_signals", "proto")
# Connex SOME/IP reliable (TCP) port range the C++ engine reassembles.
SOMEIP_PORTS = list(range(31000, 31700))


def _merge_someip(args, batches, signals) -> None:
    """Decode the SOME/IP messages the C++ single pass reassembled, merging their
    signals in place. MRC names are CONNECTOR::Message::Signal and SOME/IP names
    are Service::Event::field, so the two key spaces never collide."""
    from someip_decoder.decode import DecodeStats, SomeipDecoder
    from someip_decoder.run import accumulate_from_arrays, format_stats

    print("--- SOME/IP ---")
    decoder = SomeipDecoder(
        args.someip_services_dir, args.someip_proto_dir, args.someip_pb2_dir
    )
    si_stats = DecodeStats()
    before = len(signals)
    for arr in batches or []:
        accumulate_from_arrays(
            arr,
            decoder,
            signals,
            si_stats,
            emit_frame_updated=not args.no_someip_frame_updated,
        )
    print(format_stats(si_stats))
    print(f"  someip_signals   : {len(signals) - before}")


def _expand_inputs(inputs):
    """Expand directories to their sorted *.pcapng/*.pcap(.zst); keep files as-is."""
    files = []
    for inp in inputs:
        if os.path.isdir(inp):
            for pat in ("*.pcapng", "*.pcap", "*.pcapng.zst", "*.pcap.zst"):
                files.extend(glob.glob(os.path.join(inp, pat)))
        elif os.path.isfile(inp):
            files.append(inp)
        else:
            print(f"skip (not found): {inp}", file=sys.stderr)
    # Timestamped filenames sort chronologically, giving monotonic merged time.
    return sorted(files)


def _materialize(files):
    """Decompress any .zst inputs to temp plain pcaps (the C++ MRC engine needs a
    plain pcap). Returns (plain_files, temp_paths); temps must be cleaned up."""
    plain, temps = [], []
    for f in files:
        if f.endswith(".zst"):
            tmp = tempfile.NamedTemporaryFile(
                prefix="mrc_", suffix=".pcapng", delete=False
            )
            tmp.close()
            print(f"decompressing {os.path.basename(f)} ...")
            with open(tmp.name, "wb") as out:
                subprocess.run(["zstd", "-dc", f], stdout=out, check=True)
            plain.append(tmp.name)
            temps.append(tmp.name)
        else:
            plain.append(f)
    return plain, temps


def _vin_from(path):
    """Best-effort 17-char VIN from a '<ts>_<VIN>_...' capture filename."""
    parts = os.path.basename(path).split("_")
    return parts[1] if len(parts) > 1 and len(parts[1]) == 17 else "combined"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="spa2_decoder")
    p.add_argument("inputs", nargs="+", help="pcap file(s) or a directory of *.pcapng")
    p.add_argument("--db-dir", default=DEFAULT_DB_DIR, help="fetched DBC/LDF directory")
    p.add_argument("--manifest", default=DEFAULT_MANIFEST, help="SDB manifest.yaml")
    p.add_argument(
        "--routing-dir", default=DEFAULT_ROUTING_DIR, help="TC-*.yml routing dir"
    )
    p.add_argument(
        "--routing-table", default=None, help="force a specific TC-*.yml (path or name)"
    )
    p.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="limit packets (for a quick slice)",
    )
    p.add_argument("-o", "--out-dir", default="out", help="output directory")
    p.add_argument(
        "--csv", action="store_true", help="also write long-format CSV (large)"
    )
    p.add_argument(
        "--keep-all",
        action="store_true",
        help="keep every sample (default drops consecutive unchanged values)",
    )
    p.add_argument(
        "--per-file",
        action="store_true",
        help="write one MF4 per input instead of a single merged MF4",
    )
    p.add_argument(
        "--someip",
        action="store_true",
        help="also decode SOME/IP service signals and merge them into the same MF4",
    )
    p.add_argument("--someip-services-dir", default=SOMEIP_SERVICES_DIR)
    p.add_argument("--someip-proto-dir", default=SOMEIP_PROTO_DIR)
    p.add_argument("--someip-pb2-dir", default=SOMEIP_PB2_DIR)
    p.add_argument("--pdu", action="store_true", help="decode SPA3 signal PDUs using bundled layouts")
    p.add_argument("--pdu-config", help="directory containing Signal_PDU_*_ETH and decode_as_entries")
    p.add_argument("--no-mrc", action="store_true", help="skip SPA2 CAN/LIN bus routing")
    p.add_argument(
        "--no-someip-frame-updated",
        action="store_true",
        help="omit per-event SOME/IP FrameUpdated channels",
    )
    args = p.parse_args(argv)
    args.pdu_config = args.pdu_config or (str(DEFAULT_PDU_CONFIG) if args.pdu else None)
    if args.no_mrc and not (args.pdu_config or args.someip):
        p.error("enable --pdu or --someip when using --no-mrc")
    if args.pdu_config:
        load_config(args.pdu_config)

    files = _expand_inputs(args.inputs)
    if not files:
        print("no input pcap files found", file=sys.stderr)
        return 2
    if not args.no_mrc and not os.path.isdir(args.db_dir):
        print(f"db dir not found: {args.db_dir}", file=sys.stderr)
        return 2

    manifest_files = []
    if not args.no_mrc:
        with open(args.manifest) as fh:
            manifest_files = yaml.safe_load(fh)

    routing_table = args.routing_table
    if routing_table and not os.path.isabs(routing_table):
        cand = os.path.join(args.routing_dir, routing_table)
        routing_table = cand if os.path.isfile(cand) else routing_table

    os.makedirs(args.out_dir, exist_ok=True)

    plain_files, temps = _materialize(files)
    try:
        if args.per_file:
            return _run_per_file(
                args, files, plain_files, manifest_files, routing_table
            )
        return _run_merged(args, files, plain_files, manifest_files, routing_table)
    finally:
        for t in temps:
            if os.path.exists(t):
                os.remove(t)


def _finalize(signals, keep_all: bool):
    if keep_all:
        return
    before = sum(len(s.values) for s in signals.values())
    reduce_unchanged(signals)
    after = sum(len(s.values) for s in signals.values())
    pct = (100.0 * (before - after) / before) if before else 0.0
    print(f"  samples          : {before} -> {after} (-{pct:.1f}% unchanged dropped)")


def _run_merged(args, files, plain_files, manifest_files, routing_table) -> int:
    print(f"Merging {len(files)} file(s) into one MF4")
    si_batches = [] if args.someip else None
    pdu_stats = PduStats()
    signals, stats, _buses = decode_pcaps(
        plain_files,
        args.db_dir,
        args.routing_dir,
        manifest_files,
        routing_table=routing_table,
        max_packets=args.max_packets,
        reduce_between=not args.keep_all,
        someip_ports=SOMEIP_PORTS if args.someip else None,
        someip_sink=si_batches,
        pdu_config=args.pdu_config,
        pdu_stats=pdu_stats,
        mrc_enabled=not args.no_mrc,
    )
    print("--- stats ---")
    print(f"  files            : {len(files)}")
    print(f"  routed_frames    : {stats.routed_frames}")
    print(f"  decoded_frames   : {stats.decoded_frames}")
    print(f"  unknown_frame_ids: {stats.unknown_frame_ids}")
    print(f"  decode_errors    : {stats.decode_errors}")
    print(f"  unique_signals   : {len(signals)}")
    if args.pdu_config:
        print_stats(pdu_stats, signals)

    if args.someip:
        _merge_someip(args, si_batches, signals)

    # Per-file series were already reduced; a final pass cleans join boundaries.
    _finalize(signals, args.keep_all)

    vin = _vin_from(files[0])
    ts = os.path.basename(files[0]).split("_")[0]
    stem = f"{vin}_COMBINED_{len(files)}logs_{ts}"

    summary_path = write_summary(
        signals, os.path.join(args.out_dir, f"{stem}_signals.csv")
    )
    print(f"  summary -> {summary_path}")
    if signals:
        try:
            mf4_path = write_mf4(signals, os.path.join(args.out_dir, f"{stem}.mf4"))
            print(f"  mf4     -> {mf4_path}")
        except Exception as exc:  # noqa: BLE001 - MF4 optional, keep summary/CSV
            print(f"  mf4 write failed ({type(exc).__name__}: {exc})")
    if args.csv:
        csv_path = write_csv(signals, os.path.join(args.out_dir, f"{stem}.csv"))
        print(f"  csv     -> {csv_path}")
    return 0


def _run_per_file(args, files, plain_files, manifest_files, routing_table) -> int:
    for i, (orig, pcap) in enumerate(zip(files, plain_files), 1):
        print(f"=== [{i}/{len(files)}] {os.path.basename(orig)} ===")
        si_batches = [] if args.someip else None
        pdu_stats = PduStats()
        signals, stats, _buses = decode_pcap(
            pcap,
            args.db_dir,
            args.routing_dir,
            manifest_files,
            routing_table=routing_table,
            max_packets=args.max_packets,
            someip_ports=SOMEIP_PORTS if args.someip else None,
            someip_sink=si_batches,
            pdu_config=args.pdu_config,
            pdu_stats=pdu_stats,
            mrc_enabled=not args.no_mrc,
            keep_all=args.keep_all,
        )
        print(
            f"  routed={stats.routed_frames} decoded={stats.decoded_frames} "
            f"unknown={stats.unknown_frame_ids} signals={len(signals)}"
        )
        if args.pdu_config:
            print_stats(pdu_stats, signals)
        if args.someip:
            _merge_someip(args, si_batches, signals)
        _finalize(signals, args.keep_all)
        name = os.path.basename(orig).replace(".pcapng", "").replace(".pcap", "")
        base = os.path.splitext(name)[0]
        write_summary(signals, os.path.join(args.out_dir, f"{base}_signals.csv"))
        if signals:
            try:
                write_mf4(signals, os.path.join(args.out_dir, f"{base}_MRCDECODED.mf4"))
            except Exception as exc:  # noqa: BLE001
                print(f"  mf4 write failed ({type(exc).__name__}: {exc})")
        if args.csv:
            write_csv(signals, os.path.join(args.out_dir, f"{base}_MRCDECODED.csv"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
