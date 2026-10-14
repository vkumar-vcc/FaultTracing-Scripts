"""Command-line interface for the SOME/IP communication analyzer."""
from __future__ import annotations

import argparse
import os
import pickle
import sys
from pathlib import Path

from .profiles import DEFAULT_PROFILE, PROFILE_FILES, Names
from .reports import analyze, write_outputs

def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('pcap', nargs='+', help='.pcapng/.pcap, optionally .zst/.gz compressed')
    ap.add_argument('--profile', choices=PROFILE_FILES, default=DEFAULT_PROFILE,
                    help='bundled ECU name profile (default: SPA3)')
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
    profile_file = PROFILE_FILES[a.profile]
    names = Names(profile_file)
    if a.pickle:
        res = analyze(a.pcap[0], a, names)
        res['profile'] = a.profile
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
        res['profile'] = a.profile
        write_outputs(res, a.outdir or Path(path).parent / f'{name}_someip_report', a.max_print, path)
