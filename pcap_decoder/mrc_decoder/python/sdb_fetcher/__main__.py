"""CLI: resolve an SDB version into a directory of CAN/LIN databases (DBC/LDF).

Usage:
    python -m sdb_fetcher <version> [--project spa2|spa3] [--cache-root DIR]

The Artifactory bearer token is read from the ARTIFACTORY_TOKEN environment
variable if set, otherwise prompted (not echoed). It is never stored or logged.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys

from .artifactory import ArtifactoryError, fetch_sdb

# Vehicle-program aliases -> SDB project code.
PROJECT_ALIASES = {"spa2": "p519", "spa3": "gpa"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sdb_fetcher")
    parser.add_argument("version", help="SDB version, e.g. 2026.20.1")
    parser.add_argument(
        "--project",
        default="spa2",
        choices=sorted(PROJECT_ALIASES),
        help="vehicle program (default: spa2)",
    )
    parser.add_argument(
        "--cache-root",
        default=None,
        help="where to store the db/ and zip cache (default: ~/.cache/mrc_decoder/sdb)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    token = os.environ.get("ARTIFACTORY_TOKEN")
    if not token:
        token = getpass.getpass("Artifactory token: ")
    if not token:
        print("No token provided.", file=sys.stderr)
        return 2

    project = PROJECT_ALIASES[args.project]
    try:
        result = fetch_sdb(
            args.version, token, cache_root=args.cache_root, project=project
        )
    except ArtifactoryError as exc:
        print(f"Fetch failed: {exc}", file=sys.stderr)
        return 1

    print(f"Database directory: {result.db_dir}")
    print(f"Databases:          {len(result.db_files)}")
    print(f"Manifest:           {result.manifest_path}")
    print(f"ZIPs downloaded:    {result.zips_downloaded}, reused: {result.zips_reused}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
