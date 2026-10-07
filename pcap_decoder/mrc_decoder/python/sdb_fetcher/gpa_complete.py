#!/usr/bin/env python3
"""Fetch the GPA (SPA3) SDB *complete* ZIP and extract its CAN/LIN databases.

The GPA complete artifact is a single self-contained ZIP (see the reference
fetch_gpa_sdb_manifest.py). Signal definitions and frame IDs live in the CAN/LIN
databases under Networks/DBC/*.dbc and Networks/LDF/*.ldf -- NOT in ARXML. This
tool downloads the ZIP and extracts those databases (flattened) into the SDB
cache, writing a YAML manifest of the extracted files. It can also inventory the
ZIP (--inventory) or dump the non-database members (--extract-to) for inspection.

Security: pass the Artifactory token via --token-file or the ARTIFACTORY_TOKEN
environment variable. Never paste a token on the command line or into a file that
gets committed.

Usage:
    # Fetch DBC/LDF into the cache (default action):
    ARTIFACTORY_TOKEN=$(cat ~/.artifactory_token) \\
        python -m sdb_fetcher.gpa_complete --version 2026.28.1
    # Just inspect the ZIP contents:
    ARTIFACTORY_TOKEN=$(cat ~/.artifactory_token) \\
        python -m sdb_fetcher.gpa_complete --version 2026.28.1 --inventory
"""

import argparse
import io
import os
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import requests
import yaml

ARTIFACTORY_BASE = "https://ara-artifactory.volvocars.biz/artifactory/SDB-Hub-LTS"
COMPLETE_GROUP = "com/volvo/sdb/complete"
DB_EXTENSIONS = {".dbc", ".ldf"}
CACHE_ROOT = Path.home() / ".cache" / "mrc_decoder" / "sdb"


def complete_zip_url(project: str, version: str) -> str:
    return (
        f"{ARTIFACTORY_BASE}/{COMPLETE_GROUP}/{project}/{version}/"
        f"{project}-{version}.zip"
    )


def read_token(token_file: str | None) -> str:
    if os.environ.get("ARTIFACTORY_TOKEN"):
        return os.environ["ARTIFACTORY_TOKEN"].strip()
    if token_file:
        return Path(token_file).expanduser().read_text().strip()
    print(
        "ERROR: provide the token via ARTIFACTORY_TOKEN env var or --token-file",
        file=sys.stderr,
    )
    sys.exit(1)


def fetch_zip(project: str, version: str, token: str) -> bytes:
    url = complete_zip_url(project, version)
    print(f"Downloading: {url}")
    with requests.Session() as session:
        session.trust_env = False  # ignore ~/.netrc so our Bearer header wins
        session.headers["Authorization"] = f"Bearer {token}"
        resp = session.get(url, timeout=120)
        resp.raise_for_status()
        print(f"  {len(resp.content) / 1e6:.1f} MB")
        return resp.content


def inventory(zip_bytes: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
    by_ext: Counter[str] = Counter(Path(n).suffix.lower() or "<none>" for n in names)
    by_top: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for n in names:
        parts = Path(n).parts
        top = parts[0] if len(parts) > 1 else "<root>"
        by_top[top][Path(n).suffix.lower() or "<none>"] += 1

    print(f"\n{len(names)} files. By extension:")
    for ext, c in by_ext.most_common():
        print(f"  {ext:10} {c}")

    print("\nBy top-level folder (ext -> count):")
    for top, cc in sorted(by_top.items()):
        print(f"  {top}/")
        for ext, c in cc.most_common():
            print(f"      {ext:10} {c}")

    # Highlight likely Ethernet-PDU sources.
    eth_like = [
        n
        for n in names
        if Path(n).suffix.lower() in {".arxml", ".fibex", ".xml"}
        or "ethernet" in n.lower()
        or "someip" in n.lower()
        or "pdu" in n.lower()
    ]
    print(f"\nLikely Ethernet/PDU source files ({len(eth_like)}):")
    for n in sorted(eth_like)[:40]:
        print(f"  {n}")


def extract_databases(zip_bytes: bytes, db_dir: Path) -> list[str]:
    """Extract all .dbc/.ldf from the ZIP into db_dir (flattened). Returns names."""
    db_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        members = [n for n in zf.namelist() if Path(n).suffix.lower() in DB_EXTENSIONS]
        for name in sorted(members):
            data = zf.read(name)
            dest = db_dir / Path(name).name  # flatten Networks/DBC/... -> basename
            if not dest.exists() or dest.read_bytes() != data:
                dest.write_bytes(data)
            extracted.append(dest.name)
    return sorted(extracted)


def fetch_databases(project: str, version: str, token: str) -> tuple[Path, list[str]]:
    """Download the complete ZIP and extract DBC/LDF into the SDB cache.

    Returns (db_dir, manifest_files). Writes a YAML manifest alongside the db dir.
    """
    zip_bytes = fetch_zip(project, version, token)
    db_dir = CACHE_ROOT / f"{project}_{version}" / "db"
    files = extract_databases(zip_bytes, db_dir)
    manifest = CACHE_ROOT / f"{project}_{version}" / "manifest.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(yaml.safe_dump(files, default_flow_style=False))
    n_dbc = sum(1 for f in files if f.lower().endswith(".dbc"))
    n_ldf = sum(1 for f in files if f.lower().endswith(".ldf"))
    print(f"Extracted {len(files)} databases ({n_dbc} DBC, {n_ldf} LDF) to {db_dir}")
    print(f"Manifest: {manifest}")
    return db_dir, files


PDU_SOURCE_PATTERNS = {
    "arxml": re.compile(r"systemextract.*\.arxml$", re.IGNORECASE),
    "csv": re.compile(r"ethernetbackbone.*\.csv$", re.IGNORECASE),
}


def fetch_pdu_sources(project: str, version: str, token: str) -> tuple[Path, Path]:
    """Extract the SystemExtract ARXML and Ethernet Backbone CSV for PDU generation.

    Returns (arxml_path, csv_path) under the SDB cache's ``source`` directory.
    """
    source_dir = CACHE_ROOT / f"{project}_{version}" / "source"
    found = {kind: next((path for path in source_dir.glob("*") if pattern.search(path.name)), None)
             for kind, pattern in PDU_SOURCE_PATTERNS.items()}
    if not all(found.values()):
        source_dir.mkdir(parents=True, exist_ok=True)
        zip_bytes = fetch_zip(project, version, token)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            for kind, pattern in PDU_SOURCE_PATTERNS.items():
                if found.get(kind):
                    continue
                member = next((name for name in archive.namelist()
                               if not name.endswith("/") and pattern.search(name)), None)
                if member is None:
                    raise FileNotFoundError(
                        f"The {project} {version} SDB ZIP has no {kind} source "
                        f"(pattern {pattern.pattern}).")
                destination = source_dir / Path(member).name
                destination.write_bytes(archive.read(member))
                found[kind] = destination
    print(f"PDU sources: {found['arxml']} ; {found['csv']}")
    return found["arxml"], found["csv"]


def extract_other(zip_bytes: bytes, dest: Path) -> None:
    """Extract the non-database members (for inspecting other SDB content)."""
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        members = [
            n
            for n in zf.namelist()
            if not n.endswith("/") and Path(n).suffix.lower() not in DB_EXTENSIONS
        ]
        for n in members:
            (dest / Path(n).name).write_bytes(zf.read(n))
    print(f"\nExtracted {len(members)} non-database members to {dest}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", required=True, help="e.g. 2026.28.1")
    ap.add_argument("--project", default="gpa")
    ap.add_argument(
        "--token-file", help="path to a file containing the Artifactory token"
    )
    ap.add_argument(
        "--inventory", action="store_true", help="print a ZIP content inventory only"
    )
    ap.add_argument(
        "--extract-to", help="also extract non-database members to this directory"
    )
    args = ap.parse_args()

    token = read_token(args.token_file)

    if args.inventory:
        inventory(fetch_zip(args.project, args.version, token))
        return

    # Default action: fetch DBC/LDF databases into the cache.
    fetch_databases(args.project, args.version, token)
    if args.extract_to:
        extract_other(
            fetch_zip(args.project, args.version, token),
            Path(args.extract_to).expanduser(),
        )


if __name__ == "__main__":
    main()
