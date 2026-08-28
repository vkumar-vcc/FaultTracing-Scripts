#!/usr/bin/env python3
"""
ConfigHub part lookup tool.

Authenticates against ConfigHub (OAuth2 password grant), then for a given
part number:
  1. Fetches the current software (or hardware) part metadata.
  2. Fetches its full version history.
  3. Lists all file versions that share the same SupplierVersion as the
     current/latest version.
  4. Finds the baselines the part is directly connected to.
  5. Walks the parent baseline tree for a chosen baseline (recursively) to
     show which complete/system baselines it feeds into.

Usage:
    python confighub_lookup.py 32456876AH
    python confighub_lookup.py 32456876AH --baseline-id <handle>  # to also
        walk the parent tree of one specific connected baseline

Credentials:
    You'll be prompted securely (getpass) for your ConfigHub username and
    password. Nothing is written to disk. The access token only lives in
    memory for the duration of the script run.

    Alternatively, set the CONFIGHUB_TOKEN environment variable to an
    existing bearer token to skip the interactive login step.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from typing import Any, Optional

try:
    # Use the Windows certificate store (trusts corporate TLS-inspection CAs
    # already trusted by the OS) instead of the bundled certifi CA list.
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    print("Note: 'truststore' package not installed; if you hit SSL "
          "certificate verification errors behind a corporate proxy, run:\n"
          "    pip install truststore\n", file=__import__("sys").stderr)

import requests

# Ensure Unicode box-drawing characters print correctly even on legacy
# Windows console code pages (e.g. cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_URL = "https://confighub.volvocars.net"
CONTRACT_ID = "10002"


class ConfigHubClient:
    def __init__(self, base_url: str = BASE_URL, contract_id: str = CONTRACT_ID):
        self.base_url = base_url.rstrip("/")
        self.contract_id = contract_id
        self.token: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Auth
    # ------------------------------------------------------------------ #
    def login(self, username: str, password: str) -> None:
        """Authenticate using OAuth2 password grant (POST /api/v2/session)."""
        url = f"{self.base_url}/api/v2/session"
        headers = {"Contract-Id": self.contract_id}
        data = {"grant_type": "password", "username": username, "password": password}

        resp = requests.post(url, headers=headers, data=data, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        self.token = payload.get("access_token") or payload.get("Token")
        if not self.token:
            raise RuntimeError(f"Login succeeded but no token found in response: {payload}")

    def use_token(self, token: str) -> None:
        """Use an already-issued bearer token instead of logging in."""
        self.token = token

    def _headers(self) -> dict:
        if not self.token:
            raise RuntimeError("Not authenticated. Call login() or use_token() first.")
        return {"Authorization": f"Bearer {self.token}", "Contract-Id": self.contract_id}

    # ------------------------------------------------------------------ #
    # Generic GET helper
    # ------------------------------------------------------------------ #
    def _get(self, path: str) -> Optional[Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------ #
    # Part lookups
    # ------------------------------------------------------------------ #
    def get_software_part(self, part_number: str) -> Optional[dict]:
        return self._get(f"api/v2/software/{part_number}")

    def get_software_history(self, part_number: str) -> Optional[list]:
        return self._get(f"api/v1/software/{part_number}/history")

    def get_hardware_part(self, part_number: str) -> Optional[dict]:
        return self._get(f"api/v2/hardware/{part_number}")

    def get_hardware_history(self, part_number: str) -> Optional[list]:
        return self._get(f"api/v1/hardware/{part_number}/history")

    # ------------------------------------------------------------------ #
    # Baselines
    # ------------------------------------------------------------------ #
    def get_connected_baselines(self, artifact_id: str) -> Optional[list]:
        return self._get(f"api/v1/software/{artifact_id}/baselines")

    def get_baseline_parent_tree(self, baseline_id: str) -> Optional[dict]:
        return self._get(f"api/v3/baselines/{baseline_id}/parent")


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #
def find_files_by_supplier_version(history: list, supplier_version: str) -> list:
    return [h for h in history if h.get("SupplierVersion") == supplier_version]


def print_parent_tree(node: dict, depth: int = 0) -> None:
    name = node.get("Name")
    version = node.get("Version")
    type_ = node.get("Type")
    node_id = node.get("Id")
    print("  " * depth + f"{name} (v{version}, {type_}, id={node_id})")
    for parent in node.get("ParentBaselines", []):
        print_parent_tree(parent, depth + 1)


def summarize_baseline_connections(connected: list) -> str:
    """Collapse a list of connected-baseline entries into a short summary
    string, e.g. 'HIA_MAIN_INT (up to v389) + HIA_SPA2_COMMON_PIE_INT v1'."""
    if not connected:
        return "(none)"

    by_name: dict[str, list[int]] = {}
    for b in connected:
        name = b.get("Name", "?")
        try:
            version = int(b.get("Version"))
        except (TypeError, ValueError):
            continue
        by_name.setdefault(name, []).append(version)

    parts = []
    # Order by the highest version in each group, descending, so the most
    # "current" baseline family is listed first.
    for name, versions in sorted(by_name.items(), key=lambda kv: max(kv[1]), reverse=True):
        versions.sort()
        if len(versions) == 1:
            parts.append(f"{name} v{versions[0]}")
        else:
            parts.append(f"{name} (up to v{versions[-1]})")
    return " + ".join(parts)


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    """Render a Unicode box-drawing table (like the one used in ConfigHub
    baseline summaries)."""
    n = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i in range(n):
            widths[i] = max(widths[i], len(str(row[i])))
    widths = [w + 2 for w in widths]  # 1 space padding each side

    def hline(left: str, mid: str, right: str) -> str:
        return left + mid.join("─" * w for w in widths) + right

    def data_line(cells: list[str]) -> str:
        return "│" + "│".join(f" {c}".ljust(w) for c, w in zip(cells, widths)) + "│"

    lines = [hline("┌", "┬", "┐"), data_line(headers), hline("├", "┼", "┤")]
    for idx, row in enumerate(rows):
        lines.append(data_line([str(c) for c in row]))
        if idx != len(rows) - 1:
            lines.append(hline("├", "┼", "┤"))
    lines.append(hline("└", "┴", "┘"))
    return "\n".join(lines)


def parse_labeled_parts(entries: list[str]) -> list[tuple[str, str]]:
    """Parse '--parts' CLI entries of the form 'Label:PartNumber'
    (part number may contain spaces, which are stripped)."""
    result = []
    for entry in entries:
        if ":" not in entry:
            raise ValueError(f"Invalid --parts entry (expected 'Label:PartNumber'): {entry!r}")
        label, part_number = entry.split(":", 1)
        result.append((label.strip(), part_number.replace(" ", "").strip()))
    return result


# A part number looks like a run of digits optionally followed by a short
# run of letters, e.g. "80073512AAF", "32456876AH". We allow internal
# whitespace (e.g. "80 07 35 12 AAF") which gets stripped before validation.
_PART_NUMBER_RE = re.compile(r"^[0-9]{4,10}[A-Za-z]{0,6}$")
# Matches a line like "<description>: <value>", where <value> is made up of
# digits/letters/spaces only (i.e. plausibly a spaced-out part number).
_LOG_LINE_RE = re.compile(r"^(?P<desc>.+?):\s*(?P<value>[0-9A-Za-z](?:[0-9A-Za-z ]*[0-9A-Za-z])?)\s*$")
_PAREN_LABEL_RE = re.compile(r"\(([^()]+)\)\s*$")


def extract_parts_from_log(text: str) -> list[tuple[str, str]]:
    """Scan free-form log text for lines of the form
    '<description>(<LABEL>): <spaced part number>' or
    '<description>: <spaced part number>' and return (label, part_number)
    pairs. Lines whose value doesn't look like a part number are ignored.
    """
    results: list[tuple[str, str]] = []
    seen: set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _LOG_LINE_RE.match(line)
        if not m:
            continue

        desc = m.group("desc").strip()
        value = m.group("value")
        part_number = value.replace(" ", "").strip().upper()

        if not _PART_NUMBER_RE.match(part_number):
            continue  # doesn't look like a part number, skip this line

        label_match = _PAREN_LABEL_RE.search(desc)
        label = label_match.group(1).strip() if label_match else desc

        key = f"{label}:{part_number}"
        if key in seen:
            continue
        seen.add(key)
        results.append((label, part_number))

    return results


def run_table_mode(client: "ConfigHubClient", labeled_parts: list[tuple[str, str]]) -> None:
    """Look up multiple labeled part numbers and print a summary table."""
    headers = ["Label", "Part Number", "Type", "Version", "Filestate", "Latest Connected Baseline"]
    rows = []

    for label, part_number in labeled_parts:
        sw_part = client.get_software_part(part_number)
        part = sw_part
        artifact_id = None
        part_type = "?"
        version = "?"
        filestate = "?"
        latest_baseline_str = "(not found)"

        if sw_part is not None:
            artifact_id = sw_part.get("Id")
            part_type = sw_part.get("SwPartType", "?")
            version = f"v{sw_part.get('Version', '?')}"
            filestate = sw_part.get("Filestate", "?")
            connected = client.get_connected_baselines(artifact_id) if artifact_id else None
            latest_baseline_str = summarize_baseline_connections(connected or [])
        else:
            hw_part = client.get_hardware_part(part_number)
            if hw_part is not None:
                part_type = "HW"
                version = f"v{hw_part.get('Version', '?')}"
                filestate = hw_part.get("Filestate", "?")
                latest_baseline_str = "(hardware - baseline lookup not implemented)"

        rows.append([label, part_number, part_type, version, filestate, latest_baseline_str])

    print(render_table(headers, rows))


def summarize_part(part: dict) -> None:
    fields = [
        "Id", "PartNumber", "HeaderVersion", "Position", "SwPartType",
        "KDPPartType", "SupplierVersion", "Version", "Filestate",
        "IsPublished", "IsLatestVersion", "IsBlocked", "Replaces",
        "ReplacedBy", "CheckSum", "Sha256CheckSum", "ComplianceAssessment",
        "PositionStructure", "Audit",
    ]
    keep = {k: part[k] for k in fields if k in part}
    print(json.dumps(keep, indent=2))
    ves = part.get("VariantExpressions", [])
    print(f"\nVariantExpressions ({len(ves)}):")
    for ve in ves:
        print(f"  - Context={ve.get('Context')} EcuSolutionParameter={ve.get('EcuSolutionParameter')} "
              f"ConfigValues={ve.get('ConfigurationParameterValues')}")


# ---------------------------------------------------------------------- #
# Main
# ---------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description="Look up ConfigHub part number(s).")
    parser.add_argument("part_number", nargs="?",
                         help="Single part number to look up in detail, e.g. 32456876AH")
    parser.add_argument("--baseline-id", help="Baseline handle to walk the parent tree for "
                                               "(defaults to the first connected baseline found)")
    parser.add_argument("--parts", nargs="+", metavar="LABEL:PARTNUMBER",
                         help="Batch/table mode: one or more 'Label:PartNumber' entries, e.g. "
                              "--parts \"SWLM:80 07 35 12 AAF\" \"SWL2:80 06 79 86  AK\". "
                              "Prints a summary table instead of a detailed single-part report.")
    parser.add_argument("--log-file", metavar="PATH",
                         help="Path to a log/text file to scan for labeled part numbers "
                              "(lines like 'HIA Software Part Number(SWLM): 80 07 35 12 AAF' "
                              "or 'ECU Software Structure: 80 05 59 92  AO'). Runs table mode "
                              "using every part number found.")
    args = parser.parse_args()

    if not args.part_number and not args.parts and not args.log_file:
        parser.error("Provide a part_number, --parts, or --log-file.")

    client = ConfigHubClient()

    token = os.environ.get("CONFIGHUB_TOKEN")
    if token:
        print("Using CONFIGHUB_TOKEN from environment.")
        client.use_token(token)
    else:
        username = input("ConfigHub username: ").strip()
        password = getpass.getpass("ConfigHub password: ")
        print("Logging in...")
        client.login(username, password)
        print("Login successful.")

    if args.parts or args.log_file:
        if args.log_file:
            with open(args.log_file, "r", encoding="utf-8", errors="replace") as f:
                log_text = f.read()
            labeled_parts = extract_parts_from_log(log_text)
            if not labeled_parts:
                print(f"No part numbers found in {args.log_file!r}.")
                sys.exit(1)
            print(f"Found {len(labeled_parts)} part number(s) in {args.log_file!r}:")
            for label, part_number in labeled_parts:
                print(f"  {label}: {part_number}")
            print()
        else:
            labeled_parts = parse_labeled_parts(args.parts)
        run_table_mode(client, labeled_parts)
        return

    part_number = args.part_number

    # 1. Try software first, then hardware.
    print(f"\n=== Fetching part {part_number} ===")
    sw_part = client.get_software_part(part_number)
    hw_part = None
    is_software = sw_part is not None
    if not is_software:
        hw_part = client.get_hardware_part(part_number)
        if hw_part is None:
            print(f"Part {part_number} not found as software or hardware.")
            sys.exit(1)

    part = sw_part if is_software else hw_part
    kind = "software" if is_software else "hardware"
    print(f"Found as {kind} part.\n")
    summarize_part(part)

    # 2. History + supplier version match (software only, mirrors what we did).
    if is_software:
        print(f"\n=== Version history for {part_number} ===")
        history = client.get_software_history(part_number) or []
        print(f"Total versions: {len(history)}")
        if history:
            versions_sorted = sorted(history, key=lambda h: h.get("Version", 0))
            print(f"Version range: {versions_sorted[0]['Version']} - {versions_sorted[-1]['Version']}")

        supplier_version = part.get("SupplierVersion")
        print(f"\nSupplierVersion: {supplier_version!r}")
        matches = find_files_by_supplier_version(history, supplier_version)
        print(f"Files sharing this SupplierVersion ({len(matches)}):")
        for h in sorted(matches, key=lambda x: x.get("Version", 0)):
            print(f"  v{h['Version']:>4} | {h.get('FileURI')} | SHA256={h.get('Sha256CheckSum')} "
                  f"| Created={h['Audit']['CreatedAt']}")

    # 3. Connected baselines (software artifact Id).
    artifact_id = part.get("Id")
    connected = []
    if is_software and artifact_id:
        print(f"\n=== Baselines connected to artifact {artifact_id} ===")
        connected = client.get_connected_baselines(artifact_id) or []
        for b in connected:
            print(f"  {b.get('Name')} v{b.get('Version')} (handle={b.get('Handle')}) "
                  f"status={b.get('BaselineStatus', {}).get('Value')} "
                  f"published={b.get('IsPublished')}")

    # 4. Parent baseline tree.
    baseline_id = args.baseline_id
    if not baseline_id and connected:
        baseline_id = connected[0].get("Handle")

    if baseline_id:
        print(f"\n=== Parent baseline tree for baseline {baseline_id} ===")
        tree = client.get_baseline_parent_tree(baseline_id)
        if tree:
            print_parent_tree(tree)
        else:
            print("No parent baseline data found.")
    else:
        print("\nNo baseline id available to walk parent tree "
              "(pass --baseline-id explicitly if needed).")


if __name__ == "__main__":
    main()
