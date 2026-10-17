"""MAIN_INT baselines of each ECU's software part numbers, looked up in ConfigHub.

One call per ECU to ``POST /api/v1/baselines/getMatchingBaselineForArtifact`` (swagger.json) with the ECU's software
part numbers, ``BaselineName`` "MAIN_INT" and ``IntentOfUse`` "Integration". ConfigHub does the matching itself and
returns the three best baselines, each with the part numbers it matches. The ECUs are queried in parallel.

The download link of each software part is its ``FileURI`` (an Artifactory ``.vbf`` file), read from
``GET /api/v2/software/{partNumber}`` in parallel with the matching calls. The links are opened in the browser,
which signs in to Artifactory itself.

A match covers every ConfigHub position the parts belong to, so HPA's platform parts (HPA_MAIN_INT) and
application parts (HPAA_EE_MAIN_INT) come back together; ``PartNumbers[].MatchingWith`` says which baseline each
part belongs to. Certificate modules and ``00000000`` placeholder parts are not sent.

ConfigHub returns only the three best matches, so only the newest versions that contain all parts are listed.
"""

import os
import re
import sys
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import RLock

import requests

ROOT = Path(__file__).resolve().parent.parent
BASELINE_FILTER = "MAIN_INT"
INTENT_OF_USE = "Integration"
PLACEHOLDER_PREFIX = "00000000"
CACHE_SECONDS = 3600
TIMEOUT_SECONDS = 120
FILE_WORKERS = 6

_LOCK = RLock()
_CACHE = {}


class LoginRequired(Exception):
    """No ConfigHub credentials were supplied, saved in the keychain, or set in CONFIGHUB_TOKEN."""


def _confighub():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import confighub_lookup

    return confighub_lookup


def stored_username():
    """The ConfigHub user saved in the OS keychain by confighub_lookup.py, if any."""
    stored = _confighub().get_stored_credentials()
    return stored[0] if stored else ""


def connect(username="", password="", remember=False):
    """Return a logged-in ConfigHub client. Uses CONFIGHUB_TOKEN, then the entered login, then the saved login."""
    hub = _confighub()
    client = hub.ConfigHubClient()
    token = os.environ.get("CONFIGHUB_TOKEN")
    if token:
        client.use_token(token)
        return client
    entered = bool(username and password)
    if not entered:
        stored = hub.get_stored_credentials()
        if not stored:
            raise LoginRequired("Enter your ConfigHub username and password.")
        username, password = stored
    client.login(username, password)
    if entered and remember:
        hub.save_credentials(username, password)
    return client


def part_key(module):
    """ConfigHub part number of a software module: '32489651' + 'ACP' -> '32489651ACP'."""
    return f"{module['part']}{module['edition']}".replace(" ", "")


def is_ignored(module):
    return module["part"].startswith(PLACEHOLDER_PREFIX) or "CERT" in module["module"].upper()


def baseline_url(handle):
    """Page of a baseline in the ConfigHub web app."""
    return f"{_confighub().BASE_URL}/baselines/{handle}/details"


def hardware_part(record):
    """Delivery (or core) assembly number of an ECU; the match call requires one but does not depend on it."""
    for field in ("delivery", "core"):
        found = re.search(r"\d{8}", record.get(field) or "")
        if found:
            return found.group(0)
    return PLACEHOLDER_PREFIX


def version_text(versions):
    """[430, 431, 434] -> 'v430-v431, v434'; one version -> 'v434'."""
    ordered = sorted(set(versions))
    runs = []
    for version in ordered:
        if runs and version == runs[-1][1] + 1:
            runs[-1][1] = version
        else:
            runs.append([version, version])
    return ", ".join(f"v{a}" if a == b else f"v{a}\u2013v{b}" for a, b in runs)


def _version_number(baseline):
    try:
        return int(baseline.get("Version"))
    except (TypeError, ValueError):
        return 0


def fetch_matches(client, ecu, hardware, keys):
    """The matches ConfigHub returns for one ECU (cached for an hour)."""
    cache_key = (ecu, hardware, tuple(keys))
    now = time.monotonic()
    with _LOCK:
        hit = _CACHE.get(cache_key)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    payload = {
        "ECUPartNumbers": [{
            "Id": ecu,
            "HwPartNumber": hardware,
            "BaselineName": BASELINE_FILTER,
            "SwPartNumbers": list(keys),
            "PartTypesToBeSkipped": [],
            "IgnorePartnumberStartswith": [PLACEHOLDER_PREFIX],
        }],
        "IntentOfUse": [INTENT_OF_USE],
    }
    response = requests.post(
        f"{client.base_url}/api/v1/baselines/getMatchingBaselineForArtifact",
        headers={**client._headers(), "Content-Type": "application/json"},
        json=payload,
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    entries = (response.json() or {}).get("ECUMatchingBaselines") or []
    matches = entries[0].get("Matches") or [] if entries else []
    with _LOCK:
        _CACHE[cache_key] = (now, matches)
    return matches


def fetch_file(client, key):
    """Download link and part type of one software part (cached for an hour); None when ConfigHub has no file."""
    cache_key = ("file", key)
    now = time.monotonic()
    with _LOCK:
        hit = _CACHE.get(cache_key)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    part = client.get_software_part(key) or {}
    uri = part.get("FileURI") or ""
    info = {"uri": uri, "type": part.get("KDPPartType") or ""} if uri.startswith("http") else None
    with _LOCK:
        _CACHE[cache_key] = (now, info)
    return info


def file_links(keys, files):
    """(label, url) download links for the given part numbers."""
    links = []
    for key in keys:
        info = files.get(key)
        if info:
            links.append((f"{info['type']} {key}".strip(), info["uri"]))
    return links


def _rows_for_ecu(ecu, keys, matches, files):
    """Table rows (one per baseline family), the unknown parts and a note for one ECU's matches."""
    known = {part["PartNumber"].upper() for match in matches for part in match.get("PartNumbers") or []}
    not_found = [key for key in keys if key.upper() not in known]
    full = [m for m in matches if m.get("PartNumbers") and all(p.get("Matching") for p in m["PartNumbers"])]
    if not full:
        if not matches:
            return [{"Position": ecu, "Baseline": "No MAIN_INT baseline found", "Version(s)": "-",
                     "Download": file_links(keys, files), "Parts": str(len(keys))}], not_found
        best = matches[0]
        covered = sum(1 for part in best["PartNumbers"] if part.get("Matching"))
        names = ", ".join(b["Name"] for b in best["Baselines"])
        versions = ", ".join(f"{b['Name']} v{_version_number(b)}" for b in best["Baselines"])
        return [{
            "Position": ecu,
            "Baseline": "No single MAIN_INT baseline contains all parts",
            "Version(s)": f"Closest: {versions} ({covered} of {len(best['PartNumbers'])} parts; {names})",
            "Download": file_links(keys, files),
            "Parts": str(len(best["PartNumbers"])),
        }], not_found

    families = OrderedDict()
    for match in full:
        for baseline in match["Baselines"]:
            family = families.setdefault(
                baseline["Name"], {"position": baseline.get("EcuName") or ecu, "versions": [], "handles": {}}
            )
            family["versions"].append(_version_number(baseline))
            family["handles"][_version_number(baseline)] = baseline.get("Handle")
    rows = []
    for name, family in families.items():
        types = sorted({p.get("KdpPartType") or "" for p in full[0]["PartNumbers"] if p.get("MatchingWith") == name})
        types = [t for t in types if t]
        members = [p["PartNumber"] for p in full[0]["PartNumbers"] if p.get("MatchingWith") == name]
        count = len(members)
        rows.append({
            "Position": family["position"],
            "Baseline": name,
            "Version(s)": version_text(family["versions"]),
            "ConfigHub": [
                (f"v{version}", baseline_url(handle))
                for version, handle in sorted(family["handles"].items(), reverse=True) if handle
            ],
            "Download": file_links(members, files),
            "Parts": f"{count}: {' '.join(types)}" if types else str(count),
        })
    return rows, not_found


def lookup_main_int_baselines(client, records, progress=None):
    """Find the MAIN_INT baselines that contain the software parts of each ECU."""
    report = progress or (lambda message: None)
    started = time.monotonic()

    ecus = OrderedDict()
    ignored = []
    for record in records:
        if not record["present"]:
            continue
        keys = []
        for module in record["software"]:
            key = part_key(module)
            if is_ignored(module):
                ignored.append({"ecu": record["ecu"], "module": module["module"], "key": key})
            elif key not in keys:
                keys.append(key)
        if keys:
            ecus[record["ecu"]] = {"hardware": hardware_part(record), "keys": keys}

    report(f"Asking ConfigHub for the baselines of {len(ecus)} ECUs...")
    all_keys = list(dict.fromkeys(key for info in ecus.values() for key in info["keys"]))
    with ThreadPoolExecutor(max_workers=max(1, len(ecus) + FILE_WORKERS)) as pool:
        file_futures = {key: pool.submit(fetch_file, client, key) for key in all_keys}
        futures = {
            ecu: pool.submit(fetch_matches, client, ecu, info["hardware"], info["keys"])
            for ecu, info in ecus.items()
        }
        matches = {ecu: future.result() for ecu, future in futures.items()}
        files = {key: future.result() for key, future in file_futures.items()}

    rows = []
    not_found = []
    for ecu, info in ecus.items():
        ecu_rows, missing = _rows_for_ecu(ecu, info["keys"], matches[ecu], files)
        rows.extend(ecu_rows)
        not_found.extend(missing)
    return {
        "rows": rows,
        "ignored": ignored,
        "not_found": not_found,
        "looked_up": sum(len(info["keys"]) for info in ecus.values()),
        "seconds": time.monotonic() - started,
    }
