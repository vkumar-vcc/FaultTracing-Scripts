"""Match SPA2 buses to DBC/LDF databases by message/frame overlap.

Same scoring as the reference routing_table_to_config.py, but pointed at an
arbitrary fetched database directory + manifest so it tolerates SDB version drift
(database filenames change between versions; the overlap match does not).
"""

from __future__ import annotations

import glob
import os
from collections import defaultdict
from typing import Dict, Iterable, Optional

import cantools
import ldfparser

from .routing import Bus

NETWORK_MATCH_SCORE = 0.5


def load_db_metadata(db_dir: str, valid_files: Iterable[str]) -> Dict[str, dict]:
    """CAN db -> {message names}; LIN db -> {frame_id: size}."""
    valid = set(valid_files)
    meta: Dict[str, dict] = {}

    for ldf_path in glob.glob(os.path.join(db_dir, "*.ldf")):
        base = os.path.basename(ldf_path)
        if base not in valid:
            continue
        try:
            db = ldfparser.parse_ldf_to_dict(ldf_path)
            frames = {int(f["frame_id"]): int(f["length"]) for f in db["frames"]}
            meta[base] = {"type": "LIN", "frames": frames}
        except Exception as exc:  # noqa: BLE001 - report and skip unparsable db
            print(f"  LDF parse error {base}: {exc}")

    for dbc_path in glob.glob(os.path.join(db_dir, "*.dbc")):
        base = os.path.basename(dbc_path)
        if base not in valid:
            continue
        try:
            db = cantools.database.load_file(dbc_path)
            meta[base] = {"type": "CAN", "msg_names": {m.name for m in db.messages}}
        except Exception as exc:  # noqa: BLE001
            print(f"  DBC parse error {base}: {exc}")

    return meta


def _score(bus: Bus, dbm: dict) -> float:
    if bus.bus_type == "CAN" and dbm["type"] == "CAN":
        return len(bus.can_msg_names & dbm["msg_names"])
    if bus.bus_type == "LIN" and dbm["type"] == "LIN":
        return sum(1 for fid, size in bus.lin_frames if dbm["frames"].get(fid) == size)
    return 0


def _redundancy_adjust(db_name: str, pref: Optional[str]) -> int:
    if not pref:
        return 0
    other = "2-1" if pref == "4-1" else "4-1"
    if pref in db_name:
        return 1
    if other in db_name:
        return -1
    return 0


def _network_matches(bus: Bus, db_name: str) -> bool:
    lname = db_name.lower()
    return any(net.lower() in lname for net in bus.can_networks)


def assign_databases(
    buses: Dict[str, Bus], db_meta: Dict[str, dict], pref: Optional[str]
) -> None:
    """Assign each bus its best-overlap database (in place). A db is used at most
    once per VIU."""
    candidates = []
    for key, bus in buses.items():
        if bus.bus_type == "LIN" and "Dummy LIN ECU" in bus.ecus:
            continue
        for db_name, dbm in db_meta.items():
            score = _score(bus, dbm)
            if (
                score == 0
                and bus.bus_type == "CAN"
                and dbm["type"] == "CAN"
                and _network_matches(bus, db_name)
            ):
                score = NETWORK_MATCH_SCORE
            if score > 0:
                candidates.append(
                    (score, _redundancy_adjust(db_name, pref), key, db_name)
                )

    candidates.sort(key=lambda c: (-c[0], -c[1], c[2], c[3]))

    assigned: set = set()
    used_per_viu: Dict[str, set] = defaultdict(set)
    for _score_v, _rank, key, db_name in candidates:
        if key in assigned:
            continue
        viu = buses[key].viu_name
        if db_name in used_per_viu[viu]:
            continue
        buses[key].database = db_name
        assigned.add(key)
        used_per_viu[viu].add(db_name)
