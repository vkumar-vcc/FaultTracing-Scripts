"""Parse SPA2 routing tables (TC-*.yml) into per-bus decode metadata.

Mirrors nuc-logger SPA2_MRC/decoding_config/routing_table_to_config.py so the
bus->database matching stays consistent with the reference tooling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import yaml

# Routing table bus_type codes.
LIN_BUS_TYPES = {3, 4}
CAN_BUS_TYPES = {7, 9}

REDUNDANCY_LEVELS = ("4-1", "2-1")


@dataclass
class Bus:
    key: str
    viu_name: str
    bus_name: str
    bus_type: str  # "CAN" or "LIN"
    viu_address: str
    viu_port: int
    ecus: List[str] = field(default_factory=list)
    can_msg_names: Set[str] = field(default_factory=set)
    can_networks: Set[str] = field(default_factory=set)
    lin_frames: List[Tuple[int, int]] = field(default_factory=list)
    database: Optional[str] = None


def _redundancy_pref(routing_info: dict) -> Optional[str]:
    name = (routing_info.get("topology_configuration") or {}).get("name", "")
    for level in REDUNDANCY_LEVELS:
        if level in name:
            return level
    return None


def parse_routing_table(path: str) -> Tuple[Dict[str, Bus], Optional[str]]:
    """Return {bus_key: Bus} plus the redundancy preference for one TC table."""
    with open(path, "r") as fh:
        routing_info = yaml.safe_load(fh)

    buses: Dict[str, Bus] = {}
    for viu in routing_info.get("viu", []):
        for bus in viu.get("bus", []):
            if bus.get("bus_type") not in LIN_BUS_TYPES | CAN_BUS_TYPES:
                continue
            is_lin = bus["bus_type"] in LIN_BUS_TYPES
            key = f"{viu['connector_key']}_{bus['bus_name']}"

            can_msg_names: Set[str] = set()
            can_networks: Set[str] = set()
            for frame in bus.get("frame_routing") or []:
                name = frame.get("name")
                if not name or "=>" not in name:
                    continue
                parts = [p.strip() for p in name.split("=>")]
                if parts[0]:
                    can_networks.add(parts[0])
                if len(parts) >= 2 and parts[1] and parts[1].lower() != "match all":
                    can_msg_names.add(parts[1])

            lin_frames: List[Tuple[int, int]] = []
            for frame in bus.get("lin_frames") or []:
                lin_frames.append((int(frame["frame_id"]), int(frame["size"])))

            buses[key] = Bus(
                key=key,
                viu_name=viu["connector_key"],
                bus_name=bus["bus_name"],
                bus_type="LIN" if is_lin else "CAN",
                viu_address=bus["viu_address"],
                viu_port=int(bus["viu_port"]),
                ecus=[e["ecu_name"] for e in bus.get("diagnostic_routing", [])],
                can_msg_names=can_msg_names,
                can_networks=can_networks,
                lin_frames=lin_frames,
            )
    return buses, _redundancy_pref(routing_info)
