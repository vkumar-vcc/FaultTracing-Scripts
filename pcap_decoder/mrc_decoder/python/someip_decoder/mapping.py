"""Build the (service_id, message_id) -> protobuf-message lookup from the
rim_ecu_signals definitions.

Resolution is message-type aware: notifications (events) use the event's
`payload.notification` (falling back to the event name), while method requests and
responses use `payload.request` / `payload.response`. A message reference like
"drsu.SurroundingObjects" is reduced to the proto message name "SurroundingObjects".

Unlike the reference SomeipProtobufDecoder this reads every platform in
vsomeip_services.yml, not just "csp".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

import yaml

# SOME/IP message types.
MT_REQUEST = 0x00
MT_REQUEST_NO_RETURN = 0x01
MT_NOTIFICATION = 0x02
MT_RESPONSE = 0x80


def _ref_to_message(ref) -> Optional[str]:
    if isinstance(ref, str) and ref:
        return ref.split(".")[-1]  # strip proto package prefix
    return None


@dataclass
class MessageDef:
    service_id: int
    message_id: int
    service_name: str
    entry_name: str
    proto_stem: str  # proto file stem, e.g. "driver_support"
    # protobuf message name per direction: "notification" | "request" | "response"
    by_kind: Dict[str, str] = field(default_factory=dict)

    def message_for(self, msgtype: int) -> Optional[str]:
        if msgtype == MT_NOTIFICATION:
            return self.by_kind.get("notification")
        if msgtype in (MT_REQUEST, MT_REQUEST_NO_RETURN):
            return self.by_kind.get("request")
        if msgtype == MT_RESPONSE:
            return self.by_kind.get("response")
        return None


class ServiceCatalog:
    """Loads vsomeip_services.yml + all service YAMLs into a message lookup."""

    def __init__(self, services_dir: str | Path):
        self.services_dir = Path(services_dir)
        self.vsomeip_file = self.services_dir / "vsomeip_services.yml"
        self._by_key: Dict[Tuple[int, int], MessageDef] = {}
        self._service_name: Dict[int, str] = {}
        self._build()

    def _build(self) -> None:
        with self.vsomeip_file.open("r", encoding="utf-8") as fh:
            vsomeip = yaml.safe_load(fh)

        # service_id -> service_name across ALL platforms (csp, android, qnx, ...)
        name_to_id: Dict[str, int] = {}
        for _platform, services in vsomeip.items():
            if not isinstance(services, dict):
                continue  # skip the top-level "type" scalar
            for svc_name, info in services.items():
                if isinstance(info, dict) and "service_id" in info:
                    sid = int(info["service_id"])
                    self._service_name[sid] = svc_name
                    name_to_id[svc_name] = sid

        for yml in sorted(self.services_dir.glob("*.yml")):
            if yml.name == "vsomeip_services.yml":
                continue
            try:
                with yml.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
            except Exception:
                continue
            if not isinstance(data, dict) or data.get("type") != "service":
                continue
            svc_name = data.get("name")
            sid = name_to_id.get(svc_name)
            if sid is None:
                continue
            proto_stem = str(data.get("payload_proto", "")).strip() or None
            if not proto_stem:
                continue

            for group in data.get("event_groups", []) or []:
                for ev in group.get("events", []) or []:
                    self._add_event(sid, svc_name, ev, proto_stem)
            for meth in data.get("methods", []) or []:
                self._add_method(sid, svc_name, meth, proto_stem)

    def _entry(self, sid, svc_name, mid, name, proto_stem) -> MessageDef:
        md = self._by_key.get((sid, mid))
        if md is None:
            md = MessageDef(sid, mid, svc_name, name, proto_stem)
            self._by_key[(sid, mid)] = md
        return md

    def _add_event(self, sid, svc_name, ev, proto_stem) -> None:
        if "id" not in ev:
            return
        mid = int(ev["id"])
        name = ev.get("name", f"event_{mid}")
        payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
        msg = _ref_to_message(payload.get("notification")) or name
        self._entry(sid, svc_name, mid, name, proto_stem).by_kind["notification"] = msg

    def _add_method(self, sid, svc_name, meth, proto_stem) -> None:
        if "id" not in meth:
            return
        mid = int(meth["id"])
        name = meth.get("name", f"method_{mid}")
        payload = meth.get("payload") if isinstance(meth.get("payload"), dict) else {}
        md = self._entry(sid, svc_name, mid, name, proto_stem)
        req = _ref_to_message(payload.get("request"))
        resp = _ref_to_message(payload.get("response"))
        if req:
            md.by_kind["request"] = req
        if resp:
            md.by_kind["response"] = resp

    def lookup(self, service_id: int, message_id: int) -> Optional[MessageDef]:
        return self._by_key.get((service_id, message_id))

    def service_name(self, service_id: int) -> Optional[str]:
        return self._service_name.get(service_id)

    def __len__(self) -> int:
        return len(self._by_key)
