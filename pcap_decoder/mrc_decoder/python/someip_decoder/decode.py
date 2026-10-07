"""Decode SOME/IP protobuf payloads into flat, named numeric signal samples.

Reuses the rim_ecu_signals generated *_pb2 modules. A message is flattened by
walking the protobuf descriptor so nested messages, repeated fields and enums are
handled correctly (the reference decoder's MessageToDict+float() path throws on
lists and bytes).
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from google.protobuf.descriptor import FieldDescriptor

from .mapping import ServiceCatalog

# Scalar protobuf field types we can represent as a float sample.
_NUMERIC = {
    FieldDescriptor.TYPE_DOUBLE,
    FieldDescriptor.TYPE_FLOAT,
    FieldDescriptor.TYPE_INT64,
    FieldDescriptor.TYPE_UINT64,
    FieldDescriptor.TYPE_INT32,
    FieldDescriptor.TYPE_FIXED64,
    FieldDescriptor.TYPE_FIXED32,
    FieldDescriptor.TYPE_BOOL,
    FieldDescriptor.TYPE_UINT32,
    FieldDescriptor.TYPE_SFIXED32,
    FieldDescriptor.TYPE_SFIXED64,
    FieldDescriptor.TYPE_SINT32,
    FieldDescriptor.TYPE_SINT64,
}


@dataclass
class Sample:
    name: str  # Service::Event::field.path
    value: float
    label: str = ""  # enum label, else ""


@dataclass
class DecodeStats:
    messages: int = 0
    decoded: int = 0
    skipped_unmapped: int = 0
    errors: int = 0
    sample_rows: int = 0
    unmapped_services: Dict[int, int] = field(default_factory=dict)


class SomeipDecoder:
    def __init__(self, services_dir, proto_dir, pb2_dir):
        self.catalog = ServiceCatalog(services_dir)
        self.proto_dir = Path(proto_dir)
        self.pb2_dir = Path(pb2_dir)
        if str(self.pb2_dir) not in sys.path:
            sys.path.append(str(self.pb2_dir))
        self._modules: Dict[str, object] = {}
        self._msg_cls_cache: Dict[Tuple[str, str], Optional[type]] = {}

    def _module(self, stem: str):
        mod = self._modules.get(stem)
        if mod is not None:
            return mod
        path = self.pb2_dir / f"{stem}_pb2.py"
        if not path.exists():
            self._modules[stem] = None
            return None
        spec = importlib.util.spec_from_file_location(f"{stem}_pb2", str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        self._modules[stem] = mod
        return mod

    def _message_class(self, stem: str, message_name: str) -> Optional[type]:
        key = (stem, message_name)
        if key in self._msg_cls_cache:
            return self._msg_cls_cache[key]
        mod = self._module(stem)
        cls = getattr(mod, message_name, None) if mod else None
        self._msg_cls_cache[key] = cls
        return cls

    def decode(
        self, service_id: int, message_id: int, msgtype: int, payload: bytes
    ) -> Optional[Tuple[str, List[Sample]]]:
        """Return (header, samples) where header is "Service::Entry", or None if
        the (service, message, direction) is unknown. samples may be empty."""
        md = self.catalog.lookup(service_id, message_id)
        if md is None:
            return None
        message_name = md.message_for(msgtype)
        if message_name is None:
            return None
        cls = self._message_class(md.proto_stem, message_name)
        if cls is None:
            return None
        msg = cls()
        msg.ParseFromString(payload)
        rows: List[Tuple[str, float, str]] = []
        _flatten(msg, "", rows)
        header = f"{md.service_name}::{md.entry_name}"
        samples = [
            Sample(f"{header}::{fp}" if fp else header, v, lbl) for fp, v, lbl in rows
        ]
        return header, samples


def _flatten(msg, prefix: str, out: List[Tuple[str, float, str]]) -> None:
    """Append (dotted_field_path, value, enum_label) for every numeric leaf."""
    for fd, value in msg.ListFields():
        name = f"{prefix}.{fd.name}" if prefix else fd.name
        if fd.label == FieldDescriptor.LABEL_REPEATED:
            if fd.type == FieldDescriptor.TYPE_MESSAGE:
                for i, item in enumerate(value):
                    _flatten(item, f"{name}[{i}]", out)
            else:
                for i, item in enumerate(value):
                    _emit(f"{name}[{i}]", fd, item, out)
        elif fd.type == FieldDescriptor.TYPE_MESSAGE:
            _flatten(value, name, out)
        else:
            _emit(name, fd, value, out)


def _emit(name: str, fd, value, out: List[Tuple[str, float, str]]) -> None:
    if fd.type == FieldDescriptor.TYPE_ENUM:
        ev = fd.enum_type.values_by_number.get(value)
        out.append((name, float(value), ev.name if ev is not None else ""))
    elif fd.type in _NUMERIC:
        out.append((name, float(value), ""))
    # strings/bytes are not representable as numeric MF4 channels -> skipped
