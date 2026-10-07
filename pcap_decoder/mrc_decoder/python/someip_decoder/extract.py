"""Read SOME/IP-over-TCP messages from a pcap via tshark.

tshark handles TCP reassembly and splits each reassembled PDU into individual
SOME/IP messages, so we get one (timestamp, service_id, method_id, payload) tuple
per message. `.zst` captures are transparently decompressed to a temp file.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from typing import Iterator, List, NamedTuple, Optional

# Connex SOME/IP reliable-port range (plus any low service ports that appear).
PORT_LO, PORT_HI = 31000, 31699


class SomeipMessage(NamedTuple):
    timestamp: float
    service_id: int
    method_id: int
    msgtype: int
    payload: bytes


def _require(tool: str) -> None:
    if shutil.which(tool) is None:
        raise RuntimeError(f"required tool '{tool}' not found on PATH")


def ensure_plain_pcap(path: str) -> tuple[str, Optional[str]]:
    """Return (pcap_path, tempfile_to_cleanup). Decompresses *.zst on the fly."""
    if not path.endswith(".zst"):
        return path, None
    _require("zstd")
    tmp = tempfile.NamedTemporaryFile(prefix="someip_", suffix=".pcapng", delete=False)
    tmp.close()
    with open(tmp.name, "wb") as out:
        subprocess.run(["zstd", "-dc", path], stdout=out, check=True)
    return tmp.name, tmp.name


def discover_tcp_ports(pcap: str) -> List[int]:
    _require("tshark")
    cmd = [
        "tshark",
        "-r",
        pcap,
        "-T",
        "fields",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.srcport",
    ]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    ports = set()
    for line in out.splitlines():
        for tok in line.replace("\t", ",").split(","):
            if tok.isdigit():
                p = int(tok)
                if PORT_LO <= p <= PORT_HI:
                    ports.add(p)
    return sorted(ports)


def iter_someip_messages(
    pcap: str, ports: Optional[List[int]] = None
) -> Iterator[SomeipMessage]:
    """Yield SOME/IP messages decoded over TCP on the given (or discovered) ports."""
    _require("tshark")
    if ports is None:
        ports = discover_tcp_ports(pcap)
    if not ports:
        return
    dflags: List[str] = []
    for p in ports:
        dflags += ["-d", f"tcp.port=={p},someip"]
    cmd = (
        ["tshark", "-r", pcap]
        + dflags
        + [
            "-Y",
            "someip",
            "-T",
            "fields",
            "-e",
            "frame.time_epoch",
            "-e",
            "someip.serviceid",
            "-e",
            "someip.methodid",
            "-e",
            "someip.messagetype",
            "-e",
            "someip.payload",
        ]
    )
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5 or not parts[1]:
            continue
        try:
            ts = float(parts[0]) if parts[0] else 0.0
        except ValueError:
            continue
        # Repeated fields (multiple messages per frame) come back comma-joined.
        sids = parts[1].split(",")
        mids = parts[2].split(",") if parts[2] else []
        mts = parts[3].split(",") if parts[3] else []
        pls = parts[4].split(",") if parts[4] else []
        for i, sid_s in enumerate(sids):
            mid_s = mids[i] if i < len(mids) else (mids[-1] if mids else "")
            mt_s = mts[i] if i < len(mts) else (mts[-1] if mts else "")
            pl_s = pls[i] if i < len(pls) else ""
            try:
                sid = int(sid_s, 16)
                mid = int(mid_s, 16)
                mt = int(mt_s, 16) if mt_s else 0
                payload = bytes.fromhex(pl_s.replace(":", "")) if pl_s else b""
            except ValueError:
                continue
            yield SomeipMessage(ts, sid, mid, mt, payload)
    proc.wait()
