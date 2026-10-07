"""MRC-over-UDP frame parsing.

One MRC packet per UDP datagram. 12-byte big-endian header:
  off 0  : 4B identifier   (frame_id = low 16 bits, i.e. bytes 2-3)
  off 4  : 4B length        (= 4 + payload length; covers type+flags+payload)
  off 8  : 2B packet type   (0x0001=LIN, 0x0002=CAN base, 0x0003=CAN extended)
  off 10 : 2B flags
  off 12+: frame payload    (CAN/LIN frame bytes)
"""

from __future__ import annotations

from typing import NamedTuple, Optional

HEADER_SIZE = 12
PKT_TYPE_LIN = 0x0001
PKT_TYPE_CAN_BASE = 0x0002
PKT_TYPE_CAN_EXT = 0x0003


class MrcFrame(NamedTuple):
    frame_id: int
    pkt_type: int
    payload: bytes


def parse_mrc(data: bytes) -> Optional[MrcFrame]:
    if data is None or len(data) < HEADER_SIZE:
        return None
    frame_id = int.from_bytes(data[2:4], "big")
    length = int.from_bytes(data[4:8], "big")
    pkt_type = int.from_bytes(data[8:10], "big")
    # Payload length is length-4 (type+flags excluded); clamp to what's present.
    payload_len = max(0, length - 4)
    payload = (
        data[HEADER_SIZE : HEADER_SIZE + payload_len]
        if payload_len
        else data[HEADER_SIZE:]
    )
    return MrcFrame(frame_id=frame_id, pkt_type=pkt_type, payload=payload)
