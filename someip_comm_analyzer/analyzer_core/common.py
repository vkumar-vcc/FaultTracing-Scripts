"""Shared binary structures, constants, and lazy dataframe dependency."""
from __future__ import annotations

import struct

import numpy as np

class _LazyPandas:
    """Defer the pandas import: parser worker processes never need it and spawn much faster without it."""

    def __getattr__(self, name):
        import pandas
        globals()['pd'] = pandas
        return getattr(pandas, name)


pd = _LazyPandas()

S_II_LE = struct.Struct('<II')
S_PCAP_REC_LE = struct.Struct('<IIII')
S_PCAP_REC_BE = struct.Struct('>IIII')
S_SOMEIP = struct.Struct('>HHIHHBBBB')
S_SD_ENT = struct.Struct('>B3xHHIxxH')  # type, service, instance, major<<24|ttl, eventgroup
S_U32 = struct.Struct('>I')

CHUNK = 64 << 20
JOB_SIZE = 16 << 20
OVERLAP = 4 << 20       # > largest pcapng block, so a block straddling a job boundary is complete
HOST_TS_RES = 0.005     # host liveness timestamps are kept at 5 ms resolution
S_U32_LE = struct.Struct('<I')
MT_NAMES = {0x00: 'REQUEST', 0x01: 'REQUEST_NO_RETURN', 0x02: 'NOTIFICATION', 0x80: 'RESPONSE', 0x81: 'ERROR'}
VALID_MT = frozenset(MT_NAMES)
# Well-known non-SOME/IP UDP/TCP ports (DNS, DHCP, NTP, PTP, syslog, DLT, DoIP, XCP)
EXCLUDED_PORTS = frozenset({53, 67, 68, 123, 319, 320, 514, 3490, 5353, 13400, 5555})
SD_INFINITE_TTL = 0xFFFFFF
EVENT_COLS = ['time_utc', 't_rel_s', 'severity', 'event', 'service', 'instance', 'method_or_eventgroup',
              'src_ip', 'src_name', 'dst_ip', 'dst_name', 'detail']
