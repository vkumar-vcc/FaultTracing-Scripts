"""SPA2 MRC offline decoder: PCAP (CAN/LIN tunneled over UDP) -> named signals.

The vehicle's VIUs tunnel CAN and LIN frames over UDP. Each bus has a UDP port
(``viu_port``) and address (``viu_address``). A routing table (TC-*.yml) maps each
bus to its network/messages; matching against the fetched DBC/LDF databases yields
a ``bus -> database`` assignment. Decoding then is: UDP (src_ip, src_port) -> bus ->
database -> decode the MRC frame by frame_id into physical signals.
"""

import warnings as _warnings

# WSL emulates numpy.longdouble; its import-time probe emits a benign UserWarning.
_warnings.filterwarnings(
    "ignore",
    message=r"Signature .* for <class 'numpy\.longdouble'>",
    category=UserWarning,
)

from .dbmatch import assign_databases, load_db_metadata
from .routing import Bus, parse_routing_table

__all__ = ["Bus", "parse_routing_table", "assign_databases", "load_db_metadata"]
