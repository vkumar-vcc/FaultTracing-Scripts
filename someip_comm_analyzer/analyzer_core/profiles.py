"""Bundled vehicle-profile loading and IP-to-ECU name resolution."""
from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path

from .common import S_U32

# ---------------------------------------------------------------- name resolution
DEFAULT_PROFILE = 'SPA3'
PROFILE_FILES = {
    'SPA2': Path(__file__).resolve().parent.parent / 'spa2_profile.json',
    'SPA3': Path(__file__).resolve().parent.parent / 'spa3_profile.json',
}


def matching_ecu_names(names: list[str], query: str) -> list[str]:
    term = query.strip().casefold()
    return [name for name in names if term and term in name.casefold()]


class Names:
    def __init__(self, profile_file: Path):
        self.hosts: dict[int, str] = {0: 'unconfigured (no IP yet)'}
        self.subnets: list[tuple[int, int, str]] = []
        self.cache: dict[int, str] = {}
        with profile_file.open(encoding='utf-8') as f:
            bundled = json.load(f)
        host_lines = bundled['hosts']
        subnet_lines = bundled['subnets']
        for line in host_lines:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    self.hosts[int(ipaddress.IPv4Address(parts[0]))] = parts[1]
                except ValueError:
                    pass
        nets = []
        for line in subnet_lines:
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                try:
                    net = ipaddress.IPv4Network(parts[0], strict=False)
                except ValueError:
                    continue
                nets.append((net.prefixlen, int(net.network_address), int(net.netmask), parts[1].strip()))
        self.subnets = [(a, m, n) for _, a, m, n in sorted(nets, reverse=True)]

    def __call__(self, ip: int) -> str:
        n = self.cache.get(ip)
        if n is None:
            n = self.hosts.get(ip)
            if n is None:
                n = next((f'{name}.{ip & ~mask & 0xFFFFFFFF}' for net, mask, name in self.subnets
                          if ip & mask == net), '')
            self.cache[ip] = n
        return n


_ip_cache: dict[int, str] = {}


def ip_str(ip: int | None) -> str:
    if ip is None:
        return ''
    s = _ip_cache.get(ip)
    if s is None:
        s = _ip_cache[ip] = socket.inet_ntoa(S_U32.pack(ip))
    return s
