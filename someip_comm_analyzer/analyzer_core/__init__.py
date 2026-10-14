"""Modular core for SOME/IP capture analysis."""

from .cli import build_parser, main
from .profiles import DEFAULT_PROFILE, PROFILE_FILES, Names, matching_ecu_names
from .reports import analyze, summary_markdown, write_outputs, _utc

__all__ = [
    "DEFAULT_PROFILE", "PROFILE_FILES", "Names", "analyze", "build_parser",
    "main", "matching_ecu_names", "summary_markdown", "write_outputs", "_utc",
]
