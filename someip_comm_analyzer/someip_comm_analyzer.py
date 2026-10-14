#!/usr/bin/env python3
"""SOME/IP communication-pattern analyzer command-line entry point.

The implementation is organized in ``analyzer_core``: capture decoding,
stateful analysis, profile resolution, report generation, and CLI orchestration.
"""
from __future__ import annotations

from analyzer_core import (
    DEFAULT_PROFILE,
    PROFILE_FILES,
    Names,
    _utc,
    analyze,
    build_parser,
    main,
    matching_ecu_names,
    summary_markdown,
    write_outputs,
)

if __name__ == '__main__':
    main()
