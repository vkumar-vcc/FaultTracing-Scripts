# MEMORY.md

Working notes and backlog for the UART Verifier. Update this when a decision is
made or a feature lands, so the next session starts with context.

## Decisions

- 2026-09-30 — Single-file app (`verify_uart_V2.py`). No package split yet.
- 2026-09-30 — Scanning made asynchronous and parallel (one thread per port,
  `as_completed`) so the window appears before ports are probed.
- 2026-09-30 — Auto-log is **on by default**: responding ports start logging as
  soon as a scan completes.
- 2026-09-30 — Consoles are per port, openable as tabs and detachable into their
  own windows. Ctrl+C sends ETX `0x03` from the entry, copies text in the output.
- 2026-09-30 — Node names come from the banner (`NODE_KEYS`), shown in the Node
  column and used in tab labels and log file names.

## Backlog / ideas

- Expose the probe timeout in the toolbar to trade thoroughness for scan speed.
- Per-port baud rate instead of one global setting.
- Remember window size, log folder, and baud between runs (small JSON config).
- Optional hex view / hex send in the console.
- Log rotation or a size cap for long captures.
- Delete the legacy `.spec` files once the packager is proven in practice.
- `icon.ico` is missing — executables build without a custom icon.

## Known issues

- Re-scanning skips ports that are being logged, so their banner and node are
  whatever the previous scan found.
- No reconnect handling: if a device drops off, its logger ends and the row is
  only updated on the next refresh.
