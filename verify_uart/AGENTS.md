# AGENTS.md

Tkinter tool for verifying USB/UART COM ports, identifying the attached node,
logging traffic with timestamps, and talking to ports from per-port consoles.

## Layout

| File | Purpose |
| --- | --- |
| `verify_uart_V2.py` | the entire application — GUI, scanning, logging, consoles |
| `build_windows.ps1` | PyInstaller packager (isolated build venv, one-dir by default) |
| `UARTVerifier.spec` / `verify_uart_V2.spec` | legacy PyInstaller specs, superseded by the packager |

Single-file app by design. Keep it that way unless it grows past ~1000 lines.

## Commands

```powershell
python verify_uart_V2.py          # run
.\build_windows.ps1               # one-dir build -> dist\UARTVerifier\
.\build_windows.ps1 -OneFile -Zip # single exe + archive
.\build_windows.ps1 -Clean        # drop build\, dist\, .buildvenv\
```

Only dependency is `pyserial`; Tkinter ships with Python on Windows.

## Architecture

- `UARTVerifierApp(tk.Tk)` owns four dicts keyed by port name:
  `loggers` (PortLogger), `consoles` (ConsoleView), `nodes` (LPA/SGA/HIA/...),
  `rows` (Treeview row ids). Keep them in sync when adding features.
- `PortLogger` is a thread per port. It owns the open `serial.Serial`, writes
  timestamped lines to file, and exposes `send()` so consoles can reuse the
  connection.
- `ConsoleView(ttk.Frame)` is built to live either as a notebook tab or inside a
  `Toplevel`. Detach/attach works by dumping the text, destroying the view, and
  rebuilding — tkinter cannot reparent widgets.

## Conventions

- **A COM port can only be opened once.** Before opening a port, check
  `self.loggers` — if a logger owns it, route through `logger.send()` instead.
- All serial I/O happens off the main thread. Push results back with
  `self.after(0, callback, ...)`; never touch widgets from a worker.
- Node detection lives in `NODE_KEYS` / `determine_port_type()`. `HPA` matches
  `"#"`, so it must stay last or it will shadow every other key.
- The checkbox column is text (`☑`/`☐`) in column `#1`, not a real widget. Row
  selection and checkbox state are independent; logging acts on *checked* ports.
- Scanning is async: `refresh()` paints rows as `Scanning...`, a thread pool
  probes ports, and `_apply_scan_result` updates each row via `as_completed`.
  Never make the first scan block window creation.

## Gotchas

- PyInstaller rejects `.png` icons on Windows; `icon=['icon.png']` in the old
  specs is a no-op. Supply `icon.ico` for the packager to pick it up.
- One-file builds unpack to `%TEMP%` on every launch and start seconds slower —
  prefer one-dir.
- `get_first_response()` has a 0.6 s budget and exits early after 0.15 s of
  silence. Lowering these is the main knob for scan speed.
- `uart_logs/` and `*.log` are gitignored; do not commit captures.
