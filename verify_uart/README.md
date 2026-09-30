# UART Verifier

A Tkinter desktop tool for discovering USB/UART COM ports, identifying which node is
attached to each one, logging their traffic with timestamps, and talking to them from
per-port consoles.

## Features

- **Port scan** – enumerates USB/UART/Serial COM ports, sends `CR`, and reports the
  banner each port replies with. Scanning runs in parallel and results stream into the
  table as they arrive, so the window is usable immediately.
- **Node detection** – maps the banner to a node name (`LPA`, `SGA`, `HIA`, `HIB`,
  `HIC`, `HPA`, otherwise `Unknown`) and shows it in the **Node** column.
- **Checkbox selection** – ports that responded are ticked automatically; click the
  checkbox cell, press <kbd>Space</kbd>, or click the column header to toggle.
- **Timestamped logging** – one log file per port, written continuously. Choose
  absolute wall-clock or relative (seconds since start) timestamps. Auto-log is on by
  default and starts logging every responding port after each scan.
- **Consoles** – open a console per port (button or double-click a row), send commands
  with a selectable line ending, recall history with <kbd>↑</kbd>/<kbd>↓</kbd>, and send
  an interrupt with <kbd>Ctrl</kbd>+<kbd>C</kbd>. Consoles can be detached into their own
  windows and re-attached.

## Requirements

- Python 3.9+
- [pyserial](https://pypi.org/project/pyserial/)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install pyserial
```

Tkinter ships with the standard Windows Python installer.

## Running

```powershell
python verify_uart_V2.py
```

## Usage

1. The port table fills in as each port is probed. Responding ports are green and ticked.
2. Adjust **Baud**, **Timestamp** mode, and **Log Folder...** as needed.
3. Logging starts automatically for responding ports (**Auto-log responding ports**).
   Untick it to control logging with **Start Logging** / **Stop Logging**.
4. Click **Open Console(s)** — or double-click a row — to send commands to a port.
   Commands are mirrored into that port's log file as `>> command`.

Log files are written to `uart_logs/` as `COM45_HIB_20260930_161022.log`.

## Building an executable

Use the packaging script (creates its own isolated build venv):

```powershell
.\build_windows.ps1            # one-dir build -> dist\UARTVerifier\
.\build_windows.ps1 -OneFile   # single .exe   -> dist\UARTVerifier.exe
# Every build also produces dist\UARTVerifier-<date>.zip.
.\build_windows.ps1 -Console   # keep a console window for debugging
.\build_windows.ps1 -Clean     # remove build\, dist\ and .buildvenv\
```

Place an `icon.ico` next to the script to brand the executable (PyInstaller does not
accept `.png` for Windows icons).

One-dir builds start noticeably faster than one-file, which unpacks to a temp folder on
every launch.

Alternatively, build from the checked-in spec:

```powershell
pip install pyinstaller
pyinstaller UARTVerifier.spec
```

## Notes

- A port can only be opened once. While a port is being logged, the verifier reuses that
  open connection for console commands and skips it during re-scans.
- `build/`, `dist/`, and `uart_logs/` are ignored by git.
