# FaultTracing-Scripts
Useful scripts for analyzing, downloading, and visualizing logs.

## Setup with uv

The setup scripts install `uv`, initialize all Git submodules, create the root
`.venv`, and sync the Python dependencies from `pyproject.toml`. They also sync
the CAN decoder's separate environment from `can_decoder/pyproject.toml`.

On Windows PowerShell:

```powershell
.\setup_uv.ps1
.\.venv\Scripts\Activate.ps1
```

On Ubuntu or another Linux shell:

```bash
chmod +x setup_uv.sh
./setup_uv.sh
source .venv/bin/activate
```

Ubuntu users may also need the system Tkinter package for the graphical tools:

```bash
sudo apt-get install python3-tk
```

Initialize both decoder submodules after cloning:

```powershell
git submodule update --init --recursive
```

## Run tools

The root runners dispatch arguments to each tool from one consistent command.
Use `run.ps1` on Windows PowerShell or `run.sh` on Linux/macOS:

```powershell
.\run.ps1 <tool> [arguments]
```

```bash
./run.sh <tool> [arguments]
```

Available tools are `confighub`, `can`, `nuc`, `sat`, and `standby`. Use the
tool's normal arguments after its name:

```powershell
.\run.ps1 confighub 32456876AH
.\run.ps1 can log.blf --map can_decoder\channels.txt
.\run.ps1 nuc --help
.\run.ps1 standby --input-file hp_coldboot.log
```

To see the dispatcher help, run `.run.ps1 --help` or `./run.sh --help`.
To see the dispatcher help, run `.\run.ps1 --help` or `./run.sh --help`.

Add or update Python dependencies from the repository root with `uv`:

```powershell
uv add requests
uv sync
```

## ConfigHub lookup

Use `confighub_lookup.py` to look up ConfigHub software or hardware part
metadata, software version history, connected baselines, and parent baseline
trees.

Run a single part lookup from the repository root:

```powershell
uv run python confighub_lookup.py 32456876AH
```

By default, the script prompts for your ConfigHub username and password on the
first successful login, then stores them in your OS keyring for later runs. To
forget saved credentials and prompt again, use `--reset-credentials`:

```powershell
uv run python confighub_lookup.py 32456876AH --reset-credentials
```

To use an existing bearer token instead, set `CONFIGHUB_TOKEN` before running
the script:

```powershell
$env:CONFIGHUB_TOKEN = "<token>"
uv run python confighub_lookup.py 32456876AH
```

Look up multiple labeled part numbers and print a summary table:

```powershell
uv run python confighub_lookup.py --parts "SWLM:80 07 35 12 AAF" "SWL2:80 06 79 86 AK"
```

Scan a log file for labeled part numbers and look them up in table mode:

```powershell
uv run python confighub_lookup.py --log-file path\to\log.txt
```

To summarize a specific parent baseline tree, pass its baseline handle:

```powershell
uv run python confighub_lookup.py 32456876AH --baseline-id <handle>
```

The default single-part output is a compact summary. Add `--details` when you
need the raw part fields and the full parent baseline tree:

```powershell
uv run python confighub_lookup.py 32456876AH --details
```

## NUC DLT downloader

The NUC DLT downloader is maintained in the `download_combine_NUC_dlt`
submodule. Its setup, Azure authentication, CLI options, batch modes, and
output layout are documented in [download_combine_NUC_dlt/README.md](download_combine_NUC_dlt/README.md).

## SAT readout decoder

The SAT readout decoder is maintained in the `SAT_Readout_decoder` submodule.
Instructions are in [SAT_Readout_decoder/README.md](SAT_Readout_decoder/README.md).

## Standby decoder

The standby decoder is maintained in the `standby-decoder` submodule. From the
repository root, run it with the default `hp_coldboot.log` input:

```powershell
python standby-decoder\hpa_stanby_decoder.py
```

To decode a different log, pass its path with `--input-file`:

```powershell
python standby-decoder\hpa_stanby_decoder.py --input-file path\to\hp_coldboot.log
```

## CAN decoder

The CAN decoder is maintained in the `can_decoder` submodule. It decodes BLF
or ASC logs with DBC databases into Parquet and provides an interactive
Streamlit signal viewer. See the [can_decoder README](can_decoder/README.md)
for setup and usage instructions.
