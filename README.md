# FaultTracing-Scripts
Useful scripts for analyzing, downloading, and visualizing logs.

## Setup with uv

The setup scripts install `uv`, initialize all Git submodules, create a shared
`.venv`, and install the Python dependencies used by the decoders.

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
