# FaultTracing-Scripts
Useful scripts for analyzing, downloading, and visualizing logs.

Initialize both decoder submodules after cloning:

```powershell
git submodule update --init --recursive
```

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
