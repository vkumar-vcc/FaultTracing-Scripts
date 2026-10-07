# mrc_decoder bundle — how to run

Decodes a vehicle-Ethernet capture (PCAP/PCAPNG/.zst) into one MF4 with named
signals: MRC CAN/LIN **and** SOME/IP service signals, in a single pass.

## What's in here
    mrc_decoder/        the decoder (C++ engine .so + Python packages)
    rim_ecu_signals/    SOME/IP definitions (service YAMLs + protobuf *_pb2.py)
    SPA2_MRC_routing/   SPA2 MRC routing tables (TC-*.yml)

NOT included: the Python venv, and the SDB DBC/LDF databases (provide them yourself).

## Requirements (Linux / WSL)
- **Python 3.10** — the prebuilt engine is `cp310`. Other versions must rebuild it
  (`cmake -S mrc_decoder -B mrc_decoder/build && cmake --build mrc_decoder/build -j`).
- libpcap runtime:  `sudo apt install libpcap0.8`
- SDB DBC/LDF databases for the capture's project (for the MRC decode).

## One-time setup
    cd mrc_decoder_bundle
    python3.10 -m venv .venv
    .venv/bin/pip install -r mrc_decoder/requirements-frozen.txt
    #   protobuf MUST stay at 3.20.3 (already pinned in that file)

## Run (combined MRC + SOME/IP -> one MF4)
    cd mrc_decoder_bundle
    PYTHONPATH=mrc_decoder/python .venv/bin/python -m spa2_decoder \
      "<capture.pcapng|.zst|dir>" --someip -o out \
      --someip-services-dir rim_ecu_signals/interfaces/services \
      --someip-pb2-dir      rim_ecu_signals/python_bindings/rim_ecu_signals/proto \
      --routing-dir         SPA2_MRC_routing \
      --db-dir   "<SDB_dir>/db" \
      --manifest "<SDB_dir>/manifest.yaml"

Output: `out/<VIN>_COMBINED_<n>logs_<ts>.mf4` (+ a `*_signals.csv` summary).
MRC signal names are `CONNECTOR::Message::Signal`; SOME/IP are `Service::Event::field`.

## Options
    --someip            also decode SOME/IP (omit for MRC only, no rim_ecu_signals needed)
  --pdu               decode SPA3 signal PDUs using bundled SPA3_PDU layouts
  --pdu-config DIR    use a different version of the PDU layout tables
  --no-mrc            skip SPA2 CAN/LIN bus routing (for SPA3 PDU/SOME-IP)
    --routing-table T   force a TC-*.yml instead of auto-selecting
    --per-file          one MF4 per input instead of a merged one
    --keep-all          keep every sample (default drops consecutive unchanged values)
    --csv               also write a long-format CSV

  ## Streamlit UI (WSL)
  From PowerShell, enter the requested distribution:

  ```powershell
  wsl -d UBuntu22
  ```

  Then run in WSL:

  ```bash
  cd /mnt/c/Users/VKUMAR36/workspace/FaultTracing-Scripts/pcap_decoder
  python3.10 -m venv .venv
  .venv/bin/python -m pip install -r requirements-ui.txt
  .venv/bin/python -m streamlit run streamlit_app.py --server.address 127.0.0.1 --server.port 8501
  ```

  Open http://localhost:8501 in your Windows browser. Use the Linux `.venv` here,
  not the Windows environment in the parent workspace. The UI keeps protobuf at
  3.20.3 for compatibility with the bundled SOME/IP bindings.

  Enter capture paths (one per line) or directories and select an SDB version.
  Windows drive paths such as `C:\workspace\logs\capture.pcapng.zst`
  are also accepted and mapped to `/mnt/c/...`. Directory inputs are non-recursive.
  The database and manifest paths are selected automatically and shown read-only
  under **Selected SDB paths**.

  Choose an SDB platform, then use the two columns:
  - **Existing SDB** lists installed versions for immediate selection without an API key.
  - **Download SDB** lists available Artifactory versions and downloads the chosen version.

  - **SPA2** uses `complete/p519` and resolves the POM-linked database artifacts.
  - **SPA3** uses `complete/gpa` and extracts databases from the complete ZIP.

  Enter your Artifactory API key in the password field, or configure
  `ARTIFACTORY_TOKEN` / `ARTIFACTORY_API_KEY` in the WSL server environment or
  Streamlit secrets. Credentials are not written to download files or logs.
  Available versions are loaded through the authenticated Artifactory storage API;
  **Refresh versions** reloads the list. Download choices do not change the active
  SDB until downloading succeeds.
  **Download SDB** downloads into `~/.cache/mrc_decoder/sdb/<project>_<version>/`
  and automatically selects its `db` directory and `manifest.yaml`. Selecting an
  already-cached version also updates both paths. Failed downloads do not switch
  the active SDB.

  Options include merged/per-capture MF4, SOME/IP, routing table, sample retention,
  CSV, and a packet limit. Each run writes to a unique `decode_<timestamp>_<id>`
  subdirectory beneath the chosen output directory, including `decode.log`.
  The UI displays live logs, cancellation, output paths, and up to 5,000 rows of
  the signal-summary CSV. Large capture and output files stay on disk.
  Jobs continue if the browser disconnects; reopen the output folder to find their
  logs and results. Cancellation is available in the browser session that started
  the job. Cancel active decoding before closing the UI server.

  Compressed input requires the `zstd` executable, and decoding requires the
  native engine and libpcap described above. If missing, install system packages
  yourself with `sudo apt install zstd libpcap0.8`.

  Focused UI tests:

  ```bash
  .venv/bin/python -m unittest discover -s mrc_decoder/tests -p test_streamlit_ui.py -v
  ```

## SPA3 PDU decoding
Rebuild the native module after updating the sources:

```bash
cmake --build mrc_decoder/build --target mrc_engine -j2
```

Decode SPA3 PDU and SOME/IP signals into one MF4:

```bash
PYTHONPATH=mrc_decoder/python .venv/bin/python -m spa2_decoder \
  "<capture.pcapng|.zst|dir>" --pdu --no-mrc --someip -o out \
  --someip-services-dir rim_ecu_signals/interfaces/services \
  --someip-pb2-dir rim_ecu_signals/python_bindings/rim_ecu_signals/proto
```

In Streamlit, selecting **SPA3** defaults to **Include SPA3 PDUs** enabled and
**Include MRC CAN/LIN** disabled. SPA2 retains its MRC defaults. Decoder modes
can also be changed independently. PDU-only decoding needs neither SPA2 routing
tables nor DBC/LDF databases; the selected SDB is used when MRC is enabled.

PDU signals are named `PDU::PduName::SignalName`. The native reader unwraps
multiple Vector ASAM CMP Ethernet messages per captured packet, filters configured
UDP destination ports, and reads repeated big-endian ID/length/payload records.
Exact repeated packets within 100 microseconds are suppressed per UDP flow.
Signal decoding applies sequential bit layouts, endianness, signedness, scaling,
and padding from the configuration. Non-padding fields wider than 64 bits are
not emitted, matching the reference numeric decoder.

The four files in `SPA3_PDU` are a snapshot of the generated configuration from
the reference nuc-logger repository. They are **not automatically selected or
updated by downloading a GPA SDB**. Use `--pdu-config` or the UI's PDU configuration
directory to supply matching version-specific tables. Unknown transport IDs and
malformed/short payloads are counted in the PDU statistics, not decoded by guesswork.

### Generating PDU config from an SDB

The four files are generated from two GPA SDB sources — the **SystemExtract ARXML**
and the **Ethernet Backbone CSV** — both inside the GPA complete ZIP. In Streamlit
(SPA3 platform), enter your Artifactory key, pick a version, and use
**Generate PDU config**; it downloads the sources, writes the four files to
`~/.cache/mrc_decoder/sdb/gpa_<version>/pdu/`, and points the PDU configuration
directory there. From the CLI, if you already have the two sources extracted:

```bash
PYTHONPATH=mrc_decoder/python .venv/bin/python -m spa2_decoder.pdu_generate \
  --arxml "<...SystemExtract....arxml>" \
  --csv   "<...GPAEthernetBackbone....csv>" \
  -o SPA3_PDU_<version>
```

Signal layouts, scaling, and endianness come from the ARXML `I-SIGNAL` /
`COMPU-METHOD` / `SW-BASE-TYPE` definitions and the backbone CSV's PDU ID order
(mirroring the reference extractor). The `decode_as_entries` UDP ports are derived
from the ARXML socket model (`SOCKET-ADDRESS` UDP port linked to each signal PDU via
`SO-CON-I-PDU-IDENTIFIER` / `PDU-TRIGGERING`). Port derivation is covered by
synthetic-fixture tests; validate a freshly generated config against a known capture
before relying on it, since socket schemas can vary between SDB versions.

Embedded message hardware-time differences are aligned to the outer capture
timestamp. This offline alignment does not reproduce the live logger's adaptive
device clock drift calibration. The original compressed inputs remain untouched.

Run PDU and UI regression tests in WSL:

```bash
.venv/bin/python -m unittest discover -s mrc_decoder/tests -v
```

## Notes
- `.zst` inputs are decompressed once and fed to the single pass.
- Getting the SDB: `mrc_decoder/python/sdb_fetcher` can fetch it (needs an
  Artifactory token), or copy an existing `~/.cache/mrc_decoder/sdb/<project>/`.
