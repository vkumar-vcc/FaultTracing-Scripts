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

## Combined Streamlit app

The Streamlit app combines SAT translation and standby analysis in one
workflow. Enter a VIN and select **Load readouts** (the default readout source),
or switch the source to upload/provide a readout path. Choose the matching SDDB
with the server file browser (or upload one); the browser starts in
`~/Downloads/sddb` when it exists, or in the folder given by the `SAT_SDDB_DIR`
environment variable. Then start the analysis:

```powershell
uv run streamlit run decoder\decoder.py
```

The first translation with a given SDDB indexes every ECU, DID, and DTC in it
once (about 25 s for a 260 MB file). The index is cached in memory and on disk
(`%LOCALAPPDATA%\FaultTracing-Scripts\sddb-index`, newest six kept), so later
translations, including after restarting the app, take about 2 s. The cache is
keyed by the SDDB file's path, size, and modified time, and by the decoder
version, so it refreshes automatically when either changes. Translations and
standby summaries of an identical readout are also cached for the session.

The translated-readout view uses a structured, virtualized ECU-to-readout tree
for browsing and multi-selecting decoded blocks, with ECU filtering and a
terminal-style output pane. Use the ▸/▾ button on an ECU row (or Expand all /
Collapse all) to show or hide its readouts, and the Show checkbox on an ECU or
readout row to include it in the output; Select all and Clear apply to the
filtered readouts. Use Lookup to filter readouts by ECU, service, DID, or
description; use Search/Filter for decoded content. It uses the full-width
Streamlit layout. The **Readout summary** tab opens with an **Interpretation**
section: rule-based findings (issue, warning, info, ok) that explain what the
readout means for HPA, HIA, HIB and LPA, such as failed standby transitions,
the reasons HIA restarted HP, FSI errors, application watchdog failures, and the
LPA shutdown and wake-up history, plus a merged timeline of recorded events. The
HIA and HIB reset logs (`22 FE 04`) are decoded like the Safety-B ResetLog parser
sheet (`decoder/reset_log.py`): reset common data, reset history and the
application context (stack trace, error hook, SMU, PMIC, ...). The
rules and the platform model behind them are documented in the
[decoder-summary-interpretation skill](.github/skills/decoder-summary-interpretation/SKILL.md),
which also explains how to add a rule. Below it, the standby decoder's
results appear as collapsed sections that open on click into word-wrapped tables:
standby events, FE03 error slots and reference details, platform state
transitions, ECU DTC snapshots, and watchdog information. The translated
output is available to download as text, and the whole readout summary
(every finding with its tables, the timeline, all recorded-data tables, notes
and the raw summary output) as a Markdown report (`decoder/summary_report.py`);
the raw summary output is also available in an expander for troubleshooting.

The **SW versions** tab lists the software part numbers of HIA, HIB, HPA, SGA,
VESA and VESB. Each ECU has a collapsed section with its software modules
(module and part number with edition, for example `32489651 ACP`) and its other
identification values: diagnostic database, integrated diagnostic database,
software structure, calibration identifications and software fingerprint.
Values that repeat another one are left out, such as a calibration ID equal to
a module's part number. Hardware values that every ECU reports identically
(core assembly, delivery assembly, ECU serial number) are shown once at the top.
The values come from each ECU's identification readouts (22 F1 2E, F1 20,
F1 2A, F1 2B, F1 8C and related) and are matched by ECU name; the list of ECUs
is `SW_VERSION_ECUS` in `decoder/sw_versions.py`.

The same tab can look up the **MAIN_INT baselines** of those part numbers in
ConfigHub (button *Look up MAIN_INT baselines*). One ConfigHub matching call per
ECU (run in parallel) returns the baselines that contain the parts. HPA's
platform parts (position HPA, baseline `HPA_MAIN_INT`) and application parts
(position HPAA, baseline `HPAA_EE_MAIN_INT`) are separate rows. ConfigHub
returns its three best matches, so only the newest versions that contain every
part are listed. Only `*_MAIN_INT` baselines are
used, and certificate modules and `00000000` placeholder parts are ignored. A
*Download* column links each part's software file (`.vbf`, from Artifactory) and
opens it in a new tab, where the browser signs in to Artifactory. The
lookup signs in with the login saved by `confighub_lookup.py` (OS keychain), the
`CONFIGHUB_TOKEN` environment variable, or a username and password entered in
the tab (optionally saved to the keychain). It needs access to ConfigHub (VPN),
takes about 6 s for the six ECUs and is cached for an hour afterwards.
The logic is in `decoder/baselines.py`. The existing standalone decoder tools
remain available.

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

The FE03 error-slot table automatically uses the bundled
[SQLite error reference](standby-decoder/error_reference.sqlite3). The database
is indexed by **Reporter ID + Error Code**, so Python reads only matching rows
using the standard-library `sqlite3` module, without loading the full workbook
or requiring Excel dependencies. Its path is relative to the decoder script,
not the working directory.

FE03 output fits the console width (or `COLUMNS`, default 160 when piped). An
**FE03 error slots** table lists one line per slot with the original fields and
the matched Error Name. A second **FE03 error reference details** table, keyed by
Slot, shows Description, Error Level, Expected SOC_ERROR, HI/HP actions, and the
source reference. Long values wrap inside their column without truncation.
Other output tables are unchanged.

The slot details add Error Name, Description, Error Level, Expected SOC_ERROR,
HI Action, HP Action, and Reference columns. HP Action comes directly from the
workbook's `HP` column. Description uses the workbook's `Description`; where
absent, it uses the safety mechanism name with a `Safety mechanism:` prefix,
or `N/A` if neither is available. No descriptions or actions are invented.
Only these lookup fields, identifier pairs, and source locations are bundled;
contacts and reviewer information are excluded.

To rebuild the indexed database from an updated converted workbook JSON:

```powershell
python standby-decoder\error_reference.py "$HOME\Downloads\NVIDIA_DRIVE_OS_Error_ID_Reference_QNX.json"
```

Rebuilding verifies every stored field against the source and checks SQLite
integrity before atomically replacing the existing database. It retains
duplicate matches instead of choosing an arbitrary interpretation.

To override the bundled reference, supply either another SQLite database or
the original workbook JSON:

```powershell
.\run.ps1 standby --input-file path\to\hp_coldboot.log --error-reference "$HOME\Downloads\NVIDIA_DRIVE_OS_Error_ID_Reference_QNX.json"
```

The source JSON must be keyed by worksheet name, with each worksheet containing a
`rows` array of objects (as produced by the workbook conversion). Optional
`row_numbers` arrays preserve Excel row numbers in source references.
Both named headers and column-letter sheets with embedded headers are supported.
Hexadecimal IDs accept a `0x` prefix, bare hex, or space-separated bytes;
JSON integer IDs are treated numerically. Original FE03 values and standby
correlation are unchanged.

Unknown pairs show `Not found` / `No exact match`; missing reference fields show
`N/A`. When several entries share a Reporter ID + Error Code (for example 23
NvTime errors under `0x8134` / `0x200`), the FE03 **Error Attribute** is matched
against the workbook **Meta Data** column (`0x`-prefixed values are hex, plain
numbers decimal) to select the exact error. If no Meta Data value matches, all
entries remain on the same slot row, with numbered
alternatives linked to their source worksheet and row. Matching is exact:
placeholder IDs, wildcard templates, and partial-bit error codes are not
inferred. Reference actions describe the workbook, not an observed vehicle
response or a diagnosis. Missing or malformed reference files fail explicitly.
Use `--no-error-reference` for only the original FE03 slot table. The full internal
workbook JSON is not bundled with the decoder.

When the log includes Platform State Transition History (`1D12 22D991`), the
decoder also prints an ID, state, and UTC timestamp table. It anchors the history's
`Now` (state 255) counter to the UTC value from Vehicle Time (`1D12 22DD0E`):
`entry UTC = vehicle UTC + (entry counter - Now counter)` in milliseconds.
The `Time taken (HH:MM:SS.mmm)` column shows elapsed time since the previous
history entry, including for `Now`; the first entry shows `N/A`. Hours can
exceed 24 for longer intervals.
The table ends at the `Now` entry (inclusive); subsequent history rows are hidden.
Both raw `Complete Response` payloads and decoded log fields are supported.
Vehicle Time and exactly one `Now` entry are required when history is present;
logs without history retain the existing output. Milliseconds preserve relative
timing, while absolute accuracy depends on the Vehicle Time reference and the
delay between the two requests.

When Application Watchdog App Failure Timeline (`1D12 22D99D`) is present,
the decoder prints one summary row per application: failure count, first and
latest non-1970 timestamps, and number of 1970 timestamps. Rows are sorted by
failure count (descending), then application name. Counts include duplicates.
Use `--watchdog-details` to also print the full ID/application/timestamp timeline.
Raw version-1 responses and decoded timeline fields are supported; duplicate
entries and original order are preserved. The timestamps have no stated timezone
and are not converted using the platform counter. Entries dated 1970 are retained
with a warning that their clock may be unset.
Data Health 3 (`No data available`) prints an explicit unavailable status and
does not prevent the other tables from being displayed. It is not interpreted
as zero watchdog failures; other nonzero health values remain errors.

When an HIA (`1D0D`), HIB (`1D0E`), or HPA (`1D12`) DTC list (`19 03`) and
DTC snapshot reads (`19 04`) are present, the decoder prints one table per ECU
with one row per unique DTC, its description, latest decoded Global Real Time,
converted UTC time, and latest matching event. The UTC conversion uses the
Vehicle Time (`1D12 22DD0E`) Global Real Time and UTC fields as its anchor. DTC
snapshot times are in minutes; a timestamp without the Vehicle Time anchor is
reported as an error rather than guessed.

## CAN decoder

The CAN decoder is maintained in the `can_decoder` submodule. It decodes BLF
or ASC logs with DBC databases into Parquet and provides an interactive
Streamlit signal viewer. See the [can_decoder README](can_decoder/README.md)
for setup and usage instructions.

## UART verifier

The UART Verifier is a Tkinter desktop tool for discovering USB/UART COM ports,
identifying attached nodes, logging serial traffic, and opening per-port
consoles. It is maintained in `verify_uart`.

Install its dependency and run it from the repository root:

```powershell
pip install pyserial
python verify_uart\verify_uart_V2.py
```

For scan, logging, console, and executable packaging instructions, see the
[verify_uart README](verify_uart/README.md). Windows builds can be created with
`verify_uart\build_windows.ps1`.
