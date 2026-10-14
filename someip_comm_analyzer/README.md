# SOME/IP Communication Analyzer

A standalone analyzer for SOME/IP and SOME/IP-SD traffic in automotive Ethernet captures. It reads pcapng/pcap directly without importing `pcap_decoder` or invoking tshark. Its dependencies are managed as a member of the root uv workspace and share the root `uv.lock`.

## Requirements

- Windows PowerShell
- [uv](https://docs.astral.sh/uv/)
- Python 3.10 or newer (uv creates the local environment)
- Bundled SPA2 or SPA3 profile data is used for ECU name resolution

The analyzer always uses bundled JSON data and never reads Wireshark profile folders. SPA3 is selected by default; choose SPA2 or SPA3 in the app, or pass `--profile SPA2` / `--profile SPA3` to the CLI. The bundles contain the profiles' `hosts` and `subnets` entries, so Wireshark is not required.

## Run the app

From this folder:

```powershell
.\run.ps1
```

Open the local URL printed by Streamlit (default port `8530`). To select another port:

```powershell
.\run.ps1 -Port 8531
```

In the sidebar, either enter a path accessible to this computer or upload one `.pcapng`, `.pcap`, `.zst`, or `.gz` capture, then press **Analyse**. The uploader allows up to 4 GB. If using a remote deployment, its web server or reverse proxy may impose a lower limit.

The app uses a high-contrast dashboard theme with light and dark palettes. Switch between them from the app's **Settings** menu in the top-right corner. Capture overview cards lead into separate views for summary, ECU liveness, outages, events, service health, and SOME/IP streams. The Events tab shows the capture's error count in its label and lists errors by default. Use the multi-select ECU filter to filter views by one or more ECUs. To select all ECUs on a VLAN, enter its number (for example, `156`) in **Find ECUs by name or VLAN**, then click **Select all matches**. Tables support per-column filters. The Summary tab and sidebar Export section can download a Markdown report and CSVs.

## Run the CLI

From this folder:

```powershell
.\run.ps1 -Cli "C:\logs\capture.pcapng.zst"
```

To choose an output folder and restrict analysis to a service ID:

```powershell
.\run.ps1 -Cli "C:\logs\capture.pcapng.zst" --outdir "C:\logs\report" --service 0x00ae
```

Select the SPA2 name mapping with `--profile SPA2`; the default is `--profile SPA3`.

The CLI writes a `<capture>_someip_report` folder next to the capture unless `--outdir` is provided. Outputs include:

- `summary.md`: capture overview and key findings
- `events.csv`: timestamped detections
- `outages.csv`: stop-to-resume intervals, including unresolved intervals
- `hosts.csv`: address liveness and first/last transmit details
- `conversations.csv`: VLAN, IPs, ports, protocol, times, frame/byte counts and SOME/IP counts
- `services.csv`: service offers, subscriptions and request/response health
- `streams.csv`: per-message counts, periodicity and detected gaps

Thresholds can be adjusted with `--help`, for example `--req-timeout`, `--sd-timeout`, `--host-gap`, `--grace`, and `--gap-factor`. The app exposes the main thresholds in the sidebar.

## Detection notes

- SOME/IP-SD offers are considered active while refreshed within their advertised TTL. Stop-offer, TTL expiry, FindService without an offer, Subscribe without Ack/Nack, and related state changes are reported.
- SOME/IP requests without a matching response are grouped into outages using the configured request timeout.
- Periodic message streams and host transmit activity are checked for abnormal gaps; gaps are heuristics, not proof that an ECU is faulty.
- A host is only considered silent if the capture observes it being addressed but sees no transmitted IP frames. `Never seen` means its profile address did not appear in the capture.
- Capture start/end boundaries can make an already-running service appear to start late or a final transmission appear to stop early. Use the grace setting and inspect the event timeline before drawing conclusions.
- SOME/IP service ID `0x0000` is excluded because AUTOSAR SoAd PDU-header traffic can resemble SOME/IP at the start of a payload.
- The parser handles little-endian pcapng with Ethernet link type, classic pcap Ethernet, optional VLAN tags, IPv4 UDP/TCP, and Vector ASAM CMP-wrapped Ethernet frames. It does not currently reassemble IPv4 fragments or TCP streams; SOME/IP over TCP must be present as complete messages in individual captured payloads.

## Project files

- `someip_comm_analyzer.py`: backwards-compatible CLI entry point
- `analyzer_core/capture.py`: `CaptureReader` and pcap/pcapng/CMP decoding
- `analyzer_core/engine.py`: stateful SOME/IP `Analyzer`
- `analyzer_core/profiles.py`: bundled profile loading and `Names` resolution
- `analyzer_core/reports.py`: analysis dataframes and report generation
- `analyzer_core/cli.py`: command-line argument parsing and orchestration
- `analyzer_core/common.py`: shared binary structures and constants
- `spa3_profile.json`: bundled SPA3 ECU names and subnet mappings
- `spa2_profile.json`: bundled SPA2 ECU names and subnet mappings
- `streamlit_app.py`: Streamlit interface
- `pyproject.toml`: analyzer dependencies; the root `uv.lock` pins the shared workspace
- `run.ps1`: local CLI and app launcher
- `.streamlit/config.toml`: upload limits for the local app
