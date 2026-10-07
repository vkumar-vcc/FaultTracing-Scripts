# mrc_decoder

Offline decoder that turns captured vehicle-Ethernet **PCAP/PCAPNG** files into
**MDF (MF4)** signal files with named signals.

The primary path is the **SPA2 MRC decoder** (`python/spa2_decoder`): CAN and LIN frames
tunnelled over UDP by the VIUs are routed to their DBC/LDF databases (via the SPA2 routing
tables) and decoded into physical signals. The heavy packet work (PCAP read, Ethernet/VLAN/
IP/UDP dissection, MRC framing, endpoint routing) runs in a C++ module; the DBC/LDF signal
decode uses `cantools` + `ldfparser`.

A separate C++ engine path also exists for SPA3 ETH PDU-transport captures (Wireshark
Signal-PDU tables) and ARXML — see `cpp/` and the CLI `mrc_decoder`.

A third path, the **SOME/IP decoder** (`python/someip_decoder`), decodes the SOME/IP service
traffic (protobuf payloads over TCP) on the same captures into named signals using the
`rim_ecu_signals` definitions — see [Decode SOME/IP](#decode-someip-pythonsomeip_decoder).

## How the SPA2 decode works

```
PCAP (CAN/LIN over UDP)
  → C++ mrc_engine: parse Eth/VLAN/IP/UDP, MRC 12-byte header, route by (ip,port)
  → routing table (TC-*.yml) maps each VIU bus → DBC/LDF database
  → Python: cantools (DBC) / ldfparser (LDF) decode frame_id → physical signals
  → reduce unchanged samples + per-message FrameUpdated cadence channel
  → one merged MF4 (CONNECTOR::Message::Signal names)
```

Key details:
- **Bus endpoints are matched on source *and* destination** `(ip, port)`: VIU→VCU "direct"
  frames (endpoint = source) and VCU→VIU "data-provider/exposed" frames (endpoint =
  destination) are both decoded.
- **Routing table** is auto-selected from the capture's traffic, or forced with
  `--routing-table`.
- **Databases** come from a fetched SPA2 SDB (`sdb_fetcher`, project `p519`).

## Build the C++ module

The SPA2 decoder needs the `mrc_engine` pybind11 module (fast pcap/MRC extraction). Build on
Linux/WSL with libpcap:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j          # produces build/mrc_engine*.so and the CLI build/mrc_decoder
```

Dependencies: C++17 compiler, **libpcap** (`apt install libpcap-dev`), **pybind11**,
optionally **mdflib** (CLI MF4 output) and **pugixml** (fetched automatically).

> On WSL `/mnt/c`, incremental builds can miss edited sources due to clock skew — if a change
> doesn't take effect, delete the stale objects first:
> `find build -name "<file>*.o" -delete && cmake --build build -j`.

## Python environment

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install cantools ldfparser asammdf dpkt pyyaml numpy
```

## Fetch the SPA2 databases (DBC/LDF)

```bash
# token via env (never on the command line); default project is spa2 (p519)
ARTIFACTORY_TOKEN=... python -m sdb_fetcher <version>          # e.g. 2026.26.1
# → ~/.cache/mrc_decoder/sdb/p519_<version>/db/ + manifest.yaml
```

`--project spa3` fetches the GPA DBC/LDF instead.

## Decode (SPA2)

Run from `python/` with the venv active:

```bash
# a whole directory of captures → ONE merged MF4 (default)
python -m spa2_decoder <dir_of_pcapng> -o <out_dir>

# specific files
python -m spa2_decoder capture1.pcapng capture2.pcapng -o out
```

Inputs are decoded in chronological order (timestamped filenames) and merged into a single
`{VIN}_COMBINED_{n}logs_{firstts}.mf4` plus a `*_signals.csv` summary. Databases are loaded
once for the whole batch.

### Options

| Option | Default | Meaning |
|--------|---------|---------|
| `-o, --out-dir` | `out` | output directory |
| `--routing-table` | auto | force a `TC-*_routing_table.yml` (name or path) |
| `--db-dir` | `~/.cache/mrc_decoder/sdb/p519_2026.26.1/db` | fetched DBC/LDF directory |
| `--manifest` | matching `manifest.yaml` | SDB manifest listing valid db files |
| `--routing-dir` | SPA2_MRC/routing | folder of `TC-*_routing_table.yml` |
| `--per-file` | off | write one MF4 per input instead of a merged file |
| `--keep-all` | off | keep every sample (default drops consecutive unchanged values) |
| `--max-packets N` | all | cap datagrams (quick slice) |
| `--csv` | off | also write a long-format `signal,timestamp,value` CSV (large) |

### Output size & update timing

- Signal value channels are **reduced** (a sample only at each change, plus the sample before
  it) — losslessly reconstructable step signals.
- Every message additionally gets a `CONNECTOR::Message::FrameUpdated` channel: a monotonic
  counter sampled at **every** frame arrival, so exact update timing is preserved (lossless
  for CAN/LIN, where a frame refreshes all its signals at once) without storing every sample.
- MF4 is written with transposed-deflate compression. Typical: a 10-minute session ≈ tens of
  MB; storing every sample instead would be ~5× larger for no extra information.

## Decode SOME/IP (`python/someip_decoder`)

A second decoder turns the **SOME/IP** service traffic on the same vehicle-Ethernet captures
into named signals. SOME/IP here runs **over TCP** on the Connex reliable ports
(31000–31699); `tshark` reassembles the TCP streams and splits each PDU into individual
SOME/IP messages.

```
PCAP/.zst (SOME/IP over TCP)
  → tshark: TCP reassembly, one (ts, service_id, method_id, msgtype, payload) per message
  → (service_id, message_id, msgtype) → protobuf message, via rim_ecu_signals definitions
  → protobuf decode (generated *_pb2 modules) → flattened numeric signals
  → reduce unchanged samples + per-event FrameUpdated cadence channel
  → one merged MF4 (Service::Event::field.path names)
```

The service/event → protobuf mapping comes from the **rim_ecu_signals** repo
(`super/interfaces/rim_ecu_signals`): `vsomeip_services.yml` (all platforms) maps
`service_id → service`, each `*_service.yml` maps an event/method `id` to a protobuf message
via its `payload.notification` / `payload.request` / `payload.response` reference, and the
generated `python_bindings/.../ *_pb2.py` modules deserialize the payload. Nested messages,
repeated fields and enums are flattened by walking the protobuf descriptor.

```bash
# run from python/ with the venv active (needs protobuf 3.20.x + tshark)
pip install "protobuf==3.20.3"
python -m someip_decoder <capture.pcapng|.zst|dir> -o <out_dir>
```

Output is a merged `{VIN}_SOMEIP_{n}logs.mf4` plus a `*_signals.csv` summary. Options mirror
the SPA2 CLI: `--csv`, `--keep-all`, `--per-file`, `--no-frame-updated`, and
`--services-dir/--proto-dir/--pb2-dir` to point at a different rim_ecu_signals checkout.

### MRC + SOME/IP in one go

Pass `--someip` to the **SPA2 decoder** to decode the MRC CAN/LIN signals *and* the SOME/IP
service signals from the same capture(s) and merge everything into one MF4:

```bash
python -m spa2_decoder <capture.pcapng|.zst|dir> --someip -o <out_dir>
```

This is a **single pass over the pcap**: the C++ engine's `extract_all` classifies each packet
— UDP → MRC frame, TCP (ports 31000–31699) → SOME/IP (TCP reassembly + length-based framing) —
and returns both result sets, so the capture is read only once (the former separate tshark pass
is gone). The in-engine reassembler also recovers large multi-segment SOME/IP messages that
tshark's default desegmentation drops.

The MRC names (`CONNECTOR::Message::Signal`) and SOME/IP names (`Service::Event::field`) share
no key space, so they coexist in a single `{VIN}_COMBINED_{n}logs_{ts}.mf4`. `.zst` inputs are
decompressed once and fed to the single pass. SOME/IP paths can be overridden with
`--someip-services-dir/--someip-proto-dir/--someip-pb2-dir`.

> The standalone `python -m someip_decoder` path uses tshark instead (no MRC engine context);
> the combined `--someip` path above uses the faster single-pass C++ reassembler.

> Services whose rim_ecu_signals definition has no deterministic event→message mapping
> (no `payload.notification` and event name ≠ proto message, or no `payload_proto`) are
> skipped rather than guessed — fix those definitions upstream to decode them.

## Layout

```
mrc_decoder/
├── CMakeLists.txt              C++ engine + pybind11 module build
├── cpp/
│   ├── include/mrc_decoder/    public headers
│   ├── src/                    pcap reader, MRC parser, ARXML/PDU decode model, MDF writer, CLI
│   └── bindings/               pybind11 module `mrc_engine` (extract_frames, extract_all, endpoint_counts, run)
├── python/
│   ├── spa2_decoder/           SPA2 MRC decoder: routing, DBC/LDF match, decode, MF4 writer, CLI
│   ├── someip_decoder/         SOME/IP-over-TCP decoder: rim_ecu_signals mapping, protobuf, CLI
│   ├── sdb_fetcher/            Artifactory SDB fetcher (SPA2 p519 / SPA3 gpa → DBC/LDF)
│   └── mrc_decoder_gui/        Tkinter GUI for the C++ engine path
├── batch_decode.sh             helper: decode a folder per-file with a forced routing table
├── requirements.txt
└── tests/
```

## SPA3 / C++ engine path

For SPA3 ETH PDU-transport captures, the C++ CLI decodes using the pre-generated Wireshark
Signal-PDU tables:

```bash
./build/mrc_decoder --pdu-config <SPA3/PDU_SPA3_dir> -o out <capture.pcapng>
```

`--sdb <arxml_dir>` enables the ARXML decode-model path. `ctest --test-dir build` runs the
C++ unit test.
