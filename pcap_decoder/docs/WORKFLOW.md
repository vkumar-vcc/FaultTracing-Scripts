# PCAP → MF4 workflow (SPA2 and SPA3)

This decoder splits work between a C++ engine and a Python layer:

- **C++ (`mrc_engine`)** — reads the capture once and does all packet work:
  Ethernet/VLAN/IP/UDP/TCP dissection, Vector ASAM CMP unwrapping, MRC framing,
  SOME/IP TCP reassembly, and SPA3 PDU record framing. It returns compact numpy
  arrays and knows **no** signal names.
- **Python (`spa2_decoder`)** — turns those raw arrays into named, scaled signals
  using the SDB databases (MRC), protobuf definitions (SOME/IP), and the generated
  layout tables (PDU), then reduces unchanged samples and writes the MF4.

The C++ engine is reused unchanged for both platforms; only which decoders run and
which reference data is applied differs.

## High-level flow

```mermaid
flowchart TD
    A([Capture: .pcap / .pcapng / .zst]) --> B{.zst?}
    B -- yes --> C[Decompress once to temp pcap]
    B -- no --> D[Use file as-is]
    C --> E
    D --> E[C++ mrc_engine: single read of the capture]

    E --> F[Dissect Ethernet / VLAN / IP / UDP / TCP<br/>unwrap Vector ASAM CMP messages]
    F --> G{Platform / enabled decoders}

    G -- SPA2 default --> H[MRC CAN/LIN over UDP<br/>+ optional SOME/IP]
    G -- SPA3 default --> I[SPA3 signal PDUs over UDP<br/>+ optional SOME/IP<br/>MRC skipped --no-mrc]

    H --> J[Python signal decode]
    I --> J
    J --> K[Reduce consecutive unchanged samples<br/>unless --keep-all]
    K --> L[asammdf: one channel group per signal]
    L --> M([Output: *_COMBINED_*.mf4 + *_signals.csv])
```

## SPA2 path (MRC CAN/LIN)

```mermaid
flowchart TD
    A[UDP datagrams from C++ engine] --> B[Auto-select TC-*.yml routing table<br/>from endpoint_counts, or forced --routing-table]
    B --> C[Match VIU bus endpoints -> DBC/LDF databases<br/>parse_routing_table + assign_databases]
    C --> D[C++ extract_frames / extract_all:<br/>keep routed MRC data frames only]
    D --> E[Python per-bus decode with cantools/ldfparser<br/>signal = CONNECTOR::Message::Signal]
    E --> F[Optional SOME/IP: protobuf decode of reassembled TCP]
    F --> G[Reduce + write MF4]
```

Inputs required: SDB `db/` directory and `manifest.yaml` (SPA2 / `p519`).

## SPA3 path (signal PDUs)

```mermaid
flowchart TD
    A[UDP datagrams from C++ engine<br/>on configured PDU Transport ports] --> B[Suppress exact duplicate packets<br/>within 100 us per UDP flow]
    B --> C[Frame repeated records:<br/>4-byte transport ID + 4-byte length + payload, big-endian]
    C --> D[Bundled SPA3_PDU tables:<br/>transport ID -> signal-PDU ID -> bit layout]
    D --> E[Python bit extraction in pdu.py:<br/>endianness, signedness, factor/offset, padding<br/>signal = PDU::PduName::SignalName]
    E --> F[Optional SOME/IP: protobuf decode of reassembled TCP]
    F --> G[Reduce + write MF4]
```

Inputs required: the four generated files under `SPA3_PDU/`
(`Signal_PDU_identifiers_ETH`, `Signal_PDU_Binding_PDU_Transport_ETH`,
`Signal_PDU_signal_list_ETH`, `decode_as_entries`). These are a reference
snapshot and are **not** selected or updated by downloading a GPA SDB; use a
matching version via `--pdu-config` (or the UI's PDU configuration directory).
SPA2 routing tables and DBC/LDF databases are **not** needed for PDU-only decoding.

## Where C++ ends and Python begins

```mermaid
flowchart LR
    subgraph CPP[C++ mrc_engine - hot path, run once per capture]
        R[pcap read] --> U[unwrap Vector CMP]
        U --> P[dissect L2/L3/L4]
        P --> MF[MRC framing]
        P --> SR[SOME/IP TCP reassembly]
        P --> PF[PDU record framing]
    end
    subgraph PY[Python spa2_decoder - reference data applied here]
        MRCdec[DBC/LDF decode] --> Red
        SIdec[SOME/IP protobuf decode] --> Red
        PDUdec[PDU bit-layout decode] --> Red[reduce unchanged]
        Red --> W[asammdf MF4 writer]
    end
    MF --> MRCdec
    SR --> SIdec
    PF --> PDUdec
```

The reference `nuc-logger` instead **generates C decoder functions** from the
databases and compiles them with `make` for every SDB/PDU version, so its decode
is fully in C++. This repo keeps the signal decode in Python to avoid a per-version
codegen + recompile step; the compiled engine is only rebuilt when the engine
source itself changes:

```bash
cmake --build mrc_decoder/build --target mrc_engine -j2
```
