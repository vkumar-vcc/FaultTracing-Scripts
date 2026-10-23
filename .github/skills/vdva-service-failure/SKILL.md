---
name: vdva-service-failure
description: "Use when: DHU functions are disabled, greyed out or missing data while HPA, SGA and DHU stay connected, for example climate buttons disabled, no vehicle speed, or a SOME/IP service is offered but sends no events. Covers the vehicledataviewadapter (VDVA) failure pattern, how to confirm it from HPA DLT, readouts and PCAP, and how to separate it from an HPA-SGA-DHU network break. Keywords: VDVA, vehicledataviewadapter, DIDA, climate disabled, ClimateControlService 0x0100, VehicleCommonDataService 0x014D, DiDataService 0x0138, SUBSCRIBED_NO_EVENTS, SOSE, abandoned, non-essential."
---

# VDVA failure: DHU function disabled while the network is up

**VDVA** is the HPA application `vehicledataviewadapter`. It provides vehicle-data SOME/IP services
that HPA offers to DHU through SGA. When VDVA fails, the HPA SOME/IP stack (SOSE) and SGA can stay
healthy: services are still offered and subscriptions are acknowledged, but no data or responses
flow. DHU then disables or greys out the dependent function.

The domain owner confirmed VDVA failure as the root cause in two investigations:

| Vehicle | Date (UTC) | Symptom | Key evidence |
|---|---|---|---|
| YV11SDAC6VB030043 | 2026-10-16 | No vehicle speed at DHU, followed by a diagnostic HP reset at about 12:42 | VDVA DIDA fatal abort 12:25:43; watchdog shows `vehicledataviewadapter` crashed, non-essential, restartable, abandoned |
| YV43ZNP48VM999120 | 2026-10-21 | Climate control buttons disabled in DHU | Climate service offered and subscription ACKed through SGA, TCP alive, zero climate payload for over 6 minutes |

## Signature

Confirm all four. Each one alone is not enough.

1. **Transport is up.** HPA ↔ SGA ↔ DHU TCP sessions get ACKs. Other HPA services carry payload at the
   same time, for example VehicleCommonDataService `0x014D`.
2. **Discovery is up.** HPA keeps offering the affected service (SD offer every ~2 s, TTL 6 s). DHU
   subscribes and HPA (and SGA towards DHU) sends SubscribeEventgroup ACK. There is no NACK and no StopOffer.
3. **The application is silent.** The service's TCP connection has **zero-length payload only**. The
   TCP SEQ/ACK numbers stay the same across captures taken minutes apart. There are no notifications or
   responses, and requests to VDVA services get no answer (`REQUEST_NO_RESPONSE`).
4. **VDVA failed on HPA.** Look in HPA DLT and the readout:
   - VDVA initialization of dependent interfaces fails repeatedly, then a **DIDA fatal abort**
     ("exceeded initialization retries").
   - The watchdog record (HPA 22 D9 45 / D9 9D) shows `vehicledataviewadapter,<time>,Crashed,NonEssential,Restartable,Abandoned`.
   - SOSE removes the RX/TX tasks for the VDVA ports just before the abort, but service offers can still appear.
   - No VDVA log lines appear after the abort until the next full HPA restart.

VDVA is **non-essential**, so being abandoned does **not** reset HPA by itself (platform model,
statement 5). The function stays dead until HPA restarts. A later HP reset (for example a diagnostic
reset, HIA FE02 type `0x81`) is a separate event; do not report it as caused by VDVA unless evidence shows that.

## Services involved

Taken from `pcap_decoder/rim_ecu_signals/interfaces/services/vsomeip_services.yml` and the per-service YAML files.

| Service | ID | Instance | TCP port | Notes |
|---|---|---|---|---|
| ClimateControlService | 256 / `0x0100` | `0x5678` | 31501 | Event group `0x0100`; consumers DHU, TCAM; methods 4096–4150 (`hpa_climate_control.yml`) |
| VehicleCommonDataService | 333 / `0x014D` | 1 | 31555 | VehicleSpeed event `0xA011`, GetVehicleSpeed method `0x0012`, event group 1 |
| DiDataService | 312 / `0x0138` | 1 | 31552 | Methods `0x0004`/`0x0005` went unanswered in the climate case; the VDVA fatal trigger referenced service 312 in the speed case |

The fatal trigger can name a different VDVA service than the symptom. Report it as a VDVA failure that
affects all of its services. Do not claim that one service caused the abort.

## How to analyse

1. **Readouts** (`decoder-summary-interpretation` skill): check the HPx watchdog state for
   `vehicledataviewadapter`, including the time, `Abandoned` and the restart count. Check for HPA resets
   between the abort and the symptom. A full HPA restart restores VDVA, so the symptom should disappear
   after one.
2. **HPA DLT** (decode the `.dlt` files; download them with
   `download_combine_NUC_dlt/download_combine_NUC_dlt.py`): search for `VDVA`, `vehicledataviewadapter`,
   `DIDA`, `initialization`, `exceeded`, and the SOSE port de-registration for the service port
   (`31555`, `31501`, `31552`). Find the **first** failure and note what came before it, for example
   dependent interfaces not ready or DHU subscriptions expiring.
3. **PCAP** (`someip_comm_analyzer/someip_comm_analyzer.py <pcap> --profile SPA2|SPA3 --outdir <dir> -j 1`):
   - Check `services.csv`: the affected service shows `offered`, `subs_acked>=1`, `requests=0`, `responses=0`.
   - Check `events.csv`: look for `SUBSCRIBED_NO_EVENTS` on the service, and `REQUEST_NO_RESPONSE` on `0x0138`.
   - Check the TCP payload length on the service port with tshark:
     `tshark -r <pcap> -Y "tcp.port == 31501" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.len -e tcp.seq_raw -e tcp.ack_raw`.
     Only zero lengths, with SEQ/ACK unchanged across captures, means the application is silent.
   - SGA `all.pcap` uses Linux cooked capture v2 (pcap link type 276). The analyzer rejects it. Use
     tshark directly, or strip the 20-byte SLL2 header per `sll.ifindex` into a temporary Ethernet pcap.
     Keep the interfaces separate: one packet shows up on several bridge ports and must not be counted
     as a retransmission. The original file stays the evidence.
   - To prove SGA forwards in both directions, match the same packet on the HPA side
     (`198.19.0.1`) and the DHU side (SGA alias, for example `198.19.64.2`) by IP ID and TCP SEQ/ACK.
4. **SGA journal / DLT**: confirm the SOME/IP gateway started (`Startup complete, ready to forward
   messages`) and note any carrier loss on `fm1-mac*`, `vlan15x` or `br0`. A link loss that has already
   recovered does not explain a symptom that is still present.

## Pitfalls

- An offered service with an ACKed subscription does **not** mean the function is healthy. Check the payload.
- `SUBSCRIBED_NO_EVENTS` on its own can be normal for on-change services in a short capture. It is
  meaningful only together with steps 3 and 4.
- Do not blame repeated SGA `BAD_VALUE` (extended-HMI keep-awake, VehicleCert) or SGA gateway
  `Poll failed (Interrupted system call)` from earlier boots. HPA answers these; they are background noise.
- A SocketCAN error burst in the SGA capture (for example on ifindex 2, no-ACK) is a separate finding
  until its network is mapped to the affected function.
- DLT chunk names show the time of the **last** message; check the real coverage. Clocks before time
  sync can show stale dates.
- Do not carry one vehicle's timestamps or conclusions over to another; confirm each signature item
  again for each VIN.

## Report

- Root cause: "VDVA (vehicledataviewadapter) failed on HPA (DIDA initialization abort, abandoned as
  non-essential); HPA keeps offering its SOME/IP services but sends no data, so DHU disables <function>."
- Evidence: the watchdog record, the DLT abort line with its timestamp, a PCAP excerpt showing an ACKed
  subscription with zero payload, and proof that transport and SGA forwarding work.
- Recovery: an HPA restart. Next step for the owner: find why VDVA's dependent interfaces did not
  initialize, using the first failure before the abort.

## Engineer notes

Added by engineers from the investigation app. They refine the guidance above.

### Added 2026-10-22 from investigation `20261021T143449_YV11SDAC6VB030043_42303d`.

this is correct.vdva is the root cause
