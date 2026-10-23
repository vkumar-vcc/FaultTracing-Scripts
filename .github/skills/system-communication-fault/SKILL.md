---
name: system-communication-fault
description: "Use when: DHU shows a \"system communication fault\" (or a similar communication error message) to the driver. Gives the decision procedure: first check whether HPA reset (DLT hardware timestamp restarting from zero, SAT readout reset records) and why; if HPA did not reset, check whether DHU stopped receiving the HPA status information (from HIA and HPA) or the vehicle speed from HPA over SOME/IP through SGA. Keywords: system communication fault, DHU, HPA reset, uptime restart, timestamp from zero, HPA status, vehicle speed, SOME/IP, SGA, VehicleCommonDataService."
---

# DHU "system communication fault"

DHU shows **system communication fault** when it loses the inputs it needs from the VCU. The domain
owner gave this procedure. Follow the steps in order: the answer of step 1 decides which branch to take.

## Step 1: did HPA reset? (always check first)

An HPA reset is the most common cause. Check both sources.

- **HPA DLT.** The DLT standard-header timestamp is the HPA hardware uptime since boot. When it
  **restarts from (near) zero**, HPA reset or cold-booted. The DLT digest lists this under
  **ECU uptime restarts** (`collected/dlt_text/HPA_<window>_digest.md`). Confirm it in the text file
  around that time: the last messages before the restart and the boot messages after it.
  - A **logging gap is not a reset**. Look at the uptime after the gap: if it continues from where it
    was, HPA was suspended (standby SC7 and resume); if it starts again near zero, HPA reset or did a
    cold boot.
  - Look at all applications together. One application restarting its own counter is not an HPA reset.
- **SAT readout** (the first readout captured after the event). Look for HPA reset records near the
  event: HIA reset reasons for HPA (FE03 error slots, last reset type, FE4D exceptional resets), HPA
  watchdog (`22 D9 45` / `D9 9D`) with an **essential** application abandoned, FSI errors, HIA resets,
  failed standby followed by a cold boot. Readouts store some times without a timezone; state the
  offset you assume.

If either source shows an HPA reset close to the event, go to step 2. If neither does, go to step 3.

## Step 2: HPA reset, find why

Use the platform model in the `decoder-summary-interpretation` skill (read its `SKILL.md`; use
`references/readout-data-map.md` for DIDs). Never contradict it:

- **FSI error** (hardware error reported to HIA), then HIA resets HPA (statement 3).
- **Failed standby (SC7) or sleep**, then a cold boot instead of a resume; the reason is stored in HIA
  (statement 4). LPA does not show HPA standby failures (statement 10).
- **Failure during run**: an essential application failed more often than its restart limit (statement 5).
  Find it in the watchdog record, and in HPA DLT find its first failure before the reset.
- **HIA reset or HIA failure** that also restarted HPA (statement 7).
- **Diagnostic or functional reset** requested by a tester or the user (for example HIA FE02 type
  `0x81`). This reset is the recovery, not the cause; look further back for what failed first.

In HPA DLT, read the last minutes before the uptime restart: fatal/error lines, the watchdog,
`HPARestartEventCase`, shutdown or restart intent, and FSI messages. Report the reset, its reason from
the readout, and the first failure that led to it.

## Step 3: no HPA reset, check the DHU inputs

DHU raises the fault when one of these inputs is missing:

1. **HPA status information.** It is sent by **both HIA and HPA**. Receiving **either one** is enough;
   the fault needs **both** to be missing. So check both senders before blaming one of them.
2. **Vehicle speed from HPA**: SOME/IP `VehicleCommonDataService` (`0x014D`, instance 1, TCP port
   31555), event `VehicleSpeed` `0xA011` in event group 1, method `GetVehicleSpeed` `0x0012`. HPA
   (`198.19.0.1`) sends it to DHU **through SGA**.

For each input, find where the chain breaks:

- **Sender.** Was the HPA application that provides it running and sending? A known cause is the
  **VDVA (vehicledataviewadapter) failure**: the service is still offered and subscriptions are acknowledged,
  but no data is sent. Read the `vdva-service-failure` skill and check its four-part signature.
- **SGA.** Did SGA forward in both directions? Check SGA DLT/journal for the SOME/IP gateway start
  (`Startup complete, ready to forward messages`), restarts (uptime from zero in SGA DLT), and carrier loss
  on `fm1-mac*`, `vlan15x` or `br0`.
- **Transport and discovery.** In PCAP: SD offers, StopOffer, subscription ACK/NACK, TCP resets, and
  whether event payload actually flows. The `vdva-service-failure` skill describes the tshark and
  `someip_comm_analyzer` checks.
- **HIA.** For the HPA status from HIA: an HIA reset or HIA error log entry near the event (HIA keeps
  its own error log, statement 9).

## Pitfalls

- Do not conclude "HPA was in standby, so the logs cannot explain it" when the user was in the car and
  saw the fault. A standby record or logging gap near the event must be checked against step 1:
  was it a real suspend and resume, or a reset/cold boot? A failed standby is itself a reason for
  the fault.
- The time the user reports is often the time they noticed or recovered (for example a functional
  reset), not the time the fault started. Search from when the user entered the car up to the reported
  time, and widen the DLT window when needed.
- A reset that the user or a tester triggered to recover is the end of the fault, not its cause.
- Errors that repeat through the whole window are background noise unless they change at the fault.

## Open questions for the domain owner

- Which SOME/IP service or signal carries the **HPA status information** from HIA and from HPA to DHU,
  and what timeout does DHU use before showing the fault?
- What does DHU log (application, context, text) when it raises the fault?
