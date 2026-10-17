# Platform knowledge model

Source: statements from the domain owner (2026-10-16), verified where noted against the readout of
VIN `YV11SDAC8TB000121`. Anything marked **assumption** is not confirmed.

## Nodes

| Node | ECU address | What it is | Role |
|---|---|---|---|
| HPA | `1D12` | High Performance QNX environment | Runs the applications; controlled by HIA |
| HIA | `1D0D` | High Integrity A | Controls HPA; stores HPA reset reasons and FSI errors |
| HIB | `1D0E` | High Integrity B | Can reset on its own and keeps an error log |
| LPA | `1D1A` | Full name not stated by the domain owner | Stores standby/wake-up/reset history for the VCU nodes |
| SGA | `1D24` | Node tracked by LPA | Reported in LPA counters |
| LPC | `1D1B` | Appears in "ECUs still active at forced shutdown" | Not part of the model above |

## Causal chains

### 1. Hardware error on HPA (statement 3)

```
HPA hardware error -> reported to HIA as an FSI error -> HIA resets HPA
```

HIA keeps the history of these FSI errors (`HIA 22 FE 03`, "FSI errors history"). Each slot has a
reporter id, an error code and attribute, a SOC_ERROR flag, the HP operation state and an occurrence
count. The error reference table adds a name, an origin (`HW_`/`SW_` prefix of the reference) and the
action HIA takes ("Log error and apply the reset/reboot policy for HPA").

### 2. Sleep or standby (SC7) fails (statement 4)

```
HPA fails to enter standby/sleep -> reason stored in HIA -> next start is a cold boot, not a resume
```

Evidence in a readout:

- `HIA 22 FE 14` shutdown failure counters: `HPA Standby HW Signal Failure`, `HPA Standby Transition Failure`.
- `HIA 22 FE 18` wake-up histogram and `22 FE 17` power-up histogram (first/second/third try, not succeeded).
- `HIA 22 FE 4D` startup failure flags: "Run state from standby not received within timeout" (resume failed)
  and "Run or failure state not achieved within timeout from cold boot".
- `HPA 22 47 21` per-cycle shutdown records with a "not successful" flag.
- `HPA 22 D9 91` platform state history (Run, PrepareForStandby, Standby, PrepareForResume, Resume, ...).

**HIA powers off regardless (statement 10).** Even when HPA fails in standby, HIA powers off, so the
vehicle shutdown still completes and **LPA counts it as successful**. HPA standby failures are therefore
visible only in HIA (`22 FE 14`, `22 FE 4D`) and the HPA records, not in LPA.

### 3. HPA fails during run (statement 5)

```
essential application fails more often than its restart limit -> HPA failure -> HIA resets HPA
```

Evidence: `HPA 22 D9 45` (application, event, Essential/NonEssential, Restartable, Abandoned, restart count),
`22 D9 9C` failure counters per application, `22 D9 9D` failure timeline, `22 EF 82` latest failure record,
`22 D1 32` crash mode, and the HIA `22 FE 4D` flag "Failure operation enabled from run state".
Non-essential applications that exceed their limit are abandoned but do not reset HPA on their own.

### 4. HIA keeps every HPA reset reason (statement 6)

`HIA 22 FE 4D` (reason for the latest exceptional restart, with a timestamp), `22 FE 4E` (histogram of
in-reset reasons) and `22 FE 49` (requested HP state and request reason). Reason groups: startup failure,
thermal mitigation, safety supervision, failure operation from run, heartbeat failure, power mitigation.

### 5. HIA failure or reset restarts HPA (statement 7) and HIA/HIB self-resets (statement 9)

`HIA`/`HIB 22 FE 02` reset reason (type, counter, timestamp, triggering core, trap, ECC and thermal flags,
MCU reset register) and `22 FE 04` reset log trace. A failure or reset of HIA can restart HPA, so it should
show up as an HPA cold boot or a restart in the HPA platform state history around the same time.
HIA/HIB DTC events such as `DEM_EV_MCU_RESET_LAST_CYC` also point to a reset.

### 6. LPA history (statements 8 and 10)

LPA counts the other nodes (SGA, HIA, HIB); it is **not** evidence about HPA standby, because HIA powers
off even when HPA fails (statement 10). `LPA 22 FE 16` latest shutdown status (power good per node),
`22 FE 17` shutdown statistics (requests and successes, per node), `22 FE 18` wake-up statistics (counter,
per-node failures and fatal failures),
`22 D9 02` wake-up timeout in current cycle (HIA, HIB, SGA, HPA), `22 D9 08` fatal wake-up failure,
`22 D9 0A` reset reason statistics, `22 FE 02`/`FE 03` exceptional resets (stack overflow, hard fault,
watchdog, panic) and `22 FE 0B` HPA boot chain confirmation timeout.

## Reading several sources together

- HIA counters are **lifetime** totals; `HPA 22 47 21` holds only the **latest cycles**. A non-zero HIA
  failure counter with all-successful records means the failure is older than the records.
- A clean LPA shutdown history does **not** contradict HIA's HPA standby failure counters (statement 10).
- Compare the FE4D restart time with the first recorded standby cycle to place it before or inside the window.
- FSI errors logged while HP was in Standby, Resume or Power Off are relevant to failed standby or resume.
- A HIA or HIB reset record without ECC, thermal or trap flags is a software-requested reset whose trigger
  the record does not identify; look at the reset log trace (`22 FE 04`).
