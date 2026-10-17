# Rule catalog

Current rules in `decoder/interpretation.py`. Each rule is `rule_*(context) -> [finding, ...]`; the
engine (`interpret_readout`) runs them in the order of `RULES` and sorts findings by severity, then
category. The statement numbers refer to the platform model in [SKILL.md](../SKILL.md).

| Rule | Category | Implements | Inputs | Severity logic |
|---|---|---|---|---|
| `rule_current_state` | HPA state | context | HPA D9 9B, EF 58, D1 32; HIA FE 49 | `issue` if CrashMode set, else `info` |
| `rule_standby_records` | HPA standby and resume | 4 | standby events table (HPA 47 21) | `issue` if any record is unsuccessful, else `ok`; also lists shutdown types, intents, blockers, non-standby cycles |
| `rule_shutdown_failures` | HPA standby and resume | 4, 6 | HIA FE 14 | `issue` if an HPA counter is above 0; `warning` if only other nodes; else `ok` |
| `rule_wakeup_histogram` | HPA standby and resume | 4 | HIA FE 18 | `issue` if any not succeeded; `warning` if retries; else `ok` |
| `rule_powerup_histogram` | HPA standby and resume | 4 | HIA FE 17 (+ FE 18 for a plausibility check) | same as wake-up; adds a caution when first-try count exceeds 100x the wake-up count |
| `rule_exceptional_restart` | HP restarts requested by HIA | 3, 4, 6 | HIA FE 4D, FE 4E | `issue` when any restart reason flag is true or the histogram is non-zero, else `ok` |
| `rule_cross_checks` | HPA standby and resume | 4, 6, 10 | HIA FE 14, FE 4D; LPA FE 17; standby events; FSI slots | `info`; relates lifetime counters to the recorded cycles, places the restart in time, and explains a clean LPA history next to HIA's HPA standby failures |
| `rule_application_watchdog` | HPA runtime | 5 | HPA D9 45, EF 82 | `issue` if an essential application was abandoned; `warning` for essential failures or non-essential failures; else `ok`. Shows a per-application table: Failures in state record, Essential, Restartable |
| `rule_fsi_errors` | FSI errors reported to HIA | 3 | HIA FE 03 plus the FE03 slot and detail tables | `issue` if any hardware-origin error or an error whose HIA action resets HPA; else `warning`; `ok` if none |
| `rule_own_resets` | HIA and HIB resets | 7, 9 | HIA/HIB FE 02, FE 04; DTC tables | `issue` if an ECC, thermal or trap cause is flagged, else `info`; DTC reset events are `warning` |
| `rule_reset_logs` | HIA and HIB resets | 7, 9 | HIA/HIB FE 04 (decoded by `decoder/reset_log.py`) | `issue` if the last reset was exceptional, `warning` if the header is not `B4B4B4B4`, else `info`. Tables: Reset Common Data, reset history, application context |
| `rule_lpa_shutdowns` | LPA node history | 8, 10 | LPA FE 17 | `issue` if requests exceed successes or a node is short, else `ok`; always states that LPA does not cover HPA standby failures |
| `rule_lpa_wakeups` | LPA node history | 8 | LPA FE 18, D9 02, D9 08 | `issue` on any failure, timeout or fatal failure, else `ok` |
| `rule_lpa_resets` | LPA node history | 8 | LPA D9 0A, FE 03, FE 0B | `warning` for watchdog, brown-out or external resets; `issue` for exceptional resets; `info` for the boot chain timeout |

`build_timeline` merges standby cycles, FSI errors, platform states, DTCs and the HIA restart into one
chronological list. Entries without a usable timestamp (empty, `1970-...`, `N/A`) are dropped.

## Finding shape

```python
finding(category, severity, headline,
        details=[...],            # bullet sentences
        evidence=[(label, value)],# shown as an Item/Value table
        table=(headers, rows),    # shown instead of evidence when set
        sources=["HIA 22 FE 14"]) # readouts to check in the Translated readout tab
```

## Context helpers

| Helper | Returns |
|---|---|
| `context.values(ecu, "22FE14")` | `{label: value}` for a readout, or `None` if absent |
| `context.fields(ecu, did)` | ordered `[(label, value)]`, keeps duplicate labels |
| `context.raw(ecu, did)` | the decoded block text, including `Complete Response:` |
| `context.rows(kind, heading_prefix=None)` | rows of the parsed summary tables of a kind: `events`, `fe03_slots`, `fe03_details`, `transitions`, `dtc`, `watchdog` |
| `to_int(value)` | leading number, or `None` for unreliable values |
| `is_true(value)` | flag test for values like `1 True` / `0 False` |

## Adding a rule: worked example

Claim: "A non-zero `HPA Standby Transition Failure Counter` means HPA failed to enter standby" (statement 4).

```python
def rule_example(context):
    values = context.values("HIA", "22FE14")
    if not values:
        return []
    failures = to_int(values.get("HPA Standby Transition Failure Counter"))
    if not failures:
        return []
    return [finding("HPA standby and resume", "issue",
                    f"HIA counted {failures} failed HPA standby transition(s)",
                    sources=["HIA 22 FE 14"])]

RULES.append(rule_example)   # or add it to the RULES list
```

Then validate it on a real readout and add a row to the table above.
