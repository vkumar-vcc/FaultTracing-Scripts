---
name: decoder-summary-interpretation
description: "Use when: interpreting a vehicle readout in the decoder app's Readout summary tab, adding or changing an interpretation rule, or explaining HPA/HIA/HIB/LPA behaviour such as standby (SC7), sleep, resume, cold boot, resets, FSI errors, essential-application restart limits and the application watchdog. Also use to map readout DIDs (22 FE03, FE4D, FE14, FE17, FE18, D945, 4721, LPA FE16/FE17/FE18) to findings. Keywords: HPA, HIA, HIB, LPA, SGA, SC7, standby, cold boot, FSI, watchdog, reset reason, decoder summary, interpretation rules."
---

# Decoder summary interpretation

The **Readout summary** tab of the decoder app (`decoder/decoder.py`) shows an **Interpretation**
section: rule-based findings that explain what a readout means. The rules live in
[`decoder/interpretation.py`](../../../decoder/interpretation.py) and encode the platform model
below. Use this skill to keep that model correct, to add rules, and to explain a finding.

## Platform model (domain statements)

These statements come from the domain owner. Treat them as the source of truth and never contradict
them in a rule. Full detail and the data each statement relies on is in
[knowledge-model.md](./references/knowledge-model.md).

1. **HPA** is the High Performance QNX environment.
2. **HIA** is High Integrity A and **HIB** is High Integrity B.
3. HPA is **controlled by HIA**. A hardware error on HPA is reported to HIA as an **FSI error**, and
   HIA then **resets HPA**.
4. HPA can go to **sleep** or **standby (SC7)**. If that fails, the reasons are **stored in HIA** and HPA
   gets a **cold boot instead of a resume**.
5. HPA can reach **failure during run** when an **essential application fails more often than its
   allowed restart limit**. That triggers a reset from HIA.
6. **HIA stores all reset reasons for HPA.**
7. A **HIA reset can also cause an HPA reset**; more generally a **failure in HIA can cause HPA to restart**.
8. **LPA stores the standby failure and success history** for the VCU nodes (SGA, HPA, HIA, HIB).
9. **HIA and HIB can reset on their own** and keep an error log.
10. **An HPA standby failure does not show as a failure in LPA**: even when HPA fails in standby, HIA
    powers off, so LPA still counts a successful shutdown. LPA counts are therefore meaningful for the
    other nodes (SGA, HIA, HIB), not for HPA. HPA standby failures are read from HIA instead.

## When to use this skill

- Explaining or reviewing a finding shown in the Interpretation section.
- Adding a rule for a new DID, node or failure pattern.
- Changing severity, wording or thresholds of an existing rule.
- Answering "why did HPA restart / cold boot / fail to enter standby" from a readout.

## Procedure: add or change a rule

1. **State the claim first.** Write one sentence linking the data to a statement above, for example
   "A non-zero HPA standby transition failure counter means HPA failed to enter standby (statement 4)".
   If it needs a fact that is not in the model, add it to the open questions in
   [knowledge-model.md](./references/knowledge-model.md) and ask the domain owner before coding it.
2. **Find the data.** Look the DID up in [readout-data-map.md](./references/readout-data-map.md). If it is
   missing, decode a real readout and add the DID, ECU, field names and a sample value there.
3. **Write the rule** in `decoder/interpretation.py`:
   - a function `rule_<topic>(context)` returning a list of `finding(...)` dicts;
   - read data only through `context.values(ecu, "22XXXX")`, `context.raw(...)` and
     `context.rows(kind, heading_prefix)`; return `[]` when the data is absent;
   - never raise for missing or odd data; the engine isolates a failing rule but the finding is lost;
   - append the function to `RULES`; add a category to `CATEGORY_ORDER` only if truly new.
4. **Pick the severity** using the table below, and write hedged wording ("indicates", "consistent with").
5. **Record the evidence**: put the raw values in `evidence` or `table`, and the readouts in `sources`
   (for example `HIA 22 FE 14`) so the user can check them in the Translated readout tab.
6. **Validate on a real readout**, not a synthetic one. Translate the readout, run
   `interpret_readout(blocks, sections)` and read every new finding critically. Check it does not
   contradict another finding and that an all-zero or empty record gives an `ok` finding, not a false alarm.
7. **Update the references**: add the rule to [rule-catalog.md](./references/rule-catalog.md) and any new
   quirk to the list below.

## Severity semantics

| Severity | Meaning | Example |
|---|---|---|
| `issue` | A failure that the model says causes or reflects an HPA/HIA/HIB failure or reset was recorded | Standby transition failure counter above zero; essential application abandoned; HW FSI error |
| `warning` | Degraded or recovered behaviour, or a failure that does not by itself reset HPA | Wake-up needed a retry; non-essential applications abandoned |
| `info` | Context, a last-reset record with no flagged cause, or a cross-check note | HPA platform state; HIA last reset type |
| `ok` | The data was present and shows no problem | All recorded standby cycles succeeded |

Absent data is never `ok`; it is listed under "Not present in this readout".

## Known data quirks

Keep these in mind when interpreting values; each was observed in a real readout.

- **HIA 22 FE 4D** exceptional reset counter decodes as a multiple of 2^24 (for example 16777216 =
  0x01000000), so the SDDB field is probably little-endian and the real value is 1. The rule says so.
- **HIA 22 FE 17** first-try power-up counter was 36,009,215 beside a wake-up counter of 3,132. It looks
  implausible, so the rule flags it for caution when it exceeds 100 times the wake-up counter.
- **HPA 22 47 21** shutdown types seen are `Standby` and `Restart`; the standby decoder used to match only
  `Sleep` and left the type blank (fixed in `standby-decoder/hpa_stanby_decoder.py`). Intent value `10`
  has no name in the decoded output.
- **FE03 slot times** of `1970-01-01T00:00:00` mean "no timestamp" and are excluded from the timeline.
- **HP operation state `0`** in FE03 slots has no name; it is shown as "0 (not recorded)".
- **Platform state ids 0 and 3** appear in the state history and are unnamed in the standby decoder
  ("Unknown (0)", "Unknown (3)").
- **VIUD / VIUF / VIUP shutdown failure counters** read 4294967295 ("Value not reliable") and are ignored.
- **Timezones**: standby records, platform states and DTCs are UTC; FE03 slot times, the FE4D restart time
  and watchdog timestamps are stored without a timezone and are shown as recorded.
- **HPx watchdog state (22 D9 45)** records: the first six comma-separated fields are application, time,
  event (`Crashed`, `Failure`, `HeartbeatMissed`), `Essential`/`NonEssential`, `Restartable`/`NonRestartable`
  and `Abandoned`/`NotAbandoned`; the seventh behaves as a restart count (an application showed 1, 2, 3 and
  was then abandoned). The remaining fields are not interpreted. The SDDB defines the whole payload as one
  text field, so there are no named fields, and **the readout stores no restart limit**; the decoder does
  not show one. This record holds only the latest entries (data health `Overloaded`), so its
  counts are lower than the full failure timeline (`22 D9 9D`), and applications that appear only in the
  timeline (for example `camera-failure-*`) show N/A.
- **Watchdog table columns** (Essential, Restartable) are added in the app
  by `add_watchdog_columns` in `decoder/interpretation.py`; the standby decoder's own output is unchanged.

## Open questions for the domain owner

Assumptions the rules make that have not been confirmed. Resolve them and move the answer into the model.

- 22 47 21 is read from HPA (`1D12`) and describes shutdowns requested to the HIA shutdown manager.
  The rules use that record for per-cycle detail and the HIA counters (22 FE 14, FE 4D) for HPA standby
  failures. Per statement 10 the LPA counters (22 FE 16/17/18, D9 02, D9 08, D9 0A) are used only for
  SGA, HIA and HIB, never as evidence about HPA standby. Confirm that 22 47 21 records are still
  written when HPA fails in standby.
- What do `Restart` shutdown type and VCU intent `10` mean, and should a `Restart` be treated as a
  failed standby?
- Are HIA/HIB `Reset TimeStamp` values ECU ticks, and can they be converted to UTC?
- Which applications are essential? No essential application appeared in the sample readout, so that
  path is untested on real data. The readout stores no restart limit, so a limit cannot be shown.
- Are FE03 slot times and the FE4D restart time UTC?
