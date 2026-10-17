# Readout data map

Where each piece of evidence lives in a translated readout. Request format is `<ECU> 22 <DID>`
(for example `1D0D 22 FE 14`). In code use the DID without spaces: `context.values("HIA", "22FE14")`.
Field labels below are the decoded `Label: value` lines in the translated output.

## ECU addresses

| Name | Address | Full SW name seen |
|---|---|---|
| HIA | `1D0D` | `HIA_PBL_32477842_AA` |
| HIB | `1D0E` | `HIB_PBL_32442846_AA` |
| HPA | `1D12` | `HPA_APP_32442848_AA` |
| LPA | `1D1A` | `LPA_APP_32442849_AC` |
| LPC | `1D1B` | `LPC_PBL_32287495_AF` |
| SGA | `1D24` | `SGA_APP_32442852_AA` |
| VESA | `1D36` | `VESA_APP_32413996_AA` |
| VESB | `1D37` | `VESB_APP_32437001_AA` |

The "Full SW name" is the name in the SDDB used for translation, not a version reported by the vehicle.
Its number matches the ECU's diagnostic database part number (22 F1 20) for HPA, VESA and VESB but not
for HIA, HIB and SGA in the sample readout, so the SDDB may describe an older database for those ECUs.

## Identification readouts (SW versions tab)

Every ECU answers the same identification DIDs; `decoder/sw_versions.py` reads them by ECU name.
Part numbers are stored as bytes (`32 48 96 51 ACP`) and shown as one value, `32489651 ACP` (number, then edition).
The tab shows each ECU's software modules, then its other values, leaving out anything that repeats a module's
part number (calibration IDs, the software structure number) and showing hardware values that are identical on
all ECUs once at the top.

| DID | Name | Content | Shown as |
|---|---|---|---|
| `F1 2E` | ECU Software Part Numbers | one `Module: part edition` line per software module (HIA 4, HPA 11, SGA 6, VESA/VESB 1) | module table; the SWLM (or first application) module is the number in the ECU section title |
| `F1 20` | Application Diagnostic Database Part Number | diagnostic database part number | Diagnostic database part number |
| `F1 2A` / `F1 2B` | ECU Core / Delivery Assembly Part Number | hardware assembly numbers (identical on all six ECUs in the sample) | shown once for all ECUs |
| `F1 2C` | ECU Software Structure Part Number | HPA only; equals its "ESS Part number - Signature file" module | omitted when it repeats a module |
| `F1 8C` | ECU Serial Number | identical on all six ECUs in the sample | shown once for all ECUs |
| `F1 F0` | Integrated Diagnostic Database Part Number | HIA, HIB | item |
| `F8 04` | Calibration Identifications | calibration part numbers (HIA, HIB, HPA, SGA); in the sample all equal a module part number | omitted when it repeats a module |
| `F1 84` | Application Software Fingerprint | build string (HIA, HIB) | item |
| `ED A0` | Complete set of ECU part/serial numbers | diagnostic database and assembly numbers; used when the individual DIDs are missing | fallback |

Unprogrammed SGA modules (the Wi-Fi certificate password and key) read `00000000 ZZZ`.

## Baselines of the software part numbers (ConfigHub)

`decoder/baselines.py` finds the MAIN_INT baselines for the software part numbers above with one ConfigHub call per
ECU (`swagger.json`; auth is the OAuth2 password flow at `/api/v2/session`, header `Contract-Id`), run in parallel
(about 6 s for all six ECUs; walking each part's baseline links took 25-45 s):

`POST /api/v1/baselines/getMatchingBaselineForArtifact` with
`{"ECUPartNumbers": [{"Id": ecu, "HwPartNumber": hw, "BaselineName": "MAIN_INT", "SwPartNumbers": [...],
"PartTypesToBeSkipped": [], "IgnorePartnumberStartswith": ["00000000"]}], "IntentOfUse": ["Integration"]}`.

- A ConfigHub part number is the 8 digits plus the edition without spaces: `32489651 ACP` -> `32489651ACP`.
- The software file of a part is `FileURI` of `GET /api/v2/software/{partNumber}` (an Artifactory `.vbf` URL, e.g.
  `https://ara-artifactory.volvocars.biz/artifactory/SWCH-SPA2-LTS/HIA/<id>/32489651ACP.vbf`). The Download column
  links it; Artifactory answers 401 without credentials, so the browser has to sign in (the ConfigHub token is not
  accepted there).
- `HwPartNumber` is required (HTTP 400 without it) but did not change the matches; the readout's delivery (else core)
  assembly number is used.
- `BaselineName` "MAIN_INT" plus `IntentOfUse` "Integration" returns only `*_MAIN_INT` baselines (`HIA_MAIN_INT`,
  `HPA_MAIN_INT`, `HPAA_EE_MAIN_INT`, ...), not `_DEV`, release-candidate, PIE or test baselines. Certificate modules
  and `00000000` parts are not sent (that placeholder is linked to an unrelated `SUM_SPA2_INT` baseline).
- The response is `ECUMatchingBaselines[].Matches[]`, the best three matches. Each has `Baselines[]` (`Name`,
  `Version`, `EcuName`) and `PartNumbers[]` (`PartNumber`, `KdpPartType`, `Matching`, `MatchingWith` = baseline
  name). A match where every part has `Matching` true contains all parts; otherwise the first match is shown as the
  closest. The `/api/v2/` version of the call returns only the top match.
- HPA is two ConfigHub positions in one match: `HPA` (platform: SWE1, SWL2, SWL3, SWL4, SWLM, SWP2; baseline
  `HPA_MAIN_INT`) and `HPAA` (application: SWL2, SWLM, SWM1, SWP2, SWTV; baseline `HPAA_EE_MAIN_INT`).
  `MatchingWith` splits the parts into the two rows. The other ECUs are one position each.
- Only the newest three matching versions come back, so ranges can be incomplete (the exhaustive walk found HIA
  v430-v434 and VESA v53, v59-v60; the call gives HIA v432-v434). A part number says which baselines contain it,
  not which one was installed: HIB v500, HPA v508 + `HPAA_EE_MAIN_INT` v4812 and SGA v143 are single versions.

## HIA (`1D0D`)

| DID | Name | Useful fields | Used by |
|---|---|---|---|
| `FE 03` | FSI errors history | per slot: Time, Reporter ID, Error code, Error attribute, SOC_ERROR state, HP operation state, Occurrence | `rule_fsi_errors`, timeline |
| `FE 14` | Shutdown Failure Events Counter | `HPA Standby HW Signal Failure Counter`, `HPA Standby Transition Failure Counter`, `HPA Shutdown Failure Counter`, SGA/HIB counters, VIU* (unreliable) | `rule_shutdown_failures`, `rule_cross_checks` |
| `FE 17` | HPA Power-up Events Histogram | Succeeded 1st/2nd/3rd try, Not Succeeded | `rule_powerup_histogram` |
| `FE 18` | HPA Wakeup Events Histogram | Succeeded 1st/2nd/3rd try, Not Succeeded | `rule_wakeup_histogram` |
| `FE 49` | Requested HP State | Platform State Request, Request Reason | `rule_current_state` |
| `FE 4D` | Reason for exceptional restart | HP Exceptional reset counter, Startup failure flags, thermal, safety, power, heartbeat; ISO timestamp is inside the raw response bytes | `rule_exceptional_restart`, `rule_cross_checks`, timeline |
| `FE 4E` | Histogram of InReset reasons | one counter per restart reason | `rule_exceptional_restart` |
| `FE 02` | ECU Reset Reason | Reset Counter, Reset TimeStamp, Reset Type, Trap class/ID/address, ECC flags, thermal flags, MCU Reset Register | `rule_own_resets` |
| `FE 04` | ECU Reset Log | `Trace:` hex bytes (the DID payload after `62 FE 04`) | `rule_own_resets` (presence), `rule_reset_logs` (full decode, see below) |
| `19 03` / `19 04` | DTC list and snapshot | DTC, description, Global Real Time, "Latest event which caused <DTC>" | standby decoder DTC tables, `rule_own_resets`, timeline |

## HIB (`1D0E`)

`FE 02` ECU Reset Reason and `FE 04` ECU Reset Log (same layout as HIA), plus `19 03`/`19 04` DTCs.

### Reset log layout (`22 FE 04`, `decoder/reset_log.py`)

Ported from the Safety-B "ResetLog parser sheet" (`resetLogs_parser_script.cls`, `ResetLogs_Parser.xlsm`, 14/11/2025).
Multi-byte fields are little-endian in the payload and are shown as the hex number.

- **Reset Common Data, bytes 0-47** (address 0xF02400A0): ValidHeader `B4B4B4B4` (4), RstLoop_ModeControl (4:
  `AAAAAAAA` stay in FBL, `00000000` stay in APP, `55555555` UDS clear requested), RstLoop_ExcResetCounter (4),
  StructVersionMajor (2), StructVersionMinor (2), LastExceptionalReset (1), LastReset (1), 2 padding, ResetCounter (4),
  ResetTimestamp (4, ECU ticks), ScuRSTSTAT (4), IsExceptionalReset (1: `01` exceptional), ResetHistoryIdx (1),
  ResetHistory[0-7] (8 x 1), SwReasonCode (1), SwReasonCoreId (1), 4 padding. LastExceptionalReset, LastReset and the
  history use the reset-reason table in `reset_log.py` (cold boot 0x10-0x13, warm boot 0x20-0x25, SMU 0x30-0x35,
  start-up tests 0x50/0x51, application-initiated 0x80-0x9B).
- **Application context, from byte 48** (address 0xF02400D0): one raw area that the sheet decodes six ways, all starting
  at byte 48: protection hook (stack trace, address and data registers, Ra/Psw/..., FatalError, deadd_reg; 236 bytes),
  error hook (stack trace, Service, Error, DetailedError; 72), SMU alarms (AD0-AD11; 48), panic hook (stack trace,
  status; 69), PMIC status (TLF registers; 18) and MCAL report error (stack trace, ModuleId, ApiId, ErrorId; 72).
  The log does not say which decoding applies. `CONTEXT_FOR_REASON` picks the one that matches the reset reason
  (0x83 protection hook, 0x84 error hook, 0x85 panic hook, 0x8A MCAL, 0x30-0x35/0x95 SMU, 0x51/0x96/0x97 PMIC); that
  mapping is an assumption of this app, not part of the sheet. With no match, the non-zero fields of every decoding
  are listed.
- **Checks the sheet makes**: header `B4B4B4B4`, major version `0001`, minor version `0002`. The real readout has
  structure version `0002.0000` and a 512-byte payload (the sheet pads to 250 bytes), so the output says the context
  layout is unverified for that version. The common record cross-checks with `22 FE 02` (HIB reset counter 6 in both).
- The sheet also accepts UART logs (4-byte words reversed); the readout only has the DID form.

## HPA (`1D12`)

| DID | Name | Useful fields | Used by |
|---|---|---|---|
| `47 21` | Shutdown Information From Previous Driving Cycle | per record: shutdown-request timestamp, Shutdown Type (`Standby`, `Restart`), VcuShutdownIntent, ISTWakeUpTimer, ECUs still active at forced shutdown, "not successful" flag | standby decoder events table, `rule_standby_records`, timeline |
| `D9 91` | Platform state transition history | 9-byte records: state id, timestamp (ms) | standby decoder, timeline |
| `D9 9B` | HP Platform State | Platform state | `rule_current_state` |
| `DD 0E` | Vehicle Time | Global Real Time and UTC (anchor for UTC conversion) | standby decoder |
| `D9 45` | HPx Application Watchdog System and Software State | `Data Health`; comma records: application, time, event, criticality, restartable, abandoned, restart count | `rule_application_watchdog` |
| `D9 9C` | App Failure History | application and failure counter | not used yet |
| `D9 9D` | App Failure Timeline | application, timestamp | standby decoder watchdog tables |
| `EF 82` | Watchdog Failure Record | Application Name, Executable Failure Reason | `rule_application_watchdog` |
| `D1 32` | Crash Mode | CrashMode flag | `rule_current_state` |
| `EF 58` | Active bootchain read | A or B | `rule_current_state` |
| `EF 51` / `EF 53` | Clients requesting HPA restart (current / previous power cycle) | client names | not used yet |
| `E4 00` / `E4 01` | Expired / Pending Wakeup Events | timestamp and application | not used yet |

## LPA (`1D1A`)

| DID | Name | Useful fields | Used by |
|---|---|---|---|
| `FE 16` | Latest Shutdown Status | HIA/HIB/SGA PowerGood status | evidence only |
| `FE 17` | Shutdown Statistics | Shutdown Request counter, Successful Shutdown counter (total, HIA, HIB, SGA), Maximum Successful Shutdown Time. Covers HIA, HIB and SGA only; HPA standby failures do not show here (HIA powers off anyway) | `rule_lpa_shutdowns`, `rule_cross_checks` |
| `FE 18` | VCU Wake up Statistics | Wakeup Counter, Successful Wakeup Counter, Wakeup Failure and Fatal Failure per HIA/HIB/SGA | `rule_lpa_wakeups` |
| `D9 02` | Wakeup timeout in current cycle | HIA, HIB, SGA, HPA | `rule_lpa_wakeups` |
| `D9 08` | Fatal wakeup failure | HIA, HIB, SGA | `rule_lpa_wakeups` |
| `D9 0A` | Reset Reason Statistics | Power On, Brown Out 12/33, NVM, External, Watchdog, System Reset Request, Backup counters | `rule_lpa_resets` |
| `FE 02` / `FE 03` | Exceptional Reset Reason (+ Statistics) | Stack Overflow, Hard Fault, Watchdog, Panic | `rule_lpa_resets` |
| `FE 0B` | HPA boot chain confirmation timeout | threshold in seconds | `rule_lpa_resets` |
| `D0 79` | ECU Internal Failure Reason | CAN transceiver failure, FIST routine | not used yet |

## Not yet interpreted (candidates for new rules)

HPA `EE 40`/`EE 41`/`EE 42` (driver-initiated HPA reset attempts), `EF 51`/`EF 53` (clients requesting a
restart), `E4 00`/`E4 01` (wake-up events), `D9 46` (IST restart time probabilities), `EF F9` (IST failure
vehicle status record), `D9 2D` (IST failure monitor delay), `D0 D6`/`D0 D7` (HP thermal), SGA reset
histogram (`FD 41`) and reset reason (`FE 02`).
