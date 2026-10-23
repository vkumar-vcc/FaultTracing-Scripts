---
name: timesync-issue
description: "Use when: NVTIME_GTS_EPL_RMSG_TIMEOUT_LCK, NVTIME_GTS_EPL_RMSG_FAIL Team knowledge added from the investigation app."
---

# Timesync issue

_Added 2026-10-22 from investigation `20261022T092820_YV11SDAC6TB002188_6c4003`._

yes this reset seems to be caused by ptp packets lost, HPA gets the ptp time from external nodes( HIA through VESA in spa2, ZCLA through vesa in spa3). the reason why we dont have the dlt untill the reset timestamp is probably because the dlt streaming service does not get enough time to send out the dlt packets before HIA reset HPA. but there are apps in HPA which prints and monitors the current vehicle time( based on utc) and local time. check for anomalies in HPA, if HPA failed to read the ptp packets due to cpu load or something or if the sender did not send the packets. vesa to hpa is not exposed ethernet so you will never get pcap packets

## Engineer notes

Added by engineers from the investigation app. They refine the guidance above.

### Added 2026-10-22 from investigation `20261022T092820_YV11SDAC6TB002188_6c4003`.

Current vehicle time: 1970-02-12T00:14:50.169746Z, UTC time: 2026-10-09T11:16:01.26746Z this indicates ptp packet received, it is also printed on a constant interval, check if there is any anomaly on this, any big changes or no printouts, also the FSI error timestamp is when the issue happened. more weight on the timestamp close to FSI error. ptp error to reset is within ms , so looking at old logs is not that helpful. but old logs can indicate if there is any drift on incoming time
