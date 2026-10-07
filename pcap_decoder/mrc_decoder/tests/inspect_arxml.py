"""One-off: inspect an ARXML directory to understand the schema for the decoder.

Usage: python3 tests/inspect_arxml.py <arxml_dir_or_file>
Prints element frequency and a sample I-SIGNAL-I-PDU / mapping / socket structure.
"""

import collections
import glob
import os
import re
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "."
files = (
    [TARGET]
    if TARGET.endswith(".arxml")
    else sorted(glob.glob(os.path.join(TARGET, "*.arxml")))
)
print(f"ARXML files: {len(files)}")
for f in files:
    print(f"  {os.path.basename(f)}  ({os.path.getsize(f) // 1024} KB)")

if not files:
    sys.exit(0)

sample = files[0]
print(f"\n=== element frequency in {os.path.basename(sample)} ===")
text = open(sample, encoding="utf-8", errors="ignore").read()
freq = collections.Counter(re.findall(r"<([A-Z][A-Z0-9-]+)[ >]", text))
for tag, n in freq.most_common(40):
    print(f"{n:8d}  {tag}")

# Presence of the elements the decoder needs, across all files.
KEYS = [
    "I-SIGNAL-I-PDU",
    "I-SIGNAL-TO-I-PDU-MAPPING",
    "I-SIGNAL",
    "SYSTEM-SIGNAL",
    "COMPU-METHOD",
    "SOCKET-ADDRESS",
    "SOCKET-CONNECTION",
    "PDU-TRIGGERING",
    "SOCKET-CONNECTION-IPDU-IDENTIFIER",
    "APPLICATION-ENDPOINT",
    "UDP-TP",
    "CAN-FRAME",
    "CAN-FRAME-TRIGGERING",
    "ETHERNET-CLUSTER",
    "IPV-4-CONFIGURATION",
    "SO-AD-ROUTING-GROUP",
    "HEADER-ID",
    "START-POSITION",
    "PACKING-BYTE-ORDER",
    "COMPU-RATIONAL-COEFFS",
    "PDU-TO-FRAME-MAPPING",
]
print(f"\n=== key element presence across {len(files)} files ===")
for k in KEYS:
    total = 0
    present = 0
    for f in files:
        t = open(f, encoding="utf-8", errors="ignore").read()
        c = t.count(f"<{k}>") + t.count(f"<{k} ")
        total += c
        present += 1 if c else 0
    print(f"{k:38s} count={total:<8d} in {present}/{len(files)} files")


# Show one I-SIGNAL-I-PDU block and one socket block, if present.
def first_block(t, tag, maxlen=1600):
    m = re.search(rf"<{tag}[ >].*?</{tag}>", t, re.DOTALL)
    return m.group(0)[:maxlen] if m else None


for f in files:
    t = open(f, encoding="utf-8", errors="ignore").read()
    b = first_block(t, "I-SIGNAL-I-PDU")
    if b:
        print(f"\n=== sample I-SIGNAL-I-PDU ({os.path.basename(f)}) ===\n{b}")
        break
for f in files:
    t = open(f, encoding="utf-8", errors="ignore").read()
    b = first_block(t, "SOCKET-ADDRESS")
    if b:
        print(f"\n=== sample SOCKET-ADDRESS ({os.path.basename(f)}) ===\n{b}")
        break
