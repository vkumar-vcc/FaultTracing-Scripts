#!/usr/bin/env bash
# Batch-decode all SPA2 eth_v2 pcapng captures in a directory.
# Usage: batch_decode.sh <in_dir> <out_dir> [max_files] [routing_table]
set -o pipefail

IN="${1:?input dir}"
OUT="${2:?output dir}"
MAX="${3:-0}"          # 0 = all
RT="${4:-}"            # optional forced TC-*.yml (name); empty = auto per file

cd /mnt/c/Users/VKUMAR36/workspace/nuc-logger/mrc_decoder
. .venv/bin/activate
mkdir -p "$OUT"
cd python  # spa2_decoder package lives here

mapfile -t FILES < <(ls -1 "$IN"/*.pcapng 2>/dev/null | sort)
total=${#FILES[@]}
echo "found $total pcapng files"

i=0
ok=0
for f in "${FILES[@]}"; do
  i=$((i + 1))
  if [ "$MAX" -gt 0 ] && [ "$i" -gt "$MAX" ]; then break; fi
  base="$(basename "$f")"
  # Stop early if the disk is getting tight (< 5 GiB free).
  avail_kb="$(df --output=avail /mnt/c | tail -1 | tr -d ' ')"
  if [ "$avail_kb" -lt 5242880 ]; then
    echo "!! low disk ($((avail_kb / 1024)) MiB free) - stopping before [$i] $base"
    break
  fi
  echo "=== [$i/$total] $base (free: $((avail_kb / 1048576)) GiB) ==="
  if python -m spa2_decoder "$f" -o "$OUT" ${RT:+--routing-table "$RT"} 2>/tmp/dec_err \
      | grep -Ei "routed_frames|decoded_frames|unknown_frame|unique_signals"; then
    ok=$((ok + 1))
    mf4="$OUT/${base%.pcapng}_MRCDECODED.mf4"
    [ -f "$mf4" ] && echo "  mf4 size: $(du -h "$mf4" | cut -f1)"
  else
    echo "  FAILED:"; tail -3 /tmp/dec_err
  fi
done
echo "done: decoded $ok/$i processed (of $total total)"
