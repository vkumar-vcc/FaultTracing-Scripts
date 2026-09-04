#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir"

usage() {
  cat <<'EOF'
Usage: ./run.sh <tool> [arguments]

Tools:
  confighub  ConfigHub part lookup
  can        CAN BLF/ASC decoder and signal viewer
  nuc        NUC DLT downloader
  sat        SAT readout decoder
  standby    Standby decoder

Examples:
  ./run.sh confighub 32477281IMJ
  ./run.sh can log.blf --map can_decoder/channels.txt
  ./run.sh nuc --help
  ./run.sh standby --input-file hp_coldboot.log
EOF
}

tool="${1:-}"
if [[ -z "$tool" || "$tool" == "-h" || "$tool" == "--help" || "$tool" == "help" ]]; then
  usage
  exit 0
fi
shift

case "${tool,,}" in
  confighub)
    exec uv run python confighub_lookup.py "$@"
    ;;
  can)
    exec "$script_dir/can_decoder/run.sh" "$@"
    ;;
  nuc)
    exec uv run python download_combine_NUC_dlt/download_combine_NUC_dlt.py "$@"
    ;;
  sat)
    exec uv run python SAT_Readout_decoder/SAT_Readout_decoder.py "$@"
    ;;
  standby)
    exec uv run python standby-decoder/hpa_stanby_decoder.py "$@"
    ;;
  *)
    usage >&2
    echo "Unknown tool: $tool" >&2
    exit 2
    ;;
esac