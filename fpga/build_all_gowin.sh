#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN_DIR="${GEN_DIR:-${ROOT_DIR}/fpga/generated}"
MODULES_FILE="${GEN_DIR}/modules.txt"

if [[ ! -f "$MODULES_FILE" ]]; then
  echo "ERROR: modules list not found: $MODULES_FILE" >&2
  echo "Run make fpga-generate first." >&2
  exit 1
fi

while IFS= read -r mod; do
  [[ -n "$mod" ]] || continue
  project_dir="${GEN_DIR}/gowin/${mod}"
  echo "== Gowin ${mod}"
  LOG_FILE="${project_dir}/gowin_build.log" "${ROOT_DIR}/fpga/run_gowin_build.sh" "$project_dir"
done < "$MODULES_FILE"
