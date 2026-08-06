#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-$(pwd)}"
ROOT_DIR="$(cd "$ROOT_DIR" && pwd)"
TCL_FILE="${ROOT_DIR}/build_gowin.tcl"

if [[ ! -f "$TCL_FILE" ]]; then
  echo "ERROR: Tcl build script not found: $TCL_FILE" >&2
  exit 1
fi

LOG_FILE="${LOG_FILE:-${ROOT_DIR}/gowin_build_$(date +%Y%m%d_%H%M%S).log}"

GOWIN="${GOWIN:-$HOME/gowin/Gowin_V1.9.12.02_linux}"
GW_SH="${GW_SH:-${GOWIN}/IDE/bin/gw_sh}"
if [[ ! -x "$GW_SH" ]]; then
  echo "ERROR: Gowin shell not found or not executable: $GW_SH" >&2
  echo "Set GOWIN to your IDE directory (contains IDE/bin/gw_sh)." >&2
  exit 1
fi

echo "Running Gowin Shell: $GW_SH"
echo "Project root: $ROOT_DIR"
echo "Tcl script:    $TCL_FILE"
echo "Log:           $LOG_FILE"

(
  export LD_LIBRARY_PATH="$GOWIN/IDE/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export QT_PLUGIN_PATH="$GOWIN/IDE/plugins/qt"
  export QT_QPA_PLATFORM_PLUGIN_PATH="$GOWIN/IDE/plugins/qt/platforms"
  export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-minimal}"
  export QT_OPENGL="${QT_OPENGL:-software}"
  export LIBGL_ALWAYS_SOFTWARE="${LIBGL_ALWAYS_SOFTWARE:-1}"
  export QT_QUICK_BACKEND="${QT_QUICK_BACKEND:-software}"
  "$GW_SH" "$TCL_FILE"
) 2>&1 | tee "$LOG_FILE"

PNR_DIR="${ROOT_DIR}/impl/pnr"
if [[ ! -d "$PNR_DIR" ]]; then
  echo "ERROR: PNR output directory not found: $PNR_DIR" >&2
  exit 1
fi

LATEST_FS="$(find "$PNR_DIR" -maxdepth 1 -name '*.fs' -type f -printf '%T@\t%p\n' 2>/dev/null | sort -n | tail -1 | cut -f2-)"
if [[ -z "$LATEST_FS" || ! -f "$LATEST_FS" ]]; then
  echo "ERROR: No .fs bitstream found in $PNR_DIR" >&2
  exit 1
fi

echo "Bitstream: $LATEST_FS"
