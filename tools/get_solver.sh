#!/usr/bin/env bash
# Build a SAT solver into third_party/ for the differential analysis.
#
# CaDiCaL is the default: it is plain C++ with no dependencies, so it builds
# anywhere a compiler exists. The analysis talks DIMACS, so kissat, CryptoMiniSat or
# MiniSat work just as well if you already have one on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY="$ROOT/third_party"
SOLVER="${1:-cadical}"

mkdir -p "$THIRD_PARTY"

case "$SOLVER" in
  cadical)
    DIR="$THIRD_PARTY/cadical"
    if [ ! -d "$DIR" ]; then
      git clone --depth 1 https://github.com/arminbiere/cadical.git "$DIR"
    fi
    ( cd "$DIR" && ./configure && make -j"$(nproc)" )
    echo "built $DIR/build/cadical"
    "$DIR/build/cadical" --version
    ;;
  kissat)
    DIR="$THIRD_PARTY/kissat"
    if [ ! -d "$DIR" ]; then
      git clone --depth 1 https://github.com/arminbiere/kissat.git "$DIR"
    fi
    ( cd "$DIR" && ./configure && make -j"$(nproc)" )
    echo "built $DIR/build/kissat"
    ;;
  *)
    echo "unknown solver: $SOLVER (try cadical or kissat)" >&2
    exit 2
    ;;
esac
