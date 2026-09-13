#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CPP="$ROOT/app/src/main/cpp"
BUILD="$(mktemp -d "${TMPDIR:-/tmp}/purrview-png-fuzz-XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT

clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address \
  -I "$CPP" \
  "$ROOT/tools/fuzz_purrview_png.c" "$CPP/parser.c" -lz \
  -o "$BUILD/fuzz_purrview_png"

if [ $# -gt 0 ]; then
  echo "Running PurrView PNG parser against: $1"
  exec "$BUILD/fuzz_purrview_png" "$1"
fi

CORPUS="$BUILD/corpus"
mkdir -p "$CORPUS"
cp "$ROOT/app/src/main/assets/purrview-oob.png" "$CORPUS/" 2>/dev/null || true
echo "Fuzzing PurrView PNG parser for ${MAX_TOTAL_TIME:-30}s: $BUILD/fuzz_purrview_png"
"$BUILD/fuzz_purrview_png" "$CORPUS" -max_total_time="${MAX_TOTAL_TIME:-30}"
