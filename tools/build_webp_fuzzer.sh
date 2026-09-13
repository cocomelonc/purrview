#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$ROOT/app/src/main/cpp/third_party/libwebp-1.3.1"
BUILD="$(mktemp -d "${TMPDIR:-/tmp}/purrview-webp-XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT

cmake -S "$SOURCE" -B "$BUILD" -DCMAKE_C_COMPILER=clang \
  -DCMAKE_C_FLAGS='-fsanitize=fuzzer-no-link,address -g -O1 -fno-omit-frame-pointer' \
  -DBUILD_SHARED_LIBS=OFF -DWEBP_BUILD_ANIM_UTILS=OFF \
  -DWEBP_BUILD_CWEBP=OFF -DWEBP_BUILD_DWEBP=OFF \
  -DWEBP_BUILD_GIF2WEBP=OFF -DWEBP_BUILD_IMG2WEBP=OFF \
  -DWEBP_BUILD_VWEBP=OFF -DWEBP_BUILD_WEBPINFO=OFF \
  -DWEBP_BUILD_LIBWEBPMUX=OFF -DWEBP_BUILD_WEBPMUX=OFF \
  -DWEBP_BUILD_EXTRAS=OFF
cmake --build "$BUILD" --target webp -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address \
  -I "$SOURCE/src" "$ROOT/tools/fuzz_webp.c" "$BUILD/libwebp.a" -lm \
  -o "$BUILD/fuzz_webp_vulnerable"

INPUT="${1:-$ROOT/app/src/main/assets/bad.webp}"
echo "Running libwebp 1.3.1 against: $INPUT"
"$BUILD/fuzz_webp_vulnerable" "$INPUT"
