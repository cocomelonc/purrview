#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FIXTURE=${1:-"$ROOT/app/src/main/assets/poc.pgm"}
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/purrview-jpeg-asan.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT HUP INT TERM

# Keep the checked-in source untouched.  The lab's allocator-slab tweak makes
# ASan's redzone visible for this small (<=254 byte) historical over-read.
SRC="$BUILD/libjpeg-turbo-2.0.4"
cp -a "$ROOT/app/src/main/cpp/third_party/libjpeg-turbo-2.0.4/." "$SRC/"
sed -i 's/16000[[:space:]]*\/\* first IMAGE pool \*\//0                         \/\* first IMAGE pool \*\//; s/5000[[:space:]]*\/\* additional IMAGE pools \*\//0                          \/\* additional IMAGE pools \*\//' "$SRC/jmemmgr.c"

if [ ! -f "$FIXTURE" ]; then
  echo "fixture not found: $FIXTURE" >&2
  exit 2
fi

cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DENABLE_SHARED=OFF \
  -DENABLE_STATIC=ON \
  -DWITH_TURBOJPEG=OFF \
  -DWITH_SIMD=OFF \
  -DWITH_ARITH_ENC=OFF \
  -DWITH_ARITH_DEC=OFF \
  -DWITH_MEM_SRCDST=OFF \
  -DCMAKE_INSTALL_DOCDIR=share/doc/libjpeg-turbo \
  -DCMAKE_INSTALL_MANDIR=share/man \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build "$BUILD" --target jpeg-static

cc -std=c11 -D_GNU_SOURCE -DPPM_SUPPORTED \
  -fsanitize=address,undefined -fno-omit-frame-pointer -g \
  -I"$BUILD" -I"$SRC" \
  "$ROOT/tools/fuzz_ppm.c" "$SRC/rdppm.c" "$BUILD/libjpeg.a" \
  -o "$BUILD/fuzz_ppm"
ASAN_OPTIONS=detect_leaks=0 "$BUILD/fuzz_ppm" "$FIXTURE"
