/* Local libFuzzer harness for PurrView's own PNG envelope parser
 * (app/src/main/cpp/parser.c). It calls the same inspect_png() entry point
 * the Android :png_decoder worker uses, with fixed=0 to exercise the
 * vulnerable integer-narrowing path. Decoder-only: no network, shell, or
 * payload loading is involved. */
#include <stddef.h>
#include <stdint.h>

#include "parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == NULL || size < 8 || size > 1024u * 1024u) return 0;
  char out[1024];
  (void)inspect_png(data, size, /*fixed=*/0, out, sizeof(out));
  return 0;
}
