/* Local libFuzzer harness for the vendored libwebp 1.3.1 decoder.
 * It is deliberately a decoder-only target: no network, shell, or payload
 * loading is involved. Build this harness with AddressSanitizer enabled in
 * the library and harness to observe memory-safety diagnostics. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "webp/decode.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == NULL || size < 12 || size > 256u * 1024u ||
      memcmp(data, "RIFF", 4) != 0 || memcmp(data + 8, "WEBP", 4) != 0) {
    return 0;
  }
  WebPBitstreamFeatures features;
  if (WebPGetFeatures(data, size, &features) != VP8_STATUS_OK ||
      features.width <= 0 || features.height <= 0 || features.width > 1024 ||
      features.height > 1024) {
    return 0;
  }
  size_t output_size = (size_t)features.width * (size_t)features.height * 4u;
  uint8_t *output = (uint8_t *)malloc(output_size);
  if (output == NULL) return 0;
  (void)WebPDecodeRGBAInto(data, size, output, output_size, features.width * 4);
  free(output);
  return 0;
}
