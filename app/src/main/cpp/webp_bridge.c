#include "webp_bridge.h"

#include <android/log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webp/decode.h"

#define WEBP_LOG_TAG "PurrView/WebP"
#define WEBP_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, WEBP_LOG_TAG, __VA_ARGS__))
#define WEBP_LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, WEBP_LOG_TAG, __VA_ARGS__))

int decode_webp_vulnerable(const uint8_t *data, size_t size,
                           char *out, size_t capacity) {
  if (data == NULL || out == NULL || capacity == 0 || size < 12 ||
      size > 256u * 1024u || memcmp(data, "RIFF", 4) != 0 ||
      memcmp(data + 8, "WEBP", 4) != 0) {
    if (out != NULL && capacity != 0) {
      snprintf(out, capacity, "REJECTED | not a bounded WebP input");
    }
    WEBP_LOGW("preflight rejected input: bytes=%zu", size);
    return -1;
  }

  WebPBitstreamFeatures features;
  WEBP_LOGI("worker entering libwebp 1.3.1 decoder: bytes=%zu", size);
  VP8StatusCode status = WebPGetFeatures(data, size, &features);
  if (status != VP8_STATUS_OK || features.width <= 0 ||
      features.height <= 0 || features.width > 1024 || features.height > 1024) {
    snprintf(out, capacity, "REJECTED | WebP feature validation (%d)", status);
    WEBP_LOGW("feature validation failed: status=%d", status);
    return -1;
  }

  uint64_t output_size = (uint64_t)features.width *
                         (uint64_t)features.height * 4u;
  if (output_size > 4u * 1024u * 1024u) {
    snprintf(out, capacity, "REJECTED | decoded output exceeds 4 MiB");
    return -1;
  }
  uint8_t *pixels = (uint8_t *)malloc((size_t)output_size);
  if (pixels == NULL) {
    snprintf(out, capacity, "REJECTED | output allocation failed");
    return -1;
  }

  /* The 1.3.1 lossless decoder is the actual library under test. No callback,
   * code loading, shell, or post-decode execution is attached to this call. */
  uint8_t *decoded = WebPDecodeRGBAInto(
      data, size, pixels, (size_t)output_size, features.width * 4);
  int result = decoded != NULL ? 0 : -1;
  if (result == 0) {
    WEBP_LOGI("decoder completed: %dx%d format=%d", features.width,
              features.height, features.format);
  } else {
    WEBP_LOGW("decoder returned an error: %dx%d format=%d", features.width,
              features.height, features.format);
  }
  snprintf(out, capacity, "%s | libwebp 1.3.1 | %dx%d | VP8%s",
           result == 0 ? "DECODED" : "DECODER ERROR", features.width,
           features.height, features.format == 2 ? "L" : "");
  free(pixels);
  return result;
}
