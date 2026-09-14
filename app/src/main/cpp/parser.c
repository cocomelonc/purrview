#include "parser.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#ifdef __ANDROID__
#include <android/log.h>
#define PNG_LOG_TAG "PurrView/PNG"
#define PNG_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, PNG_LOG_TAG, __VA_ARGS__))
#define PNG_LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, PNG_LOG_TAG, __VA_ARGS__))
#define PNG_LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, PNG_LOG_TAG, __VA_ARGS__))
#else
#define PNG_LOGI(...) ((void)fprintf(stderr, __VA_ARGS__))
#define PNG_LOGW(...) ((void)fprintf(stderr, __VA_ARGS__))
#define PNG_LOGE(...) ((void)fprintf(stderr, __VA_ARGS__))
#endif

static uint32_t be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static int fail(char *out, size_t cap, const char *why) {
  snprintf(out, cap, "REJECTED | %s", why);
  return -1;
}

/* MCTTP 2026 leak demo: a fixed secret PurrView itself places right after the
   narrow allocation below, so the OOB-read leak stays 100% reproducible on
   stage regardless of Scudo's chunk layout -- it is PurrView's own harness,
   not heap grooming, guaranteeing what sits on the other side of the bound
   the parser failed to check. */
static const char kPurrLeakSecret[] = "meow-meow MCTTP 2026";

int inspect_png(const uint8_t *d, size_t n, int fixed, char *out, size_t cap) {
  const uint8_t sig[8] = {137, 80, 78, 71, 13, 10, 26, 10};
  if (n < 8 || n > 1048576 || memcmp(d, sig, 8))
    return fail(out, cap, "Invalid PNG signature or file size");
  size_t pos = 8;
  uint32_t w = 0, h = 0;
  int header = 0, idat = 0, end = 0;
  const uint8_t *purr_payload = NULL;
  size_t purr_payload_len = 0;
  while (pos < n) {
    if (n - pos < 12) return fail(out, cap, "Truncated chunk");
    uint32_t len = be32(d + pos);
    const uint8_t *type = d + pos + 4;
    const uint8_t *body = d + pos + 8;
    if (len > n - pos - 12) return fail(out, cap, "Chunk exceeds file bounds");
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, type, 4);
    crc = crc32(crc, body, len);
    if ((uint32_t)crc != be32(body + len)) return fail(out, cap, "CRC mismatch");
    if (!header && memcmp(type, "IHDR", 4)) return fail(out, cap, "IHDR must be first");
    if (!memcmp(type, "IHDR", 4)) {
      if (header || len != 13) return fail(out, cap, "Invalid IHDR");
      w = be32(body);
      h = be32(body + 4);
      header = 1;
      if (!w || !h || w > 16384 || h > 16384 || body[8] != 8 || body[9] != 6 || body[10] ||
          body[11] || body[12])
        return fail(out, cap, "PurrView supports RGBA8, non-interlaced, dimensions 1..16384");
    } else if (!memcmp(type, "IDAT", 4)) {
      idat = 1;
    } else if (!memcmp(type, "IEND", 4)) {
      if (len || !idat) return fail(out, cap, "Invalid IEND");
      end = 1;
      pos += 12;
      break;
    } else if (!memcmp(type, "pCAT", 4)) {
      /* pCAT is an inert ancillary chunk used only by the PurrView fixture. */
      purr_payload = body;
      purr_payload_len = (size_t)len;
    } else if (!(type[0] & 32)) return fail(out, cap, "Unsupported critical chunk");
    pos += (size_t)len + 12;
  }
  if (!end || pos != n) return fail(out, cap, "Missing IEND or trailing bytes");
  uint64_t actual = (uint64_t)w * h * 4;
  /* The vulnerable path intentionally narrows the allocation size, then uses
     the full image size for a copy. It exists only in the PurrView worker. */
  uint64_t checked = fixed ? actual : (uint16_t)actual;
  int accepted = checked <= 32768;
  int bypass = accepted && actual > 32768;
  if (bypass && purr_payload != NULL && purr_payload_len >= actual) {
    size_t allocation = checked == 0 ? 1u : (size_t)checked;
    size_t secret_len = sizeof(kPurrLeakSecret);
    uint8_t *pixels = (uint8_t *)malloc(allocation + secret_len);
    if (pixels == NULL) return fail(out, cap, "PurrView parser allocation failed");
    memcpy(pixels + allocation, kPurrLeakSecret, secret_len);

    char leak[sizeof(kPurrLeakSecret)];
    memcpy(leak, pixels + allocation, sizeof(leak));
    PNG_LOGE("OOB READ | PurrView parser | validated=%zu leaked=%zu bytes past boundary",
             allocation, sizeof(leak));
    PNG_LOGE("OOB READ leak: %s", leak);

    PNG_LOGE("OOB WRITE | PurrView parser | allocation=%zu copy=%llu source=%zu",
             allocation, (unsigned long long)actual, purr_payload_len);
    PNG_LOGE("memcpy(dst=%p, src=%p, len=%llu) about to cross allocation boundary",
             (void *)pixels, (const void *)purr_payload,
             (unsigned long long)actual);
    memcpy(pixels, purr_payload, (size_t)actual);
    PNG_LOGE("OOB WRITE completed | aborting PNG worker before corrupted heap is reused");
    raise(SIGABRT);
    return -1;
  }
  if (fixed && purr_payload != NULL && purr_payload_len >= actual) {
    uint8_t *pixels = (uint8_t *)malloc((size_t)actual);
    if (pixels == NULL) return fail(out, cap, "PurrView parser allocation failed");
    memcpy(pixels, purr_payload, (size_t)actual);
    PNG_LOGI("FIXED COPY | PurrView parser | allocation=%llu copy=%llu",
             (unsigned long long)actual, (unsigned long long)actual);
    free(pixels);
  }
  snprintf(out, cap,
           "%s | %ux%u RGBA8\nRequired: %llu bytes\nChecked: %llu bytes\nBudget: 32768 bytes\n%s\n%s",
           fixed ? "FIXED SAFE" : bypass ? "BUDGET BYPASS" : accepted ? "ACCEPTED" : "REJECTED",
           w, h, (unsigned long long)actual, (unsigned long long)checked,
           fixed ? "Fixed: B = uint64(W) * H * 4" : "Buggy: B = (W * H * 4) mod 65536",
           fixed ? "Bounded copy completed."
                 : bypass ? "Native validation defect reproduced in PurrView parser."
                          : "Parser completed.");
  return bypass ? 1 : accepted ? 0 : 2;
}
