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

/* Shared envelope walk used by both inspect_png and inspect_png_rw: PNG
   signature, chunk-by-chunk CRC/bounds checks, IHDR, and locating the
   inert pCAT ancillary chunk PurrView's own fixtures carry. */
static int parse_envelope(const uint8_t *d, size_t n, char *out, size_t cap, uint32_t *w_out,
                           uint32_t *h_out, const uint8_t **purr_payload_out,
                           size_t *purr_payload_len_out) {
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
  *w_out = w;
  *h_out = h;
  *purr_payload_out = purr_payload;
  *purr_payload_len_out = purr_payload_len;
  return 0;
}

int inspect_png(const uint8_t *d, size_t n, int fixed, char *out, size_t cap) {
  uint32_t w, h;
  const uint8_t *purr_payload;
  size_t purr_payload_len;
  if (parse_envelope(d, n, out, cap, &w, &h, &purr_payload, &purr_payload_len) != 0) return -1;
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

/* MCTTP 2026 R/W primitive demo: PurrView's own harness allocates a small,
   fixed "companion" region right after a small, fixed allocation - the same
   single-malloc-block trick as the OOB-read leak above, so this stays
   PurrView's own construction, not heap grooming or cross-chunk corruption.
   The pCAT chunk (already fully attacker-controlled, same as the OOB-write
   payload above) is interpreted as a 5-byte request instead of raw pixel
   bytes: [read_offset][read_len][write_offset][write_len][write_byte], each
   one byte, read/write windows bounded to the companion buffer. Unlike
   inspect_png's bypass path this never raises SIGABRT - the point is a
   primitive that is actually usable, not a one-shot crash. */
#define PURR_RW_COMPANION_SIZE 64u

typedef struct {
  uint8_t read_offset;
  uint8_t read_len;
  uint8_t write_offset;
  uint8_t write_len;
  uint8_t write_byte;
} purr_rw_request;

static int parse_rw_request(const uint8_t *body, size_t body_len, purr_rw_request *req) {
  if (body_len != 5) return -1;
  req->read_offset = body[0];
  req->read_len = body[1];
  req->write_offset = body[2];
  req->write_len = body[3];
  req->write_byte = body[4];
  if (req->read_len == 0 || req->write_len == 0) return -1;
  if ((size_t)req->read_offset + req->read_len > PURR_RW_COMPANION_SIZE) return -1;
  if ((size_t)req->write_offset + req->write_len > PURR_RW_COMPANION_SIZE) return -1;
  return 0;
}

static void hex_encode(const uint8_t *data, size_t len, char *out, size_t cap) {
  static const char digits[] = "0123456789abcdef";
  size_t max = (cap - 1) / 2;
  if (len > max) len = max;
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = digits[data[i] >> 4];
    out[i * 2 + 1] = digits[data[i] & 0xF];
  }
  out[len * 2] = 0;
}

int inspect_png_rw(const uint8_t *d, size_t n, char *out, size_t cap) {
  uint32_t w, h;
  const uint8_t *purr_payload;
  size_t purr_payload_len;
  if (parse_envelope(d, n, out, cap, &w, &h, &purr_payload, &purr_payload_len) != 0) return -1;
  (void)w;
  (void)h;

  purr_rw_request req;
  if (purr_payload == NULL || parse_rw_request(purr_payload, purr_payload_len, &req) != 0)
    return fail(out, cap, "pCAT must carry a valid 5-byte R/W request within the 64-byte "
                           "companion buffer");

  size_t allocation = 16;
  uint8_t *buf = (uint8_t *)malloc(allocation + PURR_RW_COMPANION_SIZE);
  if (buf == NULL) return fail(out, cap, "PurrView parser allocation failed");
  memset(buf, 0, allocation);
  uint8_t *companion = buf + allocation;
  memcpy(companion, kPurrLeakSecret, sizeof(kPurrLeakSecret));
  memset(companion + sizeof(kPurrLeakSecret), 0xAA,
         PURR_RW_COMPANION_SIZE - sizeof(kPurrLeakSecret));

  char before_hex[PURR_RW_COMPANION_SIZE * 2 + 1];
  hex_encode(companion + req.read_offset, req.read_len, before_hex, sizeof(before_hex));
  PNG_LOGE("RW READ | PurrView parser | offset=%u len=%u bytes=%s", req.read_offset,
           req.read_len, before_hex);

  memset(companion + req.write_offset, req.write_byte, req.write_len);
  PNG_LOGE("RW WRITE | PurrView parser | offset=%u len=%u byte=0x%02x", req.write_offset,
           req.write_len, req.write_byte);

  char after_hex[PURR_RW_COMPANION_SIZE * 2 + 1];
  hex_encode(companion + req.read_offset, req.read_len, after_hex, sizeof(after_hex));
  PNG_LOGE("RW READBACK | PurrView parser | offset=%u len=%u bytes=%s", req.read_offset,
           req.read_len, after_hex);

  free(buf);
  snprintf(out, cap,
           "RW PRIMITIVE | PurrView parser\n"
           "read  [off=%u len=%u] -> %s\n"
           "write [off=%u len=%u byte=0x%02x]\n"
           "read  [off=%u len=%u] -> %s (after write)",
           req.read_offset, req.read_len, before_hex, req.write_offset, req.write_len,
           req.write_byte, req.read_offset, req.read_len, after_hex);
  return 0;
}

/* Same primitive and wire format as inspect_png_rw, but backed by a file
   inside PurrView's own already-private files directory instead of heap
   memory - persistent storage rather than a process about to exit. The
   companion file is (re)created fresh on every call, same as the heap
   version's fresh malloc, so the demo stays deterministic call to call. The
   file name is fixed; files_dir (the app's own getFilesDir()) is the only
   directory ever touched. */
int inspect_png_rw_file(const uint8_t *d, size_t n, const char *files_dir, char *out,
                         size_t cap) {
  uint32_t w, h;
  const uint8_t *purr_payload;
  size_t purr_payload_len;
  if (parse_envelope(d, n, out, cap, &w, &h, &purr_payload, &purr_payload_len) != 0) return -1;
  (void)w;
  (void)h;

  purr_rw_request req;
  if (purr_payload == NULL || parse_rw_request(purr_payload, purr_payload_len, &req) != 0)
    return fail(out, cap, "pCAT must carry a valid 5-byte R/W request within the 64-byte "
                           "companion buffer");

  if (files_dir == NULL) return fail(out, cap, "PurrView parser missing files_dir");
  char path[512];
  int written = snprintf(path, sizeof(path), "%s/purrview-rw-companion.bin", files_dir);
  if (written < 0 || (size_t)written >= sizeof(path))
    return fail(out, cap, "PurrView parser files_dir path too long");

  uint8_t companion[PURR_RW_COMPANION_SIZE];
  memcpy(companion, kPurrLeakSecret, sizeof(kPurrLeakSecret));
  memset(companion + sizeof(kPurrLeakSecret), 0xAA,
         PURR_RW_COMPANION_SIZE - sizeof(kPurrLeakSecret));

  FILE *fp = fopen(path, "wb");
  if (fp == NULL) return fail(out, cap, "PurrView parser could not create companion file");
  size_t wrote = fwrite(companion, 1, sizeof(companion), fp);
  fclose(fp);
  if (wrote != sizeof(companion))
    return fail(out, cap, "PurrView parser companion file write failed");

  fp = fopen(path, "r+b");
  if (fp == NULL) return fail(out, cap, "PurrView parser could not open companion file");

  uint8_t io_buf[PURR_RW_COMPANION_SIZE];
  if (fseek(fp, req.read_offset, SEEK_SET) != 0 ||
      fread(io_buf, 1, req.read_len, fp) != req.read_len) {
    fclose(fp);
    return fail(out, cap, "PurrView parser companion file read failed");
  }
  char before_hex[PURR_RW_COMPANION_SIZE * 2 + 1];
  hex_encode(io_buf, req.read_len, before_hex, sizeof(before_hex));
  PNG_LOGE("RW FILE READ | PurrView parser | path=%s offset=%u len=%u bytes=%s", path,
           req.read_offset, req.read_len, before_hex);

  memset(io_buf, req.write_byte, req.write_len);
  if (fseek(fp, req.write_offset, SEEK_SET) != 0 ||
      fwrite(io_buf, 1, req.write_len, fp) != req.write_len) {
    fclose(fp);
    return fail(out, cap, "PurrView parser companion file write failed");
  }
  fflush(fp);
  PNG_LOGE("RW FILE WRITE | PurrView parser | path=%s offset=%u len=%u byte=0x%02x", path,
           req.write_offset, req.write_len, req.write_byte);

  if (fseek(fp, req.read_offset, SEEK_SET) != 0 ||
      fread(io_buf, 1, req.read_len, fp) != req.read_len) {
    fclose(fp);
    return fail(out, cap, "PurrView parser companion file readback failed");
  }
  fclose(fp);
  char after_hex[PURR_RW_COMPANION_SIZE * 2 + 1];
  hex_encode(io_buf, req.read_len, after_hex, sizeof(after_hex));
  PNG_LOGE("RW FILE READBACK | PurrView parser | path=%s offset=%u len=%u bytes=%s", path,
           req.read_offset, req.read_len, after_hex);

  snprintf(out, cap,
           "RW PRIMITIVE (file) | PurrView parser\n"
           "path  %s\n"
           "read  [off=%u len=%u] -> %s\n"
           "write [off=%u len=%u byte=0x%02x]\n"
           "read  [off=%u len=%u] -> %s (after write)",
           path, req.read_offset, req.read_len, before_hex, req.write_offset, req.write_len,
           req.write_byte, req.read_offset, req.read_len, after_hex);
  return 0;
}
