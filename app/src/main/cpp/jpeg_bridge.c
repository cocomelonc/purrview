#include "jpeg_bridge.h"

#include <android/log.h>
#include <ctype.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cdjpeg.h"

struct purr_jpeg_error {
  struct jpeg_error_mgr pub;
  jmp_buf jump;
};

#define JPEG_LOG_TAG "PurrView/JPEG"
#define JPEG_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, JPEG_LOG_TAG, __VA_ARGS__))
#define JPEG_LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, JPEG_LOG_TAG, __VA_ARGS__))

static int next_token(const unsigned char *data, size_t size, size_t *cursor,
                      char *token, size_t capacity) {
  size_t start;
  size_t length;
  if (data == NULL || cursor == NULL || token == NULL || capacity < 2) return 0;
  while (*cursor < size) {
    if (isspace(data[*cursor])) {
      (*cursor)++;
      continue;
    }
    if (data[*cursor] == '#') {
      while (*cursor < size && data[*cursor] != '\n') (*cursor)++;
      continue;
    }
    break;
  }
  if (*cursor >= size) return 0;
  start = *cursor;
  while (*cursor < size && !isspace(data[*cursor]) && data[*cursor] != '#') {
    (*cursor)++;
  }
  length = *cursor - start;
  if (length == 0 || length >= capacity) return 0;
  memcpy(token, data + start, length);
  token[length] = '\0';
  return 1;
}

/* Read-only fixture inspection for logcat. It identifies the exact input
 * relation that makes CVE-2020-13790 reachable without touching the decoder's
 * allocation. It is a diagnostic, not an attempt to reproduce the over-read
 * in this preflight code. */
static void log_ppm_preflight(FILE *input) {
  long end;
  size_t size;
  unsigned char *data;
  size_t cursor = 0;
  char magic[8], width_text[24], height_text[24], maxval_text[24];
  unsigned long width, height, maxval;

  if (fseek(input, 0, SEEK_END) != 0) return;
  end = ftell(input);
  if (end <= 0 || end > 256 * 1024L || fseek(input, 0, SEEK_SET) != 0) return;
  size = (size_t)end;
  data = (unsigned char *)malloc(size);
  if (data == NULL || fread(data, 1, size, input) != size) {
    free(data);
    (void)fseek(input, 0, SEEK_SET);
    return;
  }
  (void)fseek(input, 0, SEEK_SET);

  if (!next_token(data, size, &cursor, magic, sizeof(magic)) ||
      !next_token(data, size, &cursor, width_text, sizeof(width_text)) ||
      !next_token(data, size, &cursor, height_text, sizeof(height_text)) ||
      !next_token(data, size, &cursor, maxval_text, sizeof(maxval_text))) {
    JPEG_LOGW("preflight: unable to parse PPM header (bytes=%zu)", size);
    free(data);
    return;
  }
  width = strtoul(width_text, NULL, 10);
  height = strtoul(height_text, NULL, 10);
  maxval = strtoul(maxval_text, NULL, 10);
  JPEG_LOGI("preflight: magic=%s width=%lu height=%lu maxval=%lu bytes=%zu",
            magic, width, height, maxval, size);

  if (strcmp(magic, "P5") == 0 && maxval > 0 && maxval < 255 &&
      width > 0 && height > 0 && width <= 4096 && height <= 4096) {
    size_t pixels = width * height;
    while (cursor < size && isspace(data[cursor])) cursor++;
    if (pixels <= size - cursor) {
      size_t i;
      for (i = 0; i < pixels; i++) {
        if (data[cursor + i] > maxval) {
          JPEG_LOGW("CVE-2020-13790 candidate: P5 sample=%u exceeds maxval=%lu; "
                    "2.0.4 rescale table length=%lu (diagnostic only)",
                    (unsigned)data[cursor + i], maxval, maxval + 1);
          break;
        }
      }
      if (i == pixels) {
        JPEG_LOGI("preflight: no rescale index exceeds maxval");
      }
    }
  }
  free(data);
}

static void purr_error_exit(j_common_ptr cinfo) {
  struct purr_jpeg_error *error = (struct purr_jpeg_error *)cinfo->err;
  JPEG_LOGW("libjpeg error_exit reached; worker remains isolated");
  longjmp(error->jump, 1);
}

static void purr_silence(j_common_ptr cinfo) { (void)cinfo; }

int decode_ppm_file(const char *path, char *out, size_t capacity) {
  if (out == NULL || capacity == 0) return -1;
  if (path == NULL || path[0] == '\0') {
    snprintf(out, capacity, "REJECTED | no PPM path");
    return -1;
  }

  FILE *input = fopen(path, "rb");
  if (input == NULL) {
    JPEG_LOGW("cannot open fixture: %s", path);
    snprintf(out, capacity, "REJECTED | cannot open PPM fixture");
    return -1;
  }
  JPEG_LOGI("worker entering libjpeg-turbo 2.0.4 PPM reader: %s", path);
  log_ppm_preflight(input);

  struct jpeg_compress_struct cinfo;
  struct purr_jpeg_error error;
  cinfo.err = jpeg_std_error(&error.pub);
  error.pub.error_exit = purr_error_exit;
  error.pub.output_message = purr_silence;

  if (setjmp(error.jump)) {
    JPEG_LOGW("decoder returned a fatal error for the fixture");
    jpeg_destroy_compress(&cinfo);
    fclose(input);
    snprintf(out, capacity,
             "DECODER ERROR | libjpeg-turbo 2.0.4 | malformed PPM/PGM");
    return -1;
  }

  jpeg_create_compress(&cinfo);
  cjpeg_source_ptr source = jinit_read_ppm(&cinfo);
  if (source == NULL) {
    jpeg_destroy_compress(&cinfo);
    fclose(input);
    snprintf(out, capacity, "REJECTED | PPM reader unavailable");
    return -1;
  }
  source->input_file = input;

  /* start_input allocates the maxval-sized rescale table.  get_pixel_rows
   * then consumes pixels and exercises the 2.0.4 reader under test. */
  (*source->start_input)(&cinfo, source);
  JDIMENSION rows = 0;
  JDIMENSION limit = cinfo.image_height;
  if (limit > 4096) limit = 4096;
  while (rows < limit) {
    JDIMENSION read = (*source->get_pixel_rows)(&cinfo, source);
    if (read == 0) break;
    rows += read;
  }
  (*source->finish_input)(&cinfo, source);

  JPEG_LOGI("decoder completed: PPM %ux%u, rows=%u",
            (unsigned)cinfo.image_width, (unsigned)cinfo.image_height,
            (unsigned)rows);
  snprintf(out, capacity,
           "DECODED | libjpeg-turbo 2.0.4 | PPM %ux%u | rows %u | reader path",
           (unsigned)cinfo.image_width, (unsigned)cinfo.image_height,
           (unsigned)rows);
  jpeg_destroy_compress(&cinfo);
  fclose(input);
  return 0;
}
