/* Decoder-only host harness for libjpeg-turbo 2.0.4's PPM reader.
 * It is deliberately a single-input runner so ASan can show the historical
 * CVE-2020-13790 read in a reproducible conference rehearsal. */

#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cdjpeg.h"

struct purr_error {
  struct jpeg_error_mgr pub;
  jmp_buf jump;
};

static void error_exit(j_common_ptr cinfo) {
  struct purr_error *error = (struct purr_error *)cinfo->err;
  longjmp(error->jump, 1);
}

static void silence(j_common_ptr cinfo) { (void)cinfo; }

static int run_input(const uint8_t *data, size_t size) {
  struct jpeg_compress_struct cinfo;
  struct purr_error error;
  cinfo.err = jpeg_std_error(&error.pub);
  error.pub.error_exit = error_exit;
  error.pub.output_message = silence;
  if (setjmp(error.jump)) {
    jpeg_destroy_compress(&cinfo);
    return 0;
  }
  jpeg_create_compress(&cinfo);
  FILE *input = fmemopen((void *)data, size, "rb");
  if (input == NULL) {
    jpeg_destroy_compress(&cinfo);
    return 0;
  }
  cjpeg_source_ptr source = jinit_read_ppm(&cinfo);
  source->input_file = input;
  (*source->start_input)(&cinfo, source);
  JDIMENSION rows = 0;
  JDIMENSION limit = cinfo.image_height > 4096 ? 4096 : cinfo.image_height;
  while (rows < limit) {
    JDIMENSION read = (*source->get_pixel_rows)(&cinfo, source);
    if (read == 0) break;
    rows += read;
  }
  (*source->finish_input)(&cinfo, source);
  fclose(input);
  jpeg_destroy_compress(&cinfo);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s fixture.pgm\n", argv[0]);
    return 2;
  }
  FILE *input = fopen(argv[1], "rb");
  if (input == NULL) return 2;
  if (fseek(input, 0, SEEK_END) != 0) {
    fclose(input);
    return 2;
  }
  long end = ftell(input);
  if (end <= 0 || end > (1 << 20) || fseek(input, 0, SEEK_SET) != 0) {
    fclose(input);
    return 2;
  }
  size_t size = (size_t)end;
  uint8_t *data = (uint8_t *)malloc(size);
  if (data == NULL || fread(data, 1, size, input) != size) {
    free(data);
    fclose(input);
    return 2;
  }
  fclose(input);
  int result = run_input(data, size);
  free(data);
  return result;
}
