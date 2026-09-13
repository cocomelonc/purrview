#pragma once

#include <stddef.h>

/* Decode a PPM/PGM file through libjpeg-turbo 2.0.4's cjpeg reader path. */
int decode_ppm_file(const char *path, char *out, size_t capacity);
