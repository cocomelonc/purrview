#pragma once
#include <stddef.h>
#include <stdint.h>
/* PNG envelope + IHDR validator; not a pixel decoder. */
int inspect_png(const uint8_t *data, size_t size, int fixed, char *out, size_t capacity);
