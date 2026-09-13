#pragma once

#include <stddef.h>
#include <stdint.h>

/* Decode through the vendored libwebp 1.3.1 API. This is intentionally a
 * vulnerable lab build; the caller supplies a process boundary. */
int decode_webp_vulnerable(const uint8_t *data, size_t size,
                           char *out, size_t capacity);
