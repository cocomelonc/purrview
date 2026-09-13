#pragma once

#include <stddef.h>

int parse_purrview_pdu(const unsigned char *data, size_t size, int fixed,
                       char *out, size_t capacity);
