#pragma once
#include <stddef.h>
#include <stdint.h>
/* PNG envelope + IHDR validator; not a pixel decoder. */
int inspect_png(const uint8_t *data, size_t size, int fixed, char *out, size_t capacity);
/* MCTTP 2026 R/W primitive demo: same single-malloc "companion buffer"
   construction as inspect_png's OOB-read leak, but with an attacker-chosen
   read/write offset, length and value instead of a fixed leak - a genuine
   controlled read/write primitive, bounded to PurrView's own buffer, that
   does not crash the worker. See parser.c for the exact wire format. */
int inspect_png_rw(const uint8_t *data, size_t size, char *out, size_t capacity);
/* Same R/W primitive and wire format as inspect_png_rw, but the companion
   buffer is a file inside PurrView's own already-private files directory
   (files_dir, e.g. getFilesDir()) instead of heap memory - the same bug
   chain reaching persistent storage rather than a process that is about to
   exit. Never escapes files_dir: the companion file name is fixed. */
int inspect_png_rw_file(const uint8_t *data, size_t size, const char *files_dir, char *out,
                         size_t capacity);
