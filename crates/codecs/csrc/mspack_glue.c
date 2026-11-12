/*
 * Glue between fastoneday and libmspack's LZX decoder (lzxd.c).
 *
 * libmspack performs all I/O through a `struct mspack_system`. This file
 * provides one whose read/write calls go to callbacks supplied by Rust, so
 * the compressed CAB stream can come from a local file, a nested cabinet or
 * an HTTP range source without temporary files.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "system.h"
#include "lzx.h"

typedef int (*fod_read_fn)(void *ctx, void *buffer, int bytes);
typedef int (*fod_write_fn)(void *ctx, const void *buffer, int bytes);

/* Stands in for libmspack's opaque `struct mspack_file`. */
struct fod_file {
    void *ctx;
    fod_read_fn read;
    fod_write_fn write;
};

struct fod_lzx {
    struct mspack_system sys;
    struct fod_file file;
    struct lzxd_stream *stream;
};

static int fod_read(struct mspack_file *file, void *buffer, int bytes) {
    struct fod_file *f = (struct fod_file *) file;
    return f->read(f->ctx, buffer, bytes);
}

static int fod_write(struct mspack_file *file, void *buffer, int bytes) {
    struct fod_file *f = (struct fod_file *) file;
    return f->write(f->ctx, buffer, bytes);
}

static void *fod_alloc(struct mspack_system *self, size_t bytes) {
    (void) self;
    return malloc(bytes);
}

static void fod_free(void *ptr) {
    free(ptr);
}

/* libmspack's copy() takes (source, destination, length). */
static void fod_copy(void *src, void *dest, size_t bytes) {
    memmove(dest, src, bytes);
}

static void fod_message(struct mspack_file *file, const char *format, ...) {
    (void) file;
    (void) format;
}

struct fod_lzx *fod_lzx_new(void *ctx, fod_read_fn read, fod_write_fn write,
                            int window_bits, int reset_interval,
                            long long output_length) {
    struct fod_lzx *s = (struct fod_lzx *) calloc(1, sizeof(*s));
    if (!s) return NULL;
    /* open/close/seek/tell are never called by lzxd. */
    s->sys.read = &fod_read;
    s->sys.write = &fod_write;
    s->sys.alloc = &fod_alloc;
    s->sys.free = &fod_free;
    s->sys.copy = &fod_copy;
    s->sys.message = &fod_message;
    s->file.ctx = ctx;
    s->file.read = read;
    s->file.write = write;
    /* Same parameters libmspack's own CAB extractor (cabd.c) uses. */
    s->stream = lzxd_init(&s->sys, (struct mspack_file *) &s->file,
                          (struct mspack_file *) &s->file, window_bits,
                          reset_interval, 4096, (off_t) output_length, 0);
    if (!s->stream) {
        free(s);
        return NULL;
    }
    return s;
}

int fod_lzx_decompress(struct fod_lzx *s, long long out_bytes) {
    return lzxd_decompress(s->stream, (off_t) out_bytes);
}

void fod_lzx_free(struct fod_lzx *s) {
    if (!s) return;
    lzxd_free(s->stream);
    free(s);
}
