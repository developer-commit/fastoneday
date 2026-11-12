/*
 * The few library services wimlib's decompressors expect from the rest of
 * libwim (which fastoneday does not build): memory allocation and one-time
 * global initialisation (CPU feature detection on x86).
 */
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdlib.h>
#ifdef _WIN32
#  include <malloc.h>
#endif

#include "wimlib.h"
#include "wimlib/cpu_features.h"
#include "wimlib/util.h"

void *wimlib_malloc(size_t size) {
    return malloc(size);
}

void wimlib_free_memory(void *p) {
    free(p);
}

void *wimlib_aligned_malloc(size_t size, size_t alignment) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    void *p = NULL;
    if (alignment < sizeof(void *)) alignment = sizeof(void *);
    return posix_memalign(&p, alignment, size) == 0 ? p : NULL;
#endif
}

void wimlib_aligned_free(void *p) {
#ifdef _WIN32
    _aligned_free(p);
#else
    free(p);
#endif
}

static int fod_wimlib_initialized;

WIMLIBAPI int wimlib_global_init(int init_flags) {
    (void) init_flags;
    if (!fod_wimlib_initialized) {
        init_cpu_features();
        fod_wimlib_initialized = 1;
    }
    return 0;
}
