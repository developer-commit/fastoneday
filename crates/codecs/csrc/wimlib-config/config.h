/* Minimal configuration for building only wimlib's decompressors
 * (see crates/codecs/build.rs). No ntfs-3g, no I/O, no multithreading. */
#ifndef FASTONEDAY_WIMLIB_CONFIG_H
#define FASTONEDAY_WIMLIB_CONFIG_H
#define PACKAGE_VERSION "1.14.5"
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_TYPES_H 1
#endif
