//! Compiles the vendored C decompressors from `third_party/` into static
//! libraries linked into this crate. Requires a C compiler (GCC or Clang;
//! for Windows use the GNU toolchain, as wimlib relies on GNU C).

use std::{env, path::PathBuf};

const WIMLIB_SOURCES: &[&str] = &[
    "decompress",
    "decompress_common",
    "compress_common",
    "cpu_features",
    "lzms_common",
    "lzms_decompress",
    "lzx_common",
    "lzx_decompress",
    "xpress_decompress",
];

fn main() {
    let manifest =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let third_party = manifest.join("../../third_party");
    let glue = manifest.join("csrc");

    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") && env::var_os("CC").is_none() {
        println!(
            "cargo:warning=wimlib needs GNU C; build with the x86_64-pc-windows-gnu target or set CC=clang-cl"
        );
    }

    // libmspack: the LZX decoder used for CAB folders.
    let mspack = third_party.join("libmspack/mspack");
    cc::Build::new()
        .file(mspack.join("lzxd.c"))
        .file(glue.join("mspack_glue.c"))
        .include(&mspack)
        .define("_FILE_OFFSET_BITS", "64")
        .opt_level(2)
        .warnings(false)
        .compile("fod_mspack");

    // wimlib: chunk decompressors for WIM/ESD resources.
    let wimlib = third_party.join("wimlib");
    let mut build = cc::Build::new();
    for name in WIMLIB_SOURCES {
        build.file(wimlib.join("src").join(format!("{name}.c")));
    }
    build
        .file(glue.join("wimlib_glue.c"))
        .include(wimlib.join("include"))
        .include(glue.join("wimlib-config"))
        .define("HAVE_CONFIG_H", None)
        .flag_if_supported("-std=gnu11")
        .opt_level(2)
        .warnings(false)
        .compile("fod_wimlib");

    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=../../third_party/libmspack");
    println!("cargo:rerun-if-changed=../../third_party/wimlib");
}
