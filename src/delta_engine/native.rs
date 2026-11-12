//! Microsoft's MSDelta implementation, as shipped with Windows.
//!
//! `UpdateCompression.dll` (what the servicing stack uses on current
//! Windows; handles PA30/PA31) is preferred, `msdelta.dll` is the fallback
//! and the only one that applies legacy PA19 deltas. Both are loaded from
//! System32 only, never from the working directory.

use std::{ffi::c_void, ptr};

use super::DeltaEngine;
use crate::error::{Error, Result};

#[repr(C)]
#[derive(Clone, Copy)]
struct DeltaInput {
    start: *const c_void,
    size: usize,
    editable: i32,
}

#[repr(C)]
struct DeltaOutput {
    start: *mut c_void,
    size: usize,
}

type ApplyDeltaB = unsafe extern "system" fn(
    flags: i64,
    source: DeltaInput,
    delta: DeltaInput,
    target: *mut DeltaOutput,
) -> i32;
type DeltaFree = unsafe extern "system" fn(memory: *mut c_void) -> i32;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
}

const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const DELTA_APPLY_FLAG_ALLOW_PA19: i64 = 0x0000_0001;

struct Library {
    name: &'static str,
    apply: ApplyDeltaB,
    free: DeltaFree,
}

pub struct NativeEngine {
    libraries: Vec<Library>,
}

impl NativeEngine {
    pub fn load() -> Option<Self> {
        let libraries: Vec<Library> = [
            ("UpdateCompression.dll", "Microsoft UpdateCompression.dll"),
            ("msdelta.dll", "Microsoft msdelta.dll"),
        ]
        .into_iter()
        .filter_map(|(file, name)| load(file, name))
        .collect();
        (!libraries.is_empty()).then_some(Self { libraries })
    }
}

fn load(file: &str, name: &'static str) -> Option<Library> {
    let wide: Vec<u16> = file.encode_utf16().chain(Some(0)).collect();
    // SAFETY: plain Win32 calls with NUL-terminated names; the module stays
    // loaded for the life of the process, so the function pointers do too.
    unsafe {
        let module = LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if module.is_null() {
            return None;
        }
        let apply = GetProcAddress(module, c"ApplyDeltaB".as_ptr().cast());
        let free = GetProcAddress(module, c"DeltaFree".as_ptr().cast());
        if apply.is_null() || free.is_null() {
            return None;
        }
        Some(Library {
            name,
            apply: std::mem::transmute::<*mut c_void, ApplyDeltaB>(apply),
            free: std::mem::transmute::<*mut c_void, DeltaFree>(free),
        })
    }
}

impl DeltaEngine for NativeEngine {
    fn apply(&self, base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, &'static str)> {
        let pa19 = delta.starts_with(b"PA19");
        let mut last_error = 0u32;
        for library in self
            .libraries
            .iter()
            .filter(|l| !pa19 || l.name.ends_with("msdelta.dll"))
        {
            let source = DeltaInput {
                start: if base.is_empty() {
                    ptr::null()
                } else {
                    base.as_ptr().cast()
                },
                size: base.len(),
                editable: 0,
            };
            let input = DeltaInput {
                start: delta.as_ptr().cast(),
                size: delta.len(),
                editable: 0,
            };
            let mut output = DeltaOutput {
                start: ptr::null_mut(),
                size: 0,
            };
            let flags = if pa19 { DELTA_APPLY_FLAG_ALLOW_PA19 } else { 0 };
            // SAFETY: inputs point to live slices; on success the DLL returns
            // a buffer it owns, which we copy and hand back to DeltaFree.
            unsafe {
                if (library.apply)(flags, source, input, &mut output) != 0
                    && !output.start.is_null()
                {
                    let bytes =
                        std::slice::from_raw_parts(output.start as *const u8, output.size).to_vec();
                    (library.free)(output.start);
                    return Ok((bytes, library.name));
                }
                last_error = GetLastError();
            }
        }
        Err(Error::format(
            "delta",
            format!("Windows ApplyDeltaB rejected the delta (Win32 error {last_error})"),
        ))
    }

    fn describe(&self) -> &'static str {
        self.libraries[0].name
    }
}
