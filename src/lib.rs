//! fastoneday — fetch the exact pre-patch and post-patch Microsoft binaries for
//! a CVE so they can be patch-diffed.
//!
//! The crate is layered; each layer depends only on the ones above it:
//!
//! | layer      | responsibility                                                     |
//! |------------|--------------------------------------------------------------------|
//! | `error`    | one error type shared by every layer                               |
//! | `config`   | runtime settings (workspace, network identity)                     |
//! | `domain`   | plain data: CVE ids, products, patch pairs, digests, results       |
//! | `io`       | random-access byte sources (`ReadAt`)                              |
//! | `net`      | HTTP transport, HTTP range sources, progress/cancellation          |
//! | `formats`  | pure parsers: CAB, WIM, PSF index, MSDelta, PE, MSP                |
//! | `delta_engine` | MSDelta application: Windows' own DLL, or the vendored decoder |
//! | `sources`  | remote services: MSRC, Update Catalog, Symbol Server, Office CDN   |
//! | `packages` | update-package readers producing a uniform payload index           |
//! | `acquire`  | turns a payload into an exact, hash-verified binary                |
//! | `detect`   | ranks which binary a CVE most likely patched                       |
//! | `store`    | on-disk cache, history and the case workspace layout               |
//! | `app`      | use cases executed on worker threads, reported as events           |
//! | `tui`      | the terminal user interface                                        |

pub mod acquire;
pub mod app;
pub mod config;
pub mod delta_engine;
pub mod detect;
pub mod domain;
pub mod error;
pub mod formats;
pub mod headless;
pub mod io;
pub mod net;
pub mod packages;
pub mod sources;
pub mod store;
pub mod tui;

pub use error::{Error, Result};
