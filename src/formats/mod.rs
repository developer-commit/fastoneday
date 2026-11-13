//! Pure-Rust parsers for the containers Microsoft ships binaries in.
//! Nothing here touches the network; inputs are byte slices or [`ReadAt`]
//! sources.
//!
//! [`ReadAt`]: crate::io::ReadAt

pub mod authenticode;
pub mod c2r;
pub mod cab;
pub mod cix;
pub mod component;
pub mod delta;
pub mod msp;
pub mod pe;
pub mod wim;
