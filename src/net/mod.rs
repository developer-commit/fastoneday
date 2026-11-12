//! HTTP transport. One client for the whole program; callers pass a short
//! `context` string ("searching the Update Catalog") that ends up in errors.

mod http;
mod range;
mod urlenc;

pub use http::Http;
pub use range::HttpRangeSource;
pub use urlenc::{encode_component, encode_query};
