//! The single error type used across layers.
//!
//! Variants describe *what kind* of failure happened so the UI can phrase it
//! and decide whether a retry makes sense; the message carries the context.

use std::io;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The user supplied something we cannot use (bad CVE id, file name, ...).
    #[error("{0}")]
    Input(String),

    /// Transport-level failure (DNS, TLS, connection reset, timeout).
    #[error("network error while {context}: {message}")]
    Network { context: String, message: String },

    /// The server answered with an unexpected HTTP status.
    #[error("HTTP {status} while {context}")]
    Http { context: String, status: u16 },

    /// A lookup completed but the thing does not exist.
    #[error("{0}")]
    NotFound(String),

    /// Data did not have the structure we expected.
    #[error("malformed {what}: {detail}")]
    Format { what: String, detail: String },

    /// A hash or size check failed. Nothing is published when this happens.
    #[error("{what}: {algorithm} mismatch (expected {expected}, got {actual})")]
    Integrity {
        what: String,
        algorithm: &'static str,
        expected: String,
        actual: String,
    },

    /// A format or path we recognise but do not handle.
    #[error("{0}")]
    Unsupported(String),

    /// Local file-system failure.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    /// The operation was superseded or aborted by the user.
    #[error("cancelled")]
    Cancelled,
}

impl Error {
    pub fn format(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Format {
            what: what.into(),
            detail: detail.into(),
        }
    }

    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub fn network(context: impl Into<String>, message: impl ToString) -> Self {
        Self::Network {
            context: context.into(),
            message: message.to_string(),
        }
    }

    /// Whether repeating the same request later could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network { .. } => true,
            Self::Http { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }

    /// Short category label for the UI.
    pub fn category(&self) -> &'static str {
        match self {
            Self::Input(_) => "input",
            Self::Network { .. } | Self::Http { .. } => "network",
            Self::NotFound(_) => "not found",
            Self::Format { .. } => "format",
            Self::Integrity { .. } => "integrity",
            Self::Unsupported(_) => "unsupported",
            Self::Io { .. } => "disk",
            Self::Cancelled => "cancelled",
        }
    }
}
