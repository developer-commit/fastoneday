//! What the user can do about an error — shown next to the message, never
//! instead of it.

use crate::error::Error;

/// A next step for a failed CVE lookup.
pub fn lookup(error: &Error) -> Option<String> {
    let hint = match error {
        Error::NotFound(_) => {
            "Check the id — the Security Update Guide has no CVE with this number."
        }
        Error::Input(_) => "Type an id like CVE-2024-38193, or words from its title.",
        e if e.is_retryable() => "Check the network connection, then press Enter to try again.",
        Error::Http { .. } | Error::Network { .. } => {
            "Microsoft's Security Update Guide did not answer; press Enter to try again."
        }
        _ => return None,
    };
    Some(hint.into())
}

/// A next step for a failed fetch.
pub fn fetch(error: &Error) -> Option<String> {
    let text = error.to_string();
    let hint = match error {
        Error::Cancelled => return None,
        _ if text.contains("rate limit") => {
            "Microsoft's server is throttling requests; wait a few minutes, then press r."
        }
        e if e.is_retryable() => "A network request failed; press r to retry.",
        Error::Http { status: 404, .. } | Error::NotFound(_) => {
            "Pick another product row or another binary; this combination is not available."
        }
        Error::Integrity { .. } => {
            "The bytes did not match Microsoft's hash or signature, so nothing was saved; press r to retry."
        }
        Error::Unsupported(_) => "Pick another product row; this one cannot be fetched yet.",
        Error::Io { .. } => "Check free disk space and write access to the workspace folder.",
        Error::Http { .. } | Error::Network { .. } => "A request failed; press r to retry.",
        _ => return None,
    };
    Some(hint.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_a_next_step() {
        assert!(lookup(&Error::NotFound("x".into())).unwrap().contains("id"));
        assert!(
            fetch(&Error::Unsupported(
                "Defender CDN ... (HTTP 403, rate limit)".into()
            ))
            .unwrap()
            .contains("wait")
        );
        assert!(fetch(&Error::Cancelled).is_none());
        assert!(
            fetch(&Error::Http {
                context: "x".into(),
                status: 503
            })
            .unwrap()
            .contains("retry")
        );
    }
}
