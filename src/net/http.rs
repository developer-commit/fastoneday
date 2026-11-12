use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    thread,
    time::Duration,
};

use ureq::{Agent, http::Response};

use crate::{
    error::{Error, Result},
    io::{Cancel, Meter},
};

const TRANSFER_BUFFER: usize = 1 << 20;
const MAX_TEXT_BODY: u64 = 256 << 20;

/// Blocking HTTP client with retries, range reads and resumable downloads.
pub struct Http {
    agent: Agent,
    retries: u32,
}

impl Http {
    pub fn new(user_agent: &str, timeout: Duration) -> Self {
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(user_agent)
            .timeout_connect(Some(Duration::from_secs(20)))
            .timeout_recv_response(Some(timeout))
            .timeout_per_read(Some(timeout))
            .max_redirects(10)
            .build();
        Self {
            agent: config.into(),
            retries: 3,
        }
    }

    /// GET returning the body as text (lossy UTF-8).
    pub fn get_text(&self, url: &str, context: &str) -> Result<String> {
        self.with_retries(context, || {
            let mut response = self.send_get(url, None, context)?;
            expect_status(&response, &[200], context)?;
            response
                .body_mut()
                .with_config()
                .limit(MAX_TEXT_BODY)
                .lossy_utf8(true)
                .read_to_string()
                .map_err(|e| Error::network(context, e))
        })
    }

    pub fn get_json(&self, url: &str, context: &str) -> Result<serde_json::Value> {
        let text = self.get_text(url, context)?;
        serde_json::from_str(&text).map_err(|e| Error::format(context.to_string(), e.to_string()))
    }

    /// POST `application/x-www-form-urlencoded`, returning text.
    pub fn post_form(&self, url: &str, form: &[(&str, &str)], context: &str) -> Result<String> {
        self.with_retries(context, || {
            let mut response = self
                .agent
                .post(url)
                .send_form(form.iter().copied())
                .map_err(|e| Error::network(context, e))?;
            expect_status(&response, &[200], context)?;
            response
                .body_mut()
                .with_config()
                .limit(MAX_TEXT_BODY)
                .lossy_utf8(true)
                .read_to_string()
                .map_err(|e| Error::network(context, e))
        })
    }

    /// GET a whole (small) binary body.
    pub fn get_bytes(&self, url: &str, limit: u64, context: &str) -> Result<Vec<u8>> {
        self.with_retries(context, || {
            let mut response = self.send_get(url, None, context)?;
            expect_status(&response, &[200], context)?;
            response
                .body_mut()
                .with_config()
                .limit(limit)
                .read_to_vec()
                .map_err(|e| Error::network(context, e))
        })
    }

    /// Exactly `len` bytes at `offset` (requires HTTP range support).
    pub fn get_range(
        &self,
        url: &str,
        offset: u64,
        len: u64,
        context: &str,
        meter: &dyn Meter,
    ) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        self.with_retries(context, || {
            let range = format!("bytes={}-{}", offset, offset + len - 1);
            let response = self.send_get(url, Some(&range), context)?;
            expect_status(&response, &[206], context)?;
            let mut reader = response.into_body().into_reader();
            let mut out = Vec::with_capacity(len as usize);
            let mut buf = vec![0u8; TRANSFER_BUFFER.min(len as usize)];
            while (out.len() as u64) < len {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| Error::network(context, e))?;
                if n == 0 {
                    break;
                }
                let take = n.min((len - out.len() as u64) as usize);
                out.extend_from_slice(&buf[..take]);
                meter.advance(take as u64);
            }
            if out.len() as u64 != len {
                return Err(Error::network(
                    context,
                    format!("short range read: {} of {len} bytes", out.len()),
                ));
            }
            Ok(out)
        })
    }

    /// Final status of a HEAD request after redirects (200 or 404 typically).
    pub fn head_status(&self, url: &str, context: &str) -> Result<u16> {
        self.with_retries(context, || {
            let response = self
                .agent
                .head(url)
                .call()
                .map_err(|e| Error::network(context, e))?;
            let status = response.status().as_u16();
            if status == 429 || status >= 500 {
                return Err(Error::Http {
                    context: context.into(),
                    status,
                });
            }
            Ok(status)
        })
    }

    /// Total size of a remote resource.
    pub fn content_length(&self, url: &str, context: &str) -> Result<u64> {
        self.with_retries(context, || {
            let response = self.send_get(url, Some("bytes=0-0"), context)?;
            expect_status(&response, &[206, 200], context)?;
            if response.status().as_u16() == 206 {
                let total = response
                    .headers()
                    .get("content-range")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.rsplit('/').next())
                    .and_then(|v| v.trim().parse::<u64>().ok());
                if let Some(total) = total {
                    return Ok(total);
                }
            }
            response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .ok_or_else(|| Error::format(context.to_string(), "no content length"))
        })
    }

    /// Download to `dest`, resuming a previous `dest.part` when the server
    /// supports ranges. The file only appears at `dest` once complete.
    pub fn download(
        &self,
        url: &str,
        dest: &Path,
        expected_size: Option<u64>,
        context: &str,
        meter: &dyn Meter,
        cancel: &Cancel,
    ) -> Result<()> {
        let part = dest.with_extension("part");
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::io(format!("create {}", parent.display()), e))?;
        }
        meter.total(expected_size);
        let mut attempts = 0;
        loop {
            cancel.check()?;
            let have = fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
            if have > 0 {
                meter.advance(0);
            }
            match self.download_once(url, &part, have, expected_size, context, meter, cancel) {
                Ok(()) => break,
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) if error.is_retryable() && attempts < self.retries + 2 => {
                    attempts += 1;
                    thread::sleep(Duration::from_millis(500 << attempts.min(4)));
                }
                Err(error) => return Err(error),
            }
        }
        let size = fs::metadata(&part)
            .map_err(|e| Error::io(format!("stat {}", part.display()), e))?
            .len();
        if let Some(expected) = expected_size
            && size != expected
        {
            let _ = fs::remove_file(&part);
            return Err(Error::Integrity {
                what: context.into(),
                algorithm: "size",
                expected: expected.to_string(),
                actual: size.to_string(),
            });
        }
        fs::rename(&part, dest).map_err(|e| Error::io(format!("publish {}", dest.display()), e))
    }

    #[allow(clippy::too_many_arguments)]
    fn download_once(
        &self,
        url: &str,
        part: &Path,
        have: u64,
        expected_size: Option<u64>,
        context: &str,
        meter: &dyn Meter,
        cancel: &Cancel,
    ) -> Result<()> {
        if expected_size.is_some_and(|size| have == size) {
            return Ok(());
        }
        let range = (have > 0).then(|| format!("bytes={have}-"));
        let response = self.send_get(url, range.as_deref(), context)?;
        let status = response.status().as_u16();
        let resume = match status {
            206 if have > 0 => true,
            200 => false,
            _ => {
                return Err(Error::Http {
                    context: context.into(),
                    status,
                });
            }
        };
        let mut file = if resume {
            meter.advance(have);
            OpenOptions::new()
                .append(true)
                .open(part)
                .map_err(|e| Error::io(format!("open {}", part.display()), e))?
        } else {
            File::create(part).map_err(|e| Error::io(format!("create {}", part.display()), e))?
        };
        let mut reader = response.into_body().into_reader();
        let mut buf = vec![0u8; TRANSFER_BUFFER];
        loop {
            cancel.check()?;
            let n = reader
                .read(&mut buf)
                .map_err(|e| Error::network(context, e))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])
                .map_err(|e| Error::io(format!("write {}", part.display()), e))?;
            meter.advance(n as u64);
        }
        file.sync_all()
            .map_err(|e| Error::io(format!("sync {}", part.display()), e))
    }

    fn send_get(
        &self,
        url: &str,
        range: Option<&str>,
        context: &str,
    ) -> Result<Response<ureq::Body>> {
        let mut request = self.agent.get(url);
        if let Some(range) = range {
            request = request.header("Range", range);
        }
        request.call().map_err(|e| Error::network(context, e))
    }

    fn with_retries<T>(&self, context: &str, mut call: impl FnMut() -> Result<T>) -> Result<T> {
        let mut attempt = 0;
        loop {
            match call() {
                Err(error) if error.is_retryable() && attempt < self.retries => {
                    attempt += 1;
                    thread::sleep(Duration::from_millis(400 << attempt));
                }
                Err(Error::Http { status, .. }) if status == 404 => {
                    return Err(Error::Http {
                        context: context.into(),
                        status,
                    });
                }
                result => return result,
            }
        }
    }
}

fn expect_status(response: &Response<ureq::Body>, accepted: &[u16], context: &str) -> Result<()> {
    let status = response.status().as_u16();
    if accepted.contains(&status) {
        Ok(())
    } else {
        Err(Error::Http {
            context: context.into(),
            status,
        })
    }
}
