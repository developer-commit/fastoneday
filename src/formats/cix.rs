//! `express.psf.cix.xml`: the index of a PSF (patch storage file).
//!
//! Each `<File>` names a payload path and points at a byte range of the
//! `.psf` that holds it, with SHA-256 hashes of both the payload and the
//! stored bytes.

use quick_xml::{Reader, events::Event};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsfEntry {
    pub name: String,
    /// Length of the payload (for `RAW` sources equal to `source_length`).
    pub length: u64,
    /// SHA-256 of the payload, lower-case hex.
    pub sha256: Option<String>,
    /// `RAW` (stored as-is) or `PA30` (stored as a delta from nothing).
    pub source_type: String,
    pub offset: u64,
    pub source_length: u64,
    pub source_sha256: Option<String>,
}

pub fn parse(xml: &[u8]) -> Result<Vec<PsfEntry>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut entries = Vec::new();
    let mut current: Option<PsfEntry> = None;
    let mut in_source = false;
    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| Error::format("PSF index", e.to_string()))?;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let empty = matches!(event, Event::Empty(_));
                match e.local_name().as_ref() {
                    b"File" => {
                        let mut entry = PsfEntry {
                            name: String::new(),
                            length: 0,
                            sha256: None,
                            source_type: String::new(),
                            offset: 0,
                            source_length: 0,
                            source_sha256: None,
                        };
                        for attr in e.attributes().flatten() {
                            let value = String::from_utf8_lossy(&attr.value).into_owned();
                            match attr.key.as_ref() {
                                b"name" => entry.name = value,
                                b"length" => entry.length = value.parse().unwrap_or(0),
                                _ => {}
                            }
                        }
                        if empty {
                            entries.push(entry);
                        } else {
                            current = Some(entry);
                        }
                    }
                    b"Source" => {
                        if let Some(entry) = current.as_mut() {
                            for attr in e.attributes().flatten() {
                                let value = String::from_utf8_lossy(&attr.value).into_owned();
                                match attr.key.as_ref() {
                                    b"type" => entry.source_type = value,
                                    b"offset" => entry.offset = value.parse().unwrap_or(0),
                                    b"length" => entry.source_length = value.parse().unwrap_or(0),
                                    _ => {}
                                }
                            }
                        }
                        in_source = !empty;
                    }
                    b"Hash" => {
                        if let Some(entry) = current.as_mut() {
                            let mut alg = String::new();
                            let mut value = String::new();
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"alg" => {
                                        alg = String::from_utf8_lossy(&attr.value)
                                            .to_ascii_uppercase()
                                    }
                                    b"value" => {
                                        value = String::from_utf8_lossy(&attr.value)
                                            .to_ascii_lowercase()
                                    }
                                    _ => {}
                                }
                            }
                            if alg == "SHA256" {
                                if in_source {
                                    entry.source_sha256 = Some(value);
                                } else if entry.sha256.is_none() {
                                    entry.sha256 = Some(value);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::End(ref e) => match e.local_name().as_ref() {
                b"Source" => in_source = false,
                b"File" => {
                    if let Some(entry) = current.take() {
                        entries.push(entry);
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_raw_and_pa30_sources() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<Container name="kb-baseless.psf" type="PSF" length="10" version="1" xmlns="urn:ContainerIndex">
  <Files>
    <File id="1" name="amd64_x_31bf3856ad364e35_10.0.1.2_none_aa\f\a.sys" length="338" time="1" attr="128">
      <Hash alg="SHA256" value="AA" />
      <Delta><Source type="RAW" offset="1245184" length="338"><Hash alg="SHA256" value="AA" /></Source></Delta>
    </File>
    <File id="2" name="x86_y_6595b64144ccf1df_1.0.1.2_none_bb\GdiPlus.dll" length="1465856" time="1" attr="128">
      <Hash alg="SHA256" value="5A35" />
      <Delta><Source type="PA30" offset="1985076" length="672652"><Hash alg="SHA256" value="4A9C" /></Source></Delta>
    </File>
  </Files>
</Container>"#;
        let entries = parse(xml).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].offset, 1245184);
        assert_eq!(entries[0].sha256.as_deref(), Some("aa"));
        assert_eq!(entries[1].source_type, "PA30");
        assert_eq!(entries[1].length, 1465856);
        assert_eq!(entries[1].sha256.as_deref(), Some("5a35"));
        assert_eq!(entries[1].source_sha256.as_deref(), Some("4a9c"));
    }
}
