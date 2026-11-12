//! Office Click-to-Run stream index (`stream.<arch>.<culture>.db`).
//!
//! The `.db` ("C2RxUnityDB") wraps a zlib-compressed SQL script. We parse only
//! the `CREATE TABLE` column lists and `INSERT ... VALUES` rows we need. The
//! `.dat` stream it describes is a gapless sequence of independent zlib
//! chunks (≤ 8 MiB of one file each), so one HTTP range yields a whole file.

use std::{collections::HashMap, io::Read};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use flate2::read::ZlibDecoder;
use sha2::{Digest as _, Sha256};

use crate::{
    domain::to_hex,
    error::{Error, Result},
    io::le,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Offset of the chunk's plaintext inside the file.
    pub file_offset: u64,
    pub plain_len: u64,
    /// Compressed bytes inside the `.dat`.
    pub dat_offset: u64,
    pub dat_len: u64,
    /// SHA-256 of the compressed bytes.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFile {
    /// Install-relative path, e.g. `root\Office16\EXCEL.EXE`.
    pub path: String,
    pub size: u64,
    /// SHA-256 of the whole file, lower-case hex.
    pub sha256: String,
    pub chunks: Vec<Chunk>,
}

impl StreamFile {
    pub fn file_name(&self) -> String {
        self.path
            .rsplit('\\')
            .next()
            .unwrap_or(&self.path)
            .to_ascii_lowercase()
    }

    /// Contiguous `(offset, length)` runs of the `.dat` holding the file's
    /// chunks, in file order. Usually one run; older builds interleave files.
    pub fn dat_runs(&self) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for chunk in &self.chunks {
            match runs.last_mut() {
                Some((start, len)) if *start + *len == chunk.dat_offset => *len += chunk.dat_len,
                _ => runs.push((chunk.dat_offset, chunk.dat_len)),
            }
        }
        runs
    }

    /// Like [`Self::assemble`] for bytes fetched as separate runs.
    pub fn assemble_runs(&self, runs: &[(u64, Vec<u8>)]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.size as usize);
        for chunk in &self.chunks {
            let (base, bytes) = runs
                .iter()
                .find(|(start, bytes)| {
                    chunk.dat_offset >= *start
                        && chunk.dat_offset + chunk.dat_len <= start + bytes.len() as u64
                })
                .ok_or_else(|| {
                    Error::format("Click-to-Run stream", "chunk outside the downloaded runs")
                })?;
            let at = (chunk.dat_offset - base) as usize;
            out.extend_from_slice(&self.inflate_chunk(
                chunk,
                &bytes[at..at + chunk.dat_len as usize],
                out.len() as u64,
            )?);
        }
        self.verify_whole(&out)?;
        Ok(out)
    }

    fn inflate_chunk(&self, chunk: &Chunk, raw: &[u8], produced: u64) -> Result<Vec<u8>> {
        let actual = to_hex(&Sha256::digest(raw));
        if actual != chunk.sha256 {
            return Err(Error::Integrity {
                what: format!("{} chunk at {}", self.path, chunk.file_offset),
                algorithm: "SHA-256",
                expected: chunk.sha256.clone(),
                actual,
            });
        }
        let mut plain = Vec::with_capacity(chunk.plain_len as usize);
        ZlibDecoder::new(raw)
            .read_to_end(&mut plain)
            .map_err(|e| Error::format("Click-to-Run chunk", e.to_string()))?;
        if plain.len() as u64 != chunk.plain_len || produced != chunk.file_offset {
            return Err(Error::format(
                "Click-to-Run chunk",
                "unexpected chunk length",
            ));
        }
        Ok(plain)
    }

    fn verify_whole(&self, data: &[u8]) -> Result<()> {
        let actual = to_hex(&Sha256::digest(data));
        if actual != self.sha256 {
            return Err(Error::Integrity {
                what: self.path.clone(),
                algorithm: "SHA-256",
                expected: self.sha256.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// The byte span of the `.dat` covering the file.
    pub fn dat_span(&self) -> Option<(u64, u64)> {
        let first = self.chunks.first()?;
        let last = self.chunks.last()?;
        Some((
            first.dat_offset,
            last.dat_offset + last.dat_len - first.dat_offset,
        ))
    }

    /// Inflates the file from the bytes of [`Self::dat_span`] and verifies
    /// every chunk and the whole-file SHA-256.
    pub fn assemble(&self, span: &[u8]) -> Result<Vec<u8>> {
        match self.dat_span() {
            Some((base, _)) => self.assemble_runs(&[(base, span.to_vec())]),
            None => {
                self.verify_whole(&[])?;
                Ok(Vec::new())
            }
        }
    }
}

/// All files of one stream, keyed by upper-case path.
pub struct StreamIndex {
    files: HashMap<String, StreamFile>,
}

impl StreamIndex {
    pub fn parse(db: &[u8]) -> Result<Self> {
        let sql = unity_db_script(db)?;
        let tables = parse_sql(&sql)?;
        build(&tables)
    }

    pub fn files(&self) -> impl Iterator<Item = &StreamFile> {
        self.files.values()
    }

    pub fn get(&self, path: &str) -> Option<&StreamFile> {
        self.files
            .get(&path.replace('/', "\\").to_ascii_uppercase())
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

fn unity_db_script(raw: &[u8]) -> Result<String> {
    let bad = |d: &str| Error::format("Click-to-Run index", d.to_string());
    if raw.len() < 0x50 || &raw[..11] != b"C2RxUnityDB" {
        return Err(bad("missing C2RxUnityDB signature"));
    }
    let payload_offset = le::u32(raw, 0x14) as usize;
    let payload_len = le::u32(raw, 0x18) as usize;
    let hash_offset = le::u32(raw, 0x1c) as usize;
    let hash_len = le::u16(raw, 0x20) as usize;
    let hash_alg = le::u16(raw, 0x22);
    let sql_len = le::u32(raw, 0x24) as usize;
    let payload = raw
        .get(payload_offset..payload_offset + payload_len)
        .ok_or_else(|| bad("payload outside file"))?;
    let mut sql = Vec::with_capacity(sql_len);
    ZlibDecoder::new(payload)
        .read_to_end(&mut sql)
        .map_err(|e| bad(&e.to_string()))?;
    if sql.len() != sql_len {
        return Err(bad("script length mismatch"));
    }
    if hash_alg == 1 {
        let expected = raw
            .get(hash_offset..hash_offset + hash_len)
            .ok_or_else(|| bad("hash outside file"))?;
        if Sha256::digest(&sql).as_slice() != expected {
            return Err(Error::Integrity {
                what: "Click-to-Run index script".into(),
                algorithm: "SHA-256",
                expected: to_hex(expected),
                actual: to_hex(&Sha256::digest(&sql)),
            });
        }
    }
    String::from_utf8(sql).map_err(|_| bad("script is not UTF-8"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Int(u64),
    Text(String),
    Null,
}

impl Value {
    fn int(&self) -> Option<u64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }
    fn text(&self) -> Option<&str> {
        match self {
            Self::Text(v) => Some(v),
            _ => None,
        }
    }
}

struct Table {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}

impl Table {
    fn column(&self, name: &str) -> Result<usize> {
        self.columns
            .iter()
            .position(|c| c.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::format("Click-to-Run index", format!("missing column {name}")))
    }
}

/// Parses `CREATE TABLE` and single-statement `INSERT INTO t VALUES (...),...;`.
fn parse_sql(sql: &str) -> Result<HashMap<String, Table>> {
    let bad = |d: String| Error::format("Click-to-Run index script", d);
    let b = sql.as_bytes();
    let n = b.len();
    let mut columns: HashMap<String, Vec<String>> = HashMap::new();
    let mut tables: HashMap<String, Table> = HashMap::new();
    let mut i = 0usize;

    let skip_ws = |mut i: usize| {
        while i < n {
            if b[i].is_ascii_whitespace() {
                i += 1;
            } else if b[i..].starts_with(b"--") {
                i = sql[i..].find('\n').map(|k| i + k + 1).unwrap_or(n);
            } else {
                break;
            }
        }
        i
    };
    let skip_statement = |mut i: usize| {
        let mut quoted = false;
        while i < n {
            match b[i] {
                b'\'' => quoted = !quoted,
                b';' if !quoted => return i + 1,
                _ => {}
            }
            i += 1;
        }
        n
    };

    loop {
        i = skip_ws(i);
        if i >= n {
            break;
        }
        if b[i..].starts_with(b"CREATE TABLE ") {
            let open = sql[i..]
                .find('(')
                .map(|k| i + k)
                .ok_or_else(|| bad("CREATE without (".into()))?;
            let name = sql[i + 13..open].trim().trim_matches('"').to_owned();
            let end = skip_statement(open);
            let close = sql[open..end]
                .rfind(')')
                .map(|k| open + k)
                .ok_or_else(|| bad("CREATE without )".into()))?;
            let mut depth = 0i32;
            let mut item = String::new();
            let mut items = Vec::new();
            for ch in sql[open + 1..close].chars() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                if ch == ',' && depth == 0 {
                    items.push(std::mem::take(&mut item));
                } else {
                    item.push(ch);
                }
            }
            items.push(item);
            let cols = items
                .iter()
                .filter_map(|it| it.split_whitespace().next())
                .filter(|w| {
                    !matches!(
                        w.to_ascii_uppercase().as_str(),
                        "UNIQUE" | "PRIMARY" | "FOREIGN" | "CHECK" | "CONSTRAINT"
                    )
                })
                .map(|w| w.trim_matches('"').to_owned())
                .collect();
            columns.insert(name, cols);
            i = end;
        } else if b[i..].starts_with(b"INSERT INTO ") {
            let values = sql[i..]
                .find(" VALUES")
                .map(|k| i + k)
                .ok_or_else(|| bad("INSERT without VALUES".into()))?;
            let name = sql[i + 12..values].trim().trim_matches('"').to_owned();
            i = values + 7;
            let mut rows = Vec::new();
            loop {
                i = skip_ws(i);
                if b.get(i) != Some(&b'(') {
                    return Err(bad(format!("expected ( at {i}")));
                }
                i += 1;
                let mut row = Vec::new();
                loop {
                    i = skip_ws(i);
                    if b.get(i) == Some(&b'\'') {
                        i += 1;
                        let mut text = String::new();
                        loop {
                            let k = sql[i..]
                                .find('\'')
                                .map(|k| i + k)
                                .ok_or_else(|| bad("unterminated string".into()))?;
                            text.push_str(&sql[i..k]);
                            if b.get(k + 1) == Some(&b'\'') {
                                text.push('\'');
                                i = k + 2;
                            } else {
                                i = k + 1;
                                break;
                            }
                        }
                        row.push(Value::Text(text));
                    } else {
                        let start = i;
                        while i < n && b[i] != b',' && b[i] != b')' {
                            i += 1;
                        }
                        let token = sql[start..i].trim();
                        row.push(if token.eq_ignore_ascii_case("NULL") {
                            Value::Null
                        } else {
                            Value::Int(
                                token
                                    .parse()
                                    .map_err(|_| bad(format!("bad number `{token}`")))?,
                            )
                        });
                    }
                    i = skip_ws(i);
                    match b.get(i) {
                        Some(b',') => i += 1,
                        Some(b')') => {
                            i += 1;
                            break;
                        }
                        _ => return Err(bad(format!("bad tuple at {i}"))),
                    }
                }
                rows.push(row);
                i = skip_ws(i);
                match b.get(i) {
                    Some(b',') => i += 1,
                    Some(b';') => {
                        i += 1;
                        break;
                    }
                    _ => return Err(bad(format!("bad INSERT at {i}"))),
                }
            }
            let cols = columns.get(&name).cloned().unwrap_or_default();
            tables
                .entry(name)
                .or_insert_with(|| Table {
                    columns: cols,
                    rows: Vec::new(),
                })
                .rows
                .extend(rows);
        } else {
            i = skip_statement(i);
        }
    }
    Ok(tables)
}

fn build(tables: &HashMap<String, Table>) -> Result<StreamIndex> {
    let get = |name: &str| {
        tables
            .get(name)
            .ok_or_else(|| Error::format("Click-to-Run index", format!("missing table {name}")))
    };
    let missing = |what: &str| {
        Error::format(
            "Click-to-Run index",
            format!("dangling reference in {what}"),
        )
    };

    let dirs = get("Directories")?;
    let (d_id, d_name) = (dirs.column("directory_id")?, dirs.column("Name")?);
    let directories: HashMap<u64, String> = dirs
        .rows
        .iter()
        .filter_map(|r| Some((r[d_id].int()?, r[d_name].text()?.to_owned())))
        .collect();

    let paths_t = get("Paths")?;
    let (p_id, p_dir, p_name) = (
        paths_t.column("path_id")?,
        paths_t.column("directory_id")?,
        paths_t.column("Name")?,
    );
    let mut paths: HashMap<u64, String> = HashMap::new();
    for r in &paths_t.rows {
        let (Some(id), Some(dir), Some(name)) = (r[p_id].int(), r[p_dir].int(), r[p_name].text())
        else {
            continue;
        };
        let dir_name = directories.get(&dir).ok_or_else(|| missing("Paths"))?;
        let full = if dir_name.is_empty() {
            name.to_owned()
        } else {
            format!("{dir_name}\\{name}")
        };
        paths.insert(id, full);
    }

    let digests_t = get("Digests")?;
    let (g_id, g_value) = (digests_t.column("digest_id")?, digests_t.column("Digest")?);
    let digests: HashMap<u64, String> = digests_t
        .rows
        .iter()
        .filter_map(|r| {
            let raw = BASE64.decode(r[g_value].text()?).ok()?;
            Some((r[g_id].int()?, to_hex(&raw)))
        })
        .collect();

    let hashes_t = get("Hashes")?;
    let (h_id, h_off, h_size, h_digest) = (
        hashes_t.column("hash_id")?,
        hashes_t.column("Offset")?,
        hashes_t.column("Size")?,
        hashes_t.column("digest_id")?,
    );
    let hashes: HashMap<u64, (u64, u64, String)> = hashes_t
        .rows
        .iter()
        .filter_map(|r| {
            let digest = digests.get(&r[h_digest].int()?)?.clone();
            Some((r[h_id].int()?, (r[h_off].int()?, r[h_size].int()?, digest)))
        })
        .collect();

    let files_t = get("Files")?;
    let (f_id, f_target, f_hash) = (
        files_t.column("file_id")?,
        files_t.column("target_path")?,
        files_t.column("hash_id")?,
    );
    let mut by_id: HashMap<u64, StreamFile> = HashMap::new();
    for r in &files_t.rows {
        let (Some(id), Some(target), Some(hash)) =
            (r[f_id].int(), r[f_target].int(), r[f_hash].int())
        else {
            continue;
        };
        let path = paths.get(&target).ok_or_else(|| missing("Files"))?.clone();
        let (_, size, digest) = hashes
            .get(&hash)
            .ok_or_else(|| missing("Files hash"))?
            .clone();
        by_id.insert(
            id,
            StreamFile {
                path,
                size,
                sha256: digest,
                chunks: Vec::new(),
            },
        );
    }

    let source_t = get("BlockSource")?;
    let (s_block, s_hash) = (source_t.column("block_id")?, source_t.column("hash_id")?);
    let sources: HashMap<u64, u64> = source_t
        .rows
        .iter()
        .filter_map(|r| Some((r[s_block].int()?, r[s_hash].int()?)))
        .collect();

    let blocks_t = get("Blocks")?;
    let (b_id, b_file, b_hash) = (
        blocks_t.column("block_id")?,
        blocks_t.column("file_id")?,
        blocks_t.column("hash_id")?,
    );
    for r in &blocks_t.rows {
        let (Some(block), Some(file), Some(hash)) =
            (r[b_id].int(), r[b_file].int(), r[b_hash].int())
        else {
            continue;
        };
        let (file_offset, plain_len, _) =
            hashes.get(&hash).ok_or_else(|| missing("Blocks"))?.clone();
        let source_hash = sources.get(&block).ok_or_else(|| missing("BlockSource"))?;
        let (dat_offset, dat_len, sha256) = hashes
            .get(source_hash)
            .ok_or_else(|| missing("BlockSource hash"))?
            .clone();
        if let Some(f) = by_id.get_mut(&file) {
            f.chunks.push(Chunk {
                file_offset,
                plain_len,
                dat_offset,
                dat_len,
                sha256,
            });
        }
    }

    let mut files = HashMap::with_capacity(by_id.len());
    for (_, mut f) in by_id {
        f.chunks.sort_by_key(|c| c.file_offset);
        files.insert(f.path.to_ascii_uppercase(), f);
    }
    Ok(StreamIndex { files })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = "PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\n\
CREATE TABLE Directories (directory_id INTEGER, Name TEXT, UNIQUE(directory_id));\n\
CREATE TABLE Paths (path_id INTEGER, directory_id INTEGER, Name TEXT, Tags INTEGER);\n\
CREATE TABLE Files (file_id INTEGER, build_id INTEGER, target_path INTEGER, hash_id INTEGER, media_id INTEGER, source_path INTEGER, Tags INTEGER);\n\
CREATE TABLE Hashes (hash_id INTEGER, algorithm_id INTEGER, Offset INTEGER, Size INTEGER, digest_id INTEGER);\n\
CREATE TABLE Digests (digest_id INTEGER, Digest TEXT);\n\
CREATE TABLE Blocks (block_id INTEGER, build_id INTEGER, file_id INTEGER, hash_id INTEGER);\n\
CREATE TABLE BlockSource (id INTEGER, build_id INTEGER, block_id INTEGER, hash_id INTEGER);\n\
INSERT INTO Directories VALUES (1,'root\\Office16'),(2,'');\n\
INSERT INTO Paths VALUES (10,1,'EXCEL.EXE',0),(11,2,'It''s.txt',0);\n\
INSERT INTO Digests VALUES (100,'AAAA'),(101,'AQID'),(102,'BAUG');\n\
INSERT INTO Hashes VALUES (1000,1,0,5,100),(1001,1,0,5,101),(1002,1,40,9,102);\n\
INSERT INTO Files VALUES (7,1,10,1000,1,10,0),(8,1,11,1000,1,11,0);\n\
INSERT INTO Blocks VALUES (500,1,7,1001);\n\
INSERT INTO BlockSource VALUES (1,1,500,1002);\nCOMMIT;\n";

    #[test]
    fn builds_the_file_and_chunk_map() {
        let tables = parse_sql(SCRIPT).unwrap();
        let index = build(&tables).unwrap();
        assert_eq!(index.len(), 2);
        let excel = index.get("ROOT\\office16\\excel.exe").unwrap();
        assert_eq!(excel.size, 5);
        assert_eq!(excel.file_name(), "excel.exe");
        assert_eq!(
            excel.chunks,
            vec![Chunk {
                file_offset: 0,
                plain_len: 5,
                dat_offset: 40,
                dat_len: 9,
                sha256: "040506".into(),
            }]
        );
        assert_eq!(excel.dat_span(), Some((40, 9)));
        assert_eq!(excel.dat_runs(), vec![(40, 9)]);
        assert!(index.get("It's.txt").is_some());
    }
}
