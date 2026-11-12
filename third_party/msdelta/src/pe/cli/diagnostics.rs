//! Named CLI regions of a managed image, for differential debugging.

use super::metadata::parse_cli_metadata_from_pe;
use super::method::cli_method_bodies;
use super::schema::CliSchemaFlavor;

pub(crate) fn regions(image: &[u8]) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    let Ok(pe) = crate::pe::parse::PeInfo::parse_lenient(image) else {
        return out;
    };
    let Ok(md) = parse_cli_metadata_from_pe(image, CliSchemaFlavor::Cli4) else {
        return out;
    };
    out.push(("metadata-root".to_owned(), md.metadata_file_offset, 0x20));
    for (name, stream) in [
        ("#Strings", &md.streams.strings),
        ("#US", &md.streams.user_strings),
        ("#Blob", &md.streams.blob),
        ("#GUID", &md.streams.guid),
    ] {
        if let Some(s) = stream {
            out.push((name.to_owned(), s.file_offset, s.size as usize));
        }
    }
    out.push(("#~header".to_owned(), md.streams.tables.file_offset, 24));
    for t in 0..64usize {
        if let Some(off) = md.table_file_offsets[t] {
            let len = md.row_counts[t] as usize * md.row_sizes[t] as usize;
            out.push((
                format!("table{t:02x}(rowsize {})", md.row_sizes[t]),
                off,
                len,
            ));
        }
    }
    for body in cli_method_bodies(image, &pe, &md) {
        out.push((
            format!("il-rid{}", body.rid),
            body.file_offset,
            body.total_size,
        ));
        // Extra data sections (EH tables) start 4-aligned after the code.
        let code_end = body.file_offset + body.header_size + body.code_size;
        let eh_start = (code_end + 3) & !3;
        let end = body.file_offset + body.total_size;
        if end > eh_start {
            out.push((
                format!("eh-rid{}@{eh_start:#x}", body.rid),
                eh_start,
                end - eh_start,
            ));
        }
    }
    out
}

/// Every table column that points into `#Blob`: (heap offset, "Table[rid].Column").
pub(crate) fn blob_refs(image: &[u8]) -> Vec<(u32, String)> {
    use super::metadata::CliColumnValue;
    use super::schema::{table_schema, ColumnKind, HeapKind};
    let mut out = Vec::new();
    let Ok(md) = parse_cli_metadata_from_pe(image, CliSchemaFlavor::Cli4) else {
        return out;
    };
    for t in 0..64u8 {
        let Some(schema) = table_schema(t) else {
            continue;
        };
        for rid in 1..=md.row_counts[t as usize] {
            let Ok(row) = md.table_row_by_id(image, t, rid) else {
                continue;
            };
            for col in schema.columns {
                if col.kind != ColumnKind::Heap(HeapKind::Blob) {
                    continue;
                }
                if let Ok(CliColumnValue::Heap { offset, .. }) = row.column(col.name) {
                    out.push((offset, format!("{}[{rid}].{}", schema.name, col.name)));
                }
            }
        }
    }
    out
}

/// File offset of the `#Blob` heap.
pub(crate) fn blob_heap(image: &[u8]) -> Option<(usize, usize)> {
    let md = parse_cli_metadata_from_pe(image, CliSchemaFlavor::Cli4).ok()?;
    md.streams
        .blob
        .as_ref()
        .map(|b| (b.file_offset, b.size as usize))
}
