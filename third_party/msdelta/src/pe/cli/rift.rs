//! CLI compression-rift producer: a port of msdelta.dll's
//! `CompressionRiftTableFrom(Cli|Cli4)MapComponent::InternalProcess`
//! (10.0.26100.9974). Both flavours run the same algorithm; only the
//! column-descriptor table differs, and that is folded into `table_schema`.
//!
//! The rift maps TARGET file offsets (`source` field) to SOURCE file offsets
//! (`target` field) for the metadata heaps and tables, so LZX copies into the
//! target's metadata resolve against T(source).

use crate::lzx::rift::{RiftEntry, RiftTable};
use crate::pe::cli::map::CliMapModel;
use crate::pe::cli::metadata::{CliMetadataBitstreamRecord, CliMetadataModel, CliStream};
use crate::pe::cli::schema::{column_width, table_schema, CliSchemaFlavor, HeapIndexWidths};
use crate::{Error, Result};

/// Map entries whose source is beyond this end the walk (native sentinel).
const CLI_MAP_SOURCE_SENTINEL: i64 = u32::MAX as i64;

pub(crate) fn build_cli_heap_rift(
    source_heap_file_offset: usize,
    target_heap_file_offset: u32,
    heap_map: &RiftTable,
) -> RiftTable {
    let mut entries = Vec::new();
    add_heap_map(
        &mut entries,
        source_heap_file_offset as i64,
        i64::from(target_heap_file_offset),
        heap_map,
    );
    sorted_rift(entries)
}

/// Only the three heap streams (`#Strings`, `#US`, `#Blob`).
pub(crate) fn build_cli_heap_compression_rift(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
) -> RiftTable {
    if target_metadata.is_empty() {
        return empty_rift();
    }
    let mut entries = Vec::new();
    add_heap_maps(&mut entries, source_metadata, target_metadata, cli_map);
    sorted_rift(entries)
}

/// One table whose source and target rows have the same layout.
pub(crate) fn build_cli_table_rift(
    source_table_file_offset: usize,
    target_table_file_offset: usize,
    row_size: u32,
    table_map: &RiftTable,
) -> RiftTable {
    let mut entries = Vec::new();
    add_table_map(
        &mut entries,
        source_table_file_offset as i64,
        target_table_file_offset as i64,
        i64::from(row_size),
        table_map,
    );
    sorted_rift(entries)
}

pub(crate) fn build_cli_compression_rift(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
) -> RiftTable {
    build_cli_compression_rift_impl(source_metadata, target_metadata, cli_map, None)
}

pub(crate) fn build_cli_compression_rift_with_source_fill_offset(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
    source_widening_fill_offset: i64,
) -> RiftTable {
    build_cli_compression_rift_impl(
        source_metadata,
        target_metadata,
        cli_map,
        Some(source_widening_fill_offset),
    )
}

pub(crate) fn build_cli_compression_rift_from_transformed_source(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
    transformed_source: &[u8],
) -> RiftTable {
    build_cli_compression_rift_with_source_fill_offset(
        source_metadata,
        target_metadata,
        cli_map,
        cli_source_widening_fill_offset(transformed_source),
    )
}

pub(crate) fn build_cli4_compression_rift(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
) -> Result<RiftTable> {
    build_cli4_compression_rift_impl(source_metadata, target_metadata, cli_map, None)
}

pub(crate) fn build_cli4_compression_rift_with_source_fill_offset(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
    source_widening_fill_offset: i64,
) -> Result<RiftTable> {
    build_cli4_compression_rift_impl(
        source_metadata,
        target_metadata,
        cli_map,
        Some(source_widening_fill_offset),
    )
}

pub(crate) fn build_cli4_compression_rift_from_transformed_source(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
    transformed_source: &[u8],
) -> Result<RiftTable> {
    build_cli4_compression_rift_with_source_fill_offset(
        source_metadata,
        target_metadata,
        cli_map,
        cli_source_widening_fill_offset(transformed_source),
    )
}

/// The first offset of two adjacent zero bytes in the copy source (or its
/// length): where widened columns take their extra high bytes from.
pub(crate) fn cli_source_widening_fill_offset(transformed_source: &[u8]) -> i64 {
    transformed_source
        .windows(2)
        .position(|window| window == [0, 0])
        .unwrap_or(transformed_source.len()) as i64
}

fn build_cli4_compression_rift_impl(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
    source_widening_fill_offset: Option<i64>,
) -> Result<RiftTable> {
    if source_metadata.flavor != CliSchemaFlavor::Cli4 {
        return Err(Error::Malformed(
            "CLI4 compression rift: source metadata flavor mismatch",
        ));
    }
    if target_metadata.flavor != CliSchemaFlavor::Cli4 {
        return Err(Error::Malformed(
            "CLI4 compression rift: target metadata flavor mismatch",
        ));
    }
    Ok(build_cli_compression_rift_impl(
        source_metadata,
        target_metadata,
        cli_map,
        source_widening_fill_offset,
    ))
}

/// `InternalProcess`: the three heaps, the GUID heap as 16-byte rows, then
/// every table present (non-zero row count) on both sides, in table order;
/// finally a stable sort. A missing stream contributes offset 0, as in the
/// zero-initialised native `CliMetadata`.
fn build_cli_compression_rift_impl(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
    source_widening_fill_offset: Option<i64>,
) -> RiftTable {
    if target_metadata.is_empty() {
        return empty_rift();
    }

    let mut entries = Vec::new();
    add_heap_maps(&mut entries, source_metadata, target_metadata, cli_map);
    add_table_map(
        &mut entries,
        stream_offset(source_metadata.streams.guid),
        i64::from(target_metadata.streams.guid.file_offset),
        16,
        &cli_map.guid,
    );

    for table_id in 0..64usize {
        let source_rows = source_metadata.row_counts[table_id];
        if source_rows == 0 || target_metadata.row_counts[table_id] == 0 {
            continue;
        }
        let source_table = source_metadata.table_file_offsets[table_id].unwrap_or(0) as i64;
        let target_table = target_metadata.table_file_offsets[table_id].unwrap_or(0) as i64;
        let source_row_size = source_metadata.row_sizes[table_id];
        let target_row_size = target_metadata.row_sizes[table_id];
        let columns = column_layouts(
            table_id as u8,
            (&source_metadata.row_counts, source_metadata.heap_widths),
            (&target_metadata.row_counts, target_metadata.heap_widths),
        );
        let table_map = &cli_map.tables[table_id];
        if source_row_size == target_row_size
            && columns.iter().all(|c| c.source_width == c.target_width)
        {
            add_table_map(
                &mut entries,
                source_table,
                target_table,
                i64::from(source_row_size),
                table_map,
            );
        } else {
            add_relaid_table_map(
                &mut entries,
                RelaidTable {
                    source_table,
                    target_table,
                    source_rows,
                    source_row_size: i64::from(source_row_size),
                    target_row_size: i64::from(target_row_size),
                    columns: &columns,
                    fill: source_widening_fill_offset,
                },
                table_map,
            );
        }
    }
    sorted_rift(entries)
}

fn add_heap_maps(
    entries: &mut Vec<RiftEntry>,
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
) {
    let source = &source_metadata.streams;
    let target = &target_metadata.streams;
    for (source_stream, target_offset, map) in [
        (source.strings, target.strings.file_offset, &cli_map.strings),
        (
            source.user_strings,
            target.user_strings.file_offset,
            &cli_map.user_strings,
        ),
        (source.blob, target.blob.file_offset, &cli_map.blob),
    ] {
        add_heap_map(
            entries,
            stream_offset(source_stream),
            i64::from(target_offset),
            map,
        );
    }
}

fn stream_offset(stream: Option<CliStream>) -> i64 {
    stream.map_or(0, |stream| stream.file_offset as i64)
}

fn push(entries: &mut Vec<RiftEntry>, target_offset: i64, source_offset: i64) {
    entries.push(RiftEntry {
        source: target_offset,
        target: source_offset,
    });
}

/// Index of the first map entry whose source exceeds `floor`, and the entry
/// that covers everything up to it: the one just before, or (when the very
/// first entry already exceeds `floor`) the last one, the native
/// below-the-first-entry rule.
fn split_map(map: &RiftTable, floor: i64) -> (usize, &RiftEntry) {
    let first = map
        .entries
        .iter()
        .position(|e| e.source > floor)
        .unwrap_or(map.entries.len());
    let covering = if first > 0 {
        &map.entries[first - 1]
    } else {
        &map.entries[map.entries.len() - 1]
    };
    (first, covering)
}

/// `AddHeapMap`: heap-relative map entries become file offsets.
fn add_heap_map(
    entries: &mut Vec<RiftEntry>,
    source_offset: i64,
    target_offset: i64,
    map: &RiftTable,
) {
    if map.entries.is_empty() {
        push(entries, target_offset, source_offset);
        return;
    }
    let (first, covering) = split_map(map, 0);
    push(
        entries,
        target_offset - covering.source + covering.target,
        source_offset,
    );
    for entry in &map.entries[first..] {
        if entry.source > CLI_MAP_SOURCE_SENTINEL {
            break;
        }
        push(
            entries,
            target_offset + entry.target,
            source_offset + entry.source,
        );
    }
}

/// `AddTableMap(src, tgt, rowSize, map)`: same row layout on both sides, so
/// one entry per map segment (rid 1 first).
fn add_table_map(
    entries: &mut Vec<RiftEntry>,
    source_offset: i64,
    target_offset: i64,
    row_size: i64,
    map: &RiftTable,
) {
    if map.entries.is_empty() {
        push(entries, target_offset, source_offset);
        return;
    }
    let (first, covering) = split_map(map, 1);
    push(
        entries,
        target_offset + (covering.target - covering.source) * row_size,
        source_offset,
    );
    for entry in &map.entries[first..] {
        if entry.source > CLI_MAP_SOURCE_SENTINEL {
            break;
        }
        push(
            entries,
            (entry.target - 1) * row_size + target_offset,
            (entry.source - 1) * row_size + source_offset,
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ColumnLayout {
    source_offset: i64,
    target_offset: i64,
    source_width: u32,
    target_width: u32,
}

fn column_layouts(
    table_id: u8,
    (source_rows, source_heaps): (&[u32; 64], HeapIndexWidths),
    (target_rows, target_heaps): (&[u32; 64], HeapIndexWidths),
) -> Vec<ColumnLayout> {
    let Some(schema) = table_schema(table_id) else {
        return Vec::new();
    };
    let (mut source_offset, mut target_offset) = (0i64, 0i64);
    schema
        .columns
        .iter()
        .map(|column| {
            let layout = ColumnLayout {
                source_offset,
                target_offset,
                source_width: u32::from(column_width(column.kind, source_rows, source_heaps)),
                target_width: u32::from(column_width(column.kind, target_rows, target_heaps)),
            };
            source_offset += i64::from(layout.source_width);
            target_offset += i64::from(layout.target_width);
            layout
        })
        .collect()
}

struct RelaidTable<'a> {
    source_table: i64,
    target_table: i64,
    source_rows: u32,
    source_row_size: i64,
    target_row_size: i64,
    columns: &'a [ColumnLayout],
    /// `None` only for callers that build a rift without a copy source.
    fill: Option<i64>,
}

/// `AddTableMap(src, tgt, table)`: the row layout changed (row size or a
/// column width), so every source row gets its own entry, plus entries
/// around each column whose width changed. Like the other native per-row
/// loops these run over rids `1..rows-1`: the last source row gets none.
fn add_relaid_table_map(entries: &mut Vec<RiftEntry>, table: RelaidTable<'_>, map: &RiftTable) {
    let rows = i64::from(table.source_rows);
    let target_row = |rid: i64| (rid - 1 + map.map(rid)) * table.target_row_size;
    let source_row = |rid: i64| (rid - 1) * table.source_row_size;

    for rid in 1..rows {
        push(
            entries,
            target_row(rid) + table.target_table,
            source_row(rid) + table.source_table,
        );
    }
    for (index, column) in table.columns.iter().enumerate() {
        if column.source_width == column.target_width {
            continue;
        }
        let last_column = index + 1 >= table.columns.len();
        let source_column = table.source_table + column.source_offset;
        let target_column = table.target_table + column.target_offset;
        if column.source_width < column.target_width {
            // Widened: the new high half comes from the zero fill, the rest of
            // the row resumes after the source column.
            for rid in 1..rows {
                let base = target_row(rid) + target_column;
                if let Some(fill) = table.fill {
                    push(entries, base + 2, fill);
                }
                if !last_column {
                    push(entries, base + 4, source_column + 2 + source_row(rid));
                }
            }
        } else if !last_column {
            // Narrowed: skip the source column's dropped high half.
            for rid in 1..rows {
                push(
                    entries,
                    target_column + 2 + target_row(rid),
                    source_row(rid) + 4 + source_column,
                );
            }
        }
    }
}

fn sorted_rift(mut entries: Vec<RiftEntry>) -> RiftTable {
    // Stable, like the native LSD radix `RiftTable::Sort`: among equal keys the
    // entry added last wins a lookup.
    entries.sort_by_key(|entry| entry.source);
    RiftTable { entries }
}

const fn empty_rift() -> RiftTable {
    RiftTable {
        entries: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::cli::metadata::{
        parse_cli_metadata_from_pe, CliMetadataBitstreamStream, CliMetadataBitstreamStreams,
        CliStreamSet,
    };
    use crate::pe::cli::schema::{row_size, CliSchemaFlavor, HeapIndexWidths};
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    const MANAGED_NATIVE_CASES: &[&str] = &[
        "cli-const-string",
        "cli-add-method",
        "cli-generics-signature",
        "cli-custom-attribute",
        "cli-resource",
        "cli-platform-x64",
        "cli-properties-events",
        "cli-interface-impl",
        "cli-constructor-token-boundary",
        "cli-static-constructor-token-boundary",
        "cli-constructor-user-string-boundary",
        "cli-exception-switch",
        "cli-pinvoke-module",
        "cli-nested-struct-enum-array",
    ];
    const MANAGED_STAGE_RIFT_CASES: &[&str] = &[
        "cli-const-string",
        "cli-add-method",
        "cli-generics-signature",
        "cli-custom-attribute",
        "cli-resource",
        "cli-platform-x64",
    ];

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    fn pairs(table: &RiftTable) -> Vec<(i64, i64)> {
        table
            .entries
            .iter()
            .map(|entry| (entry.source, entry.target))
            .collect()
    }

    fn eval(table: &RiftTable, target_file_offset: i64) -> i64 {
        target_file_offset.wrapping_add(table.map(target_file_offset))
    }

    fn managed_native_corpus_dir() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/atoms/ManagedNativeCorpus"
        ))
    }

    fn cli_compression_rift_fixture_dir() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/atoms/FridaStageCapture/cli-compression-rift-win26100/objects"
        ))
    }

    const fn narrow_heap_widths() -> HeapIndexWidths {
        HeapIndexWidths {
            strings: 2,
            guid: 2,
            blob: 2,
        }
    }

    #[test]
    fn heap_rift_empty_map_adds_base_mapping() {
        let table = build_cli_heap_rift(0x1000, 0x3000, &rift(&[]));

        assert_eq!(pairs(&table), vec![(0x3000, 0x1000)]);
        assert_eq!(eval(&table, 0x3010), 0x1010);
    }

    #[test]
    fn heap_rift_converts_heap_relative_map_to_file_offsets() {
        let table =
            build_cli_heap_rift(0x1000, 0x3000, &rift(&[(0, 0), (0x64, 0x6a), (0x74, 0x85)]));

        assert_eq!(
            pairs(&table),
            vec![(0x3000, 0x1000), (0x306a, 0x1064), (0x3085, 0x1074)]
        );
        assert_eq!(eval(&table, 0x306a), 0x1064);
        assert_eq!(eval(&table, 0x3070), 0x106a);
    }

    #[test]
    fn heap_rift_stops_at_native_source_sentinel() {
        let table = build_cli_heap_rift(
            0x1000,
            0x3000,
            &rift(&[(0, 0), (0x20, 0x30), (0x1_0000_0000, 0x40)]),
        );

        assert_eq!(pairs(&table), vec![(0x3000, 0x1000), (0x3030, 0x1020)]);
    }

    #[test]
    fn heap_rift_without_a_zero_entry_starts_from_the_last_entry() {
        // Offset 0 lies below the first map entry, so (as in RiftTable::Map)
        // the LAST entry's delta places the heap start.
        let table = build_cli_heap_rift(0x1000, 0x3000, &rift(&[(0x10, 0x20), (0x40, 0x30)]));

        assert_eq!(
            pairs(&table),
            vec![(0x2ff0, 0x1000), (0x3020, 0x1010), (0x3030, 0x1040)]
        );
    }

    #[test]
    fn table_rift_empty_map_adds_base_mapping() {
        let table = build_cli_table_rift(0x1000, 0x3000, 10, &rift(&[]));

        assert_eq!(pairs(&table), vec![(0x3000, 0x1000)]);
        assert_eq!(eval(&table, 0x3005), 0x1005);
    }

    #[test]
    fn table_rift_converts_rids_to_row_file_offsets() {
        let table = build_cli_table_rift(0x1000, 0x3000, 10, &rift(&[(0, 0), (3, 4), (7, 8)]));

        assert_eq!(
            pairs(&table),
            vec![(0x3000, 0x1000), (0x301e, 0x1014), (0x3046, 0x103c)]
        );
        assert_eq!(eval(&table, 0x3020), 0x1016);
    }

    #[test]
    fn table_rift_rid_one_entry_places_the_first_row() {
        // Entries with rid <= 1 are folded into the first-row entry.
        let table = build_cli_table_rift(0x1000, 0x3000, 10, &rift(&[(0, 0), (1, 3), (10, 12)]));

        assert_eq!(pairs(&table), vec![(0x3014, 0x1000), (0x306e, 0x105a)]);
    }

    #[test]
    fn table_rift_stops_at_native_source_sentinel() {
        let table = build_cli_table_rift(
            0x1000,
            0x3000,
            10,
            &rift(&[(0, 0), (2, 4), (0x1_0000_0000, 9)]),
        );

        assert_eq!(pairs(&table), vec![(0x3000, 0x1000), (0x301e, 0x100a)]);
    }

    /// The table part of a full compression rift for one table at source
    /// 0x1000 / target 0x3000, no heaps (their four `(0, 0)` entries are
    /// dropped). `rows` set `(table, count)` pairs on each side.
    fn table_only_rift(
        table_id: u8,
        source_rows: &[(usize, u32)],
        target_rows: &[(usize, u32)],
        map: RiftTable,
        transformed_source: &[u8],
    ) -> Vec<(i64, i64)> {
        let heap_widths = narrow_heap_widths();
        let mut source = source_metadata_model();
        source.streams.strings = None;
        source.streams.user_strings = None;
        source.streams.blob = None;
        source.heap_widths = heap_widths;
        for &(t, n) in source_rows {
            source.row_counts[t] = n;
        }
        source.row_sizes[table_id as usize] =
            row_size(table_id, &source.row_counts, heap_widths).unwrap() as u32;
        source.table_file_offsets[table_id as usize] = Some(0x1000);

        let mut target = target_metadata_record();
        for stream in [
            &mut target.streams.strings,
            &mut target.streams.user_strings,
            &mut target.streams.blob,
        ] {
            *stream = CliMetadataBitstreamStream {
                file_offset: 0,
                size: 0,
            };
        }
        target.heap_widths = heap_widths;
        for &(t, n) in target_rows {
            target.row_counts[t] = n;
        }
        target.row_sizes[table_id as usize] =
            row_size(table_id, &target.row_counts, heap_widths).unwrap() as u32;
        target.table_file_offsets[table_id as usize] = Some(0x3000);

        let mut cli_map = CliMapModel::default();
        cli_map.tables[table_id as usize] = map;
        let table = build_cli_compression_rift_from_transformed_source(
            &source,
            &target,
            &cli_map,
            transformed_source,
        );
        let all = pairs(&table);
        assert_eq!(
            &all[..4],
            &[(0, 0); 4],
            "absent heaps and GUID map at offset 0"
        );
        all[4..].to_vec()
    }

    // TypeDef rows: Flags(4) Name(2) Namespace(2) Extends(2) FieldList(2|4)
    // MethodList(2|4). The fill source below is a zero pair at 0x9000.
    fn fill_at_0x9000() -> Vec<u8> {
        let mut buf = vec![1u8; 0x9002];
        buf[0x9000] = 0;
        buf[0x9001] = 0;
        buf
    }

    #[test]
    fn relaid_table_widened_nonterminal_column() {
        let pairs = table_only_rift(
            0x02,
            &[(0x02, 3)],
            &[(0x02, 4), (0x04, 1 << 16)],
            rift(&[(0, 0), (2, 3)]),
            &fill_at_0x9000(),
        );
        // One entry per source row except the last, then the widened
        // FieldList: high half from the fill, remainder resumes after it.
        assert_eq!(
            pairs,
            vec![
                (0x3000, 0x1000),
                (0x300c, 0x9000),
                (0x300e, 0x100c),
                (0x3020, 0x100e),
                (0x302c, 0x9000),
                (0x302e, 0x101a),
            ]
        );
    }

    #[test]
    fn relaid_table_narrowed_nonterminal_column() {
        let pairs = table_only_rift(
            0x02,
            &[(0x02, 2), (0x04, 1 << 16)],
            &[(0x02, 4)],
            rift(&[(0, 0), (2, 4)]),
            &fill_at_0x9000(),
        );
        assert_eq!(pairs, vec![(0x3000, 0x1000), (0x300c, 0x100e)]);
    }

    #[test]
    fn relaid_table_terminal_widening_uses_fill_without_resume() {
        let pairs = table_only_rift(
            0x02,
            &[(0x02, 2)],
            &[(0x02, 2), (0x06, 1 << 16)],
            rift(&[]),
            &fill_at_0x9000(),
        );
        assert_eq!(pairs, vec![(0x3000, 0x1000), (0x300e, 0x9000)]);
    }

    #[test]
    fn relaid_table_terminal_narrowing_adds_only_row_entries() {
        let pairs = table_only_rift(
            0x02,
            &[(0x02, 2), (0x06, 1 << 16)],
            &[(0x02, 2)],
            rift(&[]),
            &fill_at_0x9000(),
        );
        assert_eq!(pairs, vec![(0x3000, 0x1000)]);
    }

    #[test]
    fn relaid_single_row_table_gets_no_entries() {
        // The per-row loops run over rids 1..rows-1.
        let pairs = table_only_rift(
            0x02,
            &[(0x02, 1)],
            &[(0x02, 1), (0x04, 1 << 16)],
            rift(&[]),
            &fill_at_0x9000(),
        );
        assert!(pairs.is_empty());
    }

    #[test]
    fn relaid_table_takes_fill_offset_from_the_copy_source() {
        let pairs = table_only_rift(
            0x02,
            &[(0x02, 2)],
            &[(0x02, 2), (0x04, 1 << 16)],
            rift(&[]),
            &[0xaa, 0xbb, 0, 0, 0xcc],
        );
        assert_eq!(pairs, vec![(0x3000, 0x1000), (0x300c, 2), (0x300e, 0x100c)]);
    }

    #[test]
    fn source_widening_fill_offset_uses_first_adjacent_zero_pair() {
        assert_eq!(cli_source_widening_fill_offset(&[]), 0);
        assert_eq!(cli_source_widening_fill_offset(&[0]), 1);
        assert_eq!(cli_source_widening_fill_offset(&[1, 2, 3]), 3);
        assert_eq!(cli_source_widening_fill_offset(&[0, 0, 3]), 0);
        assert_eq!(cli_source_widening_fill_offset(&[1, 0, 0, 3]), 1);
        assert_eq!(cli_source_widening_fill_offset(&[1, 2, 0, 0]), 2);
    }

    #[test]
    fn heap_compression_rift_composes_strings_user_strings_and_blob_streams() {
        let source_metadata = source_metadata_model();
        let target_metadata = target_metadata_record();
        let cli_map = CliMapModel {
            strings: rift(&[(0, 0), (0x20, 0x28)]),
            user_strings: rift(&[]),
            blob: rift(&[(0, 0), (0x10, 0x18)]),
            ..CliMapModel::default()
        };

        let table = build_cli_heap_compression_rift(&source_metadata, &target_metadata, &cli_map);

        assert_eq!(
            pairs(&table),
            vec![
                (0x6000, 0x5000),
                (0x6028, 0x5020),
                (0x6200, 0x5100),
                (0x6400, 0x5300),
                (0x6418, 0x5310),
            ]
        );
    }

    #[test]
    fn heap_compression_rift_is_empty_without_target_metadata() {
        let table = build_cli_heap_compression_rift(
            &source_metadata_model(),
            &CliMetadataBitstreamRecord::empty(CliSchemaFlavor::Classic),
            &CliMapModel::default(),
        );

        assert!(table.entries.is_empty());
    }

    fn composed_map() -> CliMapModel {
        let mut cli_map = CliMapModel {
            strings: rift(&[(0, 0), (0x20, 0x28)]),
            blob: rift(&[(0, 0), (0x10, 0x18)]),
            guid: rift(&[(0, 0), (2, 3)]),
            ..CliMapModel::default()
        };
        cli_map.tables[0x02] = rift(&[(0, 0), (2, 3)]);
        cli_map
    }

    const COMPOSED: [(i64, i64); 9] = [
        (0x6000, 0x5000),
        (0x6028, 0x5020),
        (0x6200, 0x5100),
        (0x6400, 0x5300),
        (0x6418, 0x5310),
        (0x6500, 0x5400),
        (0x6520, 0x5410),
        (0x6600, 0x5500),
        (0x661c, 0x550e),
    ];

    #[test]
    fn cli_compression_rift_composes_heap_guid_and_table_rifts() {
        let table = build_cli_compression_rift(
            &source_metadata_with_tables(),
            &target_metadata_with_tables(),
            &composed_map(),
        );

        assert_eq!(pairs(&table), COMPOSED.to_vec());
    }

    #[test]
    fn cli4_compression_rift_composes_typed_heap_guid_and_table_rifts() {
        let table = build_cli4_compression_rift(
            &as_cli4_source(source_metadata_with_tables()),
            &as_cli4_target(target_metadata_with_tables()),
            &composed_map(),
        )
        .unwrap();

        assert_eq!(pairs(&table), COMPOSED.to_vec());
    }

    #[test]
    fn absent_streams_contribute_offset_zero() {
        // No GUID stream on either side: the native zero-initialised offsets
        // still produce an entry (0 -> 0).
        let table = build_cli_compression_rift(
            &source_metadata_model(),
            &target_metadata_record(),
            &CliMapModel::default(),
        );

        assert_eq!(
            pairs(&table),
            vec![(0, 0), (0x6000, 0x5000), (0x6200, 0x5100), (0x6400, 0x5300)]
        );
    }

    #[test]
    fn heap_compression_rift_builds_from_managed_native_corpus() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_heap_rift = 0usize;
        for case in MANAGED_NATIVE_CASES {
            let case_dir = root.join(case);
            let source =
                std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
            let delta =
                std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
            let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
            let preprocess = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess)
                .expect("parse classic managed preprocess");
            if !preprocess.target_info.has_target_metadata() {
                continue;
            }
            let source_metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
                .expect("parse source CLI metadata");

            let table = build_cli_heap_compression_rift(
                &source_metadata,
                &preprocess.target_info.target_metadata,
                &preprocess.cli_map,
            );
            if table.entries.is_empty() {
                continue;
            }

            cases_with_heap_rift += 1;
            assert!(
                table
                    .entries
                    .windows(2)
                    .all(|window| window[0].source <= window[1].source),
                "{case}: heap compression rift should be sorted"
            );
            assert!(
                table
                    .entries
                    .iter()
                    .all(|entry| entry.source >= 0 && entry.target >= 0),
                "{case}: heap compression rift should stay in file-offset domain"
            );
        }

        assert!(
            cases_with_heap_rift > 0,
            "managed corpus should include at least one non-empty heap compression rift"
        );
    }

    #[test]
    fn cli_compression_rift_builds_from_managed_native_corpus() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_cli_rift = 0usize;
        for case in MANAGED_NATIVE_CASES {
            let case_dir = root.join(case);
            let source =
                std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
            let delta =
                std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
            let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
            let preprocess = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess)
                .expect("parse classic managed preprocess");
            if !preprocess.target_info.has_target_metadata() {
                continue;
            }
            let source_metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
                .expect("parse source CLI metadata");

            let table = build_cli_compression_rift(
                &source_metadata,
                &preprocess.target_info.target_metadata,
                &preprocess.cli_map,
            );
            if table.entries.is_empty() {
                continue;
            }

            cases_with_cli_rift += 1;
            assert!(
                table
                    .entries
                    .windows(2)
                    .all(|window| window[0].source <= window[1].source),
                "{case}: CLI compression rift should be sorted"
            );
            assert!(
                table
                    .entries
                    .iter()
                    .all(|entry| entry.source >= 0 && entry.target >= 0),
                "{case}: CLI compression rift should stay in file-offset domain"
            );
        }

        assert!(
            cases_with_cli_rift > 0,
            "managed corpus should include at least one non-empty CLI compression rift"
        );
    }

    #[test]
    fn cli_compression_rift_matches_win26100_stage_fixture_shapes() {
        let corpus_root = managed_native_corpus_dir();
        let fixture_root = cli_compression_rift_fixture_dir();
        if !corpus_root.exists() || !fixture_root.exists() {
            return;
        }

        let mut rust_shapes = BTreeSet::new();
        for case in MANAGED_STAGE_RIFT_CASES {
            let case_dir = corpus_root.join(case);
            let source =
                std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
            let delta =
                std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
            let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
            let preprocess = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess)
                .expect("parse classic managed preprocess");
            let source_metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
                .expect("parse source CLI metadata");

            let table = build_cli_compression_rift_from_transformed_source(
                &source_metadata,
                &preprocess.target_info.target_metadata,
                &preprocess.cli_map,
                &source,
            );
            rust_shapes.insert((
                source.len() as i64,
                cli_source_widening_fill_offset(&source),
                pairs(&table),
            ));
        }

        let mut native_shapes = BTreeSet::new();
        for entry in std::fs::read_dir(&fixture_root).expect("read compression rift fixture dir") {
            let path = entry.expect("read fixture entry").path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let value: Value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
            let source_buffer_size = value["source_buffer"]["size"]
                .as_i64()
                .expect("native source buffer size should be numeric");
            let fill_offset = value["source_widening_fill_offset"]
                .as_i64()
                .expect("native fill offset should be numeric");
            let entries = value["rift"]["entries"]
                .as_array()
                .expect("native rift entries should be an array")
                .iter()
                .map(|entry| {
                    (
                        entry["source"].as_i64().expect("native source offset"),
                        entry["target"].as_i64().expect("native target offset"),
                    )
                })
                .collect::<Vec<_>>();
            native_shapes.insert((source_buffer_size, fill_offset, entries));
        }

        assert_eq!(
            rust_shapes, native_shapes,
            "Rust CLI compression rift output should match promoted Win26100 native stage records"
        );
    }

    #[test]
    fn cli4_compression_rift_rejects_classic_metadata() {
        let source_metadata = source_metadata_with_tables();
        let target_metadata = as_cli4_target(target_metadata_with_tables());

        let err = build_cli4_compression_rift(
            &source_metadata,
            &target_metadata,
            &CliMapModel::default(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            Error::Malformed("CLI4 compression rift: source metadata flavor mismatch")
        ));
    }

    fn as_cli4_source(mut model: CliMetadataModel) -> CliMetadataModel {
        model.flavor = CliSchemaFlavor::Cli4;
        model
    }

    fn as_cli4_target(mut record: CliMetadataBitstreamRecord) -> CliMetadataBitstreamRecord {
        record.flavor = CliSchemaFlavor::Cli4;
        record
    }

    fn source_metadata_model() -> CliMetadataModel {
        CliMetadataModel {
            flavor: CliSchemaFlavor::Classic,
            metadata_rva: 0x2000,
            metadata_file_offset: 0x4000,
            metadata_size: 0x1000,
            version: "v4.0.30319".to_owned(),
            streams: CliStreamSet {
                strings: Some(CliStream {
                    metadata_offset: 0x1000,
                    file_offset: 0x5000,
                    size: 0x80,
                }),
                user_strings: Some(CliStream {
                    metadata_offset: 0x1100,
                    file_offset: 0x5100,
                    size: 0x40,
                }),
                blob: Some(CliStream {
                    metadata_offset: 0x1300,
                    file_offset: 0x5300,
                    size: 0x60,
                }),
                guid: None,
                tables: CliStream {
                    metadata_offset: 0,
                    file_offset: 0x4000,
                    size: 24,
                },
            },
            heap_widths: HeapIndexWidths {
                strings: 2,
                guid: 2,
                blob: 2,
            },
            valid_table_mask: 0,
            sorted_table_mask: 0,
            row_counts: [0; 64],
            row_sizes: [0; 64],
            table_file_offsets: [None; 64],
        }
    }

    fn target_metadata_record() -> CliMetadataBitstreamRecord {
        CliMetadataBitstreamRecord {
            flavor: CliSchemaFlavor::Classic,
            present: true,
            metadata_file_offset: 0x5000,
            metadata_size: 0x1200,
            metadata_rva: 0x3000,
            stream_count: 5,
            stream_headers_end: 0x100,
            streams: CliMetadataBitstreamStreams {
                strings: CliMetadataBitstreamStream {
                    file_offset: 0x6000,
                    size: 0x90,
                },
                user_strings: CliMetadataBitstreamStream {
                    file_offset: 0x6200,
                    size: 0x40,
                },
                blob: CliMetadataBitstreamStream {
                    file_offset: 0x6400,
                    size: 0x80,
                },
                guid: CliMetadataBitstreamStream {
                    file_offset: 0,
                    size: 0,
                },
                tables: CliMetadataBitstreamStream {
                    file_offset: 0x5000,
                    size: 24,
                },
            },
            heap_widths: HeapIndexWidths {
                strings: 2,
                guid: 2,
                blob: 2,
            },
            valid_table_mask: 0,
            row_counts: [0; 64],
            row_sizes: [0; 64],
            table_file_offsets: [None; 64],
        }
    }

    fn source_metadata_with_tables() -> CliMetadataModel {
        let mut model = source_metadata_model();
        model.streams.guid = Some(CliStream {
            metadata_offset: 0x1400,
            file_offset: 0x5400,
            size: 0x20,
        });
        model.valid_table_mask = 1 << 0x02;
        model.row_counts[0x02] = 4;
        model.row_sizes[0x02] =
            row_size(0x02, &model.row_counts, model.heap_widths).unwrap() as u32;
        model.table_file_offsets[0x02] = Some(0x5500);
        model
    }

    fn target_metadata_with_tables() -> CliMetadataBitstreamRecord {
        let mut record = target_metadata_record();
        record.streams.guid = CliMetadataBitstreamStream {
            file_offset: 0x6500,
            size: 0x30,
        };
        record.valid_table_mask = 1 << 0x02;
        record.row_counts[0x02] = 5;
        record.row_sizes[0x02] =
            row_size(0x02, &record.row_counts, record.heap_widths).unwrap() as u32;
        record.table_file_offsets[0x02] = Some(0x6600);
        record
    }
}
