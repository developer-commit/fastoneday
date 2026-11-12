//! Faithful ports of msdelta.dll's PE model and of the source-transform steps
//! whose exact behaviour decides which bytes the PseudoLzx copy stage sees.
//!
//! Reverse-engineered from msdelta.dll 10.0.26100.9974 (November 2026) with its
//! public PDB:
//!
//! * `compo::SectionHelper` (`AttemptInit`, `CheckSectionsRawData`,
//!   `GetImageOffset`, `GetMaxSize`) and `compo::DataDirectories`
//!   (`AttemptInit`, `ProcessImportDirectory`, `ProcessExportDirectory`,
//!   `ProcessRelocationDirectory`, `GetImageImportByName`) -> [`NativeImage`].
//! * `MarkNonExeComponent::Transform` -> [`mark_non_exe`].
//! * `RiftTransformImportsComponent::TransformImports{32,64}` ->
//!   [`transform_imports`].
//! * `RiftTransformExportsComponent::Transform` -> [`transform_exports`].
//! * the marker side of `RiftTransformRelocationsComponent::ReadRelocationEntries`
//!   -> [`mark_relocations`].
//! * `RiftTransformDisasmAmd64Component::Transform` -> [`transform_disasm_amd64`].
//!
//! The native code keeps one byte per file offset (the "marker"): bit 0 = the
//! byte belongs to something an instruction pass must not start decoding at,
//! bit 1 = additionally an instruction may not run across it. MarkNonExe writes
//! 1 (non-executable section data) and 3 (headers, every data directory),
//! imports/exports write 3, relocations OR in 1. The amd64 disassembly pass
//! skips bytes with `& 3` and cuts an instruction at a byte with `& 2`.
//!
//! Widths, signedness and bounds below mirror the native code, including its
//! quirks (noted inline): T(source) has to be bit-identical for copies to land.

use crate::lzx::rift::RiftTable;

pub(crate) const MARK_NON_EXE: u8 = 1;
pub(crate) const MARK_DATA: u8 = 3;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Section {
    pub va: u32,
    pub vsize: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Dir {
    pub rva: u32,
    /// File offset, 0 when the directory is absent or unmapped.
    pub offset: u32,
    /// Size clamped to the end of the file.
    pub size: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeImage {
    pub len: u32,
    pub is_pe32: bool,
    pub machine: u16,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub sections: Vec<Section>,
    pub n_dirs: u32,
    pub dirs: [Dir; 16],
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn wr32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn wr64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// `memset(marker + start, value, len)`, clamped to the marker.
pub(crate) fn fill(marker: &mut [u8], start: usize, len: usize, value: u8) {
    let end = start.saturating_add(len).min(marker.len());
    if start < end {
        marker[start..end].fill(value);
    }
}

fn or_bits(marker: &mut [u8], start: usize, len: usize, value: u8) {
    let end = start.saturating_add(len).min(marker.len());
    for m in marker.iter_mut().take(end).skip(start) {
        *m |= value;
    }
}

impl NativeImage {
    /// `SectionHelper::AttemptInit` + `DataDirectories::AttemptInit`. `None`
    /// where the native code fails initialisation (and so runs no transform).
    pub(crate) fn parse(b: &[u8]) -> Option<Self> {
        let len = u32::try_from(b.len()).ok()?;
        if len < 0x200 || rd16(b, 0) != 0x5a4d {
            return None;
        }
        let nt = rd32(b, 0x3c) as usize;
        // PE32 needs the full 0xF8-byte NT header with a 0xE0 optional header,
        // PE32+ 0x108 bytes with 0xF0; nothing else is accepted.
        let is_pe32 = if nt + 0xf8 <= b.len()
            && rd16(b, nt + 0x18) == 0x10b
            && rd16(b, nt + 0x14) == 0xe0
        {
            true
        } else if nt + 0x108 <= b.len() && rd16(b, nt + 0x18) == 0x20b && rd16(b, nt + 0x14) == 0xf0
        {
            false
        } else {
            return None;
        };
        if rd32(b, nt) != 0x4550 {
            return None;
        }
        let machine = rd16(b, nt + 4);
        match machine {
            0x14c if !is_pe32 => return None,
            0x200 | 0x8664 if is_pe32 => return None,
            _ => {}
        }
        let sec_off = nt + 0x18 + rd16(b, nt + 0x14) as usize;
        let nsec = rd16(b, nt + 6) as usize;
        if sec_off + nsec * 0x28 > b.len() {
            return None;
        }
        let sections: Vec<Section> = (0..nsec)
            .map(|i| {
                let s = sec_off + i * 0x28;
                Section {
                    va: rd32(b, s + 12),
                    vsize: rd32(b, s + 8),
                    raw_size: rd32(b, s + 16),
                    raw_ptr: rd32(b, s + 20),
                    characteristics: rd32(b, s + 36),
                }
            })
            .collect();
        // CheckSectionsRawData: every section's raw data lies inside the file.
        for s in &sections {
            let end = (s.raw_ptr as i32).wrapping_add(s.raw_size as i32);
            if (s.raw_ptr as i32 as i64) > len as i64
                || end < s.raw_ptr as i32
                || end as i64 > len as i64
            {
                return None;
            }
        }
        let image_base = if is_pe32 {
            rd32(b, nt + 0x34) as u64
        } else {
            rd64(b, nt + 0x30)
        };
        let size_of_headers = rd32(b, nt + 0x54).min(len);
        let (n_dirs, dir_arr) = if is_pe32 {
            (rd32(b, nt + 0x74), nt + 0x78)
        } else {
            (rd32(b, nt + 0x84), nt + 0x88)
        };
        let mut image = NativeImage {
            len,
            is_pe32,
            machine,
            image_base,
            size_of_image: rd32(b, nt + 0x50),
            size_of_headers,
            sections,
            n_dirs,
            dirs: [Dir::default(); 16],
        };
        for i in 0..16usize {
            if (n_dirs as i32) <= i as i32 {
                continue;
            }
            let rva = rd32(b, dir_arr + i * 8);
            let size = rd32(b, dir_arr + i * 8 + 4);
            let mut offset = image.image_offset(rva, 0);
            if offset == 0 && len > rva {
                // Unmapped but inside the file: the RVA doubles as the offset.
                offset = rva;
            }
            image.dirs[i].rva = rva;
            if offset != 0 {
                let avail = (len as i32).wrapping_sub(offset as i32);
                let clamped = if avail <= size as i32 {
                    avail
                } else {
                    size as i32
                };
                image.dirs[i].offset = offset;
                image.dirs[i].size = clamped as u32;
            }
        }
        Some(image)
    }

    fn section_for(&self, rva: u32) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.va <= rva && s.va.wrapping_add(s.raw_size) > rva)
    }

    /// `SectionHelper::GetImageOffset`: file offset of `size` bytes at `rva`, 0
    /// on failure. Sections are matched on their RAW size; header RVAs map to
    /// themselves.
    pub(crate) fn image_offset(&self, rva: u32, size: u32) -> u32 {
        if self.size_of_headers <= rva {
            if let Some(s) = self.section_for(rva) {
                let delta = rva - s.va;
                if delta <= s.raw_size && size <= s.raw_size - delta {
                    return s.raw_ptr.wrapping_add(delta);
                }
            }
            0
        } else if size <= self.size_of_headers - rva {
            rva
        } else {
            0
        }
    }

    /// `CliHelper::GetMethodOffset`: `(file offset, header size, header + IL
    /// code size)` of the method body at `rva`. Extra data sections (EH
    /// tables) are never included: the native section walk sits behind a
    /// `first header byte == 0` test inside the fat-header branch, so it is
    /// unreachable, and those bytes stay visible to the i386 E8/E9 passes.
    pub(crate) fn method_offset(&self, buf: &[u8], rva: u32) -> Option<(usize, usize, usize)> {
        let off = self.image_offset(rva, 0) as usize;
        if off == 0 {
            return None;
        }
        let max = self.max_size(rva);
        if max < 1 {
            return None;
        }
        let first = *buf.get(off)?;
        match first & 3 {
            2 => {
                let code = u32::from(first >> 2);
                (code < max).then_some((off, 1, code as usize + 1))
            }
            3 if max >= 12 => {
                let header = u32::from(*buf.get(off + 1)? >> 4) << 2;
                if header < 12 || header > max {
                    return None;
                }
                let code = u32::from_le_bytes(buf.get(off + 4..off + 8)?.try_into().ok()?);
                (code <= max - header).then_some((off, header as usize, (header + code) as usize))
            }
            _ => None,
        }
    }

    /// `SectionHelper::GetMaxSize`: bytes available from `rva` to the end of
    /// its section's raw data (or of the headers).
    pub(crate) fn max_size(&self, rva: u32) -> u32 {
        if self.size_of_headers <= rva {
            match self.section_for(rva) {
                Some(s) => s.va.wrapping_add(s.raw_size).wrapping_sub(rva),
                None => 0,
            }
        } else {
            self.size_of_headers - rva
        }
    }

    /// `DataDirectories::GetImageImportByName`: file offset of the
    /// `IMAGE_IMPORT_BY_NAME` at `rva` and the name length, when the 2-byte hint
    /// and a NUL-terminated name fit before the end of the containing section
    /// (or of the headers).
    pub(crate) fn import_by_name(&self, buf: &[u8], rva: u32) -> Option<(usize, usize)> {
        let off = self.image_offset(rva, 4);
        if off == 0 {
            return None;
        }
        let end = if self.size_of_headers > rva {
            self.size_of_headers
        } else {
            let s = self.section_for(rva)?;
            s.va.wrapping_add(s.raw_size)
        };
        let avail = end.wrapping_sub(rva) as i32;
        let mut k = 2i32;
        if avail <= 2 {
            return None;
        }
        while buf.get(off as usize + k as usize).copied().unwrap_or(0) != 0 {
            k += 1;
            if avail <= k {
                break;
            }
        }
        (avail > k).then_some((off as usize, (k - 2) as usize))
    }

    /// `ProcessImportDirectory`: descriptor file offsets, cut at the first one
    /// whose OriginalFirstThunk is zero (not at an all-zero descriptor).
    fn import_descriptors(&self, buf: &[u8]) -> Vec<usize> {
        let dir = self.dirs[1];
        if dir.offset == 0 {
            return Vec::new();
        }
        let count = dir.size / 20;
        let mut out = Vec::new();
        for i in 0..count as usize {
            let at = dir.offset as usize + i * 20;
            if at + 20 > buf.len() || rd32(buf, at) == 0 {
                break;
            }
            out.push(at);
        }
        out
    }
}

/// `MarkNonExeComponent::Transform` (flag bit 1, every machine type).
pub(crate) fn mark_non_exe(image: &NativeImage, marker: &mut [u8]) {
    let len = marker.len() as i64;
    for s in &image.sections {
        if s.characteristics & 0x2000_0000 != 0 {
            continue;
        }
        let ptr = s.raw_ptr as i32 as i64;
        if ptr < len {
            let n = (len - ptr).min(s.raw_size as i32 as i64);
            if n > 0 {
                fill(marker, ptr as usize, n as usize, MARK_NON_EXE);
            }
        }
    }
    fill(marker, 0, image.size_of_headers as usize, MARK_DATA);
    for i in 0..(image.n_dirs.min(16) as usize) {
        let d = image.dirs[i];
        if d.offset != 0 {
            fill(marker, d.offset as usize, d.size as usize, MARK_DATA);
        }
    }
}

/// `InplaceMapRva` on a 32-bit RVA field (zero is mapped like any value).
fn inplace_map_rva(buf: &mut [u8], fo: usize, rift: &RiftTable) {
    if fo + 4 <= buf.len() {
        let v = rd32(buf, fo) as i64;
        wr32(buf, fo, (v + rift.map(v)) as u32);
    }
}

/// `TransformImports32` / `TransformImports64`. Returns the file ranges it
/// claimed so the caller can mirror them into other bookkeeping.
pub(crate) fn transform_imports(
    buf: &mut [u8],
    image: &NativeImage,
    rift: &RiftTable,
    marker: &mut [u8],
) -> Vec<(usize, usize)> {
    let ptr = if image.is_pe32 { 4usize } else { 8 };
    let shift = if image.is_pe32 { 2 } else { 3 };
    let read = |buf: &[u8], fo: usize| -> u64 {
        if image.is_pe32 {
            rd32(buf, fo) as u64
        } else {
            rd64(buf, fo)
        }
    };
    let negative = |v: u64| -> bool {
        if image.is_pe32 {
            (v as u32 as i32) < 0
        } else {
            (v as i64) < 0
        }
    };
    let mut claimed = Vec::new();
    for desc in image.import_descriptors(buf) {
        let oft = rd32(buf, desc);
        let tds = rd32(buf, desc + 4);
        let ft = rd32(buf, desc + 16);

        // OriginalFirstThunk array.
        let max = image.max_size(oft) >> shift;
        let oft_fo = image.image_offset(oft, 0) as usize;
        if oft_fo != 0 {
            // Native quirk: the by-ordinal test reads the FIRST thunk of the
            // array for every entry, not the current one.
            let first_is_ordinal = oft_fo + ptr <= buf.len() && negative(read(buf, oft_fo));
            let mut k = 0usize;
            while (k as u32) < max {
                let fo = oft_fo + k * ptr;
                if fo + ptr > buf.len() || read(buf, fo) == 0 {
                    break;
                }
                if !first_is_ordinal {
                    let rva = read(buf, fo) as u32;
                    if let Some((name_fo, name_len)) = image.import_by_name(buf, rva) {
                        fill(marker, name_fo, name_len + 3, MARK_DATA);
                        claimed.push((name_fo, name_len + 3));
                        inplace_map_rva(buf, fo, rift);
                    }
                }
                k += 1;
            }
            fill(marker, oft_fo, k * ptr, MARK_DATA);
            claimed.push((oft_fo, k * ptr));
        }

        // FirstThunk (IAT) array.
        let max = image.max_size(ft) >> shift;
        let ft_fo = image.image_offset(ft, 0) as usize;
        if ft_fo != 0 {
            let mut k = 0usize;
            while (k as u32) < max {
                let fo = ft_fo + k * ptr;
                if fo + ptr > buf.len() {
                    break;
                }
                let v = read(buf, fo);
                if v == 0 {
                    break;
                }
                if tds != 0 {
                    // Bound import: an absolute VA, mapped as an RVA of this
                    // image and re-based on the (source) image base.
                    if image.is_pe32 {
                        let base = image.image_base as u32;
                        let r = v as u32 as i32;
                        let r = r.wrapping_sub(base as i32) as u32 as i64;
                        let mapped = (r + rift.map(r)) as u32;
                        wr32(buf, fo, mapped.wrapping_add(base));
                    } else {
                        let r = v.wrapping_sub(image.image_base) as i64;
                        let mapped = r.wrapping_add(rift.map(r));
                        wr64(buf, fo, (mapped as u64).wrapping_add(image.image_base));
                    }
                } else if !negative(v) {
                    if let Some((name_fo, name_len)) = image.import_by_name(buf, v as u32) {
                        fill(marker, name_fo, name_len + 3, MARK_DATA);
                        claimed.push((name_fo, name_len + 3));
                        inplace_map_rva(buf, fo, rift);
                    }
                }
                k += 1;
            }
            fill(marker, ft_fo, k * ptr, MARK_DATA);
            claimed.push((ft_fo, k * ptr));
        }

        // The descriptor's own RVA fields: Name, OriginalFirstThunk, FirstThunk.
        inplace_map_rva(buf, desc + 12, rift);
        inplace_map_rva(buf, desc, rift);
        inplace_map_rva(buf, desc + 16, rift);
    }
    claimed
}

/// `RiftTransformExportsComponent::Transform` with `ProcessExportDirectory`'s
/// validity rules. Returns the claimed file ranges.
pub(crate) fn transform_exports(
    buf: &mut [u8],
    image: &NativeImage,
    rift: &RiftTable,
    marker: &mut [u8],
) -> Vec<(usize, usize)> {
    let dir = image.dirs[0];
    let mut claimed = Vec::new();
    if dir.offset == 0 || dir.size < 0x28 || dir.offset as usize + 0x28 > buf.len() {
        return claimed;
    }
    let d = dir.offset as usize;
    let n_funcs = rd32(buf, d + 0x14);
    let mut eat = None;
    if n_funcs <= 0x3fff_ffff {
        let off = image.image_offset(rd32(buf, d + 0x1c), n_funcs << 2);
        if off != 0 {
            eat = Some((off as usize, n_funcs as usize));
        }
    }
    let n_names = rd32(buf, d + 0x18);
    let mut names = None;
    if n_names <= 0x3fff_ffff {
        let npt = image.image_offset(rd32(buf, d + 0x20), n_names << 2);
        let ord = image.image_offset(rd32(buf, d + 0x24), n_names.wrapping_mul(2));
        if npt != 0 && ord != 0 {
            names = Some((npt as usize, ord as usize, n_names as usize));
        }
    }
    if let Some((off, n)) = eat {
        fill(marker, off, n * 4, MARK_DATA);
        claimed.push((off, n * 4));
        for i in 0..n {
            inplace_map_rva(buf, off + i * 4, rift);
        }
    }
    if let Some((npt, ord, n)) = names {
        fill(marker, npt, n * 4, MARK_DATA);
        claimed.push((npt, n * 4));
        for i in 0..n {
            inplace_map_rva(buf, npt + i * 4, rift);
        }
        fill(marker, ord, n * 2, MARK_DATA);
        claimed.push((ord, n * 2));
    }
    for field in [0x0c, 0x1c, 0x20, 0x24] {
        inplace_map_rva(buf, d + field, rift);
    }
    claimed
}

/// The marker writes of `ReadRelocationEntries`: every relocated field's
/// bytes get bit 0. (The value remapping itself is done by the relocation
/// transform.)
pub(crate) fn mark_relocations(buf: &[u8], image: &NativeImage, marker: &mut [u8]) {
    let dir = image.dirs[5];
    if dir.offset == 0 {
        return;
    }
    let len = buf.len();
    let mut p = dir.offset as usize;
    let mut remaining = dir.size as i32;
    while remaining >= 8 && p + 8 <= len {
        let block = rd32(buf, p + 4) as i32;
        if block < 8 || block > remaining {
            break;
        }
        let page = rd32(buf, p);
        let off = image.image_offset(page, 0) as usize;
        if off != 0 {
            let n = ((block - 8) >> 1) as usize;
            let mut j = 0usize;
            while j < n {
                let e = rd16(buf, p + 8 + j * 2);
                let typ = e >> 12;
                if typ == 0 {
                    break;
                }
                let at = off + (e & 0xfff) as usize;
                match typ {
                    3 if at + 4 <= len => or_bits(marker, at, 4, 1),
                    1 | 2 if at + 2 <= len => or_bits(marker, at, 2, 1),
                    4 => {
                        if at + 2 <= len {
                            or_bits(marker, at, 2, 1);
                        }
                        // HIGHADJ consumes the next entry as its parameter.
                        if n - j > 1 {
                            j += 1;
                        }
                    }
                    10 if at + 8 <= len => or_bits(marker, at, 8, 1),
                    _ => {}
                }
                j += 1;
            }
        }
        p += block as usize;
        remaining -= block;
        if remaining == 0 {
            break;
        }
    }
}

/// `RiftTransformDisasmAmd64Component::Transform`: walk every `.pdata`
/// function range, length-decode its instructions (skipping marked bytes and
/// cutting at bit-1 marks) and re-point every rel32 / RIP-relative disp32 so
/// `MapRva(target) - MapRva(next_ip)` holds. Returns the rewrite count.
pub(crate) fn transform_disasm_amd64(
    buf: &mut [u8],
    image: &NativeImage,
    rift: &RiftTable,
    marker: &[u8],
) -> u32 {
    if image.machine != 0x8664 {
        return 0;
    }
    let pdata = image.dirs[3];
    if pdata.offset == 0 {
        return 0;
    }
    let count = (pdata.size / 12) as usize;
    let mut changed = 0u32;
    for f in 0..count {
        let e = pdata.offset as usize + f * 12;
        if e + 8 > buf.len() {
            break;
        }
        let begin = rd32(buf, e);
        let end = rd32(buf, e + 4);
        if end <= begin {
            continue;
        }
        let mut remaining = end - begin;
        let fo = image.image_offset(begin, remaining);
        if fo == 0 {
            continue;
        }
        let mut p = fo as usize;
        let mut rva = begin;
        while remaining != 0 {
            if marker.get(p).copied().unwrap_or(0) & 3 != 0 {
                remaining -= 1;
                p += 1;
                rva = rva.wrapping_add(1);
                continue;
            }
            let window = (remaining as usize).min(15);
            let insn = crate::pe::transform::disasm_amd64(&buf[p..p + window]);
            let ilen = insn.len.max(1) as u32;
            // An instruction may not run across a byte with mark bit 1.
            let mut k = 1u32;
            let mut cut = false;
            while k < ilen {
                if marker.get(p + k as usize).copied().unwrap_or(0) & 2 != 0 {
                    cut = true;
                    break;
                }
                k += 1;
            }
            if cut {
                remaining -= k;
                p += k as usize;
                rva = rva.wrapping_add(k);
                continue;
            }
            if insn.remap {
                let field = p + insn.field_off as usize;
                if field + 4 <= buf.len() {
                    // 32-bit arithmetic, zero-extended into the rift lookup.
                    let next = rva.wrapping_add(ilen);
                    let target = rd32(buf, field).wrapping_add(next);
                    let mapped_next = (next as i64 + rift.map(next as i64)) as u32;
                    let mapped_target = (target as i64 + rift.map(target as i64)) as u32;
                    let disp = mapped_target.wrapping_sub(mapped_next);
                    if disp != rd32(buf, field) {
                        wr32(buf, field, disp);
                        changed += 1;
                    }
                }
            }
            remaining -= ilen;
            p += ilen as usize;
            rva = rva.wrapping_add(ilen);
        }
    }
    changed
}

/// Executable sections as the i386 passes scan them: file range
/// `[raw_ptr, raw_ptr + min(VirtualSize, SizeOfRawData))` and its RVA.
fn exec_ranges(image: &NativeImage) -> Vec<(usize, usize, u32)> {
    image
        .sections
        .iter()
        .filter(|s| s.characteristics & 0x2000_0000 != 0)
        .filter_map(|s| {
            let size = s.vsize.min(s.raw_size);
            let end = s.raw_ptr.wrapping_add(size);
            (image.len >= s.raw_ptr && image.len >= end).then_some((
                s.raw_ptr as usize,
                size as usize,
                s.va,
            ))
        })
        .collect()
}

/// `MapRva(target) - MapRva(site_end)` with the native 32-bit arithmetic.
fn remapped_disp(rift: &RiftTable, site_end: u32, target: u32) -> i32 {
    let mapped_site = (site_end as i64 + rift.map(site_end as i64)) as u32;
    let mapped_target = (target as i64 + rift.map(target as i64)) as u32;
    mapped_target.wrapping_sub(mapped_site) as i32
}

/// The checks both i386 branch passes make before touching a rel32: the
/// target lies inside the image and its first byte is unmarked (bit 0).
fn target_ok(image: &NativeImage, marker: &[u8], target: u32) -> bool {
    if target >= image.size_of_image {
        return false;
    }
    let off = image.image_offset(target, 0) as usize;
    off != 0 && marker.get(off).copied().unwrap_or(1) & 1 == 0
}

fn clean(marker: &[u8], at: usize, len: usize) -> bool {
    (at..at + len).all(|i| marker.get(i).copied().unwrap_or(1) & 1 == 0)
}

/// `RiftTransformRelativeJmpsI386Component::Transform` (flag bit 7): long
/// `E9 rel32` / `0F 8x rel32` branches whose displacement does not fit a byte
/// are re-pointed through the rift; when the new displacement fits in a byte
/// the instruction is rewritten in place to its short form (`EB rel8`, or
/// `7x rel8` over the `0F 8x` bytes), exactly as the native code does.
pub(crate) fn transform_relative_jmps_i386(
    buf: &mut [u8],
    image: &NativeImage,
    rift: &RiftTable,
    marker: &[u8],
) -> u32 {
    if image.machine != 0x14c {
        return 0;
    }
    let mut changed = 0;
    for (start, size, va) in exec_ranges(image) {
        if size <= 5 {
            continue;
        }
        let end = start + size - 5;
        let mut p = start;
        while p < end {
            let at = if buf[p] == 0xe9 {
                Some(p)
            } else if buf[p] == 0x0f && end > p + 1 && buf[p + 1] & 0xf0 == 0x80 {
                p += 1;
                Some(p)
            } else {
                None
            };
            if let Some(q) = at {
                let jcc = buf[q] != 0xe9;
                let ok = !(jcc && marker.get(q - 1).copied().unwrap_or(1) & 1 != 0);
                if ok && clean(marker, q, 5) {
                    let disp = rd32(buf, q + 1) as i32;
                    if (disp as u32).wrapping_add(0x80) > 0xff {
                        let site_end = ((q - start) as u32).wrapping_add(5).wrapping_add(va);
                        let target = site_end.wrapping_add(disp as u32);
                        if target_ok(image, marker, target) {
                            let new = remapped_disp(rift, site_end, target);
                            if (-128..=127).contains(&new) {
                                if buf[q] == 0xe9 {
                                    buf[q] = 0xeb;
                                    buf[q + 1] = new as u8;
                                } else {
                                    let cc = buf[q] & 0x0f;
                                    buf[q] = new as u8;
                                    buf[q - 1] = cc | 0x70;
                                }
                                changed += 1;
                            } else if new != disp {
                                wr32(buf, q + 1, new as u32);
                                changed += 1;
                            }
                            p = q + 4;
                        }
                    }
                }
                p = p.max(q);
            }
            p += 1;
        }
    }
    changed
}

/// `RiftTransformRelativeCallsI386Component::Transform` (flag bit 8).
pub(crate) fn transform_relative_calls_i386(
    buf: &mut [u8],
    image: &NativeImage,
    rift: &RiftTable,
    marker: &[u8],
) -> u32 {
    if image.machine != 0x14c {
        return 0;
    }
    let mut changed = 0;
    for (start, size, va) in exec_ranges(image) {
        if size <= 5 {
            continue;
        }
        let end = start + size - 5;
        let mut p = start;
        while p < end {
            if buf[p] == 0xe8 && clean(marker, p, 5) {
                let disp = rd32(buf, p + 1) as i32;
                let site_end = ((p - start) as u32).wrapping_add(5).wrapping_add(va);
                let target = site_end.wrapping_add(disp as u32);
                if target_ok(image, marker, target) {
                    let new = remapped_disp(rift, site_end, target);
                    if new != disp {
                        wr32(buf, p + 1, new as u32);
                        changed += 1;
                    }
                    p += 4;
                }
            }
            p += 1;
        }
    }
    changed
}

/// `RiftTransformRelocationsI386Component::TransformInferredRelocations`:
/// for i386 images WITHOUT a relocation directory, every dword after the
/// headers that looks like a pointer into the image (`ImageBase < v <
/// ImageBase + SizeOfImage`, signed compares) and whose bytes carry no mark
/// bit 1 is claimed (bit 0) and re-based through the rift onto the target
/// image base. Pointer hits advance by 4, everything else by 1.
pub(crate) fn transform_inferred_relocations_i386(
    buf: &mut [u8],
    image: &NativeImage,
    rift: &RiftTable,
    marker: &mut [u8],
    target_base: u64,
) -> u32 {
    if image.machine != 0x14c || buf.len() < 4 {
        return 0;
    }
    let base = image.image_base as u32 as i32;
    let limit = base.wrapping_add(image.size_of_image as i32);
    let end = (buf.len() as i32).wrapping_sub(4);
    let mut i = image.size_of_headers as i32;
    let mut changed = 0;
    while i < end {
        let at = i as usize;
        let v = rd32(buf, at) as i32;
        if v < limit && v > base {
            let marks =
                u32::from_le_bytes([marker[at], marker[at + 1], marker[at + 2], marker[at + 3]]);
            if marks & 0x0202_0202 == 0 {
                for m in &mut marker[at..at + 4] {
                    *m |= 1;
                }
                let rva = v.wrapping_sub(base) as i64;
                let mapped = rva + rift.map(rva);
                wr32(buf, at, (target_base as u32).wrapping_add(mapped as u32));
                changed += 1;
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::{RiftEntry, RiftTable};

    fn rift(pairs: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: pairs
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    #[test]
    fn rift_map_matches_native_lookup() {
        let r = rift(&[(0x1000, 0x1100), (0x2000, 0x2400), (0x3000, 0x2f00)]);
        // Below the first entry the native code uses the LAST entry.
        assert_eq!(r.map(0x10), 0x2f00 - 0x3000);
        assert_eq!(r.map(-5), 0x2f00 - 0x3000);
        assert_eq!(r.map(0x1000), 0x100);
        assert_eq!(r.map(0x1fff), 0x100);
        assert_eq!(r.map(0x2000), 0x400);
        assert_eq!(r.map(0x9_0000_0000), -0x100);
        assert_eq!(rift(&[]).map(123), 0);
    }

    /// A tiny PE32+ with one executable section, built in memory.
    fn image_with(text: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c] = 0x80;
        let nt = 0x80;
        b[nt..nt + 4].copy_from_slice(b"PE\0\0");
        b[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        b[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes());
        b[nt + 0x14..nt + 0x16].copy_from_slice(&0xf0u16.to_le_bytes());
        b[nt + 0x18..nt + 0x1a].copy_from_slice(&0x20bu16.to_le_bytes());
        b[nt + 0x30..nt + 0x38].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        b[nt + 0x54..nt + 0x58].copy_from_slice(&0x200u32.to_le_bytes());
        b[nt + 0x84..nt + 0x88].copy_from_slice(&16u32.to_le_bytes());
        let s = nt + 0x18 + 0xf0;
        b[s..s + 5].copy_from_slice(b".text");
        b[s + 8..s + 12].copy_from_slice(&0x200u32.to_le_bytes());
        b[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
        b[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        b[s + 36..s + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        b[0x200..0x200 + text.len()].copy_from_slice(text);
        b
    }

    #[test]
    fn section_helper_rules() {
        let b = image_with(&[0xc3]);
        let img = NativeImage::parse(&b).unwrap();
        assert_eq!(img.image_offset(0x1000, 0x200), 0x200);
        assert_eq!(img.image_offset(0x1000, 0x201), 0);
        assert_eq!(img.image_offset(0x10, 4), 0x10);
        assert_eq!(img.image_offset(0x5000, 0), 0);
        assert_eq!(img.max_size(0x1100), 0x100);
        assert_eq!(img.max_size(0x40), 0x1c0);
    }

    #[test]
    fn disasm_rewrites_rel32_and_respects_marks() {
        // 0x1000: call 0x1007 ; 0x1005: two E8 data bytes (marked) ;
        // 0x1007: call 0x1005. Everything from 0x1006 on moves up by 0x100.
        let mut text = vec![
            0xe8, 0x02, 0, 0, 0, 0xe8, 0xe8, 0xe8, 0xf9, 0xff, 0xff, 0xff,
        ];
        text.resize(0x20, 0xcc);
        let mut b = image_with(&text);
        let mut img = NativeImage::parse(&b).unwrap();
        // One .pdata entry covering [0x1000, 0x100c), placed in the headers.
        b[0x300..0x30c].copy_from_slice(&[0x00, 0x10, 0, 0, 0x0c, 0x10, 0, 0, 0, 0, 0, 0]);
        img.dirs[3] = Dir {
            rva: 0x300,
            offset: 0x300,
            size: 12,
        };
        let r = rift(&[(0, 0), (0x1006, 0x1106)]);
        let mut marker = vec![0u8; b.len()];
        marker[0x205] = MARK_DATA;
        marker[0x206] = MARK_DATA;
        let unmarked = b.clone();
        assert_eq!(transform_disasm_amd64(&mut b, &img, &r, &marker), 2);
        // next 0x1005 stays, target 0x1007 -> 0x1107: disp 0x102.
        assert_eq!(&b[0x201..0x205], &0x102u32.to_le_bytes());
        // next 0x100c -> 0x110c, target 0x1005 stays: disp -0x107.
        assert_eq!(&b[0x208..0x20c], &(-0x107i32).to_le_bytes());
        // Without the marks the data bytes would be decoded as a call and the
        // real one at 0x1007 never seen.
        let mut b2 = unmarked;
        let no_marks = vec![0u8; b2.len()];
        transform_disasm_amd64(&mut b2, &img, &r, &no_marks);
        assert_ne!(&b2[0x208..0x20c], &(-0x107i32).to_le_bytes());
    }
}
