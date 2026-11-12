//! CLI signature blob token remapping, reproducing msdelta.dll's walker.

use crate::pe::cli::blob::{read_compressed_u32, write_compressed_u32_canonical_within};
use crate::pe::cli::map::CliMapModel;

/// The signature walker inlined in msdelta.dll's CLI metadata transforms
/// (`RiftTransformCliMetadataComponent::Transform` and its CLI4 twin,
/// 10.0.26100.9974), checked against native T(source) dumps. It is NOT an ECMA-335 parser; its quirks
/// are reproduced on purpose because T(source) must match byte for byte:
///
/// * walked blob kinds: 1/2 (MethodDef/MemberRef: method sig, or field sig
///   when the first byte is 0x06), 3 (Field), 4 (Property), 5 (TypeSpec) and
///   9 (StandAloneSig: LocalVarSig on 0x07, otherwise as kind 1);
/// * a method sig is `conv count` + (count + 1) types; the conv byte is not
///   decoded, so a generic method's GenParamCount is taken as the count;
/// * VOID / TYPEDBYREF in a parameter slot re-enter the loop WITHOUT
///   advancing, so they end the walk (a void method never reaches its
///   parameters);
/// * GENERICINST is only a flag: the generic type's token is mapped, array
///   shapes are skipped, and the generic argument count and arguments are
///   then consumed as if they were the following parameters;
/// * a LocalVarSig only looks at its FIRST local; TypeSpec and field sigs end
///   after their first token;
/// * TypeDefOrRef tags 0 AND 1 map through the TypeDef rid map, tag 2 through
///   TypeSpec, tag 3 is kept; every token is written back canonically when
///   the new encoding fits in the old width.
pub(crate) fn transform_signature_blob_native(
    blob: &mut [u8],
    kind: u8,
    cli_map: &CliMapModel,
) -> usize {
    let mut w = NativeWalker {
        blob,
        pos: 0,
        cli_map,
        rewrites: 0,
    };
    let _ = match kind {
        1 | 2 => w.method_or_field(),
        3 => w.field(),
        4 => w.property(),
        5 => w.type_(),
        9 => w.standalone(),
        _ => Ok(()),
    };
    w.rewrites
}

struct NativeWalker<'a> {
    blob: &'a mut [u8],
    pos: usize,
    cli_map: &'a CliMapModel,
    rewrites: usize,
}

/// The walk ended: end of blob, a malformed integer, or one of the native
/// "give up on this blob" branches.
struct Stop;

impl NativeWalker<'_> {
    fn byte(&mut self) -> Result<u8, Stop> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    fn peek(&self) -> Result<u8, Stop> {
        self.blob.get(self.pos).copied().ok_or(Stop)
    }

    fn compressed(&mut self) -> Result<(u32, usize, usize), Stop> {
        let start = self.pos;
        let (value, width) =
            read_compressed_u32(self.blob.get(start..).ok_or(Stop)?).map_err(|_| Stop)?;
        self.pos += width;
        Ok((value, start, width))
    }

    /// A TypeDefOrRef coded token, remapped in place.
    fn map_coded(&mut self) -> Result<(), Stop> {
        let (raw, start, width) = self.compressed()?;
        let tag = raw & 3;
        let mapped = match tag {
            0 | 1 => self.map_rid(0x02, raw, tag),
            2 => self.map_rid(0x1b, raw, tag),
            _ => raw,
        };
        if write_compressed_u32_canonical_within(&mut self.blob[start..], width, mapped)
            && mapped != raw
        {
            self.rewrites += 1;
        }
        Ok(())
    }

    fn map_rid(&self, table: usize, raw: u32, tag: u32) -> u32 {
        let rid = i64::from(raw >> 2);
        ((rid.wrapping_add(self.cli_map.tables[table].map(rid)) as u32) << 2) | tag
    }

    /// 0x4X prefix bytes and custom modifiers (whose tokens are mapped).
    fn modifiers(&mut self) -> Result<(), Stop> {
        loop {
            let b = self.peek()?;
            if b & 0xf0 == 0x40 {
                self.pos += 1;
            } else if b == 0x1f || b == 0x20 {
                self.pos += 1;
                self.map_coded()?;
            } else {
                return Ok(());
            }
        }
    }

    /// One type. `Ok` when it is complete, `Err` for every native branch that
    /// abandons the blob.
    fn type_(&mut self) -> Result<(), Stop> {
        let mut arrays = 0u32;
        let mut generic = false;
        loop {
            let b = self.byte()?;
            if b == 0 {
                return Err(Stop);
            }
            if b < 0x1a && !(0x0e..=0x17).contains(&b) {
                break; // primitive (VOID included)
            }
            match b {
                0x11 | 0x12 => {
                    self.map_coded()?;
                    break;
                }
                0x0e | 0x1c => break,
                0x13 | 0x1e => {
                    self.compressed()?;
                    break;
                }
                0x15 => generic = true,
                0x14 => arrays += 1,
                0x0f | 0x1d => {
                    self.modifiers()?;
                    if self.peek()? == 0x01 {
                        self.pos += 1;
                        break;
                    }
                }
                _ => return Err(Stop),
            }
        }
        if !generic {
            for _ in 0..arrays {
                self.compressed()?;
                let (sizes, _, _) = self.compressed()?;
                for _ in 0..sizes {
                    self.compressed()?;
                }
                let (bounds, _, _) = self.compressed()?;
                for _ in 0..bounds {
                    self.compressed()?;
                }
            }
        }
        Ok(())
    }

    /// One parameter slot; `Err` also when VOID / TYPEDBYREF end the walk.
    fn param(&mut self) -> Result<(), Stop> {
        self.modifiers()?;
        match self.peek()? {
            0x01 | 0x16 => return Err(Stop),
            0x10 => self.pos += 1,
            _ => {}
        }
        self.type_()
    }

    fn method_or_field(&mut self) -> Result<(), Stop> {
        if self.peek()? == 0x06 {
            self.field()
        } else {
            self.method()
        }
    }

    fn field(&mut self) -> Result<(), Stop> {
        self.pos += 1;
        self.modifiers()?;
        self.type_()
    }

    fn method(&mut self) -> Result<(), Stop> {
        self.byte()?;
        let (count, _, _) = self.compressed()?;
        for _ in 0..=count {
            self.param()?;
        }
        Ok(())
    }

    /// Like a method sig, but the property type is read with no modifier
    /// loop in front of it.
    fn property(&mut self) -> Result<(), Stop> {
        self.byte()?;
        let (count, _, _) = self.compressed()?;
        self.type_()?;
        for _ in 0..count {
            self.param()?;
        }
        Ok(())
    }

    fn standalone(&mut self) -> Result<(), Stop> {
        if self.peek()? != 0x07 {
            return self.method_or_field();
        }
        self.pos += 1;
        self.compressed()?; // local count: only the first local is visited
        while self.peek()? & 0xf0 == 0x40 {
            self.pos += 1;
        }
        if self.peek()? == 0x10 {
            self.pos += 1;
        }
        self.type_()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::{RiftEntry, RiftTable};

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    /// TypeDef rid map: identity below `from`, `+by` from there on.
    fn typedef_shift(from: i64, by: i64) -> CliMapModel {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x02] = rift(&[(0, 0), (from, from + by)]);
        cli_map
    }

    fn walk(kind: u8, mut blob: Vec<u8>, cli_map: &CliMapModel) -> (Vec<u8>, usize) {
        let rewrites = transform_signature_blob_native(&mut blob, kind, cli_map);
        (blob, rewrites)
    }

    #[test]
    fn tags_zero_and_one_use_the_typedef_map_and_tag_two_typespec() {
        let mut cli_map = typedef_shift(3, 4);
        cli_map.tables[0x01] = rift(&[(0, 0), (3, 30)]); // never consulted
        cli_map.tables[0x1b] = rift(&[(0, 0), (1, 3)]);
        // int32 M(class 0x0d, valuetype 0x0c, class TypeSpec#1)
        let (blob, rewrites) = walk(
            1,
            vec![0x00, 0x03, 0x08, 0x12, 0x0d, 0x11, 0x0c, 0x12, 0x06],
            &cli_map,
        );
        assert_eq!(
            blob,
            vec![0x00, 0x03, 0x08, 0x12, 0x1d, 0x11, 0x1c, 0x12, 0x0e]
        );
        assert_eq!(rewrites, 3);
    }

    #[test]
    fn void_return_ends_the_walk() {
        let cli_map = typedef_shift(1, 8);
        assert_eq!(
            walk(1, vec![0x00, 0x01, 0x01, 0x12, 0x4d], &cli_map).0,
            vec![0x00, 0x01, 0x01, 0x12, 0x4d]
        );
        assert_eq!(
            walk(1, vec![0x00, 0x01, 0x02, 0x12, 0x4d], &cli_map).0,
            vec![0x00, 0x01, 0x02, 0x12, 0x6d]
        );
        // TYPEDBYREF in a parameter slot ends it too.
        assert_eq!(
            walk(1, vec![0x00, 0x02, 0x08, 0x16, 0x12, 0x4d], &cli_map).0,
            vec![0x00, 0x02, 0x08, 0x16, 0x12, 0x4d]
        );
    }

    #[test]
    fn custom_modifiers_before_a_type_are_mapped() {
        // modreq(TypeDef#2) int32 M(class TypeDef#2)
        let (blob, rewrites) = walk(
            1,
            vec![0x00, 0x01, 0x1f, 2 << 2, 0x08, 0x12, 2 << 2],
            &typedef_shift(2, 3),
        );
        assert_eq!(blob, vec![0x00, 0x01, 0x1f, 5 << 2, 0x08, 0x12, 5 << 2]);
        assert_eq!(rewrites, 2);
    }

    #[test]
    fn leaves_token_when_mapped_value_would_widen() {
        let (blob, rewrites) = walk(
            1,
            vec![0x00, 0x01, 0x08, 0x12, (0x1f << 2) | 1],
            &typedef_shift(0x1f, 1),
        );
        assert_eq!(blob, vec![0x00, 0x01, 0x08, 0x12, (0x1f << 2) | 1]);
        assert_eq!(rewrites, 0);
    }

    #[test]
    fn overlong_tokens_are_rewritten_canonically_in_place() {
        // Tag 3 is never remapped, but the native write-back still shortens a
        // two-byte encoding of a small value, leaving the second byte behind.
        let (blob, rewrites) = walk(
            1,
            vec![0x00, 0x00, 0x12, 0x80, 0x0b],
            &CliMapModel::default(),
        );
        assert_eq!(blob, vec![0x00, 0x00, 0x12, 0x0b, 0x0b]);
        assert_eq!(rewrites, 0);
    }

    #[test]
    fn generic_arguments_are_consumed_as_parameters() {
        // ret = GENERICINST CLASS #33 <2: CLASS #19, STRING>; p1 = VALUETYPE #34;
        // p2 = BOOLEAN. The argument count and the first argument fill the
        // two parameter slots, so p1 is never seen.
        let (blob, _) = walk(
            2,
            vec![
                0x20, 0x02, 0x15, 0x12, 0x80, 0x85, 0x02, 0x12, 0x4d, 0x0e, 0x11, 0x80, 0x89, 0x02,
            ],
            &typedef_shift(1, 8),
        );
        assert_eq!(
            blob,
            vec![
                0x20, 0x02, 0x15, 0x12, 0x80, 0xa5, 0x02, 0x12, 0x6d, 0x0e, 0x11, 0x80, 0x89, 0x02
            ]
        );
    }

    #[test]
    fn type_spec_and_field_sigs_stop_after_their_first_token() {
        let cli_map = typedef_shift(2, 2);
        let (blob, rewrites) = walk(
            5,
            vec![0x15, 0x12, (2 << 2) | 1, 0x01, 0x11, 3 << 2],
            &cli_map,
        );
        assert_eq!(blob, vec![0x15, 0x12, (4 << 2) | 1, 0x01, 0x11, 3 << 2]);
        assert_eq!(rewrites, 1);
        let (blob, _) = walk(
            3,
            vec![0x06, 0x15, 0x11, 2 << 2, 0x01, 0x12, 3 << 2],
            &cli_map,
        );
        assert_eq!(blob, vec![0x06, 0x15, 0x11, 4 << 2, 0x01, 0x12, 3 << 2]);
        // MemberRef with a field signature takes the field walk.
        let (blob, _) = walk(2, vec![0x06, 0x12, 2 << 2], &cli_map);
        assert_eq!(blob, vec![0x06, 0x12, 4 << 2]);
    }

    #[test]
    fn pointer_modifiers_and_local_sig_first_local_only() {
        // LocalVarSig, 2 locals: PTR modopt(#19) class #19, class #19.
        let (blob, _) = walk(
            9,
            vec![0x07, 0x02, 0x0f, 0x20, 0x4d, 0x12, 0x4d, 0x12, 0x4d],
            &typedef_shift(1, 8),
        );
        assert_eq!(
            blob,
            vec![0x07, 0x02, 0x0f, 0x20, 0x6d, 0x12, 0x6d, 0x12, 0x4d]
        );
        // A non-local StandAloneSig is walked as a method signature.
        let (blob, _) = walk(9, vec![0x00, 0x01, 0x08, 0x12, 0x4d], &typedef_shift(1, 8));
        assert_eq!(blob, vec![0x00, 0x01, 0x08, 0x12, 0x6d]);
    }

    #[test]
    fn property_type_has_no_modifier_loop() {
        let cli_map = typedef_shift(2, 3);
        let (blob, rewrites) = walk(4, vec![0x28, 0x00, 0x1f, 2 << 2, 0x08], &cli_map);
        assert_eq!(blob, vec![0x28, 0x00, 0x1f, 2 << 2, 0x08]);
        assert_eq!(rewrites, 0);
        let (blob, _) = walk(4, vec![0x28, 0x01, 0x12, 2 << 2, 0x12, 2 << 2], &cli_map);
        assert_eq!(blob, vec![0x28, 0x01, 0x12, 5 << 2, 0x12, 5 << 2]);
    }

    #[test]
    fn other_blob_kinds_are_not_walked() {
        for kind in [0u8, 6, 7, 8, 10, 11, 12] {
            let (blob, rewrites) = walk(
                kind,
                vec![0x00, 0x01, 0x08, 0x12, 0x4d],
                &typedef_shift(1, 8),
            );
            assert_eq!(blob, vec![0x00, 0x01, 0x08, 0x12, 0x4d]);
            assert_eq!(rewrites, 0);
        }
    }
}
