use fgit_deflate::{CancellationProbe, InflateLimits, Inflater, StreamProgress};

use crate::{
    Deadline, DeltaBase, DeltaObject, EntryKind, ObjectFormat, ObjectId, PackEntryHeader,
    PackError, PackHeader, PackLimits, PackObject, PackTrailerVerifier, ParsedDeltaBase,
    checkpoint, decode_entry_header, object_id_from_bytes, parse_delta_base, parse_pack_header,
    split_pack_trailer, validate_object_count, validate_pack_trailer,
};

/// An inflated pack entry that is still quarantine data.
///
/// Its type, trailer, index association, and native object ID have not yet
/// been jointly authenticated, so this value is never canonical object storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedEntry {
    pub offset: u64,
    pub header: PackEntryHeader,
    pub delta_base: Option<ParsedDeltaBase>,
    pub inflated: Vec<u8>,
}

/// A fully framed, trailer-authenticated pack whose entry payloads remain in
/// the quarantine layer pending native object identity verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedPack {
    pub header: PackHeader,
    pub format: ObjectFormat,
    pub trailer: ObjectId,
    entries: Vec<QuarantinedEntry>,
}

impl QuarantinedPack {
    #[must_use]
    pub fn entries(&self) -> &[QuarantinedEntry] {
        &self.entries
    }

    /// Converts quarantined entry payloads to the scalar delta resolver
    /// input. The provided index association is only a lookup hint; callers
    /// must still verify every reconstructed native object ID before storage.
    pub fn into_scalar_objects(
        self,
        mut oid_at_offset: impl FnMut(u64) -> Option<ObjectId>,
    ) -> Result<Vec<PackObject>, PackError> {
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(self.entries.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: self.entries.len(),
            })?;
        for entry in self.entries {
            let id = oid_at_offset(entry.offset);
            let object = match entry.delta_base {
                None => PackObject::Base {
                    offset: entry.offset,
                    id,
                    data: entry.inflated,
                },
                Some(ParsedDeltaBase::Ofs { base_offset, .. }) => PackObject::Delta(DeltaObject {
                    offset: entry.offset,
                    id,
                    base: DeltaBase::Ofs(base_offset),
                    program: entry.inflated,
                }),
                Some(ParsedDeltaBase::Ref { base, .. }) => PackObject::Delta(DeltaObject {
                    offset: entry.offset,
                    id,
                    base: DeltaBase::Ref(base),
                    program: entry.inflated,
                }),
            };
            objects.push(object);
        }
        Ok(objects)
    }
}

/// Performs structural pack framing and entry inflation without authentication.
///
/// This is useful only within a caller-owned quarantine diagnostic path;
/// [`read_verified_pack`] is the admission API.
pub fn parse_quarantined_pack(
    input: &[u8],
    format: ObjectFormat,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<QuarantinedPack, PackError> {
    let (body, trailer_bytes) = split_pack_trailer(input, format, limits)?;
    let header = parse_pack_header(body, limits)?;
    let trailer = object_id_from_bytes(format, trailer_bytes)?;
    let mut cursor = 12_usize;
    let entry_capacity =
        usize::try_from(header.object_count).map_err(|_| PackError::EntryCountLimit {
            actual: header.object_count,
            limit: limits.max_entries,
        })?;
    checkpoint(deadline)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_capacity)
        .map_err(|_| PackError::AllocationFailed {
            requested: entry_capacity,
        })?;
    let mut total_inflated = 0_usize;
    for _ in 0..header.object_count {
        checkpoint(deadline)?;
        let offset = u64::try_from(cursor).map_err(|_| PackError::IntegerOverflow {
            context: "pack entry offset",
        })?;
        let (entry_header, header_len) = decode_entry_header(
            body.get(cursor..).ok_or(PackError::Truncated {
                context: "pack entry",
            })?,
            limits,
            deadline,
        )?;
        cursor = cursor
            .checked_add(header_len)
            .ok_or(PackError::IntegerOverflow {
                context: "pack entry header boundary",
            })?;
        let delta_base = match entry_header.kind {
            EntryKind::OfsDelta | EntryKind::RefDelta => {
                let parsed = parse_delta_base(
                    entry_header.kind,
                    offset,
                    body.get(cursor..).ok_or(PackError::Truncated {
                        context: "pack delta base",
                    })?,
                    format,
                    deadline,
                )?;
                cursor = cursor.checked_add(delta_base_len(&parsed)).ok_or(
                    PackError::IntegerOverflow {
                        context: "pack delta base boundary",
                    },
                )?;
                Some(parsed)
            }
            _ => None,
        };
        total_inflated = total_inflated
            .checked_add(entry_header.declared_size)
            .ok_or(PackError::IntegerOverflow {
                context: "pack total inflated bytes",
            })?;
        if total_inflated > limits.max_total_expanded_bytes {
            return Err(PackError::TotalExpandedLimit {
                actual: total_inflated,
                limit: limits.max_total_expanded_bytes,
            });
        }
        let (inflated, consumed) = inflate_one_member(
            body.get(cursor..).ok_or(PackError::Truncated {
                context: "pack entry payload",
            })?,
            entry_header.declared_size,
            limits,
            deadline,
        )?;
        cursor = cursor
            .checked_add(consumed)
            .ok_or(PackError::IntegerOverflow {
                context: "pack entry payload boundary",
            })?;
        entries.push(QuarantinedEntry {
            offset,
            header: entry_header,
            delta_base,
            inflated,
        });
    }
    if cursor != body.len() {
        return Err(PackError::TrailingPackData);
    }
    validate_object_count(
        header,
        u32::try_from(entries.len()).map_err(|_| PackError::EntryCountLimit {
            actual: u32::MAX,
            limit: limits.max_entries,
        })?,
    )?;
    Ok(QuarantinedPack {
        header,
        format,
        trailer,
        entries,
    })
}

/// Verifies the native pack trailer before parsing any pack entry.
///
/// All resulting payloads remain quarantined until their object headers/types
/// and reconstructed native OIDs are checked by the object-verification layer.
pub fn read_verified_pack(
    input: &[u8],
    format: ObjectFormat,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
    verifier: &impl PackTrailerVerifier,
) -> Result<QuarantinedPack, PackError> {
    validate_pack_trailer(input, format, limits, verifier)?;
    parse_quarantined_pack(input, format, limits, deadline)
}

const fn delta_base_len(base: &ParsedDeltaBase) -> usize {
    match base {
        ParsedDeltaBase::Ofs { consumed, .. } | ParsedDeltaBase::Ref { consumed, .. } => *consumed,
    }
}

fn inflate_one_member(
    input: &[u8],
    declared_size: usize,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<(Vec<u8>, usize), PackError> {
    if input.is_empty() {
        return Err(PackError::Truncated {
            context: "pack zlib member",
        });
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(declared_size)
        .map_err(|_| PackError::AllocationFailed {
            requested: declared_size,
        })?;
    let mut inflater =
        Inflater::new(inflate_limits(limits, declared_size)).map_err(PackError::Inflate)?;
    for (index, byte) in input.iter().enumerate() {
        checkpoint(deadline)?;
        let progress = {
            let mut control = DeadlineProbe(deadline);
            inflater
                .push_with_control(std::slice::from_ref(byte), &mut control)
                .map_err(PackError::Inflate)?
        };
        append_inflated(&mut output, inflater.take_output(), declared_size)?;
        if progress == StreamProgress::Finished {
            inflater.finish().map_err(PackError::Inflate)?;
            append_inflated(&mut output, inflater.take_output(), declared_size)?;
            if output.len() != declared_size {
                return Err(PackError::InflatedEntrySizeMismatch {
                    declared: declared_size,
                    actual: output.len(),
                });
            }
            let consumed = index.checked_add(1).ok_or(PackError::IntegerOverflow {
                context: "pack zlib member length",
            })?;
            return Ok((output, consumed));
        }
    }
    inflater.finish().map_err(PackError::Inflate)?;
    Err(PackError::Truncated {
        context: "pack zlib member",
    })
}

fn inflate_limits(limits: &PackLimits, declared_size: usize) -> InflateLimits {
    InflateLimits {
        max_input_bytes: limits.max_input_bytes,
        // `inflate_one_member` supplies one byte at a time so it can return the
        // exact pack boundary. The decoder may nevertheless need to retain a
        // complete zlib or dynamic-Huffman header before it can consume any
        // input. The pack-wide input ceiling is therefore also the bounded
        // retained-input ceiling; `Inflater` grows this buffer incrementally
        // and fallibly rather than preallocating it.
        max_pending_input_bytes: limits.max_input_bytes,
        max_output_bytes: declared_size.max(1),
        max_expansion_ratio: Some(
            u32::try_from(limits.max_expansion_ratio)
                .unwrap_or(u32::MAX)
                .max(1),
        ),
        max_window_bytes: fgit_deflate::RFC1951_MAX_WINDOW_BYTES,
        max_huffman_symbols: 320,
        max_collection_elements: 320,
        max_work_units: limits.max_inflate_work,
    }
}

fn append_inflated(
    output: &mut Vec<u8>,
    newly_inflated: Vec<u8>,
    declared_size: usize,
) -> Result<(), PackError> {
    let resulting_len =
        output
            .len()
            .checked_add(newly_inflated.len())
            .ok_or(PackError::IntegerOverflow {
                context: "pack inflated entry length",
            })?;
    if resulting_len > declared_size {
        return Err(PackError::InflatedEntrySizeMismatch {
            declared: declared_size,
            actual: resulting_len,
        });
    }
    output.extend_from_slice(&newly_inflated);
    Ok(())
}

struct DeadlineProbe<'a, D>(&'a mut D);

impl<D> CancellationProbe for DeadlineProbe<'_, D>
where
    D: Deadline,
{
    fn is_cancelled(&mut self) -> bool {
        !self.0.checkpoint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> PackLimits {
        PackLimits {
            max_input_bytes: 10_000,
            max_entries: 10,
            max_object_bytes: 1_000,
            max_delta_depth: 10,
            max_delta_fanout: 10,
            max_total_expanded_bytes: 1_000,
            max_expansion_ratio: 100,
            max_delta_work: 1_000,
            max_inflate_work: 10_000,
            max_cached_bytes: 1_000,
            max_index_entries: 10,
        }
    }

    fn always() -> bool {
        true
    }

    fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
        let length = u16::try_from(bytes.len()).expect("test fixture length");
        let mut output = vec![0x78, 0x01, 0x01];
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(&(!length).to_le_bytes());
        output.extend_from_slice(bytes);
        let (adler_a, adler_b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
            let next_a = (a + u32::from(*byte)) % 65_521;
            (next_a, (b + next_a) % 65_521)
        });
        output.extend_from_slice(&((adler_b << 16) | adler_a).to_be_bytes());
        output
    }

    fn pack_entry(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut output = vec![(kind << 4) | u8::try_from(payload.len()).expect("small fixture")];
        output.extend_from_slice(&zlib_stored(payload));
        output
    }

    fn exact_pack(payload: &[u8]) -> Vec<u8> {
        let mut output = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        output.extend_from_slice(payload);
        output.extend_from_slice(&[0xaa; 20]);
        output
    }

    fn two_entry_ofs_pack() -> Vec<u8> {
        let mut output = b"PACK\0\0\0\x02\0\0\0\x02".to_vec();
        output.extend_from_slice(&pack_entry(3, b"a"));
        let current_offset = output.len();
        let distance = current_offset
            .checked_sub(12)
            .expect("fixture base ordering");
        output.push(0x62);
        output.push(u8::try_from(distance).expect("single-byte OFS fixture"));
        output.extend_from_slice(&zlib_stored(&[1, 1]));
        output.extend_from_slice(&[0xaa; 20]);
        output
    }

    fn thin_ref_pack() -> Vec<u8> {
        let mut output = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        output.push(0x72);
        output.extend_from_slice(&[9; 20]);
        output.extend_from_slice(&zlib_stored(&[1, 1]));
        output.extend_from_slice(&[0xaa; 20]);
        output
    }

    struct ExactTrailer;

    impl PackTrailerVerifier for ExactTrailer {
        fn verify(&self, _body: &[u8], trailer: &[u8], _format: ObjectFormat) -> bool {
            trailer == [0xaa; 20]
        }
    }

    #[test]
    fn parses_hand_built_base_entry_pack() {
        let pack = exact_pack(&pack_entry(3, b"blob"));
        let parsed = read_verified_pack(
            &pack,
            ObjectFormat::Sha1,
            &limits(),
            &mut always,
            &ExactTrailer,
        )
        .expect("hand-built stored pack");
        assert_eq!(parsed.entries()[0].header.kind, EntryKind::Blob);
        assert_eq!(parsed.entries()[0].inflated, b"blob");
    }

    #[test]
    fn parses_all_native_entry_kinds_including_ofs_and_thin_ref() {
        for (kind, expected) in [
            (1_u8, EntryKind::Commit),
            (2, EntryKind::Tree),
            (3, EntryKind::Blob),
            (4, EntryKind::Tag),
        ] {
            let parsed = parse_quarantined_pack(
                &exact_pack(&pack_entry(kind, b"x")),
                ObjectFormat::Sha1,
                &limits(),
                &mut always,
            )
            .expect("base entry fixture");
            assert_eq!(parsed.entries()[0].header.kind, expected);
        }

        let ofs = parse_quarantined_pack(
            &two_entry_ofs_pack(),
            ObjectFormat::Sha1,
            &limits(),
            &mut always,
        )
        .expect("OFS delta fixture");
        assert_eq!(ofs.entries()[1].header.kind, EntryKind::OfsDelta);
        assert!(matches!(
            ofs.entries()[1].delta_base.as_ref(),
            Some(ParsedDeltaBase::Ofs {
                base_offset: 12,
                ..
            })
        ));

        let thin =
            parse_quarantined_pack(&thin_ref_pack(), ObjectFormat::Sha1, &limits(), &mut always)
                .expect("thin REF delta fixture");
        assert_eq!(thin.entries()[0].header.kind, EntryKind::RefDelta);
        assert!(matches!(
            thin.entries()[0].delta_base.as_ref(),
            Some(ParsedDeltaBase::Ref { .. })
        ));
    }

    #[test]
    fn verified_reader_refuses_corrupt_trailer_and_extra_entry_data() {
        let mut corrupt = exact_pack(&pack_entry(3, b"blob"));
        let last = corrupt.len() - 1;
        corrupt[last] = 0;
        assert_eq!(
            read_verified_pack(
                &corrupt,
                ObjectFormat::Sha1,
                &limits(),
                &mut always,
                &ExactTrailer,
            ),
            Err(PackError::TrailerChecksumMismatch)
        );

        let mut body = pack_entry(3, b"blob");
        body.extend_from_slice(&[0]);
        assert_eq!(
            parse_quarantined_pack(
                &exact_pack(&body),
                ObjectFormat::Sha1,
                &limits(),
                &mut always,
            ),
            Err(PackError::TrailingPackData)
        );
    }

    #[test]
    fn object_count_mismatches_refuse_before_a_quarantined_pack_is_returned() {
        let mut too_many_declared = exact_pack(&pack_entry(3, b"blob"));
        too_many_declared[11] = 2;
        assert!(matches!(
            parse_quarantined_pack(
                &too_many_declared,
                ObjectFormat::Sha1,
                &limits(),
                &mut always,
            ),
            Err(PackError::Truncated { .. })
        ));

        let mut too_many_actual = pack_entry(3, b"one");
        too_many_actual.extend_from_slice(&pack_entry(3, b"two"));
        assert_eq!(
            parse_quarantined_pack(
                &exact_pack(&too_many_actual),
                ObjectFormat::Sha1,
                &limits(),
                &mut always,
            ),
            Err(PackError::TrailingPackData)
        );
    }

    #[test]
    fn reader_refuses_total_expansion_and_inflate_work_bombs() {
        let mut total_limited = limits();
        total_limited.max_total_expanded_bytes = 2;
        assert_eq!(
            parse_quarantined_pack(
                &two_entry_ofs_pack(),
                ObjectFormat::Sha1,
                &total_limited,
                &mut always,
            ),
            Err(PackError::TotalExpandedLimit {
                actual: 3,
                limit: 2,
            })
        );

        let mut work_limited = limits();
        work_limited.max_inflate_work = 1;
        assert!(matches!(
            parse_quarantined_pack(
                &exact_pack(&pack_entry(3, b"blob")),
                ObjectFormat::Sha1,
                &work_limited,
                &mut always,
            ),
            Err(PackError::Inflate(
                fgit_deflate::InflateRefusal::ResourceLimit {
                    resource: fgit_deflate::Resource::WorkUnits,
                    ..
                }
            ))
        ));
    }
}
