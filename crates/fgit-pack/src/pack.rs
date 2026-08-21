use crate::{
    Deadline, ObjectFormat, ObjectId, PackError, PackLimits, checkpoint, object_id_from_bytes,
};

const PACK_SIGNATURE: [u8; 4] = *b"PACK";
const PACK_V2: u32 = 2;

/// Pack entry kinds represented by the native pack type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl EntryKind {
    fn from_type_code(code: u8) -> Result<Self, PackError> {
        match code {
            1 => Ok(Self::Commit),
            2 => Ok(Self::Tree),
            3 => Ok(Self::Blob),
            4 => Ok(Self::Tag),
            6 => Ok(Self::OfsDelta),
            7 => Ok(Self::RefDelta),
            _ => Err(PackError::InvalidEntryType(code)),
        }
    }
}

/// The fixed v2 pack header. Entry payloads remain quarantine bytes until the
/// dependency-owned inflater and object verifier accept them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackHeader {
    pub object_count: u32,
}

/// A decoded pack entry header. The declared size is the inflated object or
/// delta-program length, never an allocation instruction by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackEntryHeader {
    pub kind: EntryKind,
    pub declared_size: usize,
}

/// Delta base reference bytes decoded immediately after a delta entry header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedDeltaBase {
    Ofs { base_offset: u64, consumed: usize },
    Ref { base: ObjectId, consumed: usize },
}

/// Parses exactly the fixed pack v2 header.
pub fn parse_pack_header(input: &[u8], limits: &PackLimits) -> Result<PackHeader, PackError> {
    limits.input(input.len())?;
    if input.len() < 12 {
        return Err(PackError::Truncated {
            context: "pack header",
        });
    }
    if input[..4] != PACK_SIGNATURE {
        return Err(PackError::InvalidPackSignature);
    }
    let version = u32::from_be_bytes(input[4..8].try_into().map_err(|_| PackError::Truncated {
        context: "pack version",
    })?);
    if version != PACK_V2 {
        return Err(PackError::UnsupportedPackVersion(version));
    }
    let object_count =
        u32::from_be_bytes(input[8..12].try_into().map_err(|_| PackError::Truncated {
            context: "pack object count",
        })?);
    if object_count > limits.max_entries {
        return Err(PackError::EntryCountLimit {
            actual: object_count,
            limit: limits.max_entries,
        });
    }
    Ok(PackHeader { object_count })
}

/// Refuses an entry stream whose actually decoded count differs from the
/// fixed count committed in its pack header. Callers invoke this only after
/// every entry boundary/inflated member has been bounded and validated.
pub fn validate_object_count(header: PackHeader, actual: u32) -> Result<(), PackError> {
    if header.object_count == actual {
        Ok(())
    } else {
        Err(PackError::ObjectCountMismatch {
            declared: header.object_count,
            actual,
        })
    }
}

/// Separates body bytes from the native hash trailer. It validates structure
/// only; a caller from fgit-crypto must verify the trailer before an object is
/// promoted out of quarantine.
pub fn split_pack_trailer<'a>(
    input: &'a [u8],
    format: ObjectFormat,
    limits: &PackLimits,
) -> Result<(&'a [u8], &'a [u8]), PackError> {
    limits.input(input.len())?;
    let trailer_len = format.digest_len();
    if input.len() < 12 + trailer_len {
        return Err(PackError::Truncated {
            context: "pack trailer",
        });
    }
    let boundary = input
        .len()
        .checked_sub(trailer_len)
        .ok_or(PackError::IntegerOverflow {
            context: "pack trailer boundary",
        })?;
    Ok((&input[..boundary], &input[boundary..]))
}

/// Dependency-injected native pack trailer verifier. The fgit-crypto adapter
/// belongs here once its frozen public surface is published; this boundary
/// keeps parsing free of a second SHA implementation.
pub trait PackTrailerVerifier {
    /// Returns `true` only when `trailer` is the native digest of `body` in
    /// `format`'s identity domain.
    fn verify(&self, body: &[u8], trailer: &[u8], format: ObjectFormat) -> bool;
}

/// Verifies a pack trailer before exposing even its raw body to an admitting
/// caller. Structural splitting alone is intentionally insufficient for
/// quarantine promotion.
pub fn validate_pack_trailer<'a>(
    input: &'a [u8],
    format: ObjectFormat,
    limits: &PackLimits,
    verifier: &impl PackTrailerVerifier,
) -> Result<&'a [u8], PackError> {
    let (body, trailer) = split_pack_trailer(input, format, limits)?;
    if verifier.verify(body, trailer, format) {
        Ok(body)
    } else {
        Err(PackError::TrailerChecksumMismatch)
    }
}

/// Decodes a pack entry's type-and-size varint with checked arithmetic.
pub fn decode_entry_header(
    input: &[u8],
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<(PackEntryHeader, usize), PackError> {
    limits.input(input.len())?;
    checkpoint(deadline)?;
    let Some(&first) = input.first() else {
        return Err(PackError::Truncated {
            context: "pack entry header",
        });
    };
    let kind = EntryKind::from_type_code((first >> 4) & 0x07)?;
    let mut value = u64::from(first & 0x0f);
    let mut shift = 4_u32;
    let mut index = 1_usize;
    let mut byte = first;
    while byte & 0x80 != 0 {
        checkpoint(deadline)?;
        let Some(&next) = input.get(index) else {
            return Err(PackError::Truncated {
                context: "pack entry size varint",
            });
        };
        index = index.checked_add(1).ok_or(PackError::IntegerOverflow {
            context: "pack entry header length",
        })?;
        if shift >= 64 {
            return Err(PackError::InvalidVarint {
                context: "pack entry size",
            });
        }
        let component =
            u64::from(next & 0x7f)
                .checked_shl(shift)
                .ok_or(PackError::InvalidVarint {
                    context: "pack entry size",
                })?;
        value = value
            .checked_add(component)
            .ok_or(PackError::IntegerOverflow {
                context: "pack entry size",
            })?;
        shift = shift.checked_add(7).ok_or(PackError::IntegerOverflow {
            context: "pack entry size shift",
        })?;
        byte = next;
    }
    let declared_size = usize::try_from(value).map_err(|_| PackError::ObjectSizeLimit {
        actual: usize::MAX,
        limit: limits.max_object_bytes,
    })?;
    limits.object_size(declared_size)?;
    Ok((
        PackEntryHeader {
            kind,
            declared_size,
        },
        index,
    ))
}

/// Decodes the backwards OFS_DELTA distance and returns its absolute base
/// offset. A base at or after the current entry is always invalid.
pub fn decode_ofs_delta_base(
    current_offset: u64,
    input: &[u8],
    deadline: &mut impl Deadline,
) -> Result<(u64, usize), PackError> {
    checkpoint(deadline)?;
    let Some(&first) = input.first() else {
        return Err(PackError::Truncated {
            context: "OFS_DELTA base",
        });
    };
    let mut distance = u64::from(first & 0x7f);
    let mut index = 1_usize;
    let mut byte = first;
    while byte & 0x80 != 0 {
        checkpoint(deadline)?;
        let Some(&next) = input.get(index) else {
            return Err(PackError::Truncated {
                context: "OFS_DELTA base",
            });
        };
        index = index.checked_add(1).ok_or(PackError::IntegerOverflow {
            context: "OFS_DELTA length",
        })?;
        distance = distance
            .checked_add(1)
            .and_then(|value| value.checked_shl(7))
            .and_then(|value| value.checked_add(u64::from(next & 0x7f)))
            .ok_or(PackError::InvalidOfsDelta)?;
        byte = next;
    }
    if distance == 0 || distance > current_offset {
        return Err(PackError::InvalidOfsDelta);
    }
    Ok((current_offset - distance, index))
}

/// Parses the delta base discriminator required by a decoded delta header.
pub fn parse_delta_base(
    kind: EntryKind,
    current_offset: u64,
    input: &[u8],
    format: ObjectFormat,
    deadline: &mut impl Deadline,
) -> Result<ParsedDeltaBase, PackError> {
    match kind {
        EntryKind::OfsDelta => {
            let (base_offset, consumed) = decode_ofs_delta_base(current_offset, input, deadline)?;
            Ok(ParsedDeltaBase::Ofs {
                base_offset,
                consumed,
            })
        }
        EntryKind::RefDelta => {
            checkpoint(deadline)?;
            let oid_len = format.digest_len();
            let Some(bytes) = input.get(..oid_len) else {
                return Err(PackError::Truncated {
                    context: "REF_DELTA base",
                });
            };
            Ok(ParsedDeltaBase::Ref {
                base: object_id_from_bytes(format, bytes)?,
                consumed: oid_len,
            })
        }
        _ => Err(PackError::InvalidEntryType(match kind {
            EntryKind::Commit => 1,
            EntryKind::Tree => 2,
            EntryKind::Blob => 3,
            EntryKind::Tag => 4,
            EntryKind::OfsDelta => 6,
            EntryKind::RefDelta => 7,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> PackLimits {
        PackLimits {
            max_input_bytes: 1024,
            max_entries: 2,
            max_object_bytes: 200,
            max_delta_depth: 4,
            max_delta_fanout: 4,
            max_total_expanded_bytes: 400,
            max_expansion_ratio: 400,
            max_delta_work: 400,
            max_inflate_work: 400,
            max_cached_bytes: 400,
            max_index_entries: 2,
        }
    }

    fn always() -> bool {
        true
    }

    #[test]
    fn parses_v2_header_and_all_native_entry_types() {
        let header = b"PACK\0\0\0\x02\0\0\0\x02";
        assert_eq!(
            parse_pack_header(header, &limits()),
            Ok(PackHeader { object_count: 2 })
        );
        for (byte, kind) in [
            (0x10, EntryKind::Commit),
            (0x20, EntryKind::Tree),
            (0x30, EntryKind::Blob),
            (0x40, EntryKind::Tag),
            (0x60, EntryKind::OfsDelta),
            (0x70, EntryKind::RefDelta),
        ] {
            assert_eq!(
                decode_entry_header(&[byte], &limits(), &mut always),
                Ok((
                    PackEntryHeader {
                        kind,
                        declared_size: 0
                    },
                    1
                ))
            );
        }
    }

    #[test]
    fn rejects_truncated_header_and_entry_varint() {
        assert!(matches!(
            parse_pack_header(b"PACK", &limits()),
            Err(PackError::Truncated { .. })
        ));
        assert!(matches!(
            decode_entry_header(&[0x38], &limits(), &mut always),
            Err(PackError::Truncated { .. })
        ));
    }

    #[test]
    fn input_and_entry_count_limits_refuse_before_entry_parsing() {
        let mut tiny_input = limits();
        tiny_input.max_input_bytes = 11;
        assert!(matches!(
            parse_pack_header(b"PACK\0\0\0\x02\0\0\0\0", &tiny_input),
            Err(PackError::InputLimit { .. })
        ));
        let mut tiny_count = limits();
        tiny_count.max_entries = 1;
        assert_eq!(
            parse_pack_header(b"PACK\0\0\0\x02\0\0\0\x02", &tiny_count),
            Err(PackError::EntryCountLimit {
                actual: 2,
                limit: 1,
            })
        );
    }

    #[test]
    fn object_count_mismatch_refuses_before_promotion() {
        let header = PackHeader { object_count: 2 };
        assert_eq!(
            validate_object_count(header, 1),
            Err(PackError::ObjectCountMismatch {
                declared: 2,
                actual: 1,
            })
        );
        assert_eq!(validate_object_count(header, 2), Ok(()));
    }

    #[test]
    fn decodes_ofs_and_ref_delta_bases() {
        assert_eq!(decode_ofs_delta_base(100, &[50], &mut always), Ok((50, 1)));
        let oid = [7; 20];
        assert_eq!(
            parse_delta_base(
                EntryKind::RefDelta,
                20,
                &oid,
                ObjectFormat::Sha1,
                &mut always
            ),
            Ok(ParsedDeltaBase::Ref {
                base: object_id_from_bytes(ObjectFormat::Sha1, &oid).expect("test OID"),
                consumed: 20,
            })
        );
    }

    #[test]
    fn trailer_verifier_refuses_corruption_before_body_is_returned() {
        struct ExactTrailer;

        impl PackTrailerVerifier for ExactTrailer {
            fn verify(&self, _body: &[u8], trailer: &[u8], _format: ObjectFormat) -> bool {
                trailer == [0xaa; 20]
            }
        }

        let mut valid = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
        valid.extend_from_slice(&[0xaa; 20]);
        assert_eq!(
            validate_pack_trailer(&valid, ObjectFormat::Sha1, &limits(), &ExactTrailer),
            Ok(&valid[..12])
        );
        valid[12] = 0xbb;
        assert_eq!(
            validate_pack_trailer(&valid, ObjectFormat::Sha1, &limits(), &ExactTrailer),
            Err(PackError::TrailerChecksumMismatch)
        );
    }
}
