use crate::{
    Deadline, ObjectFormat, ObjectId, PackError, PackHeader, PackLimits, checkpoint,
    object_id_from_bytes, validate_object_count,
};

const IDX_SIGNATURE: [u8; 4] = [0xff, b't', b'O', b'c'];
const IDX_V2: u32 = 2;
const FANOUT_BYTES: usize = 256 * 4;

/// Dependency-injected idx checksum verifier. The fgit-crypto adapter owns
/// all native hash computation; this crate merely establishes the bounded
/// byte boundary it must authenticate.
pub trait IdxChecksumVerifier {
    /// Returns true only when `trailer` is the native digest of `body` in the
    /// supplied Git hash domain.
    fn verify(&self, body: &[u8], trailer: &[u8], format: ObjectFormat) -> bool;
}

/// Verifies the trailing idx checksum before a structurally parsed index is
/// admitted to an object lookup path.
pub fn validate_idx_checksum(
    input: &[u8],
    format: ObjectFormat,
    limits: &PackLimits,
    verifier: &impl IdxChecksumVerifier,
) -> Result<(), PackError> {
    limits.input(input.len())?;
    let checksum_len = format.digest_len();
    let boundary = input
        .len()
        .checked_sub(checksum_len)
        .ok_or(PackError::Truncated {
            context: "idx checksum",
        })?;
    let (body, trailer) = input.split_at(boundary);
    if verifier.verify(body, trailer, format) {
        Ok(())
    } else {
        Err(PackError::IndexChecksumMismatch)
    }
}

/// One validated idx v2 lookup record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdxEntry {
    pub oid: ObjectId,
    pub crc32: u32,
    pub pack_offset: u64,
}

/// Validates the CRC-32 committed by one idx entry against exact raw pack bytes.
///
/// The caller supplies the framed byte span so this function does not infer an
/// entry boundary from sorted-by-OID index order.
///
/// The input boundary and each byte of CRC work are bounded before any output
/// can be exposed. CRC validation is an integrity check for quarantine/index
/// association; native pack and idx trailers still require their respective
/// checksum verifiers.
pub fn validate_idx_entry_crc(
    entry: &IdxEntry,
    packed_entry: &[u8],
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<(), PackError> {
    limits.input(packed_entry.len())?;
    let actual = ieee_crc32(packed_entry, deadline)?;
    if actual == entry.crc32 {
        Ok(())
    } else {
        Err(PackError::IndexEntryCrcMismatch {
            expected: entry.crc32,
            actual,
        })
    }
}

/// Binds an idx v2 record count to the pack header it indexes. A mismatched
/// index remains quarantine data and cannot provide object locations.
pub fn validate_idx_pack_count(index: &IdxV2, header: PackHeader) -> Result<(), PackError> {
    let actual = u32::try_from(index.entries.len()).map_err(|_| PackError::EntryCountLimit {
        actual: u32::MAX,
        limit: header.object_count,
    })?;
    validate_object_count(header, actual)
}

fn ieee_crc32(input: &[u8], deadline: &mut impl Deadline) -> Result<u32, PackError> {
    const POLYNOMIAL: u32 = 0xedb8_8320;

    let mut crc = u32::MAX;
    for &byte in input {
        checkpoint(deadline)?;
        let mut low = (crc ^ u32::from(byte)) & 0xff;
        for _ in 0..8 {
            low = if low & 1 == 0 {
                low >> 1
            } else {
                (low >> 1) ^ POLYNOMIAL
            };
        }
        crc = (crc >> 8) ^ low;
    }
    Ok(!crc)
}

/// A structurally verified idx v2 file. Its checksums are preserved for a
/// caller using fgit-crypto to validate before admission; this parser never
/// substitutes a local SHA implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdxV2 {
    format: ObjectFormat,
    entries: Vec<IdxEntry>,
    raw_offset_words: Vec<u32>,
    large_offsets: Vec<u64>,
    pack_checksum: ObjectId,
    index_checksum: ObjectId,
}

impl IdxV2 {
    /// Parses and validates idx v2 layout, fanout, object order, and offset
    /// indirection with all sizes checked before the entries allocation.
    pub fn parse(
        input: &[u8],
        format: ObjectFormat,
        limits: &PackLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, PackError> {
        limits.input(input.len())?;
        checkpoint(deadline)?;
        let oid_len = format.digest_len();
        let fixed_prefix = 8_usize
            .checked_add(FANOUT_BYTES)
            .ok_or(PackError::IntegerOverflow {
                context: "idx fixed prefix",
            })?;
        let minimum = fixed_prefix
            .checked_add(oid_len.checked_mul(2).ok_or(PackError::IntegerOverflow {
                context: "idx checksum length",
            })?)
            .ok_or(PackError::IntegerOverflow {
                context: "idx minimum length",
            })?;
        if input.len() < minimum {
            return Err(PackError::Truncated {
                context: "idx header or checksums",
            });
        }
        if input[..4] != IDX_SIGNATURE {
            return Err(PackError::InvalidIndexSignature);
        }
        let version = read_u32(input, 4, "idx version")?;
        if version != IDX_V2 {
            return Err(PackError::UnsupportedIndexVersion(version));
        }
        let (fanout, count) = parse_fanout(input, limits, deadline)?;
        let count_usize = usize::try_from(count).map_err(|_| PackError::IntegerOverflow {
            context: "idx object count",
        })?;
        let oid_bytes = count_usize
            .checked_mul(oid_len)
            .ok_or(PackError::IntegerOverflow {
                context: "idx OID table",
            })?;
        let crc_bytes = count_usize
            .checked_mul(4)
            .ok_or(PackError::IntegerOverflow {
                context: "idx CRC table",
            })?;
        let offset_bytes = crc_bytes;
        let table_end = fixed_prefix
            .checked_add(oid_bytes)
            .and_then(|value| value.checked_add(crc_bytes))
            .and_then(|value| value.checked_add(offset_bytes))
            .ok_or(PackError::IntegerOverflow {
                context: "idx fixed tables",
            })?;
        let checksum_bytes = oid_len.checked_mul(2).ok_or(PackError::IntegerOverflow {
            context: "idx checksum length",
        })?;
        let footer_start =
            input
                .len()
                .checked_sub(checksum_bytes)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx footer boundary",
                })?;
        if table_end > footer_start {
            return Err(PackError::Truncated {
                context: "idx fixed tables",
            });
        }
        let large_bytes =
            footer_start
                .checked_sub(table_end)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx large-offset table",
                })?;
        if large_bytes % 8 != 0 {
            return Err(PackError::TrailingIndexBytes);
        }
        let large_count = large_bytes / 8;
        checkpoint(deadline)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count_usize)
            .map_err(|_| PackError::AllocationFailed {
                requested: count_usize,
            })?;
        let mut raw_offset_words = Vec::new();
        raw_offset_words
            .try_reserve_exact(count_usize)
            .map_err(|_| PackError::AllocationFailed {
                requested: count_usize,
            })?;
        let mut large_offsets = Vec::new();
        large_offsets
            .try_reserve_exact(large_count)
            .map_err(|_| PackError::AllocationFailed {
                requested: large_count,
            })?;

        let oid_start = fixed_prefix;
        let crc_start = oid_start
            .checked_add(oid_bytes)
            .ok_or(PackError::IntegerOverflow {
                context: "idx CRC start",
            })?;
        let offset_start = crc_start
            .checked_add(crc_bytes)
            .ok_or(PackError::IntegerOverflow {
                context: "idx offset start",
            })?;
        let large_start =
            offset_start
                .checked_add(offset_bytes)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx large-offset start",
                })?;
        let mut observed_fanout = [0_u32; 256];
        let mut previous: Option<ObjectId> = None;
        for index in 0..count_usize {
            checkpoint(deadline)?;
            let oid_offset = oid_start
                .checked_add(
                    index
                        .checked_mul(oid_len)
                        .ok_or(PackError::IntegerOverflow {
                            context: "idx OID position",
                        })?,
                )
                .ok_or(PackError::IntegerOverflow {
                    context: "idx OID position",
                })?;
            let oid_end = oid_offset
                .checked_add(oid_len)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx OID end",
                })?;
            let oid = object_id_from_bytes(
                format,
                input
                    .get(oid_offset..oid_end)
                    .ok_or(PackError::Truncated { context: "idx OID" })?,
            )?;
            if previous
                .as_ref()
                .is_some_and(|prior| prior.as_bytes() >= oid.as_bytes())
            {
                return Err(PackError::InvalidIndexOrdering);
            }
            let first_byte = *oid
                .as_bytes()
                .first()
                .ok_or(PackError::InvalidIndexOrdering)?;
            observed_fanout[usize::from(first_byte)] = observed_fanout[usize::from(first_byte)]
                .checked_add(1)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx fanout count",
                })?;
            let crc_position = crc_start
                .checked_add(index.checked_mul(4).ok_or(PackError::IntegerOverflow {
                    context: "idx CRC position",
                })?)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx CRC position",
                })?;
            let crc32 = read_u32(input, crc_position, "idx CRC")?;
            let offset_position = offset_start
                .checked_add(index.checked_mul(4).ok_or(PackError::IntegerOverflow {
                    context: "idx offset position",
                })?)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx offset position",
                })?;
            let raw_offset = read_u32(input, offset_position, "idx offset")?;
            let pack_offset = if raw_offset & 0x8000_0000 == 0 {
                u64::from(raw_offset)
            } else {
                let large_index = usize::try_from(raw_offset & 0x7fff_ffff)
                    .map_err(|_| PackError::InvalidLargeOffset { index: usize::MAX })?;
                if large_index >= large_count {
                    return Err(PackError::InvalidLargeOffset { index: large_index });
                }
                let large_position =
                    large_start
                        .checked_add(large_index.checked_mul(8).ok_or(
                            PackError::IntegerOverflow {
                                context: "idx large offset position",
                            },
                        )?)
                        .ok_or(PackError::IntegerOverflow {
                            context: "idx large offset position",
                        })?;
                read_u64(input, large_position, "idx large offset")?
            };
            previous = Some(oid);
            raw_offset_words.push(raw_offset);
            entries.push(IdxEntry {
                oid,
                crc32,
                pack_offset,
            });
        }
        validate_fanout(&fanout, &observed_fanout)?;
        for index in 0..large_count {
            checkpoint(deadline)?;
            let position = large_start
                .checked_add(index.checked_mul(8).ok_or(PackError::IntegerOverflow {
                    context: "idx large offset position",
                })?)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx large offset position",
                })?;
            large_offsets.push(read_u64(input, position, "idx large offset")?);
        }
        let pack_checksum = object_id_from_bytes(
            format,
            input
                .get(footer_start..footer_start + oid_len)
                .ok_or(PackError::Truncated {
                    context: "idx pack checksum",
                })?,
        )?;
        let index_checksum = object_id_from_bytes(
            format,
            input
                .get(footer_start + oid_len..)
                .ok_or(PackError::Truncated {
                    context: "idx index checksum",
                })?,
        )?;
        Ok(Self {
            format,
            entries,
            raw_offset_words,
            large_offsets,
            pack_checksum,
            index_checksum,
        })
    }

    /// Verifies the checksum then parses the idx structure. This is the
    /// quarantine-admission path; [`Self::parse`] remains useful to inspect a
    /// refusal without treating its lookup records as trusted.
    pub fn parse_verified(
        input: &[u8],
        format: ObjectFormat,
        limits: &PackLimits,
        deadline: &mut impl Deadline,
        verifier: &impl IdxChecksumVerifier,
    ) -> Result<Self, PackError> {
        validate_idx_checksum(input, format, limits, verifier)?;
        Self::parse(input, format, limits, deadline)
    }

    /// Finds a pack object in native ID sort order.
    #[must_use]
    pub fn lookup(&self, oid: &ObjectId) -> Option<&IdxEntry> {
        self.entries
            .binary_search_by(|entry| entry.oid.as_bytes().cmp(oid.as_bytes()))
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    #[must_use]
    pub fn entries(&self) -> &[IdxEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn pack_checksum(&self) -> &ObjectId {
        &self.pack_checksum
    }

    #[must_use]
    pub const fn index_checksum(&self) -> &ObjectId {
        &self.index_checksum
    }

    /// Re-emits the exact structurally validated idx v2 representation. It
    /// preserves both native checksum fields; callers must independently
    /// verify the index checksum with fgit-crypto before trusting it.
    pub fn to_bytes(
        &self,
        limits: &PackLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, PackError> {
        if self.entries.len() != self.raw_offset_words.len() {
            return Err(PackError::InvalidIndexFanout);
        }
        let oid_len = self.format.digest_len();
        let count = self.entries.len();
        let oid_bytes = count
            .checked_mul(oid_len)
            .ok_or(PackError::IntegerOverflow {
                context: "idx OID table",
            })?;
        let word_bytes = count.checked_mul(4).ok_or(PackError::IntegerOverflow {
            context: "idx word table",
        })?;
        let large_bytes =
            self.large_offsets
                .len()
                .checked_mul(8)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx large-offset table",
                })?;
        let total = 8_usize
            .checked_add(FANOUT_BYTES)
            .and_then(|value| value.checked_add(oid_bytes))
            .and_then(|value| value.checked_add(word_bytes))
            .and_then(|value| value.checked_add(word_bytes))
            .and_then(|value| value.checked_add(large_bytes))
            .and_then(|value| value.checked_add(oid_len.checked_mul(2)?))
            .ok_or(PackError::IntegerOverflow {
                context: "idx serialized length",
            })?;
        limits.input(total)?;
        checkpoint(deadline)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(total)
            .map_err(|_| PackError::AllocationFailed { requested: total })?;
        output.extend_from_slice(&IDX_SIGNATURE);
        output.extend_from_slice(&IDX_V2.to_be_bytes());
        let fanout = self.fanout(deadline)?;
        for value in fanout {
            output.extend_from_slice(&value.to_be_bytes());
        }
        for entry in &self.entries {
            checkpoint(deadline)?;
            if entry.oid.as_bytes().len() != oid_len {
                return Err(PackError::ObjectIdLength {
                    expected: oid_len,
                    actual: entry.oid.as_bytes().len(),
                });
            }
            output.extend_from_slice(entry.oid.as_bytes());
        }
        for entry in &self.entries {
            checkpoint(deadline)?;
            output.extend_from_slice(&entry.crc32.to_be_bytes());
        }
        for offset in &self.raw_offset_words {
            checkpoint(deadline)?;
            output.extend_from_slice(&offset.to_be_bytes());
        }
        for offset in &self.large_offsets {
            checkpoint(deadline)?;
            output.extend_from_slice(&offset.to_be_bytes());
        }
        output.extend_from_slice(self.pack_checksum.as_bytes());
        output.extend_from_slice(self.index_checksum.as_bytes());
        debug_assert_eq!(output.len(), total);
        Ok(output)
    }

    fn fanout(&self, deadline: &mut impl Deadline) -> Result<[u32; 256], PackError> {
        let mut fanout = [0_u32; 256];
        let mut previous: Option<&ObjectId> = None;
        for entry in &self.entries {
            checkpoint(deadline)?;
            if previous.is_some_and(|prior| prior.as_bytes() >= entry.oid.as_bytes()) {
                return Err(PackError::InvalidIndexOrdering);
            }
            let first = *entry
                .oid
                .as_bytes()
                .first()
                .ok_or(PackError::InvalidIndexOrdering)?;
            fanout[usize::from(first)] =
                fanout[usize::from(first)]
                    .checked_add(1)
                    .ok_or(PackError::IntegerOverflow {
                        context: "idx fanout count",
                    })?;
            previous = Some(&entry.oid);
        }
        let mut cumulative = 0_u32;
        for value in &mut fanout {
            cumulative = cumulative
                .checked_add(*value)
                .ok_or(PackError::IntegerOverflow {
                    context: "idx fanout cumulative",
                })?;
            *value = cumulative;
        }
        Ok(fanout)
    }
}

fn parse_fanout(
    input: &[u8],
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<([u32; 256], u32), PackError> {
    let mut values = [0_u32; 256];
    let mut previous = 0_u32;
    for (index, value) in values.iter_mut().enumerate() {
        checkpoint(deadline)?;
        let position = 8_usize
            .checked_add(index.checked_mul(4).ok_or(PackError::IntegerOverflow {
                context: "idx fanout position",
            })?)
            .ok_or(PackError::IntegerOverflow {
                context: "idx fanout position",
            })?;
        let parsed = read_u32(input, position, "idx fanout")?;
        if parsed < previous {
            return Err(PackError::InvalidIndexFanout);
        }
        *value = parsed;
        previous = parsed;
    }
    let count = values[255];
    let count_usize = usize::try_from(count).map_err(|_| PackError::IntegerOverflow {
        context: "idx object count",
    })?;
    if count_usize > limits.max_index_entries {
        return Err(PackError::EntryCountLimit {
            actual: count,
            limit: u32::try_from(limits.max_index_entries).unwrap_or(u32::MAX),
        });
    }
    Ok((values, count))
}

fn validate_fanout(expected: &[u32; 256], observed: &[u32; 256]) -> Result<(), PackError> {
    let mut cumulative = 0_u32;
    for (expected_value, observed_value) in expected.iter().zip(observed) {
        cumulative = cumulative
            .checked_add(*observed_value)
            .ok_or(PackError::IntegerOverflow {
                context: "idx fanout validation",
            })?;
        if cumulative != *expected_value {
            return Err(PackError::InvalidIndexFanout);
        }
    }
    Ok(())
}

fn read_u32(input: &[u8], offset: usize, context: &'static str) -> Result<u32, PackError> {
    let end = offset
        .checked_add(4)
        .ok_or(PackError::IntegerOverflow { context })?;
    let bytes = input
        .get(offset..end)
        .ok_or(PackError::Truncated { context })?;
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| PackError::Truncated { context })?;
    Ok(u32::from_be_bytes(array))
}

fn read_u64(input: &[u8], offset: usize, context: &'static str) -> Result<u64, PackError> {
    let end = offset
        .checked_add(8)
        .ok_or(PackError::IntegerOverflow { context })?;
    let bytes = input
        .get(offset..end)
        .ok_or(PackError::Truncated { context })?;
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| PackError::Truncated { context })?;
    Ok(u64::from_be_bytes(array))
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
            max_inflate_work: 1_000,
            max_cached_bytes: 1_000,
            max_index_entries: 10,
        }
    }

    fn always() -> bool {
        true
    }

    fn idx_with_entries(entries: &[(u8, u32, u32)], large_offsets: &[u64]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&IDX_SIGNATURE);
        output.extend_from_slice(&IDX_V2.to_be_bytes());
        for bucket in 0_u16..=255 {
            let count = entries
                .iter()
                .filter(|(first, _, _)| u16::from(*first) <= bucket)
                .count();
            output.extend_from_slice(&(u32::try_from(count).expect("test count")).to_be_bytes());
        }
        for (first, _, _) in entries {
            output.push(*first);
            output.extend_from_slice(&[0; 19]);
        }
        for (_, crc, _) in entries {
            output.extend_from_slice(&crc.to_be_bytes());
        }
        for (_, _, offset) in entries {
            output.extend_from_slice(&offset.to_be_bytes());
        }
        for offset in large_offsets {
            output.extend_from_slice(&offset.to_be_bytes());
        }
        output.extend_from_slice(&[0x11; 20]);
        output.extend_from_slice(&[0x22; 20]);
        output
    }

    #[test]
    fn parses_idx_v2_and_looks_up_direct_and_large_offsets() {
        let bytes = idx_with_entries(
            &[(1, 10, 44), (2, 11, 0x8000_0000)],
            &[u64::from(u32::MAX) + 9],
        );
        let parsed =
            IdxV2::parse(&bytes, ObjectFormat::Sha1, &limits(), &mut always).expect("valid idx");
        assert_eq!(parsed.entries().len(), 2);
        assert_eq!(parsed.to_bytes(&limits(), &mut always), Ok(bytes));
        let oid = object_id_from_bytes(
            ObjectFormat::Sha1,
            &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .expect("test ID");
        assert_eq!(
            parsed.lookup(&oid).map(|entry| entry.pack_offset),
            Some(u64::from(u32::MAX) + 9)
        );
    }

    #[test]
    fn idx_refuses_fanout_order_and_large_offset_corruption() {
        let mut unordered = idx_with_entries(&[(2, 10, 44), (1, 11, 45)], &[]);
        assert_eq!(
            IdxV2::parse(&unordered, ObjectFormat::Sha1, &limits(), &mut always),
            Err(PackError::InvalidIndexOrdering)
        );
        let invalid_large = idx_with_entries(&[(1, 10, 0x8000_0001)], &[]);
        assert_eq!(
            IdxV2::parse(&invalid_large, ObjectFormat::Sha1, &limits(), &mut always),
            Err(PackError::InvalidLargeOffset { index: 1 })
        );
        unordered[8..12].copy_from_slice(&1_u32.to_be_bytes());
        assert!(matches!(
            IdxV2::parse(&unordered, ObjectFormat::Sha1, &limits(), &mut always),
            Err(PackError::InvalidIndexFanout | PackError::InvalidIndexOrdering)
        ));
    }

    #[test]
    fn verified_index_refuses_corrupt_trailer() {
        struct ExactTrailer;

        impl IdxChecksumVerifier for ExactTrailer {
            fn verify(&self, _body: &[u8], trailer: &[u8], _format: ObjectFormat) -> bool {
                trailer == [0x22; 20]
            }
        }

        let mut bytes = idx_with_entries(&[(1, 10, 44)], &[]);
        assert!(
            IdxV2::parse_verified(
                &bytes,
                ObjectFormat::Sha1,
                &limits(),
                &mut always,
                &ExactTrailer,
            )
            .is_ok()
        );
        let last = bytes.len() - 1;
        bytes[last] = 0;
        assert_eq!(
            validate_idx_checksum(&bytes, ObjectFormat::Sha1, &limits(), &ExactTrailer),
            Err(PackError::IndexChecksumMismatch)
        );
    }
}
