//! Deterministic, derived multi-pack-index V1 materialization.
//!
//! A MIDX is an accelerator over existing pack indexes, never a source of
//! object truth.  This module deliberately consumes only the existing
//! structurally parsed [`IdxV2`] representation, records the exact authority
//! source supplied by its caller, and chooses duplicate locations by a closed
//! lexical pack-name rule.  A consumer must still verify the selected pack and
//! native object identity before using a MIDX location to satisfy a read.

use crate::{Deadline, IdxV2, ObjectFormat, ObjectId, PackError, checkpoint};
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{sha1_digest, sha256_digest};
use fgit_types::{RepositoryCommitId, RepositoryId};
use std::collections::BTreeMap;

const MIDX_SIGNATURE: &[u8; 4] = b"MIDX";
const MIDX_VERSION_V1: u8 = 1;
const MIDX_HEADER_BYTES: usize = 12;
const MIDX_TOC_ENTRY_BYTES: usize = 12;
const MIDX_FANOUT_BYTES: usize = 256 * 4;
const MIDX_OBJECT_OFFSET_BYTES: usize = 8;
const LARGE_OFFSET_BIT: u32 = 0x8000_0000;
const PACK_HEADER_BYTES: u64 = 12;

const CHUNK_OID_FANOUT: [u8; 4] = *b"OIDF";
const CHUNK_OID_LOOKUP: [u8; 4] = *b"OIDL";
const CHUNK_OBJECT_OFFSETS: [u8; 4] = *b"OOFF";
const CHUNK_LARGE_OFFSETS: [u8; 4] = *b"LOFF";
const CHUNK_PACK_NAMES: [u8; 4] = *b"PNAM";

/// Bounds selected before a MIDX materializer indexes or emits pack metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MidxLimits {
    /// Most pack indexes selected for one MIDX.
    pub max_packs: usize,
    /// Most de-duplicated object locations retained in one MIDX.
    pub max_objects: usize,
    /// Most bytes in the complete MIDX including its native checksum.
    pub max_output_bytes: usize,
}

impl Default for MidxLimits {
    fn default() -> Self {
        Self {
            max_packs: 100_000,
            max_objects: 10_000_000,
            max_output_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Frozen selection rule used by the first MIDX materialization profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MidxProfile {
    /// Git MIDX V1 with generated standard pack-index names.  A duplicate OID
    /// is represented by the lexicographically first pack name, then the
    /// exact offset recorded by that checked idx record.
    V1LexicographicPackSelection,
}

/// What set this MIDX claims to cover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MidxCompleteness {
    /// Every record in the explicitly supplied set of idx files, with one
    /// deterministic selected location per object identity.
    SuppliedIndexesV1,
}

/// What verification occurred before MIDX records were retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MidxVerification {
    /// The input indexes had already passed `IdxV2`'s structural ordering and
    /// offset-indirection checks.  This does not authenticate pack contents or
    /// admit object identities; read consumers must do that independently.
    IdxStructureV1,
}

/// Exact authority-selected source coordinates for one derived MIDX.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MidxSource {
    repository_id: RepositoryId,
    source_rcr_id: RepositoryCommitId,
    source_commit_oid: ObjectId,
}

impl MidxSource {
    /// Names the authority read from which the selected pack-index set was
    /// derived.  This records a source coordinate; it does not prove the
    /// coordinate remains current after materialization.
    pub fn new(
        repository_id: RepositoryId,
        source_rcr_id: RepositoryCommitId,
        source_commit_oid: ObjectId,
    ) -> Result<Self, MidxRefusal> {
        if source_commit_oid.is_zero() {
            return Err(MidxRefusal::ZeroObjectId {
                subject: "source commit",
            });
        }
        Ok(Self {
            repository_id,
            source_rcr_id,
            source_commit_oid,
        })
    }

    /// Repository whose authority read selected this materialization input.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Canonical RCR that selected the materialized source commit.
    #[must_use]
    pub const fn source_rcr_id(&self) -> RepositoryCommitId {
        self.source_rcr_id
    }

    /// Source commit that must be present in the materialized index set.
    #[must_use]
    pub const fn source_commit_oid(&self) -> &ObjectId {
        &self.source_commit_oid
    }
}

/// Immutable evidence for one derived MIDX output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MidxV1Receipt {
    source: MidxSource,
    profile: MidxProfile,
    completeness: MidxCompleteness,
    verification: MidxVerification,
    pack_count: usize,
    object_count: usize,
    checksum: ObjectId,
    output_bytes: usize,
}

impl MidxV1Receipt {
    /// Authority-selected source coordinate recorded before materialization.
    #[must_use]
    pub const fn source(&self) -> &MidxSource {
        &self.source
    }

    /// Stable generation profile that selected duplicate object locations.
    #[must_use]
    pub const fn profile(&self) -> MidxProfile {
        self.profile
    }

    /// Scope represented by the materialized MIDX records.
    #[must_use]
    pub const fn completeness(&self) -> MidxCompleteness {
        self.completeness
    }

    /// Boundary crossed before index records were retained.
    #[must_use]
    pub const fn verification(&self) -> MidxVerification {
        self.verification
    }

    /// Number of pack index names emitted in the pack-name chunk.
    #[must_use]
    pub const fn pack_count(&self) -> usize {
        self.pack_count
    }

    /// Number of de-duplicated object locations emitted in the MIDX.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_count
    }

    /// Native MIDX checksum over every preceding output byte.
    #[must_use]
    pub const fn checksum(&self) -> &ObjectId {
        &self.checksum
    }

    /// Complete MIDX output length including its native checksum.
    #[must_use]
    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }
}

/// Complete standard MIDX V1 bytes and their derived receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MidxV1 {
    bytes: Vec<u8>,
    receipt: MidxV1Receipt,
}

/// One derived MIDX location hint selected for a native object identity.
///
/// The name and offset only identify where a subsequent pack read may begin.
/// They do not authenticate pack bytes, establish object existence, or replace
/// a current authority read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MidxLocation {
    pack_index: u32,
    pack_name: Vec<u8>,
    pack_offset: u64,
}

impl MidxLocation {
    /// Zero-based index into the MIDX's canonical `PNAM` pack order.
    #[must_use]
    pub const fn pack_index(&self) -> u32 {
        self.pack_index
    }

    /// Exact NUL-free `PNAM` pack name bytes selected by the MIDX record.
    #[must_use]
    pub fn pack_name(&self) -> &[u8] {
        &self.pack_name
    }

    /// Candidate entry offset in the selected pack.  The caller must validate
    /// the native pack and object at this offset before using it.
    #[must_use]
    pub const fn pack_offset(&self) -> u64 {
        self.pack_offset
    }
}

impl MidxV1 {
    /// Materializes a deterministic MIDX V1 over structurally checked idx V2
    /// records.
    ///
    /// The caller supplies the authority-selected source coordinate; the
    /// output contains no host effect and has no authority role.  Supplying an
    /// index that was not authenticated against its backing pack is permitted
    /// only because the resulting MIDX remains a derived hint.  Consumers
    /// must verify pack and native-object identity at lookup use.
    pub fn write(
        source: MidxSource,
        indexes: &[IdxV2],
        limits: MidxLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, MidxRefusal> {
        if indexes.is_empty() {
            return Err(MidxRefusal::EmptyPackSet);
        }
        if indexes.len() > limits.max_packs {
            return Err(MidxRefusal::PackLimitExceeded {
                observed: indexes.len(),
                limit: limits.max_packs,
            });
        }
        let format = source.source_commit_oid.algorithm();
        let mut packs = Vec::new();
        packs
            .try_reserve_exact(indexes.len())
            .map_err(|_| MidxRefusal::AllocationFailed {
                requested: indexes.len(),
            })?;
        for index in indexes {
            checkpoint(deadline).map_err(MidxRefusal::Pack)?;
            if index.format() != format {
                return Err(MidxRefusal::ObjectFormatMismatch {
                    subject: "pack index",
                    expected: format,
                    observed: index.format(),
                });
            }
            if index.pack_checksum().is_zero() {
                return Err(MidxRefusal::ZeroObjectId {
                    subject: "pack checksum",
                });
            }
            packs.push(PackInput {
                name: pack_name(index.pack_checksum()),
                index,
            });
        }
        packs.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        for pair in packs.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(MidxRefusal::DuplicatePack {
                    checksum: *pair[0].index.pack_checksum(),
                });
            }
        }

        let mut locations = BTreeMap::new();
        for (pack_index, pack) in packs.iter().enumerate() {
            let pack_index =
                u32::try_from(pack_index).map_err(|_| MidxRefusal::PackLimitExceeded {
                    observed: packs.len(),
                    limit: u32::MAX as usize,
                })?;
            for entry in pack.index.entries() {
                checkpoint(deadline).map_err(MidxRefusal::Pack)?;
                if entry.pack_offset < PACK_HEADER_BYTES {
                    return Err(MidxRefusal::InvalidPackOffset {
                        pack: *pack.index.pack_checksum(),
                        object: entry.oid,
                        offset: entry.pack_offset,
                    });
                }
                if !locations.contains_key(&entry.oid) {
                    if locations.len() >= limits.max_objects {
                        return Err(MidxRefusal::ObjectLimitExceeded {
                            observed: locations.len().saturating_add(1),
                            limit: limits.max_objects,
                        });
                    }
                    locations.insert(
                        entry.oid,
                        ObjectLocation {
                            pack_index,
                            pack_offset: entry.pack_offset,
                        },
                    );
                }
            }
        }
        if !locations.contains_key(source.source_commit_oid()) {
            return Err(MidxRefusal::SourceCommitMissing {
                object: *source.source_commit_oid(),
            });
        }

        let mut large_offsets = Vec::new();
        large_offsets
            .try_reserve_exact(locations.len())
            .map_err(|_| MidxRefusal::AllocationFailed {
                requested: locations.len(),
            })?;
        for location in locations.values() {
            checkpoint(deadline).map_err(MidxRefusal::Pack)?;
            if location.pack_offset >= u64::from(LARGE_OFFSET_BIT) {
                let large_index = u32::try_from(large_offsets.len()).map_err(|_| {
                    MidxRefusal::LargeOffsetLimitExceeded {
                        observed: large_offsets.len().saturating_add(1),
                    }
                })?;
                if large_index & LARGE_OFFSET_BIT != 0 {
                    return Err(MidxRefusal::LargeOffsetLimitExceeded {
                        observed: large_offsets.len().saturating_add(1),
                    });
                }
                large_offsets.push(location.pack_offset);
            }
        }

        let output_bytes = output_bytes(format, &packs, locations.len(), large_offsets.len())?;
        if output_bytes > limits.max_output_bytes {
            return Err(MidxRefusal::OutputBytesExceeded {
                observed: output_bytes,
                limit: limits.max_output_bytes,
            });
        }
        let bytes = encode(
            format,
            &packs,
            &locations,
            &large_offsets,
            output_bytes,
            deadline,
        )?;
        let checksum = checksum(format, &bytes[..bytes.len() - format.digest_len()]);
        if bytes.len() != output_bytes {
            return Err(MidxRefusal::OutputMismatch {
                expected: output_bytes,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            receipt: MidxV1Receipt {
                source,
                profile: MidxProfile::V1LexicographicPackSelection,
                completeness: MidxCompleteness::SuppliedIndexesV1,
                verification: MidxVerification::IdxStructureV1,
                pack_count: packs.len(),
                object_count: locations.len(),
                checksum,
                output_bytes,
            },
            bytes,
        })
    }

    /// Exact MIDX bytes, including its native trailing checksum.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derived receipt for this immutable output.
    #[must_use]
    pub const fn receipt(&self) -> &MidxV1Receipt {
        &self.receipt
    }

    /// Looks up a native object identity through this immutable MIDX output.
    ///
    /// The lookup parses the retained standard chunks instead of carrying a
    /// second object-location map.  It verifies the materialization checksum,
    /// shape, and bounded chunk layout before consulting the hint.  `None`
    /// means this MIDX has no location for `oid`; it makes no canonical-state
    /// or object-admission claim.
    pub fn locate(
        &self,
        oid: &ObjectId,
        deadline: &mut impl Deadline,
    ) -> Result<Option<MidxLocation>, MidxRefusal> {
        let layout = MidxLookupLayout::parse(&self.bytes, &self.receipt)?;
        if oid.algorithm() != layout.format {
            return Err(MidxRefusal::ObjectFormatMismatch {
                subject: "lookup object",
                expected: layout.format,
                observed: oid.algorithm(),
            });
        }
        let mut lower = 0_usize;
        let mut upper = layout.object_count;
        while lower < upper {
            checkpoint(deadline).map_err(MidxRefusal::Pack)?;
            let middle = lower
                .checked_add((upper - lower) / 2)
                .ok_or(MidxRefusal::SizeOverflow)?;
            let entry_offset = layout
                .oid_lookup
                .checked_add(
                    middle
                        .checked_mul(layout.format.digest_len())
                        .ok_or(MidxRefusal::SizeOverflow)?,
                )
                .ok_or(MidxRefusal::SizeOverflow)?;
            let entry = self
                .bytes
                .get(entry_offset..entry_offset + layout.format.digest_len())
                .ok_or(MidxRefusal::MaterializationMismatch {
                    subject: "OIDL record",
                })?;
            match entry.cmp(oid.as_bytes()) {
                core::cmp::Ordering::Less => lower = middle.saturating_add(1),
                core::cmp::Ordering::Greater => upper = middle,
                core::cmp::Ordering::Equal => {
                    let location_offset = layout
                        .object_offsets
                        .checked_add(
                            middle
                                .checked_mul(MIDX_OBJECT_OFFSET_BYTES)
                                .ok_or(MidxRefusal::SizeOverflow)?,
                        )
                        .ok_or(MidxRefusal::SizeOverflow)?;
                    let pack_index = read_u32(&self.bytes, location_offset).ok_or(
                        MidxRefusal::MaterializationMismatch {
                            subject: "OOFF pack index",
                        },
                    )?;
                    if usize::try_from(pack_index).map_err(|_| {
                        MidxRefusal::MaterializationMismatch {
                            subject: "OOFF pack index",
                        }
                    })? >= layout.pack_count
                    {
                        return Err(MidxRefusal::MaterializationMismatch {
                            subject: "OOFF pack index range",
                        });
                    }
                    let direct_offset = read_u32(&self.bytes, location_offset + 4).ok_or(
                        MidxRefusal::MaterializationMismatch {
                            subject: "OOFF pack offset",
                        },
                    )?;
                    let pack_offset =
                        if direct_offset & LARGE_OFFSET_BIT == 0 {
                            u64::from(direct_offset)
                        } else {
                            let loff = layout.large_offsets.ok_or(
                                MidxRefusal::MaterializationMismatch {
                                    subject: "missing LOFF chunk",
                                },
                            )?;
                            let index = usize::try_from(direct_offset & !LARGE_OFFSET_BIT)
                                .map_err(|_| MidxRefusal::MaterializationMismatch {
                                    subject: "LOFF index",
                                })?;
                            let location = loff
                                .checked_add(index.checked_mul(8).ok_or(MidxRefusal::SizeOverflow)?)
                                .ok_or(MidxRefusal::SizeOverflow)?;
                            if location >= layout.pack_names {
                                return Err(MidxRefusal::MaterializationMismatch {
                                    subject: "LOFF index range",
                                });
                            }
                            read_u64(&self.bytes, location).ok_or(
                                MidxRefusal::MaterializationMismatch {
                                    subject: "LOFF record",
                                },
                            )?
                        };
                    if pack_offset < PACK_HEADER_BYTES {
                        return Err(MidxRefusal::MaterializationMismatch {
                            subject: "OOFF pack offset range",
                        });
                    }
                    let pack_name = layout.pack_name(&self.bytes, pack_index, deadline)?;
                    return Ok(Some(MidxLocation {
                        pack_index,
                        pack_name,
                        pack_offset,
                    }));
                }
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy)]
struct MidxLookupLayout {
    format: ObjectFormat,
    object_count: usize,
    pack_count: usize,
    oid_lookup: usize,
    object_offsets: usize,
    large_offsets: Option<usize>,
    pack_names: usize,
    body_end: usize,
}

impl MidxLookupLayout {
    fn parse(input: &[u8], receipt: &MidxV1Receipt) -> Result<Self, MidxRefusal> {
        let format = receipt.source().source_commit_oid().algorithm();
        let digest_len = format.digest_len();
        let body_end =
            input
                .len()
                .checked_sub(digest_len)
                .ok_or(MidxRefusal::MaterializationMismatch {
                    subject: "trailing checksum length",
                })?;
        let expected_format = match format {
            ObjectFormat::Sha1 => 1,
            ObjectFormat::Sha256 => 2,
        };
        if input.len() != receipt.output_bytes()
            || input.get(..4) != Some(MIDX_SIGNATURE)
            || input.get(4) != Some(&MIDX_VERSION_V1)
            || input.get(5) != Some(&expected_format)
            || input.get(7) != Some(&0)
            || input.get(body_end..) != Some(receipt.checksum().as_bytes())
            || checksum(format, &input[..body_end]) != *receipt.checksum()
        {
            return Err(MidxRefusal::MaterializationMismatch {
                subject: "header or checksum",
            });
        }
        let chunk_count =
            usize::from(*input.get(6).ok_or(MidxRefusal::MaterializationMismatch {
                subject: "chunk count",
            })?);
        let expected_chunk_count = if input.get(6) == Some(&5) { 5 } else { 4 };
        if chunk_count != expected_chunk_count {
            return Err(MidxRefusal::MaterializationMismatch {
                subject: "chunk count profile",
            });
        }
        let pack_count = usize::try_from(read_u32(input, 8).ok_or(
            MidxRefusal::MaterializationMismatch {
                subject: "pack count",
            },
        )?)
        .map_err(|_| MidxRefusal::MaterializationMismatch {
            subject: "pack count",
        })?;
        if pack_count != receipt.pack_count() {
            return Err(MidxRefusal::MaterializationMismatch {
                subject: "receipt pack count",
            });
        }
        let toc_count = chunk_count
            .checked_add(1)
            .ok_or(MidxRefusal::SizeOverflow)?;
        let toc_end = MIDX_HEADER_BYTES
            .checked_add(
                toc_count
                    .checked_mul(MIDX_TOC_ENTRY_BYTES)
                    .ok_or(MidxRefusal::SizeOverflow)?,
            )
            .ok_or(MidxRefusal::SizeOverflow)?;
        if toc_end > body_end {
            return Err(MidxRefusal::MaterializationMismatch {
                subject: "chunk table extent",
            });
        }
        let expected_ids: &[[u8; 4]] = if chunk_count == 5 {
            &[
                CHUNK_OID_FANOUT,
                CHUNK_OID_LOOKUP,
                CHUNK_OBJECT_OFFSETS,
                CHUNK_LARGE_OFFSETS,
                CHUNK_PACK_NAMES,
            ]
        } else {
            &[
                CHUNK_OID_FANOUT,
                CHUNK_OID_LOOKUP,
                CHUNK_OBJECT_OFFSETS,
                CHUNK_PACK_NAMES,
            ]
        };
        let mut offsets = [0_usize; 6];
        for index in 0..toc_count {
            let position = MIDX_HEADER_BYTES
                .checked_add(
                    index
                        .checked_mul(MIDX_TOC_ENTRY_BYTES)
                        .ok_or(MidxRefusal::SizeOverflow)?,
                )
                .ok_or(MidxRefusal::SizeOverflow)?;
            let id =
                input
                    .get(position..position + 4)
                    .ok_or(MidxRefusal::MaterializationMismatch {
                        subject: "chunk table id",
                    })?;
            let expected_id = if index == chunk_count {
                &[0; 4][..]
            } else {
                &expected_ids[index][..]
            };
            let offset = usize::try_from(read_u64(input, position + 4).ok_or(
                MidxRefusal::MaterializationMismatch {
                    subject: "chunk table offset",
                },
            )?)
            .map_err(|_| MidxRefusal::MaterializationMismatch {
                subject: "chunk table offset",
            })?;
            if id != expected_id
                || offset < toc_end
                || offset > body_end
                || (index > 0 && offset <= offsets[index - 1])
            {
                return Err(MidxRefusal::MaterializationMismatch {
                    subject: "canonical chunk table",
                });
            }
            offsets[index] = offset;
        }
        if offsets[chunk_count] != body_end
            || offsets[1].checked_sub(offsets[0]) != Some(MIDX_FANOUT_BYTES)
            || offsets[2].checked_sub(offsets[1]) != receipt.object_count().checked_mul(digest_len)
            || offsets[3].checked_sub(offsets[2])
                != receipt.object_count().checked_mul(MIDX_OBJECT_OFFSET_BYTES)
        {
            return Err(MidxRefusal::MaterializationMismatch {
                subject: "fixed chunk extent",
            });
        }
        let large_offsets = (chunk_count == 5).then_some(offsets[3]);
        let pack_names = if chunk_count == 5 {
            offsets[4]
        } else {
            offsets[3]
        };
        if large_offsets.is_some_and(|offset| (pack_names - offset) % 8 != 0) {
            return Err(MidxRefusal::MaterializationMismatch {
                subject: "LOFF extent",
            });
        }
        Ok(Self {
            format,
            object_count: receipt.object_count(),
            pack_count,
            oid_lookup: offsets[1],
            object_offsets: offsets[2],
            large_offsets,
            pack_names,
            body_end,
        })
    }

    fn pack_name(
        self,
        input: &[u8],
        index: u32,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, MidxRefusal> {
        let index = usize::try_from(index).map_err(|_| MidxRefusal::MaterializationMismatch {
            subject: "PNAM index",
        })?;
        let mut offset = self.pack_names;
        for current in 0..self.pack_count {
            checkpoint(deadline).map_err(MidxRefusal::Pack)?;
            let rest =
                input
                    .get(offset..self.body_end)
                    .ok_or(MidxRefusal::MaterializationMismatch {
                        subject: "PNAM extent",
                    })?;
            let length = rest.iter().position(|byte| *byte == 0).ok_or(
                MidxRefusal::MaterializationMismatch {
                    subject: "PNAM terminator",
                },
            )?;
            let end = offset
                .checked_add(length)
                .ok_or(MidxRefusal::SizeOverflow)?;
            if current == index {
                let name = input
                    .get(offset..end)
                    .ok_or(MidxRefusal::MaterializationMismatch {
                        subject: "PNAM record",
                    })?;
                if name.is_empty() || !name.is_ascii() {
                    return Err(MidxRefusal::MaterializationMismatch {
                        subject: "PNAM name",
                    });
                }
                return Ok(name.to_vec());
            }
            offset = end.checked_add(1).ok_or(MidxRefusal::SizeOverflow)?;
        }
        Err(MidxRefusal::MaterializationMismatch {
            subject: "PNAM index range",
        })
    }
}

/// Why an MIDX V1 materialization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MidxRefusal {
    /// An MIDX needs at least one selected pack index.
    EmptyPackSet,
    /// The number of selected pack indexes exceeded the configured bound.
    PackLimitExceeded {
        /// Count observed.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// The number of de-duplicated object records exceeded the bound before
    /// another map entry could be retained.
    ObjectLimitExceeded {
        /// Count observed.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A selected index did not match the source commit's native object-format
    /// domain.
    ObjectFormatMismatch {
        /// Value being checked.
        subject: &'static str,
        /// Required native object format.
        expected: ObjectFormat,
        /// Format observed in the selected input.
        observed: ObjectFormat,
    },
    /// A source or pack identity used Git's all-zero non-object sentinel.
    ZeroObjectId {
        /// Identity role being checked.
        subject: &'static str,
    },
    /// The retained MIDX bytes disagree with their receipt or the strict
    /// profile required by this materializer and must not answer a lookup.
    MaterializationMismatch {
        /// Inconsistent binary component.
        subject: &'static str,
    },
    /// Two input indexes named the same standard pack file.
    DuplicatePack {
        /// Shared pack trailer checksum.
        checksum: ObjectId,
    },
    /// A structurally parsed idx record named an impossible pack-entry offset.
    InvalidPackOffset {
        /// Pack trailer checksum that named the offending pack.
        pack: ObjectId,
        /// Object index record carrying the invalid offset.
        object: ObjectId,
        /// Offset below the native pack header.
        offset: u64,
    },
    /// The authority-selected source commit was absent from every supplied idx
    /// record, so the receipt could not describe its claimed source.
    SourceCommitMissing {
        /// Missing source commit identity.
        object: ObjectId,
    },
    /// The MIDX large-offset table would exceed the format's 31-bit index
    /// space.
    LargeOffsetLimitExceeded {
        /// Number of large offsets that would be required.
        observed: usize,
    },
    /// The full MIDX output would exceed the selected bound.
    OutputBytesExceeded {
        /// Bytes required.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Checked arithmetic overflowed while calculating MIDX layout.
    SizeOverflow,
    /// Bounded MIDX output or metadata storage could not be reserved.
    AllocationFailed {
        /// Elements or bytes requested.
        requested: usize,
    },
    /// A deadline/cancellation checkpoint refused work before publication.
    Pack(PackError),
    /// Internal size accounting and emitted bytes disagreed.
    OutputMismatch {
        /// Precomputed output size.
        expected: usize,
        /// Output size actually emitted.
        actual: usize,
    },
}

impl Display for MidxRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPackSet => formatter.write_str("MIDX V1 needs one pack index"),
            Self::PackLimitExceeded { observed, limit } => {
                write!(formatter, "{observed} MIDX packs exceeds limit {limit}")
            }
            Self::ObjectLimitExceeded { observed, limit } => {
                write!(formatter, "{observed} MIDX objects exceeds limit {limit}")
            }
            Self::ObjectFormatMismatch {
                subject,
                expected,
                observed,
            } => write!(
                formatter,
                "MIDX {subject} has format {observed:?}, expected {expected:?}"
            ),
            Self::ZeroObjectId { subject } => {
                write!(formatter, "MIDX {subject} uses the zero non-object ID")
            }
            Self::MaterializationMismatch { subject } => {
                write!(formatter, "MIDX materialization {subject} is inconsistent")
            }
            Self::DuplicatePack { checksum } => {
                write!(formatter, "duplicate MIDX pack checksum {checksum}")
            }
            Self::InvalidPackOffset {
                pack,
                object,
                offset,
            } => write!(
                formatter,
                "MIDX object {object} in pack {pack} has invalid offset {offset}"
            ),
            Self::SourceCommitMissing { object } => {
                write!(
                    formatter,
                    "MIDX source commit {object} is absent from supplied indexes"
                )
            }
            Self::LargeOffsetLimitExceeded { observed } => write!(
                formatter,
                "MIDX needs {observed} large offsets, beyond the format index space"
            ),
            Self::OutputBytesExceeded { observed, limit } => {
                write!(
                    formatter,
                    "MIDX output has {observed} bytes, limit is {limit}"
                )
            }
            Self::SizeOverflow => formatter.write_str("MIDX V1 size overflowed"),
            Self::AllocationFailed { requested } => {
                write!(
                    formatter,
                    "MIDX V1 could not reserve {requested} elements or bytes"
                )
            }
            Self::Pack(error) => write!(formatter, "MIDX V1 checkpoint refused: {error}"),
            Self::OutputMismatch { expected, actual } => write!(
                formatter,
                "MIDX V1 emitted {actual} bytes after planning {expected}"
            ),
        }
    }
}

impl core::error::Error for MidxRefusal {}

struct PackInput<'index> {
    name: Vec<u8>,
    index: &'index IdxV2,
}

#[derive(Clone, Copy)]
struct ObjectLocation {
    pack_index: u32,
    pack_offset: u64,
}

fn pack_name(checksum: &ObjectId) -> Vec<u8> {
    format!("pack-{checksum}.idx").into_bytes()
}

fn output_bytes(
    format: ObjectFormat,
    packs: &[PackInput<'_>],
    object_count: usize,
    large_offset_count: usize,
) -> Result<usize, MidxRefusal> {
    let chunk_count = if large_offset_count == 0 { 4_usize } else { 5 };
    let toc_bytes = chunk_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(MIDX_TOC_ENTRY_BYTES))
        .ok_or(MidxRefusal::SizeOverflow)?;
    let name_bytes = packs.iter().try_fold(0_usize, |total, pack| {
        total
            .checked_add(pack.name.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(MidxRefusal::SizeOverflow)
    })?;
    let oid_bytes = object_count
        .checked_mul(format.digest_len())
        .ok_or(MidxRefusal::SizeOverflow)?;
    let offset_bytes = object_count
        .checked_mul(MIDX_OBJECT_OFFSET_BYTES)
        .ok_or(MidxRefusal::SizeOverflow)?;
    let large_bytes = large_offset_count
        .checked_mul(8)
        .ok_or(MidxRefusal::SizeOverflow)?;
    MIDX_HEADER_BYTES
        .checked_add(toc_bytes)
        .and_then(|value| value.checked_add(MIDX_FANOUT_BYTES))
        .and_then(|value| value.checked_add(oid_bytes))
        .and_then(|value| value.checked_add(offset_bytes))
        .and_then(|value| value.checked_add(large_bytes))
        .and_then(|value| value.checked_add(name_bytes))
        .and_then(|value| value.checked_add(format.digest_len()))
        .ok_or(MidxRefusal::SizeOverflow)
}

fn encode(
    format: ObjectFormat,
    packs: &[PackInput<'_>],
    locations: &BTreeMap<ObjectId, ObjectLocation>,
    large_offsets: &[u64],
    output_bytes: usize,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, MidxRefusal> {
    let chunk_count = if large_offsets.is_empty() { 4_usize } else { 5 };
    let toc_bytes = chunk_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(MIDX_TOC_ENTRY_BYTES))
        .ok_or(MidxRefusal::SizeOverflow)?;
    let first_chunk_offset = MIDX_HEADER_BYTES
        .checked_add(toc_bytes)
        .ok_or(MidxRefusal::SizeOverflow)?;
    let oid_lookup_bytes = locations
        .len()
        .checked_mul(format.digest_len())
        .ok_or(MidxRefusal::SizeOverflow)?;
    let object_offset_bytes = locations
        .len()
        .checked_mul(MIDX_OBJECT_OFFSET_BYTES)
        .ok_or(MidxRefusal::SizeOverflow)?;
    let large_offset_bytes = large_offsets
        .len()
        .checked_mul(8)
        .ok_or(MidxRefusal::SizeOverflow)?;
    let oid_lookup_offset = first_chunk_offset
        .checked_add(MIDX_FANOUT_BYTES)
        .ok_or(MidxRefusal::SizeOverflow)?;
    let object_offsets_offset = oid_lookup_offset
        .checked_add(oid_lookup_bytes)
        .ok_or(MidxRefusal::SizeOverflow)?;
    let large_offsets_offset = object_offsets_offset
        .checked_add(object_offset_bytes)
        .ok_or(MidxRefusal::SizeOverflow)?;
    let pack_names_offset = large_offsets_offset
        .checked_add(large_offset_bytes)
        .ok_or(MidxRefusal::SizeOverflow)?;
    let body_end = output_bytes
        .checked_sub(format.digest_len())
        .ok_or(MidxRefusal::SizeOverflow)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(output_bytes)
        .map_err(|_| MidxRefusal::AllocationFailed {
            requested: output_bytes,
        })?;
    output.extend_from_slice(MIDX_SIGNATURE);
    output.push(MIDX_VERSION_V1);
    output.push(match format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    });
    output.push(u8::try_from(chunk_count).map_err(|_| MidxRefusal::SizeOverflow)?);
    output.push(0); // MIDX V1 has no base-MIDX chain.
    append_u32(
        &mut output,
        u32::try_from(packs.len()).map_err(|_| MidxRefusal::PackLimitExceeded {
            observed: packs.len(),
            limit: u32::MAX as usize,
        })?,
    );

    append_chunk_toc(&mut output, CHUNK_OID_FANOUT, first_chunk_offset)?;
    append_chunk_toc(&mut output, CHUNK_OID_LOOKUP, oid_lookup_offset)?;
    append_chunk_toc(&mut output, CHUNK_OBJECT_OFFSETS, object_offsets_offset)?;
    if !large_offsets.is_empty() {
        append_chunk_toc(&mut output, CHUNK_LARGE_OFFSETS, large_offsets_offset)?;
    }
    append_chunk_toc(&mut output, CHUNK_PACK_NAMES, pack_names_offset)?;
    append_chunk_toc(&mut output, [0; 4], body_end)?;

    let mut fanout = [0_u32; 256];
    for object in locations.keys() {
        checkpoint(deadline).map_err(MidxRefusal::Pack)?;
        let first = *object.as_bytes().first().ok_or(MidxRefusal::SizeOverflow)?;
        fanout[usize::from(first)] = fanout[usize::from(first)]
            .checked_add(1)
            .ok_or(MidxRefusal::SizeOverflow)?;
    }
    let mut cumulative = 0_u32;
    for count in &fanout {
        cumulative = cumulative
            .checked_add(*count)
            .ok_or(MidxRefusal::SizeOverflow)?;
        append_u32(&mut output, cumulative);
    }
    for object in locations.keys() {
        checkpoint(deadline).map_err(MidxRefusal::Pack)?;
        output.extend_from_slice(object.as_bytes());
    }
    let mut next_large = 0_usize;
    for location in locations.values() {
        checkpoint(deadline).map_err(MidxRefusal::Pack)?;
        append_u32(&mut output, location.pack_index);
        let offset = if location.pack_offset >= u64::from(LARGE_OFFSET_BIT) {
            let index =
                u32::try_from(next_large).map_err(|_| MidxRefusal::LargeOffsetLimitExceeded {
                    observed: next_large.saturating_add(1),
                })?;
            if index & LARGE_OFFSET_BIT != 0 {
                return Err(MidxRefusal::LargeOffsetLimitExceeded {
                    observed: next_large.saturating_add(1),
                });
            }
            next_large = next_large.checked_add(1).ok_or(MidxRefusal::SizeOverflow)?;
            LARGE_OFFSET_BIT | index
        } else {
            u32::try_from(location.pack_offset).map_err(|_| MidxRefusal::SizeOverflow)?
        };
        append_u32(&mut output, offset);
    }
    if next_large != large_offsets.len() {
        return Err(MidxRefusal::OutputMismatch {
            expected: large_offsets.len(),
            actual: next_large,
        });
    }
    for offset in large_offsets {
        checkpoint(deadline).map_err(MidxRefusal::Pack)?;
        output.extend_from_slice(&offset.to_be_bytes());
    }
    for pack in packs {
        checkpoint(deadline).map_err(MidxRefusal::Pack)?;
        output.extend_from_slice(&pack.name);
        output.push(0);
    }
    let digest = checksum(format, &output);
    output.extend_from_slice(digest.as_bytes());
    Ok(output)
}

fn append_chunk_toc(output: &mut Vec<u8>, id: [u8; 4], offset: usize) -> Result<(), MidxRefusal> {
    output.extend_from_slice(&id);
    output.extend_from_slice(
        &u64::try_from(offset)
            .map_err(|_| MidxRefusal::SizeOverflow)?
            .to_be_bytes(),
    );
    Ok(())
}

fn append_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn read_u32(input: &[u8], offset: usize) -> Option<u32> {
    input
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_be_bytes)
}

fn read_u64(input: &[u8], offset: usize) -> Option<u64> {
    input
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_be_bytes)
}

fn checksum(format: ObjectFormat, body: &[u8]) -> ObjectId {
    match format {
        ObjectFormat::Sha1 => ObjectId::from(fgit_types::GitOidSha1::from_bytes(sha1_digest(body))),
        ObjectFormat::Sha256 => {
            ObjectId::from(fgit_types::GitOidSha256::from_bytes(sha256_digest(body)))
        }
    }
}
