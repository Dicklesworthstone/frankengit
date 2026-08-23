//! Standard Git pack-bitmap V1 materialization.
//!
//! The mandatory `FULL_DAG` bitmap flag is only honest when its bit positions
//! are tied to a real, closure-complete pack.  This module therefore consumes a
//! writer-owned [`MaterializedPack`], whose private construction binds one
//! promoted pack's bytes, exact `PackPlan`, and writer receipt.  The output is
//! a derived accelerator: it does not admit objects or authorize repository
//! state, and a consumer must still authenticate the pack and authority basis.

use crate::{Deadline, MaterializedPack, ObjectFormat, ObjectId, PackError, checkpoint};
use core::fmt::{self, Display, Formatter};
use fgit_crypto::sha1_digest;
use fgit_git_object::ObjectType;
use fgit_types::{RepositoryCommitId, RepositoryId};
use std::collections::BTreeMap;

const BITMAP_SIGNATURE: &[u8; 4] = b"BITM";
const BITMAP_VERSION_V1: u16 = 1;
const BITMAP_OPT_FULL_DAG: u16 = 0x0001;
const BITMAP_ENTRY_REUSABLE: u8 = 0x01;
const SHA1_BYTES: usize = 20;
const BITMAP_HEADER_BYTES: usize = 4 + 2 + 2 + 4 + SHA1_BYTES;
const BITMAP_ENTRY_PREFIX_BYTES: usize = 4 + 1 + 1;
const EWAH_FIXED_BYTES: usize = 4 + 4 + 8 + 4;

/// Bounds selected before bitmap traversal, bitset allocation, or emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackBitmapLimits {
    /// Most pack-order objects represented in one bitmap index.
    pub max_objects: usize,
    /// Most commit reachability entries emitted in one bitmap index.
    pub max_commits: usize,
    /// Most object positions scheduled across all commit-reachability traversals,
    /// including repeated closure references before they can grow a stack.
    pub max_reachability_steps: u64,
    /// Most complete bitmap-index bytes including the trailing checksum.
    pub max_output_bytes: usize,
}

impl Default for PackBitmapLimits {
    fn default() -> Self {
        Self {
            max_objects: 4_000_000,
            max_commits: 1_000_000,
            max_reachability_steps: 64_000_000,
            max_output_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Frozen first profile for a full-DAG pack bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackBitmapProfile {
    /// Standard SHA-1 BITM V1 with four EWAH type indexes and an independently
    /// stored, reusable EWAH reachability bitmap for every commit in pack order.
    V1FullDagNoXor,
}

/// Exact scope represented by a bitmap index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackBitmapCompleteness {
    /// Every object in the writer-owned full pack closure, with one entry for
    /// every commit object in that same pack order.
    CompleteMaterializedPackV1,
}

/// Boundary crossed before a BITM record was emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackBitmapVerification {
    /// The writer-owned promoted artifact bound pack bytes, plan, and receipt;
    /// all canonical closure references resolved to positions in that plan.
    WriterBoundClosedPlanV1,
}

/// Exact authority-selected source coordinate for one derived bitmap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackBitmapSource {
    repository_id: RepositoryId,
    source_rcr_id: RepositoryCommitId,
    source_commit_oid: ObjectId,
}

impl PackBitmapSource {
    /// Creates source coordinates and rejects the all-zero non-object sentinel.
    pub fn new(
        repository_id: RepositoryId,
        source_rcr_id: RepositoryCommitId,
        source_commit_oid: ObjectId,
    ) -> Result<Self, PackBitmapRefusal> {
        if source_commit_oid.is_zero() {
            return Err(PackBitmapRefusal::ZeroObjectId {
                subject: "source commit",
            });
        }
        Ok(Self {
            repository_id,
            source_rcr_id,
            source_commit_oid,
        })
    }

    /// Repository whose authority read selected the materialized pack.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Canonical RCR that selected the source closure.
    #[must_use]
    pub const fn source_rcr_id(&self) -> RepositoryCommitId {
        self.source_rcr_id
    }

    /// Source commit that must occur as a commit object in the pack plan.
    #[must_use]
    pub const fn source_commit_oid(&self) -> &ObjectId {
        &self.source_commit_oid
    }
}

/// Immutable receipt for a standard BITM V1 output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackBitmapV1Receipt {
    source: PackBitmapSource,
    profile: PackBitmapProfile,
    completeness: PackBitmapCompleteness,
    verification: PackBitmapVerification,
    pack_checksum: ObjectId,
    object_count: usize,
    commit_count: usize,
    checksum: [u8; SHA1_BYTES],
    output_bytes: usize,
}

impl PackBitmapV1Receipt {
    /// Authority-selected source coordinate recorded before materialization.
    #[must_use]
    pub const fn source(&self) -> &PackBitmapSource {
        &self.source
    }

    /// Frozen standard bitmap format/profile.
    #[must_use]
    pub const fn profile(&self) -> PackBitmapProfile {
        self.profile
    }

    /// Input scope represented by bit positions and commit entries.
    #[must_use]
    pub const fn completeness(&self) -> PackBitmapCompleteness {
        self.completeness
    }

    /// Verification boundary crossed before output bytes were retained.
    #[must_use]
    pub const fn verification(&self) -> PackBitmapVerification {
        self.verification
    }

    /// SHA-1 pack trailer named in the standard BITM header.
    #[must_use]
    pub const fn pack_checksum(&self) -> &ObjectId {
        &self.pack_checksum
    }

    /// Number of objects in the associated pack order.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_count
    }

    /// Number of indexed commit reachability bitmaps.
    #[must_use]
    pub const fn commit_count(&self) -> usize {
        self.commit_count
    }

    /// SHA-1 trailer over every preceding bitmap-index byte.
    #[must_use]
    pub const fn checksum(&self) -> &[u8; SHA1_BYTES] {
        &self.checksum
    }

    /// Complete bitmap-index length including its SHA-1 trailer.
    #[must_use]
    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }
}

/// Complete standard pack-bitmap V1 bytes and their derived receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackBitmapV1 {
    bytes: Vec<u8>,
    receipt: PackBitmapV1Receipt,
}

impl PackBitmapV1 {
    /// Materializes a standard SHA-1 pack bitmap over a writer-owned promoted
    /// full pack.  The standard V1 format cannot name a SHA-256 pack checksum,
    /// so that domain receives a typed refusal rather than a nonstandard file.
    pub fn write(
        source: PackBitmapSource,
        pack: &MaterializedPack,
        limits: PackBitmapLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, PackBitmapRefusal> {
        let plan = pack.plan();
        if plan.format() != ObjectFormat::Sha1 {
            return Err(PackBitmapRefusal::UnsupportedObjectFormat {
                observed: plan.format(),
            });
        }
        let pack_checksum = pack.receipt().checksum;
        if pack_checksum.algorithm() != ObjectFormat::Sha1 {
            return Err(PackBitmapRefusal::UnsupportedObjectFormat {
                observed: pack_checksum.algorithm(),
            });
        }
        if pack.bytes().len() != pack.receipt().output_bytes {
            return Err(PackBitmapRefusal::WriterArtifactMismatch {
                subject: "pack byte length",
            });
        }
        if pack.bytes().len() < SHA1_BYTES
            || pack.bytes()[pack.bytes().len() - SHA1_BYTES..] != *pack_checksum.as_bytes()
        {
            return Err(PackBitmapRefusal::WriterArtifactMismatch {
                subject: "pack trailer",
            });
        }
        let object_count = plan.entries().len();
        let object_count_u32 =
            u32::try_from(object_count).map_err(|_| PackBitmapRefusal::ObjectLimitExceeded {
                observed: object_count,
                limit: u32::MAX as usize,
            })?;
        if object_count > limits.max_objects {
            return Err(PackBitmapRefusal::ObjectLimitExceeded {
                observed: object_count,
                limit: limits.max_objects,
            });
        }
        if pack.receipt().object_count != object_count_u32 {
            return Err(PackBitmapRefusal::WriterArtifactMismatch {
                subject: "planned object count",
            });
        }
        let (positions, commit_positions) =
            build_positions(plan, source.source_commit_oid(), deadline)?;
        if commit_positions.len() > limits.max_commits {
            return Err(PackBitmapRefusal::CommitLimitExceeded {
                observed: commit_positions.len(),
                limit: limits.max_commits,
            });
        }
        let bitmap_bytes = ewah_bytes(object_count)?;
        let output_bytes = output_bytes(bitmap_bytes, commit_positions.len())?;
        if output_bytes > limits.max_output_bytes {
            return Err(PackBitmapRefusal::OutputBytesExceeded {
                observed: output_bytes,
                limit: limits.max_output_bytes,
            });
        }

        let mut output = Vec::new();
        output.try_reserve_exact(output_bytes).map_err(|_| {
            PackBitmapRefusal::AllocationFailed {
                requested: output_bytes,
            }
        })?;
        output.extend_from_slice(BITMAP_SIGNATURE);
        output.extend_from_slice(&BITMAP_VERSION_V1.to_be_bytes());
        output.extend_from_slice(&BITMAP_OPT_FULL_DAG.to_be_bytes());
        append_u32(&mut output, object_count_u32);
        output.extend_from_slice(pack_checksum.as_bytes());

        for object_type in [
            ObjectType::Commit,
            ObjectType::Tree,
            ObjectType::Blob,
            ObjectType::Tag,
        ] {
            checkpoint(deadline).map_err(PackBitmapRefusal::Pack)?;
            let mut words = zeroed_words(object_count)?;
            for (position, entry) in plan.entries().iter().enumerate() {
                if entry.object().object_type() == object_type {
                    set_bit(&mut words, position)?;
                }
            }
            append_ewah(&mut output, object_count, &words)?;
        }

        let mut steps = 0_u64;
        for commit_position in &commit_positions {
            checkpoint(deadline).map_err(PackBitmapRefusal::Pack)?;
            append_u32(
                &mut output,
                u32::try_from(*commit_position).map_err(|_| PackBitmapRefusal::SizeOverflow)?,
            );
            output.push(0);
            output.push(BITMAP_ENTRY_REUSABLE);
            let words = reachability_words(
                plan,
                &positions,
                *commit_position,
                object_count,
                &mut steps,
                limits.max_reachability_steps,
                deadline,
            )?;
            append_ewah(&mut output, object_count, &words)?;
        }
        let checksum = sha1_digest(&output);
        output.extend_from_slice(&checksum);
        if output.len() != output_bytes {
            return Err(PackBitmapRefusal::OutputMismatch {
                expected: output_bytes,
                actual: output.len(),
            });
        }
        Ok(Self {
            bytes: output,
            receipt: PackBitmapV1Receipt {
                source,
                profile: PackBitmapProfile::V1FullDagNoXor,
                completeness: PackBitmapCompleteness::CompleteMaterializedPackV1,
                verification: PackBitmapVerification::WriterBoundClosedPlanV1,
                pack_checksum,
                object_count,
                commit_count: commit_positions.len(),
                checksum,
                output_bytes,
            },
        })
    }

    /// Exact BITM V1 bytes, including its SHA-1 trailer.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derived receipt for this immutable bitmap output.
    #[must_use]
    pub const fn receipt(&self) -> &PackBitmapV1Receipt {
        &self.receipt
    }
}

/// Why pack-bitmap V1 materialization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackBitmapRefusal {
    /// Standard BITM V1 is fixed to a 20-byte SHA-1 pack checksum.
    UnsupportedObjectFormat { observed: ObjectFormat },
    /// A source commit used Git's all-zero non-object sentinel.
    ZeroObjectId { subject: &'static str },
    /// The writer-owned pack's bytes and receipt disagreed.
    WriterArtifactMismatch { subject: &'static str },
    /// Selected pack entries exceeded the configured bound.
    ObjectLimitExceeded { observed: usize, limit: usize },
    /// Selected commit entries exceeded the configured bound.
    CommitLimitExceeded { observed: usize, limit: usize },
    /// The authority-selected source commit was not present in the plan.
    SourceCommitMissing { object: ObjectId },
    /// The authority-selected source object was present but was not a commit.
    SourceCommitIsNotCommit { object: ObjectId },
    /// The plan named the same native identity at two pack positions.
    DuplicateObject { object: ObjectId },
    /// A canonical closure reference did not occur in the materialized pack.
    ReferenceOutsidePack {
        object: ObjectId,
        reference: ObjectId,
    },
    /// Aggregate closure scheduling exceeded its selected work bound.
    ReachabilityWorkExceeded { observed: u64, limit: u64 },
    /// Checked arithmetic overflowed while planning a bitmap or EWAH layout.
    SizeOverflow,
    /// Bounded scratch/output allocation could not be reserved.
    AllocationFailed { requested: usize },
    /// A deadline/cancellation checkpoint refused work before output publication.
    Pack(PackError),
    /// Planned and emitted output lengths disagreed.
    OutputMismatch { expected: usize, actual: usize },
    /// Complete output would exceed the selected byte bound.
    OutputBytesExceeded { observed: usize, limit: usize },
}

impl Display for PackBitmapRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedObjectFormat { observed } => write!(
                formatter,
                "standard BITM V1 cannot name a {observed:?} pack checksum"
            ),
            Self::ZeroObjectId { subject } => {
                write!(formatter, "bitmap {subject} uses the zero non-object ID")
            }
            Self::WriterArtifactMismatch { subject } => {
                write!(
                    formatter,
                    "writer-owned pack {subject} mismatches its receipt"
                )
            }
            Self::ObjectLimitExceeded { observed, limit } => {
                write!(formatter, "{observed} bitmap objects exceeds limit {limit}")
            }
            Self::CommitLimitExceeded { observed, limit } => {
                write!(formatter, "{observed} bitmap commits exceeds limit {limit}")
            }
            Self::SourceCommitMissing { object } => {
                write!(
                    formatter,
                    "source commit {object} is absent from materialized pack"
                )
            }
            Self::SourceCommitIsNotCommit { object } => {
                write!(formatter, "source object {object} is not a commit")
            }
            Self::DuplicateObject { object } => {
                write!(formatter, "materialized pack repeats object {object}")
            }
            Self::ReferenceOutsidePack { object, reference } => write!(
                formatter,
                "pack object {object} references {reference} outside the materialized closure"
            ),
            Self::ReachabilityWorkExceeded { observed, limit } => write!(
                formatter,
                "bitmap traversal scheduled {observed} positions, limit is {limit}"
            ),
            Self::SizeOverflow => formatter.write_str("pack bitmap V1 size overflowed"),
            Self::AllocationFailed { requested } => {
                write!(
                    formatter,
                    "pack bitmap could not reserve {requested} elements or bytes"
                )
            }
            Self::Pack(error) => write!(formatter, "pack bitmap checkpoint refused: {error}"),
            Self::OutputMismatch { expected, actual } => write!(
                formatter,
                "pack bitmap emitted {actual} bytes after planning {expected}"
            ),
            Self::OutputBytesExceeded { observed, limit } => {
                write!(
                    formatter,
                    "pack bitmap has {observed} bytes, limit is {limit}"
                )
            }
        }
    }
}

impl core::error::Error for PackBitmapRefusal {}

fn build_positions(
    plan: &crate::PackPlan,
    source_commit: &ObjectId,
    deadline: &mut impl Deadline,
) -> Result<(BTreeMap<ObjectId, usize>, Vec<usize>), PackBitmapRefusal> {
    let mut positions = BTreeMap::new();
    let mut commits = Vec::new();
    commits
        .try_reserve_exact(plan.entries().len())
        .map_err(|_| PackBitmapRefusal::AllocationFailed {
            requested: plan.entries().len(),
        })?;
    let mut source_position = None;
    for (position, entry) in plan.entries().iter().enumerate() {
        checkpoint(deadline).map_err(PackBitmapRefusal::Pack)?;
        let object = entry.object();
        if positions.insert(object.id(), position).is_some() {
            return Err(PackBitmapRefusal::DuplicateObject {
                object: object.id(),
            });
        }
        if object.object_type() == ObjectType::Commit {
            commits.push(position);
        }
        if object.id() == *source_commit {
            source_position = Some(position);
        }
    }
    let source_position = source_position.ok_or(PackBitmapRefusal::SourceCommitMissing {
        object: *source_commit,
    })?;
    if plan.entries()[source_position].object().object_type() != ObjectType::Commit {
        return Err(PackBitmapRefusal::SourceCommitIsNotCommit {
            object: *source_commit,
        });
    }
    Ok((positions, commits))
}

fn reachability_words(
    plan: &crate::PackPlan,
    positions: &BTreeMap<ObjectId, usize>,
    root: usize,
    object_count: usize,
    steps: &mut u64,
    max_steps: u64,
    deadline: &mut impl Deadline,
) -> Result<Vec<u64>, PackBitmapRefusal> {
    let mut words = zeroed_words(object_count)?;
    let mut pending = Vec::new();
    pending
        .try_reserve(1)
        .map_err(|_| PackBitmapRefusal::AllocationFailed { requested: 1 })?;
    *steps = steps
        .checked_add(1)
        .ok_or(PackBitmapRefusal::SizeOverflow)?;
    if *steps > max_steps {
        return Err(PackBitmapRefusal::ReachabilityWorkExceeded {
            observed: *steps,
            limit: max_steps,
        });
    }
    pending.push(root);
    while let Some(position) = pending.pop() {
        checkpoint(deadline).map_err(PackBitmapRefusal::Pack)?;
        if bit_is_set(&words, position)? {
            continue;
        }
        set_bit(&mut words, position)?;
        let object = plan
            .entries()
            .get(position)
            .ok_or(PackBitmapRefusal::SizeOverflow)?
            .object();
        for reference in object.references() {
            let referenced_position = positions.get(reference).copied().ok_or(
                PackBitmapRefusal::ReferenceOutsidePack {
                    object: object.id(),
                    reference: *reference,
                },
            )?;
            *steps = steps
                .checked_add(1)
                .ok_or(PackBitmapRefusal::SizeOverflow)?;
            if *steps > max_steps {
                return Err(PackBitmapRefusal::ReachabilityWorkExceeded {
                    observed: *steps,
                    limit: max_steps,
                });
            }
            pending
                .try_reserve(1)
                .map_err(|_| PackBitmapRefusal::AllocationFailed { requested: 1 })?;
            pending.push(referenced_position);
        }
    }
    Ok(words)
}

fn ewah_bytes(object_count: usize) -> Result<usize, PackBitmapRefusal> {
    let words = object_count
        .checked_add(63)
        .ok_or(PackBitmapRefusal::SizeOverflow)?
        / 64;
    EWAH_FIXED_BYTES
        .checked_add(
            words
                .checked_mul(8)
                .ok_or(PackBitmapRefusal::SizeOverflow)?,
        )
        .ok_or(PackBitmapRefusal::SizeOverflow)
}

fn output_bytes(bitmap_bytes: usize, commit_count: usize) -> Result<usize, PackBitmapRefusal> {
    let types = bitmap_bytes
        .checked_mul(4)
        .ok_or(PackBitmapRefusal::SizeOverflow)?;
    let entry = BITMAP_ENTRY_PREFIX_BYTES
        .checked_add(bitmap_bytes)
        .ok_or(PackBitmapRefusal::SizeOverflow)?;
    BITMAP_HEADER_BYTES
        .checked_add(types)
        .and_then(|value| value.checked_add(entry.checked_mul(commit_count)?))
        .and_then(|value| value.checked_add(SHA1_BYTES))
        .ok_or(PackBitmapRefusal::SizeOverflow)
}

fn zeroed_words(object_count: usize) -> Result<Vec<u64>, PackBitmapRefusal> {
    let count = object_count
        .checked_add(63)
        .ok_or(PackBitmapRefusal::SizeOverflow)?
        / 64;
    let mut words = Vec::new();
    words
        .try_reserve_exact(count)
        .map_err(|_| PackBitmapRefusal::AllocationFailed { requested: count })?;
    words.resize(count, 0);
    Ok(words)
}

fn set_bit(words: &mut [u64], position: usize) -> Result<(), PackBitmapRefusal> {
    let word = position / 64;
    let bit = position % 64;
    let target = words.get_mut(word).ok_or(PackBitmapRefusal::SizeOverflow)?;
    *target |= 1_u64 << bit;
    Ok(())
}

fn bit_is_set(words: &[u64], position: usize) -> Result<bool, PackBitmapRefusal> {
    let word = position / 64;
    let bit = position % 64;
    Ok(words.get(word).ok_or(PackBitmapRefusal::SizeOverflow)? & (1_u64 << bit) != 0)
}

fn append_ewah(
    output: &mut Vec<u8>,
    object_count: usize,
    words: &[u64],
) -> Result<(), PackBitmapRefusal> {
    append_u32(
        output,
        u32::try_from(object_count).map_err(|_| PackBitmapRefusal::SizeOverflow)?,
    );
    let compressed_words = words
        .len()
        .checked_add(1)
        .ok_or(PackBitmapRefusal::SizeOverflow)?;
    append_u32(
        output,
        u32::try_from(compressed_words).map_err(|_| PackBitmapRefusal::SizeOverflow)?,
    );
    let literal_count = u64::try_from(words.len()).map_err(|_| PackBitmapRefusal::SizeOverflow)?;
    if literal_count >= (1_u64 << 31) {
        return Err(PackBitmapRefusal::SizeOverflow);
    }
    output.extend_from_slice(&(literal_count << 33).to_be_bytes());
    for word in words {
        output.extend_from_slice(&word.to_be_bytes());
    }
    append_u32(output, 0);
    Ok(())
}

fn append_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}
