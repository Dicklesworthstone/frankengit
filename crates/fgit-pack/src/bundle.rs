//! Deterministic, full Git bundle V2 materialization.
//!
//! This module composes the existing verified [`PackWriter`] rather than
//! producing a second pack implementation.  Its supported profile is narrow
//! on purpose: a self-contained SHA-1 bundle with no prerequisites, no thin
//! pack, and no v3 capabilities.  Those omitted cases have distinct closure
//! and compatibility semantics and are typed unsupported rather than silently
//! represented by a misleading header.

use crate::{
    Deadline, ObjectFormat, ObjectId, PackError, PackLimits, PackPlan, PackWriteError,
    PackWriteReceipt, PackWriter, parse_pack_header,
};
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{sha1_digest, sha256_digest};
use fgit_types::{RefName, RepositoryCommitId, RepositoryId};
use std::collections::BTreeSet;

const BUNDLE_V2_SIGNATURE: &[u8] = b"# v2 git bundle\n";
const BUNDLE_V2_OBJECT_ID_BYTES: usize = 20;
const BUNDLE_V2_OBJECT_ID_HEX_BYTES: usize = BUNDLE_V2_OBJECT_ID_BYTES * 2;
const PACK_V2_HEADER_BYTES: usize = 12;

/// Bounds selected before a bundle header or final stream is retained.
///
/// The supplied [`PackWriter`] separately bounds pack planning and emission.
/// These limits bound the additional ref-header and combined bundle stream
/// owned by this materializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleV2Limits {
    /// Most advertised references in one bundle.
    pub max_references: usize,
    /// Most bytes retained before the pack boundary.
    pub max_header_bytes: usize,
    /// Most bytes in the complete header-plus-pack output.
    pub max_output_bytes: usize,
}

impl Default for BundleV2Limits {
    fn default() -> Self {
        Self {
            max_references: 100_000,
            max_header_bytes: 8 * 1024 * 1024,
            max_output_bytes: 512 * 1024 * 1024,
        }
    }
}

/// The only currently supported bundle materialization profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleProfile {
    /// Self-contained Bundle V2 with SHA-1 object IDs and no prerequisites.
    FullV2Sha1,
}

/// Exact authority-selected source coordinates for a derived bundle.
///
/// This is evidence about the source selected before materialization.  The
/// receipt does not make a local bundle authoritative or prove its RCR remains
/// current after construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleSource {
    repository_id: RepositoryId,
    source_rcr_id: RepositoryCommitId,
    source_commit_oid: ObjectId,
}

impl BundleSource {
    /// Names one authority-selected source commit for this derived output.
    pub fn new(
        repository_id: RepositoryId,
        source_rcr_id: RepositoryCommitId,
        source_commit_oid: ObjectId,
    ) -> Result<Self, BundleV2Refusal> {
        require_sha1(&source_commit_oid, "source commit")?;
        require_nonzero(&source_commit_oid, "source commit")?;
        Ok(Self {
            repository_id,
            source_rcr_id,
            source_commit_oid,
        })
    }

    /// Repository selected by the source authority read.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Canonical RCR that selected the source commit.
    #[must_use]
    pub const fn source_rcr_id(&self) -> RepositoryCommitId {
        self.source_rcr_id
    }

    /// Commit that must be represented by the full bundle closure.
    #[must_use]
    pub const fn source_commit_oid(&self) -> &ObjectId {
        &self.source_commit_oid
    }
}

/// One reference advertised by a Bundle V2 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleReference {
    target: ObjectId,
    name: RefName,
}

impl BundleReference {
    /// Builds a validated reference advertisement.
    ///
    /// The reference type rejects spaces, controls, and ref syntax that could
    /// turn one bundle header record into another.  The object-format and
    /// zero-ID checks occur when a concrete V2 profile is selected.
    #[must_use]
    pub const fn new(target: ObjectId, name: RefName) -> Self {
        Self { target, name }
    }

    /// Advertised target object identity.
    #[must_use]
    pub const fn target(&self) -> &ObjectId {
        &self.target
    }

    /// Advertised validated reference name.
    #[must_use]
    pub const fn name(&self) -> &RefName {
        &self.name
    }
}

/// Immutable evidence returned with one completed bundle stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleV2Receipt {
    source: BundleSource,
    profile: BundleProfile,
    reference_count: usize,
    header_sha256: [u8; 32],
    pack_receipt: PackWriteReceipt,
    output_bytes: usize,
}

impl BundleV2Receipt {
    /// Authority-selected coordinates from which this bundle was derived.
    #[must_use]
    pub const fn source(&self) -> &BundleSource {
        &self.source
    }

    /// Deterministic bundle profile applied to the output.
    #[must_use]
    pub const fn profile(&self) -> BundleProfile {
        self.profile
    }

    /// Number of canonical reference records before the blank pack delimiter.
    #[must_use]
    pub const fn reference_count(&self) -> usize {
        self.reference_count
    }

    /// SHA-256 of the complete header, ending with its blank delimiter line.
    #[must_use]
    pub const fn header_sha256(&self) -> &[u8; 32] {
        &self.header_sha256
    }

    /// The final immutable receipt produced by the composed pack writer.
    #[must_use]
    pub const fn pack_receipt(&self) -> &PackWriteReceipt {
        &self.pack_receipt
    }

    /// Complete bundle-stream length, header plus pack.
    #[must_use]
    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }
}

/// A complete self-contained Bundle V2 stream and its derived receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleV2 {
    bytes: Vec<u8>,
    receipt: BundleV2Receipt,
}

impl BundleV2 {
    /// Writes a full Bundle V2 from one closure-complete [`PackPlan`].
    ///
    /// The pack comes only from `writer`; callers cannot pair a convenient raw
    /// byte buffer with an unrelated plan or receipt.  Before pack emission,
    /// this validates that the advertised refs, source commit, and every
    /// verified outgoing edge are present in the same plan.  A plan assembled
    /// with omissions is therefore refused instead of being mislabeled as a
    /// self-contained bundle.
    pub fn write_full(
        source: BundleSource,
        references: &[BundleReference],
        plan: &PackPlan,
        writer: &PackWriter,
        deadline: &mut impl Deadline,
        limits: BundleV2Limits,
    ) -> Result<Self, BundleV2Refusal> {
        if plan.format() != ObjectFormat::Sha1 {
            return Err(BundleV2Refusal::ObjectFormatUnsupported {
                subject: "pack plan",
                observed: plan.format(),
            });
        }
        let references = canonical_references(references, &limits)?;
        let plan_ids = validate_full_closure(plan, &source, &references)?;
        let header = encode_header(&references, &limits)?;
        if header.len() > limits.max_output_bytes {
            return Err(BundleV2Refusal::OutputBytesExceeded {
                observed: header.len(),
                limit: limits.max_output_bytes,
            });
        }

        let (pack, pack_receipt) = writer
            .write(plan, deadline)
            .map_err(BundleV2Refusal::Pack)?;
        validate_pack_output(&pack, &pack_receipt, plan_ids.len())?;
        let output_bytes = header
            .len()
            .checked_add(pack.len())
            .ok_or(BundleV2Refusal::SizeOverflow)?;
        if output_bytes > limits.max_output_bytes {
            return Err(BundleV2Refusal::OutputBytesExceeded {
                observed: output_bytes,
                limit: limits.max_output_bytes,
            });
        }

        let mut bytes = header;
        bytes
            .try_reserve_exact(pack.len())
            .map_err(|_| BundleV2Refusal::AllocationFailed {
                requested: pack.len(),
            })?;
        bytes.extend_from_slice(&pack);
        let receipt = BundleV2Receipt {
            source,
            profile: BundleProfile::FullV2Sha1,
            reference_count: references.len(),
            header_sha256: sha256_digest(&bytes[..bytes.len() - pack.len()]),
            pack_receipt,
            output_bytes,
        };
        Ok(Self { bytes, receipt })
    }

    /// Exact bundle bytes: header, blank delimiter, then a native Git pack.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derived source, format, header, and pack evidence for this stream.
    #[must_use]
    pub const fn receipt(&self) -> &BundleV2Receipt {
        &self.receipt
    }
}

/// Why a Bundle V2 materialization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleV2Refusal {
    /// Bundle V2 cannot represent this object format.
    ObjectFormatUnsupported {
        /// Identity or plan being checked.
        subject: &'static str,
        /// Runtime Git identity domain observed.
        observed: ObjectFormat,
    },
    /// A ref or source commit used Git's all-zero non-object sentinel.
    ZeroObjectId {
        /// Identity role being checked.
        subject: &'static str,
    },
    /// This full-bundle profile needs at least one advertised reference.
    EmptyReferenceSet,
    /// Too many reference records were offered before header allocation.
    ReferenceLimitExceeded {
        /// Count observed.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Two offered records had the same ref name.
    DuplicateReference {
        /// Duplicate name.
        name: RefName,
    },
    /// An advertised ref or source commit is not present in the plan.
    MissingPlannedObject {
        /// Identity role being checked.
        subject: &'static str,
        /// Absent identity.
        object: ObjectId,
    },
    /// A verified object says it references an object not included in this
    /// full-bundle plan.
    ClosureEdgeMissing {
        /// Source object owning the missing edge.
        source: ObjectId,
        /// Missing referenced object.
        target: ObjectId,
    },
    /// The header would exceed its configured byte limit.
    HeaderBytesExceeded {
        /// Bytes that would be retained.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// The complete stream would exceed its configured byte limit.
    OutputBytesExceeded {
        /// Bytes that would be retained.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// The pack writer refused planning, compression, cancellation, or
    /// promotion before a bundle could be assembled.
    Pack(PackWriteError),
    /// A completed writer result disagreed with its pack framing or receipt.
    PackReceiptMismatch {
        /// Stable mismatch class.
        context: &'static str,
    },
    /// Pack framing could not be parsed through the existing pack boundary.
    PackStructure(PackError),
    /// Header or complete-stream length overflowed address-space accounting.
    SizeOverflow,
    /// Header or final output could not reserve bounded memory.
    AllocationFailed {
        /// Bytes requested from the allocator.
        requested: usize,
    },
}

impl Display for BundleV2Refusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectFormatUnsupported { subject, observed } => write!(
                formatter,
                "Bundle V2 supports only SHA-1; {subject} uses {observed:?}"
            ),
            Self::ZeroObjectId { subject } => {
                write!(formatter, "Bundle V2 {subject} uses the zero non-object ID")
            }
            Self::EmptyReferenceSet => formatter.write_str("full Bundle V2 needs one reference"),
            Self::ReferenceLimitExceeded { observed, limit } => {
                write!(
                    formatter,
                    "{observed} bundle references exceeds the limit of {limit}"
                )
            }
            Self::DuplicateReference { name } => {
                write!(formatter, "duplicate Bundle V2 reference {name}")
            }
            Self::MissingPlannedObject { subject, object } => {
                write!(
                    formatter,
                    "Bundle V2 {subject} {object} is not in the pack plan"
                )
            }
            Self::ClosureEdgeMissing { source, target } => write!(
                formatter,
                "full Bundle V2 plan omits closure edge {source} -> {target}"
            ),
            Self::HeaderBytesExceeded { observed, limit } => write!(
                formatter,
                "Bundle V2 header would retain {observed} bytes, limit is {limit}"
            ),
            Self::OutputBytesExceeded { observed, limit } => write!(
                formatter,
                "Bundle V2 output would retain {observed} bytes, limit is {limit}"
            ),
            Self::Pack(error) => {
                write!(formatter, "Bundle V2 pack materialization refused: {error}")
            }
            Self::PackReceiptMismatch { context } => {
                write!(formatter, "Bundle V2 pack receipt mismatch: {context}")
            }
            Self::PackStructure(error) => {
                write!(formatter, "Bundle V2 pack framing refused: {error}")
            }
            Self::SizeOverflow => formatter.write_str("Bundle V2 size overflowed"),
            Self::AllocationFailed { requested } => {
                write!(formatter, "Bundle V2 could not reserve {requested} bytes")
            }
        }
    }
}

impl core::error::Error for BundleV2Refusal {}

fn canonical_references(
    offered: &[BundleReference],
    limits: &BundleV2Limits,
) -> Result<Vec<BundleReference>, BundleV2Refusal> {
    if offered.is_empty() {
        return Err(BundleV2Refusal::EmptyReferenceSet);
    }
    if offered.len() > limits.max_references {
        return Err(BundleV2Refusal::ReferenceLimitExceeded {
            observed: offered.len(),
            limit: limits.max_references,
        });
    }
    let mut references = Vec::new();
    references
        .try_reserve_exact(offered.len())
        .map_err(|_| BundleV2Refusal::AllocationFailed {
            requested: offered.len(),
        })?;
    for reference in offered {
        require_sha1(&reference.target, "reference target")?;
        require_nonzero(&reference.target, "reference target")?;
        references.push(reference.clone());
    }
    references.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    for pair in references.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(BundleV2Refusal::DuplicateReference {
                name: pair[0].name.clone(),
            });
        }
    }
    Ok(references)
}

fn validate_full_closure(
    plan: &PackPlan,
    source: &BundleSource,
    references: &[BundleReference],
) -> Result<BTreeSet<ObjectId>, BundleV2Refusal> {
    let mut ids = BTreeSet::new();
    for entry in plan.entries() {
        ids.insert(entry.object().id());
    }
    if !ids.contains(&source.source_commit_oid) {
        return Err(BundleV2Refusal::MissingPlannedObject {
            subject: "source commit",
            object: source.source_commit_oid,
        });
    }
    for reference in references {
        if !ids.contains(&reference.target) {
            return Err(BundleV2Refusal::MissingPlannedObject {
                subject: "reference target",
                object: reference.target,
            });
        }
    }
    for entry in plan.entries() {
        for target in entry.object().references() {
            if !ids.contains(target) {
                return Err(BundleV2Refusal::ClosureEdgeMissing {
                    source: entry.object().id(),
                    target: *target,
                });
            }
        }
    }
    Ok(ids)
}

fn encode_header(
    references: &[BundleReference],
    limits: &BundleV2Limits,
) -> Result<Vec<u8>, BundleV2Refusal> {
    let mut header_bytes = BUNDLE_V2_SIGNATURE
        .len()
        .checked_add(1)
        .ok_or(BundleV2Refusal::SizeOverflow)?;
    for reference in references {
        let record_bytes = BUNDLE_V2_OBJECT_ID_HEX_BYTES
            .checked_add(1)
            .and_then(|value| value.checked_add(reference.name.as_bytes().len()))
            .and_then(|value| value.checked_add(1))
            .ok_or(BundleV2Refusal::SizeOverflow)?;
        header_bytes = header_bytes
            .checked_add(record_bytes)
            .ok_or(BundleV2Refusal::SizeOverflow)?;
        if header_bytes > limits.max_header_bytes {
            return Err(BundleV2Refusal::HeaderBytesExceeded {
                observed: header_bytes,
                limit: limits.max_header_bytes,
            });
        }
    }
    let mut header = Vec::new();
    header
        .try_reserve_exact(header_bytes)
        .map_err(|_| BundleV2Refusal::AllocationFailed {
            requested: header_bytes,
        })?;
    header.extend_from_slice(BUNDLE_V2_SIGNATURE);
    for reference in references {
        append_hex(&mut header, reference.target.as_bytes());
        header.push(b' ');
        header.extend_from_slice(reference.name.as_bytes());
        header.push(b'\n');
    }
    header.push(b'\n');
    Ok(header)
}

fn validate_pack_output(
    pack: &[u8],
    receipt: &PackWriteReceipt,
    planned_object_count: usize,
) -> Result<(), BundleV2Refusal> {
    if pack.len() != receipt.output_bytes {
        return Err(BundleV2Refusal::PackReceiptMismatch {
            context: "output byte count",
        });
    }
    if pack.len() < PACK_V2_HEADER_BYTES + BUNDLE_V2_OBJECT_ID_BYTES {
        return Err(BundleV2Refusal::PackReceiptMismatch {
            context: "pack shorter than v2 header and SHA-1 trailer",
        });
    }
    require_sha1(&receipt.checksum, "pack checksum")?;
    let parse_limits = PackLimits {
        max_input_bytes: pack.len(),
        max_entries: u32::MAX,
        ..PackLimits::default()
    };
    let header = parse_pack_header(pack, &parse_limits).map_err(BundleV2Refusal::PackStructure)?;
    if header.object_count != receipt.object_count
        || usize::try_from(header.object_count).ok() != Some(planned_object_count)
    {
        return Err(BundleV2Refusal::PackReceiptMismatch {
            context: "pack object count",
        });
    }
    let split = pack
        .len()
        .checked_sub(BUNDLE_V2_OBJECT_ID_BYTES)
        .ok_or(BundleV2Refusal::SizeOverflow)?;
    let trailer = &pack[split..];
    if trailer != receipt.checksum.as_bytes() || sha1_digest(&pack[..split]).as_slice() != trailer {
        return Err(BundleV2Refusal::PackReceiptMismatch {
            context: "native SHA-1 trailer",
        });
    }
    Ok(())
}

fn require_sha1(object: &ObjectId, subject: &'static str) -> Result<(), BundleV2Refusal> {
    if object.algorithm() == ObjectFormat::Sha1 {
        Ok(())
    } else {
        Err(BundleV2Refusal::ObjectFormatUnsupported {
            subject,
            observed: object.algorithm(),
        })
    }
}

fn require_nonzero(object: &ObjectId, subject: &'static str) -> Result<(), BundleV2Refusal> {
    if object.as_bytes().iter().any(|byte| *byte != 0) {
        Ok(())
    } else {
        Err(BundleV2Refusal::ZeroObjectId { subject })
    }
}

fn append_hex(output: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)]);
        output.push(HEX[usize::from(byte & 0x0f)]);
    }
}
