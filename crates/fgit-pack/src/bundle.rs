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
use fgit_types::{GitOidSha1, RefName, RepositoryCommitId, RepositoryId};
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

/// A bounded, checksum-verified Bundle V2 input which remains in quarantine.
///
/// The header is restricted to the canonical full-Bundle-V2 profile emitted by
/// [`BundleV2::write_full`]: SHA-1 references, no prerequisites, and strictly
/// increasing reference names.  The pack's native checksum is checked to
/// reject transit corruption, but that is not object admission: callers must
/// still pass [`Self::pack_bytes`] through the existing bounded pack
/// quarantine and native-object verification boundaries before storing or
/// using any object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedBundleV2<'input> {
    references: Vec<BundleReference>,
    header_bytes: &'input [u8],
    pack_bytes: &'input [u8],
    header_sha256: [u8; 32],
    pack_checksum: ObjectId,
}

impl<'input> QuarantinedBundleV2<'input> {
    /// Canonically ordered reference advertisements from the untrusted header.
    #[must_use]
    pub fn references(&self) -> &[BundleReference] {
        &self.references
    }

    /// Exact header bytes through the blank pack delimiter.
    #[must_use]
    pub fn header_bytes(&self) -> &'input [u8] {
        self.header_bytes
    }

    /// Raw native pack bytes, still requiring object quarantine and admission.
    #[must_use]
    pub fn pack_bytes(&self) -> &'input [u8] {
        self.pack_bytes
    }

    /// SHA-256 digest of the complete received header.
    #[must_use]
    pub const fn header_sha256(&self) -> &[u8; 32] {
        &self.header_sha256
    }

    /// Native SHA-1 trailer checksum already matched against the pack bytes.
    #[must_use]
    pub const fn pack_checksum(&self) -> ObjectId {
        self.pack_checksum
    }
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

    /// Inspects one untrusted, full SHA-1 Bundle V2 stream without admitting it.
    ///
    /// This is intentionally a narrow materialization-verification profile,
    /// not a general Git bundle importer.  In particular, prerequisite lines,
    /// SHA-256, and Bundle V3 capabilities are refused rather than being
    /// silently reinterpreted.  The returned value exposes only a checked
    /// header and a checksum-matched *quarantine* pack; no authority, object
    /// closure, or object identity claim follows from this call.
    pub fn inspect_quarantined_full_sha1<'input>(
        input: &'input [u8],
        limits: BundleV2Limits,
        pack_limits: &PackLimits,
    ) -> Result<QuarantinedBundleV2<'input>, BundleV2Refusal> {
        if input.len() > limits.max_output_bytes {
            return Err(BundleV2Refusal::InputBytesExceeded {
                observed: input.len(),
                limit: limits.max_output_bytes,
            });
        }
        if !input.starts_with(BUNDLE_V2_SIGNATURE) {
            return Err(BundleV2Refusal::InvalidSignature);
        }
        if BUNDLE_V2_SIGNATURE.len() > limits.max_header_bytes {
            return Err(BundleV2Refusal::HeaderBytesExceeded {
                observed: BUNDLE_V2_SIGNATURE.len(),
                limit: limits.max_header_bytes,
            });
        }

        let (references, header_end) = inspect_header(input, limits)?;
        let header_bytes = &input[..header_end];
        let pack_bytes = input
            .get(header_end..)
            .ok_or(BundleV2Refusal::SizeOverflow)?;
        let pack_checksum = inspect_pack(pack_bytes, pack_limits)?;

        Ok(QuarantinedBundleV2 {
            references,
            header_bytes,
            pack_bytes,
            header_sha256: sha256_digest(header_bytes),
            pack_checksum,
        })
    }
}

/// Why a Bundle V2 materialization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleV2Refusal {
    /// An untrusted input stream exceeded the caller-selected bound before
    /// header or pack parsing could retain derived state.
    InputBytesExceeded {
        /// Complete input length observed.
        observed: usize,
        /// Caller-selected maximum.
        limit: usize,
    },
    /// The input did not start with the exact Bundle V2 signature.
    InvalidSignature,
    /// The bounded Bundle V2 header ended before its blank pack delimiter.
    HeaderDelimiterMissing,
    /// A nonempty header record was not exactly `40-lower-hex SP refname`.
    MalformedReferenceRecord {
        /// One-based header record number after the signature.
        line: usize,
    },
    /// A header reference name violated the shared Git refname grammar.
    InvalidReferenceName {
        /// One-based header record number after the signature.
        line: usize,
    },
    /// Header references were not strictly increasing by canonical refname
    /// byte order.
    NonCanonicalReferenceOrder {
        /// Earlier reference name.
        previous: RefName,
        /// Later reference name which was not greater than `previous`.
        next: RefName,
    },
    /// The native SHA-1 pack trailer did not match the preceding pack bytes.
    PackChecksumMismatch,
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
            Self::InputBytesExceeded { observed, limit } => write!(
                formatter,
                "Bundle V2 input has {observed} bytes, limit is {limit}"
            ),
            Self::InvalidSignature => formatter.write_str("invalid Bundle V2 signature"),
            Self::HeaderDelimiterMissing => {
                formatter.write_str("Bundle V2 header has no blank pack delimiter")
            }
            Self::MalformedReferenceRecord { line } => {
                write!(formatter, "malformed Bundle V2 reference record {line}")
            }
            Self::InvalidReferenceName { line } => {
                write!(
                    formatter,
                    "invalid Bundle V2 reference name at record {line}"
                )
            }
            Self::NonCanonicalReferenceOrder { previous, next } => write!(
                formatter,
                "Bundle V2 reference {next} does not follow canonical predecessor {previous}"
            ),
            Self::PackChecksumMismatch => {
                formatter.write_str("Bundle V2 native pack trailer checksum mismatch")
            }
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

fn inspect_header(
    input: &[u8],
    limits: BundleV2Limits,
) -> Result<(Vec<BundleReference>, usize), BundleV2Refusal> {
    let mut cursor = BUNDLE_V2_SIGNATURE.len();
    let mut line = 0_usize;
    let mut references = Vec::new();

    loop {
        let remaining = limits.max_header_bytes.checked_sub(cursor).ok_or(
            BundleV2Refusal::HeaderBytesExceeded {
                observed: cursor,
                limit: limits.max_header_bytes,
            },
        )?;
        let scan_end = cursor
            .checked_add(remaining)
            .map_or(input.len(), |end| end.min(input.len()));
        let Some(relative_newline) = input[cursor..scan_end]
            .iter()
            .position(|byte| *byte == b'\n')
        else {
            if scan_end == input.len() {
                return Err(BundleV2Refusal::HeaderDelimiterMissing);
            }
            return Err(BundleV2Refusal::HeaderBytesExceeded {
                observed: limits.max_header_bytes.saturating_add(1),
                limit: limits.max_header_bytes,
            });
        };
        let line_end = cursor
            .checked_add(relative_newline)
            .ok_or(BundleV2Refusal::SizeOverflow)?;
        let next = line_end
            .checked_add(1)
            .ok_or(BundleV2Refusal::SizeOverflow)?;
        let record = &input[cursor..line_end];
        if record.is_empty() {
            if references.is_empty() {
                return Err(BundleV2Refusal::EmptyReferenceSet);
            }
            return Ok((references, next));
        }

        line = line.checked_add(1).ok_or(BundleV2Refusal::SizeOverflow)?;
        if references.len() >= limits.max_references {
            return Err(BundleV2Refusal::ReferenceLimitExceeded {
                observed: references.len().saturating_add(1),
                limit: limits.max_references,
            });
        }
        let reference = parse_reference_record(record, line)?;
        if let Some(previous) = references.last().map(BundleReference::name) {
            if previous >= reference.name() {
                return Err(BundleV2Refusal::NonCanonicalReferenceOrder {
                    previous: previous.clone(),
                    next: reference.name().clone(),
                });
            }
        }
        references.push(reference);
        cursor = next;
    }
}

fn parse_reference_record(record: &[u8], line: usize) -> Result<BundleReference, BundleV2Refusal> {
    if record.len() <= BUNDLE_V2_OBJECT_ID_HEX_BYTES
        || record.get(BUNDLE_V2_OBJECT_ID_HEX_BYTES) != Some(&b' ')
    {
        return Err(BundleV2Refusal::MalformedReferenceRecord { line });
    }
    let target = parse_sha1_hex(&record[..BUNDLE_V2_OBJECT_ID_HEX_BYTES])
        .ok_or(BundleV2Refusal::MalformedReferenceRecord { line })?;
    let target = ObjectId::from(GitOidSha1::from_bytes(target));
    require_nonzero(&target, "reference target")?;
    let name = RefName::try_new(&record[BUNDLE_V2_OBJECT_ID_HEX_BYTES + 1..])
        .map_err(|_| BundleV2Refusal::InvalidReferenceName { line })?;
    Ok(BundleReference::new(target, name))
}

fn parse_sha1_hex(input: &[u8]) -> Option<[u8; BUNDLE_V2_OBJECT_ID_BYTES]> {
    if input.len() != BUNDLE_V2_OBJECT_ID_HEX_BYTES {
        return None;
    }
    let mut output = [0_u8; BUNDLE_V2_OBJECT_ID_BYTES];
    for (index, chunk) in input.chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn inspect_pack(pack: &[u8], pack_limits: &PackLimits) -> Result<ObjectId, BundleV2Refusal> {
    if pack.len() > pack_limits.max_input_bytes {
        return Err(BundleV2Refusal::PackStructure(PackError::InputLimit {
            actual: pack.len(),
            limit: pack_limits.max_input_bytes,
        }));
    }
    if pack.len() < PACK_V2_HEADER_BYTES + BUNDLE_V2_OBJECT_ID_BYTES {
        return Err(BundleV2Refusal::PackReceiptMismatch {
            context: "pack shorter than v2 header and SHA-1 trailer",
        });
    }
    parse_pack_header(pack, pack_limits).map_err(BundleV2Refusal::PackStructure)?;
    let split = pack
        .len()
        .checked_sub(BUNDLE_V2_OBJECT_ID_BYTES)
        .ok_or(BundleV2Refusal::SizeOverflow)?;
    let trailer: [u8; BUNDLE_V2_OBJECT_ID_BYTES] =
        pack[split..]
            .try_into()
            .map_err(|_| BundleV2Refusal::PackReceiptMismatch {
                context: "SHA-1 trailer length",
            })?;
    if sha1_digest(&pack[..split]).as_slice() != trailer {
        return Err(BundleV2Refusal::PackChecksumMismatch);
    }
    Ok(ObjectId::from(GitOidSha1::from_bytes(trailer)))
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
