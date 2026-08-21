//! Immutable compaction-generation records and their canonical codec.

use std::collections::BTreeSet;
use std::fmt;

use fgit_codec::{BodyIdentity, CanonicalBody, CodecRefusal, Decoder, Encoder, body_id};
use fgit_types::{
    DecisionSequence, Digest, GenerationId, GitOid, HeadGeneration, RepositoryAuthorityHeadId,
    SchemaFamily, SegmentManifestId,
};

const COMPACTION_SCHEMA_FAMILY: SchemaFamily =
    SchemaFamily::from_static("frankengit.compaction-record");
const COMPACTION_SCHEMA_MAJOR: u16 = 1;
const COMPACTION_SCHEMA_MINOR: u16 = 0;

/// The deliberately closed algorithm profile used by the first compaction
/// slice.  It re-encodes physical layout only; it never changes logical
/// object or decision identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CompactionAlgorithm {
    /// Stable, deterministic re-encoding with no layout-specific identity.
    DeterministicReencodeV1,
}

impl CompactionAlgorithm {
    const fn discriminant(self) -> u8 {
        match self {
            Self::DeterministicReencodeV1 => 1,
        }
    }

    fn from_discriminant(value: u8, offset: u64) -> Result<Self, CodecRefusal> {
        match value {
            1 => Ok(Self::DeterministicReencodeV1),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "CompactionAlgorithm",
                observed: u32::from(observed),
                offset,
            }),
        }
    }
}

/// The selected layout profile.
///
/// ADR-0004 deliberately fixes no numeric block or segment size before its
/// workload measurement exists.  The only supported profile here is therefore
/// the conservative interim profile rather than a caller-selected number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CompactionProfile {
    /// Larger blocks and segments with less aggressive compaction.
    ConservativeInterimV1,
}

impl CompactionProfile {
    const fn discriminant(self) -> u8 {
        match self {
            Self::ConservativeInterimV1 => 1,
        }
    }

    fn from_discriminant(value: u8, offset: u64) -> Result<Self, CodecRefusal> {
        match value {
            1 => Ok(Self::ConservativeInterimV1),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "CompactionProfile",
                observed: u32::from(observed),
                offset,
            }),
        }
    }
}

/// Inclusive decision-log range supplied by the authenticated input basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DecisionRange {
    /// First decision included in this compaction input.
    pub first: DecisionSequence,
    /// Last decision included in this compaction input.
    pub last: DecisionSequence,
}

impl DecisionRange {
    /// Builds a non-empty, increasing range.
    pub fn new(first: DecisionSequence, last: DecisionSequence) -> Result<Self, CompactionRefusal> {
        if first > last {
            return Err(CompactionRefusal::DecisionRangeReversed);
        }
        Ok(Self { first, last })
    }

    fn write(self, out: &mut Encoder) {
        out.write_scalar(self.first.get());
        out.write_scalar(self.last.get());
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let first = DecisionSequence::try_new(input.read_scalar::<u64>("range.first")?)?;
        let last = DecisionSequence::try_new(input.read_scalar::<u64>("range.last")?)?;
        Self::new(first, last).map_err(|_| CompactionRefusal::into_codec())
    }
}

/// A logical input that compaction must account for exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceEntry {
    /// A native Git object, whose Git identity is preserved through re-encode.
    Object(GitOid),
    /// A decision-log position, whose decision remains in the authority chain.
    Decision(DecisionSequence),
}

impl SourceEntry {
    /// Returns the object identity when this is an object entry.
    #[must_use]
    pub const fn object(self) -> Option<GitOid> {
        match self {
            Self::Object(object) => Some(object),
            Self::Decision(_) => None,
        }
    }

    fn write(self, out: &mut Encoder) {
        match self {
            Self::Object(object) => {
                out.write_raw_byte(1);
                out.write_git_oid(&object);
            }
            Self::Decision(sequence) => {
                out.write_raw_byte(2);
                out.write_scalar(sequence.get());
            }
        }
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        match input.read_raw_byte("SourceEntry")? {
            1 => Ok(Self::Object(input.read_git_oid()?)),
            2 => Ok(Self::Decision(DecisionSequence::try_new(
                input.read_scalar::<u64>("SourceEntry.decision")?,
            )?)),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "SourceEntry",
                observed: u32::from(observed),
                offset,
            }),
        }
    }
}

/// The physical result, or a documented intentional omission, for one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutputDisposition {
    /// The source is retained in the named output pack and segment manifest.
    Stored {
        /// Immutable packed-output root.
        pack_root: Digest,
        /// Immutable segment manifest that contains the packed representation.
        segment_manifest: SegmentManifestId,
    },
    /// The source was intentionally omitted, with immutable evidence naming
    /// the exact drop rule.  Silent omission is not representable.
    DocumentedDrop {
        /// Evidence root describing why this otherwise-source entry may drop.
        evidence_root: Digest,
    },
}

impl OutputDisposition {
    fn write(self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        match self {
            Self::Stored {
                pack_root,
                segment_manifest,
            } => {
                out.write_raw_byte(1);
                out.write_digest(&pack_root)?;
                out.write_internal_object_id(segment_manifest.as_internal_object_id())
            }
            Self::DocumentedDrop { evidence_root } => {
                out.write_raw_byte(2);
                out.write_digest(&evidence_root)
            }
        }
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        match input.read_raw_byte("OutputDisposition")? {
            1 => Ok(Self::Stored {
                pack_root: input.read_digest()?,
                segment_manifest: SegmentManifestId::from_internal_object_id(
                    input.read_internal_object_id()?,
                )?,
            }),
            2 => Ok(Self::DocumentedDrop {
                evidence_root: input.read_digest()?,
            }),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "OutputDisposition",
                observed: u32::from(observed),
                offset,
            }),
        }
    }
}

/// One source-to-output totality-map entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TotalityEntry {
    /// The logical input accounted for by this entry.
    pub source: SourceEntry,
    /// Its retained output or evidence-backed drop.
    pub disposition: OutputDisposition,
}

impl TotalityEntry {
    fn write(self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.source.write(out);
        self.disposition.write(out)
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            source: SourceEntry::read(input)?,
            disposition: OutputDisposition::read(input)?,
        })
    }
}

/// A total, target-disjoint mapping from every input object/decision to its
/// physical output or an evidence-backed drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceOutputTotalityMap {
    entries: Vec<TotalityEntry>,
}

impl SourceOutputTotalityMap {
    /// Builds a map and refuses an empty or multiply-accounted source set.
    pub fn new(entries: Vec<TotalityEntry>) -> Result<Self, CompactionRefusal> {
        let map = Self { entries };
        map.validate_shape()?;
        Ok(map)
    }

    /// The entries.  Their order has no semantics; the codec commits the
    /// canonical encoded order.
    #[must_use]
    pub fn entries(&self) -> &[TotalityEntry] {
        &self.entries
    }

    /// Whether this map explicitly accounts for a source object.
    #[must_use]
    pub fn contains_object(&self, object: GitOid) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.source == SourceEntry::Object(object))
    }

    fn validate_shape(&self) -> Result<(), CompactionRefusal> {
        if self.entries.is_empty() {
            return Err(CompactionRefusal::TotalityMapEmpty);
        }
        let mut sources = BTreeSet::new();
        for entry in &self.entries {
            if !sources.insert(entry.source) {
                return Err(CompactionRefusal::SourceAccountedMoreThanOnce {
                    source: entry.source,
                });
            }
        }
        Ok(())
    }

    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate_shape()
            .map_err(|_| CompactionRefusal::into_codec())?;
        out.write_canonical_set("CompactionRecord.totality", &self.entries, |out, entry| {
            entry.write(out)
        })
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let entries = input.read_canonical_set("CompactionRecord.totality", TotalityEntry::read)?;
        Self::new(entries).map_err(|_| CompactionRefusal::into_codec())
    }
}

/// Immutable physical outputs named by a compaction record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionOutputs {
    /// Roots of immutable output packs.
    pub pack_roots: Vec<Digest>,
    /// Immutable segment manifests for the output layout.
    pub segment_manifests: Vec<SegmentManifestId>,
    /// Rebuildable index roots created alongside the layout.
    pub index_roots: Vec<Digest>,
}

impl CompactionOutputs {
    fn validate_shape(&self) -> Result<(), CompactionRefusal> {
        if self.pack_roots.is_empty() || self.segment_manifests.is_empty() {
            return Err(CompactionRefusal::OutputLayoutEmpty);
        }
        if contains_duplicate(&self.pack_roots) {
            return Err(CompactionRefusal::DuplicateOutput {
                field: "pack_roots",
            });
        }
        if contains_duplicate(&self.segment_manifests) {
            return Err(CompactionRefusal::DuplicateOutput {
                field: "segment_manifests",
            });
        }
        if contains_duplicate(&self.index_roots) {
            return Err(CompactionRefusal::DuplicateOutput {
                field: "index_roots",
            });
        }
        Ok(())
    }

    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate_shape()
            .map_err(|_| CompactionRefusal::into_codec())?;
        out.write_canonical_set(
            "CompactionRecord.pack_roots",
            &self.pack_roots,
            |out, root| out.write_digest(root),
        )?;
        out.write_canonical_set(
            "CompactionRecord.segment_manifests",
            &self.segment_manifests,
            |out, manifest| out.write_internal_object_id(manifest.as_internal_object_id()),
        )?;
        out.write_canonical_set(
            "CompactionRecord.index_roots",
            &self.index_roots,
            |out, root| out.write_digest(root),
        )
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let pack_roots =
            input.read_canonical_set("CompactionRecord.pack_roots", |input| input.read_digest())?;
        let segment_manifests =
            input.read_canonical_set("CompactionRecord.segment_manifests", |input| {
                SegmentManifestId::from_internal_object_id(input.read_internal_object_id()?)
                    .map_err(CodecRefusal::from)
            })?;
        let index_roots = input
            .read_canonical_set("CompactionRecord.index_roots", |input| input.read_digest())?;
        let outputs = Self {
            pack_roots,
            segment_manifests,
            index_roots,
        };
        outputs
            .validate_shape()
            .map_err(|_| CompactionRefusal::into_codec())?;
        Ok(outputs)
    }
}

/// Evidence that the logical source stream and reconstructed output stream are
/// equal even though their physical layouts differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LogicalEquivalenceProof {
    /// Canonical logical root reconstructed from the authoritative input.
    pub source_logical_root: Digest,
    /// Canonical logical root reconstructed from every output pack/segment.
    pub output_logical_root: Digest,
    /// Immutable proof/evaluation receipt root.
    pub proof_root: Digest,
}

impl LogicalEquivalenceProof {
    /// Constructs a proof only when source and output reconstruction agree.
    pub fn construct(
        source_logical_root: Digest,
        output_logical_root: Digest,
        proof_root: Digest,
    ) -> Result<Self, CompactionRefusal> {
        let proof = Self {
            source_logical_root,
            output_logical_root,
            proof_root,
        };
        proof.verify()?;
        Ok(proof)
    }

    /// Re-verifies the equality obligation.
    pub fn verify(&self) -> Result<(), CompactionRefusal> {
        if self.source_logical_root != self.output_logical_root {
            return Err(CompactionRefusal::LogicalEquivalenceMismatch);
        }
        Ok(())
    }

    fn write(self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_digest(&self.source_logical_root)?;
        out.write_digest(&self.output_logical_root)?;
        out.write_digest(&self.proof_root)
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let proof = Self {
            source_logical_root: input.read_digest()?,
            output_logical_root: input.read_digest()?,
            proof_root: input.read_digest()?,
        };
        proof
            .verify()
            .map_err(|_| CompactionRefusal::into_codec())?;
        Ok(proof)
    }
}

/// The complete immutable compaction-generation record.
///
/// This is a `GenerationId` body.  The generation digest is the one value an
/// ordinary decision batch binds as its evidence root; no local compaction
/// index can make the record canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionRecord {
    /// Exact authority head from which the input was read.
    pub input_head: RepositoryAuthorityHeadId,
    /// Monotone generation carried by `input_head`.
    pub input_head_generation: HeadGeneration,
    /// Exact decision-log interval compacted.
    pub decision_range: DecisionRange,
    /// Authenticated input segment root.
    pub input_segment_root: Digest,
    /// Authenticated input decision root.
    pub input_decision_root: Digest,
    /// Closed physical re-encoding algorithm.
    pub algorithm: CompactionAlgorithm,
    /// The measured-profile doctrine's conservative interim selection.
    pub profile: CompactionProfile,
    /// Fingerprint of the toolchain that constructed this layout.
    pub toolchain_fingerprint: Digest,
    /// Immutable output packs, segments, and rebuildable indexes.
    pub outputs: CompactionOutputs,
    /// Logical-equivalence proof over the input and reconstructed outputs.
    pub equivalence_proof: LogicalEquivalenceProof,
    /// Complete source-to-output accounting.
    pub totality: SourceOutputTotalityMap,
    /// Resource/performance receipt for this concrete run.
    pub resource_receipt_root: Digest,
    /// Evidence describing candidate layouts deliberately rejected.
    pub rejected_layout_evidence_root: Digest,
}

impl CompactionRecord {
    /// Validates cross-field compaction invariants before publication.
    pub fn validate(&self) -> Result<(), CompactionRefusal> {
        let _ = DecisionRange::new(self.decision_range.first, self.decision_range.last)?;
        self.outputs.validate_shape()?;
        self.equivalence_proof.verify()?;
        self.totality.validate_shape()?;

        let packs: BTreeSet<_> = self.outputs.pack_roots.iter().copied().collect();
        let segments: BTreeSet<_> = self.outputs.segment_manifests.iter().copied().collect();
        let mut used_packs = BTreeSet::new();
        let mut used_segments = BTreeSet::new();
        for entry in self.totality.entries() {
            if let OutputDisposition::Stored {
                pack_root,
                segment_manifest,
            } = entry.disposition
            {
                if !packs.contains(&pack_root) || !segments.contains(&segment_manifest) {
                    return Err(CompactionRefusal::OutputReferenceUnknown);
                }
                used_packs.insert(pack_root);
                used_segments.insert(segment_manifest);
            }
        }
        if used_packs != packs || used_segments != segments {
            return Err(CompactionRefusal::OutputNotAccountedFor);
        }
        Ok(())
    }

    /// Computes the domain-pinned compaction generation identity.
    pub fn generation_id<I>(&self, identity: &I) -> Result<GenerationId, CodecRefusal>
    where
        I: BodyIdentity + ?Sized,
    {
        self.validate()
            .map_err(|_| CompactionRefusal::into_codec())?;
        let raw = body_id(identity, self)?;
        GenerationId::from_internal_object_id(raw).map_err(CodecRefusal::from)
    }

    /// The generation identity represented as the batch evidence-root value.
    ///
    /// The caller still carries the typed [`GenerationId`] alongside this
    /// digest.  The digest is only the authority schema's existing root field,
    /// never a replacement identity type.
    pub fn evidence_root<I>(&self, identity: &I) -> Result<Digest, CodecRefusal>
    where
        I: BodyIdentity + ?Sized,
    {
        let generation = self.generation_id(identity)?;
        let raw = generation.as_internal_object_id();
        Ok(Digest::new(raw.algorithm(), *raw.digest()))
    }
}

impl CanonicalBody for CompactionRecord {
    const DOMAIN: fgit_types::DomainTag = GenerationId::DOMAIN_TAG;
    const SCHEMA_FAMILY: SchemaFamily = COMPACTION_SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = COMPACTION_SCHEMA_MAJOR;
    const SCHEMA_MINOR: u16 = COMPACTION_SCHEMA_MINOR;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()
            .map_err(|_| CompactionRefusal::into_codec())?;
        out.write_internal_object_id(self.input_head.as_internal_object_id())?;
        out.write_scalar(self.input_head_generation.get());
        self.decision_range.write(out);
        out.write_digest(&self.input_segment_root)?;
        out.write_digest(&self.input_decision_root)?;
        out.write_raw_byte(self.algorithm.discriminant());
        out.write_raw_byte(self.profile.discriminant());
        out.write_digest(&self.toolchain_fingerprint)?;
        self.outputs.write(out)?;
        self.equivalence_proof.write(out)?;
        self.totality.write(out)?;
        out.write_digest(&self.resource_receipt_root)?;
        out.write_digest(&self.rejected_layout_evidence_root)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let input_head =
            RepositoryAuthorityHeadId::from_internal_object_id(input.read_internal_object_id()?)?;
        let input_head_generation = HeadGeneration::try_new(
            input.read_scalar::<u64>("CompactionRecord.input_head_generation")?,
        )?;
        let decision_range = DecisionRange::read(input)?;
        let input_segment_root = input.read_digest()?;
        let input_decision_root = input.read_digest()?;
        let algorithm_offset = input.offset();
        let algorithm = CompactionAlgorithm::from_discriminant(
            input.read_raw_byte("CompactionRecord.algorithm")?,
            algorithm_offset,
        )?;
        let profile_offset = input.offset();
        let profile = CompactionProfile::from_discriminant(
            input.read_raw_byte("CompactionRecord.profile")?,
            profile_offset,
        )?;
        let toolchain_fingerprint = input.read_digest()?;
        let outputs = CompactionOutputs::read(input)?;
        let equivalence_proof = LogicalEquivalenceProof::read(input)?;
        let totality = SourceOutputTotalityMap::read(input)?;
        let resource_receipt_root = input.read_digest()?;
        let rejected_layout_evidence_root = input.read_digest()?;
        let record = Self {
            input_head,
            input_head_generation,
            decision_range,
            input_segment_root,
            input_decision_root,
            algorithm,
            profile,
            toolchain_fingerprint,
            outputs,
            equivalence_proof,
            totality,
            resource_receipt_root,
            rejected_layout_evidence_root,
        };
        record
            .validate()
            .map_err(|_| CompactionRefusal::into_codec())?;
        Ok(record)
    }
}

/// Why a compaction record, proof, or totality map refuses construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactionRefusal {
    /// The decision interval is backwards.
    DecisionRangeReversed,
    /// There is no source accounting to verify.
    TotalityMapEmpty,
    /// A source appears in more than one totality entry.
    SourceAccountedMoreThanOnce {
        /// The conflicting source.
        source: SourceEntry,
    },
    /// A physical output vector has no usable pack/segment layout.
    OutputLayoutEmpty,
    /// A logically unordered output vector repeats an element.
    DuplicateOutput {
        /// The repeated output field.
        field: &'static str,
    },
    /// The proof's reconstructed logical roots differ.
    LogicalEquivalenceMismatch,
    /// A stored totality entry names an output absent from this record.
    OutputReferenceUnknown,
    /// An output pack or segment has no corresponding totality entry.
    OutputNotAccountedFor,
}

impl CompactionRefusal {
    const fn into_codec() -> CodecRefusal {
        CodecRefusal::ValueUnrepresentable {
            field: "CompactionRecord invariant",
            observed: 1,
            limit: 0,
        }
    }
}

impl fmt::Display for CompactionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionRangeReversed => {
                formatter.write_str("compaction decision range is reversed")
            }
            Self::TotalityMapEmpty => formatter.write_str("compaction totality map is empty"),
            Self::SourceAccountedMoreThanOnce { source } => {
                write!(
                    formatter,
                    "compaction source is accounted for more than once: {source:?}"
                )
            }
            Self::OutputLayoutEmpty => {
                formatter.write_str("compaction output layout has no pack or segment")
            }
            Self::DuplicateOutput { field } => {
                write!(
                    formatter,
                    "compaction output field repeats an entry: {field}"
                )
            }
            Self::LogicalEquivalenceMismatch => {
                formatter.write_str("compaction logical source and output roots differ")
            }
            Self::OutputReferenceUnknown => {
                formatter.write_str("compaction totality map references an unknown output")
            }
            Self::OutputNotAccountedFor => {
                formatter.write_str("compaction output is not accounted for by the totality map")
            }
        }
    }
}

impl std::error::Error for CompactionRefusal {}

fn contains_duplicate<T>(values: &[T]) -> bool
where
    T: Ord + Copy,
{
    let mut unique = BTreeSet::new();
    values.iter().any(|value| !unique.insert(*value))
}
