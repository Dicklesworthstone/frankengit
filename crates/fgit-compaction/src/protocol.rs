//! Staged, visible, and durable compaction publication.
//!
//! The types deliberately prevent a caller from asking retention to delete a
//! source while a compaction is merely staged or merely visible.  A local
//! output layout is not a publication: only `fgit-chronicle`'s normal decision
//! publication makes the record visible, and the fabric's authenticated
//! retention registry decides deletion after durability is established.

use std::fmt;

use fgit_authority::{
    AuthorityStore, AuthorityVersionToken, HeadKey, OutcomeFailure, authority_head_identity,
};
use fgit_chronicle::{LostCandidate, PublicationVerdict, VerifiedPublication, publish};
use fgit_codec::{CodecRefusal, CryptoBodyIdentity};
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, PublicationState, RetentionRootProposal, StoreRefusal,
};
use fgit_types::{
    Digest, GenerationId, GitOid, PublicationEpoch, RepositoryAuthorityHeadId, TenantId,
};

use crate::record::{CompactionProfile, CompactionRecord, CompactionRefusal};

/// Evidence that every physical compaction output reached the staged epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputStageReceipt {
    states: Vec<PublicationState>,
}

impl OutputStageReceipt {
    /// Checks that the caller recorded one staged state for every physical
    /// output.  The constructor intentionally does not infer visibility or
    /// durability from object existence.
    pub fn new(states: Vec<PublicationState>) -> Result<Self, CompactionPublicationRefusal> {
        if states.is_empty() {
            return Err(CompactionPublicationRefusal::OutputReceiptCardinality);
        }
        if states
            .iter()
            .any(|state| !state.contains(PublicationEpoch::Staged))
        {
            return Err(CompactionPublicationRefusal::OutputNotStaged);
        }
        Ok(Self { states })
    }

    const fn len(&self) -> usize {
        self.states.len()
    }
}

/// A complete immutable output set that is not yet authority-visible.
#[must_use = "staged output is not canonical until an ordinary decision publishes it"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedCompaction {
    record: CompactionRecord,
    generation: GenerationId,
    compaction_generation_link: Digest,
    output_stage: OutputStageReceipt,
}

impl StagedCompaction {
    /// Stages a validated record after every output has reached the staged
    /// epoch.  The record identity is always calculated through the production
    /// codec/crypto bridge; callers cannot choose a local compaction ID.
    pub fn stage(
        record: CompactionRecord,
        output_stage: OutputStageReceipt,
    ) -> Result<Self, CompactionPublicationRefusal> {
        record
            .validate()
            .map_err(CompactionPublicationRefusal::Record)?;
        let expected_outputs = output_count(&record);
        if output_stage.len() != expected_outputs {
            return Err(CompactionPublicationRefusal::OutputReceiptCardinality);
        }
        let identity = CryptoBodyIdentity;
        let generation = record
            .generation_id(&identity)
            .map_err(CompactionPublicationRefusal::Codec)?;
        let compaction_generation_link = record
            .compaction_generation_link(&identity)
            .map_err(CompactionPublicationRefusal::Codec)?;
        Ok(Self {
            record,
            generation,
            compaction_generation_link,
            output_stage,
        })
    }

    /// The immutable compaction record.
    #[must_use]
    pub const fn record(&self) -> &CompactionRecord {
        &self.record
    }

    /// The typed identity of the staged generation.
    #[must_use]
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// The explicit batch linkage value that carries `generation`.
    #[must_use]
    pub const fn compaction_generation_link(&self) -> Digest {
        self.compaction_generation_link
    }

    /// Validates that an ordinary committed decision batch carries this exact
    /// compaction record, and returns the authority head that batch proposes.
    ///
    /// This runs before any CAS attempt.  A record not linked into the RCR and
    /// batch linkage cannot accidentally acquire visibility through an
    /// unrelated decision.
    pub fn validate_publication(
        &self,
        publication: &VerifiedPublication,
    ) -> Result<RepositoryAuthorityHeadId, CompactionPublicationRefusal> {
        if publication.is_refusal_only() {
            return Err(CompactionPublicationRefusal::RefusalOnlyPublication);
        }
        if publication.basis().id() != self.record.input_head
            || publication.basis().generation() != self.record.input_head_generation
        {
            return Err(CompactionPublicationRefusal::InputBasisMismatch);
        }
        if publication.batch().compaction_generation_link != Some(self.compaction_generation_link) {
            return Err(CompactionPublicationRefusal::CompactionGenerationLinkMismatch);
        }
        if !publication
            .batch()
            .committed_rcrs
            .iter()
            .any(|record| record.invariant_evidence_root == self.compaction_generation_link)
        {
            return Err(CompactionPublicationRefusal::RcrEvidenceLinkMissing);
        }
        authority_head_identity(publication.head())
            .map_err(|_| CompactionPublicationRefusal::SuccessorIdentityUnavailable)
    }

    /// Publishes through the normal decision-log authority protocol.
    ///
    /// A head race or duplicate leaves a [`UnpublishedCompaction`] holding the
    /// same staged output.  An authority error is explicitly indeterminate;
    /// it does not manufacture a non-commit conclusion after the CAS may have
    /// occurred.
    pub fn publish<S>(
        self,
        store: &S,
        head_key: &HeadKey,
        expected: AuthorityVersionToken,
        publication: &VerifiedPublication,
        tenant: TenantId,
    ) -> CompactionExecution
    where
        S: AuthorityStore + ?Sized,
    {
        let successor_head = match self.validate_publication(publication) {
            Ok(head) => head,
            Err(reason) => {
                return CompactionExecution::Unpublished(UnpublishedCompaction {
                    staged: self,
                    reason,
                });
            }
        };
        match publish(store, head_key, expected, publication, tenant) {
            Ok(PublicationVerdict::Published(receipt)) => {
                CompactionExecution::Visible(VisibleCompaction {
                    staged: self,
                    successor_head,
                    receipt,
                })
            }
            Ok(PublicationVerdict::Lost(candidate)) => {
                CompactionExecution::Unpublished(UnpublishedCompaction {
                    staged: self,
                    reason: CompactionPublicationRefusal::AuthorityRaceLost(candidate),
                })
            }
            Ok(PublicationVerdict::AlreadyDecided { .. }) => {
                CompactionExecution::Unpublished(UnpublishedCompaction {
                    staged: self,
                    reason: CompactionPublicationRefusal::AlreadyDecided,
                })
            }
            Err(failure) => CompactionExecution::Indeterminate(IndeterminateCompaction {
                staged: self,
                failure,
            }),
        }
    }
}

/// The only results an attempted compaction publication can report.
#[must_use = "a compaction publication must be driven to a visible, unpublished, or indeterminate outcome"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactionExecution {
    /// The ordinary authority decision made the generation visible.
    Visible(VisibleCompaction),
    /// Nothing was published through this attempt; the complete staged output
    /// remains available for inspection and, only when its refusal permits it,
    /// authenticated re-planning.
    Unpublished(UnpublishedCompaction),
    /// The store did not establish whether the CAS took effect.  The caller
    /// must resolve from the authenticated authority state, never delete source
    /// data or call this a failed compaction.
    Indeterminate(IndeterminateCompaction),
}

/// A known-noncanonical publication attempt retaining its staged output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpublishedCompaction {
    staged: StagedCompaction,
    reason: CompactionPublicationRefusal,
}

impl UnpublishedCompaction {
    /// Why no authority-visible generation was established by this attempt.
    #[must_use]
    pub const fn reason(&self) -> &CompactionPublicationRefusal {
        &self.reason
    }

    /// Recovers the staged output after the caller has acted on [`Self::reason`].
    ///
    /// A recovered output is not authority-visible and does not itself permit a
    /// re-plan. In particular, an
    /// [`CompactionPublicationRefusal::AuthorityRaceLost`] carrying
    /// [`LostCandidate::Superseded`] names terminal transactions that must not
    /// be re-decided.
    pub fn into_staged(self) -> StagedCompaction {
        self.staged
    }
}

/// An attempt whose authority outcome must be resolved, not guessed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndeterminateCompaction {
    staged: StagedCompaction,
    failure: OutcomeFailure,
}

impl IndeterminateCompaction {
    /// The authority failure that prevented a terminal local conclusion.
    #[must_use]
    pub const fn failure(&self) -> &OutcomeFailure {
        &self.failure
    }

    /// Recovers staged data without claiming it was not published.
    pub fn into_staged(self) -> StagedCompaction {
        self.staged
    }
}

/// A compaction generation that is visible because a normal decision batch was
/// selected by the authority-head CAS, but is not yet durable.
#[must_use = "a visible compaction is not deletion-safe until durability is established"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleCompaction {
    staged: StagedCompaction,
    successor_head: RepositoryAuthorityHeadId,
    receipt: Box<fgit_chronicle::CanonicalBatchReceipt>,
}

impl VisibleCompaction {
    /// The exact head selected by the normal authority path.
    #[must_use]
    pub const fn successor_head(&self) -> RepositoryAuthorityHeadId {
        self.successor_head
    }

    /// The typed identity of the visible compaction generation.
    #[must_use]
    pub const fn generation(&self) -> GenerationId {
        self.staged.generation
    }

    /// The exact compaction-generation link selected by this batch.
    #[must_use]
    pub const fn compaction_generation_link(&self) -> Digest {
        self.staged.compaction_generation_link
    }

    /// Receipt from the ordinary authority publication.
    #[must_use]
    pub const fn publication_receipt(&self) -> &fgit_chronicle::CanonicalBatchReceipt {
        &self.receipt
    }

    /// Confirms that every output is staged, visible, and durable under the
    /// selected profile.  The transition consumes `self`, so callers cannot
    /// obtain a durable-deletion capability from a merely visible generation.
    pub fn confirm_durability(
        &self,
        receipt: DurabilityReceipt,
    ) -> Result<DurableCompaction, DurabilityRefusal> {
        if receipt.generation != self.generation() {
            return Err(DurabilityRefusal::GenerationMismatch);
        }
        if receipt.profile != self.staged.record.profile {
            return Err(DurabilityRefusal::ProfileMismatch);
        }
        if receipt.states.len() != self.staged.output_stage.len() {
            return Err(DurabilityRefusal::OutputReceiptCardinality);
        }
        if receipt.states.iter().any(|state| {
            !state.contains(PublicationEpoch::Staged)
                || !state.contains(PublicationEpoch::Visible)
                || !state.contains(PublicationEpoch::Durable)
        }) {
            return Err(DurabilityRefusal::OutputNotDurable);
        }
        Ok(DurableCompaction {
            visible: self.clone(),
            durability_evidence_root: receipt.evidence_root,
        })
    }
}

/// Evidence that every output of one visible generation reached the selected
/// durability profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurabilityReceipt {
    generation: GenerationId,
    profile: CompactionProfile,
    states: Vec<PublicationState>,
    evidence_root: Digest,
}

impl DurabilityReceipt {
    /// Constructs a receipt to be supplied by the selected placement profile.
    #[must_use]
    pub const fn new(
        generation: GenerationId,
        profile: CompactionProfile,
        states: Vec<PublicationState>,
        evidence_root: Digest,
    ) -> Self {
        Self {
            generation,
            profile,
            states,
            evidence_root,
        }
    }
}

/// A compaction generation that is both authority-visible and durable.
#[must_use = "the deletion permit is explicit; inspect retention before executing any deletion"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableCompaction {
    visible: VisibleCompaction,
    durability_evidence_root: Digest,
}

impl DurableCompaction {
    /// The exact generation now selected and durable.
    #[must_use]
    pub const fn generation(&self) -> GenerationId {
        self.visible.generation()
    }

    /// Durability evidence for the selected physical profile.
    #[must_use]
    pub const fn durability_evidence_root(&self) -> Digest {
        self.durability_evidence_root
    }

    /// Consults the *authenticated* retention basis before allowing a source
    /// placement deletion.  A compaction index is intentionally not an input
    /// to this decision.
    pub fn authorize_source_deletion<R>(
        &self,
        retention: &R,
        proposal: &RetentionRootProposal,
        source: GitOid,
    ) -> Result<SourceDeletionPermit, RetentionRefusal>
    where
        R: AuthenticatedRetentionRegistry + ?Sized,
    {
        if !self.visible.staged.record.totality.contains_object(source) {
            return Err(RetentionRefusal::SourceNotInTotality);
        }
        if proposal.authority_head() != self.visible.successor_head {
            return Err(RetentionRefusal::AuthorityHeadMismatch);
        }
        retention
            .revalidate_root(proposal)
            .map_err(RetentionRefusal::Registry)?;
        retention
            .permits_placement_deletion(source)
            .map_err(RetentionRefusal::Registry)?;
        Ok(SourceDeletionPermit {
            source,
            generation: self.generation(),
        })
    }
}

/// Explicit capability produced only after durable compaction and an
/// authenticated-retention revalidation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceDeletionPermit {
    source: GitOid,
    generation: GenerationId,
}

impl SourceDeletionPermit {
    /// The source object this permit names.
    #[must_use]
    pub const fn source(&self) -> GitOid {
        self.source
    }

    /// The durable generation under which it was authorized.
    #[must_use]
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }
}

/// Why staging or visibility refused before a compaction became canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactionPublicationRefusal {
    /// The immutable record violates a local compaction invariant.
    Record(CompactionRefusal),
    /// One staged-state list did not name each physical output exactly once.
    OutputReceiptCardinality,
    /// A claimed staged output was not staged.
    OutputNotStaged,
    /// The ordinary publication was prepared from another authority head.
    InputBasisMismatch,
    /// The explicit batch link does not bind this compaction generation.
    CompactionGenerationLinkMismatch,
    /// No committed RCR in the batch references this compaction evidence.
    RcrEvidenceLinkMissing,
    /// Compaction must be an ordinary commit, never a refusal-only batch.
    RefusalOnlyPublication,
    /// The successor head could not be canonically identified before CAS.
    SuccessorIdentityUnavailable,
    /// Another authority publication won; staged output is still
    /// noncanonical. The authenticated classification preserves whether the
    /// candidate may be replanned or contains a transaction that is already
    /// terminal.
    AuthorityRaceLost(LostCandidate),
    /// The batch's transaction was already terminal; it must not be re-decided.
    AlreadyDecided,
    /// Canonical record encoding or identity computation refused.
    Codec(CodecRefusal),
}

impl fmt::Display for CompactionPublicationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(refusal) => write!(formatter, "compaction record refused: {refusal}"),
            Self::OutputReceiptCardinality => formatter
                .write_str("compaction output receipt does not cover each output exactly once"),
            Self::OutputNotStaged => {
                formatter.write_str("compaction output has not reached staged")
            }
            Self::InputBasisMismatch => {
                formatter.write_str("compaction publication does not use the record input head")
            }
            Self::CompactionGenerationLinkMismatch => {
                formatter.write_str("decision batch does not bind the compaction generation link")
            }
            Self::RcrEvidenceLinkMissing => {
                formatter.write_str("no committed RCR links the compaction generation evidence")
            }
            Self::RefusalOnlyPublication => {
                formatter.write_str("compaction cannot become visible through a refusal-only batch")
            }
            Self::SuccessorIdentityUnavailable => {
                formatter.write_str("compaction successor authority head could not be identified")
            }
            Self::AuthorityRaceLost(LostCandidate::Replannable) => {
                formatter.write_str("compaction authority publication lost a replannable race")
            }
            Self::AuthorityRaceLost(LostCandidate::Superseded { decided }) => {
                write!(
                    formatter,
                    "compaction authority publication lost its race after {} transaction(s) became terminal",
                    decided.len()
                )
            }
            Self::AlreadyDecided => {
                formatter.write_str("compaction publication transaction was already terminal")
            }
            Self::Codec(refusal) => write!(formatter, "compaction codec refused: {refusal}"),
        }
    }
}

impl std::error::Error for CompactionPublicationRefusal {}

/// Why a visible compaction may not become durable yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurabilityRefusal {
    /// The receipt belongs to another compaction generation.
    GenerationMismatch,
    /// The receipt names a profile other than the record's selection.
    ProfileMismatch,
    /// The receipt does not cover every physical output.
    OutputReceiptCardinality,
    /// At least one output lacks a staged, visible, or durable epoch.
    OutputNotDurable,
}

impl fmt::Display for DurabilityRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerationMismatch => {
                formatter.write_str("durability receipt names another generation")
            }
            Self::ProfileMismatch => {
                formatter.write_str("durability receipt names another profile")
            }
            Self::OutputReceiptCardinality => {
                formatter.write_str("durability receipt does not cover every output")
            }
            Self::OutputNotDurable => {
                formatter.write_str("at least one compaction output is not durable")
            }
        }
    }
}

impl std::error::Error for DurabilityRefusal {}

/// Why authenticated retention did not yield a source-deletion permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetentionRefusal {
    /// The caller requested deletion of an object absent from the totality map.
    SourceNotInTotality,
    /// The retention proposal names a head other than the compacted successor.
    AuthorityHeadMismatch,
    /// The authority-owned retention registry refused the current basis.
    Registry(StoreRefusal),
}

impl fmt::Display for RetentionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceNotInTotality => {
                formatter.write_str("source object is absent from the compaction totality map")
            }
            Self::AuthorityHeadMismatch => formatter
                .write_str("retention proposal is not bound to the compaction successor head"),
            Self::Registry(refusal) => {
                write!(formatter, "authenticated retention refused: {refusal}")
            }
        }
    }
}

impl std::error::Error for RetentionRefusal {}

const fn output_count(record: &CompactionRecord) -> usize {
    record.outputs.pack_roots.len()
        + record.outputs.segment_manifests.len()
        + record.outputs.index_roots.len()
}
