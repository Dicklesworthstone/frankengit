//! The authenticated base and retrieval boundary of the Agent Protocol.
//!
//! `IntentRun` used to carry only an [`AuthorityBasisRef`](crate::AuthorityBasisRef):
//! a four-field identifier that deliberately was not an authority receipt.  A
//! caller could consequently prove which generation it meant without proving
//! the complete repository state it was allowed to use.  This module makes the
//! real boundary explicit. [`AuthorityReadReceipt`] is built only from an
//! [`fgit_authority::AuthenticatedHead`], which has already been checked by the
//! authority backend and whose body is generation-checked before its fields
//! are exposed here.
//!
//! [`ContextPacket`] then binds every source to that exact receipt. Control
//! metadata and repository-derived source bytes use different Rust types and
//! different accessors; no source byte can occupy a control field. This slice
//! supports one exact authority generation per packet. A cross-generation join
//! needs its own named join receipt and is refused here rather than being
//! silently flattened into a prompt.

use core::fmt;

use fgit_authority::{
    AuthenticatedHead, AuthorityVersionToken, ExpectedOld, HeadBodyRefusal, IdempotencyKey,
    OutcomeFailure, ProposedNew, RECEIVE_ADMISSION_SCHEMA, RefCommand, RequestRefusal, SealAttempt,
    SemanticRequest, authority_head_identity,
};
use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, NativeObjectIdentity, Sha256};
use fgit_treefs::{ExpectedRef, ProposedTransaction, WorkspaceId, WorkspaceSnapshotBody};
use fgit_types::{
    Digest, HeadGeneration, PolicyEpoch, PrincipalId, RefName, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId, RepositoryId,
    RepositorySequence, TenantId, TypeRefusal,
};

use crate::capability::LogicalTime;
use crate::classes::ClassSet;
use crate::intent::{IntentRun, RunId};

/// Maximum source entries in one context packet.
pub const MAX_CONTEXT_SOURCES: usize = 1_024;
/// Maximum retained source bytes in one entry.
pub const MAX_CONTEXT_SOURCE_BYTES: usize = 1 << 20;
/// Maximum retained source bytes across one packet.
pub const MAX_CONTEXT_TOTAL_BYTES: usize = 8 << 20;

/// A complete §4.1 authenticated authority read.
///
/// The backend version token remains opaque. It is preserved for the ordinary
/// conditional publication path but never interpreted as a generation or as a
/// content digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityReadReceipt {
    repository_id: RepositoryId,
    authority_head_id: RepositoryAuthorityHeadId,
    authority_head_generation: HeadGeneration,
    backend_version_token: AuthorityVersionToken,
    latest_decision_batch_id: Option<RepositoryDecisionBatchId>,
    latest_repository_sequence: Option<RepositorySequence>,
    latest_repository_commit_id: Option<RepositoryCommitId>,
    ref_root: Digest,
    forge_position_root: Digest,
    retention_root: Digest,
    policy_epoch: PolicyEpoch,
    format_epoch: RegistryEpoch,
    verified_at_logical_time: LogicalTime,
    verifier_profile: [u8; 32],
}

impl AuthorityReadReceipt {
    /// Builds the §4.1 receipt from a store-authenticated, generation-checked
    /// authority head.
    ///
    /// The caller cannot supply a body, token, or head identity independently:
    /// all three are taken from the authenticated authority result. This keeps
    /// a backend `ETag` or a decoded but unverified body from masquerading as the
    /// agent's canonical base.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when the authenticated bytes do not decode as
    /// an authority head, when their encoded generation disagrees with the
    /// receipt generation, or when the body cannot re-identify itself.
    pub fn from_authenticated_head(
        authenticated: &AuthenticatedHead,
        verified_at_logical_time: LogicalTime,
        verifier_profile: [u8; 32],
    ) -> Result<Self, ProtocolRefusal> {
        let body = authenticated
            .body()
            .map_err(ProtocolRefusal::AuthorityHeadBody)?;
        let authority_head_id =
            authority_head_identity(&body).map_err(ProtocolRefusal::AuthorityHeadIdentity)?;
        let receipt = authenticated.receipt();

        Ok(Self {
            repository_id: body.repository_id,
            authority_head_id,
            authority_head_generation: receipt.generation(),
            backend_version_token: receipt.token(),
            latest_decision_batch_id: body.decision_tail_id,
            latest_repository_sequence: body.latest_repository_sequence,
            latest_repository_commit_id: body.latest_committed_rcr_id,
            ref_root: body.ref_root,
            forge_position_root: body.forge_position_root,
            retention_root: body.retention_root,
            policy_epoch: body.policy_epoch,
            format_epoch: body.format_registry_epoch,
            verified_at_logical_time,
            verifier_profile,
        })
    }

    /// Repository governed by this receipt.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Authenticated authority-head identity.
    #[must_use]
    pub const fn authority_head_id(&self) -> RepositoryAuthorityHeadId {
        self.authority_head_id
    }

    /// Authenticated authority-head generation.
    #[must_use]
    pub const fn authority_head_generation(&self) -> HeadGeneration {
        self.authority_head_generation
    }

    /// Opaque conditional-write token issued by the backend.
    #[must_use]
    pub const fn backend_version_token(&self) -> AuthorityVersionToken {
        self.backend_version_token
    }

    /// Latest decision batch, if the repository has one.
    #[must_use]
    pub const fn latest_decision_batch_id(&self) -> Option<RepositoryDecisionBatchId> {
        self.latest_decision_batch_id
    }

    /// Latest repository sequence, if a commit exists.
    #[must_use]
    pub const fn latest_repository_sequence(&self) -> Option<RepositorySequence> {
        self.latest_repository_sequence
    }

    /// Latest committed RCR, if a commit exists.
    #[must_use]
    pub const fn latest_repository_commit_id(&self) -> Option<RepositoryCommitId> {
        self.latest_repository_commit_id
    }

    /// Authenticated ref-state root.
    #[must_use]
    pub const fn ref_root(&self) -> Digest {
        self.ref_root
    }

    /// Authenticated forge-position root.
    #[must_use]
    pub const fn forge_position_root(&self) -> Digest {
        self.forge_position_root
    }

    /// Authenticated retention root.
    #[must_use]
    pub const fn retention_root(&self) -> Digest {
        self.retention_root
    }

    /// Policy epoch under which this base was read.
    #[must_use]
    pub const fn policy_epoch(&self) -> PolicyEpoch {
        self.policy_epoch
    }

    /// Format/algorithm registry epoch under which this base was read.
    #[must_use]
    pub const fn format_epoch(&self) -> RegistryEpoch {
        self.format_epoch
    }

    /// Logical time at which authentication completed.
    #[must_use]
    pub const fn verified_at_logical_time(&self) -> LogicalTime {
        self.verified_at_logical_time
    }

    /// Identity of the verifier profile that performed the authenticated read.
    #[must_use]
    pub const fn verifier_profile(&self) -> [u8; 32] {
        self.verifier_profile
    }
}

/// A retrieval channel for visibly untrusted source material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RetrievalChannel {
    /// Exact immutable object or forge content.
    Exact,
    /// Lexical retrieval.
    Lexical,
    /// Symbol-derived retrieval.
    Symbol,
    /// Structural retrieval.
    Structural,
    /// Semantic retrieval.
    Semantic,
    /// Graph-derived retrieval.
    Graph,
    /// History-derived retrieval.
    History,
    /// Ownership-derived retrieval.
    Ownership,
    /// Test-derived retrieval.
    Test,
    /// Policy-derived retrieval.
    Policy,
}

impl RetrievalChannel {
    const fn code_point(self) -> u8 {
        match self {
            Self::Exact => 1,
            Self::Lexical => 2,
            Self::Symbol => 3,
            Self::Structural => 4,
            Self::Semantic => 5,
            Self::Graph => 6,
            Self::History => 7,
            Self::Ownership => 8,
            Self::Test => 9,
            Self::Policy => 10,
        }
    }
}

/// One provenance-labelled, untrusted source entry.
///
/// Source bytes are intentionally private and are reachable only through
/// [`Self::untrusted_bytes`]. The control plane has no setter that accepts
/// source bytes, so a repository file cannot become an instruction, a
/// capability, or a publication policy by field confusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextSource {
    identity_commitment: [u8; 32],
    channel: RetrievalChannel,
    untrusted_bytes: Vec<u8>,
}

impl ContextSource {
    /// Admits one bounded source body.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolRefusal::SourceTooLarge`] before the packet retains
    /// the body when the per-source hard ceiling would be exceeded.
    pub fn new(
        identity_commitment: [u8; 32],
        channel: RetrievalChannel,
        untrusted_bytes: Vec<u8>,
    ) -> Result<Self, ProtocolRefusal> {
        if untrusted_bytes.len() > MAX_CONTEXT_SOURCE_BYTES {
            return Err(ProtocolRefusal::SourceTooLarge {
                observed: untrusted_bytes.len(),
                limit: MAX_CONTEXT_SOURCE_BYTES,
            });
        }
        Ok(Self {
            identity_commitment,
            channel,
            untrusted_bytes,
        })
    }

    /// Immutable identity commitment of the source object/span.
    #[must_use]
    pub const fn identity_commitment(&self) -> [u8; 32] {
        self.identity_commitment
    }

    /// Retrieval channel that produced this source.
    #[must_use]
    pub const fn channel(&self) -> RetrievalChannel {
        self.channel
    }

    /// Repository-derived data, never authenticated control metadata.
    #[must_use]
    pub fn untrusted_bytes(&self) -> &[u8] {
        &self.untrusted_bytes
    }
}

/// Bounded control metadata for one context packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextControl {
    request_intent_commitment: [u8; 32],
    authorization_scope: ClassSet,
    ranking_and_fusion_identity: [u8; 32],
    coverage_claims: Vec<[u8; 32]>,
    omission_commitments: Vec<[u8; 32]>,
}

impl ContextControl {
    /// Builds control metadata without accepting repository-derived source
    /// bytes. Coverage and omission commitments remain visible even when no
    /// source body is retained.
    #[must_use]
    pub const fn new(
        request_intent_commitment: [u8; 32],
        authorization_scope: ClassSet,
        ranking_and_fusion_identity: [u8; 32],
        coverage_claims: Vec<[u8; 32]>,
        omission_commitments: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            request_intent_commitment,
            authorization_scope,
            ranking_and_fusion_identity,
            coverage_claims,
            omission_commitments,
        }
    }

    /// Canonical request identity the retrieval was for.
    #[must_use]
    pub const fn request_intent_commitment(&self) -> [u8; 32] {
        self.request_intent_commitment
    }

    /// Machine-enforced retrieval authorization scope.
    #[must_use]
    pub const fn authorization_scope(&self) -> ClassSet {
        self.authorization_scope
    }

    /// Identity of the ranking/fusion implementation and profile.
    #[must_use]
    pub const fn ranking_and_fusion_identity(&self) -> [u8; 32] {
        self.ranking_and_fusion_identity
    }

    /// Typed coverage claims, represented by immutable commitments.
    #[must_use]
    pub fn coverage_claims(&self) -> &[[u8; 32]] {
        &self.coverage_claims
    }

    /// Deliberate and budget-induced omissions, represented by commitments.
    #[must_use]
    pub fn omission_commitments(&self) -> &[[u8; 32]] {
        &self.omission_commitments
    }
}

/// Stable identity of one context packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ContextPacketId([u8; 32]);

impl ContextPacketId {
    /// Raw SHA-256 commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A bounded context packet pinned to exactly one authenticated authority read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextPacket {
    packet_id: ContextPacketId,
    authority_read_receipt: AuthorityReadReceipt,
    control: ContextControl,
    sources: Vec<ContextSource>,
}

/// A `TreeFS` workspace manifest bound to the exact authenticated base used by
/// the agent run.
///
/// The wrapped snapshot is the real `fgit-treefs` immutable body, not a second
/// agent-owned workspace record. Binding refuses a repository mismatch, a
/// different base RCR, or a receipt that has no committed RCR to pin. The
/// snapshot retains its own staged/visible/durable epochs; this type exposes
/// their digest without conflating any of those epochs with canonical
/// repository publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceBinding<A: GitHashAlgorithm> {
    run: IntentRun,
    authority_read_receipt: AuthorityReadReceipt,
    snapshot: WorkspaceSnapshotBody<A>,
    manifest_commitment: [u8; 32],
}

impl<A: GitHashAlgorithm> WorkspaceBinding<A> {
    /// Binds one immutable `TreeFS` snapshot to the authenticated run and
    /// authority receipt that supplied its base.
    ///
    /// # Errors
    ///
    /// Refuses a legacy run lacking a complete receipt, a run without
    /// `TreeFsWorkspace` authority, a workspace over another repository, a
    /// workspace whose base RCR differs from the receipt, or a receipt before
    /// the first committed RCR. The latter is not silently replaced by an
    /// authority-head generation: `TreeFS` names a base RCR and the two are
    /// distinct protocol positions.
    pub fn bind(
        run: IntentRun,
        snapshot: WorkspaceSnapshotBody<A>,
    ) -> Result<Self, ProtocolRefusal> {
        let authority_read_receipt = run
            .authority_read_receipt()
            .ok_or(ProtocolRefusal::RunAuthorityReceiptRequired)?
            .clone();
        if !run
            .allowed_operation_classes()
            .contains(crate::OperationClass::TreeFsWorkspace)
        {
            return Err(ProtocolRefusal::WorkspaceOperationOutsideRun);
        }
        if snapshot.repository_id() != authority_read_receipt.repository_id() {
            return Err(ProtocolRefusal::WorkspaceRepositoryMismatch);
        }
        let expected_base = authority_read_receipt
            .latest_repository_commit_id()
            .ok_or(ProtocolRefusal::WorkspaceBaseMissing)?;
        if snapshot.base_rcr_id() != expected_base {
            return Err(ProtocolRefusal::WorkspaceBaseMismatch {
                expected: Box::new(expected_base),
                observed: Box::new(snapshot.base_rcr_id()),
            });
        }
        if !snapshot.epochs().invariant_holds() {
            return Err(ProtocolRefusal::WorkspaceEpochInvariant);
        }
        let manifest_commitment = snapshot.snapshot_digest().map_err(ProtocolRefusal::Codec)?;
        Ok(Self {
            run,
            authority_read_receipt,
            snapshot,
            manifest_commitment,
        })
    }

    /// The exact authenticated base of the workspace.
    #[must_use]
    pub const fn authority_read_receipt(&self) -> &AuthorityReadReceipt {
        &self.authority_read_receipt
    }

    /// Exact run that authorized this `TreeFS` workspace.
    #[must_use]
    pub const fn run(&self) -> &IntentRun {
        &self.run
    }

    /// The immutable `TreeFS` snapshot this binding authenticated.
    #[must_use]
    pub const fn snapshot(&self) -> &WorkspaceSnapshotBody<A> {
        &self.snapshot
    }

    /// The workspace identity assigned by `TreeFS`.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.snapshot.workspace_id()
    }

    /// Commitment of the immutable `TreeFS` manifest body.
    #[must_use]
    pub const fn manifest_commitment(&self) -> [u8; 32] {
        self.manifest_commitment
    }

    /// Converts a real `TreeFS` proposal into the ordinary sealed-ref-transaction
    /// request shape.
    ///
    /// This method deliberately has no authority-head mutation API. It proves
    /// that the agent path uses the same canonical request and seal as every
    /// other mutation; only the existing admission/authority path can turn the
    /// resulting seal into a terminal decision and successful head CAS.
    ///
    /// # Errors
    ///
    /// Refuses a packet from another authority position, a proposal from
    /// another `TreeFS` workspace or base RCR, and a run that lacks
    /// `PreparePublication` authority.
    pub fn prepare_ref_transaction(
        &self,
        proposal: ProposedTransaction<A>,
        context_packets: &[ContextPacket],
    ) -> Result<AgentRefTransaction<A>, ProtocolRefusal> {
        if !self
            .run
            .allowed_operation_classes()
            .contains(crate::OperationClass::PreparePublication)
        {
            return Err(ProtocolRefusal::PublicationOperationOutsideRun);
        }
        if proposal.workspace_id() != self.workspace_id() {
            return Err(ProtocolRefusal::ProposalWorkspaceMismatch);
        }
        if proposal.receipt().repository_id != self.authority_read_receipt.repository_id() {
            return Err(ProtocolRefusal::ProposalRepositoryMismatch);
        }
        if proposal.receipt().base_rcr_id != self.snapshot.base_rcr_id() {
            return Err(ProtocolRefusal::ProposalBaseMismatch {
                expected: Box::new(self.snapshot.base_rcr_id()),
                observed: Box::new(proposal.receipt().base_rcr_id),
            });
        }
        for packet in context_packets {
            if packet.authority_read_receipt() != &self.authority_read_receipt {
                return Err(ProtocolRefusal::ContextAuthorityMismatch);
            }
        }

        let semantic_request = semantic_request_for_proposal::<A>(&proposal)?;
        Ok(AgentRefTransaction {
            run: self.run.clone(),
            authority_read_receipt: self.authority_read_receipt.clone(),
            workspace_manifest_commitment: self.manifest_commitment,
            context_packet_ids: context_packets
                .iter()
                .map(ContextPacket::packet_id)
                .collect(),
            proposal,
            semantic_request,
        })
    }
}

/// An agent proposal in the same sealed transaction universe as non-agent
/// mutations.
///
/// It contains a real `TreeFS` proposal and the canonical authority request it
/// became. It is not a terminal outcome and it has no API for moving an
/// authority head. [`Self::seal_attempt`] produces only the ordinary input to
/// the authority seal path. The agent does not own the effectful call: an
/// `EffectBroker` grant and its lifecycle ledger must authorize and record that
/// call before an executor submits this attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRefTransaction<A: GitHashAlgorithm> {
    run: IntentRun,
    authority_read_receipt: AuthorityReadReceipt,
    workspace_manifest_commitment: [u8; 32],
    context_packet_ids: Vec<ContextPacketId>,
    proposal: ProposedTransaction<A>,
    semantic_request: SemanticRequest,
}

impl<A: GitHashAlgorithm> AgentRefTransaction<A> {
    /// Intent run that authorized the request.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run.run_id()
    }

    /// Exact run whose machine scope authorized this preparation.
    #[must_use]
    pub const fn run(&self) -> &IntentRun {
        &self.run
    }

    /// Exact authenticated authority basis.
    #[must_use]
    pub const fn authority_read_receipt(&self) -> &AuthorityReadReceipt {
        &self.authority_read_receipt
    }

    /// `TreeFS` manifest commitment from which the request was derived.
    #[must_use]
    pub const fn workspace_manifest_commitment(&self) -> [u8; 32] {
        self.workspace_manifest_commitment
    }

    /// Context packets that supplied agent evidence for this proposed effect.
    ///
    /// These remain outside [`SemanticRequest`]: request provenance cannot
    /// split the one canonical transaction identity for the same ref command.
    #[must_use]
    pub fn context_packet_ids(&self) -> &[ContextPacketId] {
        &self.context_packet_ids
    }

    /// The inert `TreeFS` proposal, which cannot assert a commit outcome.
    #[must_use]
    pub const fn proposal(&self) -> &ProposedTransaction<A> {
        &self.proposal
    }

    /// The ordinary canonical request that authority sealing receives.
    ///
    /// Its schema and ref-command lowering are exactly the shared
    /// receive-admission form. Agent provenance remains in this wrapper rather
    /// than changing a ref mutation's transaction identity.
    #[must_use]
    pub const fn semantic_request(&self) -> &SemanticRequest {
        &self.semantic_request
    }

    /// Produces the ordinary authority seal attempt for this prepared request.
    ///
    /// This does not write anything. The attempt is intentionally handed to
    /// the effect executor instead of calling `fgit_authority::seal_request`
    /// here: §9 requires the executor to possess a broker grant, reserve its
    /// obligation, and record/reconcile the effect lifecycle. The follow-on
    /// ledger slice owns that effectful boundary.
    #[must_use]
    pub fn seal_attempt(
        &self,
        tenant_id: TenantId,
        authenticated_principal_id: PrincipalId,
        idempotency_key: IdempotencyKey,
    ) -> SealAttempt {
        SealAttempt {
            tenant_id,
            repository_id: self.authority_read_receipt.repository_id(),
            authenticated_principal_id,
            idempotency_key,
            request: self.semantic_request.clone(),
        }
    }
}

impl ContextPacket {
    /// Builds a single-generation context packet.
    ///
    /// The packet itself is the source-generation set: every source is pinned
    /// to `authority_read_receipt`, so a caller cannot combine old and new
    /// source bodies without a dedicated cross-generation join implementation.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal before retaining the source vector when count
    /// or aggregate source-byte bounds would be exceeded.
    pub fn build(
        authority_read_receipt: AuthorityReadReceipt,
        control: ContextControl,
        sources: Vec<ContextSource>,
    ) -> Result<Self, ProtocolRefusal> {
        if sources.len() > MAX_CONTEXT_SOURCES {
            return Err(ProtocolRefusal::TooManySources {
                observed: sources.len(),
                limit: MAX_CONTEXT_SOURCES,
            });
        }

        let mut total_source_bytes = 0_usize;
        for source in &sources {
            total_source_bytes = total_source_bytes
                .checked_add(source.untrusted_bytes.len())
                .ok_or(ProtocolRefusal::TotalSourceBytesExceeded {
                    observed: usize::MAX,
                    limit: MAX_CONTEXT_TOTAL_BYTES,
                })?;
            if total_source_bytes > MAX_CONTEXT_TOTAL_BYTES {
                return Err(ProtocolRefusal::TotalSourceBytesExceeded {
                    observed: total_source_bytes,
                    limit: MAX_CONTEXT_TOTAL_BYTES,
                });
            }
        }

        let packet_id = ContextPacketId(packet_commitment(
            &authority_read_receipt,
            &control,
            &sources,
        )?);
        Ok(Self {
            packet_id,
            authority_read_receipt,
            control,
            sources,
        })
    }

    /// Stable packet commitment over the receipt, control metadata, and
    /// visibly separate source entries.
    #[must_use]
    pub const fn packet_id(&self) -> ContextPacketId {
        self.packet_id
    }

    /// The one authenticated authority position all packet material uses.
    #[must_use]
    pub const fn authority_read_receipt(&self) -> &AuthorityReadReceipt {
        &self.authority_read_receipt
    }

    /// Authenticated control metadata only.
    #[must_use]
    pub const fn control(&self) -> &ContextControl {
        &self.control
    }

    /// Provenance-labelled, visibly untrusted source entries.
    #[must_use]
    pub fn sources(&self) -> &[ContextSource] {
        &self.sources
    }
}

/// Why a protocol boundary refused its input.
#[derive(Debug)]
pub enum ProtocolRefusal {
    /// An authenticated receipt did not carry a valid, generation-matched head body.
    AuthorityHeadBody(HeadBodyRefusal),
    /// The authority head could not reproduce its claimed identity.
    AuthorityHeadIdentity(OutcomeFailure),
    /// One source body exceeds the bounded per-entry profile.
    SourceTooLarge {
        /// Source bytes offered.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Too many source entries were offered.
    TooManySources {
        /// Source entries offered.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Total source bytes exceed the packet profile.
    TotalSourceBytesExceeded {
        /// Source bytes offered.
        observed: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// The `TreeFS` snapshot names another repository.
    WorkspaceRepositoryMismatch,
    /// The authenticated authority receipt has no committed RCR to pin a
    /// workspace base.
    WorkspaceBaseMissing,
    /// The snapshot names a different base RCR from its authority receipt.
    WorkspaceBaseMismatch {
        /// RCR named by the authenticated authority receipt.
        expected: Box<RepositoryCommitId>,
        /// RCR named by the `TreeFS` snapshot.
        observed: Box<RepositoryCommitId>,
    },
    /// The `TreeFS` snapshot violated its staged/visible/durable invariant.
    WorkspaceEpochInvariant,
    /// The run does not authorize `TreeFS` workspace creation or use.
    WorkspaceOperationOutsideRun,
    /// A legacy run supplied an identifying reference rather than a complete
    /// authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// The run does not authorize publication preparation.
    PublicationOperationOutsideRun,
    /// The proposal came from another `TreeFS` workspace.
    ProposalWorkspaceMismatch,
    /// The proposal targets another repository.
    ProposalRepositoryMismatch,
    /// The proposal was based on another committed repository record.
    ProposalBaseMismatch {
        /// RCR named by the bound workspace.
        expected: Box<RepositoryCommitId>,
        /// RCR named by the proposal receipt.
        observed: Box<RepositoryCommitId>,
    },
    /// A context packet belongs to a different authority position.
    ContextAuthorityMismatch,
    /// A shared identity type rejected a proposed ref name.
    Type(TypeRefusal),
    /// The authority request surface refused a bounded or ambiguous request.
    Request(RequestRefusal),
    /// Canonical packet framing could not represent a bounded field.
    Codec(CodecRefusal),
}

impl fmt::Display for ProtocolRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorityHeadBody(refusal) => {
                write!(formatter, "authority head refused: {refusal}")
            }
            Self::AuthorityHeadIdentity(refusal) => {
                write!(formatter, "authority head identity refused: {refusal}")
            }
            Self::SourceTooLarge { observed, limit } => {
                write!(
                    formatter,
                    "context source has {observed} bytes, limit {limit}"
                )
            }
            Self::TooManySources { observed, limit } => {
                write!(
                    formatter,
                    "context packet has {observed} sources, limit {limit}"
                )
            }
            Self::TotalSourceBytesExceeded { observed, limit } => write!(
                formatter,
                "context packet retains {observed} source bytes, limit {limit}"
            ),
            Self::WorkspaceRepositoryMismatch => {
                formatter.write_str("TreeFS snapshot repository differs from authority receipt")
            }
            Self::WorkspaceBaseMissing => formatter.write_str(
                "authority receipt has no committed RCR; it cannot pin a TreeFS workspace base",
            ),
            Self::WorkspaceBaseMismatch { expected, observed } => write!(
                formatter,
                "TreeFS snapshot base RCR {observed} differs from authority receipt {expected}"
            ),
            Self::WorkspaceEpochInvariant => {
                formatter.write_str("TreeFS snapshot violates staged >= visible >= durable")
            }
            Self::WorkspaceOperationOutsideRun => formatter.write_str(
                "intent run does not authorize TreeFS workspace creation or use",
            ),
            Self::RunAuthorityReceiptRequired => formatter.write_str(
                "publication preparation requires a run with a complete authenticated authority receipt",
            ),
            Self::PublicationOperationOutsideRun => formatter.write_str(
                "intent run does not authorize publication preparation",
            ),
            Self::ProposalWorkspaceMismatch => formatter.write_str(
                "TreeFS proposal belongs to another workspace",
            ),
            Self::ProposalRepositoryMismatch => formatter.write_str(
                "TreeFS proposal targets another repository",
            ),
            Self::ProposalBaseMismatch { expected, observed } => write!(
                formatter,
                "TreeFS proposal base RCR {observed} differs from bound workspace {expected}"
            ),
            Self::ContextAuthorityMismatch => formatter.write_str(
                "context packet authority receipt differs from the bound workspace",
            ),
            Self::Type(refusal) => write!(formatter, "agent protocol type refusal: {refusal}"),
            Self::Request(refusal) => {
                write!(formatter, "ordinary ref request refused: {refusal}")
            }
            Self::Codec(refusal) => write!(formatter, "context packet codec refusal: {refusal}"),
        }
    }
}

impl core::error::Error for ProtocolRefusal {}

impl From<CodecRefusal> for ProtocolRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

impl From<TypeRefusal> for ProtocolRefusal {
    fn from(value: TypeRefusal) -> Self {
        Self::Type(value)
    }
}

impl From<RequestRefusal> for ProtocolRefusal {
    fn from(value: RequestRefusal) -> Self {
        Self::Request(value)
    }
}

fn semantic_request_for_proposal<A: GitHashAlgorithm>(
    proposal: &ProposedTransaction<A>,
) -> Result<SemanticRequest, ProtocolRefusal> {
    let ref_commands = proposal
        .ref_intents()
        .iter()
        .map(|intent| {
            let expected_old = match intent.expected {
                ExpectedRef::Absent => ExpectedOld::Absent,
                ExpectedRef::Exactly { oid } => ExpectedOld::Exactly(oid.erase()),
            };
            Ok(RefCommand {
                name: RefName::try_new(&intent.name)?,
                expected_old,
                proposed_new: ProposedNew::Update(intent.new.erase()),
                force: false,
            })
        })
        .collect::<Result<Vec<_>, ProtocolRefusal>>()?;

    SemanticRequest::build(
        RECEIVE_ADMISSION_SCHEMA,
        A::OBJECT_FORMAT,
        true,
        ref_commands,
        Vec::new(),
        Vec::new(),
    )
    .map_err(ProtocolRefusal::Request)
}

fn packet_commitment(
    receipt: &AuthorityReadReceipt,
    control: &ContextControl,
    sources: &[ContextSource],
) -> Result<[u8; 32], ProtocolRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes(
        "context_packet_domain",
        b"frankengit.agent.context-packet/v1\0",
    )?;
    encoder.write_opaque_id(receipt.repository_id.as_bytes());
    encoder.write_internal_object_id(receipt.authority_head_id.as_internal_object_id())?;
    encoder.write_scalar(receipt.authority_head_generation.get());
    encoder.write_raw(&receipt.backend_version_token.to_opaque_bytes());
    write_optional_identity(
        &mut encoder,
        receipt
            .latest_decision_batch_id
            .as_ref()
            .map(RepositoryDecisionBatchId::as_internal_object_id),
    )?;
    write_optional_scalar(
        &mut encoder,
        receipt
            .latest_repository_sequence
            .map(RepositorySequence::get),
    );
    write_optional_identity(
        &mut encoder,
        receipt
            .latest_repository_commit_id
            .as_ref()
            .map(RepositoryCommitId::as_internal_object_id),
    )?;
    encoder.write_digest(&receipt.ref_root)?;
    encoder.write_digest(&receipt.forge_position_root)?;
    encoder.write_digest(&receipt.retention_root)?;
    encoder.write_scalar(receipt.policy_epoch.get());
    encoder.write_scalar(receipt.format_epoch.get());
    encoder.write_scalar(receipt.verified_at_logical_time.value());
    encoder.write_raw(&receipt.verifier_profile);
    encoder.write_raw(&control.request_intent_commitment);
    encoder.write_scalar(control.authorization_scope.bits());
    encoder.write_raw(&control.ranking_and_fusion_identity);
    write_commitments(&mut encoder, "coverage_claims", &control.coverage_claims)?;
    write_commitments(
        &mut encoder,
        "omission_commitments",
        &control.omission_commitments,
    )?;
    write_count(&mut encoder, "context_sources", sources.len())?;
    for source in sources {
        encoder.write_raw(&source.identity_commitment);
        encoder.write_raw_byte(source.channel.code_point());
        encoder.write_bytes("context_source_bytes", &source.untrusted_bytes)?;
    }

    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_optional_identity(
    encoder: &mut Encoder,
    value: Option<&fgit_types::InternalObjectId>,
) -> Result<(), CodecRefusal> {
    match value {
        Some(identity) => {
            encoder.write_bool(true);
            encoder.write_internal_object_id(identity)?;
        }
        None => encoder.write_bool(false),
    }
    Ok(())
}

fn write_optional_scalar(encoder: &mut Encoder, value: Option<u64>) {
    match value {
        Some(value) => {
            encoder.write_bool(true);
            encoder.write_scalar(value);
        }
        None => encoder.write_bool(false),
    }
}

fn write_commitments(
    encoder: &mut Encoder,
    field: &'static str,
    commitments: &[[u8; 32]],
) -> Result<(), CodecRefusal> {
    write_count(encoder, field, commitments.len())?;
    for commitment in commitments {
        encoder.write_raw(commitment);
    }
    Ok(())
}

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), CodecRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}
