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
    AuthenticatedHead, AuthorityVersionToken, HeadBodyRefusal, OutcomeFailure,
    authority_head_identity,
};
use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{
    Digest, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId,
    RepositoryCommitId, RepositoryDecisionBatchId, RepositoryId, RepositorySequence,
};

use crate::capability::LogicalTime;
use crate::classes::ClassSet;

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
    /// a backend ETag or a decoded but unverified body from masquerading as the
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
    pub fn new(
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
