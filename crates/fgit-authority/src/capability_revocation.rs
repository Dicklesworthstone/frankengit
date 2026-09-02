//! Canonical capability-revocation generations selected by repository authority.
//!
//! Capability revocation is policy state, not a mutable local deny list.  The
//! authority head already commits the exact [`PolicyEpoch`] and
//! `configuration_root` under which a request is interpreted.  This module
//! turns that authenticated tuple into one deterministic immutable selector:
//!
//! ```text
//! (repository_id, policy_epoch, configuration_root)
//!     -> CapabilityRevocationGenerationBody
//! ```
//!
//! The body is also stored under its ordinary content-addressed
//! [`GenerationId`] key.  A read succeeds only when the selected bytes decode,
//! name the exact authenticated tuple, re-identify canonically, and agree
//! byte-for-byte with the content-addressed copy.  A local cache, listing, or
//! caller-supplied set never decides revocation.
//!
//! Staging is deliberately not publication.  The generation and selector are
//! immutable candidate bodies until an ordinary repository authority-head
//! transition selects their tuple.  A migration introducing this vocabulary
//! must stage the generation before publishing a new policy epoch or
//! configuration root; filling a selector behind an already advertised head is
//! not revision-bound publication evidence.

use core::fmt;

use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Decoder, Encoder, body_id,
    decode_body, encode_body,
};
use fgit_types::{
    Digest, GenerationId, PolicyEpoch, RepositoryId, SchemaFamily, TypeRefusal,
};

use crate::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityStore, HeadBodyRefusal,
    ImmutableKey, ImmutableRead, KeyError, PutOutcome, SealFailure, body_key_for_id,
};

/// Maximum revoked capability identities retained in one canonical generation.
///
/// This is the same system ceiling enforced by `fgit-agent` at the effect-time
/// read boundary.  The body refuses a larger set before retaining or emitting
/// it, so a storage adapter cannot hand the agent an already-unbounded value.
pub const MAX_CAPABILITY_REVOCATION_ENTRIES: usize = 4_096;

/// Immutable namespace selecting the revocation generation for one exact
/// authenticated policy tuple.
pub const CAPABILITY_REVOCATION_SELECTOR_KEY_PREFIX: &[u8] =
    b"fg/capability-revocations/v1/";

/// The registered identity of one immutable capability-revocation generation.
pub type CapabilityRevocationGenerationId = GenerationId;

/// Why an in-memory candidate could not become a canonical generation body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityRevocationBodyRefusal {
    /// The full snapshot exceeded its hard system ceiling.
    TooManyRevocations {
        /// Identities supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// One capability identity appeared twice in the full snapshot.
    DuplicateCapabilityId {
        /// Repeated opaque capability identity.
        capability_id: [u8; 16],
    },
}

impl fmt::Display for CapabilityRevocationBodyRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRevocations { observed, limit } => write!(
                formatter,
                "capability revocation generation has {observed} identities, limit {limit}"
            ),
            Self::DuplicateCapabilityId { capability_id } => {
                formatter.write_str("capability revocation generation repeats capability ")?;
                write_hex(formatter, capability_id)
            }
        }
    }
}

impl core::error::Error for CapabilityRevocationBodyRefusal {}

/// Complete immutable revocation state selected at one repository policy tuple.
///
/// This is a full snapshot rather than a delta.  Effect authorization therefore
/// performs one bounded exact read and never walks an unbounded event history.
/// `predecessor_generation_id` preserves lineage for audit, migration, and
/// anti-rollback verification without making predecessor availability a
/// prerequisite for deciding the current set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationGenerationBody {
    repository_id: RepositoryId,
    policy_epoch: PolicyEpoch,
    configuration_root: Digest,
    predecessor_generation_id: Option<CapabilityRevocationGenerationId>,
    revoked_capability_ids: Vec<[u8; 16]>,
    evidence_root: Digest,
}

impl CapabilityRevocationGenerationBody {
    /// Builds one bounded, canonical full snapshot.
    ///
    /// Input order is not semantic.  Identities are sorted and duplicates are
    /// refused rather than silently collapsed, so two producers cannot hide a
    /// disagreement behind set normalization.
    pub fn try_new(
        repository_id: RepositoryId,
        policy_epoch: PolicyEpoch,
        configuration_root: Digest,
        predecessor_generation_id: Option<CapabilityRevocationGenerationId>,
        mut revoked_capability_ids: Vec<[u8; 16]>,
        evidence_root: Digest,
    ) -> Result<Self, CapabilityRevocationBodyRefusal> {
        if revoked_capability_ids.len() > MAX_CAPABILITY_REVOCATION_ENTRIES {
            return Err(CapabilityRevocationBodyRefusal::TooManyRevocations {
                observed: revoked_capability_ids.len(),
                limit: MAX_CAPABILITY_REVOCATION_ENTRIES,
            });
        }
        revoked_capability_ids.sort_unstable();
        for adjacent in revoked_capability_ids.windows(2) {
            if adjacent[0] == adjacent[1] {
                return Err(CapabilityRevocationBodyRefusal::DuplicateCapabilityId {
                    capability_id: adjacent[0],
                });
            }
        }
        Ok(Self {
            repository_id,
            policy_epoch,
            configuration_root,
            predecessor_generation_id,
            revoked_capability_ids,
            evidence_root,
        })
    }

    /// Repository whose capability namespace this snapshot covers.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Authenticated policy epoch selecting this snapshot.
    #[must_use]
    pub const fn policy_epoch(&self) -> PolicyEpoch {
        self.policy_epoch
    }

    /// Exact repository configuration under which this snapshot is interpreted.
    #[must_use]
    pub const fn configuration_root(&self) -> Digest {
        self.configuration_root
    }

    /// Previous revocation generation, when the producer retained lineage.
    #[must_use]
    pub const fn predecessor_generation_id(
        &self,
    ) -> Option<CapabilityRevocationGenerationId> {
        self.predecessor_generation_id
    }

    /// Canonically sorted revoked capability identities.
    #[must_use]
    pub fn revoked_capability_ids(&self) -> &[[u8; 16]] {
        &self.revoked_capability_ids
    }

    /// Evidence supporting construction of this policy generation.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }

    /// Re-identifies this complete canonical body in the registered generation
    /// domain.
    pub fn generation_id(
        &self,
    ) -> Result<CapabilityRevocationGenerationId, CapabilityRevocationAuthorityFailure> {
        let identity = body_id(&CryptoBodyIdentity, self)?;
        Ok(CapabilityRevocationGenerationId::from_internal_object_id(
            identity,
        )?)
    }
}

impl CanonicalBody for CapabilityRevocationGenerationBody {
    const DOMAIN: fgit_types::DomainTag = CapabilityRevocationGenerationId::DOMAIN_TAG;
    const SCHEMA_FAMILY: SchemaFamily =
        SchemaFamily::from_static("capability-revocation-generation");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        if self.revoked_capability_ids.len() > MAX_CAPABILITY_REVOCATION_ENTRIES {
            return Err(CodecRefusal::ValueUnrepresentable {
                field: "capability_revocation.revoked_capability_ids",
                observed: u64::try_from(self.revoked_capability_ids.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(MAX_CAPABILITY_REVOCATION_ENTRIES).unwrap_or(u64::MAX),
            });
        }
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_scalar(self.policy_epoch.get());
        out.write_digest(&self.configuration_root)?;
        out.write_option(
            self.predecessor_generation_id.as_ref(),
            |encoder, predecessor| {
                encoder.write_internal_object_id(predecessor.as_internal_object_id())
            },
        )?;
        out.write_canonical_set(&self.revoked_capability_ids, |encoder, capability_id| {
            encoder.write_opaque_id(capability_id)
        })?;
        out.write_digest(&self.evidence_root)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(
            input.read_opaque_id("capability_revocation.repository_id")?,
        );
        let policy_epoch = PolicyEpoch::try_new(
            input.read_scalar::<u64>("capability_revocation.policy_epoch")?,
        )?;
        let configuration_root = input.read_digest()?;
        let predecessor_generation_id = input.read_option(
            "capability_revocation.predecessor_generation_id",
            |decoder| {
                Ok(CapabilityRevocationGenerationId::from_internal_object_id(
                    decoder.read_internal_object_id()?,
                )?)
            },
        )?;
        let revoked_capability_ids = input.read_canonical_set(
            "capability_revocation.revoked_capability_ids",
            |decoder| decoder.read_opaque_id("capability_revocation.capability_id"),
        )?;
        if revoked_capability_ids.len() > MAX_CAPABILITY_REVOCATION_ENTRIES {
            return Err(CodecRefusal::ValueUnrepresentable {
                field: "capability_revocation.revoked_capability_ids",
                observed: u64::try_from(revoked_capability_ids.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(MAX_CAPABILITY_REVOCATION_ENTRIES).unwrap_or(u64::MAX),
            });
        }
        let evidence_root = input.read_digest()?;
        Ok(Self {
            repository_id,
            policy_epoch,
            configuration_root,
            predecessor_generation_id,
            revoked_capability_ids,
            evidence_root,
        })
    }
}

/// The two immutable writes that stage one revocation generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationGenerationStage {
    generation_id: CapabilityRevocationGenerationId,
    content_outcome: PutOutcome,
    selector_outcome: PutOutcome,
}

impl CapabilityRevocationGenerationStage {
    /// Canonical identity of the staged generation.
    #[must_use]
    pub const fn generation_id(self) -> CapabilityRevocationGenerationId {
        self.generation_id
    }

    /// Outcome of writing the ordinary content-addressed body slot.
    #[must_use]
    pub const fn content_outcome(self) -> PutOutcome {
        self.content_outcome
    }

    /// Outcome of binding the authenticated policy tuple to the same bytes.
    #[must_use]
    pub const fn selector_outcome(self) -> PutOutcome {
        self.selector_outcome
    }
}

/// One strictly validated authority-selected revocation generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationGenerationRead {
    generation_id: CapabilityRevocationGenerationId,
    body: CapabilityRevocationGenerationBody,
}

impl CapabilityRevocationGenerationRead {
    /// Exact canonical generation identity.
    #[must_use]
    pub const fn generation_id(&self) -> CapabilityRevocationGenerationId {
        self.generation_id
    }

    /// Complete selected snapshot.
    #[must_use]
    pub const fn body(&self) -> &CapabilityRevocationGenerationBody {
        &self.body
    }
}

/// Why staging or resolving canonical revocation state failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityRevocationAuthorityFailure {
    /// Candidate construction refused an excessive or duplicate set.
    Body(CapabilityRevocationBodyRefusal),
    /// Canonical framing or identity derivation failed.
    Codec(CodecRefusal),
    /// A typed identity used the wrong domain or malformed bytes.
    Type(TypeRefusal),
    /// A deterministic immutable key exceeded the authority contract.
    Key(KeyError),
    /// The authority backend refused or returned an ambiguous result.
    Authority(AuthorityFailure),
    /// The authenticated head body was malformed or generation-skewed.
    HeadBody(HeadBodyRefusal),
    /// Standard content-addressed body-key derivation failed.
    BodyKey(Box<SealFailure>),
    /// The content-addressed slot already held different bytes.
    ContentAddressedConflict {
        /// Generation whose own body slot conflicted.
        generation_id: Box<CapabilityRevocationGenerationId>,
    },
    /// The authenticated policy tuple was already bound to another body.
    SelectorConflict,
    /// No revocation generation exists for the exact authenticated policy tuple.
    SelectionMissing,
    /// The selected body names another repository.
    RepositoryMismatch {
        /// Repository selected by the authenticated head.
        expected: RepositoryId,
        /// Repository named by the selected body.
        observed: RepositoryId,
    },
    /// The selected body names another policy epoch.
    PolicyEpochMismatch {
        /// Epoch selected by the authenticated head.
        expected: PolicyEpoch,
        /// Epoch named by the selected body.
        observed: PolicyEpoch,
    },
    /// The selected body names another configuration root.
    ConfigurationRootMismatch,
    /// The selected body re-identified to another generation.
    GenerationIdentityMismatch {
        /// Identity whose content-addressed slot was requested.
        expected: Box<CapabilityRevocationGenerationId>,
        /// Identity re-derived from the stored bytes.
        observed: Box<CapabilityRevocationGenerationId>,
    },
    /// The selected generation had no copy under its canonical body key.
    ContentAddressedCopyMissing {
        /// Missing generation.
        generation_id: Box<CapabilityRevocationGenerationId>,
    },
    /// The selector and content-addressed slots carried different bytes.
    ContentAddressedCopyMismatch {
        /// Generation whose two immutable copies disagreed.
        generation_id: Box<CapabilityRevocationGenerationId>,
    },
}

impl fmt::Display for CapabilityRevocationAuthorityFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(refusal) => write!(formatter, "{refusal}"),
            Self::Codec(refusal) => write!(formatter, "revocation codec refused: {refusal}"),
            Self::Type(refusal) => write!(formatter, "revocation identity refused: {refusal}"),
            Self::Key(refusal) => write!(formatter, "revocation key refused: {refusal}"),
            Self::Authority(refusal) => {
                write!(formatter, "revocation authority operation failed: {refusal}")
            }
            Self::HeadBody(refusal) => write!(formatter, "revocation head refused: {refusal}"),
            Self::BodyKey(refusal) => write!(formatter, "revocation body key refused: {refusal}"),
            Self::ContentAddressedConflict { generation_id } => write!(
                formatter,
                "content-addressed revocation slot for {generation_id} contains different bytes"
            ),
            Self::SelectorConflict => formatter.write_str(
                "the authenticated revocation selector already contains different bytes",
            ),
            Self::SelectionMissing => formatter.write_str(
                "the authenticated policy tuple selects no capability revocation generation",
            ),
            Self::RepositoryMismatch { expected, observed } => write!(
                formatter,
                "selected revocation generation names repository {observed}, expected {expected}"
            ),
            Self::PolicyEpochMismatch { expected, observed } => write!(
                formatter,
                "selected revocation generation names policy epoch {}, expected {}",
                observed.get(),
                expected.get()
            ),
            Self::ConfigurationRootMismatch => formatter.write_str(
                "selected revocation generation names another repository configuration root",
            ),
            Self::GenerationIdentityMismatch { expected, observed } => write!(
                formatter,
                "revocation body stored for {expected} re-identifies as {observed}"
            ),
            Self::ContentAddressedCopyMissing { generation_id } => write!(
                formatter,
                "selected revocation generation {generation_id} has no content-addressed copy"
            ),
            Self::ContentAddressedCopyMismatch { generation_id } => write!(
                formatter,
                "selected and content-addressed bytes disagree for {generation_id}"
            ),
        }
    }
}

impl core::error::Error for CapabilityRevocationAuthorityFailure {}

impl From<CapabilityRevocationBodyRefusal> for CapabilityRevocationAuthorityFailure {
    fn from(value: CapabilityRevocationBodyRefusal) -> Self {
        Self::Body(value)
    }
}

impl From<CodecRefusal> for CapabilityRevocationAuthorityFailure {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

impl From<TypeRefusal> for CapabilityRevocationAuthorityFailure {
    fn from(value: TypeRefusal) -> Self {
        Self::Type(value)
    }
}

impl From<KeyError> for CapabilityRevocationAuthorityFailure {
    fn from(value: KeyError) -> Self {
        Self::Key(value)
    }
}

impl From<AuthorityFailure> for CapabilityRevocationAuthorityFailure {
    fn from(value: AuthorityFailure) -> Self {
        Self::Authority(value)
    }
}

impl From<HeadBodyRefusal> for CapabilityRevocationAuthorityFailure {
    fn from(value: HeadBodyRefusal) -> Self {
        Self::HeadBody(value)
    }
}

impl From<SealFailure> for CapabilityRevocationAuthorityFailure {
    fn from(value: SealFailure) -> Self {
        Self::BodyKey(Box::new(value))
    }
}

/// Deterministic immutable selector for one exact authenticated policy tuple.
///
/// The key contains the repository, nonzero policy epoch, digest algorithm,
/// digest length, and complete configuration-root bytes.  No listing or local
/// index participates in resolution.
pub fn capability_revocation_selector_key(
    repository_id: RepositoryId,
    policy_epoch: PolicyEpoch,
    configuration_root: &Digest,
) -> Result<ImmutableKey, KeyError> {
    let digest_bytes = configuration_root.bytes().as_bytes();
    let digest_len = u16::try_from(digest_bytes.len()).map_err(|_| KeyError::TooLong {
        len: digest_bytes.len(),
        limit: usize::from(u16::MAX),
    })?;
    let mut key = Vec::with_capacity(
        CAPABILITY_REVOCATION_SELECTOR_KEY_PREFIX.len() + 16 + 8 + 2 + 2 + digest_bytes.len(),
    );
    key.extend_from_slice(CAPABILITY_REVOCATION_SELECTOR_KEY_PREFIX);
    key.extend_from_slice(repository_id.as_bytes());
    key.extend_from_slice(&policy_epoch.get().to_be_bytes());
    key.extend_from_slice(&configuration_root.algorithm().code_point().to_be_bytes());
    key.extend_from_slice(&digest_len.to_be_bytes());
    key.extend_from_slice(digest_bytes);
    ImmutableKey::new(key)
}

/// Stages one immutable candidate on the deterministic verification surface.
///
/// The content body is written first and the tuple selector second.  Either
/// conflict is a refusal.  An orphaned content body after a selector race is
/// harmless and non-authoritative; the authority head selects only the exact
/// tuple and the selector remains immutable.
pub fn stage_capability_revocation_generation<S>(
    store: &S,
    body: &CapabilityRevocationGenerationBody,
) -> Result<CapabilityRevocationGenerationStage, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    let generation_id = body.generation_id()?;
    let encoded = encode_body(body)?;
    let content_key = body_key_for_id(generation_id.as_internal_object_id())?;
    let content_outcome = store.put_if_absent(&content_key, &encoded)?;
    if content_outcome == PutOutcome::Conflict {
        return Err(CapabilityRevocationAuthorityFailure::ContentAddressedConflict {
            generation_id: Box::new(generation_id),
        });
    }
    let selector_key = capability_revocation_selector_key(
        body.repository_id,
        body.policy_epoch,
        &body.configuration_root,
    )?;
    let selector_outcome = store.put_if_absent(&selector_key, &encoded)?;
    if selector_outcome == PutOutcome::Conflict {
        return Err(CapabilityRevocationAuthorityFailure::SelectorConflict);
    }
    Ok(CapabilityRevocationGenerationStage {
        generation_id,
        content_outcome,
        selector_outcome,
    })
}

/// Production asynchronous twin of [`stage_capability_revocation_generation`].
pub async fn stage_capability_revocation_generation_async<S>(
    store: &S,
    cx: &S::Context,
    body: &CapabilityRevocationGenerationBody,
) -> Result<CapabilityRevocationGenerationStage, CapabilityRevocationAuthorityFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let generation_id = body.generation_id()?;
    let encoded = encode_body(body)?;
    let content_key = body_key_for_id(generation_id.as_internal_object_id())?;
    let content_outcome = store.put_if_absent(cx, &content_key, &encoded).await?;
    if content_outcome == PutOutcome::Conflict {
        return Err(CapabilityRevocationAuthorityFailure::ContentAddressedConflict {
            generation_id: Box::new(generation_id),
        });
    }
    let selector_key = capability_revocation_selector_key(
        body.repository_id,
        body.policy_epoch,
        &body.configuration_root,
    )?;
    let selector_outcome = store.put_if_absent(cx, &selector_key, &encoded).await?;
    if selector_outcome == PutOutcome::Conflict {
        return Err(CapabilityRevocationAuthorityFailure::SelectorConflict);
    }
    Ok(CapabilityRevocationGenerationStage {
        generation_id,
        content_outcome,
        selector_outcome,
    })
}

/// Reads one generation by its content identity and requires re-identification.
pub fn read_capability_revocation_generation_by_id<S>(
    store: &S,
    generation_id: CapabilityRevocationGenerationId,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key_for_id(generation_id.as_internal_object_id())?;
    let ImmutableRead::Present(bytes) = store.read_immutable(&key)? else {
        return Err(CapabilityRevocationAuthorityFailure::ContentAddressedCopyMissing {
            generation_id: Box::new(generation_id),
        });
    };
    identified_generation(&bytes, generation_id)
}

/// Production asynchronous twin of
/// [`read_capability_revocation_generation_by_id`].
pub async fn read_capability_revocation_generation_by_id_async<S>(
    store: &S,
    cx: &S::Context,
    generation_id: CapabilityRevocationGenerationId,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = body_key_for_id(generation_id.as_internal_object_id())?;
    let ImmutableRead::Present(bytes) = store.read_immutable(cx, &key).await? else {
        return Err(CapabilityRevocationAuthorityFailure::ContentAddressedCopyMissing {
            generation_id: Box::new(generation_id),
        });
    };
    identified_generation(&bytes, generation_id)
}

/// Resolves the generation selected by one authenticated repository tuple.
pub fn read_capability_revocation_generation<S>(
    store: &S,
    repository_id: RepositoryId,
    policy_epoch: PolicyEpoch,
    configuration_root: &Digest,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    let selector_key =
        capability_revocation_selector_key(repository_id, policy_epoch, configuration_root)?;
    let ImmutableRead::Present(selected_bytes) = store.read_immutable(&selector_key)? else {
        return Err(CapabilityRevocationAuthorityFailure::SelectionMissing);
    };
    validate_selected_generation(
        store,
        &selected_bytes,
        repository_id,
        policy_epoch,
        configuration_root,
    )
}

/// Production asynchronous twin of [`read_capability_revocation_generation`].
pub async fn read_capability_revocation_generation_async<S>(
    store: &S,
    cx: &S::Context,
    repository_id: RepositoryId,
    policy_epoch: PolicyEpoch,
    configuration_root: &Digest,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let selector_key =
        capability_revocation_selector_key(repository_id, policy_epoch, configuration_root)?;
    let ImmutableRead::Present(selected_bytes) =
        store.read_immutable(cx, &selector_key).await?
    else {
        return Err(CapabilityRevocationAuthorityFailure::SelectionMissing);
    };
    validate_selected_generation_async(
        store,
        cx,
        &selected_bytes,
        repository_id,
        policy_epoch,
        configuration_root,
    )
    .await
}

/// Resolves capability revocations from the exact authenticated head body.
///
/// The caller cannot substitute a repository, epoch, or configuration root:
/// all three are taken from the store-authenticated, generation-checked body.
pub fn read_head_selected_capability_revocation_generation<S>(
    store: &S,
    authenticated: &AuthenticatedHead,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    let head = authenticated.body()?;
    read_capability_revocation_generation(
        store,
        head.repository_id,
        head.policy_epoch,
        &head.configuration_root,
    )
}

/// Production asynchronous twin of
/// [`read_head_selected_capability_revocation_generation`].
pub async fn read_head_selected_capability_revocation_generation_async<S>(
    store: &S,
    cx: &S::Context,
    authenticated: &AuthenticatedHead,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let head = authenticated.body()?;
    read_capability_revocation_generation_async(
        store,
        cx,
        head.repository_id,
        head.policy_epoch,
        &head.configuration_root,
    )
    .await
}

fn identified_generation(
    bytes: &[u8],
    expected: CapabilityRevocationGenerationId,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure> {
    let body: CapabilityRevocationGenerationBody = decode_body(bytes, DecodeLimits::DEFAULT)?;
    let observed = body.generation_id()?;
    if observed != expected {
        return Err(CapabilityRevocationAuthorityFailure::GenerationIdentityMismatch {
            expected: Box::new(expected),
            observed: Box::new(observed),
        });
    }
    Ok(CapabilityRevocationGenerationRead {
        generation_id: expected,
        body,
    })
}

fn validate_selection_fields(
    body: &CapabilityRevocationGenerationBody,
    repository_id: RepositoryId,
    policy_epoch: PolicyEpoch,
    configuration_root: &Digest,
) -> Result<(), CapabilityRevocationAuthorityFailure> {
    if body.repository_id != repository_id {
        return Err(CapabilityRevocationAuthorityFailure::RepositoryMismatch {
            expected: repository_id,
            observed: body.repository_id,
        });
    }
    if body.policy_epoch != policy_epoch {
        return Err(CapabilityRevocationAuthorityFailure::PolicyEpochMismatch {
            expected: policy_epoch,
            observed: body.policy_epoch,
        });
    }
    if &body.configuration_root != configuration_root {
        return Err(CapabilityRevocationAuthorityFailure::ConfigurationRootMismatch);
    }
    Ok(())
}

fn validate_selected_generation<S>(
    store: &S,
    selected_bytes: &[u8],
    repository_id: RepositoryId,
    policy_epoch: PolicyEpoch,
    configuration_root: &Digest,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    let body: CapabilityRevocationGenerationBody =
        decode_body(selected_bytes, DecodeLimits::DEFAULT)?;
    validate_selection_fields(&body, repository_id, policy_epoch, configuration_root)?;
    let generation_id = body.generation_id()?;
    let content_key = body_key_for_id(generation_id.as_internal_object_id())?;
    match store.read_immutable(&content_key)? {
        ImmutableRead::Absent => {
            Err(CapabilityRevocationAuthorityFailure::ContentAddressedCopyMissing {
                generation_id: Box::new(generation_id),
            })
        }
        ImmutableRead::Present(content_bytes) if content_bytes == selected_bytes => {
            Ok(CapabilityRevocationGenerationRead {
                generation_id,
                body,
            })
        }
        ImmutableRead::Present(_) => {
            Err(CapabilityRevocationAuthorityFailure::ContentAddressedCopyMismatch {
                generation_id: Box::new(generation_id),
            })
        }
    }
}

async fn validate_selected_generation_async<S>(
    store: &S,
    cx: &S::Context,
    selected_bytes: &[u8],
    repository_id: RepositoryId,
    policy_epoch: PolicyEpoch,
    configuration_root: &Digest,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let body: CapabilityRevocationGenerationBody =
        decode_body(selected_bytes, DecodeLimits::DEFAULT)?;
    validate_selection_fields(&body, repository_id, policy_epoch, configuration_root)?;
    let generation_id = body.generation_id()?;
    let content_key = body_key_for_id(generation_id.as_internal_object_id())?;
    match store.read_immutable(cx, &content_key).await? {
        ImmutableRead::Absent => {
            Err(CapabilityRevocationAuthorityFailure::ContentAddressedCopyMissing {
                generation_id: Box::new(generation_id),
            })
        }
        ImmutableRead::Present(content_bytes) if content_bytes == selected_bytes => {
            Ok(CapabilityRevocationGenerationRead {
                generation_id,
                body,
            })
        }
        ImmutableRead::Present(_) => {
            Err(CapabilityRevocationAuthorityFailure::ContentAddressedCopyMismatch {
                generation_id: Box::new(generation_id),
            })
        }
    }
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

const _: () = {
    assert!(size_of::<CapabilityRevocationBodyRefusal>() <= crate::request::MAX_ERROR_BYTES);
    assert!(size_of::<CapabilityRevocationAuthorityFailure>() <= crate::request::MAX_ERROR_BYTES);
};
