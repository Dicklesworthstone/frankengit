//! Canonical capability-revocation generations selected by repository authority.
//!
//! Capability revocation is policy state, not a mutable local deny list. One
//! immutable full snapshot is stored under the registered
//! `frankengit/generation/v1` identity domain. Repository configuration schema
//! 2.2 carries that generation's exact digest, and the authority head carries
//! the configuration digest. Selection therefore follows one ordinary chain:
//!
//! ```text
//! authenticated RepositoryAuthorityHead
//!     -> configuration_root
//!     -> RepositoryIncarnationConfigurationBodyV2_2
//!     -> capability_revocation_root
//!     -> CapabilityRevocationGenerationBody
//! ```
//!
//! There is deliberately no side selector or mutable cache here. Changing the
//! revoked set requires staging a new generation, staging a new configuration
//! that names it, and publishing that configuration through the ordinary
//! authority-head compare-and-swap.
//!
//! The selected body is a bounded full snapshot. A reader never walks an
//! unbounded event history and never interprets an absent root as an empty set.
//! Repositories on configuration schema 2.0 or 2.1 therefore fail closed for
//! high-value authorization until schema 2.2 names an explicit generation,
//! including an explicit empty generation when nothing is revoked.

use core::fmt;

use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Decoder, Encoder, body_id,
    decode_body, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GenerationId, PolicyEpoch, RepositoryId,
    RepositoryIncarnationId, SchemaFamily, TenantId,
};

use crate::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityStore, HeadBodyRefusal,
    ImmutableRead, OutcomeFailure, PutOutcome, SealFailure, body_key, body_key_for_id,
    read_repository_incarnation_configuration,
    read_repository_incarnation_configuration_async,
};

/// Maximum revoked capability identities retained in one canonical generation.
pub const MAX_CAPABILITY_REVOCATION_ENTRIES: usize = 4_096;

/// Authoritative readers apply this bound before collection allocation.
const REVOCATION_DECODE_LIMITS: DecodeLimits = DecodeLimits {
    elements: 4_096,
    ..DecodeLimits::DEFAULT
};

/// Registered identity of one immutable capability-revocation generation.
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

/// Complete immutable revocation state selected at one repository policy epoch.
///
/// This is a full snapshot rather than a delta. The optional predecessor keeps
/// lineage for audit and migration, but current authorization needs only the
/// selected body. Tenant, repository, and incarnation are all retained because
/// repository IDs are tenant-scoped and an incarnation must not survive
/// delete/recreate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationGenerationBody {
    tenant_id: TenantId,
    repository_id: RepositoryId,
    repository_incarnation_id: RepositoryIncarnationId,
    policy_epoch: PolicyEpoch,
    predecessor_generation_id: Option<CapabilityRevocationGenerationId>,
    revoked_capability_ids: Vec<[u8; 16]>,
    evidence_root: Digest,
}

impl CapabilityRevocationGenerationBody {
    /// Builds one bounded, canonical full snapshot.
    ///
    /// Input order is not semantic. Identities are sorted and duplicates are
    /// refused rather than silently collapsed.
    pub fn try_new(
        tenant_id: TenantId,
        repository_id: RepositoryId,
        repository_incarnation_id: RepositoryIncarnationId,
        policy_epoch: PolicyEpoch,
        predecessor_generation_id: Option<CapabilityRevocationGenerationId>,
        mut revoked_capability_ids: Vec<[u8; 16]>,
        evidence_root: Digest,
    ) -> Result<Self, CapabilityRevocationBodyRefusal> {
        validate_revoked_ids(&mut revoked_capability_ids)?;
        Ok(Self {
            tenant_id,
            repository_id,
            repository_incarnation_id,
            policy_epoch,
            predecessor_generation_id,
            revoked_capability_ids,
            evidence_root,
        })
    }

    /// Tenant containing the repository capability namespace.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Repository whose capability namespace this snapshot covers.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Repository incarnation this snapshot may authorize against.
    #[must_use]
    pub const fn repository_incarnation_id(&self) -> RepositoryIncarnationId {
        self.repository_incarnation_id
    }

    /// Authenticated policy epoch selecting this snapshot.
    #[must_use]
    pub const fn policy_epoch(&self) -> PolicyEpoch {
        self.policy_epoch
    }

    /// Previous revocation generation, when lineage was retained.
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

    /// Re-identifies this complete canonical body in the generation domain.
    pub fn generation_id(
        &self,
    ) -> Result<CapabilityRevocationGenerationId, CapabilityRevocationAuthorityFailure> {
        let identity = body_id(&CryptoBodyIdentity, self)?;
        Ok(CapabilityRevocationGenerationId::from_internal_object_id(
            identity,
        )?)
    }

    /// Digest carried by repository configuration schema 2.2.
    pub fn generation_root(
        &self,
    ) -> Result<Digest, CapabilityRevocationAuthorityFailure> {
        Ok(capability_revocation_generation_root(self.generation_id()?))
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
            return Err(too_many_codec_refusal(self.revoked_capability_ids.len()));
        }
        out.write_opaque_id(self.tenant_id.as_bytes());
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_opaque_id(self.repository_incarnation_id.as_bytes());
        out.write_scalar(self.policy_epoch.get());
        out.write_option(
            self.predecessor_generation_id.as_ref(),
            |encoder, predecessor| {
                encoder.write_internal_object_id(predecessor.as_internal_object_id())
            },
        )?;
        out.write_canonical_set(
            "capability_revocation.revoked_capability_ids",
            &self.revoked_capability_ids,
            |encoder, capability_id| {
                encoder.write_opaque_id(capability_id);
                Ok(())
            },
        )?;
        out.write_digest(&self.evidence_root)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let tenant_id = TenantId::from_bytes(
            input.read_opaque_id("capability_revocation.tenant_id")?,
        );
        let repository_id = RepositoryId::from_bytes(
            input.read_opaque_id("capability_revocation.repository_id")?,
        );
        let repository_incarnation_id = RepositoryIncarnationId::from_bytes(
            input.read_opaque_id("capability_revocation.repository_incarnation_id")?,
        );
        let policy_epoch = PolicyEpoch::try_new(
            input.read_scalar::<u64>("capability_revocation.policy_epoch")?,
        )?;
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
            return Err(too_many_codec_refusal(revoked_capability_ids.len()));
        }
        let evidence_root = input.read_digest()?;
        Ok(Self {
            tenant_id,
            repository_id,
            repository_incarnation_id,
            policy_epoch,
            predecessor_generation_id,
            revoked_capability_ids,
            evidence_root,
        })
    }
}

/// The immutable write that stages one revocation generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationGenerationStage {
    generation_id: CapabilityRevocationGenerationId,
    outcome: PutOutcome,
}

impl CapabilityRevocationGenerationStage {
    /// Canonical identity of the staged generation.
    #[must_use]
    pub const fn generation_id(self) -> CapabilityRevocationGenerationId {
        self.generation_id
    }

    /// Digest a schema-2.2 configuration carries.
    #[must_use]
    pub fn generation_root(self) -> Digest {
        capability_revocation_generation_root(self.generation_id)
    }

    /// Outcome of writing the content-addressed body slot.
    #[must_use]
    pub const fn outcome(self) -> PutOutcome {
        self.outcome
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

    /// Digest selected by repository configuration.
    #[must_use]
    pub fn generation_root(&self) -> Digest {
        capability_revocation_generation_root(self.generation_id)
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
    /// Canonical framing or decoding failed.
    Codec(CodecRefusal),
    /// A generation identity carried another domain.
    Type(fgit_types::TypeRefusal),
    /// The authority backend refused or returned an ambiguous result.
    Authority(AuthorityFailure),
    /// The authenticated head body was malformed or generation-skewed.
    HeadBody(HeadBodyRefusal),
    /// Repository configuration could not be resolved exactly.
    Configuration(Box<OutcomeFailure>),
    /// Standard content-addressed body-key derivation failed.
    BodyKey(Box<SealFailure>),
    /// The content-addressed slot already held different bytes.
    ContentAddressedConflict {
        /// Generation whose own body slot conflicted.
        generation_id: Box<CapabilityRevocationGenerationId>,
    },
    /// No body exists under the exact generation identity.
    GenerationMissing {
        /// Missing generation.
        generation_id: Box<CapabilityRevocationGenerationId>,
    },
    /// Stored bytes re-identified to another generation.
    GenerationIdentityMismatch {
        /// Identity requested by configuration.
        expected: Box<CapabilityRevocationGenerationId>,
        /// Identity re-derived from stored bytes.
        observed: Box<CapabilityRevocationGenerationId>,
    },
    /// The selected configuration predates or omits revocation state.
    ConfigurationHasNoRevocationRoot,
    /// The selected generation belongs to another tenant.
    TenantMismatch {
        /// Tenant supplied by the authenticated request boundary.
        expected: TenantId,
        /// Tenant named by the selected body.
        observed: TenantId,
    },
    /// The selected generation belongs to another repository.
    RepositoryMismatch {
        /// Repository named by the authenticated head.
        expected: RepositoryId,
        /// Repository named by the selected body.
        observed: RepositoryId,
    },
    /// The selected generation belongs to a stale repository incarnation.
    IncarnationMismatch {
        /// Incarnation selected by repository configuration.
        expected: RepositoryIncarnationId,
        /// Incarnation named by the selected body.
        observed: RepositoryIncarnationId,
    },
    /// The selected generation belongs to another policy epoch.
    PolicyEpochMismatch {
        /// Epoch named by the authenticated head.
        expected: PolicyEpoch,
        /// Epoch named by the selected body.
        observed: PolicyEpoch,
    },
}

impl fmt::Display for CapabilityRevocationAuthorityFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(refusal) => write!(formatter, "{refusal}"),
            Self::Codec(refusal) => write!(formatter, "revocation codec refused: {refusal}"),
            Self::Type(refusal) => write!(formatter, "revocation identity refused: {refusal}"),
            Self::Authority(refusal) => {
                write!(formatter, "revocation authority operation failed: {refusal}")
            }
            Self::HeadBody(refusal) => write!(formatter, "revocation head refused: {refusal}"),
            Self::Configuration(refusal) => {
                write!(formatter, "revocation configuration refused: {refusal}")
            }
            Self::BodyKey(refusal) => write!(formatter, "revocation body key refused: {refusal}"),
            Self::ContentAddressedConflict { generation_id } => write!(
                formatter,
                "content-addressed revocation slot for {generation_id} contains different bytes"
            ),
            Self::GenerationMissing { generation_id } => write!(
                formatter,
                "selected capability revocation generation {generation_id} is missing"
            ),
            Self::GenerationIdentityMismatch { expected, observed } => write!(
                formatter,
                "revocation body stored for {expected} re-identifies as {observed}"
            ),
            Self::ConfigurationHasNoRevocationRoot => formatter.write_str(
                "repository configuration has no canonical capability revocation root",
            ),
            Self::TenantMismatch { expected, observed } => write!(
                formatter,
                "selected revocation generation names tenant {observed}, expected {expected}"
            ),
            Self::RepositoryMismatch { expected, observed } => write!(
                formatter,
                "selected revocation generation names repository {observed}, expected {expected}"
            ),
            Self::IncarnationMismatch { expected, observed } => write!(
                formatter,
                "selected revocation generation names incarnation {observed}, expected {expected}"
            ),
            Self::PolicyEpochMismatch { expected, observed } => write!(
                formatter,
                "selected revocation generation names policy epoch {}, expected {}",
                observed.get(),
                expected.get()
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

impl From<fgit_types::TypeRefusal> for CapabilityRevocationAuthorityFailure {
    fn from(value: fgit_types::TypeRefusal) -> Self {
        Self::Type(value)
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

impl From<OutcomeFailure> for CapabilityRevocationAuthorityFailure {
    fn from(value: OutcomeFailure) -> Self {
        Self::Configuration(Box::new(value))
    }
}

impl From<SealFailure> for CapabilityRevocationAuthorityFailure {
    fn from(value: SealFailure) -> Self {
        Self::BodyKey(Box::new(value))
    }
}

/// Converts a generation identity into the digest carried by configuration 2.2.
#[must_use]
pub fn capability_revocation_generation_root(
    generation_id: CapabilityRevocationGenerationId,
) -> Digest {
    let identity = generation_id.as_internal_object_id();
    Digest::new(identity.algorithm(), *identity.digest())
}

/// Converts the digest carried by configuration 2.2 into its typed generation
/// identity.
#[must_use]
pub fn capability_revocation_generation_id_from_root(
    root: &Digest,
) -> CapabilityRevocationGenerationId {
    CapabilityRevocationGenerationId::from_digest(
        root.algorithm(),
        CANONICAL_CODEC_VERSION,
        *root.bytes(),
    )
}

/// Stages one immutable full snapshot under its ordinary content identity.
///
/// Staging alone grants no authority. A caller must next stage configuration
/// schema 2.2 with this generation's digest and publish that configuration root
/// through an ordinary authority-head transition.
pub fn stage_capability_revocation_generation<S>(
    store: &S,
    body: &CapabilityRevocationGenerationBody,
) -> Result<CapabilityRevocationGenerationStage, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    let generation_id = body.generation_id()?;
    let key = body_key(IdentityDomain::Generation, body)?;
    let outcome = store.put_if_absent(&key, &encode_body(body)?)?;
    if outcome == PutOutcome::Conflict {
        return Err(CapabilityRevocationAuthorityFailure::ContentAddressedConflict {
            generation_id: Box::new(generation_id),
        });
    }
    Ok(CapabilityRevocationGenerationStage {
        generation_id,
        outcome,
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
    let key = body_key(IdentityDomain::Generation, body)?;
    let outcome = store.put_if_absent(cx, &key, &encode_body(body)?).await?;
    if outcome == PutOutcome::Conflict {
        return Err(CapabilityRevocationAuthorityFailure::ContentAddressedConflict {
            generation_id: Box::new(generation_id),
        });
    }
    Ok(CapabilityRevocationGenerationStage {
        generation_id,
        outcome,
    })
}

/// Reads one generation by exact content identity and requires canonical
/// re-identification.
pub fn read_capability_revocation_generation_by_id<S>(
    store: &S,
    generation_id: CapabilityRevocationGenerationId,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key_for_id(generation_id.as_internal_object_id())?;
    let ImmutableRead::Present(bytes) = store.read_immutable(&key)? else {
        return Err(CapabilityRevocationAuthorityFailure::GenerationMissing {
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
        return Err(CapabilityRevocationAuthorityFailure::GenerationMissing {
            generation_id: Box::new(generation_id),
        });
    };
    identified_generation(&bytes, generation_id)
}

/// Resolves capability revocation from one exact authenticated head.
///
/// The receipt is reauthenticated against `store` before any immutable read, so
/// an [`AuthenticatedHead`] minted by another backend cannot route this lookup.
/// Tenant remains explicit because repository IDs are tenant-scoped and the
/// authority head intentionally does not duplicate tenant identity.
pub fn read_head_selected_capability_revocation_generation<S>(
    store: &S,
    tenant_id: TenantId,
    authenticated: &AuthenticatedHead,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    let authenticated = store.authenticate_head_receipt(authenticated.receipt())?;
    let head = authenticated.body()?;
    let configuration =
        read_repository_incarnation_configuration(store, &head.configuration_root)?;
    let root = configuration
        .capability_revocation_root
        .ok_or(CapabilityRevocationAuthorityFailure::ConfigurationHasNoRevocationRoot)?;
    let generation_id = capability_revocation_generation_id_from_root(&root);
    let selected = read_capability_revocation_generation_by_id(store, generation_id)?;
    validate_selected_generation(
        &selected,
        tenant_id,
        head.repository_id,
        configuration.repository_incarnation_id,
        head.policy_epoch,
    )?;
    Ok(selected)
}

/// Production asynchronous twin of
/// [`read_head_selected_capability_revocation_generation`].
pub async fn read_head_selected_capability_revocation_generation_async<S>(
    store: &S,
    cx: &S::Context,
    tenant_id: TenantId,
    authenticated: &AuthenticatedHead,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let authenticated = store
        .authenticate_head_receipt(cx, authenticated.receipt())
        .await?;
    let head = authenticated.body()?;
    let configuration = read_repository_incarnation_configuration_async(
        store,
        cx,
        &head.configuration_root,
    )
    .await?;
    let root = configuration
        .capability_revocation_root
        .ok_or(CapabilityRevocationAuthorityFailure::ConfigurationHasNoRevocationRoot)?;
    let generation_id = capability_revocation_generation_id_from_root(&root);
    let selected =
        read_capability_revocation_generation_by_id_async(store, cx, generation_id).await?;
    validate_selected_generation(
        &selected,
        tenant_id,
        head.repository_id,
        configuration.repository_incarnation_id,
        head.policy_epoch,
    )?;
    Ok(selected)
}

fn identified_generation(
    bytes: &[u8],
    expected: CapabilityRevocationGenerationId,
) -> Result<CapabilityRevocationGenerationRead, CapabilityRevocationAuthorityFailure> {
    let body: CapabilityRevocationGenerationBody =
        decode_body(bytes, REVOCATION_DECODE_LIMITS)?;
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

fn validate_selected_generation(
    selected: &CapabilityRevocationGenerationRead,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    repository_incarnation_id: RepositoryIncarnationId,
    policy_epoch: PolicyEpoch,
) -> Result<(), CapabilityRevocationAuthorityFailure> {
    let body = selected.body();
    if body.tenant_id != tenant_id {
        return Err(CapabilityRevocationAuthorityFailure::TenantMismatch {
            expected: tenant_id,
            observed: body.tenant_id,
        });
    }
    if body.repository_id != repository_id {
        return Err(CapabilityRevocationAuthorityFailure::RepositoryMismatch {
            expected: repository_id,
            observed: body.repository_id,
        });
    }
    if body.repository_incarnation_id != repository_incarnation_id {
        return Err(CapabilityRevocationAuthorityFailure::IncarnationMismatch {
            expected: repository_incarnation_id,
            observed: body.repository_incarnation_id,
        });
    }
    if body.policy_epoch != policy_epoch {
        return Err(CapabilityRevocationAuthorityFailure::PolicyEpochMismatch {
            expected: policy_epoch,
            observed: body.policy_epoch,
        });
    }
    Ok(())
}

fn validate_revoked_ids(
    revoked_capability_ids: &mut Vec<[u8; 16]>,
) -> Result<(), CapabilityRevocationBodyRefusal> {
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
    Ok(())
}

fn too_many_codec_refusal(observed: usize) -> CodecRefusal {
    CodecRefusal::ValueUnrepresentable {
        field: "capability_revocation.revoked_capability_ids",
        observed: u64::try_from(observed).unwrap_or(u64::MAX),
        limit: u64::try_from(MAX_CAPABILITY_REVOCATION_ENTRIES).unwrap_or(u64::MAX),
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
