//! Canonical effect-time revocations from a current descendant authority head.
//!
//! An Intent Run is intentionally pinned to the exact authority read that
//! opened it.  Revocation checks are different: a high-value effect must observe
//! policy at effect time, and a later canonical head may revoke a capability
//! after the run began.  Generation comparison alone cannot establish that the
//! later head belongs to the same history, while accepting only the original
//! head makes newly published revocations invisible.
//!
//! This module joins those requirements without widening authority:
//!
//! ```text
//! IntentRun historical AuthorityReadReceipt
//!     -> reconstruct and authenticate that exact receipt against this store
//!     -> read and authenticate the current HeadKey
//!     -> bounded exact predecessor walk to the historical head
//!     -> current head-selected capability-revocation generation
//!     -> ordinary bounded CapabilityRevocationReceipt admission
//!     -> one identity binding the admission and ancestry receipts
//! ```
//!
//! The final effect-authorization wrapper binds that combined receipt identity
//! to the ordinary exact-request authorization.  A caller therefore cannot
//! retain the revocation rows while silently dropping the proof that their
//! selecting head descended from the run's authenticated basis.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityHeadAncestryReceipt,
    AuthorityHeadAncestryRefusal, AuthorityStore, CapabilityRevocationAuthorityFailure,
    CapabilityRevocationGenerationRead, HeadKey, HeadReadReceipt, OutcomeFailure,
    read_authority_head_body, read_authority_head_body_async,
    read_current_authority_head_descendant, read_current_authority_head_descendant_async,
    read_head_selected_capability_revocation_generation,
    read_head_selected_capability_revocation_generation_async,
};
use fgit_codec::{CodecRefusal, Encoder, encode_body};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{RepositoryAuthorityHeadId, TenantId};

use crate::{
    AuthorityReadReceipt, CapabilityEffectAuthorization, CapabilityEffectAuthorizationRefusal,
    CapabilityId, CapabilityRevocationReadAdapterRefusal, CapabilityRevocationReadObservation,
    CapabilityRevocationReadRefusal, CapabilityRevocationReadRequest,
    CapabilityRevocationReadRequestId, CapabilityRevocationReader, CapabilityRevocationReceipt,
    CapabilityRevocationReceiptId, EffectRequest, IntentRun, LogicalTime,
    MAX_CAPABILITY_REVOCATIONS, ProtocolRefusal, VerifiedCapabilityChain,
    read_capability_revocations,
};

/// Stable profile identity for the descendant-aware canonical reader.
///
/// Version 1.1 is deliberately distinct from the exact-head-only 1.0 profile:
/// its receipt additionally rests on same-store historical authentication and
/// an exact bounded predecessor proof.
pub const DESCENDANT_AUTHORITY_CAPABILITY_REVOCATION_READER_PROFILE: [u8; 32] =
    *b"fgit.authority.revocations/v1.1\0";

const RECEIPT_DOMAIN: &[u8] = b"frankengit.agent.current-authority-capability-revocations/v1\0";
const AUTHORIZATION_DOMAIN: &[u8] =
    b"frankengit.agent.current-authority-capability-authorization/v1\0";

/// Stable identity of one current-head revocation receipt plus its exact
/// ancestor proof.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CurrentAuthorityCapabilityRevocationReceiptId([u8; 32]);

impl CurrentAuthorityCapabilityRevocationReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CurrentAuthorityCapabilityRevocationReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("current-authority-capability-revocations:")?;
        write_hex(formatter, &self.0)
    }
}

/// Canonical current-policy revocations proven to descend from a run's exact
/// historical authority read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentAuthorityCapabilityRevocationReceipt {
    receipt_id: CurrentAuthorityCapabilityRevocationReceiptId,
    admitted: CapabilityRevocationReceipt,
    ancestry: AuthorityHeadAncestryReceipt,
}

impl CurrentAuthorityCapabilityRevocationReceipt {
    fn try_new(
        admitted: &CapabilityRevocationReceipt,
        ancestry: &AuthorityHeadAncestryReceipt,
    ) -> Result<Self, CodecRefusal> {
        let receipt_id = CurrentAuthorityCapabilityRevocationReceiptId(
            current_revocation_receipt_commitment(admitted.receipt_id(), ancestry.receipt_id())?,
        );
        Ok(Self {
            receipt_id,
            admitted: admitted.clone(),
            ancestry: *ancestry,
        })
    }

    /// Stable identity binding the admitted rows to the exact head path.
    #[must_use]
    pub const fn receipt_id(&self) -> CurrentAuthorityCapabilityRevocationReceiptId {
        self.receipt_id
    }

    /// Identity of the ordinary bounded revocation admission retained inside
    /// this proof.
    #[must_use]
    pub const fn admitted_receipt_id(&self) -> CapabilityRevocationReceiptId {
        self.admitted.receipt_id()
    }

    /// Exact bounded ancestor-to-current-head proof.
    #[must_use]
    pub const fn ancestry(&self) -> AuthorityHeadAncestryReceipt {
        self.ancestry
    }

    /// Current authenticated head that selected the generation.
    #[must_use]
    pub const fn current_authority_head_id(&self) -> RepositoryAuthorityHeadId {
        self.ancestry.descendant_head_id()
    }

    /// Canonically sorted revoked capability identities.
    #[must_use]
    pub fn revoked_capability_ids(&self) -> &[CapabilityId] {
        self.admitted.revoked_capability_ids()
    }

    /// Derived identity of the current selected generation.
    #[must_use]
    pub const fn revocation_generation(&self) -> [u8; 32] {
        self.admitted.revocation_generation()
    }

    /// Logical instant at which the current generation was admitted.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.admitted.observed_at()
    }

    /// Exclusive freshness deadline inherited from the ordinary admission.
    #[must_use]
    pub const fn valid_until(&self) -> LogicalTime {
        self.admitted.valid_until()
    }

    /// Stable reader/decoder/verifier profile retained by the admission.
    #[must_use]
    pub const fn reader_profile(&self) -> [u8; 32] {
        self.admitted.reader_profile()
    }

    /// Whether one capability ancestry identity is revoked.
    #[must_use]
    pub fn is_revoked(&self, capability_id: CapabilityId) -> bool {
        self.admitted.is_revoked(capability_id)
    }

    pub(crate) const fn admitted(&self) -> &CapabilityRevocationReceipt {
        &self.admitted
    }
}

/// Stable identity of an effect authorization that retains current-head
/// ancestry evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CurrentAuthorityCapabilityEffectAuthorizationId([u8; 32]);

impl CurrentAuthorityCapabilityEffectAuthorizationId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CurrentAuthorityCapabilityEffectAuthorizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("current-authority-capability-authorization:")?;
        write_hex(formatter, &self.0)
    }
}

/// One exact high-value effect authorization carrying proof that its revocation
/// generation was selected by a current descendant head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentAuthorityCapabilityEffectAuthorization {
    authorization_id: CurrentAuthorityCapabilityEffectAuthorizationId,
    authorization: CapabilityEffectAuthorization,
    revocation_receipt_id: CurrentAuthorityCapabilityRevocationReceiptId,
}

impl CurrentAuthorityCapabilityEffectAuthorization {
    /// Authorizes one exact request while retaining the current-head ancestry
    /// identity in the returned proof.
    ///
    /// # Errors
    ///
    /// Preserves every ordinary capability, run, request, freshness, revocation,
    /// quota, and framing refusal from [`CapabilityEffectAuthorization`].
    pub fn authorize(
        run: &IntentRun,
        chain: &VerifiedCapabilityChain,
        revocations: &CurrentAuthorityCapabilityRevocationReceipt,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<Self, CapabilityEffectAuthorizationRefusal> {
        let authorization = CapabilityEffectAuthorization::authorize(
            run,
            chain,
            revocations.admitted(),
            now,
            request,
        )?;
        let authorization_id = CurrentAuthorityCapabilityEffectAuthorizationId(
            current_effect_authorization_commitment(
                authorization.authorization_id().as_bytes(),
                revocations.receipt_id.as_bytes(),
            )
            .map_err(CapabilityEffectAuthorizationRefusal::Codec)?,
        );
        Ok(Self {
            authorization_id,
            authorization,
            revocation_receipt_id: revocations.receipt_id,
        })
    }

    /// Stable identity binding ordinary authorization to current-head policy
    /// ancestry.
    #[must_use]
    pub const fn authorization_id(self) -> CurrentAuthorityCapabilityEffectAuthorizationId {
        self.authorization_id
    }

    /// Ordinary exact-request authorization retained inside this proof.
    #[must_use]
    pub const fn authorization(self) -> CapabilityEffectAuthorization {
        self.authorization
    }

    /// Current-head revocation proof used for this authorization.
    #[must_use]
    pub const fn revocation_receipt_id(self) -> CurrentAuthorityCapabilityRevocationReceiptId {
        self.revocation_receipt_id
    }
}

/// Why a current descendant-head revocation read failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentAuthorityCapabilityRevocationReadRefusal {
    /// Request construction or ordinary receipt admission failed.
    Read(Box<CapabilityRevocationReadRefusal>),
    /// The historical head body could not be resolved by exact identity.
    HistoricalHead(Box<OutcomeFailure>),
    /// The reconstructed historical receipt was not issued by this exact store
    /// and head slot.
    HistoricalAuthentication(Box<AuthorityFailure>),
    /// The reconstructed authenticated head could not become the exact agent
    /// receipt retained by the Intent Run.
    HistoricalProtocol(Box<ProtocolRefusal>),
    /// The reconstructed read event differs from the run's complete read event.
    HistoricalReceiptMismatch,
    /// The current head could not be proved an exact descendant.
    Ancestry(Box<AuthorityHeadAncestryRefusal>),
    /// Current configuration or selected generation resolution failed.
    Authority(Box<CapabilityRevocationAuthorityFailure>),
    /// Selected generation digest width is unsupported by the current agent
    /// receipt profile.
    GenerationDigestWidth {
        /// Digest bytes observed.
        observed: usize,
        /// Required fixed width.
        expected: usize,
    },
    /// Canonical framing failed.
    Codec(Box<CodecRefusal>),
}

impl fmt::Display for CurrentAuthorityCapabilityRevocationReadRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(refusal) => write!(formatter, "current revocation read refused: {refusal}"),
            Self::HistoricalHead(refusal) => {
                write!(formatter, "historical authority head refused: {refusal}")
            }
            Self::HistoricalAuthentication(refusal) => write!(
                formatter,
                "historical authority receipt was not issued by this store and slot: {refusal}"
            ),
            Self::HistoricalProtocol(refusal) => {
                write!(formatter, "historical agent receipt refused: {refusal}")
            }
            Self::HistoricalReceiptMismatch => formatter.write_str(
                "the same-store historical head does not reproduce the Intent Run read event",
            ),
            Self::Ancestry(refusal) => {
                write!(formatter, "current authority ancestry refused: {refusal}")
            }
            Self::Authority(refusal) => {
                write!(
                    formatter,
                    "current canonical revocation state refused: {refusal}"
                )
            }
            Self::GenerationDigestWidth { observed, expected } => write!(
                formatter,
                "current revocation generation digest has {observed} bytes, expected {expected}"
            ),
            Self::Codec(refusal) => {
                write!(formatter, "current revocation framing refused: {refusal}")
            }
        }
    }
}

impl core::error::Error for CurrentAuthorityCapabilityRevocationReadRefusal {}

impl From<CapabilityRevocationReadRefusal> for CurrentAuthorityCapabilityRevocationReadRefusal {
    fn from(value: CapabilityRevocationReadRefusal) -> Self {
        Self::Read(Box::new(value))
    }
}

impl From<AuthorityHeadAncestryRefusal> for CurrentAuthorityCapabilityRevocationReadRefusal {
    fn from(value: AuthorityHeadAncestryRefusal) -> Self {
        Self::Ancestry(Box::new(value))
    }
}

impl From<CapabilityRevocationAuthorityFailure>
    for CurrentAuthorityCapabilityRevocationReadRefusal
{
    fn from(value: CapabilityRevocationAuthorityFailure) -> Self {
        Self::Authority(Box::new(value))
    }
}

impl From<CodecRefusal> for CurrentAuthorityCapabilityRevocationReadRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(Box::new(value))
    }
}

/// Reads canonical revocations from the current head only after proving that
/// head descends from the Intent Run's exact same-store historical read.
///
/// Request validation precedes every store operation.  The historical read is
/// reconstructed from its head identity, generation, opaque token, and the
/// caller-supplied canonical head key, then authenticated by the store that will
/// serve the current read.  Only after that succeeds is the bounded predecessor
/// walk performed.
///
/// # Errors
///
/// Missing, forged, cross-store, cross-slot, forked, discontinuous, excessive,
/// unsupported-configuration, malformed-generation, stale-run, and row-bound
/// states are all typed refusals.  None is normalized to an empty revoked set.
pub fn read_current_authority_capability_revocations<S>(
    store: &S,
    tenant_id: TenantId,
    head_key: &HeadKey,
    run: &IntentRun,
    requested_at: LogicalTime,
    max_age: u64,
    max_entries: usize,
    max_ancestry_hops: usize,
) -> Result<
    CurrentAuthorityCapabilityRevocationReceipt,
    CurrentAuthorityCapabilityRevocationReadRefusal,
>
where
    S: AuthorityStore + ?Sized,
{
    let authority = run
        .authority_read_receipt()
        .ok_or(CapabilityRevocationReadRefusal::RunAuthorityReceiptRequired)?;
    let request =
        CapabilityRevocationReadRequest::build(authority, run, requested_at, max_age, max_entries)?;

    let historical = authenticate_historical_sync(store, head_key, authority)?;
    validate_historical_receipt(authority, &historical)?;

    let current = read_current_authority_head_descendant(
        store,
        head_key,
        authority.repository_id(),
        authority.authority_head_id(),
        authority.authority_head_generation(),
        max_ancestry_hops,
    )?;
    let generation = read_head_selected_capability_revocation_generation(
        store,
        tenant_id,
        current.authenticated(),
    )?;
    let admitted = admit_generation(
        authority,
        run,
        requested_at,
        max_age,
        max_entries,
        &request,
        &generation,
    )?;
    Ok(CurrentAuthorityCapabilityRevocationReceipt::try_new(
        &admitted,
        &current.ancestry(),
    )?)
}

/// Production asynchronous twin of
/// [`read_current_authority_capability_revocations`].
///
/// Request validation still completes before the first awaited store operation;
/// all historical authentication, current-head authentication, ancestry reads,
/// and selected-generation reads use the backend's native async surface.
pub async fn read_current_authority_capability_revocations_async<S>(
    store: &S,
    cx: &S::Context,
    tenant_id: TenantId,
    head_key: &HeadKey,
    run: &IntentRun,
    requested_at: LogicalTime,
    max_age: u64,
    max_entries: usize,
    max_ancestry_hops: usize,
) -> Result<
    CurrentAuthorityCapabilityRevocationReceipt,
    CurrentAuthorityCapabilityRevocationReadRefusal,
>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let authority = run
        .authority_read_receipt()
        .ok_or(CapabilityRevocationReadRefusal::RunAuthorityReceiptRequired)?;
    let request =
        CapabilityRevocationReadRequest::build(authority, run, requested_at, max_age, max_entries)?;

    let historical = authenticate_historical_async(store, cx, head_key, authority).await?;
    validate_historical_receipt(authority, &historical)?;

    let current = read_current_authority_head_descendant_async(
        store,
        cx,
        head_key,
        authority.repository_id(),
        authority.authority_head_id(),
        authority.authority_head_generation(),
        max_ancestry_hops,
    )
    .await?;
    let generation = read_head_selected_capability_revocation_generation_async(
        store,
        cx,
        tenant_id,
        current.authenticated(),
    )
    .await?;
    let admitted = admit_generation(
        authority,
        run,
        requested_at,
        max_age,
        max_entries,
        &request,
        &generation,
    )?;
    Ok(CurrentAuthorityCapabilityRevocationReceipt::try_new(
        &admitted,
        &current.ancestry(),
    )?)
}

fn authenticate_historical_sync<S>(
    store: &S,
    head_key: &HeadKey,
    authority: &AuthorityReadReceipt,
) -> Result<AuthenticatedHead, CurrentAuthorityCapabilityRevocationReadRefusal>
where
    S: AuthorityStore + ?Sized,
{
    let body =
        read_authority_head_body(store, authority.authority_head_id()).map_err(|failure| {
            CurrentAuthorityCapabilityRevocationReadRefusal::HistoricalHead(Box::new(failure))
        })?;
    let receipt = HeadReadReceipt::new(
        head_key.clone(),
        authority.backend_version_token(),
        authority.authority_head_generation(),
        encode_body(&body)?,
    );
    store
        .authenticate_head_receipt(&receipt)
        .map_err(|failure| {
            CurrentAuthorityCapabilityRevocationReadRefusal::HistoricalAuthentication(Box::new(
                failure,
            ))
        })
}

async fn authenticate_historical_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    authority: &AuthorityReadReceipt,
) -> Result<AuthenticatedHead, CurrentAuthorityCapabilityRevocationReadRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let body = read_authority_head_body_async(store, cx, authority.authority_head_id())
        .await
        .map_err(|failure| {
            CurrentAuthorityCapabilityRevocationReadRefusal::HistoricalHead(Box::new(failure))
        })?;
    let receipt = HeadReadReceipt::new(
        head_key.clone(),
        authority.backend_version_token(),
        authority.authority_head_generation(),
        encode_body(&body)?,
    );
    store
        .authenticate_head_receipt(cx, &receipt)
        .await
        .map_err(|failure| {
            CurrentAuthorityCapabilityRevocationReadRefusal::HistoricalAuthentication(Box::new(
                failure,
            ))
        })
}

fn validate_historical_receipt(
    expected: &AuthorityReadReceipt,
    authenticated: &AuthenticatedHead,
) -> Result<(), CurrentAuthorityCapabilityRevocationReadRefusal> {
    let observed = AuthorityReadReceipt::from_authenticated_head(
        authenticated,
        expected.verified_at_logical_time(),
        expected.verifier_profile(),
    )
    .map_err(|refusal| {
        CurrentAuthorityCapabilityRevocationReadRefusal::HistoricalProtocol(Box::new(refusal))
    })?;
    if &observed != expected {
        return Err(CurrentAuthorityCapabilityRevocationReadRefusal::HistoricalReceiptMismatch);
    }
    Ok(())
}

fn admit_generation(
    authority: &AuthorityReadReceipt,
    run: &IntentRun,
    requested_at: LogicalTime,
    max_age: u64,
    max_entries: usize,
    request: &CapabilityRevocationReadRequest,
    generation: &CapabilityRevocationGenerationRead,
) -> Result<CapabilityRevocationReceipt, CurrentAuthorityCapabilityRevocationReadRefusal> {
    let observed_rows = generation.body().revoked_capability_ids().len();
    if observed_rows > request.max_entries() as usize || observed_rows > MAX_CAPABILITY_REVOCATIONS
    {
        return Err(CapabilityRevocationReadRefusal::TooManyRevocations {
            observed: observed_rows,
            request_limit: request.max_entries(),
            hard_limit: MAX_CAPABILITY_REVOCATIONS,
        }
        .into());
    }

    let generation_root = generation.generation_root();
    let generation_bytes = generation_root.bytes().as_bytes();
    let revocation_generation: [u8; 32] = generation_bytes.try_into().map_err(|_| {
        CurrentAuthorityCapabilityRevocationReadRefusal::GenerationDigestWidth {
            observed: generation_bytes.len(),
            expected: 32,
        }
    })?;
    let revoked_capability_ids = generation
        .body()
        .revoked_capability_ids()
        .iter()
        .copied()
        .map(|bytes| CapabilityId::new(u128::from_be_bytes(bytes)))
        .collect();
    let observation = CapabilityRevocationReadObservation::new(
        request.request_id(),
        revocation_generation,
        requested_at,
        revoked_capability_ids,
        generation.body().evidence_root(),
    );
    let mut reader = PreparedDescendantAuthorityRevocationReader {
        expected_request_id: request.request_id(),
        observation,
    };
    Ok(read_capability_revocations(
        &mut reader,
        authority,
        run,
        requested_at,
        max_age,
        max_entries,
    )?)
}

#[derive(Clone, Debug)]
struct PreparedDescendantAuthorityRevocationReader {
    expected_request_id: CapabilityRevocationReadRequestId,
    observation: CapabilityRevocationReadObservation,
}

impl CapabilityRevocationReader for PreparedDescendantAuthorityRevocationReader {
    fn reader_profile(&self) -> [u8; 32] {
        DESCENDANT_AUTHORITY_CAPABILITY_REVOCATION_READER_PROFILE
    }

    fn read(
        &mut self,
        request: &CapabilityRevocationReadRequest,
    ) -> Result<CapabilityRevocationReadObservation, CapabilityRevocationReadAdapterRefusal> {
        if request.request_id() != self.expected_request_id {
            return Err(CapabilityRevocationReadAdapterRefusal::Invalid {
                evidence_root: self.observation.evidence_root(),
            });
        }
        Ok(self.observation.clone())
    }
}

fn current_revocation_receipt_commitment(
    admitted_receipt_id: CapabilityRevocationReceiptId,
    ancestry_receipt_id: fgit_authority::AuthorityHeadAncestryReceiptId,
) -> Result<[u8; 32], CodecRefusal> {
    let mut encoder = Encoder::with_capacity(160);
    encoder.write_bytes(
        "current_authority_revocation_receipt_domain",
        RECEIPT_DOMAIN,
    )?;
    encoder.write_raw(admitted_receipt_id.as_bytes());
    encoder.write_raw(ancestry_receipt_id.as_bytes());
    Ok(hash(&encoder.into_bytes()))
}

fn current_effect_authorization_commitment(
    authorization_id: &[u8; 32],
    revocation_receipt_id: &[u8; 32],
) -> Result<[u8; 32], CodecRefusal> {
    let mut encoder = Encoder::with_capacity(160);
    encoder.write_bytes(
        "current_authority_effect_authorization_domain",
        AUTHORIZATION_DOMAIN,
    )?;
    encoder.write_raw(authorization_id);
    encoder.write_raw(revocation_receipt_id);
    Ok(hash(&encoder.into_bytes()))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

const _: () = {
    assert!(size_of::<CurrentAuthorityCapabilityRevocationReadRefusal>() <= 128);
};
