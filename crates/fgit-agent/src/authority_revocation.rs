//! Canonical authority-store adapter for effect-time capability revocation.
//!
//! [`crate::CapabilityRevocationReceipt`] deliberately admits observations from
//! a storage-neutral reader so tests and future service adapters share one
//! freshness and complete-run validation boundary.  This module supplies the
//! production repository-authority reader:
//!
//! ```text
//! IntentRun + exact AuthorityReadReceipt
//!     -> validate request before I/O
//!     -> exact AuthenticatedHead equality
//!     -> same-store head reauthentication
//!     -> configuration-2.2 revocation root
//!     -> bounded canonical generation
//!     -> CapabilityRevocationReceipt
//! ```
//!
//! The adapter never accepts a caller-provided revoked set, never lists policy
//! objects, and never treats missing configuration as an empty set.  It also
//! does not bypass the existing receipt constructor: after authority resolution
//! it feeds one request-matched observation through
//! [`crate::read_capability_revocations`], preserving the single implementation
//! of freshness, row bounds, duplicate refusal, run binding, and canonical
//! receipt identity.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityStore,
    CapabilityRevocationAuthorityFailure,
    read_head_selected_capability_revocation_generation,
    read_head_selected_capability_revocation_generation_async,
};
use fgit_types::TenantId;

use crate::effect_authorization::{
    CapabilityRevocationReadAdapterRefusal, CapabilityRevocationReadObservation,
    CapabilityRevocationReadRefusal, CapabilityRevocationReadRequest,
    CapabilityRevocationReadRequestId, CapabilityRevocationReader, CapabilityRevocationReceipt,
    MAX_CAPABILITY_REVOCATIONS, read_capability_revocations,
};
use crate::{
    AuthorityReadReceipt, CapabilityId, IntentRun, LogicalTime, ProtocolRefusal,
};

/// Stable identity of the canonical authority-generation reader profile.
///
/// This is an implementation/profile identity, not a capability or authority
/// token.  Its exact bytes enter every admitted revocation-receipt commitment.
pub const AUTHORITY_CAPABILITY_REVOCATION_READER_PROFILE: [u8; 32] =
    *b"fgit.authority.revocations/v1.0\0";

/// Why the canonical authority-to-agent revocation read failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityCapabilityRevocationReadRefusal {
    /// Request construction or final receipt admission failed.
    Read(Box<CapabilityRevocationReadRefusal>),
    /// The authenticated authority/configuration/generation path failed.
    Authority(Box<CapabilityRevocationAuthorityFailure>),
    /// The supplied authenticated head could not become an agent receipt.
    Protocol(Box<ProtocolRefusal>),
    /// The authenticated head and the run carry different exact read events.
    AuthorityReceiptMismatch,
    /// The selected generation used a digest width unsupported by the current
    /// agent receipt wire profile.
    GenerationDigestWidth {
        /// Digest bytes observed.
        observed: usize,
        /// Required fixed width.
        expected: usize,
    },
}

impl fmt::Display for AuthorityCapabilityRevocationReadRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(refusal) => write!(formatter, "revocation read refused: {refusal}"),
            Self::Authority(refusal) => {
                write!(formatter, "canonical revocation authority refused: {refusal}")
            }
            Self::Protocol(refusal) => {
                write!(formatter, "revocation authority receipt refused: {refusal}")
            }
            Self::AuthorityReceiptMismatch => formatter.write_str(
                "the authenticated head differs from the Intent Run authority receipt",
            ),
            Self::GenerationDigestWidth { observed, expected } => write!(
                formatter,
                "revocation generation digest has {observed} bytes, expected {expected}"
            ),
        }
    }
}

impl core::error::Error for AuthorityCapabilityRevocationReadRefusal {}

impl From<CapabilityRevocationReadRefusal> for AuthorityCapabilityRevocationReadRefusal {
    fn from(value: CapabilityRevocationReadRefusal) -> Self {
        Self::Read(Box::new(value))
    }
}

impl From<CapabilityRevocationAuthorityFailure> for AuthorityCapabilityRevocationReadRefusal {
    fn from(value: CapabilityRevocationAuthorityFailure) -> Self {
        Self::Authority(Box::new(value))
    }
}

impl From<ProtocolRefusal> for AuthorityCapabilityRevocationReadRefusal {
    fn from(value: ProtocolRefusal) -> Self {
        Self::Protocol(Box::new(value))
    }
}

/// Reads the exact canonical revocation generation selected by one authenticated
/// head and admits it as an effect-time receipt.
///
/// Request construction happens before any authority-store call.  A zero age,
/// invalid row limit, legacy or substituted run, pre-verification request time,
/// or expired run therefore refuses without touching the backend.
///
/// # Errors
///
/// Returns a typed request/admission, exact-receipt, authority, configuration,
/// generation, or digest-profile refusal.  Missing canonical state is never
/// normalized to an empty revoked set.
pub fn read_authority_capability_revocations<S>(
    store: &S,
    tenant_id: TenantId,
    authenticated: &AuthenticatedHead,
    run: &IntentRun,
    requested_at: LogicalTime,
    max_age: u64,
    max_entries: usize,
) -> Result<CapabilityRevocationReceipt, AuthorityCapabilityRevocationReadRefusal>
where
    S: AuthorityStore + ?Sized,
{
    let authority = run
        .authority_read_receipt()
        .ok_or(CapabilityRevocationReadRefusal::RunAuthorityReceiptRequired)?;
    let request = CapabilityRevocationReadRequest::build(
        authority,
        run,
        requested_at,
        max_age,
        max_entries,
    )?;
    validate_authenticated_head(authority, authenticated)?;

    let generation =
        read_head_selected_capability_revocation_generation(store, tenant_id, authenticated)?;
    admit_generation(authority, run, requested_at, max_age, max_entries, request, &generation)
}

/// Production asynchronous twin of
/// [`read_authority_capability_revocations`].
///
/// The same request and exact-head checks run before the first awaited backend
/// operation.  The authority layer then performs same-store receipt
/// authentication and exact configuration/generation reads through the
/// backend's native asynchronous contract.
pub async fn read_authority_capability_revocations_async<S>(
    store: &S,
    cx: &S::Context,
    tenant_id: TenantId,
    authenticated: &AuthenticatedHead,
    run: &IntentRun,
    requested_at: LogicalTime,
    max_age: u64,
    max_entries: usize,
) -> Result<CapabilityRevocationReceipt, AuthorityCapabilityRevocationReadRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let authority = run
        .authority_read_receipt()
        .ok_or(CapabilityRevocationReadRefusal::RunAuthorityReceiptRequired)?;
    let request = CapabilityRevocationReadRequest::build(
        authority,
        run,
        requested_at,
        max_age,
        max_entries,
    )?;
    validate_authenticated_head(authority, authenticated)?;

    let generation = read_head_selected_capability_revocation_generation_async(
        store,
        cx,
        tenant_id,
        authenticated,
    )
    .await?;
    admit_generation(authority, run, requested_at, max_age, max_entries, request, &generation)
}

fn validate_authenticated_head(
    expected: &AuthorityReadReceipt,
    authenticated: &AuthenticatedHead,
) -> Result<(), AuthorityCapabilityRevocationReadRefusal> {
    let observed = AuthorityReadReceipt::from_authenticated_head(
        authenticated,
        expected.verified_at_logical_time(),
        expected.verifier_profile(),
    )?;
    if &observed != expected {
        return Err(AuthorityCapabilityRevocationReadRefusal::AuthorityReceiptMismatch);
    }
    Ok(())
}

fn admit_generation(
    authority: &AuthorityReadReceipt,
    run: &IntentRun,
    requested_at: LogicalTime,
    max_age: u64,
    max_entries: usize,
    request: CapabilityRevocationReadRequest,
    generation: &fgit_authority::CapabilityRevocationGenerationRead,
) -> Result<CapabilityRevocationReceipt, AuthorityCapabilityRevocationReadRefusal> {
    let observed_rows = generation.body().revoked_capability_ids().len();
    if observed_rows > request.max_entries() as usize
        || observed_rows > MAX_CAPABILITY_REVOCATIONS
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
        AuthorityCapabilityRevocationReadRefusal::GenerationDigestWidth {
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
    let mut reader = PreparedAuthorityRevocationReader {
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
struct PreparedAuthorityRevocationReader {
    expected_request_id: CapabilityRevocationReadRequestId,
    observation: CapabilityRevocationReadObservation,
}

impl CapabilityRevocationReader for PreparedAuthorityRevocationReader {
    fn reader_profile(&self) -> [u8; 32] {
        AUTHORITY_CAPABILITY_REVOCATION_READER_PROFILE
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

const _: () = {
    assert!(size_of::<AuthorityCapabilityRevocationReadRefusal>() <= 128);
};
