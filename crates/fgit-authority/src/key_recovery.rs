//! Recover an authority decision using the original client key, not its inputs.
//!
//! Reading a lost-response outcome must not re-seal, re-stage, or execute the
//! mutation. The immutable key binding supplies a candidate identity; only a
//! strictly checked seal can bind it to this repository, principal and key.
//! The existing stream/accelerator resolver supplies the terminal decision.
//! Missing observations are explicitly nonterminal, never proof of non-commit.

use fgit_codec::{DecodeLimits, Decoder, Encoder, TransactionSealBody, decode_body, encode_body};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, PrincipalId, RefusalCode, RepositoryId, TenantId,
    TransactionSealId, TxId,
};

use crate::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityStore, HeadKey,
    HeadRead, HeadReadReceipt, IdempotencyKey, ImmutableRead, OutcomeFailure, OutcomeLookup,
    SealFailure, TxIdPreimage, canonical_body_id, derive_tx_id, idempotency_binding_key,
    resolve_outcome, resolve_outcome_async, seal_key,
};

const MAX_BINDING_BYTES: usize = 256;
const MAX_SEAL_BYTES: usize = 8192;
const LIMITS: DecodeLimits = DecodeLimits {
    frame_bytes: MAX_SEAL_BYTES as u64,
    // Canonical framing reads the entire payload as a byte string. Keep that
    // within the existing frame ceiling; binding_identity separately enforces
    // the smaller binding limit and typed digest decoders enforce their widths.
    byte_string_bytes: MAX_SEAL_BYTES as u64,
    elements: 8,
    depth: 8,
};

/// Scope independently authenticated by the gateway or local operator.
/// Knowing somebody else's key is not authorization to query their scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryScope {
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub principal_id: PrincipalId,
}

/// One verified seal and the result of the existing authority outcome resolver.
/// Fields are private: clients cannot construct a recovered result from a row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredRequest {
    seal: TransactionSealBody,
    seal_id: TransactionSealId,
    outcome: OutcomeLookup,
}

impl RecoveredRequest {
    #[must_use]
    pub const fn seal(&self) -> &TransactionSealBody { &self.seal }
    #[must_use]
    pub const fn seal_id(&self) -> TransactionSealId { self.seal_id }
    #[must_use]
    pub const fn tx_id(&self) -> TxId { self.seal.tx_id }
    #[must_use]
    pub const fn outcome(&self) -> OutcomeLookup { self.outcome }
}

/// Observations, not instructions to retry with a different key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestRecovery {
    /// The scoped binding was absent when read. A concurrent request can still
    /// create it; a wrong key or scope produces the same observation.
    KeyNotObserved,
    /// A binding was present but its seal was not observed. This includes the
    /// interval between binding and sealing and is NOT an abort certificate.
    /// The unverified binding's target is deliberately not disclosed.
    SealNotObserved,
    /// The scope/key/identity matched a canonical seal. Only `Decided` here is
    /// a terminal decision; `Undecided` can change immediately after the read.
    Recovered(Box<RecoveredRequest>),
}

impl RequestRecovery {
    #[must_use]
    pub fn terminal(&self) -> Option<crate::TerminalOutcome> {
        match self {
            Self::Recovered(request) => match request.outcome {
                OutcomeLookup::Decided(terminal) => Some(terminal),
                OutcomeLookup::Undecided => None,
            },
            Self::KeyNotObserved | Self::SealNotObserved => None,
        }
    }
}

/// Infrastructure failure never masquerades as an absent key or undecided request.
#[derive(Debug)]
pub enum RecoveryFailure {
    AuthenticationRequired,
    Authority(AuthorityFailure),
    Seal(Box<SealFailure>),
    Outcome(Box<OutcomeFailure>),
    Codec(fgit_codec::CodecRefusal),
    HeadNotObserved,
    Integrity { field: &'static str },
    BoundExceeded { field: &'static str, limit: usize, observed: usize },
    Interrupted(RefusalCode),
}

impl std::fmt::Display for RecoveryFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationRequired => out.write_str("transaction recovery requires an authenticated principal"),
            Self::Authority(error) => write!(out, "transaction recovery authority: {error}"),
            Self::Seal(error) => write!(out, "transaction recovery seal: {error}"),
            Self::Outcome(error) => write!(out, "transaction recovery outcome: {error}"),
            Self::Codec(error) => write!(out, "transaction recovery codec: {error}"),
            Self::HeadNotObserved => out.write_str("transaction recovery did not observe a repository head"),
            Self::Integrity { field } => write!(out, "transaction recovery binding mismatch: {field}"),
            Self::BoundExceeded { field, limit, observed } => write!(out,
                "transaction recovery {field} is {observed} bytes, exceeds {limit}"),
            Self::Interrupted(code) => write!(out, "transaction recovery interrupted: {code:?}"),
        }
    }
}
impl std::error::Error for RecoveryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Seal(error) => Some(error.as_ref()),
            Self::Outcome(error) => Some(error.as_ref()),
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}
impl From<AuthorityFailure> for RecoveryFailure {
    fn from(error: AuthorityFailure) -> Self { Self::Authority(error) }
}
impl From<SealFailure> for RecoveryFailure {
    fn from(error: SealFailure) -> Self { Self::Seal(Box::new(error)) }
}
impl From<OutcomeFailure> for RecoveryFailure {
    fn from(error: OutcomeFailure) -> Self { Self::Outcome(Box::new(error)) }
}
impl From<fgit_codec::CodecRefusal> for RecoveryFailure {
    fn from(error: fgit_codec::CodecRefusal) -> Self { Self::Codec(error) }
}

/// Read-only recovery on the synchronous reference/verification surface.
///
/// The caller authenticates `scope`. No original command, bundle, workspace,
/// request text or transaction identity is required. No mutation is attempted.
/// The repository head is authenticated even for a negative binding observation.
/// Outcomes use the existing resolver, including its accelerator cross-check.
/// No single-snapshot claim is made for the several nonterminal observations.
pub fn recover_request<S, C>(
    store: &S, head_key: &HeadKey, scope: RecoveryScope, key: &IdempotencyKey,
    checkpoint: &C,
) -> Result<RequestRecovery, RecoveryFailure>
where S: AuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + Sync,
{
    check(checkpoint)?;
    let receipt = head_receipt(store.read_head(head_key)?)?;
    check(checkpoint)?;
    let authenticated = store.authenticate_head_receipt(&receipt)?;
    check_head(&receipt, &authenticated, store.instance_id(), head_key, scope)?;
    check(checkpoint)?;
    let slot = idempotency_binding_key(scope.tenant_id, scope.repository_id, scope.principal_id, key)?;
    let binding = store.read_immutable(&slot)?;
    check(checkpoint)?;
    let Some(tx_id) = binding_identity(binding)? else { return Ok(RequestRecovery::KeyNotObserved); };
    let slot = seal_key(scope.tenant_id, scope.repository_id, tx_id)?;
    let stored = store.read_immutable(&slot)?;
    check(checkpoint)?;
    let Some((seal, seal_id)) = checked_seal(stored, scope, key, tx_id)? else {
        return Ok(RequestRecovery::SealNotObserved);
    };
    check(checkpoint)?;
    let outcome = resolve_outcome(store, head_key, scope.tenant_id, scope.repository_id, tx_id)?;
    finish(seal, seal_id, outcome, checkpoint)
}

/// Production twin, awaiting only the caller's authority and runtime context.
/// Pure decoding, scope checks, result classification and limits are shared
/// with the synchronous surface. There is no detached task or retrying writer.
pub async fn recover_request_async<S, C>(
    store: &S, cx: &S::Context, head_key: &HeadKey, scope: RecoveryScope,
    key: &IdempotencyKey, checkpoint: &C,
) -> Result<RequestRecovery, RecoveryFailure>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + Sync,
{
    check(checkpoint)?;
    let receipt = head_receipt(store.read_head(cx, head_key).await?)?;
    check(checkpoint)?;
    let authenticated = store.authenticate_head_receipt(cx, &receipt).await?;
    check_head(&receipt, &authenticated, store.instance_id(), head_key, scope)?;
    check(checkpoint)?;
    let slot = idempotency_binding_key(scope.tenant_id, scope.repository_id, scope.principal_id, key)?;
    let binding = store.read_immutable(cx, &slot).await?;
    check(checkpoint)?;
    let Some(tx_id) = binding_identity(binding)? else { return Ok(RequestRecovery::KeyNotObserved); };
    let slot = seal_key(scope.tenant_id, scope.repository_id, tx_id)?;
    let stored = store.read_immutable(cx, &slot).await?;
    check(checkpoint)?;
    let Some((seal, seal_id)) = checked_seal(stored, scope, key, tx_id)? else {
        return Ok(RequestRecovery::SealNotObserved);
    };
    check(checkpoint)?;
    let outcome = resolve_outcome_async(store, cx, head_key, scope.tenant_id, scope.repository_id, tx_id).await?;
    finish(seal, seal_id, outcome, checkpoint)
}

fn check<C: Fn() -> Result<(), RefusalCode>>(checkpoint: &C) -> Result<(), RecoveryFailure> {
    checkpoint().map_err(RecoveryFailure::Interrupted)
}
fn bounded(bytes: &[u8], limit: usize, field: &'static str) -> Result<(), RecoveryFailure> {
    if bytes.len() > limit {
        return Err(RecoveryFailure::BoundExceeded { field, limit, observed: bytes.len() });
    }
    Ok(())
}
fn integrity(field: &'static str) -> RecoveryFailure { RecoveryFailure::Integrity { field } }
fn head_receipt(read: HeadRead) -> Result<HeadReadReceipt, RecoveryFailure> {
    match read { HeadRead::Present(receipt) => Ok(receipt), HeadRead::Absent => Err(RecoveryFailure::HeadNotObserved) }
}
fn check_head(
    receipt: &HeadReadReceipt, authenticated: &AuthenticatedHead, instance: crate::StoreInstanceId,
    key: &HeadKey, scope: RecoveryScope,
) -> Result<(), RecoveryFailure> {
    if receipt.key() != key || authenticated.receipt() != receipt || authenticated.verified_against() != instance {
        return Err(integrity("authenticated head receipt"));
    }
    bounded(receipt.body(), MAX_SEAL_BYTES, "head")?;
    let body: fgit_codec::RepositoryAuthorityHeadBody = decode_body(receipt.body(), LIMITS)?;
    if body.repository_id != scope.repository_id { return Err(integrity("head repository")); }
    if body.generation != receipt.generation() { return Err(integrity("head generation")); }
    Ok(())
}
fn binding_identity(read: ImmutableRead) -> Result<Option<TxId>, RecoveryFailure> {
    let ImmutableRead::Present(bytes) = read else { return Ok(None); };
    bounded(&bytes, MAX_BINDING_BYTES, "idempotency binding")?;
    let mut input = Decoder::new(&bytes, LIMITS);
    let id = input.read_internal_object_id()?;
    input.finish()?;
    let tx_id = TxId::from_internal_object_id(id).map_err(|_| integrity("binding identity domain"))?;
    let mut out = Encoder::new();
    out.write_internal_object_id(tx_id.as_internal_object_id())?;
    if out.into_bytes() != bytes { return Err(integrity("canonical binding bytes")); }
    Ok(Some(tx_id))
}
fn checked_seal(
    read: ImmutableRead, scope: RecoveryScope, key: &IdempotencyKey, tx_id: TxId,
) -> Result<Option<(TransactionSealBody, TransactionSealId)>, RecoveryFailure> {
    let ImmutableRead::Present(bytes) = read else { return Ok(None); };
    bounded(&bytes, MAX_SEAL_BYTES, "seal")?;
    let seal: TransactionSealBody = decode_body(&bytes, LIMITS)?;
    if seal.tenant_id != scope.tenant_id { return Err(integrity("seal tenant")); }
    if seal.repository_id != scope.repository_id { return Err(integrity("seal repository")); }
    if seal.authenticated_principal_id != scope.principal_id { return Err(integrity("seal principal")); }
    if seal.idempotency_key_digest != key.digest() { return Err(integrity("seal idempotency key")); }
    if seal.tx_id != tx_id { return Err(integrity("seal transaction")); }
    let derived = derive_tx_id(&TxIdPreimage {
        tenant_id: scope.tenant_id, repository_id: scope.repository_id,
        authenticated_principal_id: scope.principal_id, idempotency_key: key.clone(),
        canonical_request_digest: seal.canonical_request_digest,
    }).map_err(SealFailure::from)?;
    if derived != tx_id { return Err(integrity("derived transaction identity")); }
    if encode_body(&seal)? != bytes { return Err(integrity("canonical seal bytes")); }
    let id = canonical_body_id(IdentityDomain::TransactionSeal, CANONICAL_CODEC_VERSION, &seal)
        .map_err(SealFailure::from)?;
    let seal_id = TransactionSealId::from_internal_object_id(id).map_err(|_| integrity("seal identity domain"))?;
    Ok(Some((seal, seal_id)))
}
fn finish<C: Fn() -> Result<(), RefusalCode>>(
    seal: TransactionSealBody, seal_id: TransactionSealId, outcome: OutcomeLookup, checkpoint: &C,
) -> Result<RequestRecovery, RecoveryFailure> {
    // A known terminal outcome survives cancellation arriving after resolution.
    // An undecided observation, in contrast, is never returned after exhaustion.
    if matches!(outcome, OutcomeLookup::Undecided) { check(checkpoint)?; }
    Ok(RequestRecovery::Recovered(Box::new(RecoveredRequest { seal, seal_id, outcome })))
}

#[cfg(test)]
mod tests;
