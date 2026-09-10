//! Canonical compiled-policy storage on the existing authority object store.
//!
//! The registered policy-snapshot domain and ordinary immutable body keys are
//! reused. No second database, ambient configuration or fallback policy exists.
//! Staging is NOT activation: the caller must obtain the requested policy ID
//! from authenticated configuration before using a returned verdict to decide
//! an operation. In particular, hidden-ref policy roots are not policy IDs.

use fgit_authority::{
    AsyncAuthorityStore, AuthorityFailure, AuthorityStore, ImmutableRead, PutOutcome,
    OutcomeFailure, body_key_for_id,
};
use fgit_codec::{CodecRefusal, DecodeLimits};
use fgit_policy::{PolicyCompileRefusal, PolicyInputRoot, PolicySnapshot, PolicySnapshotId};
use fgit_types::RefusalCode;

use super::{PolicySourceRefusal, ProtectionVerdict, SubjectCodeMap, evaluate_snapshot};

/// A finite input profile, checked before codec work. The store independently
/// bounds the allocation required to return one immutable value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyStoreLimits {
    pub frame_bytes: u64,
    pub byte_string_bytes: u64,
    pub elements: u64,
    pub depth: u32,
}
impl Default for PolicyStoreLimits {
    fn default() -> Self {
        Self { frame_bytes: 1024 * 1024, byte_string_bytes: 64 * 1024, elements: 4096, depth: 32 }
    }
}
impl PolicyStoreLimits {
    fn decode(self) -> Result<DecodeLimits, PolicyStoreError> {
        let ceiling = Self::default();
        if self.frame_bytes == 0 || self.frame_bytes > ceiling.frame_bytes
            || self.byte_string_bytes == 0 || self.byte_string_bytes > ceiling.byte_string_bytes
            || self.elements == 0 || self.elements > ceiling.elements
            || self.depth == 0 || self.depth > ceiling.depth
        { return Err(PolicyStoreError::InvalidLimits); }
        Ok(DecodeLimits { frame_bytes: self.frame_bytes, byte_string_bytes: self.byte_string_bytes,
            elements: self.elements, depth: self.depth })
    }
}

/// The operation whose storage response failed. An ambiguous staging failure
/// is not proof of absence; retry recovery may read the exact immutable key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyStoreOperation { Read, Stage }

#[derive(Debug)]
pub enum PolicyStoreError {
    InvalidLimits,
    FrameTooLarge { bytes: usize, limit: u64 },
    Stopped(RefusalCode),
    Compile(Box<PolicyCompileRefusal>),
    Codec(Box<CodecRefusal>),
    Key(Box<OutcomeFailure>),
    Authority { operation: PolicyStoreOperation, failure: Box<AuthorityFailure> },
    Missing { requested: Box<PolicySnapshotId> },
    IdentityMismatch { requested: Box<PolicySnapshotId>, observed: Box<PolicySnapshotId> },
    NonCanonical { id: Box<PolicySnapshotId> },
    ConflictingSlot { id: Box<PolicySnapshotId> },
    Evaluation(PolicySourceRefusal),
}
impl std::fmt::Display for PolicyStoreError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => out.write_str("invalid compiled-policy storage limits"),
            Self::FrameTooLarge { bytes, limit } => write!(out, "policy frame {bytes} exceeds {limit} bytes"),
            Self::Stopped(code) => write!(out, "policy work stopped: {code:?}"),
            Self::Compile(error) => write!(out, "policy compilation: {error}"),
            Self::Codec(error) => write!(out, "policy codec: {error}"),
            Self::Key(error) => write!(out, "policy immutable key: {error}"),
            Self::Authority { operation, failure } => write!(out, "policy {operation:?}: {failure}"),
            Self::Missing { requested } => write!(out, "selected policy is missing: {requested}"),
            Self::IdentityMismatch { requested, observed } => write!(out, "policy mismatch: requested {requested}, received {observed}"),
            Self::NonCanonical { id } => write!(out, "policy {id} has non-canonical stored bytes"),
            Self::ConflictingSlot { id } => write!(out, "conflicting immutable policy slot: {id}"),
            Self::Evaluation(error) => write!(out, "policy evaluation: {error}"),
        }
    }
}
impl std::error::Error for PolicyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compile(error) => Some(error.as_ref()),
            Self::Codec(error) => Some(error.as_ref()),
            Self::Key(error) => Some(error.as_ref()),
            Self::Authority { failure, .. } => Some(failure.as_ref()),
            Self::Evaluation(error) => Some(error),
            _ => None,
        }
    }
}

/// Canonically checked bytes ready for an immutable put. Construction cannot
/// accept an asserted digest or silently normalize a non-canonical frame.
#[derive(Clone, Debug)]
pub struct PolicyFrame {
    id: PolicySnapshotId,
    bytes: Vec<u8>,
}
impl PolicyFrame {
    /// Compile through the existing bounded policy compiler, then validate the
    /// exact resulting frame through the same path used for untrusted storage.
    pub fn compile<C>(source: &str, limits: PolicyStoreLimits, checkpoint: &C) -> Result<Self, PolicyStoreError>
    where C: Fn() -> Result<(), RefusalCode> + ?Sized,
    {
        limits.decode()?;
        checkpoint().map_err(PolicyStoreError::Stopped)?;
        let snapshot = fgit_policy::compile_and_seal(source)
            .map_err(|error| PolicyStoreError::Compile(Box::new(error)))?;
        checkpoint().map_err(PolicyStoreError::Stopped)?;
        let bytes = snapshot.encode().map_err(codec)?;
        Self::from_bytes(&bytes, limits, checkpoint)
    }

    pub fn from_bytes<C>(bytes: &[u8], limits: PolicyStoreLimits, checkpoint: &C) -> Result<Self, PolicyStoreError>
    where C: Fn() -> Result<(), RefusalCode> + ?Sized,
    {
        let snapshot = identify(bytes, None, limits, checkpoint)?;
        Ok(Self { id: snapshot.id(), bytes: bytes.to_vec() })
    }
    pub const fn id(&self) -> PolicySnapshotId { self.id }
    pub fn bytes(&self) -> &[u8] { &self.bytes }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyStageDisposition { Created, IdenticalRetry }

/// Evidence of an acknowledged immutable put, never active-policy authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyStageReceipt {
    pub id: PolicySnapshotId,
    pub disposition: PolicyStageDisposition,
    pub encoded_bytes: usize,
}

fn codec(error: CodecRefusal) -> PolicyStoreError { PolicyStoreError::Codec(Box::new(error)) }
fn authority(operation: PolicyStoreOperation, failure: AuthorityFailure) -> PolicyStoreError {
    PolicyStoreError::Authority { operation, failure: Box::new(failure) }
}
fn identify<C>(
    bytes: &[u8], expected: Option<PolicySnapshotId>, limits: PolicyStoreLimits, checkpoint: &C,
) -> Result<PolicySnapshot, PolicyStoreError>
where C: Fn() -> Result<(), RefusalCode> + ?Sized,
{
    let decode = limits.decode()?;
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limits.frame_bytes {
        return Err(PolicyStoreError::FrameTooLarge { bytes: bytes.len(), limit: limits.frame_bytes });
    }
    let snapshot = PolicySnapshot::decode(bytes, decode).map_err(codec)?;
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    if let Some(requested) = expected && snapshot.id() != requested {
        return Err(PolicyStoreError::IdentityMismatch { requested: Box::new(requested), observed: Box::new(snapshot.id()) });
    }
    // Constructors may normalize their input. Equality of the re-identified
    // policy is not enough: the bytes in its immutable slot must be canonical.
    if snapshot.encode().map_err(codec)?.as_slice() != bytes {
        return Err(PolicyStoreError::NonCanonical { id: Box::new(snapshot.id()) });
    }
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    Ok(snapshot)
}
fn receipt(frame: &PolicyFrame, outcome: PutOutcome) -> Result<PolicyStageReceipt, PolicyStoreError> {
    let disposition = match outcome {
        PutOutcome::Created => PolicyStageDisposition::Created,
        PutOutcome::IdenticalRetry => PolicyStageDisposition::IdenticalRetry,
        PutOutcome::Conflict => return Err(PolicyStoreError::ConflictingSlot { id: Box::new(frame.id) }),
    };
    Ok(PolicyStageReceipt { id: frame.id, disposition, encoded_bytes: frame.bytes.len() })
}

/// Store one complete, validated frame under its registered canonical body key.
/// No head is created or modified. After an acknowledged put, return its known
/// disposition even if cancellation arrives; never report it as an absent put.
pub fn stage_policy<S, C>(store: &S, frame: &PolicyFrame, checkpoint: &C) -> Result<PolicyStageReceipt, PolicyStoreError>
where S: AuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + ?Sized,
{
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    let key = body_key_for_id(frame.id.as_internal_object_id()).map_err(|e| PolicyStoreError::Key(Box::new(e.into())))?;
    receipt(frame, store.put_if_absent(&key, &frame.bytes).map_err(|e| authority(PolicyStoreOperation::Stage, e))?)
}

/// Await the caller's authority store; do not create a runtime or worker.
/// Ambiguous errors are retained and are not automatically retried.
pub async fn stage_policy_async<S, C>(
    store: &S, cx: &S::Context, frame: &PolicyFrame, checkpoint: &C,
) -> Result<PolicyStageReceipt, PolicyStoreError>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + Sync + ?Sized,
{
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    let key = body_key_for_id(frame.id.as_internal_object_id()).map_err(|e| PolicyStoreError::Key(Box::new(e.into())))?;
    receipt(frame, store.put_if_absent(cx, &key, &frame.bytes).await
        .map_err(|e| authority(PolicyStoreOperation::Stage, e))?)
}

/// Re-read and independently re-identify the selected policy. Missing, wrong,
/// corrupt and oversized bodies remain distinct from a valid denying policy.
pub fn read_policy<S, C>(store: &S, id: PolicySnapshotId, limits: PolicyStoreLimits, checkpoint: &C)
    -> Result<PolicySnapshot, PolicyStoreError>
where S: AuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + ?Sized,
{
    limits.decode()?;
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    let key = body_key_for_id(id.as_internal_object_id()).map_err(|e| PolicyStoreError::Key(Box::new(e.into())))?;
    let read = store.read_immutable(&key).map_err(|e| authority(PolicyStoreOperation::Read, e))?;
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    let ImmutableRead::Present(bytes) = read else { return Err(PolicyStoreError::Missing { requested: Box::new(id) }); };
    identify(&bytes, Some(id), limits, checkpoint)
}

pub async fn read_policy_async<S, C>(
    store: &S, cx: &S::Context, id: PolicySnapshotId, limits: PolicyStoreLimits, checkpoint: &C,
) -> Result<PolicySnapshot, PolicyStoreError>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + Sync + ?Sized,
{
    limits.decode()?;
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    let key = body_key_for_id(id.as_internal_object_id()).map_err(|e| PolicyStoreError::Key(Box::new(e.into())))?;
    let read = store.read_immutable(cx, &key).await.map_err(|e| authority(PolicyStoreOperation::Read, e))?;
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    let ImmutableRead::Present(bytes) = read else { return Err(PolicyStoreError::Missing { requested: Box::new(id) }); };
    identify(&bytes, Some(id), limits, checkpoint)
}

pub fn evaluate_stored_policy<S, C>(
    store: &S, id: PolicySnapshotId, input: &PolicyInputRoot, codes: &SubjectCodeMap,
    limits: PolicyStoreLimits, checkpoint: &C,
) -> Result<ProtectionVerdict, PolicyStoreError>
where S: AuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + ?Sized,
{
    let policy = read_policy(store, id, limits, checkpoint)?;
    let verdict = evaluate_snapshot(&policy, codes, input).map_err(PolicyStoreError::Evaluation)?;
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    Ok(verdict)
}

pub async fn evaluate_stored_policy_async<S, C>(
    store: &S, cx: &S::Context, id: PolicySnapshotId, input: &PolicyInputRoot,
    codes: &SubjectCodeMap, limits: PolicyStoreLimits, checkpoint: &C,
) -> Result<ProtectionVerdict, PolicyStoreError>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + Sync + ?Sized,
{
    let policy = read_policy_async(store, cx, id, limits, checkpoint).await?;
    let verdict = evaluate_snapshot(&policy, codes, input).map_err(PolicyStoreError::Evaluation)?;
    checkpoint().map_err(PolicyStoreError::Stopped)?;
    Ok(verdict)
}

#[cfg(test)]
mod tests;
