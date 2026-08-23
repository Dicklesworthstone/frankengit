//! Freeze and stage a repository capsule from an authenticated live head.
//!
//! A capsule is not a best-effort snapshot. This boundary authenticates the
//! observed authority head, derives the capsule from that one body, stages and
//! rereads the capsule bytes, then rereads the authority head before returning
//! a pointer candidate. A concurrent head change therefore leaves only an
//! immutable, unreachable capsule body; it can never publish a stale root.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, AuthorityFailure, AuthorityStore, CasOutcome, HeadRead, HeadReadReceipt,
    ImmutableRead, PutOutcome, authority_head_identity, body_key,
};
use fgit_codec::attest::BodyIdentity;
use fgit_codec::{
    CodecRefusal, DecodeLimits, RepositoryAuthorityHeadBody, decode_body, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{Digest, RepositoryCapsuleId};

use crate::{
    BackupProfile, CapsuleDefect, CapsulePointer, ChronicleRefusal, RepositoryCapsuleBody,
    RestoreClassification, capsule_identity,
};

/// Inputs naming immutable closure material that the object-fabric owner has
/// already verified. This crate never infers a closure from directory listing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapsuleClosure {
    /// Validated object closure root.
    pub object_closure_root: Digest,
    /// Validated segment-manifest root.
    pub segment_manifest_root: Digest,
    /// Coverage the staged material satisfies.
    pub backup_profile: BackupProfile,
}

/// A capsule body staged from a head that remained current through staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenCapsule {
    capsule: RepositoryCapsuleBody,
    capsule_id: RepositoryCapsuleId,
    pointer: CapsulePointer,
}

/// The result of root-last checkpoint activation.
///
/// The returned head receipt is the new authority position carrying the
/// checkpoint pointer. Routing is deliberately absent from this type: it is a
/// derived publication and cannot become visible until a later consumer has
/// completed its own verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedCapsule {
    pointer: CapsulePointer,
    head: HeadReadReceipt,
}

impl ActivatedCapsule {
    /// The activated anti-rollback checkpoint pointer.
    #[must_use]
    pub const fn pointer(&self) -> CapsulePointer {
        self.pointer
    }

    /// The new authority-head receipt that records the activated pointer.
    #[must_use]
    pub const fn head(&self) -> &HeadReadReceipt {
        &self.head
    }
}

impl FrozenCapsule {
    /// The immutable staged capsule body.
    #[must_use]
    pub const fn capsule(&self) -> &RepositoryCapsuleBody {
        &self.capsule
    }

    /// The canonical identity of the staged body.
    #[must_use]
    pub const fn capsule_id(&self) -> RepositoryCapsuleId {
        self.capsule_id
    }

    /// The root-last pointer candidate. A caller publishes it only after this
    /// function's exact-byte and current-head checks have completed.
    #[must_use]
    pub const fn pointer(&self) -> CapsulePointer {
        self.pointer
    }
}

/// Why live capsule freezing stopped before yielding a pointer candidate.
#[derive(Debug)]
pub enum LiveCapsuleRefusal {
    /// The supplied receipt was not issued by this authority endpoint.
    HeadUnauthenticated(AuthorityFailure),
    /// The receipt bytes are not a canonical authority-head body.
    HeadDecode(CodecRefusal),
    /// The decoded head does not agree with the receipt's generation.
    HeadGenerationMismatch,
    /// The authority-head identity could not be derived from canonical bytes.
    HeadIdentity(Box<fgit_authority::OutcomeFailure>),
    /// Capsule construction or pointer monotonicity refused.
    Capsule(ChronicleRefusal),
    /// The capsule could not be encoded canonically.
    CapsuleEncoding(CodecRefusal),
    /// The authority backend refused or left staging ambiguous.
    CapsuleStage(AuthorityFailure),
    /// The canonical capsule slot was already occupied by different bytes.
    CapsuleSlotConflict,
    /// Readback after staging did not prove the exact capsule bytes exist.
    CapsuleReadbackMismatch,
    /// The repository head disappeared while the capsule was staged.
    HeadDisappeared,
    /// The repository advanced while the capsule was staged.
    HeadMoved,
    /// The authenticated activation basis does not match the frozen capsule.
    ActivationBasisMismatch,
    /// The existing checkpoint pointer is not the frozen capsule's predecessor.
    CheckpointPredecessorMismatch,
    /// The authority-head generation cannot advance without overflowing.
    ActivationGenerationExhausted,
    /// Staging the successor authority head failed or was ambiguous.
    ActivationHeadStage(AuthorityFailure),
    /// The successor authority-head identity slot already held different bytes.
    ActivationHeadSlotConflict,
    /// The staged successor authority head did not read back byte-identically.
    ActivationHeadReadbackMismatch,
}

impl fmt::Display for LiveCapsuleRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadUnauthenticated(error) => write!(
                formatter,
                "authority head receipt was not authenticated: {error}"
            ),
            Self::HeadDecode(error) => {
                write!(formatter, "authority head bytes did not decode: {error}")
            }
            Self::HeadGenerationMismatch => formatter.write_str(
                "authority head body disagrees with its authenticated receipt generation",
            ),
            Self::HeadIdentity(error) => write!(
                formatter,
                "authority head identity was unavailable: {error}"
            ),
            Self::Capsule(error) => write!(formatter, "capsule construction refused: {error}"),
            Self::CapsuleEncoding(error) => write!(formatter, "capsule encoding refused: {error}"),
            Self::CapsuleStage(error) => {
                write!(formatter, "capsule staging did not complete: {error}")
            }
            Self::CapsuleSlotConflict => {
                formatter.write_str("canonical capsule slot held different bytes")
            }
            Self::CapsuleReadbackMismatch => {
                formatter.write_str("capsule staging was not proven by exact byte readback")
            }
            Self::HeadDisappeared => {
                formatter.write_str("authority head disappeared while the capsule was staged")
            }
            Self::HeadMoved => {
                formatter.write_str("authority head moved while the capsule was staged")
            }
            Self::ActivationBasisMismatch => formatter.write_str(
                "activation receipt does not name the exact authority head frozen by this capsule",
            ),
            Self::CheckpointPredecessorMismatch => formatter.write_str(
                "authority head's checkpoint pointer is not the frozen capsule predecessor",
            ),
            Self::ActivationGenerationExhausted => formatter
                .write_str("authority head generation is exhausted before checkpoint activation"),
            Self::ActivationHeadStage(error) => {
                write!(
                    formatter,
                    "successor authority-head staging did not complete: {error}"
                )
            }
            Self::ActivationHeadSlotConflict => {
                formatter.write_str("successor authority-head identity slot held different bytes")
            }
            Self::ActivationHeadReadbackMismatch => formatter.write_str(
                "successor authority-head staging was not proven by exact byte readback",
            ),
        }
    }
}

impl std::error::Error for LiveCapsuleRefusal {}

/// The result of inspecting capsule bytes at a declared immutable identity.
///
/// The decoder, identity check, and predecessor check are deliberately here
/// rather than in a fixture. A restore executor can therefore only hand the
/// classifier defects it actually derived from the bytes and pointer chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleInspection {
    capsule: RepositoryCapsuleBody,
    classification: RestoreClassification,
}

/// Why a capsule could not be inspected as restore input.
#[derive(Debug)]
pub enum CapsuleInspectionRefusal {
    /// The supplied bytes are not a canonical capsule body.
    Decode(CodecRefusal),
    /// The decoded body has no registered canonical identity.
    Identity(ChronicleRefusal),
    /// The supplied authority-head bytes are not a canonical authority head.
    HeadDecode(CodecRefusal),
    /// The decoded authority head has no canonical identity.
    HeadIdentity(Box<fgit_authority::OutcomeFailure>),
}

impl fmt::Display for CapsuleInspectionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "capsule bytes did not decode: {error}"),
            Self::Identity(error) => write!(formatter, "capsule identity was unavailable: {error}"),
            Self::HeadDecode(error) => {
                write!(formatter, "authority-head bytes did not decode: {error}")
            }
            Self::HeadIdentity(error) => write!(
                formatter,
                "authority-head identity was unavailable: {error}"
            ),
        }
    }
}

impl std::error::Error for CapsuleInspectionRefusal {}

impl CapsuleInspection {
    /// The decoded capsule body.
    #[must_use]
    pub const fn capsule(&self) -> &RepositoryCapsuleBody {
        &self.capsule
    }

    /// Classification of the byte-derived defects.
    #[must_use]
    pub const fn classification(&self) -> &RestoreClassification {
        &self.classification
    }
}

/// Decode a capsule and derive the identity and pointer-chain defects that
/// restore can determine without asking a placement backend to enumerate.
pub fn inspect_capsule_bytes<I>(
    identity: &I,
    declared_id: RepositoryCapsuleId,
    bytes: &[u8],
    expected_predecessor: Option<RepositoryCapsuleId>,
) -> Result<CapsuleInspection, CapsuleInspectionRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let (capsule, defects) =
        decoded_capsule_defects(identity, declared_id, bytes, expected_predecessor)?;
    Ok(CapsuleInspection::from_defects(capsule, defects))
}

/// Decode a capsule and its named authority head, deriving every mismatch
/// between the two from their actual canonical bytes.
///
/// A portable restore cannot trust a caller that says a capsule was taken at a
/// particular head. This function recomputes that head's identity and checks
/// each field the capsule copies from it before a destination can stage or
/// initialize anything. The caller supplies bytes rather than a store because
/// the source authority may no longer exist during a clean-machine restore.
pub fn inspect_capsule_against_authority_head_bytes<I>(
    identity: &I,
    declared_id: RepositoryCapsuleId,
    capsule_bytes: &[u8],
    authority_head_bytes: &[u8],
    expected_predecessor: Option<RepositoryCapsuleId>,
) -> Result<CapsuleInspection, CapsuleInspectionRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let (capsule, mut defects) =
        decoded_capsule_defects(identity, declared_id, capsule_bytes, expected_predecessor)?;
    let head: RepositoryAuthorityHeadBody =
        decode_body(authority_head_bytes, DecodeLimits::DEFAULT)
            .map_err(CapsuleInspectionRefusal::HeadDecode)?;
    let head_id = authority_head_identity(&head)
        .map_err(|error| CapsuleInspectionRefusal::HeadIdentity(Box::new(error)))?;
    collect_authority_head_defects(&capsule, head_id, &head, &mut defects);
    Ok(CapsuleInspection::from_defects(capsule, defects))
}

impl CapsuleInspection {
    fn from_defects(capsule: RepositoryCapsuleBody, defects: Vec<CapsuleDefect>) -> Self {
        let classification = RestoreClassification::classify(&capsule, &defects);
        Self {
            capsule,
            classification,
        }
    }
}

fn decoded_capsule_defects<I>(
    identity: &I,
    declared_id: RepositoryCapsuleId,
    bytes: &[u8],
    expected_predecessor: Option<RepositoryCapsuleId>,
) -> Result<(RepositoryCapsuleBody, Vec<CapsuleDefect>), CapsuleInspectionRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let capsule: RepositoryCapsuleBody =
        decode_body(bytes, DecodeLimits::DEFAULT).map_err(CapsuleInspectionRefusal::Decode)?;
    let recomputed =
        capsule_identity(identity, &capsule).map_err(CapsuleInspectionRefusal::Identity)?;
    let mut defects = Vec::with_capacity(15);
    if recomputed != declared_id {
        defects.push(CapsuleDefect::IdentityMismatch {
            declared: declared_id,
            recomputed,
        });
    }
    if capsule.predecessor_capsule_id != expected_predecessor {
        defects.push(CapsuleDefect::PredecessorStale {
            named: capsule.predecessor_capsule_id,
            expected: expected_predecessor,
        });
    }
    Ok((capsule, defects))
}

fn collect_authority_head_defects(
    capsule: &RepositoryCapsuleBody,
    head_id: fgit_types::RepositoryAuthorityHeadId,
    head: &RepositoryAuthorityHeadBody,
    defects: &mut Vec<CapsuleDefect>,
) {
    for (field, agrees) in [
        ("head_id", capsule.head_id == head_id),
        ("repository_id", capsule.repository_id == head.repository_id),
        (
            "head_generation",
            capsule.head_generation == head.generation,
        ),
        (
            "decision_tail_id",
            capsule.decision_tail_id == head.decision_tail_id,
        ),
        (
            "latest_decision_sequence",
            capsule.latest_decision_sequence == head.latest_decision_sequence,
        ),
        (
            "latest_committed_rcr_id",
            capsule.latest_committed_rcr_id == head.latest_committed_rcr_id,
        ),
        (
            "latest_repository_sequence",
            capsule.latest_repository_sequence == head.latest_repository_sequence,
        ),
        ("ref_root", capsule.ref_root == head.ref_root),
        (
            "forge_position_root",
            capsule.forge_position_root == head.forge_position_root,
        ),
        (
            "retention_root",
            capsule.retention_root == head.retention_root,
        ),
        (
            "configuration_root",
            capsule.configuration_root == head.configuration_root,
        ),
        ("policy_epoch", capsule.policy_epoch == head.policy_epoch),
        (
            "format_registry_epoch",
            capsule.format_registry_epoch == head.format_registry_epoch,
        ),
    ] {
        if !agrees {
            defects.push(CapsuleDefect::AuthorityHeadMismatch { field });
        }
    }
}

/// Stage and activate a frozen capsule through the exact authority head it
/// checkpointed.
///
/// The successor authority head is an immutable body and is staged/read back
/// before its head-slot CAS. The CAS is therefore the final visibility point:
/// neither a capsule nor a successor head object becoming readable publishes a
/// checkpoint on its own. The function performs no routing publication.
pub fn activate_frozen_capsule<S>(
    store: &S,
    basis: &HeadReadReceipt,
    frozen: &FrozenCapsule,
) -> Result<ActivatedCapsule, LiveCapsuleRefusal>
where
    S: AuthorityStore + ?Sized,
{
    store
        .authenticate_head_receipt(basis)
        .map_err(LiveCapsuleRefusal::HeadUnauthenticated)?;
    let mut head: RepositoryAuthorityHeadBody =
        decode_body(basis.body(), DecodeLimits::DEFAULT).map_err(LiveCapsuleRefusal::HeadDecode)?;
    if head.generation != basis.generation() {
        return Err(LiveCapsuleRefusal::HeadGenerationMismatch);
    }
    let head_id = authority_head_identity(&head)
        .map_err(|error| LiveCapsuleRefusal::HeadIdentity(Box::new(error)))?;
    let mut basis_defects = Vec::with_capacity(13);
    collect_authority_head_defects(frozen.capsule(), head_id, &head, &mut basis_defects);
    if !basis_defects.is_empty() {
        return Err(LiveCapsuleRefusal::ActivationBasisMismatch);
    }
    if head.last_checkpoint_id != frozen.capsule().predecessor_capsule_id {
        return Err(LiveCapsuleRefusal::CheckpointPredecessorMismatch);
    }

    head.predecessor_head_id = Some(head_id);
    head.generation = head
        .generation
        .next()
        .map_err(|_| LiveCapsuleRefusal::ActivationGenerationExhausted)?;
    head.last_checkpoint_id = Some(frozen.capsule_id());
    let successor_bytes = encode_body(&head).map_err(LiveCapsuleRefusal::CapsuleEncoding)?;
    let successor_key = body_key(IdentityDomain::RepositoryAuthorityHead, &head)
        .map_err(|_| LiveCapsuleRefusal::ActivationBasisMismatch)?;
    match store
        .put_if_absent(&successor_key, &successor_bytes)
        .map_err(LiveCapsuleRefusal::ActivationHeadStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(LiveCapsuleRefusal::ActivationHeadSlotConflict),
    }
    if !matches!(store.read_immutable(&successor_key), Ok(ImmutableRead::Present(found)) if found == successor_bytes)
    {
        return Err(LiveCapsuleRefusal::ActivationHeadReadbackMismatch);
    }
    let CasOutcome::Committed(head) = store
        .compare_exchange_head(
            basis.key(),
            basis.token(),
            head.generation,
            &successor_bytes,
        )
        .map_err(LiveCapsuleRefusal::ActivationHeadStage)?
    else {
        return Err(LiveCapsuleRefusal::HeadMoved);
    };
    Ok(ActivatedCapsule {
        pointer: frozen.pointer(),
        head,
    })
}

/// Async production twin of [`activate_frozen_capsule`].
///
/// It carries the same stage/readback/CAS order as the deterministic surface;
/// only the waiting belongs to the runtime-owned authority context.
pub async fn activate_frozen_capsule_async<S>(
    store: &S,
    cx: &S::Context,
    basis: &HeadReadReceipt,
    frozen: &FrozenCapsule,
) -> Result<ActivatedCapsule, LiveCapsuleRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    store
        .authenticate_head_receipt(cx, basis)
        .await
        .map_err(LiveCapsuleRefusal::HeadUnauthenticated)?;
    let mut head: RepositoryAuthorityHeadBody =
        decode_body(basis.body(), DecodeLimits::DEFAULT).map_err(LiveCapsuleRefusal::HeadDecode)?;
    if head.generation != basis.generation() {
        return Err(LiveCapsuleRefusal::HeadGenerationMismatch);
    }
    let head_id = authority_head_identity(&head)
        .map_err(|error| LiveCapsuleRefusal::HeadIdentity(Box::new(error)))?;
    let mut basis_defects = Vec::with_capacity(13);
    collect_authority_head_defects(frozen.capsule(), head_id, &head, &mut basis_defects);
    if !basis_defects.is_empty() {
        return Err(LiveCapsuleRefusal::ActivationBasisMismatch);
    }
    if head.last_checkpoint_id != frozen.capsule().predecessor_capsule_id {
        return Err(LiveCapsuleRefusal::CheckpointPredecessorMismatch);
    }

    head.predecessor_head_id = Some(head_id);
    head.generation = head
        .generation
        .next()
        .map_err(|_| LiveCapsuleRefusal::ActivationGenerationExhausted)?;
    head.last_checkpoint_id = Some(frozen.capsule_id());
    let successor_bytes = encode_body(&head).map_err(LiveCapsuleRefusal::CapsuleEncoding)?;
    let successor_key = body_key(IdentityDomain::RepositoryAuthorityHead, &head)
        .map_err(|_| LiveCapsuleRefusal::ActivationBasisMismatch)?;
    match store
        .put_if_absent(cx, &successor_key, &successor_bytes)
        .await
        .map_err(LiveCapsuleRefusal::ActivationHeadStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(LiveCapsuleRefusal::ActivationHeadSlotConflict),
    }
    if !matches!(store.read_immutable(cx, &successor_key).await, Ok(ImmutableRead::Present(found)) if found == successor_bytes)
    {
        return Err(LiveCapsuleRefusal::ActivationHeadReadbackMismatch);
    }
    let CasOutcome::Committed(head) = store
        .compare_exchange_head(
            cx,
            basis.key(),
            basis.token(),
            head.generation,
            &successor_bytes,
        )
        .await
        .map_err(LiveCapsuleRefusal::ActivationHeadStage)?
    else {
        return Err(LiveCapsuleRefusal::HeadMoved);
    };
    Ok(ActivatedCapsule {
        pointer: frozen.pointer(),
        head,
    })
}

/// Freeze the authenticated head, stage its capsule, and return a pointer
/// candidate only if that exact head remains current.
pub fn freeze_capsule<S, I>(
    store: &S,
    identity: &I,
    receipt: &HeadReadReceipt,
    current_pointer: Option<&CapsulePointer>,
    closure: CapsuleClosure,
) -> Result<FrozenCapsule, LiveCapsuleRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    store
        .authenticate_head_receipt(receipt)
        .map_err(LiveCapsuleRefusal::HeadUnauthenticated)?;
    let head: RepositoryAuthorityHeadBody = decode_body(receipt.body(), DecodeLimits::DEFAULT)
        .map_err(LiveCapsuleRefusal::HeadDecode)?;
    if head.generation != receipt.generation() {
        return Err(LiveCapsuleRefusal::HeadGenerationMismatch);
    }
    let head_id = authority_head_identity(&head)
        .map_err(|error| LiveCapsuleRefusal::HeadIdentity(Box::new(error)))?;
    let capsule = RepositoryCapsuleBody::at_head(
        head_id,
        &head,
        current_pointer.map(CapsulePointer::capsule_id),
        closure.object_closure_root,
        closure.segment_manifest_root,
        closure.backup_profile,
    );
    let capsule_id = capsule_identity(identity, &capsule).map_err(LiveCapsuleRefusal::Capsule)?;
    let bytes = encode_body(&capsule).map_err(LiveCapsuleRefusal::CapsuleEncoding)?;
    let key = body_key(IdentityDomain::RepositoryCapsule, &capsule)
        .map_err(|_| LiveCapsuleRefusal::Capsule(ChronicleRefusal::CapsuleIdentityUnavailable))?;
    match store
        .put_if_absent(&key, &bytes)
        .map_err(LiveCapsuleRefusal::CapsuleStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(LiveCapsuleRefusal::CapsuleSlotConflict),
    }
    if !matches!(store.read_immutable(&key), Ok(ImmutableRead::Present(found)) if found == bytes) {
        return Err(LiveCapsuleRefusal::CapsuleReadbackMismatch);
    }
    match store
        .read_head(receipt.key())
        .map_err(LiveCapsuleRefusal::CapsuleStage)?
    {
        HeadRead::Present(current) if current == *receipt => {}
        HeadRead::Present(_) => return Err(LiveCapsuleRefusal::HeadMoved),
        HeadRead::Absent => return Err(LiveCapsuleRefusal::HeadDisappeared),
    }
    let pointer = match current_pointer {
        Some(pointer) => pointer.advance(capsule_id, &capsule),
        None => CapsulePointer::genesis(capsule_id, &capsule),
    }
    .map_err(LiveCapsuleRefusal::Capsule)?;
    Ok(FrozenCapsule {
        capsule,
        capsule_id,
        pointer,
    })
}

/// Async production twin of [`freeze_capsule`].
///
/// It has the same identity, staging, readback, and current-head decisions as
/// the deterministic surface above; only waiting is delegated to the one
/// runtime-owned authority context.
pub async fn freeze_capsule_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    receipt: &HeadReadReceipt,
    current_pointer: Option<&CapsulePointer>,
    closure: CapsuleClosure,
) -> Result<FrozenCapsule, LiveCapsuleRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    store
        .authenticate_head_receipt(cx, receipt)
        .await
        .map_err(LiveCapsuleRefusal::HeadUnauthenticated)?;
    let head: RepositoryAuthorityHeadBody = decode_body(receipt.body(), DecodeLimits::DEFAULT)
        .map_err(LiveCapsuleRefusal::HeadDecode)?;
    if head.generation != receipt.generation() {
        return Err(LiveCapsuleRefusal::HeadGenerationMismatch);
    }
    let head_id = authority_head_identity(&head)
        .map_err(|error| LiveCapsuleRefusal::HeadIdentity(Box::new(error)))?;
    let capsule = RepositoryCapsuleBody::at_head(
        head_id,
        &head,
        current_pointer.map(CapsulePointer::capsule_id),
        closure.object_closure_root,
        closure.segment_manifest_root,
        closure.backup_profile,
    );
    let capsule_id = capsule_identity(identity, &capsule).map_err(LiveCapsuleRefusal::Capsule)?;
    let bytes = encode_body(&capsule).map_err(LiveCapsuleRefusal::CapsuleEncoding)?;
    let key = body_key(IdentityDomain::RepositoryCapsule, &capsule)
        .map_err(|_| LiveCapsuleRefusal::Capsule(ChronicleRefusal::CapsuleIdentityUnavailable))?;
    match store
        .put_if_absent(cx, &key, &bytes)
        .await
        .map_err(LiveCapsuleRefusal::CapsuleStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(LiveCapsuleRefusal::CapsuleSlotConflict),
    }
    if !matches!(store.read_immutable(cx, &key).await, Ok(ImmutableRead::Present(found)) if found == bytes)
    {
        return Err(LiveCapsuleRefusal::CapsuleReadbackMismatch);
    }
    match store
        .read_head(cx, receipt.key())
        .await
        .map_err(LiveCapsuleRefusal::CapsuleStage)?
    {
        HeadRead::Present(current) if current == *receipt => {}
        HeadRead::Present(_) => return Err(LiveCapsuleRefusal::HeadMoved),
        HeadRead::Absent => return Err(LiveCapsuleRefusal::HeadDisappeared),
    }
    let pointer = match current_pointer {
        Some(pointer) => pointer.advance(capsule_id, &capsule),
        None => CapsulePointer::genesis(capsule_id, &capsule),
    }
    .map_err(LiveCapsuleRefusal::Capsule)?;
    Ok(FrozenCapsule {
        capsule,
        capsule_id,
        pointer,
    })
}
