//! Freeze and stage a repository capsule from an authenticated live head.
//!
//! A capsule is not a best-effort snapshot. This boundary authenticates the
//! observed authority head, derives the capsule from that one body, stages and
//! rereads the capsule bytes, then rereads the authority head before returning
//! a pointer candidate. A concurrent head change therefore leaves only an
//! immutable, unreachable capsule body; it can never publish a stale root.

use core::fmt;

use fgit_authority::{
    AuthorityFailure, AuthorityStore, HeadRead, HeadReadReceipt, ImmutableRead, PutOutcome,
    authority_head_identity, body_key,
};
use fgit_codec::attest::BodyIdentity;
use fgit_codec::{
    CodecRefusal, DecodeLimits, RepositoryAuthorityHeadBody, decode_body, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{Digest, RepositoryCapsuleId};

use crate::{
    BackupProfile, CapsulePointer, ChronicleRefusal, RepositoryCapsuleBody, capsule_identity,
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
        }
    }
}

impl std::error::Error for LiveCapsuleRefusal {}

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
