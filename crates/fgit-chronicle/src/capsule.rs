//! Repository capsule bodies and the root-last capsule pointer.
//!
//! A capsule is the checkpoint a repository can be rebuilt or restored from.
//! Section 23 of the normative contract fixes what it must bind — the exact
//! authority head and commit record, the decision-log position, the ref, forge,
//! object, segment and retention roots, the policy, configuration and format
//! epochs, and the backup profile — and fixes how it is published: root-last,
//! with the pointer moved only after the referenced data is staged, verified,
//! and durable.
//!
//! Two rules do the real work here.
//!
//! **Identity excludes anything mutable.** The capsule identity is the digest
//! of the unsigned body. Signatures, placements, and repair-symbol locations
//! attest to a capsule; they do not participate in what it *is*. That is why
//! this module carries no signature field: signing happens by wrapping the
//! encoded body in `fgit_codec`'s signed envelope, whose identity is computed
//! from the carried body's own bytes, so attaching or removing a signature
//! cannot change which capsule you are pointing at.
//!
//! **An older checkpoint can never masquerade as current.** The pointer is
//! monotone in the head generation the capsule was taken at, *and* each capsule
//! names the exact capsule it succeeds. Advancing the pointer requires both to
//! agree, so a stale capsule cannot be re-published as the current one even by
//! a caller holding a valid older body. Recovery therefore cannot silently fall
//! back: section 23 requires older-state recovery to be an explicit audited
//! restore that advances a new authority generation, never a quiet reuse of a
//! capsule that still verifies.

use fgit_authority::{AsyncAuthorityStore, AuthorityStore, ImmutableRead, body_key};
use fgit_codec::attest::{BodyIdentity, body_id};
use fgit_codec::error::CodecRefusal;
use fgit_codec::reader::Decoder;
use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_codec::wire::CanonicalBody;
use fgit_codec::writer::Encoder;
use fgit_types::{
    DecisionSequence, Digest, DomainTag, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryCapsuleId, RepositoryCommitId, RepositoryDecisionBatchId,
    RepositoryId, RepositorySequence, SchemaFamily,
};

use fgit_crypto::IdentityDomain;

use crate::refusal::ChronicleRefusal;

/// How much of the repository a capsule's referenced data covers.
///
/// The profile is part of the body because a capsule that covers less than a
/// reader assumes is worse than no capsule: restore would silently produce a
/// repository missing the classes this one never included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackupProfile {
    /// Canonical decision history and refs only; object bodies are expected to
    /// be recoverable from another source.
    DecisionHistoryOnly,
    /// Decision history plus the full object closure the roots reference.
    FullClosure,
    /// Full closure plus the repair symbols needed to survive the declared
    /// failure-domain loss.
    FullClosureWithRepair,
}

impl BackupProfile {
    /// Stable lowercase name for receipts and refusals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DecisionHistoryOnly => "decision_history_only",
            Self::FullClosure => "full_closure",
            Self::FullClosureWithRepair => "full_closure_with_repair",
        }
    }

    /// The wire discriminant.
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        match self {
            Self::DecisionHistoryOnly => 1,
            Self::FullClosure => 2,
            Self::FullClosureWithRepair => 3,
        }
    }

    /// Reads a discriminant, refusing one this build does not define.
    ///
    /// An unknown profile is refused rather than defaulted: guessing would let
    /// a capsule written by a newer build be restored as though it covered
    /// less, or more, than it does.
    pub const fn from_discriminant(value: u8) -> Result<Self, ChronicleRefusal> {
        match value {
            1 => Ok(Self::DecisionHistoryOnly),
            2 => Ok(Self::FullClosure),
            3 => Ok(Self::FullClosureWithRepair),
            _ => Err(ChronicleRefusal::BackupProfileUnknown { observed: value }),
        }
    }
}

/// The unsigned body of one repository capsule.
///
/// Every field is immutable evidence about one exact repository position.
/// Nothing here is a mutable pointer, a placement, or a signature, because the
/// capsule identity is this body's digest and identity may not move when
/// attestations are added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryCapsuleBody {
    /// Repository this capsule checkpoints.
    pub repository_id: RepositoryId,
    /// The exact authority head the capsule was taken at.
    pub head_id: RepositoryAuthorityHeadId,
    /// That head's generation, which is what makes the pointer monotone.
    pub head_generation: HeadGeneration,
    /// The capsule this one succeeds, absent only for the first capsule.
    pub predecessor_capsule_id: Option<RepositoryCapsuleId>,
    /// Decision batch at the head, absent before the first decision.
    pub decision_tail_id: Option<RepositoryDecisionBatchId>,
    /// Decision-log position, absent before the first decision.
    pub latest_decision_sequence: Option<DecisionSequence>,
    /// Latest committed record, absent before the first commit.
    pub latest_committed_rcr_id: Option<RepositoryCommitId>,
    /// Committed-transition position, absent before the first commit.
    pub latest_repository_sequence: Option<RepositorySequence>,
    /// Root over the ref state this capsule restores to.
    pub ref_root: Digest,
    /// Root over the forge position.
    pub forge_position_root: Digest,
    /// Root over the validated object closure the roots reference.
    pub object_closure_root: Digest,
    /// Root over the segment manifests holding those objects.
    pub segment_manifest_root: Digest,
    /// Root over retention state, so a restore cannot drop a legal hold.
    pub retention_root: Digest,
    /// Root over the configuration needed to interpret this capsule.
    pub configuration_root: Digest,
    /// Policy epoch in force at the head.
    pub policy_epoch: PolicyEpoch,
    /// Format and algorithm registry epoch needed to read the bodies.
    pub format_registry_epoch: RegistryEpoch,
    /// How much of the repository the referenced data covers.
    pub backup_profile: BackupProfile,
}

impl RepositoryCapsuleBody {
    /// Builds a capsule body from the head it checkpoints.
    ///
    /// Taking the head body rather than loose fields is what stops a capsule
    /// from claiming a position its head never had: the decision-log position,
    /// the commit pointers and the roots are copied from one authenticated
    /// head, so they cannot be assembled from two different ones.
    #[must_use]
    pub const fn at_head(
        head_id: RepositoryAuthorityHeadId,
        head: &RepositoryAuthorityHeadBody,
        predecessor_capsule_id: Option<RepositoryCapsuleId>,
        object_closure_root: Digest,
        segment_manifest_root: Digest,
        backup_profile: BackupProfile,
    ) -> Self {
        Self {
            repository_id: head.repository_id,
            head_id,
            head_generation: head.generation,
            predecessor_capsule_id,
            decision_tail_id: head.decision_tail_id,
            latest_decision_sequence: head.latest_decision_sequence,
            latest_committed_rcr_id: head.latest_committed_rcr_id,
            latest_repository_sequence: head.latest_repository_sequence,
            ref_root: head.ref_root,
            forge_position_root: head.forge_position_root,
            object_closure_root,
            segment_manifest_root,
            retention_root: head.retention_root,
            configuration_root: head.configuration_root,
            policy_epoch: head.policy_epoch,
            format_registry_epoch: head.format_registry_epoch,
            backup_profile,
        }
    }
}

impl CanonicalBody for RepositoryCapsuleBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/repository-capsule/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("repository-capsule");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_internal_object_id(self.head_id.as_internal_object_id())?;
        out.write_scalar(self.head_generation.get());
        out.write_option(self.predecessor_capsule_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_option(self.decision_tail_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_option(self.latest_decision_sequence.as_ref(), |out, sequence| {
            out.write_scalar(sequence.get());
            Ok(())
        })?;
        out.write_option(self.latest_committed_rcr_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_option(self.latest_repository_sequence.as_ref(), |out, sequence| {
            out.write_scalar(sequence.get());
            Ok(())
        })?;
        for digest in [
            &self.ref_root,
            &self.forge_position_root,
            &self.object_closure_root,
            &self.segment_manifest_root,
            &self.retention_root,
            &self.configuration_root,
        ] {
            out.write_digest(digest)?;
        }
        out.write_scalar(self.policy_epoch.get());
        out.write_scalar(self.format_registry_epoch.get());
        out.write_raw_byte(self.backup_profile.discriminant());
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let head_id =
            RepositoryAuthorityHeadId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)?;
        let head_generation =
            HeadGeneration::try_new(input.read_scalar::<u64>("head_generation")?)?;
        let predecessor_capsule_id = input.read_option("predecessor_capsule_id", |input| {
            RepositoryCapsuleId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)
        })?;
        let decision_tail_id = input.read_option("decision_tail_id", |input| {
            RepositoryDecisionBatchId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)
        })?;
        let latest_decision_sequence = input.read_option("latest_decision_sequence", |input| {
            DecisionSequence::try_new(input.read_scalar::<u64>("latest_decision_sequence")?)
                .map_err(CodecRefusal::from)
        })?;
        let latest_committed_rcr_id = input.read_option("latest_committed_rcr_id", |input| {
            RepositoryCommitId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)
        })?;
        let latest_repository_sequence =
            input.read_option("latest_repository_sequence", |input| {
                RepositorySequence::try_new(input.read_scalar::<u64>("latest_repository_sequence")?)
                    .map_err(CodecRefusal::from)
            })?;
        let ref_root = input.read_digest()?;
        let forge_position_root = input.read_digest()?;
        let object_closure_root = input.read_digest()?;
        let segment_manifest_root = input.read_digest()?;
        let retention_root = input.read_digest()?;
        let configuration_root = input.read_digest()?;
        let policy_epoch = PolicyEpoch::try_new(input.read_scalar::<u64>("policy_epoch")?)?;
        let format_registry_epoch =
            RegistryEpoch::try_new(input.read_scalar::<u64>("format_registry_epoch")?)?;
        let profile_byte = input.read_raw_byte("backup_profile")?;
        let backup_profile = BackupProfile::from_discriminant(profile_byte).map_err(|_| {
            CodecRefusal::from(fgit_types::TypeRefusal::CodePointUnknown {
                field: "backup_profile",
                observed: u32::from(profile_byte),
            })
        })?;
        Ok(Self {
            repository_id,
            head_id,
            head_generation,
            predecessor_capsule_id,
            decision_tail_id,
            latest_decision_sequence,
            latest_committed_rcr_id,
            latest_repository_sequence,
            ref_root,
            forge_position_root,
            object_closure_root,
            segment_manifest_root,
            retention_root,
            configuration_root,
            policy_epoch,
            format_registry_epoch,
            backup_profile,
        })
    }
}

/// The anti-rollback pointer naming the current capsule.
///
/// This is the value section 23 publishes last, after the referenced data is
/// staged, verified and durable. It is deliberately tiny: the pointer carries
/// no roots of its own, so the only thing it can assert is *which* capsule is
/// current, and it can only ever move forward.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapsulePointer {
    repository_id: RepositoryId,
    capsule_id: RepositoryCapsuleId,
    head_generation: HeadGeneration,
}

impl CapsulePointer {
    /// Establishes the first pointer for a repository.
    ///
    /// Refuses a capsule that claims a predecessor, because a first capsule by
    /// definition succeeds nothing; accepting one would leave a gap that no
    /// later verification could detect.
    pub const fn genesis(
        capsule_id: RepositoryCapsuleId,
        capsule: &RepositoryCapsuleBody,
    ) -> Result<Self, ChronicleRefusal> {
        if capsule.predecessor_capsule_id.is_some() {
            return Err(ChronicleRefusal::CapsulePredecessorMismatch);
        }
        Ok(Self {
            repository_id: capsule.repository_id,
            capsule_id,
            head_generation: capsule.head_generation,
        })
    }

    /// The repository this pointer belongs to.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// The capsule this pointer names.
    #[must_use]
    pub const fn capsule_id(&self) -> RepositoryCapsuleId {
        self.capsule_id
    }

    /// The head generation the named capsule was taken at.
    #[must_use]
    pub const fn head_generation(&self) -> HeadGeneration {
        self.head_generation
    }

    /// Moves the pointer to a newer capsule.
    ///
    /// Both conditions must hold, and neither implies the other: the successor
    /// must have been taken at a strictly later head generation, and it must
    /// name *this* capsule as its predecessor. Generation alone would let a
    /// capsule from a forked history jump in; predecessor alone would let a
    /// capsule taken at an older head be re-published as current.
    pub fn advance(
        &self,
        capsule_id: RepositoryCapsuleId,
        capsule: &RepositoryCapsuleBody,
    ) -> Result<Self, ChronicleRefusal> {
        if capsule.repository_id != self.repository_id {
            return Err(ChronicleRefusal::RepositoryMismatch);
        }
        if capsule.head_generation <= self.head_generation {
            return Err(ChronicleRefusal::CapsuleNotAdvancing {
                current: self.head_generation,
                proposed: capsule.head_generation,
            });
        }
        if capsule.predecessor_capsule_id != Some(self.capsule_id) {
            return Err(ChronicleRefusal::CapsulePredecessorMismatch);
        }
        Ok(Self {
            repository_id: self.repository_id,
            capsule_id,
            head_generation: capsule.head_generation,
        })
    }
}

/// The identity of a capsule body, computed from its canonical bytes.
///
/// The unsigned body is what is hashed. A signed envelope carrying this body
/// yields the same answer, which is the property section 23 relies on when it
/// says signatures attest to a capsule without participating in its identity.
pub fn capsule_identity<I>(
    identity: &I,
    capsule: &RepositoryCapsuleBody,
) -> Result<RepositoryCapsuleId, ChronicleRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let object =
        body_id(identity, capsule).map_err(|_| ChronicleRefusal::CapsuleIdentityUnavailable)?;
    RepositoryCapsuleId::from_internal_object_id(object)
        .map_err(|_| ChronicleRefusal::CapsuleIdentityUnavailable)
}

/// Advances the capsule pointer, root-last.
///
/// The order is section 23's: the body must already be staged and readable
/// before the pointer that names it moves. Checking here rather than trusting
/// the caller is the point — a pointer published ahead of its body names a root
/// no reader can fetch, which is indistinguishable from corruption at exactly
/// the moment a restore needs it most.
///
/// This performs no staging of its own. Staging, closure verification, and
/// durability evidence are steps 1 to 3 of the protocol and belong to the
/// fabric; this is step 6, and it refuses if the earlier steps did not happen.
pub fn advance_pointer_root_last<S, I>(
    store: &S,
    identity: &I,
    pointer: &CapsulePointer,
    capsule: &RepositoryCapsuleBody,
) -> Result<CapsulePointer, ChronicleRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let capsule_id = capsule_identity(identity, capsule)?;
    let key = body_key(IdentityDomain::RepositoryCapsule, capsule)
        .map_err(|_| ChronicleRefusal::CapsuleIdentityUnavailable)?;
    // A body that is absent and a store that cannot answer are the same
    // fact here: nothing has proved the data is fetchable, so the pointer
    // does not move. Distinguishing them would invite treating an
    // unreachable store as evidence of presence.
    if !matches!(store.read_immutable(&key), Ok(ImmutableRead::Present(_))) {
        return Err(ChronicleRefusal::CapsuleBodyNotStaged);
    }
    pointer.advance(capsule_id, capsule)
}

/// [`advance_pointer_root_last`] over an [`AsyncAuthorityStore`].
///
/// The production counterpart of the synchronous function above. Per the
/// t7ip ruling the sync trait is the deterministic-verification surface and
/// the async trait is the production surface: both permanent, neither
/// deprecated.
///
/// This is a transport change and nothing else. The two bodies make the same
/// decisions in the same order - same identity derivation, same staged-body
/// precondition, same refusal, same `pointer.advance`. Only the `read_immutable` call
/// differs, because reading the staged body is the only thing this function
/// asks the store for. An edit that makes one of these do something the other
/// does not is the semantic fork condition 1 of that ruling forbids, and
/// `advance_pointer_async_matches_sync_exactly` pins it.
///
/// The context is threaded per call and never held, so a cancellation or a
/// budget arriving mid-operation reaches the store instead of being lost to a
/// context captured once at construction.
pub async fn advance_pointer_root_last_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    pointer: &CapsulePointer,
    capsule: &RepositoryCapsuleBody,
) -> Result<CapsulePointer, ChronicleRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    // `Sync` is the one bound the sync twin does not carry, and it is a
    // transport requirement rather than a semantic one: `&I` is only `Send`
    // when `I` is `Sync`, and a future that is not `Send` cannot be driven by
    // the production runtime. Without it this function compiles and then
    // cannot be used for the surface it exists to serve. It constrains the
    // caller, never the decisions - the body below is unchanged, and
    // `advance_pointer_async_matches_sync_exactly` still pins the two paths
    // to the same behaviour.
    I: BodyIdentity + ?Sized + Sync,
{
    let capsule_id = capsule_identity(identity, capsule)?;
    let key = body_key(IdentityDomain::RepositoryCapsule, capsule)
        .map_err(|_| ChronicleRefusal::CapsuleIdentityUnavailable)?;
    // Identical to the sync path: a body that is absent and a store that
    // cannot answer are the same fact, because neither has proved the data is
    // fetchable.
    if !matches!(
        store.read_immutable(cx, &key).await,
        Ok(ImmutableRead::Present(_))
    ) {
        return Err(ChronicleRefusal::CapsuleBodyNotStaged);
    }
    pointer.advance(capsule_id, capsule)
}
