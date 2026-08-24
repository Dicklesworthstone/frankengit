//! The terminal-outcome index and its recovery path.
//!
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §8.4 is unusually explicit about what this
//! is: a direct identity-to-decision pointer is a **repairable accelerator, not
//! a second truth**. If it is missing after a crash, replay from the authority
//! head reconstructs it. If it *disagrees* with the stream, it fails closed.
//!
//! Both halves are implemented here and both are exercised against the same
//! corpus, because an accelerator nobody cross-checks is indistinguishable from
//! a second source of truth that happens to agree so far.
//!
//! # Why the index is written after the conditional replacement
//!
//! The mutation linearizes at the head replacement (§8.3). The index entry is
//! derived from a decision that is already canonical, so writing it earlier
//! would publish an answer for a transaction that had not been decided. Writing
//! it later means a crash in between leaves the index short — which is exactly
//! the repairable state §8.4 describes, and which [`replay_outcome`] resolves
//! without it.
//!
//! # Walking backwards
//!
//! A head names its decision tail and its predecessor head; a batch names the
//! head it was prepared against. Replay therefore alternates: read the head,
//! read its tail batch, scan the batch, then resolve the batch's predecessor
//! head and repeat. That requires head bodies to be addressable by identity as
//! well as reachable through the head slot, which is why [`publish_decisions`]
//! stages the head body as an immutable object before replacing the slot.

use crate::vocabulary::AuthenticatedHead;
use fgit_codec::wire::encode_body;
use fgit_codec::{
    CodecRefusal, CreationAttemptBody, DecodeLimits, Decoder, Encoder, RepositoryAuthorityHeadBody,
    RepositoryConfigurationBody, RepositoryDecision, RepositoryDecisionBatchBody,
    RepositoryIncarnationConfigurationBody, decode_body,
};
use fgit_crypto::{
    IdentityDomain, MerkleProof, MerkleRefusal, RefStateNonMembershipProof, merkle_leaf,
    merkle_proof, merkle_root, ref_state_non_membership_proof, verify_merkle_proof,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{
    InternalObjectId, RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, RepositoryId, TenantId, TxId,
};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitOid;
use fgit_types::numeric::DecisionSequence;
use fgit_types::refs::RefName;
use fgit_types::vocabulary::{DecisionOutcome, RefusalCode};
use std::collections::BTreeMap;

use crate::async_contract::{AsyncAuthorityStore, DuplicateAbsenceWitness};
use crate::contract::AuthorityStore;
use crate::identity::{IdempotencyKey, canonical_body_id};
use crate::keys::{HeadKey, ImmutableKey};
use crate::seal::{BODY_KEY_PREFIX, SealFailure, body_key};
use fgit_types::HeadGeneration;

use crate::tokens::AuthorityVersionToken;
use crate::vocabulary::{
    AuthorityFailure, AuthorityRefusal, CasOutcome, HeadInit, HeadRead, HeadReadReceipt,
    ImmutableRead, PutOutcome,
};

/// Namespace prefix of a per-identity outcome accelerator slot.
pub const OUTCOME_KEY_PREFIX: &[u8] = b"fg/outcome/v1/";

/// Namespace prefix of an immutable repository-creation-attempt slot.
///
/// The bytes that follow are fixed-width tenant and repository identities plus
/// the digest of the caller-supplied idempotency key. This is not a second
/// routing authority: it is the immutable idempotency record that determines
/// which minted incarnation a lost-response retry must reuse.
pub const CREATION_ATTEMPT_KEY_PREFIX: &[u8] = b"fg/creation-attempt/v1/";

/// Largest number of batches one replay will walk before refusing.
///
/// Replay is bounded before work rather than after: an unbounded backwards walk
/// over an adversarial or corrupt chain is a denial-of-service surface.
pub const MAX_REPLAY_BATCHES: usize = 65_536;

/// What is known about one sealed transaction's terminal decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeLookup {
    /// The transaction has a terminal decision.
    Decided(TerminalOutcome),
    /// The transaction is not decided in the authenticated stream.
    ///
    /// Undecided is a real answer, not an error: infrastructure interruption
    /// before publication leaves a sealed transaction undecided and retryable
    /// (§5.3).
    Undecided,
}

/// The result of recording one repository-creation attempt.
///
/// Both variants carry the authoritative stored body. A retry must use the
/// `Recovered` body rather than its locally minted candidate, because only the
/// first successful put-if-absent chose the repository incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreationAttemptOutcome {
    /// This caller first occupied the attempt slot.
    Created(CreationAttemptBody),
    /// A prior writer occupied the slot with the same fixed request fields.
    Recovered(CreationAttemptBody),
}

impl CreationAttemptOutcome {
    /// The immutable attempt body selected by the creation slot.
    #[must_use]
    pub const fn body(&self) -> &CreationAttemptBody {
        match self {
            Self::Created(body) | Self::Recovered(body) => body,
        }
    }
}

/// One terminal decision, as the index and the stream both report it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalOutcome {
    /// Position in the terminal-decision order, refusals included.
    pub decision_sequence: DecisionSequence,
    /// The terminal outcome itself.
    pub outcome: DecisionOutcome,
}

/// Why an outcome could not be resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutcomeFailure {
    /// The accelerator and the authenticated stream disagree.
    ///
    /// This fails closed. Preferring either side would make the accelerator a
    /// second source of truth, which §8.4 forbids by name.
    AcceleratorConflict {
        /// What the accelerator claims.
        indexed: Box<TerminalOutcome>,
        /// What the stream proves.
        replayed: Box<TerminalOutcome>,
    },
    /// A body the stream references is not present.
    StreamBodyMissing {
        /// Which link was unresolvable.
        link: &'static str,
    },
    /// The backwards walk exceeded its declared bound.
    ReplayBoundExceeded {
        /// The bound.
        limit: usize,
    },
    /// A retained checkpoint does not name a complete decision-log position.
    ///
    /// The checkpoint is evidence for one exact tail. Reaching a head with the
    /// same batch identity but a different decision sequence, or reaching
    /// genesis before the named tail, would otherwise make a partial leaf set
    /// look complete.
    CheckpointPositionMismatch,
    /// A checkpoint leaf set does not reproduce the authenticated root at the
    /// position it claims to summarize.
    CheckpointRootMismatch,
    /// The bytes stored under a body's own identity key are a different body.
    ///
    /// A body key is derived from the body's canonical identity, so the store
    /// is being asked "give me the bytes that hash to this". Bytes that decode
    /// to something else did not come from the body that was requested,
    /// whatever the reason -- a corrupted slot, a backend that resolved the key
    /// loosely, or a caller handed an identity from another repository.
    ///
    /// This fails closed rather than returning the body it found. Accepting it
    /// would be §4's "decoder result accepted without original commitments",
    /// and on the replay path it would let a walk that thinks it is proving one
    /// repository's decision stream read another's.
    BodyIdentityMismatch {
        /// Which link was being resolved.
        link: &'static str,
        /// The identity asked for and the identity the bytes carry.
        ///
        /// Boxed to keep [`OutcomeFailure`] inside `MAX_ERROR_BYTES`; two
        /// identities inline are wider than the whole error budget.
        identities: Box<IdentityDisagreement>,
    },
    /// A head receipt's declared generation disagrees with the body it carries.
    ///
    /// The store told us the slot holds generation N and handed back bytes that
    /// say something else. Continuing would mint a duplicate-absence witness
    /// against a token that names one head while scanning the history of
    /// another, which is §5.2's "one sealed transaction has at most one terminal
    /// decision" resting on a body the token does not cover.
    ///
    /// Unreachable through this crate's own publication: every write derives the
    /// generation from the body it writes (see [`head_generation`] and
    /// [`initialize_repository`]). It fires only where a store is already
    /// inconsistent.
    HeadGenerationSkew {
        /// What the receipt declares.
        receipt: HeadGeneration,
        /// What the decoded body carries.
        body: HeadGeneration,
    },
    /// Sealing, storage, identity, or codec failed underneath.
    /// A cumulative leaf set was folded against a head it was not collected from.
    ///
    /// The CAS-loser case. A set is a snapshot of one head's reachable history;
    /// folding it onto a different head publishes a cumulative root for a
    /// history that was never extended. Every digest in that root is
    /// individually valid and the body is well-formed, so nothing downstream
    /// can detect it -- the same failure mode as a truncated walk, arriving
    /// through timing instead of through a bound.
    ///
    /// §5.2 requires a CAS loser to revalidate against the exact per-attempt
    /// basis. `publish_decisions` already applies this rule to the
    /// duplicate-scan witness; this applies it to the other walk over the same
    /// stream in the same publication.
    ///
    /// Both tokens are `VERSION_TOKEN_BYTES` wide, so this stays inside
    /// `MAX_ERROR_BYTES` unboxed.
    CumulativeIndexStale {
        /// The head the leaf set was collected against.
        observed: AuthorityVersionToken,
        /// The head the caller intends to replace.
        expected: AuthorityVersionToken,
    },
    /// One sealed transaction acquired a second terminal decision.
    ///
    /// §5.2 is the invariant: *one sealed transaction has at most one terminal
    /// decision*. The index is the structure that has to hold it, because §10.4
    /// duplicate detection consults the index to answer "does this `TxId`
    /// already have a decision".
    ///
    /// This fails closed rather than de-duplicating, and the reason is not
    /// merely conservatism. [`outcome_index_root`] commits to a **multiset** of
    /// leaves: a repeated entry is sorted alongside its twin and both are
    /// hashed, so folding one transaction in twice produces a root that no
    /// single-decision leaf set can produce. Silently collapsing the repeat
    /// would hide a §5.2 violation behind a root that still looks well-formed,
    /// and keeping it would publish a root committing to a history in which one
    /// transaction was decided twice. Neither is publishable.
    ///
    /// Boxed to keep [`OutcomeFailure`] inside `MAX_ERROR_BYTES`.
    DuplicateTerminalDecision {
        /// The transaction named twice, and the two decisions offered for it.
        duplicate: Box<DuplicateDecision>,
    },
    Seal(Box<SealFailure>),
    /// A canonical body could not be encoded or decoded.
    Codec(CodecRefusal),
    /// A membership proof was requested for a decision the index does not hold.
    ///
    /// Refused rather than answered with an empty proof: an empty proof
    /// verifies vacuously, and a caller that accepted one would conclude
    /// membership from nothing.
    ///
    /// Boxed to keep [`OutcomeFailure`] inside `MAX_ERROR_BYTES`: a `TxId`
    /// carries a full internal object identity and is wider than the whole
    /// error budget on its own.
    OutcomeNotIndexed(Box<TxId>),
    /// The shared Merkle core refused to build or walk the tree.
    MerkleShape(Box<MerkleRefusal>),
    /// A head's `configuration_root` names no decodable configuration body.
    ///
    /// Refused only on the PROOF-GENERATION path. Verification treats the same
    /// state as legacy v0, because that is the layout such a head is actually
    /// carrying; a proof under it would be a path through a tree that does not
    /// exist.
    ConfigurationUnresolvable,
    /// The supplied caller key does not digest to the body field it purports
    /// to bind.
    ///
    /// Accepting it would make a key select a creation body that records a
    /// different key, defeating the byte-for-byte retry check.
    CreationAttemptKeyMismatch,
    /// A reused creation idempotency key changed one or more fixed request
    /// bytes.
    ///
    /// This is a typed §5.2 refusal: the original immutable body remains
    /// authoritative, and the retry may not repurpose its key to mint a new
    /// incarnation or alter the selected repository facts.
    CreationAttemptFixedFieldsMismatch,
    /// A completed put-if-absent was not readable by its exact attempt key.
    ///
    /// The implementation never treats this as absence: doing so would let a
    /// later writer mint a second incarnation after a lost response.
    CreationAttemptUnresolvable,
}

/// The identity a read asked for beside the identity the bytes actually carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityDisagreement {
    /// The identity whose key was read.
    pub requested: InternalObjectId,
    /// The identity the decoded body re-derives.
    pub found: InternalObjectId,
}

/// One transaction carrying two terminal decisions, as
/// [`OutcomeFailure::DuplicateTerminalDecision`] reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateDecision {
    /// The transaction named twice.
    pub tx_id: TxId,
    /// The decision encountered first.
    ///
    /// From the carried index when the collision crosses the two inputs, and
    /// from the earlier position when it lies within one of them.
    pub existing: TerminalOutcome,
    /// The decision offered for the same transaction.
    pub offered: TerminalOutcome,
}

impl core::fmt::Display for OutcomeFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AcceleratorConflict { .. } => f.write_str(
                "the outcome accelerator disagrees with the authenticated decision stream; \
                 failing closed rather than choosing a side",
            ),
            Self::StreamBodyMissing { link } => {
                write!(f, "the decision stream references a missing {link}")
            }
            Self::ReplayBoundExceeded { limit } => {
                write!(f, "decision-stream replay exceeded {limit} batches")
            }
            Self::CheckpointPositionMismatch => f.write_str(
                "the retained outcome-index checkpoint does not name a reachable exact decision position",
            ),
            Self::CheckpointRootMismatch => f.write_str(
                "the retained outcome-index checkpoint leaves do not reproduce the authenticated outcome root",
            ),
            Self::BodyIdentityMismatch { link, identities } => write!(
                f,
                "the {link} stored under {} decodes to {} instead",
                identities.requested, identities.found
            ),
            Self::HeadGenerationSkew { receipt, body } => write!(
                f,
                "the head receipt declares generation {} but its body carries {}",
                receipt.get(),
                body.get()
            ),
            Self::CumulativeIndexStale { .. } => f.write_str(
                "the cumulative outcome index was collected against a different head \
                 than the one being replaced; failing closed rather than folding a \
                 leaf set from another history",
            ),
            Self::DuplicateTerminalDecision { duplicate } => write!(
                f,
                "transaction {} carries two terminal decisions (sequences {} and {}); \
                 one sealed transaction has at most one",
                duplicate.tx_id,
                duplicate.existing.decision_sequence.get(),
                duplicate.offered.decision_sequence.get()
            ),
            Self::Seal(failure) => write!(f, "{failure}"),
            Self::Codec(refusal) => write!(f, "canonical encoding refused: {refusal}"),
            Self::OutcomeNotIndexed(tx_id) => write!(
                f,
                "the outcome index does not hold that decision for {tx_id}, so no membership \
                 proof exists"
            ),
            Self::MerkleShape(refusal) => write!(f, "outcome-index tree refused: {refusal}"),
            Self::ConfigurationUnresolvable => f.write_str(
                "the head's configuration_root names no decodable configuration body, so the \
                 root layout cannot be established for proof generation",
            ),
            Self::CreationAttemptKeyMismatch => f.write_str(
                "the supplied creation idempotency key does not match the digest committed by \
                 the creation attempt body",
            ),
            Self::CreationAttemptFixedFieldsMismatch => f.write_str(
                "the creation idempotency key was reused with different fixed request bytes",
            ),
            Self::CreationAttemptUnresolvable => f.write_str(
                "the immutable creation attempt could not be read after its slot was occupied",
            ),
        }
    }
}

impl std::error::Error for OutcomeFailure {}

impl From<SealFailure> for OutcomeFailure {
    fn from(failure: SealFailure) -> Self {
        Self::Seal(Box::new(failure))
    }
}

impl From<CodecRefusal> for OutcomeFailure {
    fn from(refusal: CodecRefusal) -> Self {
        Self::Codec(refusal)
    }
}

impl From<HeadBodyRefusal> for OutcomeFailure {
    fn from(refusal: HeadBodyRefusal) -> Self {
        match refusal {
            HeadBodyRefusal::Codec(codec) => Self::Codec(codec),
            HeadBodyRefusal::GenerationMismatch { receipt, body } => {
                Self::HeadGenerationSkew { receipt, body }
            }
        }
    }
}

impl From<crate::identity::IdentityRefusal> for OutcomeFailure {
    fn from(refusal: crate::identity::IdentityRefusal) -> Self {
        Self::Seal(Box::new(SealFailure::Identity(Box::new(refusal))))
    }
}

impl From<crate::vocabulary::AuthorityFailure> for OutcomeFailure {
    fn from(failure: crate::vocabulary::AuthorityFailure) -> Self {
        Self::Seal(Box::new(SealFailure::Store(failure)))
    }
}

/// The deterministic accelerator slot key for one identity.
pub fn outcome_key(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
) -> Result<ImmutableKey, SealFailure> {
    let mut bytes = Vec::with_capacity(OUTCOME_KEY_PREFIX.len() + 96);
    bytes.extend_from_slice(OUTCOME_KEY_PREFIX);
    bytes.extend_from_slice(tenant_id.as_bytes());
    bytes.extend_from_slice(repository_id.as_bytes());
    bytes.extend_from_slice(tx_id.as_internal_object_id().digest().as_bytes());
    Ok(ImmutableKey::new(bytes)?)
}

fn encode_outcome(outcome: &TerminalOutcome) -> Result<Vec<u8>, CodecRefusal> {
    let mut out = Encoder::new();
    out.write_scalar(outcome.decision_sequence.get());
    out.write_raw_byte(outcome.outcome.discriminant());
    match &outcome.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => out.write_internal_object_id(repository_commit_id.as_internal_object_id())?,
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => {
            out.write_scalar(code.code_point());
            out.write_internal_object_id(refusal_record_id.as_internal_object_id())?;
        }
    }
    Ok(out.into_bytes())
}

fn decode_outcome(bytes: &[u8]) -> Result<TerminalOutcome, CodecRefusal> {
    let mut input = Decoder::new(bytes, DecodeLimits::DEFAULT);
    let decision_sequence = DecisionSequence::try_new(input.read_scalar::<u64>("sequence")?)?;
    let offset = input.offset();
    let outcome = match input.read_raw_byte("DecisionOutcome")? {
        1 => DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_internal_object_id(
                input.read_internal_object_id()?,
            )?,
        },
        2 => {
            let code = RefusalCode::from_code_point(input.read_scalar::<u16>("refusal_code")?)?;
            DecisionOutcome::Refused {
                code,
                refusal_record_id: RefusalRecordId::from_internal_object_id(
                    input.read_internal_object_id()?,
                )?,
            }
        }
        observed => {
            return Err(CodecRefusal::VariantUnknown {
                field: "DecisionOutcome",
                observed: u32::from(observed),
                offset,
            });
        }
    };
    input.finish()?;
    Ok(TerminalOutcome {
        decision_sequence,
        outcome,
    })
}

/// Read the accelerator entry for one identity, if it has one.
pub fn indexed_outcome<S>(
    store: &S,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
) -> Result<OutcomeLookup, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = outcome_key(tenant_id, repository_id, tx_id)?;
    interpret_indexed_outcome(store.read_immutable(&key)?)
}

/// Interpret one accelerator read.
///
/// Shared core (t7ip condition 1): the read differs between the synchronous and
/// asynchronous drivers, this interpretation does not. An absent slot means the
/// accelerator has no answer — **not** that the transaction is undecided, which
/// is why [`reconcile_outcome`] must still consult the authenticated replay.
pub fn interpret_indexed_outcome(read: ImmutableRead) -> Result<OutcomeLookup, OutcomeFailure> {
    match read {
        ImmutableRead::Absent => Ok(OutcomeLookup::Undecided),
        ImmutableRead::Present(bytes) => Ok(OutcomeLookup::Decided(decode_outcome(&bytes)?)),
    }
}

/// The asynchronous sibling of [`indexed_outcome`].
///
/// Identical semantics by construction: the same key derivation, the same
/// [`interpret_indexed_outcome`]. Only the read is awaited.
///
/// # Errors
///
/// Propagates the store's failure and any decode refusal, exactly as the
/// synchronous form does.
pub async fn indexed_outcome_async<S>(
    store: &S,
    cx: &S::Context,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
) -> Result<OutcomeLookup, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = outcome_key(tenant_id, repository_id, tx_id)?;
    interpret_indexed_outcome(store.read_immutable(cx, &key).await?)
}

/// Read one authority head body by identity, on the verification surface.
///
/// The bytes are read by the key the identity derives, decoded under
/// [`DecodeLimits::DEFAULT`], and required to re-identify as `head_id`.
///
/// # Why this is public
///
/// A consumer resolving `predecessor_head_id` or `decision_tail_id` off an
/// authenticated head needs the bytes those identities name. Without this it
/// reconstructs the `fg/body/v1/` key convention itself, and a second copy of a
/// key derivation is a second copy of a rule nobody can hold it to. The
/// synchronous twin exists for the same reason the trait does: this surface is
/// the deterministic one, not a legacy one, and a consumer writing a
/// reproducible test of its own walk should not have to go async to do it.
///
/// # Errors
///
/// [`OutcomeFailure::StreamBodyMissing`] when the slot is empty,
/// [`OutcomeFailure::Codec`] when the bytes do not decode, and
/// [`OutcomeFailure::BodyIdentityMismatch`] when they decode to a different
/// head than the one requested.
pub fn read_authority_head_body<S>(
    store: &S,
    head_id: RepositoryAuthorityHeadId,
) -> Result<RepositoryAuthorityHeadBody, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key_for_id(head_id.as_internal_object_id())?;
    match store.read_immutable(&key)? {
        ImmutableRead::Absent => Err(OutcomeFailure::StreamBodyMissing { link: "head body" }),
        ImmutableRead::Present(bytes) => identified_head_body(&bytes, head_id),
    }
}

/// Read one decision batch body by identity, on the verification surface.
///
/// See [`read_authority_head_body`] for why this is public and what it checks.
///
/// # Errors
///
/// [`OutcomeFailure::StreamBodyMissing`] when the slot is empty,
/// [`OutcomeFailure::Codec`] when the bytes do not decode, and
/// [`OutcomeFailure::BodyIdentityMismatch`] when they decode to a different
/// batch than the one requested.
pub fn read_decision_batch_body<S>(
    store: &S,
    batch_id: RepositoryDecisionBatchId,
) -> Result<RepositoryDecisionBatchBody, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key_for_id(batch_id.as_internal_object_id())?;
    match store.read_immutable(&key)? {
        ImmutableRead::Absent => Err(OutcomeFailure::StreamBodyMissing {
            link: "decision batch",
        }),
        ImmutableRead::Present(bytes) => identified_batch_body(&bytes, batch_id),
    }
}

/// Decode a head receipt's bytes, requiring the two generations to agree.
///
/// A receipt is the store's claim that a slot holds these bytes at this
/// generation. Those are two separate statements and nothing makes the store
/// keep them consistent, so this compares them before anything acts on the
/// body.
///
/// # Why this is a function rather than four inline decodes
///
/// It used to be four inline decodes plus one cross-checked accessor, which is
/// two implementations of "what does this head say" — free to disagree, which
/// is the drift `frankengit-0kqi` was filed for one crate over. The accessor's
/// own documentation said a caller who skips the comparison "can act on a body
/// one generation away from the head it just authenticated"; four callers in
/// this file were doing exactly that.
///
/// # Errors
///
/// [`HeadBodyRefusal::Codec`] when the bytes do not decode, and
/// [`HeadBodyRefusal::GenerationMismatch`] when the generations disagree.
fn head_body_of(receipt: &HeadReadReceipt) -> Result<RepositoryAuthorityHeadBody, HeadBodyRefusal> {
    let body: RepositoryAuthorityHeadBody = decode_body(receipt.body(), DecodeLimits::DEFAULT)?;
    let declared = receipt.generation();
    if body.generation == declared {
        Ok(body)
    } else {
        Err(HeadBodyRefusal::GenerationMismatch {
            receipt: declared,
            body: body.generation,
        })
    }
}

/// The immutable slot an already-identified body occupies.
///
/// The twin of [`body_key`], which derives the identity from the body. This one
/// is for the walk, which has the identity and wants the bytes.
///
/// It takes no prefix parameter. Every caller passed the same literal, and a
/// parameter with one possible value is an invitation to pass a second one:
/// this function spelled `b"fg/body/v1/"` out while [`BODY_KEY_PREFIX`] sat
/// exported two modules over, so the two derivations were already free to
/// drift. They cannot now.
/// Derives the immutable-store key for an already domain-checked body identity.
///
/// Readers know an identity before they have the body bytes needed by
/// [`body_key`]. Keeping that derivation here ensures immutable reads use the
/// same namespace as body staging rather than rebuilding `BODY_KEY_PREFIX` in
/// each consumer.
pub fn body_key_for_id(id: &InternalObjectId) -> Result<ImmutableKey, SealFailure> {
    let mut bytes = Vec::with_capacity(BODY_KEY_PREFIX.len() + 80);
    bytes.extend_from_slice(BODY_KEY_PREFIX);
    bytes.extend_from_slice(id.domain().as_bytes());
    bytes.push(b'/');
    bytes.extend_from_slice(id.digest().as_bytes());
    Ok(ImmutableKey::new(bytes)?)
}

/// Decode a head body's bytes and require them to re-identify as `expected`.
///
/// Shared by both surfaces so the check cannot hold on one and lapse on the
/// other, which is the drift the sibling-surface doctrine exists to prevent.
///
/// # Cost
///
/// One canonical re-encode per body read. That is real, it is on the replay
/// path, and it is bounded by [`MAX_REPLAY_BATCHES`]. It buys the property that
/// a body is never trusted on the strength of the key it was filed under.
fn identified_head_body(
    bytes: &[u8],
    expected: RepositoryAuthorityHeadId,
) -> Result<RepositoryAuthorityHeadBody, OutcomeFailure> {
    let body: RepositoryAuthorityHeadBody = decode_body(bytes, DecodeLimits::DEFAULT)?;
    let found = authority_head_identity(&body)?;
    if found == expected {
        Ok(body)
    } else {
        Err(OutcomeFailure::BodyIdentityMismatch {
            link: "head body",
            identities: Box::new(IdentityDisagreement {
                requested: expected.into_internal_object_id(),
                found: found.into_internal_object_id(),
            }),
        })
    }
}

/// Decode a decision batch's bytes and require them to re-identify as `expected`.
///
/// See [`identified_head_body`]; the same reasoning and the same cost.
fn identified_batch_body(
    bytes: &[u8],
    expected: RepositoryDecisionBatchId,
) -> Result<RepositoryDecisionBatchBody, OutcomeFailure> {
    let body: RepositoryDecisionBatchBody = decode_body(bytes, DecodeLimits::DEFAULT)?;
    let found = decision_batch_identity(&body)?;
    if found == expected {
        Ok(body)
    } else {
        Err(OutcomeFailure::BodyIdentityMismatch {
            link: "decision batch",
            identities: Box::new(IdentityDisagreement {
                requested: expected.into_internal_object_id(),
                found: found.into_internal_object_id(),
            }),
        })
    }
}

/// Resolve one identity's terminal decision by replaying the authenticated stream.
///
/// This is the recovery path: it consults no accelerator and would give the
/// same answer on a node whose index was wiped.
/// Decide which batch the replay walk reads next, and enforce the bound.
///
/// Shared core (t7ip condition 1). The walk's *reads* differ between the
/// synchronous and asynchronous drivers; this decision does not, so both call
/// it and the bound cannot be enforced in one driver and forgotten in the
/// other — which is the failure mode where an async replay walks forever on a
/// cyclic or adversarial chain.
///
/// Advances `walked` as a side effect so the caller cannot forget to count.
///
/// # Errors
///
/// [`OutcomeFailure::ReplayBoundExceeded`] once the walk would exceed
/// [`MAX_REPLAY_BATCHES`].
pub const fn next_batch_to_replay(
    head: &RepositoryAuthorityHeadBody,
    walked: &mut usize,
) -> Result<Option<RepositoryDecisionBatchId>, OutcomeFailure> {
    let Some(batch_id) = head.decision_tail_id else {
        return Ok(None);
    };
    *walked = walked.saturating_add(1);
    if *walked > MAX_REPLAY_BATCHES {
        return Err(OutcomeFailure::ReplayBoundExceeded {
            limit: MAX_REPLAY_BATCHES,
        });
    }
    Ok(Some(batch_id))
}

/// Find one transaction's terminal outcome within a decision batch.
///
/// Shared core (t7ip condition 1): the search is identical for both drivers.
#[must_use]
pub fn scan_batch_for(batch: &RepositoryDecisionBatchBody, tx_id: TxId) -> Option<TerminalOutcome> {
    batch
        .decisions
        .iter()
        .find(|decision| decision.tx_id == tx_id)
        .map(|decision| TerminalOutcome {
            decision_sequence: decision.decision_sequence,
            outcome: decision.outcome,
        })
}

/// What an authenticated duplicate scan found.
///
/// The two arms are the inputs to requirement 2's three-way verdict: `Absent`
/// lets publication proceed, `Found` becomes `AlreadyDecided` naming the
/// transactions and their existing terminal outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DuplicateScan {
    /// No transaction in the request has a prior terminal decision.
    ///
    /// Carries the witness bound to the head token the walk was performed
    /// against — the only way to obtain one.
    Absent(DuplicateAbsenceWitness),
    /// At least one transaction is already terminal, with its decision.
    ///
    /// Carries the observed token for the same reason [`Self::Absent`] does:
    /// the caller cannot classify this without knowing whether the head it
    /// walked is still the head it intends to replace.
    Found {
        /// The head token this walk observed.
        observed: AuthorityVersionToken,
        /// The transactions already terminal, with their decisions.
        decided: Vec<(TxId, TerminalOutcome)>,
    },
}

/// Walk the authenticated decision stream for prior decisions on `tx_ids`.
///
/// This is requirement 2 of the §5.2 ruling: whether a transaction already has
/// a terminal decision is answered **from the authenticated stream reachable
/// from the current head**, never from an accelerator row's presence or
/// absence. A missing accelerator row means "resolve it authoritatively", and
/// reading it as "no decision exists" is the TOCTOU that produced the defect.
///
/// The returned witness is bound to the head token this walk observed, so the
/// publication that consumes it is conditioned on the same state the check was
/// performed against. That binding is what makes an upstream check sound; see
/// [`AsyncAuthorityStore::publish_head_with_outcomes`].
///
/// # Errors
///
/// Propagates store failures and any decode refusal, and refuses a stream
/// longer than [`MAX_REPLAY_BATCHES`].
pub fn scan_for_existing_decisions<S>(
    store: &S,
    head_key: &HeadKey,
    tx_ids: &[TxId],
) -> Result<DuplicateScan, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        // No head at all: nothing can have been decided.
        //
        // The witness minted here binds to a zero token, which will not match
        // any real `expected` the caller presents — so the primitive refuses.
        // That is deliberate and it fails CLOSED: with no head there is nothing
        // to conditionally replace, and publication goes through
        // `initialize_head` rather than a CAS. A caller that reaches the atomic
        // publish against an absent head has a bug, and gets a refusal rather
        // than a witness that silently validates nothing.
        return Ok(DuplicateScan::Absent(
            DuplicateAbsenceWitness::minted_against(AuthorityVersionToken::from_opaque_bytes(
                [0_u8; crate::tokens::VERSION_TOKEN_BYTES],
            )),
        ));
    };
    let observed = receipt.token();
    let mut head: RepositoryAuthorityHeadBody = head_body_of(&receipt)?;
    let mut walked = 0_usize;
    let mut found: Vec<(TxId, TerminalOutcome)> = Vec::new();

    while let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? {
        let batch = read_decision_batch_body(store, batch_id)?;
        for tx_id in tx_ids {
            if let Some(outcome) = scan_batch_for(&batch, *tx_id) {
                found.push((*tx_id, outcome));
            }
        }
        let Some(previous) = read_predecessor(store, batch.predecessor_head_id)? else {
            break;
        };
        head = previous;
    }

    if found.is_empty() {
        Ok(DuplicateScan::Absent(
            DuplicateAbsenceWitness::minted_against(observed),
        ))
    } else {
        Ok(DuplicateScan::Found {
            observed,
            decided: found,
        })
    }
}

pub fn replay_outcome<S>(
    store: &S,
    head_key: &HeadKey,
    tx_id: TxId,
) -> Result<OutcomeLookup, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        return Ok(OutcomeLookup::Undecided);
    };
    let mut head: RepositoryAuthorityHeadBody = head_body_of(&receipt)?;
    let mut walked = 0_usize;
    loop {
        let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? else {
            return Ok(OutcomeLookup::Undecided);
        };
        let batch = read_decision_batch_body(store, batch_id)?;
        if let Some(found) = scan_batch_for(&batch, tx_id) {
            return Ok(OutcomeLookup::Decided(found));
        }
        let predecessor = batch.predecessor_head_id;
        let Some(previous) = read_predecessor(store, predecessor)? else {
            return Ok(OutcomeLookup::Undecided);
        };
        head = previous;
    }
}

fn read_predecessor<S>(
    store: &S,
    head_id: RepositoryAuthorityHeadId,
) -> Result<Option<RepositoryAuthorityHeadBody>, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let body = read_authority_head_body(store, head_id)?;
    // The genesis head has no decision tail, so the walk ends there.
    Ok(body.decision_tail_id.map(|_| body))
}

/// Answer "what happened to this transaction" using both paths, and refuse to
/// choose between them if they disagree.
pub fn resolve_outcome<S>(
    store: &S,
    head_key: &HeadKey,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
) -> Result<OutcomeLookup, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let replayed = replay_outcome(store, head_key, tx_id)?;
    let indexed = indexed_outcome(store, tenant_id, repository_id, tx_id)?;
    reconcile_outcome(indexed, replayed)
}

/// Reconcile the accelerator's answer with the authenticated replay.
///
/// **This is the shared core of outcome resolution** (t7ip condition 1). The
/// two reads differ between the synchronous and asynchronous drivers; this
/// decision does not, and it lives here exactly once so the two cannot fork.
///
/// # Why it takes both answers rather than fetching them
///
/// Not merely to be pure. Replay of the authenticated decision stream is
/// **authoritative** and the accelerator is a repairable hint, because the
/// accelerator is written *after* the head moves: a crash in that window leaves
/// a transaction genuinely decided with no accelerator entry. Consulting the
/// accelerator alone reads that as undecided and returns "replannable" —
/// telling a caller to replan a transaction that already committed, which is
/// how one sealed transaction acquires two terminal decisions.
///
/// Requiring both answers as arguments makes an accelerator-only resolver
/// **unrepresentable** rather than merely discouraged. An asynchronous port
/// that quietly dropped the replay would have to change this signature to do
/// it, instead of silently omitting a call.
pub fn reconcile_outcome(
    indexed: OutcomeLookup,
    replayed: OutcomeLookup,
) -> Result<OutcomeLookup, OutcomeFailure> {
    match (indexed, replayed) {
        // The accelerator is allowed to be behind: that is the repairable
        // state a crash between publication and indexing leaves.
        (OutcomeLookup::Undecided, answer) => Ok(answer),
        (OutcomeLookup::Decided(left), OutcomeLookup::Decided(right)) if left == right => {
            Ok(OutcomeLookup::Decided(left))
        }
        (OutcomeLookup::Decided(indexed), OutcomeLookup::Decided(replayed)) => {
            Err(OutcomeFailure::AcceleratorConflict {
                indexed: Box::new(indexed),
                replayed: Box::new(replayed),
            })
        }
        // An accelerator that claims a decision the stream does not contain is
        // the dangerous direction, and it is the one that fails closed.
        (OutcomeLookup::Decided(indexed), OutcomeLookup::Undecided) => {
            Err(OutcomeFailure::AcceleratorConflict {
                indexed: Box::new(indexed),
                replayed: Box::new(indexed),
            })
        }
    }
}

/// The schema pinning the outcome-index tree construction.
const fn outcome_index_schema() -> fgit_types::label::SchemaId {
    fgit_types::label::SchemaId::new(
        fgit_types::label::SchemaFamily::from_static("outcome-index"),
        1,
        0,
    )
}

/// The commitment over one repository's terminal-outcome index.
///
/// A binary Merkle tree over the index entries, sorted by leaf bytes so the
/// root is a function of the *set* rather than of any insertion order. Leaves
/// and interior nodes use the two separate registered Merkle domains, which is
/// what stops an interior node's preimage being presented as a leaf.
///
/// An odd node at a level is promoted unchanged rather than paired with itself,
/// because duplicating a node is the classic construction that lets two
/// different multisets produce one root.
///
/// # Scope of this function
///
/// It computes the root. It does **not** gate publication. The
/// `resulting_outcome_index_root` field on a batch is a value several crates
/// must agree on, and the reference state machine is the other party to that
/// agreement, so wiring this in as a publication precondition is a cross-crate
/// decision rather than one this crate may take alone. The check is
/// deliberately absent rather than unilaterally imposed.
pub fn outcome_index_root(entries: &[(TxId, TerminalOutcome)]) -> Result<Digest, OutcomeFailure> {
    Ok(Digest::new(
        IdentityDomain::MerkleNode.algorithm().id(),
        merkle_root(outcome_index_schema(), &ordered_outcome_leaves(entries)?),
    ))
}

// --- the head-selected root layout (frankengit-ls44) ---------------------------
//
// A head already carries `configuration_root`. This is the code that turns it
// into a `RootLayoutVersion`, which is what makes the layout HEAD-SELECTED
// rather than a convention every verifier reimplements.
//
// The asymmetry below is deliberate and is the orchestrator's ruling, not an
// inconsistency: a head whose `configuration_root` does not resolve to a
// decodable body is treated as **v0 legacy for verification** and as a **typed
// refusal for proof generation**.
//
// Verification defaults to v0 because that is what such a head actually
// carries: every root published before this vocabulary existed is a whole-body
// digest, and refusing to verify them would break heads that are not wrong.
// Proof GENERATION refuses because emitting a proof under a layout that has no
// tree would be emitting something that cannot exist — and a caller handed one
// would verify it vacuously.

/// Derive the immutable slot for one caller-supplied creation idempotency key.
///
/// The slot's fixed-width scope prevents a key used under one repository from
/// selecting a creation record under another. The raw client key never enters
/// durable state; its canonical digest is sufficient to select the record and
/// is checked again against the body before any write.
fn creation_attempt_key(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    idempotency_key: &IdempotencyKey,
) -> Result<ImmutableKey, OutcomeFailure> {
    let key_digest = idempotency_key.digest();
    let mut bytes = Vec::with_capacity(CREATION_ATTEMPT_KEY_PREFIX.len() + 16 + 16 + 2 + 32);
    bytes.extend_from_slice(CREATION_ATTEMPT_KEY_PREFIX);
    bytes.extend_from_slice(tenant_id.as_bytes());
    bytes.extend_from_slice(repository_id.as_bytes());
    bytes.extend_from_slice(&key_digest.algorithm().code_point().to_be_bytes());
    bytes.extend_from_slice(key_digest.bytes().as_bytes());
    Ok(ImmutableKey::new(bytes).map_err(SealFailure::from)?)
}

/// Require that the body actually commits to the caller key that selected it.
fn validate_creation_attempt_key(
    attempt: &CreationAttemptBody,
    idempotency_key: &IdempotencyKey,
) -> Result<(), OutcomeFailure> {
    if attempt.idempotency_key_digest == idempotency_key.digest() {
        Ok(())
    } else {
        Err(OutcomeFailure::CreationAttemptKeyMismatch)
    }
}

/// Decode a stored creation body and require an exact fixed-request retry.
fn recovered_creation_attempt(
    bytes: &[u8],
    requested: &CreationAttemptBody,
) -> Result<CreationAttemptOutcome, OutcomeFailure> {
    let stored: CreationAttemptBody = decode_body(bytes, DecodeLimits::DEFAULT)?;
    if stored.fixed_request_bytes()? != requested.fixed_request_bytes()? {
        return Err(OutcomeFailure::CreationAttemptFixedFieldsMismatch);
    }
    Ok(CreationAttemptOutcome::Recovered(stored))
}

/// Record a repository-creation attempt or recover the first writer's result.
///
/// The caller must supply an explicit [`IdempotencyKey`]. On an empty slot,
/// its minted incarnation is committed with `put_if_absent`; if the response is
/// lost, a retry may present a freshly minted candidate but must receive the
/// immutable incarnation already stored. Reusing a key with any different
/// fixed request bytes is a typed refusal, never a replacement.
///
/// # Errors
///
/// Store ambiguity remains ambiguity. A caller resolves it by retrying this
/// exact operation with the same caller key; the retry reads the occupied slot
/// and either recovers its body or fails closed.
pub fn record_creation_attempt<S>(
    store: &S,
    idempotency_key: &IdempotencyKey,
    attempt: &CreationAttemptBody,
) -> Result<CreationAttemptOutcome, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    validate_creation_attempt_key(attempt, idempotency_key)?;
    let key = creation_attempt_key(attempt.tenant_id, attempt.repository_id, idempotency_key)?;
    let encoded = encode_body(attempt)?;

    match store.put_if_absent(&key, &encoded)? {
        PutOutcome::Created => Ok(CreationAttemptOutcome::Created(*attempt)),
        PutOutcome::IdenticalRetry | PutOutcome::Conflict => {
            let ImmutableRead::Present(bytes) = store.read_immutable(&key)? else {
                return Err(OutcomeFailure::CreationAttemptUnresolvable);
            };
            recovered_creation_attempt(&bytes, attempt)
        }
    }
}

/// The production asynchronous twin of [`record_creation_attempt`].
///
/// It deliberately retains the same occupied-slot read and byte-for-byte
/// validation. A production node therefore cannot turn a transport retry into
/// a second incarnation merely because its authority backend is asynchronous.
pub async fn record_creation_attempt_async<S>(
    store: &S,
    cx: &S::Context,
    idempotency_key: &IdempotencyKey,
    attempt: &CreationAttemptBody,
) -> Result<CreationAttemptOutcome, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    validate_creation_attempt_key(attempt, idempotency_key)?;
    let key = creation_attempt_key(attempt.tenant_id, attempt.repository_id, idempotency_key)?;
    let encoded = encode_body(attempt)?;

    match store.put_if_absent(cx, &key, &encoded).await? {
        PutOutcome::Created => Ok(CreationAttemptOutcome::Created(*attempt)),
        PutOutcome::IdenticalRetry | PutOutcome::Conflict => {
            let ImmutableRead::Present(bytes) = store.read_immutable(cx, &key).await? else {
                return Err(OutcomeFailure::CreationAttemptUnresolvable);
            };
            recovered_creation_attempt(&bytes, attempt)
        }
    }
}

/// The immutable slot a repository configuration body occupies.
fn configuration_key(root: &Digest) -> Result<ImmutableKey, OutcomeFailure> {
    let identity = InternalObjectId::new(
        root.algorithm(),
        IdentityDomain::RepositoryConfiguration.domain_tag(),
        CANONICAL_CODEC_VERSION,
        *root.bytes(),
    );
    Ok(body_key_for_id(&identity)?)
}

/// Stage a repository configuration body and return the root a head selects it by.
///
/// The returned digest is what goes in `RepositoryAuthorityHeadBody::
/// configuration_root`. Publishing a head that names it is what advances the
/// repository's layout — an ordinary head transition, with no rewrite of
/// anything already published.
///
/// # Errors
///
/// Whatever the store or the canonical encoder refuses.
pub fn stage_repository_configuration<S>(
    store: &S,
    configuration: &RepositoryConfigurationBody,
) -> Result<Digest, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key(IdentityDomain::RepositoryConfiguration, configuration)?;
    store.put_if_absent(&key, &encode_body(configuration)?)?;
    let identity = canonical_body_id(
        IdentityDomain::RepositoryConfiguration,
        CANONICAL_CODEC_VERSION,
        configuration,
    )?;
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

/// Stage an incarnation-aware repository configuration body and return the
/// root an authority head selects it by.
///
/// This uses the existing configuration slot but a schema-major-2 body. It is
/// intentionally distinct from [`stage_repository_configuration`]: a caller
/// selecting a v1 configuration cannot accidentally satisfy a resolver that
/// requires the minted incarnation binding.
///
/// # Errors
///
/// Whatever the store or the canonical encoder refuses.
pub fn stage_repository_incarnation_configuration<S>(
    store: &S,
    configuration: &RepositoryIncarnationConfigurationBody,
) -> Result<Digest, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key(IdentityDomain::RepositoryConfiguration, configuration)?;
    store.put_if_absent(&key, &encode_body(configuration)?)?;
    let identity = canonical_body_id(
        IdentityDomain::RepositoryConfiguration,
        CANONICAL_CODEC_VERSION,
        configuration,
    )?;
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

/// The layout a head selects, for **verification**.
///
/// A `configuration_root` absent from the store yields
/// [`RootLayoutVersion::LegacyWholeBody`], because a head that predates this
/// vocabulary carries that layout. A *present* body must decode under this
/// exact configuration schema; treating a version-skewed body as absent would
/// silently replace the layout its authenticated head selected.
///
/// Note what is NOT defaulted: a body that decodes but names a layout version
/// this build does not know is a **refusal**, not a fall back to v0. An unknown
/// version means the head is describing something newer than we can read, and
/// reading it as legacy would be a confident wrong answer.
///
/// # Errors
///
/// Whatever the store refuses, and [`OutcomeFailure::Codec`] for a body that
/// decodes into an unknown layout version.
pub fn root_layout_for_verification<S>(
    store: &S,
    configuration_root: &Digest,
) -> Result<RootLayoutVersion, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = configuration_key(configuration_root)?;
    match store.read_immutable(&key)? {
        ImmutableRead::Absent => Ok(RootLayoutVersion::LegacyWholeBody),
        ImmutableRead::Present(bytes) => Ok(decode_body::<RepositoryConfigurationBody>(
            &bytes,
            DecodeLimits::DEFAULT,
        )?
        .root_layout),
    }
}

/// The layout a head selects, for **proof generation**.
///
/// Unlike [`root_layout_for_verification`], an unresolvable or undecodable
/// `configuration_root` is a typed refusal here. A proof generated under an
/// assumed legacy layout would be a proof of nothing: v0 has no tree, so there
/// is no path to hand over, and silently producing one is worse than refusing.
///
/// # Errors
///
/// [`OutcomeFailure::ConfigurationUnresolvable`] when the root names no stored
/// body, and [`OutcomeFailure::Codec`] when a present body cannot decode under
/// this build's exact schema.
pub fn root_layout_for_proof<S>(
    store: &S,
    configuration_root: &Digest,
) -> Result<RootLayoutVersion, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    Ok(read_repository_configuration(store, configuration_root)?.root_layout)
}

/// Reads the exact canonical repository configuration named by an authority
/// head.
///
/// Unlike [`root_layout_for_verification`], this is a complete configuration
/// read: absence, a previous schema minor without the required object-format
/// field, and malformed bytes are all refusals. In particular it never turns
/// an old or unreadable object-format declaration into SHA-1.
///
/// # Errors
///
/// [`OutcomeFailure::ConfigurationUnresolvable`] when no body is stored at the
/// selected root, and [`OutcomeFailure::Codec`] when the present body cannot be
/// decoded by this build's exact schema.
pub fn read_repository_configuration<S>(
    store: &S,
    configuration_root: &Digest,
) -> Result<RepositoryConfigurationBody, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = configuration_key(configuration_root)?;
    let ImmutableRead::Present(bytes) = store.read_immutable(&key)? else {
        return Err(OutcomeFailure::ConfigurationUnresolvable);
    };
    Ok(decode_body(&bytes, DecodeLimits::DEFAULT)?)
}

/// Reads the exact incarnation-aware configuration selected by an authority
/// head.
///
/// This is a strict resolver, deliberately matching
/// [`root_layout_for_proof`] rather than the verification resolver. An absent
/// root, a selected v1 body, or malformed v2 bytes is a refusal: none may be
/// interpreted as a legacy configuration because each lacks the binding that
/// keeps a stale repository incarnation from resolving as current.
///
/// # Errors
///
/// [`OutcomeFailure::ConfigurationUnresolvable`] when no body is stored at the
/// selected root, and [`OutcomeFailure::Codec`] when a present body is not the
/// exact v2 incarnation-aware schema.
pub fn read_repository_incarnation_configuration<S>(
    store: &S,
    configuration_root: &Digest,
) -> Result<RepositoryIncarnationConfigurationBody, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = configuration_key(configuration_root)?;
    let ImmutableRead::Present(bytes) = store.read_immutable(&key)? else {
        return Err(OutcomeFailure::ConfigurationUnresolvable);
    };
    Ok(decode_body(&bytes, DecodeLimits::DEFAULT)?)
}

// --- the production surface for the carrier (frankengit-m01t) -----------------
//
// FsqliteAuthorityStore implements AsyncAuthorityStore only, so without these a
// production node cannot resolve its own root layout — and a verified read
// cannot know whether a membership proof is admissible at all.
//
// Every rule below is the same rule the synchronous surface applies, because
// neither surface owns it: `configuration_key` defines the selected immutable
// slot, and the typed codec owns its exact schema. In particular the
// v0-for-verification / refuse-for-complete-read asymmetry cannot drift between
// the two, which matters more here than usual — a node that silently assumed
// v0 or SHA-1 would operate in the wrong repository domain.

/// Stage a repository configuration body, on the production surface.
///
/// The asynchronous twin of [`stage_repository_configuration`].
///
/// # Errors
///
/// Whatever the store or the canonical encoder refuses.
pub async fn stage_repository_configuration_async<S>(
    store: &S,
    cx: &S::Context,
    configuration: &RepositoryConfigurationBody,
) -> Result<Digest, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = body_key(IdentityDomain::RepositoryConfiguration, configuration)?;
    store
        .put_if_absent(cx, &key, &encode_body(configuration)?)
        .await?;
    let identity = canonical_body_id(
        IdentityDomain::RepositoryConfiguration,
        CANONICAL_CODEC_VERSION,
        configuration,
    )?;
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

/// Stage an incarnation-aware repository configuration body on the production
/// surface.
///
/// The asynchronous twin of [`stage_repository_incarnation_configuration`].
///
/// # Errors
///
/// Whatever the store or the canonical encoder refuses.
pub async fn stage_repository_incarnation_configuration_async<S>(
    store: &S,
    cx: &S::Context,
    configuration: &RepositoryIncarnationConfigurationBody,
) -> Result<Digest, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = body_key(IdentityDomain::RepositoryConfiguration, configuration)?;
    store
        .put_if_absent(cx, &key, &encode_body(configuration)?)
        .await?;
    let identity = canonical_body_id(
        IdentityDomain::RepositoryConfiguration,
        CANONICAL_CODEC_VERSION,
        configuration,
    )?;
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

/// The layout a head selects, for verification, on the production surface.
///
/// The asynchronous twin of [`root_layout_for_verification`]. An absent root
/// is legacy for verification; every present body must decode under the exact
/// current schema.
///
/// # Errors
///
/// Whatever the store refuses, and [`OutcomeFailure::Codec`] for an unknown
/// layout version.
pub async fn root_layout_for_verification_async<S>(
    store: &S,
    cx: &S::Context,
    configuration_root: &Digest,
) -> Result<RootLayoutVersion, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = configuration_key(configuration_root)?;
    match store.read_immutable(cx, &key).await? {
        ImmutableRead::Absent => Ok(RootLayoutVersion::LegacyWholeBody),
        ImmutableRead::Present(bytes) => Ok(decode_body::<RepositoryConfigurationBody>(
            &bytes,
            DecodeLimits::DEFAULT,
        )?
        .root_layout),
    }
}

/// The layout a head selects, for proof generation, on the production surface.
///
/// The asynchronous twin of [`root_layout_for_proof`], including its refusal:
/// an unresolvable configuration is a typed failure here rather than an assumed
/// v0, because a proof under a layout with no tree is a path through nothing.
///
/// # Errors
///
/// [`OutcomeFailure::ConfigurationUnresolvable`] when the root names no stored
/// body, and [`OutcomeFailure::Codec`] when a present body cannot decode under
/// this build's exact schema.
pub async fn root_layout_for_proof_async<S>(
    store: &S,
    cx: &S::Context,
    configuration_root: &Digest,
) -> Result<RootLayoutVersion, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    Ok(
        read_repository_configuration_async(store, cx, configuration_root)
            .await?
            .root_layout,
    )
}

/// The production twin of [`read_repository_configuration`].
///
/// # Errors
///
/// [`OutcomeFailure::ConfigurationUnresolvable`] when no body is stored at the
/// selected root, and [`OutcomeFailure::Codec`] when the present body cannot be
/// decoded by this build's exact schema.
pub async fn read_repository_configuration_async<S>(
    store: &S,
    cx: &S::Context,
    configuration_root: &Digest,
) -> Result<RepositoryConfigurationBody, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = configuration_key(configuration_root)?;
    let ImmutableRead::Present(bytes) = store.read_immutable(cx, &key).await? else {
        return Err(OutcomeFailure::ConfigurationUnresolvable);
    };
    Ok(decode_body(&bytes, DecodeLimits::DEFAULT)?)
}

/// Reads the exact incarnation-aware configuration selected by an authority
/// head on the production surface.
///
/// The asynchronous twin of [`read_repository_incarnation_configuration`]. It
/// retains that resolver's no-fallback rule for absent, v1, and malformed
/// bodies.
///
/// # Errors
///
/// [`OutcomeFailure::ConfigurationUnresolvable`] when no body is stored at the
/// selected root, and [`OutcomeFailure::Codec`] when a present body is not the
/// exact v2 incarnation-aware schema.
pub async fn read_repository_incarnation_configuration_async<S>(
    store: &S,
    cx: &S::Context,
    configuration_root: &Digest,
) -> Result<RepositoryIncarnationConfigurationBody, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = configuration_key(configuration_root)?;
    let ImmutableRead::Present(bytes) = store.read_immutable(cx, &key).await? else {
        return Err(OutcomeFailure::ConfigurationUnresolvable);
    };
    Ok(decode_body(&bytes, DecodeLimits::DEFAULT)?)
}

/// One outcome-index leaf.
///
/// The preimage is a fixed-width transaction digest followed by the canonical
/// outcome encoding, so it needs no length delimiter: nothing variable-length
/// precedes anything else. [`fgit_crypto::ref_state_leaf`] is the case where
/// that is not true and a prefix is required.
fn outcome_leaf(tx_id: TxId, outcome: &TerminalOutcome) -> Result<DigestBytes, OutcomeFailure> {
    let encoded = encode_outcome(outcome)?;
    Ok(merkle_leaf(
        outcome_index_schema(),
        &[tx_id.as_internal_object_id().digest().as_bytes(), &encoded],
    ))
}

/// Outcome leaves in the order the root commits to: sorted by leaf digest.
///
/// Sorting by DIGEST rather than by transaction identity is the rule this root
/// has always used, and it is why [`outcome_index_root`] commits to a multiset
/// rather than to an ordered list. It is also why the shared Merkle core takes
/// leaves already ordered: the ref state sorts by name instead, and a core that
/// imposed either rule would force one of them to hash something it does not
/// publish.
fn ordered_outcome_leaves(
    entries: &[(TxId, TerminalOutcome)],
) -> Result<Vec<DigestBytes>, OutcomeFailure> {
    let mut leaves = Vec::with_capacity(entries.len());
    for (tx_id, outcome) in entries {
        leaves.push(outcome_leaf(*tx_id, outcome)?);
    }
    leaves.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(leaves)
}

/// Canonicalizes retained terminal decisions into the exact order committed by
/// [`outcome_index_root`].
///
/// The outcome-index tree sorts **leaf digests**, not transaction identities.
/// A checkpoint must preserve that order in its own canonical body so two
/// producers cannot serialize the same set into different checkpoint bodies.
/// This conversion lives here because this crate owns both the terminal-outcome
/// encoding and the leaf preimage; asking Chronicle to repeat either would
/// create a second commitment definition.
///
/// Duplicate transaction identities are refused before sorting, just as
/// [`fold_outcome_index`] does. A retained leaf set with a duplicate would make
/// the index commit to a history in which one sealed transaction decided twice.
pub fn canonical_outcome_index_decisions(
    decisions: &[RepositoryDecision],
) -> Result<Vec<RepositoryDecision>, OutcomeFailure> {
    let mut seen: BTreeMap<TxId, TerminalOutcome> = BTreeMap::new();
    let mut ordered = Vec::with_capacity(decisions.len());

    for decision in decisions {
        let terminal = TerminalOutcome {
            decision_sequence: decision.decision_sequence,
            outcome: decision.outcome,
        };
        if let Some(existing) = seen.insert(decision.tx_id, terminal) {
            return Err(OutcomeFailure::DuplicateTerminalDecision {
                duplicate: Box::new(DuplicateDecision {
                    tx_id: decision.tx_id,
                    existing,
                    offered: terminal,
                }),
            });
        }
        ordered.push((outcome_leaf(decision.tx_id, &terminal)?, decision.clone()));
    }

    ordered.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    Ok(ordered.into_iter().map(|(_, decision)| decision).collect())
}

/// A membership proof that one terminal decision is in the outcome index.
///
/// # What this is for
///
/// FG-037 verified reads need to hand a client one decision plus a proof,
/// rather than the whole index. The proof is against the exact root
/// [`outcome_index_root`] publishes — the same leaves, the same order, the same
/// tree — because both go through one construction rather than two.
///
/// # Why this lives here and not beside the ref-state verifier
///
/// The leaf preimage is the canonical outcome encoding, which is this crate's.
/// A verifier for it therefore cannot be dependency-free the way
/// [`fgit_crypto::verify_ref_state_membership`] is, and pretending otherwise
/// would move an encoder into a crate that has no business owning one. That
/// asymmetry is a property of the two leaf shapes, not an oversight.
///
/// # Errors
///
/// [`OutcomeFailure::Codec`] when an outcome does not encode, and
/// [`OutcomeFailure::OutcomeNotIndexed`] when `tx_id` with that exact outcome
/// is absent — absence is refused rather than answered with an empty proof,
/// which would verify vacuously.
pub fn outcome_index_proof(
    entries: &[(TxId, TerminalOutcome)],
    tx_id: TxId,
    outcome: &TerminalOutcome,
) -> Result<MerkleProof, OutcomeFailure> {
    let target = outcome_leaf(tx_id, outcome)?;
    let leaves = ordered_outcome_leaves(entries)?;
    let index = leaves
        .iter()
        .position(|leaf| leaf.as_bytes() == target.as_bytes())
        .ok_or_else(|| OutcomeFailure::OutcomeNotIndexed(Box::new(tx_id)))?;
    merkle_proof(outcome_index_schema(), &leaves, index)
        .map_err(|refusal| OutcomeFailure::MerkleShape(Box::new(refusal)))
}

/// Generate a ref-state absence proof under the layout the head selects.
///
/// # Why generation is head-aware when verification is not
///
/// [`fgit_crypto::verify_ref_state_non_membership`] deliberately reaches
/// nothing: a client checks a proof against a root it already trusts. Emitting
/// one is the opposite situation. The layout version is a fact about the head,
/// and a repository still on [`RootLayoutVersion::LegacyWholeBody`] has no tree
/// to take neighbours from, so emitting a proof there would be inventing a
/// shape the published root does not have. This is the same asymmetry
/// [`root_layout_for_proof`] already encodes, applied to the second proof kind.
///
/// # Errors
///
/// [`OutcomeFailure::ConfigurationUnresolvable`] when the head's configuration
/// cannot be read, and [`OutcomeFailure::MerkleShape`] carrying
/// [`MerkleRefusal::LayoutAdmitsNoProof`] under a layout with no tree or
/// [`MerkleRefusal::RefIsPresent`] when the ref is in fact there.
pub fn head_selected_ref_state_absence_proof<S>(
    store: &S,
    configuration_root: &Digest,
    entries: &[(RefName, GitOid)],
    name: &RefName,
) -> Result<RefStateNonMembershipProof, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let version = root_layout_for_proof(store, configuration_root)?;
    absence_proof_under(version, entries, name)
}

/// The production twin of [`head_selected_ref_state_absence_proof`].
///
/// `FsqliteAuthorityStore` implements [`AsyncAuthorityStore`] only, so without
/// this a serving node could not emit an absence proof at all.
///
/// # Errors
///
/// The same refusals as [`head_selected_ref_state_absence_proof`].
pub async fn head_selected_ref_state_absence_proof_async<S>(
    store: &S,
    cx: &S::Context,
    configuration_root: &Digest,
    entries: &[(RefName, GitOid)],
    name: &RefName,
) -> Result<RefStateNonMembershipProof, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let version = root_layout_for_proof_async(store, cx, configuration_root).await?;
    absence_proof_under(version, entries, name)
}

/// The shared decision both surfaces delegate to.
fn absence_proof_under(
    version: RootLayoutVersion,
    entries: &[(RefName, GitOid)],
    name: &RefName,
) -> Result<RefStateNonMembershipProof, OutcomeFailure> {
    if !version.admits_ref_state_membership_proof() {
        return Err(OutcomeFailure::MerkleShape(Box::new(
            MerkleRefusal::LayoutAdmitsNoProof { version },
        )));
    }
    ref_state_non_membership_proof(entries, name)
        .map_err(|refusal| OutcomeFailure::MerkleShape(Box::new(refusal)))
}

/// Whether `proof` shows this decision is committed to by `root`.
///
/// Establishes membership in the tree with that root, and nothing about
/// whether `root` is the repository's current `outcome_index_root`. That is an
/// authenticated head read the caller must already hold; treating this as a
/// substitute accepts a stale-but-internally-valid proof.
///
/// # Errors
///
/// [`OutcomeFailure::Codec`] when the outcome does not encode. A proof that
/// simply fails to verify returns `Ok(false)` — that is an answer, not a fault.
pub fn verify_outcome_index_membership(
    root: &Digest,
    tx_id: TxId,
    outcome: &TerminalOutcome,
    proof: &MerkleProof,
) -> Result<bool, OutcomeFailure> {
    if root.algorithm() != IdentityDomain::MerkleNode.algorithm().id() {
        return Ok(false);
    }
    let leaf = outcome_leaf(tx_id, outcome)?;
    Ok(verify_merkle_proof(
        outcome_index_schema(),
        root.bytes(),
        &leaf,
        proof,
    ))
}

/// Collect every terminal outcome reachable from the head, as the fold's
/// `carried` argument.
///
/// This is the same authenticated walk [`scan_for_existing_decisions`] makes --
/// `next_batch_to_replay`, `read_decision_batch_body`, `read_predecessor` --
/// differing only in that it takes *every* decision in each batch rather than
/// probing for named ones.
///
/// # Why this is not a retention decision
///
/// It materializes nothing. The returned set is a **projection derived from the
/// authenticated decision stream on demand** and dropped by the caller, so §5.1
/// is untouched and no §4 "second database whose rows compete with the
/// authority-head decision stream" comes into existence. The open question on
/// `frankengit-boet` is whether to *retain* the leaf set or change the
/// commitment; this answers neither and pre-empts neither. What it does is
/// narrow the question: within the replay bound the derivation already works,
/// so the ruling governs only what happens beyond that bound.
///
/// # The bound is a refusal, never a truncation
///
/// Past [`MAX_REPLAY_BATCHES`] the walk returns
/// [`OutcomeFailure::ReplayBoundExceeded`] and this function propagates it
/// rather than returning the entries gathered so far. That distinction is the
/// whole safety property: a *short* leaf set does not produce a short root, it
/// produces a **wrong root that is indistinguishable from a right one**, and it
/// would be committed to a canonical body field. §3.1's typed refusal is the
/// only admissible answer, so there is deliberately no partial-result variant
/// for a caller to reach for.
///
/// # Duplicates are reported, not resolved
///
/// The stream is reported faithfully, including a `TxId` that somehow carries
/// two decisions. Enforcing §5.2 here would hide such a stream behind a clean
/// read; [`fold_outcome_index`] refuses it instead, at the point where it would
/// otherwise become a published root.
///
/// # Errors
///
/// [`OutcomeFailure::ReplayBoundExceeded`] past the walk's bound, plus the
/// body-read failures [`read_decision_batch_body`] can raise.
pub fn collect_cumulative_outcomes<S>(
    store: &S,
    head_key: &HeadKey,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        // No head: nothing has been decided, so the index is empty. Bound to a
        // ZERO token, which no minted token equals, so `fold_against` refuses
        // it. That mirrors the absent-head witness in
        // `scan_for_existing_decisions` and fails closed for the same reason:
        // with no head there is nothing to conditionally replace, and genesis
        // publishes through `initialize_repository` rather than a CAS.
        return Ok(CumulativeOutcomes {
            observed: AuthorityVersionToken::from_opaque_bytes(
                [0_u8; crate::tokens::VERSION_TOKEN_BYTES],
            ),
            entries: Vec::new(),
        });
    };
    let observed = receipt.token();
    let mut head: RepositoryAuthorityHeadBody = head_body_of(&receipt)?;
    let mut walked = 0_usize;
    let mut collected: Vec<(TxId, TerminalOutcome)> = Vec::new();

    while let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? {
        let batch = read_decision_batch_body(store, batch_id)?;
        for decision in &batch.decisions {
            collected.push((
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            ));
        }
        let Some(previous) = read_predecessor(store, batch.predecessor_head_id)? else {
            break;
        };
        head = previous;
    }

    Ok(CumulativeOutcomes {
        observed,
        entries: collected,
    })
}

/// The asynchronous twin of [`collect_cumulative_outcomes`].
///
/// Same walk, same bound, same refusal. It exists because the publication path
/// that needs the carried set is asynchronous -- `fgit-node`'s
/// `materialize_commit_async` -- so a synchronous-only collector would be
/// uncallable exactly where the fold is required, and the caller's remaining
/// option would be to invent a value.
///
/// The two are kept deliberately identical in structure rather than one
/// delegating to the other: an asynchronous port that quietly dropped the
/// bound, or returned what it had gathered instead of propagating
/// [`OutcomeFailure::ReplayBoundExceeded`], would publish a wrong root on the
/// path that actually runs. See the sync twin for why a short leaf set is worse
/// than no leaf set.
///
/// # Errors
///
/// As [`collect_cumulative_outcomes`].
pub async fn collect_cumulative_outcomes_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        // No head: empty, bound to the zero token so `fold_against` refuses.
        // See the sync twin.
        return Ok(CumulativeOutcomes {
            observed: AuthorityVersionToken::from_opaque_bytes(
                [0_u8; crate::tokens::VERSION_TOKEN_BYTES],
            ),
            entries: Vec::new(),
        });
    };
    let observed = receipt.token();
    let mut head: RepositoryAuthorityHeadBody = head_body_of(&receipt)?;
    let mut walked = 0_usize;
    let mut collected: Vec<(TxId, TerminalOutcome)> = Vec::new();

    while let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? {
        let batch = read_decision_batch_body_async(store, cx, batch_id).await?;
        for decision in &batch.decisions {
            collected.push((
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            ));
        }
        let Some(previous) = read_predecessor_async(store, cx, batch.predecessor_head_id).await?
        else {
            break;
        };
        head = previous;
    }

    Ok(CumulativeOutcomes {
        observed,
        entries: collected,
    })
}

/// Collect a cumulative outcome-index leaf set from an authenticated retained
/// checkpoint and the strictly newer decision tail.
///
/// `checkpoint_decisions` are canonical checkpoint contents verified by the
/// chronicle layer against a capsule-bound checkpoint body. Authority still
/// re-canonicalizes them here: a caller cannot use this API to replace the
/// outcome-index ordering rule with an insertion order. The named checkpoint
/// position must be reached exactly while walking the authenticated head's
/// predecessor chain; otherwise the result is a typed refusal, never a short
/// prefix.
///
/// [`MAX_REPLAY_BATCHES`] applies only to the tail after the checkpoint. A
/// missing or undecodable checkpoint is deliberately not represented here;
/// Chronicle selects the existing from-genesis collector in that case.
pub fn collect_cumulative_outcomes_from_checkpoint<S>(
    store: &S,
    head_key: &HeadKey,
    checkpoint_decisions: &[RepositoryDecision],
    checkpoint_tail_id: Option<RepositoryDecisionBatchId>,
    checkpoint_latest_decision_sequence: Option<DecisionSequence>,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        return Ok(CumulativeOutcomes {
            observed: AuthorityVersionToken::from_opaque_bytes(
                [0_u8; crate::tokens::VERSION_TOKEN_BYTES],
            ),
            entries: Vec::new(),
        });
    };
    let observed = receipt.token();
    let mut head: RepositoryAuthorityHeadBody = head_body_of(&receipt)?;
    let mut walked = 0_usize;
    let canonical = canonical_outcome_index_decisions(checkpoint_decisions)?;
    let mut collected: Vec<(TxId, TerminalOutcome)> = canonical
        .into_iter()
        .map(|decision| {
            (
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            )
        })
        .collect();
    let mut tail: Vec<(TxId, TerminalOutcome)> = Vec::new();

    loop {
        if head.decision_tail_id == checkpoint_tail_id {
            if head.latest_decision_sequence != checkpoint_latest_decision_sequence {
                return Err(OutcomeFailure::CheckpointPositionMismatch);
            }
            if outcome_index_root(&collected)? != head.outcome_index_root {
                return Err(OutcomeFailure::CheckpointRootMismatch);
            }
            collected.extend(tail);
            break;
        }

        let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? else {
            return Err(OutcomeFailure::CheckpointPositionMismatch);
        };
        let batch = read_decision_batch_body(store, batch_id)?;
        for decision in &batch.decisions {
            tail.push((
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            ));
        }
        let Some(previous) = read_predecessor(store, batch.predecessor_head_id)? else {
            return Err(OutcomeFailure::CheckpointPositionMismatch);
        };
        head = previous;
    }

    Ok(CumulativeOutcomes {
        observed,
        entries: collected,
    })
}

/// Asynchronous twin of [`collect_cumulative_outcomes_from_checkpoint`].
pub async fn collect_cumulative_outcomes_from_checkpoint_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    checkpoint_decisions: &[RepositoryDecision],
    checkpoint_tail_id: Option<RepositoryDecisionBatchId>,
    checkpoint_latest_decision_sequence: Option<DecisionSequence>,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        return Ok(CumulativeOutcomes {
            observed: AuthorityVersionToken::from_opaque_bytes(
                [0_u8; crate::tokens::VERSION_TOKEN_BYTES],
            ),
            entries: Vec::new(),
        });
    };
    let observed = receipt.token();
    let mut head: RepositoryAuthorityHeadBody = head_body_of(&receipt)?;
    let mut walked = 0_usize;
    let canonical = canonical_outcome_index_decisions(checkpoint_decisions)?;
    let mut collected: Vec<(TxId, TerminalOutcome)> = canonical
        .into_iter()
        .map(|decision| {
            (
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            )
        })
        .collect();
    let mut tail: Vec<(TxId, TerminalOutcome)> = Vec::new();

    loop {
        if head.decision_tail_id == checkpoint_tail_id {
            if head.latest_decision_sequence != checkpoint_latest_decision_sequence {
                return Err(OutcomeFailure::CheckpointPositionMismatch);
            }
            if outcome_index_root(&collected)? != head.outcome_index_root {
                return Err(OutcomeFailure::CheckpointRootMismatch);
            }
            collected.extend(tail);
            break;
        }

        let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? else {
            return Err(OutcomeFailure::CheckpointPositionMismatch);
        };
        let batch = read_decision_batch_body_async(store, cx, batch_id).await?;
        for decision in &batch.decisions {
            tail.push((
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            ));
        }
        let Some(previous) = read_predecessor_async(store, cx, batch.predecessor_head_id).await?
        else {
            return Err(OutcomeFailure::CheckpointPositionMismatch);
        };
        head = previous;
    }

    Ok(CumulativeOutcomes {
        observed,
        entries: collected,
    })
}

/// A cumulative leaf set, inseparable from the head it was collected against.
///
/// # Why the binding is part of the type
///
/// This file already establishes the rule twice. [`DuplicateScan::Found`]
/// carries an `observed` token because, in its own words, "the caller cannot
/// classify this without knowing whether the head it walked is still the head
/// it intends to replace", and [`DuplicateAbsenceWitness`] goes further -- its
/// constructor is deliberately `pub(crate)` so that "a public constructor would
/// make the witness a token anyone can forge, which is the documented
/// obligation again wearing a type".
///
/// `DuplicateScan::Found.decided` and the cumulative leaf set are the *same
/// element type*, produced by the *same walk primitives*, over the *same
/// stream*, in the *same publication*. Returning one bound and the other bare
/// would leave two adjacent walks with opposite safety postures.
///
/// # What the binding buys
///
/// The fields are private and there is no public constructor, so a set cannot
/// be fabricated claiming a token it was never collected under. The only way to
/// obtain one is [`collect_cumulative_outcomes`] or its async twin, and the
/// only way to fold one is [`Self::fold_against`], which requires the caller to
/// name the head being replaced.
///
/// The entries are deliberately **not** exposed as a slice. Handing them out
/// would let a caller reach [`fold_outcome_index`] directly and skip the check,
/// which is the documented-obligation shape this type exists to replace.
/// [`Self::decision_for`] covers the legitimate read -- it is the §10.4
/// "does this transaction already have a decision" query against the cumulative
/// index.
///
/// # Why the token and not the head id
///
/// [`AuthorityVersionToken`] embeds the `StoreInstanceId` and a per-instance
/// issuance sequence that never repeats, and the conditional replacement
/// compares *this exact value*. Binding to the head id would identify the body
/// while the CAS tests the slot version, so the token is not merely sufficient
/// here -- it is the only binding that is byte-for-byte the thing publication
/// conditions on.
///
/// # The binding cannot be forged
///
/// The fields are private, so a set claiming a token it was never collected
/// under does not compile:
///
/// ```compile_fail
/// use fgit_authority::{AuthorityVersionToken, CumulativeOutcomes};
///
/// let forged = CumulativeOutcomes {
///     observed: AuthorityVersionToken::from_opaque_bytes([0; 16]),
///     entries: Vec::new(),
/// };
/// ```
///
/// A `compile_fail` example passes when compilation fails for *any* reason,
/// including a typo, so it proves nothing on its own. This companion is
/// identical in its imports and in every name it touches, and it **does**
/// compile -- so the only difference left to explain the failure above is the
/// struct literal reaching private fields:
///
/// ```
/// use fgit_authority::{AuthorityVersionToken, CumulativeOutcomes};
///
/// let _token = AuthorityVersionToken::from_opaque_bytes([0; 16]);
/// fn _accepts(_set: &CumulativeOutcomes) {}
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CumulativeOutcomes {
    observed: AuthorityVersionToken,
    entries: Vec<(TxId, TerminalOutcome)>,
}

impl CumulativeOutcomes {
    /// The head token this set was collected against.
    #[must_use]
    pub const fn observed(&self) -> AuthorityVersionToken {
        self.observed
    }

    /// How many terminal outcomes the index holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty, which is the genesis case.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The decision this transaction already has, if any.
    ///
    /// This is the §10.4 duplicate-detection query answered against the
    /// *cumulative* index rather than against one batch: a transaction decided
    /// in any prior batch reachable from the collected head is found here.
    #[must_use]
    pub fn decision_for(&self, tx_id: TxId) -> Option<TerminalOutcome> {
        self.entries
            .iter()
            .find(|(candidate, _)| *candidate == tx_id)
            .map(|(_, outcome)| *outcome)
    }

    /// Materializes this exact head-bound set as canonical decision records for
    /// an immutable outcome-index checkpoint.
    ///
    /// The expected token is required before entries leave the authority
    /// boundary. A checkpoint writer therefore cannot turn a leaf set from a
    /// CAS-losing head into durable evidence for the head it now observes.
    pub fn checkpoint_decisions_against(
        &self,
        expected: AuthorityVersionToken,
    ) -> Result<Vec<RepositoryDecision>, OutcomeFailure> {
        if self.observed != expected {
            return Err(OutcomeFailure::CumulativeIndexStale {
                observed: self.observed,
                expected,
            });
        }
        let decisions: Vec<RepositoryDecision> = self
            .entries
            .iter()
            .map(|(tx_id, terminal)| RepositoryDecision {
                tx_id: *tx_id,
                decision_sequence: terminal.decision_sequence,
                outcome: terminal.outcome,
            })
            .collect();
        canonical_outcome_index_decisions(&decisions)
    }

    /// Fold a batch's stamped outcomes onto this set, for a named head.
    ///
    /// # Errors
    ///
    /// [`OutcomeFailure::CumulativeIndexStale`] if this set was collected
    /// against a head other than `expected` -- the CAS-loser case, refused
    /// before any digest is computed. Otherwise as [`fold_outcome_index`].
    pub fn fold_against(
        &self,
        expected: AuthorityVersionToken,
        stamped: &[(TxId, TerminalOutcome)],
    ) -> Result<Digest, OutcomeFailure> {
        if self.observed != expected {
            return Err(OutcomeFailure::CumulativeIndexStale {
                observed: self.observed,
                expected,
            });
        }
        fold_outcome_index(&self.entries, stamped)
    }
}

/// Derive the repository's cumulative outcome index after a batch.
///
/// This is the authority-owned derivation the `frankengit-boet` ruling names:
/// `resulting_outcome_index_root` is the repository's **cumulative**
/// authenticated outcome index after this batch, not a per-batch root. §10
/// step 4 queries the authenticated outcome index *during* transaction
/// handling for duplicate detection, and only a repository-wide index can
/// answer "does this `TxId` already have a decision".
///
/// # Why this takes the carried leaf set rather than the predecessor root
///
/// The obvious signature is `(predecessor_root, stamped)`, and it is not
/// implementable. [`outcome_index_root`] sorts leaves by digest before
/// pairing, so a new leaf's position -- and therefore every interior node
/// above it -- depends on comparison against the individual existing leaves.
/// `root(A)` is a single digest and does not carry them. No function of the
/// predecessor root and the new leaves yields the root of their union under
/// this commitment. An append-only construction would admit one; sorting buys
/// canonical-set semantics and pays incrementality for it.
///
/// So the carried entries are a parameter, following the same discipline
/// [`reconcile_outcome`] uses for its two reads: requiring them makes a
/// derivation that *cannot* see the history **unrepresentable** rather than
/// merely discouraged. Carrying a predecessor root forward unchanged -- the
/// `frankengit-d6nl` defect -- is not something a caller of this function can
/// express by omission.
///
/// # Refusals are entries
///
/// Both commits and refusals are terminal outcomes: they consume decision
/// sequence and must be found by §10.4 duplicate detection. A refusal-only
/// batch therefore *advances* the root. There is deliberately no early return
/// for an empty `stamped`: such a shortcut would return the predecessor's root
/// unchanged, which is the carry-forward defect arriving by another route.
///
/// # What this does not do
///
/// It does not gate publication, and it does not itself choose where `carried`
/// comes from. The retained-leaf checkpoint route supplies a canonical leaf
/// set from immutable evidence bound by a root-last capsule, then replays the
/// bounded tail after that checkpoint. A missing or unusable checkpoint falls
/// back to the decision-chain walk; the bound still produces the typed
/// [`OutcomeFailure::ReplayBoundExceeded`] refusal rather than a partial set.
///
/// A capsule never binds `outcome_index_root` as a replacement for the leaf
/// set. The root alone cannot be extended under this digest-sorted commitment,
/// as the argument above shows. That rejected shortcut must not be reintroduced
/// by a caller attempting to supply a root in place of `carried`.
///
/// # Errors
///
/// [`OutcomeFailure::DuplicateTerminalDecision`] if any `TxId` appears more
/// than once across `carried` and `stamped`, including twice within either
/// one; [`OutcomeFailure::Codec`] if an outcome does not encode.
pub fn fold_outcome_index(
    carried: &[(TxId, TerminalOutcome)],
    stamped: &[(TxId, TerminalOutcome)],
) -> Result<Digest, OutcomeFailure> {
    let mut seen: BTreeMap<TxId, TerminalOutcome> = BTreeMap::new();
    let mut folded = Vec::with_capacity(carried.len() + stamped.len());

    for (tx_id, outcome) in carried.iter().chain(stamped) {
        if let Some(existing) = seen.insert(*tx_id, *outcome) {
            return Err(OutcomeFailure::DuplicateTerminalDecision {
                duplicate: Box::new(DuplicateDecision {
                    tx_id: *tx_id,
                    existing,
                    offered: *outcome,
                }),
            });
        }
        folded.push((*tx_id, *outcome));
    }

    outcome_index_root(&folded)
}

/// Create a repository's genesis head, staging its body by identity.
///
/// The counterpart of [`publish_decisions`]: replay resolves a head by its
/// identity, so every head body has to be addressable that way, including the
/// first one.
pub fn initialize_repository<S>(
    store: &S,
    head_key: &HeadKey,
    head: &RepositoryAuthorityHeadBody,
) -> Result<HeadInit, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key(IdentityDomain::RepositoryAuthorityHead, head)?;
    let bytes = encode_body(head)?;
    store.put_if_absent(&key, &bytes)?;
    let generation = HeadGeneration::try_new(head.generation.get())
        .map_err(|refusal| OutcomeFailure::Codec(refusal.into()))?;
    Ok(store.initialize_head(head_key, generation, &bytes)?)
}

/// What one successful publication established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedBatch {
    /// The head this publication established.
    pub head: HeadReadReceipt,
    /// The batch that became canonical.
    pub batch_id: RepositoryDecisionBatchId,
    /// How many accelerator entries this publication added.
    pub indexed: usize,
}

/// The outcome of publishing one decision batch.
///
/// The success payload is boxed: a published head carries canonical bytes and a
/// domain-pinned identity, so inlining it would make every returned value —
/// including the empty loss case — carry that weight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    /// The batch is canonical and its terminal outcomes are observable.
    ///
    /// Both became true at the same instant: see [`publish_decisions`].
    ///
    /// # This establishes `Visible`, never `Durable`
    ///
    /// NPC §5.4 requires staged, visible and durable to stay distinct, and
    /// forbids conflating object existence, canonical visibility, and
    /// completion of the selected durability profile. **This outcome reports
    /// the middle one.** The conditional replacement linearized, so the head
    /// and its terminal outcomes are canonically visible to any reader.
    ///
    /// It says nothing about the durability profile having completed. For the
    /// fsqlite backend the store runs on WAL — measured, not assumed, by
    /// `fgit-authority-fsqlite`'s `journal_mode_probe` — so a published head
    /// lives in the write-ahead log until a checkpoint transfers it, and that
    /// checkpoint is neither driven nor observed from this surface.
    ///
    /// So a caller must not read this as an acknowledgement of durability.
    /// Nothing in the tree does today, which is why the distinction is recorded
    /// here rather than expressed as a third state on this enum: a
    /// [`PublicationEpoch`]-shaped return with no consumer would be a surface
    /// invented for a caller that does not exist.
    ///
    /// **Reopen condition:** a caller that needs durable-before-acknowledge.
    /// That is a real consumer, and it makes the witness worth building; until
    /// one exists this limit is the honest statement of what we can promise.
    ///
    /// [`PublicationEpoch`]: fgit_types::vocabulary::PublicationEpoch
    Published(Box<PublishedBatch>),
    /// The head moved before the conditional replacement landed.
    ///
    /// Nothing was published; the staged bodies remain staged and unreferenced.
    PredecessorMismatch,
    /// At least one transaction in the batch was already terminal.
    ///
    /// This is the §5.2 "at most one terminal decision" rule holding, and it is
    /// decided from the authenticated decision stream rather than from the
    /// accelerator. Nothing was published; the carried decisions are the ones
    /// that already stand, so a caller can answer with the original outcome
    /// instead of re-deciding a transaction that is already resolved.
    AlreadyDecided {
        /// The transactions that already have a terminal decision, with it.
        decided: Vec<(TxId, TerminalOutcome)>,
    },
}

/// Name the accelerator entry that disagrees with the authenticated stream.
///
/// Called only after the store has already refused the publication, so this
/// decides nothing: it turns an opaque token refusal into the specific
/// conflict, which is what a caller needs in order to act. If no disagreement
/// can be reproduced the refusal is propagated unchanged rather than guessed at.
fn accelerator_conflict_for<S>(
    store: &S,
    tenant_id: TenantId,
    batch: &RepositoryDecisionBatchBody,
) -> OutcomeFailure
where
    S: AuthorityStore + ?Sized,
{
    for decision in &batch.decisions {
        let proposed = TerminalOutcome {
            decision_sequence: decision.decision_sequence,
            outcome: decision.outcome,
        };
        match indexed_outcome(store, tenant_id, batch.repository_id, decision.tx_id) {
            Ok(OutcomeLookup::Decided(existing)) if existing != proposed => {
                return OutcomeFailure::AcceleratorConflict {
                    indexed: Box::new(existing),
                    replayed: Box::new(proposed),
                };
            }
            Ok(_) => {}
            Err(failure) => return failure,
        }
    }
    OutcomeFailure::Seal(Box::new(SealFailure::Store(AuthorityFailure::Refused(
        AuthorityRefusal::TokenBodyMismatch,
    ))))
}

/// What a duplicate walk means for a publication that intends to replace
/// `expected`.
///
/// This is the whole decision, and it is deliberately a pure function of what
/// the walk saw. Both the synchronous and the asynchronous driver consult it,
/// so the two surfaces cannot answer the same situation differently — the
/// drivers differ only in how they perform I/O, never in what they conclude.
#[derive(Clone, Debug, Eq, PartialEq)]
enum DuplicateVerdict {
    /// The walk observed a head other than the one being replaced.
    Lost,
    /// Every decision that already stands is the one being replayed.
    Idempotent,
    /// A different terminal decision already stands for a sealed transaction.
    Conflict {
        /// The decision that already stands.
        indexed: Box<TerminalOutcome>,
        /// The decision this batch proposed for the same transaction.
        replayed: Box<TerminalOutcome>,
    },
}

/// The terminal outcome this batch proposes for `tx_id`, if it carries one.
fn proposed_outcome(batch: &RepositoryDecisionBatchBody, tx_id: TxId) -> Option<TerminalOutcome> {
    batch
        .decisions
        .iter()
        .find(|decision| decision.tx_id == tx_id)
        .map(|decision| TerminalOutcome {
            decision_sequence: decision.decision_sequence,
            outcome: decision.outcome,
        })
}

/// Classify what the walk found against what this publication intends.
///
/// Two orderings here are load-bearing.
///
/// Staleness is checked first because it dominates: if the head already moved,
/// this batch lost a race and the winner consumed the positions it chose.
/// Reporting the duplicates as a pre-replacement decision would tell the caller
/// its basis is still current when it is not.
///
/// Then §5.2 is applied at its actual boundary, which is *semantics* rather
/// than recurrence. Replaying a decision that already stands is an idempotent
/// retry and is exactly what a lost response produces; presenting a *different*
/// decision for the same sealed transaction is the one-terminal-decision rule
/// being broken, and fails closed.
fn classify_duplicates(
    observed: AuthorityVersionToken,
    expected: AuthorityVersionToken,
    decided: &[(TxId, TerminalOutcome)],
    batch: &RepositoryDecisionBatchBody,
) -> DuplicateVerdict {
    if observed != expected {
        return DuplicateVerdict::Lost;
    }
    for (tx_id, existing) in decided {
        let Some(proposed) = proposed_outcome(batch, *tx_id) else {
            // Decided, but not by this batch. It constrains nothing here.
            continue;
        };
        if proposed != *existing {
            return DuplicateVerdict::Conflict {
                indexed: Box::new(*existing),
                replayed: Box::new(proposed),
            };
        }
    }
    DuplicateVerdict::Idempotent
}

/// The accelerator entries this batch publishes, in decision order.
///
/// One sealed transaction has at most one terminal decision, so a batch that
/// lists one transaction identity twice is malformed no matter whether the two
/// entries agree: publication would have to pick a survivor by slice order,
/// which is exactly the discretion §5.2 withholds. Refused before anything is
/// staged.
fn outcome_entries(
    tenant_id: TenantId,
    batch: &RepositoryDecisionBatchBody,
) -> Result<Vec<(ImmutableKey, Vec<u8>)>, OutcomeFailure> {
    let mut entries: Vec<(ImmutableKey, Vec<u8>)> = Vec::with_capacity(batch.decisions.len());
    for decision in &batch.decisions {
        let key = outcome_key(tenant_id, batch.repository_id, decision.tx_id)?;
        if entries.iter().any(|(staged, _)| staged == &key) {
            return Err(OutcomeFailure::Seal(Box::new(
                SealFailure::SlotContentUnexpected {
                    slot: "decision batch",
                },
            )));
        }
        let entry = TerminalOutcome {
            decision_sequence: decision.decision_sequence,
            outcome: decision.outcome,
        };
        entries.push((key, encode_outcome(&entry)?));
    }
    Ok(entries)
}

/// The generation a head body publishes at.
fn head_generation(head: &RepositoryAuthorityHeadBody) -> Result<HeadGeneration, OutcomeFailure> {
    HeadGeneration::try_new(head.generation.get())
        .map_err(|refusal| OutcomeFailure::Codec(refusal.into()))
}

/// The identity an authority head publishes under.
///
/// The counterpart of [`decision_batch_identity`]; see it for why this is
/// public. A head body is addressed by this identity in the immutable store, so
/// a caller staging one needs the same derivation the publication uses, and
/// must get it from the same place rather than a parallel copy.
///
/// # Errors
///
/// [`OutcomeFailure::StreamBodyMissing`] when the body cannot be encoded to a
/// canonical identity.
pub fn authority_head_identity(
    head: &RepositoryAuthorityHeadBody,
) -> Result<RepositoryAuthorityHeadId, OutcomeFailure> {
    RepositoryAuthorityHeadId::from_internal_object_id(canonical_body_id(
        IdentityDomain::RepositoryAuthorityHead,
        CANONICAL_CODEC_VERSION,
        head,
    )?)
    .map_err(|_| OutcomeFailure::StreamBodyMissing {
        link: "authority head identity",
    })
}

/// The identity a decision batch publishes under.
///
/// Public because a caller that builds a batch must be able to name it without
/// reconstructing the derivation: the identity domain and codec version are
/// this crate's to know, and a caller that spells them out is duplicating a
/// rule it cannot be held to. Requested for the fsqlite crash
/// matrix, where the alternative was a dev-dependency on `fgit-crypto` solely
/// to name an `IdentityDomain`.
///
/// # Errors
///
/// [`OutcomeFailure::StreamBodyMissing`] when the body cannot be encoded to a
/// canonical identity.
pub fn decision_batch_identity(
    batch: &RepositoryDecisionBatchBody,
) -> Result<RepositoryDecisionBatchId, OutcomeFailure> {
    RepositoryDecisionBatchId::from_internal_object_id(canonical_body_id(
        IdentityDomain::RepositoryDecisionBatch,
        CANONICAL_CODEC_VERSION,
        batch,
    )?)
    .map_err(|_| OutcomeFailure::StreamBodyMissing {
        link: "decision batch identity",
    })
}

/// Stage a batch and its head, then publish the head and its terminal outcomes
/// as one indivisible transition.
///
/// The staging order is the one §8.3 and §8.4 require: bodies are staged first
/// and are unreachable canonically until the conditional replacement makes them
/// canonical. The publication itself is a single linearization point, which is
/// what §5.2 means by effects that belong together publishing in one RCR — the
/// head transition and the terminal outcome entries commit together or not at
/// all. Publishing the head first and indexing afterwards would leave a window
/// in which a transaction is canonically decided but its decision is not yet
/// observable, and a crash inside that window would strand it there.
///
/// Duplicate detection reads the authenticated decision stream, never the
/// accelerator: the accelerator is a derived index that the head's version
/// token does not cover, so its state cannot decide whether a transaction is
/// already terminal.
pub fn publish_decisions<S>(
    store: &S,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
    tenant_id: TenantId,
) -> Result<PublicationOutcome, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let batch_id = decision_batch_identity(batch)?;

    let batch_key = body_key(IdentityDomain::RepositoryDecisionBatch, batch)?;
    let batch_bytes = encode_body(batch)?;
    store.put_if_absent(&batch_key, &batch_bytes)?;

    let head_key_by_id = body_key(IdentityDomain::RepositoryAuthorityHead, head)?;
    let head_bytes = encode_body(head)?;
    store.put_if_absent(&head_key_by_id, &head_bytes)?;

    let generation = head_generation(head)?;

    // Requirement 2. The question "is this transaction already decided?" is
    // answered from the authenticated decision stream reachable from the head,
    // not from the presence or absence of an accelerator entry. The accelerator
    // is a projection (§5.1): the head's version token says nothing about it, so
    // a missing entry does not prove a transaction is undecided.
    let tx_ids: Vec<TxId> = batch
        .decisions
        .iter()
        .map(|decision| decision.tx_id)
        .collect();
    let witness = match scan_for_existing_decisions(store, head_key, &tx_ids)? {
        DuplicateScan::Found { observed, decided } => {
            return match classify_duplicates(observed, expected, &decided, batch) {
                DuplicateVerdict::Lost => Ok(PublicationOutcome::PredecessorMismatch),
                DuplicateVerdict::Conflict { indexed, replayed } => {
                    Err(OutcomeFailure::AcceleratorConflict { indexed, replayed })
                }
                DuplicateVerdict::Idempotent => Ok(PublicationOutcome::AlreadyDecided { decided }),
            };
        }
        DuplicateScan::Absent(witness) => witness,
    };

    // The walk is sound only if it observed the very head this publication is
    // about to replace. A witness minted against some other head proves nothing
    // about the state the conditional replacement will act on.
    if witness.bound_to() != expected {
        return Ok(PublicationOutcome::PredecessorMismatch);
    }

    let entries = outcome_entries(tenant_id, batch)?;
    let indexed = entries.len();

    // One linearization point: the entries and the head move together.
    let published = store.publish_head_with_outcomes(
        head_key,
        expected,
        generation,
        &head_bytes,
        &entries,
        &witness,
    );
    let receipt = match published {
        Ok(CasOutcome::Committed(receipt)) => receipt,
        Ok(CasOutcome::PredecessorMismatch) => {
            return Ok(PublicationOutcome::PredecessorMismatch);
        }
        // The store refuses when an outcome slot already holds different bytes.
        // The stream walk found no decision, so this is an accelerator entry
        // that disagrees with the authenticated stream. Reading the index HERE
        // decides nothing — the refusal already happened — it only names which
        // entry disagreed, so the caller gets the specific conflict instead of
        // an opaque token refusal.
        Err(AuthorityFailure::Refused(AuthorityRefusal::TokenBodyMismatch)) => {
            return Err(accelerator_conflict_for(store, tenant_id, batch));
        }
        Err(failure) => return Err(failure.into()),
    };

    Ok(PublicationOutcome::Published(Box::new(PublishedBatch {
        head: receipt,
        batch_id,
        indexed,
    })))
}

const _: () = assert!(size_of::<OutcomeFailure>() <= crate::request::MAX_ERROR_BYTES);

/// Read one authority head body by identity, on the production surface.
///
/// The asynchronous twin of [`read_authority_head_body`]: same key, same
/// bounded decode, same re-identification, same refusals. Only the waiting
/// differs.
///
/// # Errors
///
/// [`OutcomeFailure::StreamBodyMissing`] when the slot is empty,
/// [`OutcomeFailure::Codec`] when the bytes do not decode, and
/// [`OutcomeFailure::BodyIdentityMismatch`] when they decode to a different
/// head than the one requested.
pub async fn read_authority_head_body_async<S>(
    store: &S,
    cx: &S::Context,
    head_id: RepositoryAuthorityHeadId,
) -> Result<RepositoryAuthorityHeadBody, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = body_key_for_id(head_id.as_internal_object_id())?;
    match store.read_immutable(cx, &key).await? {
        ImmutableRead::Absent => Err(OutcomeFailure::StreamBodyMissing { link: "head body" }),
        ImmutableRead::Present(bytes) => identified_head_body(&bytes, head_id),
    }
}

/// Read one decision batch body by identity, on the production surface.
///
/// The asynchronous twin of [`read_decision_batch_body`]. This is the reader a
/// node uses to resolve an authenticated head's `decision_tail_id` into the
/// batch it commits to.
///
/// # Errors
///
/// [`OutcomeFailure::StreamBodyMissing`] when the slot is empty,
/// [`OutcomeFailure::Codec`] when the bytes do not decode, and
/// [`OutcomeFailure::BodyIdentityMismatch`] when they decode to a different
/// batch than the one requested.
pub async fn read_decision_batch_body_async<S>(
    store: &S,
    cx: &S::Context,
    batch_id: RepositoryDecisionBatchId,
) -> Result<RepositoryDecisionBatchBody, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = body_key_for_id(batch_id.as_internal_object_id())?;
    match store.read_immutable(cx, &key).await? {
        ImmutableRead::Absent => Err(OutcomeFailure::StreamBodyMissing {
            link: "decision batch",
        }),
        ImmutableRead::Present(bytes) => identified_batch_body(&bytes, batch_id),
    }
}

/// Step one link back along the decision stream, asynchronously.
async fn read_predecessor_async<S>(
    store: &S,
    cx: &S::Context,
    head_id: RepositoryAuthorityHeadId,
) -> Result<Option<RepositoryAuthorityHeadBody>, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let body = read_authority_head_body_async(store, cx, head_id).await?;
    // The genesis head has no decision tail, so the walk ends there.
    Ok(body.decision_tail_id.map(|_| body))
}

/// Walk the authenticated decision stream for prior decisions, asynchronously.
///
/// The asynchronous twin of [`scan_for_existing_decisions`]. It performs the
/// same walk, in the same order, with the same bound, and mints the witness
/// against the same observed token — only the I/O differs.
pub async fn scan_for_existing_decisions_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    tx_ids: &[TxId],
) -> Result<DuplicateScan, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        // No head at all: nothing can have been decided. The zero token will
        // not match any real `expected`, so the primitive refuses rather than
        // accepting a witness that validated nothing. See the sync twin.
        return Ok(DuplicateScan::Absent(
            DuplicateAbsenceWitness::minted_against(AuthorityVersionToken::from_opaque_bytes(
                [0_u8; crate::tokens::VERSION_TOKEN_BYTES],
            )),
        ));
    };
    let observed = receipt.token();
    let mut head: RepositoryAuthorityHeadBody = head_body_of(&receipt)?;
    let mut walked = 0_usize;
    let mut found: Vec<(TxId, TerminalOutcome)> = Vec::new();

    while let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? {
        let batch = read_decision_batch_body_async(store, cx, batch_id).await?;
        for tx_id in tx_ids {
            if let Some(outcome) = scan_batch_for(&batch, *tx_id) {
                found.push((*tx_id, outcome));
            }
        }
        let Some(previous) = read_predecessor_async(store, cx, batch.predecessor_head_id).await?
        else {
            break;
        };
        head = previous;
    }

    if found.is_empty() {
        Ok(DuplicateScan::Absent(
            DuplicateAbsenceWitness::minted_against(observed),
        ))
    } else {
        Ok(DuplicateScan::Found {
            observed,
            decided: found,
        })
    }
}

/// Name the accelerator entry that disagrees with the stream, asynchronously.
async fn accelerator_conflict_for_async<S>(
    store: &S,
    cx: &S::Context,
    tenant_id: TenantId,
    batch: &RepositoryDecisionBatchBody,
) -> OutcomeFailure
where
    S: AsyncAuthorityStore + ?Sized,
{
    for decision in &batch.decisions {
        let proposed = TerminalOutcome {
            decision_sequence: decision.decision_sequence,
            outcome: decision.outcome,
        };
        match indexed_outcome_async(store, cx, tenant_id, batch.repository_id, decision.tx_id).await
        {
            Ok(OutcomeLookup::Decided(existing)) if existing != proposed => {
                return OutcomeFailure::AcceleratorConflict {
                    indexed: Box::new(existing),
                    replayed: Box::new(proposed),
                };
            }
            Ok(_) => {}
            Err(failure) => return failure,
        }
    }
    OutcomeFailure::Seal(Box::new(SealFailure::Store(AuthorityFailure::Refused(
        AuthorityRefusal::TokenBodyMismatch,
    ))))
}

/// Publish one decision batch on the production surface.
///
/// The asynchronous twin of [`publish_decisions`], and deliberately not a
/// second protocol. Every decision either surface makes is taken by the same
/// pure core — [`classify_duplicates`] for what the walk means,
/// [`outcome_entries`] for what gets written, [`next_batch_to_replay`] for how
/// far the walk goes — so the two cannot diverge in what they conclude, only in
/// how they wait. §5.2 requires one publication model, not one per runtime.
pub async fn publish_decisions_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
    tenant_id: TenantId,
) -> Result<PublicationOutcome, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let batch_id = decision_batch_identity(batch)?;

    let batch_key = body_key(IdentityDomain::RepositoryDecisionBatch, batch)?;
    let batch_bytes = encode_body(batch)?;
    store.put_if_absent(cx, &batch_key, &batch_bytes).await?;

    let head_key_by_id = body_key(IdentityDomain::RepositoryAuthorityHead, head)?;
    let head_bytes = encode_body(head)?;
    store
        .put_if_absent(cx, &head_key_by_id, &head_bytes)
        .await?;

    let generation = head_generation(head)?;

    let tx_ids: Vec<TxId> = batch
        .decisions
        .iter()
        .map(|decision| decision.tx_id)
        .collect();
    let witness = match scan_for_existing_decisions_async(store, cx, head_key, &tx_ids).await? {
        DuplicateScan::Found { observed, decided } => {
            return match classify_duplicates(observed, expected, &decided, batch) {
                DuplicateVerdict::Lost => Ok(PublicationOutcome::PredecessorMismatch),
                DuplicateVerdict::Conflict { indexed, replayed } => {
                    Err(OutcomeFailure::AcceleratorConflict { indexed, replayed })
                }
                DuplicateVerdict::Idempotent => Ok(PublicationOutcome::AlreadyDecided { decided }),
            };
        }
        DuplicateScan::Absent(witness) => witness,
    };

    if witness.bound_to() != expected {
        return Ok(PublicationOutcome::PredecessorMismatch);
    }

    let entries = outcome_entries(tenant_id, batch)?;
    let indexed = entries.len();

    let published = store
        .publish_head_with_outcomes(
            cx,
            head_key,
            expected,
            generation,
            &head_bytes,
            &entries,
            &witness,
        )
        .await;
    let receipt = match published {
        Ok(CasOutcome::Committed(receipt)) => receipt,
        Ok(CasOutcome::PredecessorMismatch) => {
            return Ok(PublicationOutcome::PredecessorMismatch);
        }
        Err(AuthorityFailure::Refused(AuthorityRefusal::TokenBodyMismatch)) => {
            return Err(accelerator_conflict_for_async(store, cx, tenant_id, batch).await);
        }
        Err(failure) => return Err(failure.into()),
    };

    Ok(PublicationOutcome::Published(Box::new(PublishedBatch {
        head: receipt,
        batch_id,
        indexed,
    })))
}

/// Create the repository head slot on the production surface.
///
/// The asynchronous twin of [`initialize_repository`]. Without it a live node
/// can publish decisions over a durable store but cannot bring a repository
/// into existence there, which leaves the production path able to continue a
/// history it has no way to start.
///
/// # Errors
///
/// Propagates the store's typed refusals, and
/// [`OutcomeFailure::Codec`] when the head's generation is not admissible.
pub async fn initialize_repository_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    head: &RepositoryAuthorityHeadBody,
) -> Result<HeadInit, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = body_key(IdentityDomain::RepositoryAuthorityHead, head)?;
    let bytes = encode_body(head)?;
    store.put_if_absent(cx, &key, &bytes).await?;
    let generation = head_generation(head)?;
    Ok(store
        .initialize_head(cx, head_key, generation, &bytes)
        .await?)
}

/// Replay the authenticated decision stream for one transaction, async.
///
/// The asynchronous twin of [`replay_outcome`]: same walk, same order, same
/// [`MAX_REPLAY_BATCHES`] bound via [`next_batch_to_replay`], same hit test via
/// [`scan_batch_for`]. Only the reads differ.
///
/// # Errors
///
/// Propagates the store's typed refusals, [`OutcomeFailure::StreamBodyMissing`]
/// when a link in the stream is absent, and
/// [`OutcomeFailure::ReplayBoundExceeded`] when the walk exceeds its bound.
pub async fn replay_outcome_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    tx_id: TxId,
) -> Result<OutcomeLookup, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        return Ok(OutcomeLookup::Undecided);
    };
    let mut head: RepositoryAuthorityHeadBody = head_body_of(&receipt)?;
    let mut walked = 0_usize;
    loop {
        let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? else {
            return Ok(OutcomeLookup::Undecided);
        };
        let batch = read_decision_batch_body_async(store, cx, batch_id).await?;
        if let Some(found) = scan_batch_for(&batch, tx_id) {
            return Ok(OutcomeLookup::Decided(found));
        }
        let predecessor = batch.predecessor_head_id;
        let Some(previous) = read_predecessor_async(store, cx, predecessor).await? else {
            return Ok(OutcomeLookup::Undecided);
        };
        head = previous;
    }
}

/// Answer "what happened to this transaction" on the production surface.
///
/// The asynchronous twin of [`resolve_outcome`], and the reason it has to exist
/// rather than callers using [`indexed_outcome_async`]: **that function reads
/// the accelerator alone.** The accelerator is a derived projection (§5.1), so
/// an absent row means "resolve authoritatively", never "no decision exists" —
/// and answering a post-disconnect lookup from it is the exact TOCTOU the §5.2
/// ruling exists to eliminate. Until this existed, the production surface could
/// *publish* correctly but could only *answer* from the hint.
///
/// Both answers are handed to [`reconcile_outcome`], which is the same pure
/// core the synchronous path uses. The two surfaces therefore cannot disagree
/// about what a pair of reads means; they differ only in how they wait.
///
/// # Errors
///
/// [`OutcomeFailure::AcceleratorConflict`] when the accelerator and the stream
/// disagree — this fails closed rather than picking a side. Otherwise the
/// store's typed refusals.
pub async fn resolve_outcome_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
) -> Result<OutcomeLookup, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let replayed = replay_outcome_async(store, cx, head_key, tx_id).await?;
    let indexed = indexed_outcome_async(store, cx, tenant_id, repository_id, tx_id).await?;
    reconcile_outcome(indexed, replayed)
}

// --- the authenticated head, read as a typed body ------------------------------
//
// `AuthenticatedHead` proves a receipt was issued by the store that returned it.
// It does not hand back the head; `receipt().body()` is opaque bytes, so every
// consumer has to decode them itself and remember the cross-check that makes the
// decode trustworthy.
//
// `fgit-admission` does that today in about fifteen lines, correctly. The next
// consumer -- the authenticated-head-bound reader FG-028a is blocked on -- would
// be the second copy, and a third would follow. Two implementations of "what
// does this head say" are free to disagree, which is the drift `frankengit-0kqi`
// was filed for one crate over: a model checked only against itself is a mirror,
// not a guard.
//
// So the decode and its cross-check live once, here, behind the type that
// already proves authenticity.

/// Why an authenticated head's body could not be read as a typed head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadBodyRefusal {
    /// The receipt's bytes are not a decodable head body.
    Codec(CodecRefusal),
    /// The decoded body's generation disagrees with the receipt's.
    ///
    /// Authentication proves the store issued this receipt; it does not prove
    /// the bytes inside describe the same head the receipt names. A caller that
    /// decodes without this check can act on a body one generation away from
    /// the head it authenticated, which §5.1 forbids: only the exact
    /// predecessor may be replaced.
    GenerationMismatch {
        /// What the authenticated receipt says.
        receipt: HeadGeneration,
        /// What the decoded body says.
        body: HeadGeneration,
    },
}

impl core::fmt::Display for HeadBodyRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(refusal) => write!(f, "head body is not decodable: {refusal}"),
            Self::GenerationMismatch { receipt, body } => write!(
                f,
                "authenticated receipt names generation {} but its body says {}",
                receipt.get(),
                body.get()
            ),
        }
    }
}

impl std::error::Error for HeadBodyRefusal {}

impl From<CodecRefusal> for HeadBodyRefusal {
    fn from(refusal: CodecRefusal) -> Self {
        Self::Codec(refusal)
    }
}

impl AuthenticatedHead {
    /// The typed head body carried by this authenticated receipt.
    ///
    /// Decoding is bounded by [`DecodeLimits::DEFAULT`], and the decoded
    /// generation is required to equal the receipt's. That cross-check is the
    /// reason this exists rather than callers writing `decode_body` themselves:
    /// authentication proves *the store issued this receipt*, and nothing more.
    /// It does not prove the bytes inside describe the head the receipt names,
    /// so a decode without the check can hand a caller a body one generation
    /// away from the head it just authenticated.
    ///
    /// # Errors
    ///
    /// [`HeadBodyRefusal::Codec`] if the bytes are not a decodable head body,
    /// [`HeadBodyRefusal::GenerationMismatch`] if the decoded generation
    /// disagrees with the authenticated receipt.
    pub fn body(&self) -> Result<RepositoryAuthorityHeadBody, HeadBodyRefusal> {
        head_body_of(self.receipt())
    }
}
