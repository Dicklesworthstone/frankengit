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
    CodecRefusal, DecodeLimits, Decoder, Encoder, RepositoryAuthorityHeadBody,
    RepositoryDecisionBatchBody, decode_body,
};
use fgit_crypto::{IdentityDomain, internal_digest_over_parts};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{
    InternalObjectId, RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, RepositoryId, TenantId, TxId,
};
use fgit_types::numeric::DecisionSequence;
use fgit_types::vocabulary::{DecisionOutcome, RefusalCode};
use std::collections::BTreeMap;

use crate::async_contract::{AsyncAuthorityStore, DuplicateAbsenceWitness};
use crate::contract::AuthorityStore;
use crate::identity::canonical_body_id;
use crate::keys::{HeadKey, ImmutableKey};
use crate::seal::{BODY_KEY_PREFIX, SealFailure, body_key};
use fgit_types::HeadGeneration;

use crate::tokens::AuthorityVersionToken;
use crate::vocabulary::{
    AuthorityFailure, AuthorityRefusal, CasOutcome, HeadInit, HeadRead, HeadReadReceipt,
    ImmutableRead,
};

/// Namespace prefix of a per-identity outcome accelerator slot.
pub const OUTCOME_KEY_PREFIX: &[u8] = b"fg/outcome/v1/";

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
fn body_key_for_id(id: &InternalObjectId) -> Result<ImmutableKey, SealFailure> {
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
    let schema = outcome_index_schema();
    let mut level: Vec<DigestBytes> = Vec::with_capacity(entries.len());
    for (tx_id, outcome) in entries {
        let encoded = encode_outcome(outcome)?;
        level.push(internal_digest_over_parts(
            IdentityDomain::MerkleLeaf,
            schema,
            &[tx_id.as_internal_object_id().digest().as_bytes(), &encoded],
        ));
    }
    level.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    let Some(mut root) = level.first().copied() else {
        return Ok(Digest::new(
            IdentityDomain::MerkleNode.algorithm().id(),
            internal_digest_over_parts(IdentityDomain::MerkleNode, schema, &[]),
        ));
    };

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let (pairs, remainder) = level.as_chunks::<2>();
        for [left, right] in pairs {
            next.push(internal_digest_over_parts(
                IdentityDomain::MerkleNode,
                schema,
                &[left.as_bytes(), right.as_bytes()],
            ));
        }
        if let Some(odd) = remainder.first() {
            next.push(*odd);
        }
        level = next;
        root = level.first().copied().unwrap_or(root);
    }

    Ok(Digest::new(
        IdentityDomain::MerkleNode.algorithm().id(),
        root,
    ))
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
/// It does not gate publication, and it does not say where `carried` comes
/// from. Retention -- whether the authority materializes the cumulative leaf
/// set, or the commitment changes, or capsules gain an `outcome_index_root`
/// field to bound the walk -- is a canonical-body question under §5.2/§10 and
/// is escalated, not decided here. Today the only route to historic outcomes
/// is the decision-chain walk, bounded at [`MAX_REPLAY_BATCHES`], so a caller
/// past that bound cannot supply `carried` at all. That is a refusal at the
/// caller's layer, deliberately not papered over here with a partial set that
/// would silently produce a wrong root.
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
fn outcome_entries(
    tenant_id: TenantId,
    batch: &RepositoryDecisionBatchBody,
) -> Result<Vec<(ImmutableKey, Vec<u8>)>, OutcomeFailure> {
    let mut entries: Vec<(ImmutableKey, Vec<u8>)> = Vec::with_capacity(batch.decisions.len());
    for decision in &batch.decisions {
        let key = outcome_key(tenant_id, batch.repository_id, decision.tx_id)?;
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
