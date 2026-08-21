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

use fgit_codec::wire::encode_body;
use fgit_codec::{
    CodecRefusal, DecodeLimits, Decoder, Encoder, RepositoryAuthorityHeadBody,
    RepositoryDecisionBatchBody, decode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::identity::{
    RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId,
    RepositoryId, TenantId, TxId,
};
use fgit_types::numeric::DecisionSequence;
use fgit_types::vocabulary::{DecisionOutcome, RefusalCode};

use crate::contract::AuthorityStore;
use crate::identity::canonical_body_id;
use crate::keys::{HeadKey, ImmutableKey};
use crate::seal::{SealFailure, body_key};
use fgit_types::HeadGeneration;

use crate::tokens::AuthorityVersionToken;
use crate::vocabulary::{CasOutcome, HeadRead, HeadReadReceipt, ImmutableRead, PutOutcome};

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
        indexed: TerminalOutcome,
        /// What the stream proves.
        replayed: TerminalOutcome,
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
    /// Sealing, storage, identity, or codec failed underneath.
    Seal(SealFailure),
    /// A canonical body could not be encoded or decoded.
    Codec(CodecRefusal),
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
            Self::Seal(failure) => write!(f, "{failure}"),
            Self::Codec(refusal) => write!(f, "canonical encoding refused: {refusal}"),
        }
    }
}

impl std::error::Error for OutcomeFailure {}

impl From<SealFailure> for OutcomeFailure {
    fn from(failure: SealFailure) -> Self {
        Self::Seal(failure)
    }
}

impl From<CodecRefusal> for OutcomeFailure {
    fn from(refusal: CodecRefusal) -> Self {
        Self::Codec(refusal)
    }
}

impl From<crate::identity::IdentityRefusal> for OutcomeFailure {
    fn from(refusal: crate::identity::IdentityRefusal) -> Self {
        Self::Seal(SealFailure::Identity(refusal))
    }
}

impl From<crate::vocabulary::AuthorityFailure> for OutcomeFailure {
    fn from(failure: crate::vocabulary::AuthorityFailure) -> Self {
        Self::Seal(SealFailure::Store(failure))
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
    match store.read_immutable(&key)? {
        ImmutableRead::Absent => Ok(OutcomeLookup::Undecided),
        ImmutableRead::Present(bytes) => Ok(OutcomeLookup::Decided(decode_outcome(&bytes)?)),
    }
}

fn read_head_body<S>(
    store: &S,
    head_id: RepositoryAuthorityHeadId,
) -> Result<RepositoryAuthorityHeadBody, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key_for_id(b"fg/body/v1/", head_id.as_internal_object_id())?;
    match store.read_immutable(&key)? {
        ImmutableRead::Absent => Err(OutcomeFailure::StreamBodyMissing { link: "head body" }),
        ImmutableRead::Present(bytes) => Ok(decode_body(&bytes, DecodeLimits::DEFAULT)?),
    }
}

fn read_batch_body<S>(
    store: &S,
    batch_id: RepositoryDecisionBatchId,
) -> Result<RepositoryDecisionBatchBody, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = body_key_for_id(b"fg/body/v1/", batch_id.as_internal_object_id())?;
    match store.read_immutable(&key)? {
        ImmutableRead::Absent => Err(OutcomeFailure::StreamBodyMissing {
            link: "decision batch",
        }),
        ImmutableRead::Present(bytes) => Ok(decode_body(&bytes, DecodeLimits::DEFAULT)?),
    }
}

fn body_key_for_id(
    prefix: &[u8],
    id: &fgit_types::identity::InternalObjectId,
) -> Result<ImmutableKey, SealFailure> {
    let mut bytes = Vec::with_capacity(prefix.len() + 80);
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(id.domain().as_bytes());
    bytes.push(b'/');
    bytes.extend_from_slice(id.digest().as_bytes());
    Ok(ImmutableKey::new(bytes)?)
}

/// Resolve one identity's terminal decision by replaying the authenticated stream.
///
/// This is the recovery path: it consults no accelerator and would give the
/// same answer on a node whose index was wiped.
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
    let mut head: RepositoryAuthorityHeadBody = decode_body(receipt.body(), DecodeLimits::DEFAULT)?;
    let mut walked = 0_usize;
    loop {
        let Some(batch_id) = head.decision_tail_id else {
            return Ok(OutcomeLookup::Undecided);
        };
        walked = walked.saturating_add(1);
        if walked > MAX_REPLAY_BATCHES {
            return Err(OutcomeFailure::ReplayBoundExceeded {
                limit: MAX_REPLAY_BATCHES,
            });
        }
        let batch = read_batch_body(store, batch_id)?;
        for decision in &batch.decisions {
            if decision.tx_id == tx_id {
                return Ok(OutcomeLookup::Decided(TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                }));
            }
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
    let body = read_head_body(store, head_id)?;
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
    match (indexed, replayed) {
        // The accelerator is allowed to be behind: that is the repairable
        // state a crash between publication and indexing leaves.
        (OutcomeLookup::Undecided, answer) => Ok(answer),
        (OutcomeLookup::Decided(left), OutcomeLookup::Decided(right)) if left == right => {
            Ok(OutcomeLookup::Decided(left))
        }
        (OutcomeLookup::Decided(indexed), OutcomeLookup::Decided(replayed)) => {
            Err(OutcomeFailure::AcceleratorConflict { indexed, replayed })
        }
        // An accelerator that claims a decision the stream does not contain is
        // the dangerous direction, and it is the one that fails closed.
        (OutcomeLookup::Decided(indexed), OutcomeLookup::Undecided) => {
            Err(OutcomeFailure::AcceleratorConflict {
                indexed,
                replayed: indexed,
            })
        }
    }
}

/// The outcome of publishing one decision batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    /// The batch is canonical and the accelerator entries are written.
    Published {
        /// The head this publication established.
        head: HeadReadReceipt,
        /// The batch that became canonical.
        batch_id: RepositoryDecisionBatchId,
        /// How many accelerator entries this publication added.
        indexed: usize,
    },
    /// The head moved before the conditional replacement landed.
    ///
    /// Nothing was published; the staged bodies remain staged and unreferenced.
    PredecessorMismatch,
}

/// Stage a batch and its head, replace the head, then index the decisions.
///
/// The order is the one §8.3 and §8.4 require: bodies are staged first and are
/// unreachable canonically until the conditional replacement makes them
/// canonical, and the accelerator is written only afterwards, from decisions
/// that are already canonical.
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
    let batch_id = RepositoryDecisionBatchId::from_internal_object_id(canonical_body_id(
        IdentityDomain::RepositoryDecisionBatch,
        CANONICAL_CODEC_VERSION,
        batch,
    )?)
    .map_err(|_| OutcomeFailure::StreamBodyMissing {
        link: "decision batch identity",
    })?;

    let batch_key = body_key(IdentityDomain::RepositoryDecisionBatch, batch)?;
    let batch_bytes = encode_body(batch)?;
    store.put_if_absent(&batch_key, &batch_bytes)?;

    let head_key_by_id = body_key(IdentityDomain::RepositoryAuthorityHead, head)?;
    let head_bytes = encode_body(head)?;
    store.put_if_absent(&head_key_by_id, &head_bytes)?;

    let generation = HeadGeneration::try_new(head.generation.get())
        .map_err(|refusal| OutcomeFailure::Codec(refusal.into()))?;
    let receipt = match store.compare_exchange_head(head_key, expected, generation, &head_bytes)? {
        CasOutcome::Committed(receipt) => receipt,
        CasOutcome::PredecessorMismatch => return Ok(PublicationOutcome::PredecessorMismatch),
    };

    let mut indexed = 0_usize;
    for decision in &batch.decisions {
        let key = outcome_key(tenant_id, batch.repository_id, decision.tx_id)?;
        let entry = TerminalOutcome {
            decision_sequence: decision.decision_sequence,
            outcome: decision.outcome,
        };
        // Put-if-absent is what enforces at most one terminal decision per
        // sealed transaction: a second, different decision cannot overwrite the
        // first, it conflicts.
        match store.put_if_absent(&key, &encode_outcome(&entry)?)? {
            PutOutcome::Created | PutOutcome::IdenticalRetry => indexed = indexed.saturating_add(1),
            PutOutcome::Conflict => {
                let existing =
                    match indexed_outcome(store, tenant_id, batch.repository_id, decision.tx_id)? {
                        OutcomeLookup::Decided(existing) => existing,
                        OutcomeLookup::Undecided => entry,
                    };
                return Err(OutcomeFailure::AcceleratorConflict {
                    indexed: existing,
                    replayed: entry,
                });
            }
        }
    }

    Ok(PublicationOutcome::Published {
        head: receipt,
        batch_id,
        indexed,
    })
}
