//! Immutable retained-leaf checkpoints for the cumulative outcome index.
//!
//! The outcome-index commitment is ordered by leaf digest, not insertion
//! sequence. A checkpoint therefore retains the terminal decisions from which
//! authority derives those leaves; retaining only the root would make a later
//! tail impossible to fold. This body is immutable evidence, while the
//! capsule that names its digest remains the root-last publication point.

use core::fmt;
use std::collections::BTreeSet;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityStore, CumulativeOutcomes,
    HeadKey, HeadRead, ImmutableRead, OutcomeFailure, PutOutcome, body_key_for_id,
    canonical_outcome_index_decisions, collect_cumulative_outcomes,
    collect_cumulative_outcomes_async, collect_cumulative_outcomes_from_checkpoint,
    collect_cumulative_outcomes_from_checkpoint_async,
};
use fgit_codec::attest::{BodyIdentity, body_id};
use fgit_codec::{
    CODEC_VERSION, CanonicalBody, CodecRefusal, DecodeLimits, RepositoryDecision, decode_body,
    encode_body,
};
use fgit_codec::{Decoder, Encoder};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    DecisionSequence, Digest, DomainTag, InternalObjectId, RepositoryCapsuleId,
    RepositoryDecisionBatchId, RepositoryId, SchemaFamily,
};

/// The immutable retained leaf set for one exact decision-log position.
///
/// `decisions` are in the authority-owned digest order. They are terminal
/// facts rather than precomputed leaf bytes so the one existing authority
/// implementation continues to own the leaf encoding and Merkle commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeIndexCheckpointBody {
    /// Repository whose decision stream this checkpoint summarizes.
    pub repository_id: RepositoryId,
    /// Exact decision-tail body the retained leaf set includes through.
    pub decision_tail_id: Option<RepositoryDecisionBatchId>,
    /// Exact terminal-decision position the retained leaf set includes through.
    pub latest_decision_sequence: Option<DecisionSequence>,
    /// Digest of the immediate older retained-leaf checkpoint, absent at genesis.
    pub predecessor_checkpoint_root: Option<Digest>,
    decisions: Vec<RepositoryDecision>,
}

impl OutcomeIndexCheckpointBody {
    /// Constructs a checkpoint only from the authority's canonical leaf order.
    pub fn new(
        repository_id: RepositoryId,
        decision_tail_id: Option<RepositoryDecisionBatchId>,
        latest_decision_sequence: Option<DecisionSequence>,
        predecessor_checkpoint_root: Option<Digest>,
        decisions: Vec<RepositoryDecision>,
    ) -> Result<Self, OutcomeIndexCheckpointRefusal> {
        if decision_tail_id.is_some() != latest_decision_sequence.is_some() {
            return Err(OutcomeIndexCheckpointRefusal::PositionPairMismatch);
        }
        let decisions = canonical_outcome_index_decisions(&decisions)
            .map_err(OutcomeIndexCheckpointRefusal::Outcome)?;
        Ok(Self {
            repository_id,
            decision_tail_id,
            latest_decision_sequence,
            predecessor_checkpoint_root,
            decisions,
        })
    }

    /// The retained terminal decisions in the one commitment order.
    #[must_use]
    pub fn decisions(&self) -> &[RepositoryDecision] {
        &self.decisions
    }

    /// Checks the position pairing and authority-owned ordering after decoding.
    pub fn verify_canonical(&self) -> Result<(), OutcomeIndexCheckpointRefusal> {
        if self.decision_tail_id.is_some() != self.latest_decision_sequence.is_some() {
            return Err(OutcomeIndexCheckpointRefusal::PositionPairMismatch);
        }
        let canonical = canonical_outcome_index_decisions(&self.decisions)
            .map_err(OutcomeIndexCheckpointRefusal::Outcome)?;
        if canonical != self.decisions {
            return Err(OutcomeIndexCheckpointRefusal::LeafOrderMismatch);
        }
        Ok(())
    }
}

impl CanonicalBody for OutcomeIndexCheckpointBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/outcome-index-checkpoint/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("outcome-index-checkpoint");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_option(self.decision_tail_id.as_ref(), |out, tail_id| {
            out.write_internal_object_id(tail_id.as_internal_object_id())
        })?;
        out.write_option(self.latest_decision_sequence.as_ref(), |out, sequence| {
            out.write_scalar(sequence.get());
            Ok(())
        })?;
        out.write_option(self.predecessor_checkpoint_root.as_ref(), |out, root| {
            out.write_digest(root)
        })?;
        out.write_sequence(
            "outcome_index_decisions",
            &self.decisions,
            RepositoryDecision::write_canonical,
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let decision_tail_id = input.read_option("decision_tail_id", |input| {
            RepositoryDecisionBatchId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)
        })?;
        let latest_decision_sequence = input.read_option("latest_decision_sequence", |input| {
            DecisionSequence::try_new(input.read_scalar::<u64>("latest_decision_sequence")?)
                .map_err(CodecRefusal::from)
        })?;
        let predecessor_checkpoint_root =
            input.read_option("predecessor_checkpoint_root", Decoder::read_digest)?;
        let decisions = input.read_sequence(
            "outcome_index_decisions",
            RepositoryDecision::read_canonical,
        )?;
        Ok(Self {
            repository_id,
            decision_tail_id,
            latest_decision_sequence,
            predecessor_checkpoint_root,
            decisions,
        })
    }
}

/// Refusals while deriving, staging, or reading retained outcome-index evidence.
#[derive(Debug)]
pub enum OutcomeIndexCheckpointRefusal {
    /// The checkpoint did not name both parts of its exact decision position.
    PositionPairMismatch,
    /// Retained decisions are not in authority's one commitment order.
    LeafOrderMismatch,
    /// Authority refused duplicate, malformed, or otherwise invalid decisions.
    Outcome(OutcomeFailure),
    /// Canonical body encoding or decoding refused.
    Codec(CodecRefusal),
    /// The configured identity implementation could not identify this body.
    IdentityUnavailable,
    /// The identity result did not use the registered checkpoint domain.
    IdentityDomainMismatch,
    /// A requested immutable checkpoint body was absent.
    NotStaged,
    /// An immutable slot already held different checkpoint bytes.
    SlotConflict,
    /// Exact byte readback after staging did not prove the checkpoint exists.
    ReadbackMismatch,
    /// The body decoded at a requested digest has a different identity.
    IdentityMismatch,
    /// A predecessor cycle would make retained evidence non-terminating.
    PredecessorCycle,
    /// The predecessor chain exceeded its bounded verification budget.
    PredecessorChainTooLong,
    /// A predecessor belongs to another repository.
    PredecessorRepositoryMismatch,
    /// A predecessor does not name an older decision position.
    PredecessorPositionMismatch,
    /// The authority backend refused an immutable operation.
    Authority(AuthorityFailure),
}

impl fmt::Display for OutcomeIndexCheckpointRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PositionPairMismatch => formatter.write_str(
                "outcome-index checkpoint must name both decision-tail id and decision sequence",
            ),
            Self::LeafOrderMismatch => formatter
                .write_str("outcome-index checkpoint decisions are not in commitment order"),
            Self::Outcome(error) => write!(formatter, "outcome-index checkpoint refused: {error}"),
            Self::Codec(error) => {
                write!(formatter, "outcome-index checkpoint codec refused: {error}")
            }
            Self::IdentityUnavailable => {
                formatter.write_str("outcome-index checkpoint identity was unavailable")
            }
            Self::IdentityDomainMismatch => formatter
                .write_str("outcome-index checkpoint identity used the wrong registered domain"),
            Self::NotStaged => formatter.write_str("outcome-index checkpoint body was not staged"),
            Self::SlotConflict => {
                formatter.write_str("outcome-index checkpoint immutable slot held different bytes")
            }
            Self::ReadbackMismatch => formatter.write_str(
                "outcome-index checkpoint staging was not proven by exact byte readback",
            ),
            Self::IdentityMismatch => formatter.write_str(
                "outcome-index checkpoint bytes did not reproduce the requested identity",
            ),
            Self::PredecessorCycle => {
                formatter.write_str("outcome-index checkpoint predecessor chain contains a cycle")
            }
            Self::PredecessorChainTooLong => formatter.write_str(
                "outcome-index checkpoint predecessor chain exceeded its verification bound",
            ),
            Self::PredecessorRepositoryMismatch => formatter
                .write_str("outcome-index checkpoint predecessor belongs to another repository"),
            Self::PredecessorPositionMismatch => formatter.write_str(
                "outcome-index checkpoint predecessor does not name an older decision position",
            ),
            Self::Authority(error) => {
                write!(
                    formatter,
                    "outcome-index checkpoint authority operation refused: {error}"
                )
            }
        }
    }
}

impl std::error::Error for OutcomeIndexCheckpointRefusal {}

/// Derives the digest a capsule binds for an immutable checkpoint body.
pub fn outcome_index_checkpoint_root<I>(
    identity: &I,
    checkpoint: &OutcomeIndexCheckpointBody,
) -> Result<Digest, OutcomeIndexCheckpointRefusal>
where
    I: BodyIdentity + ?Sized,
{
    checkpoint.verify_canonical()?;
    let id = body_id(identity, checkpoint)
        .map_err(|_| OutcomeIndexCheckpointRefusal::IdentityUnavailable)?;
    if id.domain() != IdentityDomain::OutcomeIndexCheckpoint.domain_tag() {
        return Err(OutcomeIndexCheckpointRefusal::IdentityDomainMismatch);
    }
    Ok(Digest::new(id.algorithm(), *id.digest()))
}

fn checkpoint_key(
    root: Digest,
) -> Result<fgit_authority::ImmutableKey, OutcomeIndexCheckpointRefusal> {
    let domain = IdentityDomain::OutcomeIndexCheckpoint;
    if root.algorithm() != domain.algorithm().id() {
        return Err(OutcomeIndexCheckpointRefusal::IdentityDomainMismatch);
    }
    let id = InternalObjectId::new(
        root.algorithm(),
        domain.domain_tag(),
        CODEC_VERSION,
        *root.bytes(),
    );
    body_key_for_id(&id).map_err(|_| OutcomeIndexCheckpointRefusal::IdentityUnavailable)
}

/// Stages a verified checkpoint and proves the exact canonical bytes are readable.
pub fn stage_outcome_index_checkpoint<S, I>(
    store: &S,
    identity: &I,
    checkpoint: &OutcomeIndexCheckpointBody,
) -> Result<Digest, OutcomeIndexCheckpointRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let root = outcome_index_checkpoint_root(identity, checkpoint)?;
    let bytes = encode_body(checkpoint).map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    let key = checkpoint_key(root)?;
    match store
        .put_if_absent(&key, &bytes)
        .map_err(OutcomeIndexCheckpointRefusal::Authority)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(OutcomeIndexCheckpointRefusal::SlotConflict),
    }
    if !matches!(store.read_immutable(&key), Ok(ImmutableRead::Present(found)) if found == bytes) {
        return Err(OutcomeIndexCheckpointRefusal::ReadbackMismatch);
    }
    Ok(root)
}

/// Asynchronous twin of [`stage_outcome_index_checkpoint`].
pub async fn stage_outcome_index_checkpoint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    checkpoint: &OutcomeIndexCheckpointBody,
) -> Result<Digest, OutcomeIndexCheckpointRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let root = outcome_index_checkpoint_root(identity, checkpoint)?;
    let bytes = encode_body(checkpoint).map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    let key = checkpoint_key(root)?;
    match store
        .put_if_absent(cx, &key, &bytes)
        .await
        .map_err(OutcomeIndexCheckpointRefusal::Authority)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(OutcomeIndexCheckpointRefusal::SlotConflict),
    }
    if !matches!(store.read_immutable(cx, &key).await, Ok(ImmutableRead::Present(found)) if found == bytes)
    {
        return Err(OutcomeIndexCheckpointRefusal::ReadbackMismatch);
    }
    Ok(root)
}

/// Loads a checkpoint only when its exact requested identity and canonical form agree.
pub fn load_outcome_index_checkpoint<S, I>(
    store: &S,
    identity: &I,
    root: Digest,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let key = checkpoint_key(root)?;
    let ImmutableRead::Present(bytes) = store
        .read_immutable(&key)
        .map_err(OutcomeIndexCheckpointRefusal::Authority)?
    else {
        return Err(OutcomeIndexCheckpointRefusal::NotStaged);
    };
    let checkpoint =
        decode_body(&bytes, DecodeLimits::DEFAULT).map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    if outcome_index_checkpoint_root(identity, &checkpoint)? != root {
        return Err(OutcomeIndexCheckpointRefusal::IdentityMismatch);
    }
    Ok(checkpoint)
}

/// Asynchronous twin of [`load_outcome_index_checkpoint`].
pub async fn load_outcome_index_checkpoint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    root: Digest,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let key = checkpoint_key(root)?;
    let ImmutableRead::Present(bytes) = store
        .read_immutable(cx, &key)
        .await
        .map_err(OutcomeIndexCheckpointRefusal::Authority)?
    else {
        return Err(OutcomeIndexCheckpointRefusal::NotStaged);
    };
    let checkpoint =
        decode_body(&bytes, DecodeLimits::DEFAULT).map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    if outcome_index_checkpoint_root(identity, &checkpoint)? != root {
        return Err(OutcomeIndexCheckpointRefusal::IdentityMismatch);
    }
    Ok(checkpoint)
}

/// Maximum predecessor links accepted while validating checkpoint evidence.
///
/// A checkpoint chain is acceleration evidence, never an unbounded traversal
/// permission. This mirrors the decision-tail bound while remaining far above
/// a normal compaction cadence.
pub const MAX_CHECKPOINT_PREDECESSORS: usize = 65_536;

/// Verifies the complete predecessor chain and returns the checkpoint named by
/// `root`.
///
/// Every body is reread at its declared digest, has its canonical leaf order
/// checked, belongs to one repository, and strictly advances the decision
/// position over its predecessor. A malformed chain is not usable evidence.
pub fn verify_outcome_index_checkpoint_chain<S, I>(
    store: &S,
    identity: &I,
    root: Digest,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let first = load_outcome_index_checkpoint(store, identity, root)?;
    let repository_id = first.repository_id;
    let mut current = first.clone();
    let mut seen = BTreeSet::from([root]);
    let mut links = 0_usize;

    while let Some(predecessor_root) = current.predecessor_checkpoint_root {
        if links == MAX_CHECKPOINT_PREDECESSORS {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorChainTooLong);
        }
        if !seen.insert(predecessor_root) {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorCycle);
        }
        let predecessor = load_outcome_index_checkpoint(store, identity, predecessor_root)?;
        if predecessor.repository_id != repository_id {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorRepositoryMismatch);
        }
        if !checkpoint_position_advances(&current, &predecessor) {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorPositionMismatch);
        }
        current = predecessor;
        links += 1;
    }
    Ok(first)
}

/// Asynchronous twin of [`verify_outcome_index_checkpoint_chain`].
pub async fn verify_outcome_index_checkpoint_chain_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    root: Digest,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let first = load_outcome_index_checkpoint_async(store, cx, identity, root).await?;
    let repository_id = first.repository_id;
    let mut current = first.clone();
    let mut seen = BTreeSet::from([root]);
    let mut links = 0_usize;

    while let Some(predecessor_root) = current.predecessor_checkpoint_root {
        if links == MAX_CHECKPOINT_PREDECESSORS {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorChainTooLong);
        }
        if !seen.insert(predecessor_root) {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorCycle);
        }
        let predecessor =
            load_outcome_index_checkpoint_async(store, cx, identity, predecessor_root).await?;
        if predecessor.repository_id != repository_id {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorRepositoryMismatch);
        }
        if !checkpoint_position_advances(&current, &predecessor) {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorPositionMismatch);
        }
        current = predecessor;
        links += 1;
    }
    Ok(first)
}

fn checkpoint_position_advances(
    newer: &OutcomeIndexCheckpointBody,
    older: &OutcomeIndexCheckpointBody,
) -> bool {
    match (
        newer.latest_decision_sequence,
        older.latest_decision_sequence,
    ) {
        (Some(newer), Some(older)) => newer > older,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn load_capsule_at_id<S, I>(
    store: &S,
    identity: &I,
    capsule_id: RepositoryCapsuleId,
) -> Result<Option<crate::RepositoryCapsuleBody>, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let key = body_key_for_id(capsule_id.as_internal_object_id())?;
    let ImmutableRead::Present(bytes) = store.read_immutable(&key)? else {
        return Ok(None);
    };
    let Ok(capsule) = decode_body(&bytes, DecodeLimits::DEFAULT) else {
        return Ok(None);
    };
    let Ok(found) = crate::capsule_identity(identity, &capsule) else {
        return Ok(None);
    };
    if found != capsule_id {
        return Ok(None);
    }
    Ok(Some(capsule))
}

async fn load_capsule_at_id_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    capsule_id: RepositoryCapsuleId,
) -> Result<Option<crate::RepositoryCapsuleBody>, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let key = body_key_for_id(capsule_id.as_internal_object_id())?;
    let ImmutableRead::Present(bytes) = store.read_immutable(cx, &key).await? else {
        return Ok(None);
    };
    let Ok(capsule) = decode_body(&bytes, DecodeLimits::DEFAULT) else {
        return Ok(None);
    };
    let Ok(found) = crate::capsule_identity(identity, &capsule) else {
        return Ok(None);
    };
    if found != capsule_id {
        return Ok(None);
    }
    Ok(Some(capsule))
}

/// Collects outcome-index leaves from a capsule-bound retained checkpoint when
/// one is usable, otherwise performs today's bounded genesis walk.
///
/// Checkpoint evidence is an acceleration hint, never a second authority. A
/// missing, undecodable, wrongly identified, or malformed checkpoint selects
/// the genesis collector. Backend failures still propagate, and a usable
/// checkpoint whose exact authority position/root cannot be reached is also
/// discarded in favour of that same bounded baseline.
pub fn collect_cumulative_outcomes_from_capsule_checkpoint<S, I>(
    store: &S,
    identity: &I,
    head_key: &HeadKey,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        return collect_cumulative_outcomes(store, head_key);
    };
    let head: fgit_codec::RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT)?;
    collect_cumulative_outcomes_from_checkpoint_hint(store, identity, head_key, &head)
}

/// Collects outcome-index leaves using a head that the caller already
/// authenticated for its publication basis.
///
/// Admission reads and authenticates one exact basis before it resolves the
/// cumulative index. Reusing that head for the optional capsule hint avoids a
/// speculative extra `read_head` while the baseline collector retains its own
/// read, preserving the recovery transcript and its version binding.
pub fn collect_cumulative_outcomes_from_authenticated_capsule_checkpoint<S, I>(
    store: &S,
    identity: &I,
    head_key: &HeadKey,
    authenticated_head: &AuthenticatedHead,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let head = authenticated_head.body()?;
    collect_cumulative_outcomes_from_checkpoint_hint(store, identity, head_key, &head)
}

fn collect_cumulative_outcomes_from_checkpoint_hint<S, I>(
    store: &S,
    identity: &I,
    head_key: &HeadKey,
    head: &fgit_codec::RepositoryAuthorityHeadBody,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let Some(capsule_id) = head.last_checkpoint_id else {
        return collect_cumulative_outcomes(store, head_key);
    };
    let Some(capsule) = load_capsule_at_id(store, identity, capsule_id)? else {
        return collect_cumulative_outcomes(store, head_key);
    };
    if capsule.repository_id != head.repository_id {
        return collect_cumulative_outcomes(store, head_key);
    }
    let Some(root) = capsule.outcome_index_checkpoint_root else {
        return collect_cumulative_outcomes(store, head_key);
    };
    let checkpoint = match verify_outcome_index_checkpoint_chain(store, identity, root) {
        Ok(checkpoint) if checkpoint.repository_id == head.repository_id => checkpoint,
        Ok(_) => {
            return collect_cumulative_outcomes(store, head_key);
        }
        Err(OutcomeIndexCheckpointRefusal::Authority(error)) => return Err(error.into()),
        Err(_) => return collect_cumulative_outcomes(store, head_key),
    };
    match collect_cumulative_outcomes_from_checkpoint(
        store,
        head_key,
        checkpoint.decisions(),
        checkpoint.decision_tail_id,
        checkpoint.latest_decision_sequence,
    ) {
        Ok(outcomes) => Ok(outcomes),
        Err(
            OutcomeFailure::CheckpointPositionMismatch | OutcomeFailure::CheckpointRootMismatch,
        ) => collect_cumulative_outcomes(store, head_key),
        Err(error) => Err(error),
    }
}

/// Asynchronous production twin of
/// [`collect_cumulative_outcomes_from_capsule_checkpoint`].
pub async fn collect_cumulative_outcomes_from_capsule_checkpoint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    head_key: &HeadKey,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    let head: fgit_codec::RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT)?;
    collect_cumulative_outcomes_from_checkpoint_hint_async(store, cx, identity, head_key, &head)
        .await
}

/// Asynchronous sibling of
/// [`collect_cumulative_outcomes_from_authenticated_capsule_checkpoint`].
pub async fn collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    head_key: &HeadKey,
    authenticated_head: &AuthenticatedHead,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let head = authenticated_head.body()?;
    collect_cumulative_outcomes_from_checkpoint_hint_async(store, cx, identity, head_key, &head)
        .await
}

async fn collect_cumulative_outcomes_from_checkpoint_hint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    head_key: &HeadKey,
    head: &fgit_codec::RepositoryAuthorityHeadBody,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let Some(capsule_id) = head.last_checkpoint_id else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    let Some(capsule) = load_capsule_at_id_async(store, cx, identity, capsule_id).await? else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    if capsule.repository_id != head.repository_id {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    }
    let Some(root) = capsule.outcome_index_checkpoint_root else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    enum CheckpointCandidate {
        Exact(Box<OutcomeIndexCheckpointBody>),
        ForeignRepository,
        Unavailable,
    }
    // A valid checkpoint for another repository and an unusable checkpoint both
    // fall back to the genesis walk, but remain distinct cases: authority errors
    // must still propagate rather than being treated as an unavailable hint.
    let candidate =
        match verify_outcome_index_checkpoint_chain_async(store, cx, identity, root).await {
            Ok(checkpoint) if checkpoint.repository_id == head.repository_id => {
                CheckpointCandidate::Exact(Box::new(checkpoint))
            }
            Ok(_) => CheckpointCandidate::ForeignRepository,
            Err(OutcomeIndexCheckpointRefusal::Authority(error)) => return Err(error.into()),
            Err(_) => CheckpointCandidate::Unavailable,
        };
    let CheckpointCandidate::Exact(checkpoint) = candidate else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    match collect_cumulative_outcomes_from_checkpoint_async(
        store,
        cx,
        head_key,
        checkpoint.decisions(),
        checkpoint.decision_tail_id,
        checkpoint.latest_decision_sequence,
    )
    .await
    {
        Ok(outcomes) => Ok(outcomes),
        Err(
            OutcomeFailure::CheckpointPositionMismatch | OutcomeFailure::CheckpointRootMismatch,
        ) => collect_cumulative_outcomes_async(store, cx, head_key).await,
        Err(error) => Err(error),
    }
}
