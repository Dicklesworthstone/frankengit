//! Authority-selected forge frontiers and their immutable body placement.
//! Legacy carry-forward roots may be bootstrapped only through verified history;
//! loss of an advanced frontier is not permission to rebuild an empty stream.

use std::collections::BTreeMap;

use fgit_authority::{AsyncAuthorityStore, ImmutableKey, ImmutableRead, PutOutcome};
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::canonical_state::{
    CanonicalForgePositionState, ForgePositionStateEntry, MAX_FORGE_POSITION_STATE_ENTRIES,
};
use fgit_codec::{CanonicalBody, CryptoBodyIdentity, DecodeLimits, decode_body, encode_body};
use fgit_forge::aggregate::{AggregateHead, AggregateId, AggregateVersion};
use fgit_forge::event::{ForgeEventBatch, ForgeEventPayload};
use fgit_types::{AsciiSlug, Digest, RefusalCode, RepositoryId};

use super::{NativeMergeIntent, unavailable};
use crate::AdmissionError;

pub(super) const EVENT_NAMESPACE: &[u8] = b"frankengit/admission/forge-event-batch/v1/";
pub(super) const POSITION_NAMESPACE: &[u8] = b"frankengit/admission/forge-position-state/v1/";
pub(super) const INVARIANT_NAMESPACE: &[u8] = b"frankengit/admission/invariant-evidence/v1/";
const MAX_BOOTSTRAP_BATCHES: usize = 4096;
const MAX_EVENTS: usize = 65_536;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const EVENT_LIMITS: DecodeLimits = DecodeLimits {
    elements: MAX_EVENTS as u64,
    ..DecodeLimits::DEFAULT
};
const POSITION_LIMITS: DecodeLimits = DecodeLimits {
    elements: MAX_FORGE_POSITION_STATE_ENTRIES as u64,
    ..DecodeLimits::DEFAULT
};

pub(super) async fn aggregate_refusal<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    positions: &CanonicalForgePositionState,
    intent: &NativeMergeIntent,
) -> Result<Option<RefusalCode>, AdmissionError> {
    let stream = aggregate_label(intent.event().aggregate)?;
    let previous = positions.entry(stream);
    let head = match previous {
        Some(entry) => AggregateHead::at(
            intent.event().aggregate,
            AggregateVersion::try_new(entry.successor_position())
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?,
        ),
        None => AggregateHead::empty(intent.event().aggregate),
    };
    if head.admit(intent.expected_version()).ok() != Some(intent.event().version) {
        return Ok(Some(RefusalCode::EvidenceStale));
    }
    if let Some(entry) = previous {
        let batch = read_events(
            store,
            cx,
            positions.repository_id(),
            entry.event_batch_root(),
        )
        .await?;
        let event = batch
            .events
            .iter()
            .rev()
            .find(|event| event.aggregate == intent.event().aggregate)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if event.version.get() != entry.successor_position() {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        if matches!(
            event.payload,
            ForgeEventPayload::MergeCommitted { .. }
                | ForgeEventPayload::MergeCommittedNative(_)
                | ForgeEventPayload::PullRequestClosed { .. }
        ) {
            return Ok(Some(RefusalCode::ProtectedRefTransitionDenied));
        }
        if let ForgeEventPayload::PullRequestChangedNative(change) = &event.payload {
            if change.action == fgit_forge::event::pull_request::PullRequestAction::Close {
                return Ok(Some(RefusalCode::ProtectedRefTransitionDenied));
            }
            // A PR number cannot authorize a different branch pair or newer
            // tips. Refresh the compared coordinates through an explicit update.
            if !change.data.matches_merge(intent.merge()?) {
                return Ok(Some(RefusalCode::EvidenceStale));
            }
        }
    }
    Ok(None)
}

/// Load the exact selected frontier. A legacy root that was carried unchanged
/// since genesis can be bootstrapped from the complete authenticated event
/// history; this is not allowed after any forge-root advancement. The returned
/// bootstrap state is derived until a native merge actually publishes its root.
/// Caller authorization must precede disclosure of this repository-level view.
pub async fn load_forge_positions<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
) -> Result<CanonicalForgePositionState, AdmissionError> {
    let repository = basis.body().repository_id;
    let selected_root = basis.body().forge_position_root;
    if let Some(frame) =
        read_frame(store, cx, repository, POSITION_NAMESPACE, selected_root).await?
    {
        let state = decode_body::<CanonicalForgePositionState>(&frame, POSITION_LIMITS)
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        if state.repository_id() != repository || root(&state)? != selected_root {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        return Ok(state);
    }
    let mut successor = basis.body().clone();
    let mut roots = Vec::new();
    let mut walked = 0;
    while let Some(batch_id) = successor.decision_tail_id {
        if walked >= MAX_BOOTSTRAP_BATCHES {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        walked += 1;
        let predecessor_id = successor
            .predecessor_head_id
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let predecessor =
            fgit_authority::read_authority_head_body_async(store, cx, predecessor_id).await?;
        let batch = fgit_authority::read_decision_batch_body_async(store, cx, batch_id).await?;
        verify_pair(
            &CryptoBodyIdentity,
            &PublicationBasis::new(predecessor_id, predecessor.clone()),
            &batch,
            &successor,
        )
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        if predecessor.forge_position_root != selected_root
            || successor.forge_position_root != selected_root
        {
            return Err(unavailable(RefusalCode::EvidenceMissing));
        }
        for record in batch.committed_rcrs.iter().rev() {
            if record.resulting_forge_position_root != selected_root {
                return Err(unavailable(RefusalCode::EvidenceMissing));
            }
            if roots.len() >= MAX_EVENTS {
                return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
            }
            roots.push(record.forge_event_batch_root);
        }
        successor = predecessor;
    }
    if selected_root != legacy_genesis_root(repository, b"forge-position")
        || successor.predecessor_head_id.is_some()
        || successor.latest_committed_rcr_id.is_some()
        || successor.latest_decision_sequence.is_some()
        || successor.repository_id != repository
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let mut state = CanonicalForgePositionState::try_new(repository, Vec::new())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    let mut events_seen = 0_usize;
    for event_root in roots.into_iter().rev() {
        let events = read_events(store, cx, repository, event_root).await?;
        events_seen = events_seen
            .checked_add(events.events.len())
            .filter(|count| *count <= MAX_EVENTS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        state = advance_positions(&state, &events, event_root)?;
    }
    Ok(state)
}

pub(super) fn advance_positions(
    previous: &CanonicalForgePositionState,
    batch: &ForgeEventBatch,
    event_root: Digest,
) -> Result<CanonicalForgePositionState, AdmissionError> {
    let mut entries: BTreeMap<_, _> = previous
        .entries()
        .iter()
        .map(|entry| (entry.stream(), *entry))
        .collect();
    let mut ranges = BTreeMap::<AsciiSlug, (u64, u32)>::new();
    let mut streams = entries.len();
    for event in &batch.events {
        let stream = aggregate_label(event.aggregate)?;
        if !entries.contains_key(&stream) && !ranges.contains_key(&stream) {
            if streams >= MAX_FORGE_POSITION_STATE_ENTRIES {
                return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
            }
            streams += 1;
        }
        let initial = entries
            .get(&stream)
            .map_or(0, ForgePositionStateEntry::successor_position);
        let range = ranges.entry(stream).or_insert((initial, 0));
        let next_count = range
            .1
            .checked_add(1)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        let expected = range
            .0
            .checked_add(u64::from(next_count))
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        if event.version.get() != expected {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        range.1 = next_count;
    }
    for (stream, (before, count)) in ranges {
        entries.insert(
            stream,
            ForgePositionStateEntry::try_new(stream, before, count, event_root)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?,
        );
    }
    CanonicalForgePositionState::try_new(previous.repository_id(), entries.into_values().collect())
        .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))
}

pub(super) fn aggregate_label(aggregate: AggregateId) -> Result<AsciiSlug, AdmissionError> {
    AsciiSlug::try_new("forge_stream", aggregate.to_string().as_bytes())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))
}

pub(super) async fn read_events<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    event_root: Digest,
) -> Result<ForgeEventBatch, AdmissionError> {
    let frame = read_frame(store, cx, repository, EVENT_NAMESPACE, event_root)
        .await?
        .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    if let Ok(batch) = decode_body::<ForgeEventBatch>(&frame, EVENT_LIMITS) {
        if root(&batch)? != event_root {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        return Ok(batch);
    }
    // Ref-only commits use a different, empty evidence schema. It must decode,
    // verify its exact commitment, AND be empty. Corruption is not emptiness.
    let empty = decode_body::<crate::evidence::ForgeEventBatch>(&frame, EVENT_LIMITS)
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    if root(&empty)? != event_root
        || !empty
            .is_empty()
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(ForgeEventBatch { events: Vec::new() })
}

pub(super) fn body_key(
    namespace: &[u8],
    repository: RepositoryId,
    digest: Digest,
) -> Result<ImmutableKey, AdmissionError> {
    let mut key = Vec::with_capacity(namespace.len() + 18 + digest.bytes().len());
    key.extend_from_slice(namespace);
    key.extend_from_slice(repository.as_bytes());
    key.extend_from_slice(&digest.algorithm().code_point().to_be_bytes());
    key.extend_from_slice(digest.bytes().as_bytes());
    ImmutableKey::new(key).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))
}

pub(super) async fn read_frame<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    namespace: &[u8],
    digest: Digest,
) -> Result<Option<Vec<u8>>, AdmissionError> {
    match store
        .read_immutable(cx, &body_key(namespace, repository, digest)?)
        .await?
    {
        ImmutableRead::Absent => Ok(None),
        ImmutableRead::Present(frame) => {
            if frame.len() > MAX_FRAME_BYTES {
                return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
            }
            Ok(Some(frame))
        }
    }
}

pub(super) async fn stage_body<S: AsyncAuthorityStore + ?Sized, B: CanonicalBody + Sync>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    namespace: &[u8],
    body: &B,
) -> Result<Digest, AdmissionError> {
    let digest = root(body)?;
    let frame = encode_body(body).map_err(|_| unavailable(RefusalCode::CanonicalFramingInvalid))?;
    if frame.len() > MAX_FRAME_BYTES {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    match store
        .put_if_absent(cx, &body_key(namespace, repository, digest)?, &frame)
        .await?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(digest),
        PutOutcome::Conflict => Err(unavailable(RefusalCode::EvidenceInvalid)),
    }
}

pub(super) fn root<B: CanonicalBody>(body: &B) -> Result<Digest, AdmissionError> {
    crate::evidence::evidence_root(body).map_err(unavailable)
}

/// The historical empty-node sentinel, preserved byte-for-byte for old heads.
pub fn legacy_genesis_root(repository_id: RepositoryId, label: &[u8]) -> Digest {
    let mut bytes = Vec::with_capacity(label.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(repository_id.as_bytes());
    let commitment = fgit_crypto::git_payload_commitment(
        fgit_crypto::GitObjectKind::Blob,
        &bytes,
        fgit_types::CANONICAL_CODEC_VERSION,
    );
    Digest::new(
        fgit_crypto::IdentityDomain::GitPayloadCommitment
            .algorithm()
            .id(),
        *commitment.digest(),
    )
}
