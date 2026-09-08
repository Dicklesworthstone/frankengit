//! Position-addressed snapshot projection over immutable repository history.
//! Current disclosure policy governs historical reads. Native merge receipts
//! remain native identities; legacy digest-valued events are never cast to OIDs.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use fgit_authority::AuthorityFailure;
use fgit_chronicle::{ChronicleRefusal, RepositoryCapsuleBody};
use fgit_codec::schema::{RepositoryAuthorityHeadBody, RepositoryDecisionBatchBody};
use fgit_codec::{CodecRefusal, CryptoBodyIdentity, body_id};
use fgit_types::{
    DecisionSequence, Digest, GitOid, HeadGeneration, PolicyEpoch, RepositoryAuthorityHeadId,
    RepositoryCapsuleId, RepositoryCommitId, RepositoryDecisionBatchId, RepositoryId,
    RepositorySequence,
};
use crate::aggregate::{AggregateId, AggregateVersion, PullRequestNumber};
use crate::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload, NativeMerge};

pub const DEFAULT_MAX_REPLAY_BATCHES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum PositionTarget {
    Decision(DecisionSequence),
    Commit(RepositoryCommitId),
    Sequence(RepositorySequence),
    Head(RepositoryAuthorityHeadId),
    Capsule(RepositoryCapsuleId),
    Latest,
}
impl fmt::Display for PositionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decision(seq) => write!(f, "decision:{seq}"),
            Self::Commit(id) => write!(f, "commit:{id}"),
            Self::Sequence(seq) => write!(f, "sequence:{seq}"),
            Self::Head(id) => write!(f, "head:{id}"),
            Self::Capsule(id) => write!(f, "capsule:{id}"),
            Self::Latest => f.write_str("latest"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PullRequestState {
    Open,
    /// Historical internal-digest event representation.
    Merged { merge_commit: Digest, target_tip_after: Digest },
    Closed { withdrawn: bool },
    /// A native merge carries its complete typed coordinates. The legacy
    /// snapshot tip fields are not rewritten with an invented digest encoding.
    MergedNative { merge: NativeMerge },
}
impl fmt::Display for PullRequestState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => f.write_str("open"),
            Self::Merged { merge_commit, .. } => write!(f, "merged (commit: {merge_commit})"),
            Self::MergedNative { merge } => write!(f, "merged (commit: {})", merge.merge_commit),
            Self::Closed { withdrawn: true } => f.write_str("closed (withdrawn)"),
            Self::Closed { withdrawn: false } => f.write_str("closed (rejected)"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestSnapshot {
    pub number: PullRequestNumber,
    pub source_ref: Vec<u8>,
    pub target_ref: Vec<u8>,
    /// Historical digest-valued source tip. Native merge coordinates are in
    /// `PullRequestState::MergedNative`, not converted into this legacy field.
    pub source_tip: Digest,
    /// Historical digest-valued target position; see `state` for native merges.
    pub target_tip: Digest,
    pub state: PullRequestState,
    pub version: AggregateVersion,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckReceiptSnapshot {
    pub name: String,
    pub status: String,
    pub commit: Digest,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeSnapshot {
    pub target_position: PositionTarget,
    pub repository_id: RepositoryId,
    pub effective_decision_sequence: Option<DecisionSequence>,
    pub effective_head_id: RepositoryAuthorityHeadId,
    pub effective_head_generation: HeadGeneration,
    pub effective_committed_rcr_id: Option<RepositoryCommitId>,
    pub ref_root: Digest,
    pub forge_position_root: Digest,
    pub historical_policy_epoch: PolicyEpoch,
    pub refs: BTreeMap<Vec<u8>, GitOid>,
    pub pull_requests: BTreeMap<PullRequestNumber, PullRequestSnapshot>,
    pub check_receipts: Vec<CheckReceiptSnapshot>,
    pub replayed_batches_count: usize,
    pub used_capsule_id: Option<RepositoryCapsuleId>,
}
impl ForgeSnapshot {
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Forge Snapshot at {}\n  Repository: {}\n  Head: {} (gen {})\n  Decision Sequence: {}\n  Policy Epoch: {}\n  Refs: {}\n  Pull Requests: {}\n  Replay Batches: {} (capsule: {})",
            self.target_position, self.repository_id, self.effective_head_id,
            self.effective_head_generation.get(),
            self.effective_decision_sequence.map_or("none".to_string(), |s| s.get().to_string()),
            self.historical_policy_epoch.get(), self.refs.len(), self.pull_requests.len(),
            self.replayed_batches_count,
            self.used_capsule_id.map_or("genesis".to_string(), |c| c.to_string()),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotDisclosurePolicy {
    PermitAll,
    Restricted {
        allowed_refs: Option<BTreeSet<Vec<u8>>>,
        revoked_refs: BTreeSet<Vec<u8>>,
        allowed_prs: Option<BTreeSet<PullRequestNumber>>,
        revoked_prs: BTreeSet<PullRequestNumber>,
        repository_access_revoked: bool,
    },
}
impl SnapshotDisclosurePolicy {
    #[must_use]
    pub const fn permit_all() -> Self { Self::PermitAll }
    #[must_use]
    pub const fn with_revoked_refs(revoked_refs: BTreeSet<Vec<u8>>) -> Self {
        Self::Restricted {
            allowed_refs: None, revoked_refs, allowed_prs: None,
            revoked_prs: BTreeSet::new(), repository_access_revoked: false,
        }
    }
    #[must_use]
    pub const fn revoked_actor() -> Self {
        Self::Restricted {
            allowed_refs: None, revoked_refs: BTreeSet::new(), allowed_prs: None,
            revoked_prs: BTreeSet::new(), repository_access_revoked: true,
        }
    }
    pub fn filter_snapshot(&self, mut snapshot: ForgeSnapshot) -> Result<ForgeSnapshot, SnapshotRefusal> {
        match self {
            Self::PermitAll => Ok(snapshot),
            Self::Restricted { allowed_refs, revoked_refs, allowed_prs, revoked_prs, repository_access_revoked } => {
                if *repository_access_revoked {
                    return Err(SnapshotRefusal::AccessDenied {
                        reason: "current repository access is revoked; historical state cannot be disclosed",
                    });
                }
                snapshot.refs.retain(|name, _| {
                    !revoked_refs.contains(name)
                        && allowed_refs.as_ref().is_none_or(|allowed| allowed.contains(name))
                });
                snapshot.pull_requests.retain(|num, pr| {
                    !revoked_prs.contains(num)
                        && !revoked_refs.contains(&pr.source_ref)
                        && !revoked_refs.contains(&pr.target_ref)
                        && allowed_prs.as_ref().is_none_or(|allowed| allowed.contains(num))
                });
                Ok(snapshot)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefChange {
    Created(GitOid),
    Modified { before: GitOid, after: GitOid },
    Deleted(GitOid),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PullRequestChange {
    Opened(PullRequestSnapshot),
    HeadAdvanced { before: Digest, after: Digest },
    Merged { merge_commit: Digest, target_tip_after: Digest },
    Closed { withdrawn: bool },
    MergedNative { merge: NativeMerge },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeSnapshotDiff {
    pub older_position: PositionTarget,
    pub newer_position: PositionTarget,
    pub ref_changes: BTreeMap<Vec<u8>, RefChange>,
    pub pr_changes: BTreeMap<PullRequestNumber, PullRequestChange>,
    pub policy_epoch_change: Option<(PolicyEpoch, PolicyEpoch)>,
    pub decision_sequence_delta: (Option<DecisionSequence>, Option<DecisionSequence>),
}
impl ForgeSnapshotDiff {
    #[must_use]
    pub fn diff(older: &ForgeSnapshot, newer: &ForgeSnapshot) -> Self {
        let mut ref_changes = BTreeMap::new();
        for (name, newer_oid) in &newer.refs {
            match older.refs.get(name) {
                None => { ref_changes.insert(name.clone(), RefChange::Created(*newer_oid)); }
                Some(older_oid) if older_oid != newer_oid => {
                    ref_changes.insert(name.clone(), RefChange::Modified { before: *older_oid, after: *newer_oid });
                }
                Some(_) => {}
            }
        }
        for (name, older_oid) in &older.refs {
            if !newer.refs.contains_key(name) {
                ref_changes.insert(name.clone(), RefChange::Deleted(*older_oid));
            }
        }
        let mut pr_changes = BTreeMap::new();
        for (num, newer_pr) in &newer.pull_requests {
            match older.pull_requests.get(num) {
                None => { pr_changes.insert(*num, PullRequestChange::Opened(newer_pr.clone())); }
                Some(older_pr) => {
                    if older_pr.state != newer_pr.state {
                        match &newer_pr.state {
                            PullRequestState::Merged { merge_commit, target_tip_after } => {
                                pr_changes.insert(*num, PullRequestChange::Merged {
                                    merge_commit: *merge_commit, target_tip_after: *target_tip_after,
                                });
                            }
                            PullRequestState::MergedNative { merge } => {
                                pr_changes.insert(*num, PullRequestChange::MergedNative { merge: merge.clone() });
                            }
                            PullRequestState::Closed { withdrawn } => {
                                pr_changes.insert(*num, PullRequestChange::Closed { withdrawn: *withdrawn });
                            }
                            PullRequestState::Open => {}
                        }
                    } else if older_pr.source_tip != newer_pr.source_tip {
                        pr_changes.insert(*num, PullRequestChange::HeadAdvanced {
                            before: older_pr.source_tip, after: newer_pr.source_tip,
                        });
                    }
                }
            }
        }
        let policy_epoch_change = (older.historical_policy_epoch != newer.historical_policy_epoch)
            .then_some((older.historical_policy_epoch, newer.historical_policy_epoch));
        Self {
            older_position: older.target_position, newer_position: newer.target_position,
            ref_changes, pr_changes, policy_epoch_change,
            decision_sequence_delta: (older.effective_decision_sequence, newer.effective_decision_sequence),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotLimits { pub max_replay_batches: usize }
impl Default for SnapshotLimits {
    fn default() -> Self { Self { max_replay_batches: DEFAULT_MAX_REPLAY_BATCHES } }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotRefusal {
    TargetNotFound { target: PositionTarget },
    TargetAheadOfAuthority { target: DecisionSequence, head_sequence: Option<DecisionSequence> },
    ReplayBoundExceeded { limit: usize, attempted: usize },
    AccessDenied { reason: &'static str },
    ConsistencyMismatch { detail: String },
    Authority(AuthorityFailure),
    Codec(CodecRefusal),
    Chronicle(ChronicleRefusal),
}
impl fmt::Display for SnapshotRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetNotFound { target } => write!(f, "target position {target} not found in repository history"),
            Self::TargetAheadOfAuthority { target, head_sequence } => write!(f,
                "target decision sequence {target} is ahead of authority head sequence {}",
                head_sequence.map_or("none".to_string(), |s| s.to_string())),
            Self::ReplayBoundExceeded { limit, attempted } => write!(f, "replay bound exceeded: attempted {attempted} > limit {limit}"),
            Self::AccessDenied { reason } => write!(f, "snapshot access denied under current policy: {reason}"),
            Self::ConsistencyMismatch { detail } => write!(f, "snapshot continuous consistency check failed: {detail}"),
            Self::Authority(failure) => write!(f, "authority store failure: {failure}"),
            Self::Codec(refusal) => write!(f, "codec refusal: {refusal}"),
            Self::Chronicle(refusal) => write!(f, "chronicle refusal: {refusal}"),
        }
    }
}
impl std::error::Error for SnapshotRefusal {}
impl From<AuthorityFailure> for SnapshotRefusal { fn from(value: AuthorityFailure) -> Self { Self::Authority(value) } }
impl From<CodecRefusal> for SnapshotRefusal { fn from(value: CodecRefusal) -> Self { Self::Codec(value) } }
impl From<ChronicleRefusal> for SnapshotRefusal { fn from(value: ChronicleRefusal) -> Self { Self::Chronicle(value) } }

/// Apply canonical events without confusing legacy digests with native OIDs.
/// As before, a merge-only history is not invented into an opened PR aggregate.
/// Its receipt remains available in the authenticated `HistoricalBatch` events.
pub fn apply_forge_event_to_prs(prs: &mut BTreeMap<PullRequestNumber, PullRequestSnapshot>, event: &ForgeEvent) {
    if let AggregateId::PullRequest(num) = event.aggregate {
        match &event.payload {
            ForgeEventPayload::PullRequestOpened { source_ref, target_ref, source_tip, target_tip } => {
                prs.insert(num, PullRequestSnapshot {
                    number: num, source_ref: source_ref.clone(), target_ref: target_ref.clone(),
                    source_tip: *source_tip, target_tip: *target_tip,
                    state: PullRequestState::Open, version: event.version,
                });
            }
            ForgeEventPayload::PullRequestHeadAdvanced { source_tip } => {
                if let Some(pr) = prs.get_mut(&num) { pr.source_tip = *source_tip; pr.version = event.version; }
            }
            ForgeEventPayload::MergeCommitted { merge_commit, target_tip_after, .. } => {
                if let Some(pr) = prs.get_mut(&num) {
                    pr.state = PullRequestState::Merged { merge_commit: *merge_commit, target_tip_after: *target_tip_after };
                    pr.target_tip = *target_tip_after;
                    pr.version = event.version;
                }
            }
            ForgeEventPayload::MergeCommittedNative(merge) => {
                if let Some(pr) = prs.get_mut(&num) {
                    pr.state = PullRequestState::MergedNative { merge: merge.clone() };
                    pr.version = event.version;
                }
            }
            ForgeEventPayload::PullRequestClosed { withdrawn } => {
                if let Some(pr) = prs.get_mut(&num) {
                    pr.state = PullRequestState::Closed { withdrawn: *withdrawn };
                    pr.version = event.version;
                }
            }
        }
    }
}
pub fn apply_forge_event_batch_to_prs(prs: &mut BTreeMap<PullRequestNumber, PullRequestSnapshot>, batch: &ForgeEventBatch) {
    for event in &batch.events { apply_forge_event_to_prs(prs, event); }
}

pub fn verify_continuous_consistency(
    snapshot: &ForgeSnapshot, live_head_id: RepositoryAuthorityHeadId,
    live_head: &RepositoryAuthorityHeadBody, live_refs: &BTreeMap<Vec<u8>, GitOid>,
    live_prs: &BTreeMap<PullRequestNumber, PullRequestSnapshot>,
) -> Result<(), SnapshotRefusal> {
    if snapshot.effective_head_id != live_head_id {
        return Err(SnapshotRefusal::ConsistencyMismatch { detail: format!(
            "head id mismatch: snapshot={}, live={}", snapshot.effective_head_id, live_head_id) });
    }
    if snapshot.effective_head_generation != live_head.generation {
        return Err(SnapshotRefusal::ConsistencyMismatch { detail: format!(
            "generation mismatch: snapshot={}, live={}", snapshot.effective_head_generation.get(), live_head.generation.get()) });
    }
    if snapshot.ref_root != live_head.ref_root {
        return Err(SnapshotRefusal::ConsistencyMismatch { detail: format!(
            "ref_root mismatch: snapshot={}, live={}", snapshot.ref_root, live_head.ref_root) });
    }
    if snapshot.forge_position_root != live_head.forge_position_root {
        return Err(SnapshotRefusal::ConsistencyMismatch { detail: format!(
            "forge_position_root mismatch: snapshot={}, live={}", snapshot.forge_position_root, live_head.forge_position_root) });
    }
    if snapshot.historical_policy_epoch != live_head.policy_epoch {
        return Err(SnapshotRefusal::ConsistencyMismatch { detail: format!(
            "policy_epoch mismatch: snapshot={}, live={}", snapshot.historical_policy_epoch.get(), live_head.policy_epoch.get()) });
    }
    if snapshot.refs != *live_refs {
        return Err(SnapshotRefusal::ConsistencyMismatch { detail: format!(
            "refs table mismatch: snapshot has {} refs ({:?}), live has {} refs ({:?})",
            snapshot.refs.len(), snapshot.refs, live_refs.len(), live_refs) });
    }
    if snapshot.pull_requests != *live_prs {
        return Err(SnapshotRefusal::ConsistencyMismatch { detail: format!(
            "pull requests mismatch: snapshot has {} prs ({:?}), live has {} prs ({:?})",
            snapshot.pull_requests.len(), snapshot.pull_requests, live_prs.len(), live_prs) });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MovementDirection { Forward, Backward, Identical }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateCapsule {
    pub capsule_id: RepositoryCapsuleId,
    pub capsule: RepositoryCapsuleBody,
    pub refs: BTreeMap<Vec<u8>, GitOid>,
    pub pull_requests: BTreeMap<PullRequestNumber, PullRequestSnapshot>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalBatch {
    pub batch_id: RepositoryDecisionBatchId,
    pub resulting_head_id: RepositoryAuthorityHeadId,
    pub resulting_head_generation: HeadGeneration,
    pub batch: RepositoryDecisionBatchBody,
    pub forge_events: Vec<ForgeEvent>,
    pub ref_updates: Vec<(Vec<u8>, Option<GitOid>)>,
}

/// Materialize an exact complete-batch position, seeking to the nearest supplied
/// checkpoint and enforcing the existing replay bound. Positions inside a batch
/// remain unsupported rather than approximated by its final state.
pub fn project_snapshot_from_history(
    target: PositionTarget, live_head_id: RepositoryAuthorityHeadId,
    live_head: &RepositoryAuthorityHeadBody, capsules: &[CandidateCapsule],
    batches: &[HistoricalBatch], genesis_refs: &BTreeMap<Vec<u8>, GitOid>,
    limits: &SnapshotLimits,
) -> Result<ForgeSnapshot, SnapshotRefusal> {
    let live_seq = live_head.latest_decision_sequence;
    let target_seq: Option<DecisionSequence> = match target {
        PositionTarget::Latest => live_seq,
        PositionTarget::Decision(seq) => {
            if live_seq.is_none_or(|head_seq| seq > head_seq) {
                return Err(SnapshotRefusal::TargetAheadOfAuthority { target: seq, head_sequence: live_seq });
            }
            Some(seq)
        }
        PositionTarget::Head(head_id) => {
            if head_id == live_head_id { live_seq } else {
                Some(batches.iter().find(|b| b.resulting_head_id == head_id)
                    .map(|b| b.batch.decisions.last().map(|d| d.decision_sequence).unwrap_or(b.batch.first_decision_sequence))
                    .ok_or(SnapshotRefusal::TargetNotFound { target })?)
            }
        }
        PositionTarget::Commit(commit_id) => {
            let mut found_seq = None;
            for b in batches {
                for rcr in &b.batch.committed_rcrs {
                    let rcr_id = body_id(&CryptoBodyIdentity, rcr).and_then(|identity| {
                        RepositoryCommitId::from_internal_object_id(identity).map_err(CodecRefusal::from)
                    })?;
                    if rcr_id == commit_id
                        && let Some(d) = b.batch.decisions.iter().find(|d| d.tx_id == rcr.tx_id)
                    {
                        found_seq = Some(d.decision_sequence);
                        break;
                    }
                }
                if found_seq.is_some() { break; }
            }
            Some(found_seq.ok_or(SnapshotRefusal::TargetNotFound { target })?)
        }
        PositionTarget::Sequence(req_seq) => {
            let mut found_seq = None;
            for b in batches {
                for record in &b.batch.committed_rcrs {
                    if record.repository_sequence == req_seq
                        && let Some(decision) = b.batch.decisions.iter().find(|d| d.tx_id == record.tx_id)
                    {
                        found_seq = Some(decision.decision_sequence);
                        break;
                    }
                }
                if found_seq.is_some() { break; }
            }
            Some(found_seq.ok_or(SnapshotRefusal::TargetNotFound { target })?)
        }
        PositionTarget::Capsule(capsule_id) => {
            capsules.iter().find(|c| c.capsule_id == capsule_id)
                .ok_or(SnapshotRefusal::TargetNotFound { target })?.capsule.latest_decision_sequence
        }
    };
    let Some(target_limit) = target_seq else {
        return Ok(ForgeSnapshot {
            target_position: target, repository_id: live_head.repository_id,
            effective_decision_sequence: None, effective_head_id: live_head_id,
            effective_head_generation: live_head.generation, effective_committed_rcr_id: None,
            ref_root: live_head.ref_root, forge_position_root: live_head.forge_position_root,
            historical_policy_epoch: live_head.policy_epoch, refs: genesis_refs.clone(),
            pull_requests: BTreeMap::new(), check_receipts: Vec::new(),
            replayed_batches_count: 0, used_capsule_id: None,
        });
    };
    let mut nearest_capsule: Option<&CandidateCapsule> = None;
    for cap in capsules {
        if let Some(cap_seq) = cap.capsule.latest_decision_sequence
            && cap_seq <= target_limit
        {
            match nearest_capsule {
                None => nearest_capsule = Some(cap),
                Some(current) => {
                    if cap_seq > current.capsule.latest_decision_sequence.unwrap() { nearest_capsule = Some(cap); }
                }
            }
        }
    }
    let (start_seq, mut current_head_id, mut current_head_generation, mut current_rcr_id,
        mut current_ref_root, mut current_forge_root, mut current_policy_epoch,
        mut accumulated_refs, mut accumulated_prs, used_capsule_id) = match nearest_capsule {
        Some(cap) => (
            cap.capsule.latest_decision_sequence, cap.capsule.head_id, cap.capsule.head_generation,
            cap.capsule.latest_committed_rcr_id, cap.capsule.ref_root, cap.capsule.forge_position_root,
            cap.capsule.policy_epoch, cap.refs.clone(), cap.pull_requests.clone(), Some(cap.capsule_id),
        ),
        None => (
            None, live_head_id, HeadGeneration::try_new(1).unwrap(), None,
            live_head.ref_root, live_head.forge_position_root, live_head.policy_epoch,
            genesis_refs.clone(), BTreeMap::new(), None,
        ),
    };
    let mut batches_to_replay = Vec::new();
    for batch in batches {
        let first_seq = batch.batch.first_decision_sequence;
        let last_seq = batch.batch.decisions.last().map(|d| d.decision_sequence).unwrap_or(first_seq);
        if let Some(start) = start_seq && last_seq <= start { continue; }
        if first_seq <= target_limit {
            if last_seq > target_limit { return Err(SnapshotRefusal::TargetNotFound { target }); }
            batches_to_replay.push(batch);
        }
    }
    batches_to_replay.sort_by_key(|b| b.batch.first_decision_sequence);
    if batches_to_replay.len() > limits.max_replay_batches {
        return Err(SnapshotRefusal::ReplayBoundExceeded {
            limit: limits.max_replay_batches, attempted: batches_to_replay.len(),
        });
    }
    let replayed_batches_count = batches_to_replay.len();
    let mut effective_decision_sequence = start_seq;
    for batch in &batches_to_replay {
        current_head_id = batch.resulting_head_id;
        current_head_generation = batch.resulting_head_generation;
        current_ref_root = batch.batch.resulting_ref_root;
        current_forge_root = batch.batch.resulting_forge_position_root;
        current_policy_epoch = batch.batch.resulting_policy_epoch;
        for (name, tip_opt) in &batch.ref_updates {
            match tip_opt {
                Some(tip) => { accumulated_refs.insert(name.clone(), *tip); }
                None => { accumulated_refs.remove(name); }
            }
        }
        for event in &batch.forge_events { apply_forge_event_to_prs(&mut accumulated_prs, event); }
        for decision in &batch.batch.decisions {
            if decision.decision_sequence <= target_limit {
                effective_decision_sequence = Some(decision.decision_sequence);
                if let fgit_types::vocabulary::DecisionOutcome::Committed { repository_commit_id } = decision.outcome {
                    current_rcr_id = Some(repository_commit_id);
                }
            }
        }
    }
    Ok(ForgeSnapshot {
        target_position: target, repository_id: live_head.repository_id,
        effective_decision_sequence, effective_head_id: current_head_id,
        effective_head_generation: current_head_generation, effective_committed_rcr_id: current_rcr_id,
        ref_root: current_ref_root, forge_position_root: current_forge_root,
        historical_policy_epoch: current_policy_epoch, refs: accumulated_refs,
        pull_requests: accumulated_prs, check_receipts: Vec::new(),
        replayed_batches_count, used_capsule_id,
    })
}
