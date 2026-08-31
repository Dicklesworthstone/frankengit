//! Position-addressed snapshot projection engine and forge state materialization.
//!
//! Because canonical state is an immutable decision stream, "the entire forge at
//! decision N" is a well-defined object, not table archaeology.
//!
//! # Invariants
//!
//! 1. **Position Addressability:** Snapshots bind an exact target position
//!    (decision sequence, commit ID, head ID, capsule ID, or latest).
//! 2. **Bounded Replay via Checkpoint Seeking:** Replay cost is bounded by
//!    seeking to the nearest available capsule/checkpoint at or before the target
//!    position, avoiding full stream replay from genesis when checkpoints exist.
//! 3. **Current-Policy Authorization Filter:** Authorization evaluates against
//!    the CURRENT policy for disclosure, while historical policy is displayed as
//!    immutable data. Time travel never resurrects access that has since been
//!    revoked.
//! 4. **Continuous Consistency:** Projecting a snapshot at the latest position
//!    matches the live projection state.

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
use crate::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};

/// Largest number of batches a snapshot projection walk will evaluate before refusing.
pub const DEFAULT_MAX_REPLAY_BATCHES: usize = 65_536;

/// Target position identifying where in repository history to project forge state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum PositionTarget {
    /// Exact decision sequence in the immutable decision log.
    Decision(DecisionSequence),
    /// Exact committed repository commit record.
    Commit(RepositoryCommitId),
    /// Exact committed transition sequence.
    Sequence(RepositorySequence),
    /// Exact authority head identity.
    Head(RepositoryAuthorityHeadId),
    /// Exact capsule checkpoint identity.
    Capsule(RepositoryCapsuleId),
    /// The latest published authority head position.
    Latest,
}

impl fmt::Display for PositionTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decision(seq) => write!(formatter, "decision:{seq}"),
            Self::Commit(id) => write!(formatter, "commit:{id}"),
            Self::Sequence(seq) => write!(formatter, "sequence:{seq}"),
            Self::Head(id) => write!(formatter, "head:{id}"),
            Self::Capsule(id) => write!(formatter, "capsule:{id}"),
            Self::Latest => formatter.write_str("latest"),
        }
    }
}

/// Lifecycle state of a pull request aggregate within a snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PullRequestState {
    /// The pull request is open and can receive head advances or merge.
    Open,
    /// The pull request was merged into its target branch.
    Merged {
        /// The merge commit identity.
        merge_commit: Digest,
        /// The new target branch tip after the merge.
        target_tip_after: Digest,
    },
    /// The pull request was closed without merge.
    Closed {
        /// True if explicitly withdrawn by author, false if rejected.
        withdrawn: bool,
    },
}

impl fmt::Display for PullRequestState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => formatter.write_str("open"),
            Self::Merged { merge_commit, .. } => {
                write!(formatter, "merged (commit: {merge_commit})")
            }
            Self::Closed { withdrawn: true } => formatter.write_str("closed (withdrawn)"),
            Self::Closed { withdrawn: false } => formatter.write_str("closed (rejected)"),
        }
    }
}

/// Materialized snapshot of a single pull request aggregate as of a position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestSnapshot {
    /// Number identifying this pull request.
    pub number: PullRequestNumber,
    /// Source reference name (e.g. `refs/heads/feature`).
    pub source_ref: Vec<u8>,
    /// Target reference name (e.g. `refs/heads/main`).
    pub target_ref: Vec<u8>,
    /// Source branch tip commit.
    pub source_tip: Digest,
    /// Target branch tip commit as recorded at opening.
    pub target_tip: Digest,
    /// Current state within this snapshot.
    pub state: PullRequestState,
    /// Current aggregate stream version.
    pub version: AggregateVersion,
}

/// Materialized snapshot of one check receipt associated with a position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckReceiptSnapshot {
    /// Name or descriptor of the check suite.
    pub name: String,
    /// Status description.
    pub status: String,
    /// Target commit the check evaluated.
    pub commit: Digest,
}

/// A complete read-only forge snapshot materialized as of an exact position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeSnapshot {
    /// The requested position target.
    pub target_position: PositionTarget,
    /// Repository identity.
    pub repository_id: RepositoryId,
    /// Effective decision sequence at this snapshot (absent before first decision).
    pub effective_decision_sequence: Option<DecisionSequence>,
    /// Effective authority head identity.
    pub effective_head_id: RepositoryAuthorityHeadId,
    /// Generation of the effective authority head.
    pub effective_head_generation: HeadGeneration,
    /// Latest committed RCR identity (absent before first commit).
    pub effective_committed_rcr_id: Option<RepositoryCommitId>,
    /// Root over the canonical ref state as of this position.
    pub ref_root: Digest,
    /// Root over the forge position as of this position.
    pub forge_position_root: Digest,
    /// Historical policy epoch in force at this position (displayed as data).
    pub historical_policy_epoch: PolicyEpoch,
    /// Materialized reference table as of this position.
    pub refs: BTreeMap<Vec<u8>, GitOid>,
    /// Materialized pull request aggregates as of this position.
    pub pull_requests: BTreeMap<PullRequestNumber, PullRequestSnapshot>,
    /// Materialized check receipts as of this position.
    pub check_receipts: Vec<CheckReceiptSnapshot>,
    /// Number of decision batches replayed from the nearest checkpoint/genesis.
    pub replayed_batches_count: usize,
    /// Nearest capsule identity used as the replay starting point, if any.
    pub used_capsule_id: Option<RepositoryCapsuleId>,
}

impl ForgeSnapshot {
    /// Formats a readable summary of the snapshot.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Forge Snapshot at {}\n  Repository: {}\n  Head: {} (gen {})\n  Decision Sequence: {}\n  Policy Epoch: {}\n  Refs: {}\n  Pull Requests: {}\n  Replay Batches: {} (capsule: {})",
            self.target_position,
            self.repository_id,
            self.effective_head_id,
            self.effective_head_generation.get(),
            self.effective_decision_sequence
                .map_or("none".to_string(), |s| s.get().to_string()),
            self.historical_policy_epoch.get(),
            self.refs.len(),
            self.pull_requests.len(),
            self.replayed_batches_count,
            self.used_capsule_id
                .map_or("genesis".to_string(), |c| c.to_string()),
        )
    }
}

/// Disclosure policy enforcing current authorization against historical snapshots.
///
/// Current policy governs disclosure; historical policy is displayed as data.
/// Revoked access is never resurrected by time travel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotDisclosurePolicy {
    /// Full disclosure allowed (e.g. administrator or unrestricted internal read).
    PermitAll,
    /// Filtered disclosure restricting specific refs and pull requests.
    Restricted {
        /// If specified, only refs matching one of these paths are disclosed.
        allowed_refs: Option<BTreeSet<Vec<u8>>>,
        /// Specific refs that have been revoked and must be hidden.
        revoked_refs: BTreeSet<Vec<u8>>,
        /// If specified, only PRs matching one of these numbers are disclosed.
        allowed_prs: Option<BTreeSet<PullRequestNumber>>,
        /// Specific PR numbers whose access has been revoked.
        revoked_prs: BTreeSet<PullRequestNumber>,
        /// Whether access to the repository itself is currently active.
        repository_access_revoked: bool,
    },
}

impl SnapshotDisclosurePolicy {
    /// Builds an unrestricted disclosure policy.
    #[must_use]
    pub const fn permit_all() -> Self {
        Self::PermitAll
    }

    /// Builds a restricted disclosure policy for an actor with revoked refs.
    #[must_use]
    pub const fn with_revoked_refs(revoked_refs: BTreeSet<Vec<u8>>) -> Self {
        Self::Restricted {
            allowed_refs: None,
            revoked_refs,
            allowed_prs: None,
            revoked_prs: BTreeSet::new(),
            repository_access_revoked: false,
        }
    }

    /// Builds a policy where the actor's repository access was completely revoked.
    #[must_use]
    pub const fn revoked_actor() -> Self {
        Self::Restricted {
            allowed_refs: None,
            revoked_refs: BTreeSet::new(),
            allowed_prs: None,
            revoked_prs: BTreeSet::new(),
            repository_access_revoked: true,
        }
    }

    /// Filters a snapshot according to this current authorization policy.
    ///
    /// # Errors
    ///
    /// [`SnapshotRefusal::AccessDenied`] when current policy forbids access to the repository.
    pub fn filter_snapshot(
        &self,
        mut snapshot: ForgeSnapshot,
    ) -> Result<ForgeSnapshot, SnapshotRefusal> {
        match self {
            Self::PermitAll => Ok(snapshot),
            Self::Restricted {
                allowed_refs,
                revoked_refs,
                allowed_prs,
                revoked_prs,
                repository_access_revoked,
            } => {
                if *repository_access_revoked {
                    return Err(SnapshotRefusal::AccessDenied {
                        reason: "current repository access is revoked; historical state cannot be disclosed",
                    });
                }

                // Filter refs
                snapshot.refs.retain(|name, _| {
                    if revoked_refs.contains(name) {
                        return false;
                    }
                    if let Some(allowed) = allowed_refs
                        && !allowed.contains(name)
                    {
                        return false;
                    }
                    true
                });

                // Filter PRs
                snapshot.pull_requests.retain(|num, pr| {
                    if revoked_prs.contains(num) {
                        return false;
                    }
                    if revoked_refs.contains(&pr.source_ref)
                        || revoked_refs.contains(&pr.target_ref)
                    {
                        return false;
                    }
                    if let Some(allowed) = allowed_prs
                        && !allowed.contains(num)
                    {
                        return false;
                    }
                    true
                });

                Ok(snapshot)
            }
        }
    }
}

/// Ref difference between two snapshot positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefChange {
    /// Ref was created.
    Created(GitOid),
    /// Ref was modified from one tip to another.
    Modified {
        /// Tip before.
        before: GitOid,
        /// Tip after.
        after: GitOid,
    },
    /// Ref was deleted.
    Deleted(GitOid),
}

/// Pull request difference between two snapshot positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PullRequestChange {
    /// PR was opened.
    Opened(PullRequestSnapshot),
    /// PR head branch advanced.
    HeadAdvanced {
        /// Source tip before.
        before: Digest,
        /// Source tip after.
        after: Digest,
    },
    /// PR was merged.
    Merged {
        /// Merge commit identity.
        merge_commit: Digest,
        /// Target tip after.
        target_tip_after: Digest,
    },
    /// PR was closed without merge.
    Closed {
        /// Withdrawn flag.
        withdrawn: bool,
    },
}

/// Difference between two snapshot positions (`older` -> `newer`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeSnapshotDiff {
    /// Older position.
    pub older_position: PositionTarget,
    /// Newer position.
    pub newer_position: PositionTarget,
    /// Changes to refs.
    pub ref_changes: BTreeMap<Vec<u8>, RefChange>,
    /// Changes to pull requests.
    pub pr_changes: BTreeMap<PullRequestNumber, PullRequestChange>,
    /// Policy epoch transition, if changed.
    pub policy_epoch_change: Option<(PolicyEpoch, PolicyEpoch)>,
    /// Decision sequence transition.
    pub decision_sequence_delta: (Option<DecisionSequence>, Option<DecisionSequence>),
}

impl ForgeSnapshotDiff {
    /// Computes the difference between two materialized snapshots.
    #[must_use]
    pub fn diff(older: &ForgeSnapshot, newer: &ForgeSnapshot) -> Self {
        let mut ref_changes = BTreeMap::new();

        for (name, newer_oid) in &newer.refs {
            match older.refs.get(name) {
                None => {
                    ref_changes.insert(name.clone(), RefChange::Created(*newer_oid));
                }
                Some(older_oid) if older_oid != newer_oid => {
                    ref_changes.insert(
                        name.clone(),
                        RefChange::Modified {
                            before: *older_oid,
                            after: *newer_oid,
                        },
                    );
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
                None => {
                    pr_changes.insert(*num, PullRequestChange::Opened(newer_pr.clone()));
                }
                Some(older_pr) => {
                    if older_pr.state != newer_pr.state {
                        match &newer_pr.state {
                            PullRequestState::Merged {
                                merge_commit,
                                target_tip_after,
                            } => {
                                pr_changes.insert(
                                    *num,
                                    PullRequestChange::Merged {
                                        merge_commit: *merge_commit,
                                        target_tip_after: *target_tip_after,
                                    },
                                );
                            }
                            PullRequestState::Closed { withdrawn } => {
                                pr_changes.insert(
                                    *num,
                                    PullRequestChange::Closed {
                                        withdrawn: *withdrawn,
                                    },
                                );
                            }
                            PullRequestState::Open => {}
                        }
                    } else if older_pr.source_tip != newer_pr.source_tip {
                        pr_changes.insert(
                            *num,
                            PullRequestChange::HeadAdvanced {
                                before: older_pr.source_tip,
                                after: newer_pr.source_tip,
                            },
                        );
                    }
                }
            }
        }

        let policy_epoch_change = if older.historical_policy_epoch == newer.historical_policy_epoch
        {
            None
        } else {
            Some((older.historical_policy_epoch, newer.historical_policy_epoch))
        };

        Self {
            older_position: older.target_position,
            newer_position: newer.target_position,
            ref_changes,
            pr_changes,
            policy_epoch_change,
            decision_sequence_delta: (
                older.effective_decision_sequence,
                newer.effective_decision_sequence,
            ),
        }
    }
}

/// Execution limits for snapshot projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotLimits {
    /// Maximum number of decision batches to replay.
    pub max_replay_batches: usize,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            max_replay_batches: DEFAULT_MAX_REPLAY_BATCHES,
        }
    }
}

/// Every way snapshot projection can decline to materialize state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotRefusal {
    /// Target position was not found in the decision chain.
    TargetNotFound {
        /// Target requested.
        target: PositionTarget,
    },
    /// Target decision sequence is ahead of the authority head's sequence.
    TargetAheadOfAuthority {
        /// Requested sequence.
        target: DecisionSequence,
        /// Current authority head sequence.
        head_sequence: Option<DecisionSequence>,
    },
    /// Replay exceeded the maximum allowed batch bound.
    ReplayBoundExceeded {
        /// Configured limit.
        limit: usize,
        /// Batches traversed.
        attempted: usize,
    },
    /// Current policy denies disclosure.
    AccessDenied {
        /// Reason for refusal.
        reason: &'static str,
    },
    /// Continuous consistency check failed between snapshot and live state.
    ConsistencyMismatch {
        /// Mismatch details.
        detail: String,
    },
    /// Authority store read error.
    Authority(AuthorityFailure),
    /// Codec decoding error.
    Codec(CodecRefusal),
    /// Chronicle error.
    Chronicle(ChronicleRefusal),
}

impl fmt::Display for SnapshotRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetNotFound { target } => {
                write!(
                    formatter,
                    "target position {target} not found in repository history"
                )
            }
            Self::TargetAheadOfAuthority {
                target,
                head_sequence,
            } => {
                write!(
                    formatter,
                    "target decision sequence {target} is ahead of authority head sequence {}",
                    head_sequence.map_or("none".to_string(), |s| s.to_string())
                )
            }
            Self::ReplayBoundExceeded { limit, attempted } => {
                write!(
                    formatter,
                    "replay bound exceeded: attempted {attempted} > limit {limit}"
                )
            }
            Self::AccessDenied { reason } => {
                write!(
                    formatter,
                    "snapshot access denied under current policy: {reason}"
                )
            }
            Self::ConsistencyMismatch { detail } => {
                write!(
                    formatter,
                    "snapshot continuous consistency check failed: {detail}"
                )
            }
            Self::Authority(failure) => write!(formatter, "authority store failure: {failure}"),
            Self::Codec(refusal) => write!(formatter, "codec refusal: {refusal}"),
            Self::Chronicle(refusal) => write!(formatter, "chronicle refusal: {refusal}"),
        }
    }
}

impl std::error::Error for SnapshotRefusal {}

impl From<AuthorityFailure> for SnapshotRefusal {
    fn from(failure: AuthorityFailure) -> Self {
        Self::Authority(failure)
    }
}

impl From<CodecRefusal> for SnapshotRefusal {
    fn from(refusal: CodecRefusal) -> Self {
        Self::Codec(refusal)
    }
}

impl From<ChronicleRefusal> for SnapshotRefusal {
    fn from(refusal: ChronicleRefusal) -> Self {
        Self::Chronicle(refusal)
    }
}

/// Applies a single forge event to an in-memory pull request snapshot table.
pub fn apply_forge_event_to_prs(
    prs: &mut BTreeMap<PullRequestNumber, PullRequestSnapshot>,
    event: &ForgeEvent,
) {
    if let AggregateId::PullRequest(num) = event.aggregate {
        match &event.payload {
            ForgeEventPayload::PullRequestOpened {
                source_ref,
                target_ref,
                source_tip,
                target_tip,
            } => {
                prs.insert(
                    num,
                    PullRequestSnapshot {
                        number: num,
                        source_ref: source_ref.clone(),
                        target_ref: target_ref.clone(),
                        source_tip: *source_tip,
                        target_tip: *target_tip,
                        state: PullRequestState::Open,
                        version: event.version,
                    },
                );
            }
            ForgeEventPayload::PullRequestHeadAdvanced { source_tip } => {
                if let Some(pr) = prs.get_mut(&num) {
                    pr.source_tip = *source_tip;
                    pr.version = event.version;
                }
            }
            ForgeEventPayload::MergeCommitted {
                merge_commit,
                target_tip_after,
                ..
            } => {
                if let Some(pr) = prs.get_mut(&num) {
                    pr.state = PullRequestState::Merged {
                        merge_commit: *merge_commit,
                        target_tip_after: *target_tip_after,
                    };
                    pr.target_tip = *target_tip_after;
                    pr.version = event.version;
                }
            }
            ForgeEventPayload::PullRequestClosed { withdrawn } => {
                if let Some(pr) = prs.get_mut(&num) {
                    pr.state = PullRequestState::Closed {
                        withdrawn: *withdrawn,
                    };
                    pr.version = event.version;
                }
            }
        }
    }
}

/// Applies a forge event batch's events to the pull request table.
pub fn apply_forge_event_batch_to_prs(
    prs: &mut BTreeMap<PullRequestNumber, PullRequestSnapshot>,
    batch: &ForgeEventBatch,
) {
    for event in &batch.events {
        apply_forge_event_to_prs(prs, event);
    }
}

/// Verifies that a materialized snapshot equals live projection state.
///
/// Continuous consistency check (acceptance gate).
///
/// # Errors
///
/// [`SnapshotRefusal::ConsistencyMismatch`] when any field does not match.
pub fn verify_continuous_consistency(
    snapshot: &ForgeSnapshot,
    live_head_id: RepositoryAuthorityHeadId,
    live_head: &RepositoryAuthorityHeadBody,
    live_refs: &BTreeMap<Vec<u8>, GitOid>,
    live_prs: &BTreeMap<PullRequestNumber, PullRequestSnapshot>,
) -> Result<(), SnapshotRefusal> {
    if snapshot.effective_head_id != live_head_id {
        return Err(SnapshotRefusal::ConsistencyMismatch {
            detail: format!(
                "head id mismatch: snapshot={}, live={}",
                snapshot.effective_head_id, live_head_id
            ),
        });
    }

    if snapshot.effective_head_generation != live_head.generation {
        return Err(SnapshotRefusal::ConsistencyMismatch {
            detail: format!(
                "generation mismatch: snapshot={}, live={}",
                snapshot.effective_head_generation.get(),
                live_head.generation.get()
            ),
        });
    }

    if snapshot.ref_root != live_head.ref_root {
        return Err(SnapshotRefusal::ConsistencyMismatch {
            detail: format!(
                "ref_root mismatch: snapshot={}, live={}",
                snapshot.ref_root, live_head.ref_root
            ),
        });
    }

    if snapshot.forge_position_root != live_head.forge_position_root {
        return Err(SnapshotRefusal::ConsistencyMismatch {
            detail: format!(
                "forge_position_root mismatch: snapshot={}, live={}",
                snapshot.forge_position_root, live_head.forge_position_root
            ),
        });
    }

    if snapshot.historical_policy_epoch != live_head.policy_epoch {
        return Err(SnapshotRefusal::ConsistencyMismatch {
            detail: format!(
                "policy_epoch mismatch: snapshot={}, live={}",
                snapshot.historical_policy_epoch.get(),
                live_head.policy_epoch.get()
            ),
        });
    }

    if snapshot.refs != *live_refs {
        return Err(SnapshotRefusal::ConsistencyMismatch {
            detail: format!(
                "refs table mismatch: snapshot has {} refs ({:?}), live has {} refs ({:?})",
                snapshot.refs.len(),
                snapshot.refs,
                live_refs.len(),
                live_refs
            ),
        });
    }

    if snapshot.pull_requests != *live_prs {
        return Err(SnapshotRefusal::ConsistencyMismatch {
            detail: format!(
                "pull requests mismatch: snapshot has {} prs ({:?}), live has {} prs ({:?})",
                snapshot.pull_requests.len(),
                snapshot.pull_requests,
                live_prs.len(),
                live_prs
            ),
        });
    }

    Ok(())
}

/// Direction of movement between two snapshot positions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MovementDirection {
    /// Moving forward in time (newer decision sequence).
    Forward,
    /// Moving backward in time (older decision sequence).
    Backward,
    /// Same position.
    Identical,
}

/// A verified candidate capsule available as a potential replay starting point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateCapsule {
    /// The capsule identity.
    pub capsule_id: RepositoryCapsuleId,
    /// The authenticated capsule body.
    pub capsule: RepositoryCapsuleBody,
    /// Reference state recorded at this capsule.
    pub refs: BTreeMap<Vec<u8>, GitOid>,
    /// Pull requests recorded at this capsule.
    pub pull_requests: BTreeMap<PullRequestNumber, PullRequestSnapshot>,
}

/// One historical decision batch with its associated forge events and ref updates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalBatch {
    /// Decision batch identity.
    pub batch_id: RepositoryDecisionBatchId,
    /// Resulting head identity after this batch.
    pub resulting_head_id: RepositoryAuthorityHeadId,
    /// Resulting head generation after this batch.
    pub resulting_head_generation: HeadGeneration,
    /// The canonical decision batch body.
    pub batch: RepositoryDecisionBatchBody,
    /// Optional forge events admitted in this batch.
    pub forge_events: Vec<ForgeEvent>,
    /// Ref updates made in this batch (mapping ref name to new tip, or None for deletion).
    pub ref_updates: Vec<(Vec<u8>, Option<GitOid>)>,
}

/// Materializes a position-addressed forge snapshot from historical batches and capsules.
///
/// Bounded replay via checkpoint seeking:
/// 1. Determines the exact target decision sequence from `target`.
/// 2. Finds the nearest candidate capsule with `capsule.latest_decision_sequence <= target_seq`.
/// 3. If found, starts accumulator from capsule state and replays only batches after the capsule.
/// 4. If no capsule is found, replays batches from genesis.
/// 5. Validates that the number of replayed batches is bounded by `limits.max_replay_batches`.
///
/// # Errors
///
/// [`SnapshotRefusal::TargetAheadOfAuthority`] if target sequence is beyond live head.
/// [`SnapshotRefusal::TargetNotFound`] if target commit/head/sequence is not found.
/// [`SnapshotRefusal::ReplayBoundExceeded`] if replayed batches exceed limit.
pub fn project_snapshot_from_history(
    target: PositionTarget,
    live_head_id: RepositoryAuthorityHeadId,
    live_head: &RepositoryAuthorityHeadBody,
    capsules: &[CandidateCapsule],
    batches: &[HistoricalBatch],
    genesis_refs: &BTreeMap<Vec<u8>, GitOid>,
    limits: &SnapshotLimits,
) -> Result<ForgeSnapshot, SnapshotRefusal> {
    // 1. Resolve target to an effective decision sequence bound
    let live_seq = live_head.latest_decision_sequence;

    let target_seq: Option<DecisionSequence> = match target {
        PositionTarget::Latest => live_seq,
        PositionTarget::Decision(seq) => {
            if let Some(head_seq) = live_seq {
                if seq > head_seq {
                    return Err(SnapshotRefusal::TargetAheadOfAuthority {
                        target: seq,
                        head_sequence: Some(head_seq),
                    });
                }
            } else {
                return Err(SnapshotRefusal::TargetAheadOfAuthority {
                    target: seq,
                    head_sequence: None,
                });
            }
            Some(seq)
        }
        PositionTarget::Head(head_id) => {
            if head_id == live_head_id {
                live_seq
            } else {
                // Find batch producing this head
                batches
                    .iter()
                    .find(|b| b.resulting_head_id == head_id)
                    .map(|b| {
                        b.batch
                            .decisions
                            .last()
                            .map(|d| d.decision_sequence)
                            .unwrap_or(b.batch.first_decision_sequence)
                    })
                    .ok_or(SnapshotRefusal::TargetNotFound { target })?
                    .into()
            }
        }
        PositionTarget::Commit(commit_id) => {
            let mut found_seq = None;
            for b in batches {
                for rcr in &b.batch.committed_rcrs {
                    let rcr_id = body_id(&CryptoBodyIdentity, rcr).and_then(|identity| {
                        RepositoryCommitId::from_internal_object_id(identity)
                            .map_err(CodecRefusal::from)
                    })?;
                    if rcr_id == commit_id {
                        if let Some(d) = b.batch.decisions.iter().find(|d| d.tx_id == rcr.tx_id) {
                            found_seq = Some(d.decision_sequence);
                            break;
                        }
                    }
                }
                if found_seq.is_some() {
                    break;
                }
            }
            if let Some(seq) = found_seq {
                Some(seq)
            } else {
                return Err(SnapshotRefusal::TargetNotFound { target });
            }
        }
        PositionTarget::Sequence(req_seq) => {
            let mut found_seq = None;
            for b in batches {
                for record in &b.batch.committed_rcrs {
                    if record.repository_sequence == req_seq
                        && let Some(decision) = b
                            .batch
                            .decisions
                            .iter()
                            .find(|decision| decision.tx_id == record.tx_id)
                    {
                        found_seq = Some(decision.decision_sequence);
                        break;
                    }
                }
                if found_seq.is_some() {
                    break;
                }
            }
            if let Some(seq) = found_seq {
                Some(seq)
            } else {
                return Err(SnapshotRefusal::TargetNotFound { target });
            }
        }
        PositionTarget::Capsule(capsule_id) => {
            let cap = capsules
                .iter()
                .find(|c| c.capsule_id == capsule_id)
                .ok_or(SnapshotRefusal::TargetNotFound { target })?;
            cap.capsule.latest_decision_sequence
        }
    };

    // If target is before any decisions (genesis)
    let Some(target_limit) = target_seq else {
        return Ok(ForgeSnapshot {
            target_position: target,
            repository_id: live_head.repository_id,
            effective_decision_sequence: None,
            effective_head_id: live_head_id,
            effective_head_generation: live_head.generation,
            effective_committed_rcr_id: None,
            ref_root: live_head.ref_root,
            forge_position_root: live_head.forge_position_root,
            historical_policy_epoch: live_head.policy_epoch,
            refs: genesis_refs.clone(),
            pull_requests: BTreeMap::new(),
            check_receipts: Vec::new(),
            replayed_batches_count: 0,
            used_capsule_id: None,
        });
    };

    // 2. Checkpoint seeking: find closest capsule at or before target_limit
    let mut nearest_capsule: Option<&CandidateCapsule> = None;
    for cap in capsules {
        if let Some(cap_seq) = cap.capsule.latest_decision_sequence
            && cap_seq <= target_limit
        {
            match nearest_capsule {
                None => nearest_capsule = Some(cap),
                Some(current) => {
                    if cap_seq > current.capsule.latest_decision_sequence.unwrap() {
                        nearest_capsule = Some(cap);
                    }
                }
            }
        }
    }

    // 3. Initialize state from capsule or genesis
    let (
        start_seq,
        mut current_head_id,
        mut current_head_generation,
        mut current_rcr_id,
        mut current_ref_root,
        mut current_forge_root,
        mut current_policy_epoch,
        mut accumulated_refs,
        mut accumulated_prs,
        used_capsule_id,
    ) = match nearest_capsule {
        Some(cap) => (
            cap.capsule.latest_decision_sequence,
            cap.capsule.head_id,
            cap.capsule.head_generation,
            cap.capsule.latest_committed_rcr_id,
            cap.capsule.ref_root,
            cap.capsule.forge_position_root,
            cap.capsule.policy_epoch,
            cap.refs.clone(),
            cap.pull_requests.clone(),
            Some(cap.capsule_id),
        ),
        None => (
            None,
            live_head_id,
            HeadGeneration::try_new(1).unwrap(),
            None,
            live_head.ref_root,
            live_head.forge_position_root,
            live_head.policy_epoch,
            genesis_refs.clone(),
            BTreeMap::new(),
            None,
        ),
    };

    // 4. Filter batches to replay (strictly after start_seq and up to target_limit)
    let mut batches_to_replay = Vec::new();
    for batch in batches {
        let first_seq = batch.batch.first_decision_sequence;
        let last_seq = batch
            .batch
            .decisions
            .last()
            .map(|d| d.decision_sequence)
            .unwrap_or(first_seq);

        if let Some(start) = start_seq
            && last_seq <= start
        {
            continue;
        }

        if first_seq <= target_limit {
            if last_seq > target_limit {
                return Err(SnapshotRefusal::TargetNotFound { target });
            }
            batches_to_replay.push(batch);
        }
    }

    // Sort batches by first_decision_sequence
    batches_to_replay.sort_by_key(|b| b.batch.first_decision_sequence);

    // 5. Check replay bound
    if batches_to_replay.len() > limits.max_replay_batches {
        return Err(SnapshotRefusal::ReplayBoundExceeded {
            limit: limits.max_replay_batches,
            attempted: batches_to_replay.len(),
        });
    }

    let replayed_batches_count = batches_to_replay.len();
    let mut effective_decision_sequence = start_seq;

    // 6. Fold replayed batches
    for batch in &batches_to_replay {
        current_head_id = batch.resulting_head_id;
        current_head_generation = batch.resulting_head_generation;
        current_ref_root = batch.batch.resulting_ref_root;
        current_forge_root = batch.batch.resulting_forge_position_root;
        current_policy_epoch = batch.batch.resulting_policy_epoch;

        // Apply ref updates from this batch
        for (name, tip_opt) in &batch.ref_updates {
            match tip_opt {
                Some(tip) => {
                    accumulated_refs.insert(name.clone(), *tip);
                }
                None => {
                    accumulated_refs.remove(name);
                }
            }
        }

        // Apply forge events
        for event in &batch.forge_events {
            apply_forge_event_to_prs(&mut accumulated_prs, event);
        }

        // Evaluate decisions up to target_limit
        for decision in &batch.batch.decisions {
            if decision.decision_sequence <= target_limit {
                effective_decision_sequence = Some(decision.decision_sequence);
                if let fgit_types::vocabulary::DecisionOutcome::Committed {
                    repository_commit_id,
                } = decision.outcome
                {
                    current_rcr_id = Some(repository_commit_id);
                }
            }
        }
    }

    Ok(ForgeSnapshot {
        target_position: target,
        repository_id: live_head.repository_id,
        effective_decision_sequence,
        effective_head_id: current_head_id,
        effective_head_generation: current_head_generation,
        effective_committed_rcr_id: current_rcr_id,
        ref_root: current_ref_root,
        forge_position_root: current_forge_root,
        historical_policy_epoch: current_policy_epoch,
        refs: accumulated_refs,
        pull_requests: accumulated_prs,
        check_receipts: Vec::new(),
        replayed_batches_count,
        used_capsule_id,
    })
}
