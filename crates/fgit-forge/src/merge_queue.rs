//! Synthetic queue refs, deterministic batch identity, speculative merge,
//! single-decision landing, and queue state projections.
//!
//! # Invariants
//!
//! - **Synthetic Queue Refs**: The merge queue operates as a first-class ref
//!   namespace under `refs/queue/`. Queue refs never escape this namespace.
//! - **Deterministic Batch Identity**: Batch IDs are derived deterministically
//!   over canonical batch parameters and receipted with verifiable attestations.
//! - **Speculative State Binding**: Speculative merge results bind the exact
//!   candidate tip and projected-head tip, and are strictly invalidatable when
//!   either tip or workspace epoch moves.
//! - **Single-Decision Landing**: Landing a speculative batch produces one
//!   atomic decision carrying target ref movements and individual `NativeMerge`
//!   events, preserving per-PR atomicity within the batch.
//! - **Canonical Queue Events**: Queue mutations (enqueue, dequeue, reorder,
//!   batch formation, landing) are versioned canonical forge events evaluated
//!   under expected aggregate versions.

use core::fmt;
use std::collections::BTreeMap;

use fgit_codec::attest::BodyIdentity;
use fgit_codec::schema::RepositoryCommitRecord;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_treefs::WorkspaceEpoch;
use fgit_types::hash::DigestBytes;
use fgit_types::{Digest, GitOid, PrincipalId, RefName};

use crate::aggregate::{AggregateId, AggregateVersion, PullRequestNumber, QueueNumber};
pub use crate::event::queue::{DequeueReason, NativeQueueEvent, QueueAction};
use crate::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload, NativeMerge};
use crate::merge::{EffectRoots, MergedTree, RecordFrame, RefIntent, root_of};
use crate::{ForgeRefusal, MergeSide, StaleTips};

/// Synthetic queue reference namespace root.
pub const QUEUE_REF_PREFIX: &[u8] = b"refs/queue/";

/// The kind and coordinates of a synthetic queue reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueueRefKind {
    /// The projected head of the queue for a target branch.
    /// Format: `refs/queue/<target-tail>/head`
    ProjectedHead { target_ref: RefName },
    /// A speculative batch candidate reference.
    /// Format: `refs/queue/<target-tail>/batches/<batch-id>`
    Batch {
        target_ref: RefName,
        batch_id: QueueBatchId,
    },
    /// An individual queued entry's speculative tip reference.
    /// Format: `refs/queue/<target-tail>/entries/<pr>`
    Entry {
        target_ref: RefName,
        pull_request: PullRequestNumber,
    },
}

/// Helper for constructing and inspecting synthetic queue references.
pub struct QueueRef;

impl QueueRef {
    /// True when the given reference name is in the synthetic queue namespace.
    #[must_use]
    pub fn is_queue_ref(ref_name: &RefName) -> bool {
        ref_name.as_bytes().starts_with(QUEUE_REF_PREFIX)
    }

    fn sanitize_target_ref(target_ref: &RefName) -> &[u8] {
        let bytes = target_ref.as_bytes();
        if let Some(tail) = bytes.strip_prefix(b"refs/heads/") {
            tail
        } else if let Some(tail) = bytes.strip_prefix(b"refs/") {
            tail
        } else {
            bytes
        }
    }

    /// Constructs the projected head reference for a target branch.
    pub fn projected_head(target_ref: &RefName) -> Result<RefName, ForgeRefusal> {
        let tail = Self::sanitize_target_ref(target_ref);
        let mut buf = Vec::with_capacity(QUEUE_REF_PREFIX.len() + tail.len() + 6);
        buf.extend_from_slice(QUEUE_REF_PREFIX);
        buf.extend_from_slice(tail);
        buf.extend_from_slice(b"/head");
        RefName::try_new(&buf).map_err(|cause| ForgeRefusal::BodyUnrepresentable {
            cause: Box::new(CodecRefusal::from(cause)),
        })
    }

    /// Constructs the reference for a speculative batch.
    pub fn batch(target_ref: &RefName, batch_id: &QueueBatchId) -> Result<RefName, ForgeRefusal> {
        let tail = Self::sanitize_target_ref(target_ref);
        let hex = batch_id.to_hex();
        let mut buf = Vec::with_capacity(QUEUE_REF_PREFIX.len() + tail.len() + 9 + hex.len());
        buf.extend_from_slice(QUEUE_REF_PREFIX);
        buf.extend_from_slice(tail);
        buf.extend_from_slice(b"/batches/");
        buf.extend_from_slice(hex.as_bytes());
        RefName::try_new(&buf).map_err(|cause| ForgeRefusal::BodyUnrepresentable {
            cause: Box::new(CodecRefusal::from(cause)),
        })
    }

    /// Constructs the reference for an individual queued pull request entry.
    pub fn entry(target_ref: &RefName, pr: PullRequestNumber) -> Result<RefName, ForgeRefusal> {
        let tail = Self::sanitize_target_ref(target_ref);
        let pr_str = pr.to_string();
        let mut buf = Vec::with_capacity(QUEUE_REF_PREFIX.len() + tail.len() + 9 + pr_str.len());
        buf.extend_from_slice(QUEUE_REF_PREFIX);
        buf.extend_from_slice(tail);
        buf.extend_from_slice(b"/entries/");
        buf.extend_from_slice(pr_str.as_bytes());
        RefName::try_new(&buf).map_err(|cause| ForgeRefusal::BodyUnrepresentable {
            cause: Box::new(CodecRefusal::from(cause)),
        })
    }

    /// Parses a reference name into a structured [`QueueRefKind`], if it is a valid queue reference.
    #[must_use]
    pub fn parse(ref_name: &RefName) -> Option<QueueRefKind> {
        let bytes = ref_name.as_bytes();
        let rest = bytes.strip_prefix(QUEUE_REF_PREFIX)?;
        // Find suffix: /head, /batches/<id>, /entries/<pr>
        if let Some(target_tail) = rest.strip_suffix(b"/head") {
            let mut target_buf = Vec::from(b"refs/heads/");
            target_buf.extend_from_slice(target_tail);
            let target_ref = RefName::try_new(&target_buf).ok()?;
            return Some(QueueRefKind::ProjectedHead { target_ref });
        }
        if let Some(pos) = rest.windows(9).position(|w| w == b"/batches/") {
            let target_tail = &rest[..pos];
            let batch_hex = &rest[pos + 9..];
            let mut target_buf = Vec::from(b"refs/heads/");
            target_buf.extend_from_slice(target_tail);
            let target_ref = RefName::try_new(&target_buf).ok()?;
            let hex_str = std::str::from_utf8(batch_hex).ok()?;
            let batch_id = QueueBatchId::from_hex(hex_str).ok()?;
            return Some(QueueRefKind::Batch {
                target_ref,
                batch_id,
            });
        }
        if let Some(pos) = rest.windows(9).position(|w| w == b"/entries/") {
            let target_tail = &rest[..pos];
            let pr_bytes = &rest[pos + 9..];
            let mut target_buf = Vec::from(b"refs/heads/");
            target_buf.extend_from_slice(target_tail);
            let target_ref = RefName::try_new(&target_buf).ok()?;
            let pr_str = std::str::from_utf8(pr_bytes).ok()?;
            let pr_num = pr_str.parse::<u64>().ok()?;
            let pull_request = PullRequestNumber::try_new(pr_num)?;
            return Some(QueueRefKind::Entry {
                target_ref,
                pull_request,
            });
        }
        None
    }
}

/// One candidate entry in a merge queue batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueBatchEntry {
    pub pull_request: PullRequestNumber,
    pub source_ref: RefName,
    pub head_tip: GitOid,
}

impl QueueBatchEntry {
    pub fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(self.pull_request.get());
        out.write_bytes("source_ref", self.source_ref.as_bytes())?;
        out.write_git_oid(&self.head_tip);
        Ok(())
    }

    pub fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let pr_val = input.read_scalar::<u64>("pull_request")?;
        let pull_request = PullRequestNumber::try_new(pr_val).ok_or({
            CodecRefusal::ValueUnrepresentable {
                field: "pull_request",
                observed: pr_val,
                limit: 1,
            }
        })?;
        let source_ref =
            RefName::try_new(input.read_bytes("source_ref")?).map_err(CodecRefusal::from)?;
        let head_tip = input.read_git_oid()?;
        Ok(Self {
            pull_request,
            source_ref,
            head_tip,
        })
    }
}

fn sha256_digest_from_bytes(raw: [u8; 32]) -> Result<Digest, ForgeRefusal> {
    let bytes = DigestBytes::try_new(&raw).map_err(|cause| ForgeRefusal::BodyUnrepresentable {
        cause: Box::new(CodecRefusal::from(cause)),
    })?;
    Ok(Digest::new(
        fgit_crypto::InternalDigestAlgorithm::Sha256.id(),
        bytes,
    ))
}

/// Deterministic identity of a speculative merge queue batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueueBatchId(Digest);

impl QueueBatchId {
    #[must_use]
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        fgit_crypto::lowercase_hex(self.0.bytes().as_bytes())
    }

    pub fn from_hex(hex: &str) -> Result<Self, ForgeRefusal> {
        if hex.len() != 64 {
            return Err(ForgeRefusal::BodyUnrepresentable {
                cause: Box::new(CodecRefusal::ValueUnrepresentable {
                    field: "QueueBatchId.hex_len",
                    observed: hex.len() as u64,
                    limit: 64,
                }),
            });
        }
        let mut raw = [0u8; 32];
        for i in 0..32 {
            raw[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
                ForgeRefusal::BodyUnrepresentable {
                    cause: Box::new(CodecRefusal::ValueUnrepresentable {
                        field: "QueueBatchId.hex_byte",
                        observed: 0,
                        limit: 1,
                    }),
                }
            })?;
        }
        let digest = sha256_digest_from_bytes(raw)?;
        Ok(Self(digest))
    }

    /// Computes the deterministic batch identity from canonical batch parameters.
    pub fn compute(
        target_ref: &RefName,
        base_tip: GitOid,
        entries: &[QueueBatchEntry],
    ) -> Result<Self, ForgeRefusal> {
        let mut encoder = Encoder::new();
        encoder
            .write_bytes("domain", b"frankengit/merge-queue-batch/v1")
            .map_err(|c| ForgeRefusal::BodyUnrepresentable { cause: Box::new(c) })?;
        encoder
            .write_bytes("target_ref", target_ref.as_bytes())
            .map_err(|c| ForgeRefusal::BodyUnrepresentable { cause: Box::new(c) })?;
        encoder.write_git_oid(&base_tip);
        encoder
            .write_sequence("entries", entries, |out, entry| entry.write(out))
            .map_err(|c| ForgeRefusal::BodyUnrepresentable { cause: Box::new(c) })?;
        let bytes = encoder.into_bytes();
        let digest_bytes = fgit_crypto::sha256_digest(&bytes);
        let digest = sha256_digest_from_bytes(digest_bytes)?;
        Ok(Self(digest))
    }
}

impl fmt::Display for QueueBatchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Speculative status of an evaluated batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchStatus {
    SpeculativePass,
    SpeculativeConflict,
    SpeculativeCheckFailed,
    Landed,
    Aborted,
}

impl BatchStatus {
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::SpeculativePass => 1,
            Self::SpeculativeConflict => 2,
            Self::SpeculativeCheckFailed => 3,
            Self::Landed => 4,
            Self::Aborted => 5,
        }
    }
}

/// A receipt recording the evaluation and outcome of a speculative batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueBatchReceipt {
    pub batch_id: QueueBatchId,
    pub target_ref: RefName,
    pub base_tip: GitOid,
    pub resulting_tip: GitOid,
    pub entries: Vec<QueueBatchEntry>,
    pub status: BatchStatus,
    pub timestamp_epoch: u64,
}

impl QueueBatchReceipt {
    /// Computes the cryptographic digest attesting to this receipt.
    pub fn receipt_digest(&self) -> Result<Digest, ForgeRefusal> {
        let mut encoder = Encoder::new();
        encoder
            .write_bytes("domain", b"frankengit/merge-queue-receipt/v1")
            .map_err(|c| ForgeRefusal::BodyUnrepresentable { cause: Box::new(c) })?;
        encoder
            .write_digest(self.batch_id.digest())
            .map_err(|c| ForgeRefusal::BodyUnrepresentable { cause: Box::new(c) })?;
        encoder
            .write_bytes("target_ref", self.target_ref.as_bytes())
            .map_err(|c| ForgeRefusal::BodyUnrepresentable { cause: Box::new(c) })?;
        encoder.write_git_oid(&self.base_tip);
        encoder.write_git_oid(&self.resulting_tip);
        encoder.write_scalar(self.status.wire_value());
        encoder.write_scalar(self.timestamp_epoch);
        let bytes = encoder.into_bytes();
        let digest_bytes = fgit_crypto::sha256_digest(&bytes);
        sha256_digest_from_bytes(digest_bytes)
    }

    /// Verifies if this receipt is valid for the current observed target ref and base tip.
    pub fn check_validity(
        &self,
        observed_target_ref: &RefName,
        observed_base_tip: GitOid,
    ) -> Result<(), ForgeRefusal> {
        if &self.target_ref != observed_target_ref || self.base_tip != observed_base_tip {
            return Err(ForgeRefusal::MergeStale {
                reference: MergeSide::Target,
                tips: StaleTips {
                    computed_against: self.base_tip,
                    observed: observed_base_tip,
                },
            });
        }
        Ok(())
    }
}

/// One candidate merge step in a speculative batch sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpeculativeMergeStep {
    /// Candidate pull request being merged.
    pub pull_request: PullRequestNumber,
    /// Candidate source branch.
    pub candidate_source_ref: RefName,
    /// Candidate branch head tip.
    pub candidate_tip: GitOid,
    /// Base tip this step was speculatively merged onto (the prior step's tip or batch base tip).
    pub projected_base_tip: GitOid,
    /// Merge base used for three-way tree merge.
    pub merge_base_tip: GitOid,
    /// Speculative commit tip resulting from this step.
    pub resulting_speculative_tip: GitOid,
    /// Workspace epoch the speculative merge was executed in.
    pub workspace_epoch: WorkspaceEpoch,
    /// The clean merged tree.
    pub merged_tree: MergedTree,
}

impl SpeculativeMergeStep {
    /// Checks that the candidate and base tips have not moved, and workspace epoch is unchanged.
    pub fn check_validity(
        &self,
        observed_candidate_tip: GitOid,
        observed_base_tip: GitOid,
        observed_workspace_epoch: WorkspaceEpoch,
    ) -> Result<(), ForgeRefusal> {
        if observed_candidate_tip != self.candidate_tip {
            return Err(ForgeRefusal::MergeStale {
                reference: MergeSide::Source,
                tips: StaleTips {
                    computed_against: self.candidate_tip,
                    observed: observed_candidate_tip,
                },
            });
        }
        if observed_base_tip != self.projected_base_tip {
            return Err(ForgeRefusal::MergeStale {
                reference: MergeSide::Target,
                tips: StaleTips {
                    computed_against: self.projected_base_tip,
                    observed: observed_base_tip,
                },
            });
        }
        if observed_workspace_epoch != self.workspace_epoch {
            return Err(ForgeRefusal::WorkspaceMoved {
                computed_in: self.workspace_epoch,
                observed: observed_workspace_epoch,
            });
        }
        Ok(())
    }
}

/// A complete speculative plan for a queue batch, chaining speculative merge steps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpeculativeBatchPlan {
    pub batch_id: QueueBatchId,
    pub target_ref: RefName,
    pub initial_target_tip: GitOid,
    pub final_target_tip: GitOid,
    pub steps: Vec<SpeculativeMergeStep>,
}

impl SpeculativeBatchPlan {
    /// Checks that all candidate tips, the target branch tip, and workspace epoch remain fresh.
    pub fn check_freshness(
        &self,
        observed_target_tip: GitOid,
        candidate_tips: &BTreeMap<PullRequestNumber, GitOid>,
        observed_workspace_epoch: WorkspaceEpoch,
    ) -> Result<(), ForgeRefusal> {
        if observed_target_tip != self.initial_target_tip {
            return Err(ForgeRefusal::MergeStale {
                reference: MergeSide::Target,
                tips: StaleTips {
                    computed_against: self.initial_target_tip,
                    observed: observed_target_tip,
                },
            });
        }
        for step in &self.steps {
            let observed_candidate = candidate_tips
                .get(&step.pull_request)
                .copied()
                .unwrap_or(step.candidate_tip);
            if observed_candidate != step.candidate_tip {
                return Err(ForgeRefusal::MergeStale {
                    reference: MergeSide::Source,
                    tips: StaleTips {
                        computed_against: step.candidate_tip,
                        observed: observed_candidate,
                    },
                });
            }
            if observed_workspace_epoch != step.workspace_epoch {
                return Err(ForgeRefusal::WorkspaceMoved {
                    computed_in: step.workspace_epoch,
                    observed: observed_workspace_epoch,
                });
            }
        }
        Ok(())
    }
}

/// The atomic landing package for a batch, reducing all ref and event effects to one decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchLandingPackage {
    /// Conditional target branch movement.
    pub target_ref_intent: RefIntent,
    /// Conditional synthetic queue head ref movement.
    pub queue_head_intent: RefIntent,
    /// Objects created by all merges in the batch.
    pub objects: Vec<GitOid>,
    /// All canonical events published by this landing (per-PR `NativeMerge` + queue `BatchLanded`).
    pub event_batch: ForgeEventBatch,
}

impl BatchLandingPackage {
    /// Derives the canonical effect roots for this batch landing.
    pub fn roots<I>(&self, identity: &I) -> Result<EffectRoots, ForgeRefusal>
    where
        I: BodyIdentity + ?Sized,
    {
        Ok(EffectRoots {
            ref_intent_root: root_of(identity, &self.target_ref_intent, "RefIntent")?,
            forge_event_batch_root: root_of(identity, &self.event_batch, "ForgeEventBatch")?,
        })
    }

    /// Reduces the batch landing effect to ONE commit record carrying both roots.
    pub fn seal_into_record<I>(
        &self,
        identity: &I,
        frame: RecordFrame,
    ) -> Result<RepositoryCommitRecord, ForgeRefusal>
    where
        I: BodyIdentity + ?Sized,
    {
        let roots = self.roots(identity)?;
        Ok(RepositoryCommitRecord {
            repository_id: frame.repository_id,
            repository_sequence: frame.repository_sequence,
            parent_rcr_id: frame.parent_rcr_id,
            tx_id: frame.tx_id,
            principal_snapshot_id: frame.principal_snapshot_id,
            canonical_request_digest: frame.canonical_request_digest,
            ref_delta_root: frame.ref_delta_root,
            resulting_ref_root: frame.resulting_ref_root,
            object_closure_root: frame.object_closure_root,
            forge_event_batch_root: roots.forge_event_batch_root,
            resulting_forge_position_root: frame.resulting_forge_position_root,
            policy_epoch: frame.policy_epoch,
            policy_decision_root: frame.policy_decision_root,
            invariant_evidence_root: frame.invariant_evidence_root,
            outbox_effect_root: frame.outbox_effect_root,
            retention_delta_root: frame.retention_delta_root,
        })
    }
}

/// Assembles a single-decision landing package for a speculative batch plan.
///
/// Each PR in the batch receives its own distinct [`NativeMerge`] event with its
/// individual source tip, base tip, and merge commit. The merge queue aggregate
/// receives a [`NativeQueueEvent`] with `QueueAction::BatchLanded`. All events
/// are combined into one [`ForgeEventBatch`], and target and queue head movements
/// are assembled into one atomic package.
pub fn assemble_batch_landing_package(
    plan: &SpeculativeBatchPlan,
    queue_number: QueueNumber,
    queue_version: AggregateVersion,
    existing_queue_head_tip: GitOid,
    created_objects: Vec<GitOid>,
) -> Result<BatchLandingPackage, ForgeRefusal> {
    if plan.steps.is_empty() {
        return Err(ForgeRefusal::BodyUnrepresentable {
            cause: Box::new(CodecRefusal::ValueUnrepresentable {
                field: "speculative_plan.steps",
                observed: 0,
                limit: 1,
            }),
        });
    }

    let target_ref_intent = RefIntent {
        name: plan.target_ref.as_bytes().to_vec(),
        expected_tip: plan.initial_target_tip,
        new_tip: plan.final_target_tip,
    };

    let queue_head_ref = QueueRef::projected_head(&plan.target_ref)?;
    let queue_head_intent = RefIntent {
        name: queue_head_ref.as_bytes().to_vec(),
        expected_tip: existing_queue_head_tip,
        new_tip: plan.final_target_tip,
    };

    let mut events = Vec::with_capacity(plan.steps.len() + 1);

    // 1. Individual NativeMerge event for each candidate PR in the batch
    for step in &plan.steps {
        let native_merge = NativeMerge {
            source_ref: step.candidate_source_ref.clone(),
            source_tip: step.candidate_tip,
            base_tip: step.merge_base_tip,
            target_ref: plan.target_ref.clone(),
            target_tip_before: step.projected_base_tip,
            merge_commit: step.resulting_speculative_tip,
        };
        native_merge
            .validate()
            .map_err(|c| ForgeRefusal::BodyUnrepresentable { cause: Box::new(c) })?;

        events.push(ForgeEvent {
            aggregate: AggregateId::PullRequest(step.pull_request),
            version: AggregateVersion::FIRST, // Each PR's terminal merge event
            payload: ForgeEventPayload::MergeCommittedNative(native_merge),
        });
    }

    // 2. Canonical event for the merge queue aggregate
    let landed_entries: Vec<PullRequestNumber> =
        plan.steps.iter().map(|s| s.pull_request).collect();
    let queue_event = NativeQueueEvent {
        queue_number,
        target_ref: plan.target_ref.clone(),
        action: QueueAction::BatchLanded {
            batch_id: *plan.batch_id.digest(),
            entries: landed_entries,
            target_tip: plan.final_target_tip,
        },
    };
    queue_event
        .validate()
        .map_err(|c| ForgeRefusal::BodyUnrepresentable { cause: Box::new(c) })?;

    events.push(ForgeEvent {
        aggregate: AggregateId::MergeQueue(queue_number),
        version: queue_version,
        payload: ForgeEventPayload::MergeQueueChangedNative(queue_event),
    });

    Ok(BatchLandingPackage {
        target_ref_intent,
        queue_head_intent,
        objects: created_objects,
        event_batch: ForgeEventBatch { events },
    })
}

/// One active entry in a merge queue snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueEntry {
    pub pull_request: PullRequestNumber,
    pub source_ref: RefName,
    pub head_tip: GitOid,
    pub enqueued_by: PrincipalId,
    pub priority: u32,
    pub enqueued_version: AggregateVersion,
}

/// The projected state of one repository merge queue aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeQueueSnapshot {
    pub queue_number: QueueNumber,
    pub target_ref: RefName,
    pub version: AggregateVersion,
    pub entries: Vec<QueueEntry>,
    pub active_batch: Option<QueueBatchId>,
}

impl MergeQueueSnapshot {
    /// Creates an empty queue snapshot at version 1.
    #[must_use]
    pub const fn new(queue_number: QueueNumber, target_ref: RefName) -> Self {
        Self {
            queue_number,
            target_ref,
            version: AggregateVersion::FIRST,
            entries: Vec::new(),
            active_batch: None,
        }
    }

    /// True when the queue has no active entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of active entries in the queue.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the projected head ref for this queue.
    pub fn projected_head_ref(&self) -> Result<RefName, ForgeRefusal> {
        QueueRef::projected_head(&self.target_ref)
    }

    /// Finds a candidate entry by pull request number.
    #[must_use]
    pub fn find_entry(&self, pr: PullRequestNumber) -> Option<&QueueEntry> {
        self.entries.iter().find(|e| e.pull_request == pr)
    }

    /// Returns pull request numbers sorted in deterministic execution order.
    ///
    /// Tie-breaking rules:
    /// 1. Higher priority first
    /// 2. Earlier enqueued aggregate version first (FIFO)
    /// 3. Lower pull request number first (total order)
    #[must_use]
    pub fn deterministic_order(&self) -> Vec<PullRequestNumber> {
        let mut sorted = self.entries.clone();
        sorted.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.enqueued_version.cmp(&b.enqueued_version))
                .then_with(|| a.pull_request.cmp(&b.pull_request))
        });
        sorted.into_iter().map(|e| e.pull_request).collect()
    }

    /// Applies a canonical queue event, verifying version progression.
    pub fn apply_event(&mut self, event: &ForgeEvent) -> Result<(), ForgeRefusal> {
        if event.aggregate != AggregateId::MergeQueue(self.queue_number) {
            return Err(ForgeRefusal::BodyUnrepresentable {
                cause: Box::new(CodecRefusal::ValueUnrepresentable {
                    field: "queue.aggregate",
                    observed: 0,
                    limit: 1,
                }),
            });
        }
        let ForgeEventPayload::MergeQueueChangedNative(change) = &event.payload else {
            return Err(ForgeRefusal::BodyUnrepresentable {
                cause: Box::new(CodecRefusal::VariantUnknown {
                    field: "queue.payload",
                    observed: event.payload.kind(),
                    offset: 0,
                }),
            });
        };

        match &change.action {
            QueueAction::Enqueue {
                pull_request,
                source_ref,
                head_tip,
                enqueued_by,
                priority,
            } => {
                // If entry already exists, update head_tip and priority
                if let Some(pos) = self
                    .entries
                    .iter()
                    .position(|e| e.pull_request == *pull_request)
                {
                    self.entries[pos].head_tip = *head_tip;
                    self.entries[pos].priority = *priority;
                } else {
                    self.entries.push(QueueEntry {
                        pull_request: *pull_request,
                        source_ref: source_ref.clone(),
                        head_tip: *head_tip,
                        enqueued_by: *enqueued_by,
                        priority: *priority,
                        enqueued_version: event.version,
                    });
                }
            }
            QueueAction::Dequeue { pull_request, .. } => {
                self.entries.retain(|e| e.pull_request != *pull_request);
            }
            QueueAction::Reorder { order, .. } => {
                let mut reordered = Vec::with_capacity(self.entries.len());
                for pr in order {
                    if let Some(pos) = self.entries.iter().position(|e| e.pull_request == *pr) {
                        reordered.push(self.entries[pos].clone());
                    }
                }
                // Retain remaining entries not in explicit order
                for entry in &self.entries {
                    if !order.contains(&entry.pull_request) {
                        reordered.push(entry.clone());
                    }
                }
                self.entries = reordered;
            }
            QueueAction::BatchFormed { batch_id, .. } => {
                self.active_batch = Some(QueueBatchId::from_digest(*batch_id));
            }
            QueueAction::BatchLanded { entries, .. } => {
                self.entries.retain(|e| !entries.contains(&e.pull_request));
                self.active_batch = None;
            }
            QueueAction::BatchRejected { .. } => {
                self.active_batch = None;
            }
        }

        self.version = event.version;
        Ok(())
    }
}
