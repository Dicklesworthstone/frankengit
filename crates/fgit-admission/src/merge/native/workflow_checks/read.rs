//! Bounded observations for one exact PR source. Canonical frontiers select
//! immutable event bodies; local execution journals and mutable indexes do not.

use std::collections::BTreeMap;

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_codec::{DecodeLimits, ForgePositionStateEntry, decode_body};
use fgit_forge::aggregate::{AggregateId, AggregateVersion, PullRequestNumber};
use fgit_forge::event::workflow_check::{
    MAX_CHECK_EVIDENCE_BYTES, MAX_CHECK_JOB_BYTES, NativeWorkflowCheck, WorkflowCheckConclusion,
    WorkflowCheckId,
};
use fgit_forge::{ForgeEventBatch, ForgeEventPayload};
use fgit_types::{GitOid, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId};

use super::super::{delivery, storage, unavailable};
use crate::AdmissionError;

const MAX_PAGE: u16 = 100;
const MAX_SCAN_EVENTS: usize = 65_536;
const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;

/// A bounded summary of the publisher's statement. Evidence stays in the
/// canonical event; its exact SHA-256 and length permit integrity comparison
/// without returning megabytes of execution content on a PR listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowCheckSummary {
    pub id: WorkflowCheckId,
    pub publisher: PrincipalId,
    pub run_id: [u8; 32],
    pub attempt_id: [u8; 32],
    pub graph_root: [u8; 32],
    pub job: String,
    pub conclusion: WorkflowCheckConclusion,
    pub evidence_sha256: [u8; 32],
    pub evidence_bytes: u64,
}

/// Display observations, never an aggregate success or merge authorization.
/// Every returned check names precisely this PR's source ref and recorded tip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestChecksPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub number: PullRequestNumber,
    pub pull_request_version: AggregateVersion,
    pub source_ref: RefName,
    pub target_ref: RefName,
    pub source_tip: GitOid,
    pub target_tip: GitOid,
    /// Whether the source ref at this SAME selected head still names the PR's
    /// recorded source tip. A stale or deleted source yields an empty page.
    pub source_current: bool,
    pub checks: Vec<WorkflowCheckSummary>,
    pub next_after: Option<WorkflowCheckId>,
}

impl PullRequestChecksPage {
    /// Validate the response window before a transport discloses it. This is
    /// structural validation; a page never certifies execution or merge policy.
    pub fn validate_window(
        &self,
        number: PullRequestNumber,
        after: Option<WorkflowCheckId>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<(), RefusalCode> {
        if limit == 0 || limit > MAX_PAGE || self.checks.len() > usize::from(limit) {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        if (after.is_some() && expected_head.is_none())
            || self.number != number
            || expected_head.is_some_and(|head| head != self.source_head)
            || self.source_ref == self.target_ref
            || !self.source_ref.as_bytes().starts_with(b"refs/heads/")
            || !self.target_ref.as_bytes().starts_with(b"refs/heads/")
            || self.source_tip.is_zero()
            || self.target_tip.is_zero()
            || self.source_tip.algorithm() != self.target_tip.algorithm()
            || (!self.source_current && (!self.checks.is_empty() || self.next_after.is_some()))
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let mut previous = after;
        for check in &self.checks {
            if previous.is_some_and(|id| check.id <= id)
                || check.job.is_empty()
                || check.job.len() > MAX_CHECK_JOB_BYTES
                || check.job.chars().any(char::is_control)
                || check.evidence_bytes == 0
                || check.evidence_bytes > MAX_CHECK_EVIDENCE_BYTES as u64
            {
                return Err(RefusalCode::EvidenceInvalid);
            }
            previous = Some(check.id);
        }
        if self.next_after.is_some()
            && (self.checks.len() != usize::from(limit) || self.next_after != previous)
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }
}

/// Read a current or retained PR's observations. `basis` and `refs` must come
/// from the SAME authenticated head, and `visible` must apply CURRENT caller
/// and canonical hidden-ref policy to both PR branches before disclosure.
///
/// The selected PR/check event ranges are verified through the shared canonical
/// validator. Unlike delivery processing this read does not replay the outbox:
/// the authenticated forge frontier already commits to each selected event.
/// At most 65,536 event bodies / 128 MiB of frames are examined, with one bounded
/// frame in memory at a time. Page memory is at most 100 short job summaries.
pub async fn read_pull_request_page_at<S, V, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    number: PullRequestNumber,
    refs: &BTreeMap<RefName, GitOid>,
    after: Option<WorkflowCheckId>,
    limit: u16,
    visible: &V,
    cancelled: &C,
) -> Result<Option<PullRequestChecksPage>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    V: Fn(&RefName, &RefName) -> bool + Sync,
    C: Fn() -> bool + Sync,
{
    if limit == 0 || limit > MAX_PAGE {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    checkpoint(cancelled)?;
    let positions = storage::load_forge_positions(store, cx, basis).await?;
    checkpoint(cancelled)?;
    let aggregate = AggregateId::PullRequest(number);
    let Some(frontier) = positions.entry(storage::aggregate_label(aggregate)?) else {
        return Ok(None);
    };
    let mut scan = ScanBudget::default();
    let batch = read_batch(store, cx, basis, frontier, &mut scan, cancelled).await?;
    let event = batch
        .events
        .into_iter()
        .rev()
        .find(|event| event.aggregate == aggregate)
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    let (source_ref, target_ref, source_tip, target_tip) = match event.payload {
        ForgeEventPayload::PullRequestChangedNative(change) => (
            change.data.source_ref,
            change.data.target_ref,
            change.data.source_tip,
            change.data.target_tip,
        ),
        ForgeEventPayload::MergeCommittedNative(merge) => (
            merge.source_ref,
            merge.target_ref,
            merge.source_tip,
            merge.target_tip_before,
        ),
        // Legacy digest-only PRs have no native source coordinate to select.
        _ => return Ok(None),
    };
    if !visible(&source_ref, &target_ref) {
        return Ok(None);
    }
    let source_current = refs.get(&source_ref) == Some(&source_tip);
    let mut page = PullRequestChecksPage {
        source_head: basis.id(),
        number,
        pull_request_version: event.version,
        source_ref,
        target_ref,
        source_tip,
        target_tip,
        source_current,
        checks: Vec::new(),
        next_after: None,
    };
    if source_current {
        // Stream labels are canonical encodings of the full 256-bit identity.
        // Sorting the typed IDs makes the cursor contract independent of label
        // representation, forge insertion order, run names and event timing.
        let mut candidates = BTreeMap::new();
        for entry in positions.entries() {
            checkpoint(cancelled)?;
            let label = entry.stream();
            if !label.as_str().starts_with("check/") {
                continue;
            }
            let id = WorkflowCheckId::from_label(label.as_str())
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            if after.is_none_or(|cursor| id > cursor) {
                candidates.insert(id, entry);
            }
        }
        for (id, entry) in candidates {
            checkpoint(cancelled)?;
            if entry.successor_position() != 1 {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            let batch = read_batch(store, cx, basis, entry, &mut scan, cancelled).await?;
            let change = observation(batch, id)?;
            if change.record.source_ref != page.source_ref
                || change.record.source_commit != page.source_tip
            {
                continue;
            }
            if page.checks.len() == usize::from(limit) {
                page.next_after = page.checks.last().map(|check| check.id);
                break;
            }
            let record = change.record;
            let evidence_sha256 = fgit_crypto::sha256_digest(&record.evidence);
            checkpoint(cancelled)?;
            page.checks.push(WorkflowCheckSummary {
                id,
                publisher: change.actor,
                run_id: record.run_id,
                attempt_id: record.attempt_id,
                graph_root: record.graph_root,
                job: record.job,
                conclusion: record.conclusion,
                evidence_sha256,
                evidence_bytes: record.evidence.len() as u64,
            });
        }
    }
    checkpoint(cancelled)?;
    page.validate_window(number, after, limit, Some(basis.id()))
        .map_err(unavailable)?;
    Ok(Some(page))
}

fn observation(
    batch: ForgeEventBatch,
    id: WorkflowCheckId,
) -> Result<NativeWorkflowCheck, AdmissionError> {
    let mut events = batch
        .events
        .into_iter()
        .filter(|event| event.aggregate == AggregateId::WorkflowCheck(id));
    let event = events
        .next()
        .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    if events.next().is_some() || event.version != AggregateVersion::FIRST {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let ForgeEventPayload::WorkflowCheckObservedNative(change) = event.payload else {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    };
    if change.id() != id {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(change)
}

#[derive(Default)]
struct ScanBudget {
    bytes: usize,
    events: usize,
}
impl ScanBudget {
    fn charge(&mut self, bytes: usize, events: usize) -> Result<(), AdmissionError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|count| *count <= MAX_SCAN_BYTES)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        self.events = self
            .events
            .checked_add(events)
            .filter(|count| *count <= MAX_SCAN_EVENTS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        Ok(())
    }
}

async fn read_batch<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    position: &ForgePositionStateEntry,
    scan: &mut ScanBudget,
    cancelled: &C,
) -> Result<ForgeEventBatch, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let frame = storage::read_frame(
        store,
        cx,
        basis.body().repository_id,
        storage::EVENT_NAMESPACE,
        position.event_batch_root(),
    )
    .await?
    .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    checkpoint(cancelled)?;
    scan.charge(frame.len(), 0)?;
    let batch: ForgeEventBatch = decode_body(
        &frame,
        DecodeLimits {
            elements: MAX_SCAN_EVENTS as u64,
            ..DecodeLimits::DEFAULT
        },
    )
    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    scan.charge(0, batch.events.len())?;
    if storage::root(&batch)? != position.event_batch_root() {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    delivery::validate_position_batch(position, &batch)?;
    checkpoint(cancelled)?;
    Ok(batch)
}

fn checkpoint<C: Fn() -> bool + Sync>(cancelled: &C) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
