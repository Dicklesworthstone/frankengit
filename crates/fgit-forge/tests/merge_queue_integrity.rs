//! Refusal tests for untrusted speculative plans and batch receipts.

use std::collections::BTreeMap;

use fgit_forge::aggregate::{AggregateVersion, PullRequestNumber, QueueNumber};
use fgit_forge::merge::MergedTree;
use fgit_forge::merge_queue::{
    BatchStatus, QueueBatchEntry, QueueBatchId, QueueBatchReceipt, SpeculativeBatchPlan,
    SpeculativeMergeStep, assemble_batch_landing_package,
};
use fgit_forge::{ForgeRefusal, MergeSide, WorkspaceEpoch};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    let width = match format {
        GitHashAlgorithm::Sha1 => 20,
        GitHashAlgorithm::Sha256 => 32,
    };
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(width)).unwrap()
}

fn entries(plan: &SpeculativeBatchPlan) -> Vec<QueueBatchEntry> {
    plan.steps
        .iter()
        .map(|step| QueueBatchEntry {
            pull_request: step.pull_request,
            source_ref: step.candidate_source_ref.clone(),
            head_tip: step.candidate_tip,
        })
        .collect()
}

fn rebind(plan: &mut SpeculativeBatchPlan) {
    plan.batch_id =
        QueueBatchId::compute(&plan.target_ref, plan.initial_target_tip, &entries(plan)).unwrap();
}

fn plan(format: GitHashAlgorithm) -> SpeculativeBatchPlan {
    let target = RefName::try_new(b"refs/heads/main").unwrap();
    let base = oid(format, 0x10);
    let candidates = [
        QueueBatchEntry {
            pull_request: PullRequestNumber::try_new(11).unwrap(),
            source_ref: RefName::try_new(b"refs/heads/first").unwrap(),
            head_tip: oid(format, 0x21),
        },
        QueueBatchEntry {
            pull_request: PullRequestNumber::try_new(12).unwrap(),
            source_ref: RefName::try_new(b"refs/heads/second").unwrap(),
            head_tip: oid(format, 0x22),
        },
    ];
    let batch_id = QueueBatchId::compute(&target, base, &candidates).unwrap();
    let mut projected = base;
    let steps = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let result = oid(format, 0x31 + u8::try_from(index).unwrap());
            let step = SpeculativeMergeStep {
                pull_request: candidate.pull_request,
                candidate_source_ref: candidate.source_ref.clone(),
                candidate_tip: candidate.head_tip,
                projected_base_tip: projected,
                merge_base_tip: oid(format, 0x01),
                resulting_speculative_tip: result,
                workspace_epoch: WorkspaceEpoch::from_u64(7),
                merged_tree: MergedTree {
                    entries: Vec::new(),
                },
            };
            projected = result;
            step
        })
        .collect();
    SpeculativeBatchPlan {
        batch_id,
        target_ref: target,
        initial_target_tip: base,
        final_target_tip: projected,
        steps,
    }
}

fn observations(plan: &SpeculativeBatchPlan) -> BTreeMap<PullRequestNumber, GitOid> {
    plan.steps
        .iter()
        .map(|step| (step.pull_request, step.candidate_tip))
        .collect()
}

fn assert_cannot_land(plan: &SpeculativeBatchPlan) {
    assert!(plan.validate().is_err());
    assert!(
        plan.check_freshness(
            plan.initial_target_tip,
            &observations(plan),
            WorkspaceEpoch::from_u64(7),
        )
        .is_err()
    );
    assert!(
        assemble_batch_landing_package(
            plan,
            QueueNumber::FIRST,
            AggregateVersion::try_new(5).unwrap(),
            plan.initial_target_tip,
            plan.steps
                .iter()
                .map(|step| step.resulting_speculative_tip)
                .collect(),
        )
        .is_err()
    );
}

#[test]
fn valid_multi_pr_chains_land_in_both_git_object_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let plan = plan(format);
        plan.validate().unwrap();
        plan.check_freshness(
            plan.initial_target_tip,
            &observations(&plan),
            WorkspaceEpoch::from_u64(7),
        )
        .unwrap();
        let package = assemble_batch_landing_package(
            &plan,
            QueueNumber::FIRST,
            AggregateVersion::try_new(5).unwrap(),
            plan.initial_target_tip,
            plan.steps
                .iter()
                .map(|step| step.resulting_speculative_tip)
                .collect(),
        )
        .unwrap();
        assert_eq!(package.target_ref_intent.new_tip, plan.final_target_tip);
        assert_eq!(package.queue_head_intent.new_tip, plan.final_target_tip);
        assert_eq!(package.event_batch.events.len(), 3);
    }
}

#[test]
fn absent_candidate_observations_never_mean_unchanged() {
    let plan = plan(GitHashAlgorithm::Sha256);
    let mut tips = observations(&plan);
    for step in &plan.steps {
        tips.remove(&step.pull_request);
        assert!(
            plan.check_freshness(plan.initial_target_tip, &tips, WorkspaceEpoch::from_u64(7))
                .is_err()
        );
        tips.insert(step.pull_request, step.candidate_tip);
    }
    tips.clear();
    assert!(
        plan.check_freshness(plan.initial_target_tip, &tips, WorkspaceEpoch::from_u64(7))
            .is_err()
    );
}

#[test]
fn moved_candidates_targets_and_epochs_are_still_refused() {
    let plan = plan(GitHashAlgorithm::Sha256);
    let mut tips = observations(&plan);
    tips.insert(
        plan.steps[0].pull_request,
        oid(GitHashAlgorithm::Sha256, 0x70),
    );
    assert!(matches!(
        plan.check_freshness(plan.initial_target_tip, &tips, WorkspaceEpoch::from_u64(7)),
        Err(ForgeRefusal::MergeStale {
            reference: MergeSide::Source,
            ..
        })
    ));
    let tips = observations(&plan);
    assert!(matches!(
        plan.check_freshness(
            oid(GitHashAlgorithm::Sha256, 0x71),
            &tips,
            WorkspaceEpoch::from_u64(7)
        ),
        Err(ForgeRefusal::MergeStale {
            reference: MergeSide::Target,
            ..
        })
    ));
    assert!(matches!(
        plan.check_freshness(plan.initial_target_tip, &tips, WorkspaceEpoch::from_u64(8)),
        Err(ForgeRefusal::WorkspaceMoved { .. })
    ));
}

#[test]
fn disconnected_first_and_intermediate_bases_cannot_land() {
    for index in 0..2 {
        let mut plan = plan(GitHashAlgorithm::Sha256);
        plan.steps[index].projected_base_tip = oid(GitHashAlgorithm::Sha256, 0x72);
        assert_cannot_land(&plan);
    }
}

#[test]
fn substituted_final_tip_cannot_land() {
    let mut plan = plan(GitHashAlgorithm::Sha256);
    plan.final_target_tip = oid(GitHashAlgorithm::Sha256, 0x73);
    assert_cannot_land(&plan);
}

#[test]
fn substituted_candidate_tip_or_ref_invalidates_batch_identity() {
    let mut changed_tip = plan(GitHashAlgorithm::Sha256);
    changed_tip.steps[0].candidate_tip = oid(GitHashAlgorithm::Sha256, 0x74);
    assert_cannot_land(&changed_tip);
    let mut changed_ref = plan(GitHashAlgorithm::Sha256);
    changed_ref.steps[0].candidate_source_ref =
        RefName::try_new(b"refs/heads/substituted").unwrap();
    assert_cannot_land(&changed_ref);
}

#[test]
fn duplicate_pull_requests_are_refused_even_with_recomputed_identity() {
    let mut plan = plan(GitHashAlgorithm::Sha256);
    plan.steps[1].pull_request = plan.steps[0].pull_request;
    rebind(&mut plan);
    assert_cannot_land(&plan);
}

#[test]
fn inconsistent_workspace_epochs_and_object_formats_cannot_land() {
    let mut changed_epoch = plan(GitHashAlgorithm::Sha256);
    changed_epoch.steps[1].workspace_epoch = WorkspaceEpoch::from_u64(8);
    assert_cannot_land(&changed_epoch);
    let mut changed_format = plan(GitHashAlgorithm::Sha256);
    changed_format.steps[1].merge_base_tip = oid(GitHashAlgorithm::Sha1, 0x01);
    assert_cannot_land(&changed_format);
}

#[test]
fn empty_and_over_budget_plans_are_refused_before_assembly() {
    let mut empty = plan(GitHashAlgorithm::Sha256);
    empty.steps.clear();
    assert_cannot_land(&empty);
    let mut large = plan(GitHashAlgorithm::Sha256);
    large.steps = vec![large.steps[0].clone(); fgit_forge::event::queue::MAX_QUEUE_ENTRIES + 1];
    assert_cannot_land(&large);
}

fn receipt(plan: &SpeculativeBatchPlan) -> QueueBatchReceipt {
    QueueBatchReceipt {
        batch_id: plan.batch_id,
        target_ref: plan.target_ref.clone(),
        base_tip: plan.initial_target_tip,
        resulting_tip: plan.final_target_tip,
        entries: entries(plan),
        status: BatchStatus::SpeculativePass,
        timestamp_epoch: 1234,
    }
}

#[test]
fn receipt_attestation_refuses_substituted_omitted_or_reordered_candidates() {
    let plan = plan(GitHashAlgorithm::Sha256);
    let original = receipt(&plan);
    let digest = original.receipt_digest().unwrap();
    assert_eq!(digest, original.receipt_digest().unwrap());
    original
        .check_validity(&plan.target_ref, plan.initial_target_tip)
        .unwrap();
    let mut changed = original.clone();
    changed.entries[0].head_tip = oid(GitHashAlgorithm::Sha256, 0x75);
    let mut omitted = original.clone();
    omitted.entries.pop();
    let mut reordered = original;
    reordered.entries.reverse();
    for invalid in [changed, omitted, reordered] {
        assert!(invalid.receipt_digest().is_err());
        assert!(
            invalid
                .check_validity(&plan.target_ref, plan.initial_target_tip)
                .is_err()
        );
    }
}
