//! Queue-only policy must distinguish an identical ordinary merge from a
//! validated canonical queue landing, including after policy changes/reopen.

use super::*;
use fgit_admission::merge::native::{NativeMergeIntent, objects::MergeObjectLimits};

pub(super) fn queue_only(name: RefName) -> ProtectedBranch {
    ProtectedBranch {
        name,
        reviewers: Vec::new(),
        required_approvals: 0,
        required_checks: Vec::new(),
        require_merge_queue: true,
    }
}

fn ordinary_fast_forward(
    node: &OneNode,
    offered: &QueueLandingCommand,
    key: &str,
) -> TerminalOutcome {
    let intent = NativeMergeIntent::fast_forward_only(
        offered.pull_request,
        offered.expected_pull_request_version,
        offered.source_ref.clone(),
        offered.head_tip,
        offered.target_ref.clone(),
        offered.expected_target_tip,
    )
    .unwrap();
    node.runtime()
        .block_on(node.admit_native_merge_durable_in(
            &node.request_context(),
            &session(key),
            &intent,
            AdmissionLimits::default(),
            MergeObjectLimits::default(),
        ))
        .unwrap()
}

fn assert_queue_required(result: &TerminalOutcome) {
    assert!(
        matches!(
            result.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ),
        "{result:?}"
    );
}

#[test]
fn queue_only_policy_refuses_ordinary_publication_and_lands_only_the_current_head() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
        accepted(apply(&node, &enqueue(1, 1, &pulls[1], 0), "second"));
        let mut offered = landing(&pulls[0], 2);
        let rule = queue_only(offered.target_ref.clone());
        offered.expected_policy_epoch = protect(&node, vec![rule.clone()], "queue-required");
        let before = snapshot(&node);
        let ordinary = ordinary_fast_forward(&node, &offered, "ordinary-bypass");
        assert_queue_required(&ordinary);
        unchanged_publication(&before, &snapshot(&node));
        let direct = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &session("direct-bypass"),
                &[RefCommand {
                    name: offered.target_ref.clone(),
                    expected_old: ExpectedOld::Exactly(offered.expected_target_tip),
                    proposed_new: ProposedNew::Update(offered.head_tip),
                    force: false,
                }],
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert_eq!(direct.commands.len(), 1);
        assert_queue_required(&direct.commands[0].terminal);
        unchanged_publication(&before, &snapshot(&node));
        let mut skipped = landing(&pulls[1], 2);
        skipped.expected_policy_epoch = offered.expected_policy_epoch;
        denied(
            &node,
            &skipped,
            "skip-required-queue-head",
            RefusalCode::ProtectedRefTransitionDenied,
        );

        // An administrator can remove the rule, but cannot rewrite an earlier
        // refusal. Reinstalling it changes the epoch and invalidates old offers.
        protect(&node, Vec::new(), "temporarily-clear-queue-rule");
        assert_eq!(
            ordinary_fast_forward(&node, &offered, "ordinary-bypass"),
            ordinary
        );
        let epoch = protect(&node, vec![rule], "restore-queue-rule");
        denied(
            &node,
            &offered,
            "stale-queue-policy",
            RefusalCode::EvidenceStale,
        );
        offered.expected_policy_epoch = epoch;
        let before_landing = snapshot(&node);
        let original = accepted(land(&node, &offered, "required-queue-head"));
        let after = snapshot(&node);
        assert_eq!(after.snapshot().refs[&offered.target_ref], offered.head_tip);
        assert_eq!(
            after.snapshot().outbox.len(),
            before_landing.snapshot().outbox.len() + 1
        );
        let queue = read(&node, 1, None).queue.unwrap();
        assert_eq!(queue.version, version(4));
        assert_eq!(queue.deterministic_order(), vec![pulls[1].number]);
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&node.request_context()))
            .unwrap();
        let decision = history.last().unwrap();
        assert_eq!(decision.batch.decisions.len(), 1);
        assert_eq!(decision.batch.committed_rcrs.len(), 1);
        assert_eq!(decision.forge_events.len(), 3);

        protect(&node, Vec::new(), "clear-after-landing");
        let head = snapshot(&node).basis().id();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            land(&reopened, &offered, "required-queue-head").unwrap(),
            original
        );
        assert_eq!(
            ordinary_fast_forward(&reopened, &offered, "ordinary-bypass"),
            ordinary
        );
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis().id(), head);
        reopened.shutdown().unwrap();
    }
}
