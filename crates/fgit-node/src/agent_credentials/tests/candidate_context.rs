//! The request proof may remain live while its original HTTP database context
//! has stopped. Candidate engines must use that exact context, never a sibling.
use super::*;
use crate::{BundleInspectionRefusal, NodeWorkspaceRefusal, PackContextCheckpoint};
use fgit_forge::preparation::MergeMetadata;
use fgit_runtime::{ClassLimits, Exhaustion};
use fgit_types::RefName;
use std::time::Duration;

const INITIAL: &[u8] = b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+before\n";
const PATCH: &[u8] =
    b"diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-before\n+after\n";

fn context(node: &OneNode, limits: ClassLimits) -> NodeRequestContext {
    let authority = crate::FsqliteCx::new();
    authority.set_native_cx(
        node.runtime()
            .request_cx_with_budget(limits.at(node.runtime().now())),
    );
    NodeRequestContext { authority }
}

fn stopped_contexts(node: &OneNode) -> Vec<(NodeRequestContext, Option<Exhaustion>)> {
    let cancelled = node.command_request_context(None);
    cancelled.cancel();
    let polls = context(
        node,
        ClassLimits::finite(Duration::from_secs(300), 1, 1_000_000),
    );
    // Spend the original context's allowance, then keep the still-live agent
    // reservation as the success twin. Regenerating a sibling would hide this.
    let _ = crate::checkpoint_pack_context(polls.authority());
    assert!(matches!(
        crate::checkpoint_pack_context(polls.authority()),
        PackContextCheckpoint::Stopped {
            budget_exhaustion: Some(Exhaustion::PollQuota)
        }
    ));
    let deadline = context(
        node,
        ClassLimits::finite(Duration::ZERO, 1_000_000, 1_000_000),
    );
    vec![
        (cancelled, None),
        (polls, Some(Exhaustion::PollQuota)),
        (deadline, Some(Exhaustion::Deadline)),
    ]
}

fn cancelled(error: NodeWorkspaceRefusal, expected: Option<Exhaustion>) {
    assert!(
        matches!(error, NodeWorkspaceRefusal::Cancelled { exhaustion } if exhaustion == expected),
        "original cancellation/exhaustion must remain attributed: {error:?}"
    );
}

#[test]
fn candidate_engines_retain_original_context_cancellation_poll_quota_and_deadline() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let metadata = MergeMetadata {
            author: "A <a@example.invalid>".into(),
            committer: "C <c@example.invalid>".into(),
            timestamp: 1,
            message: b"candidate context fixture\n".to_vec(),
        };
        let seed_context = node.command_request_context(None);
        let (_, plan, bundle) = node
            .runtime()
            .block_on(node.prepare_trusted_initial_patch_in(
                &seed_context,
                &reference,
                INITIAL,
                &metadata,
                Default::default(),
                None,
            ))
            .unwrap();
        let seeded = node
            .runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &seed_context,
                &operator(actor(1), "candidate-context-seed"),
                &reference,
                plan.commit,
                bundle.bytes(),
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            seeded.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let token = bearer('f');
        committed(credential(
            &node,
            &issue_command(
                &token,
                AgentCredentialGrant {
                    operations: SOURCE_CANDIDATES,
                    ..grant(&node)
                },
            ),
            actor(1),
            "candidate-context-credential",
        ));
        let run = authentication(&node, &token, "candidate-context", SOURCE_CANDIDATES);
        let proof = run.source_candidates(&node).unwrap();
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let prepare = |original: &NodeRequestContext| {
            node.runtime()
                .block_on(node.prepare_agent_source_patch_with_context_in(
                    original,
                    &proof,
                    &reference,
                    plan.commit,
                    PATCH,
                    &metadata,
                    false,
                ))
        };
        let candidate = prepare(&run.context(&node)).unwrap();
        let inspect = |original: &NodeRequestContext| {
            node.runtime()
                .block_on(node.inspect_agent_source_bundle_with_context_in(
                    original,
                    &proof,
                    &reference,
                    plan.commit,
                    candidate.candidate_commit,
                    candidate.bundle_bytes(),
                    &Default::default(),
                    None,
                    &Default::default(),
                ))
        };
        assert!(inspect(&run.context(&node)).is_ok());
        for (original, exhaustion) in stopped_contexts(&node) {
            // Credential expiry is not the reason either operation must stop.
            run.check(PATCH.len() as u64, 0).unwrap();
            cancelled(prepare(&original).unwrap_err(), exhaustion);
            let error = inspect(&original).unwrap_err();
            let BundleInspectionRefusal::Envelope(error) = error else {
                panic!("inspection lost its original context cause: {error:?}");
            };
            cancelled(*error, exhaustion);
        }
        // The same valid source and request still work under a live context;
        // no stopped phase staged candidate objects or changed authority.
        let repeated = prepare(&run.context(&node)).unwrap();
        assert_eq!(candidate.bundle_bytes(), repeated.bundle_bytes());
        assert!(inspect(&run.context(&node)).is_ok());
        assert!(node.read_git_object(candidate.candidate_commit).is_err());
        let after = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        assert_eq!(before.receipt(), after.receipt());
        node.shutdown().unwrap();
    }
}
