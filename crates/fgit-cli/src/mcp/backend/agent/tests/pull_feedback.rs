//! Sponsored feedback uses real canonical reviews and PR state. An observation
//! never supplies review, publication, artifact-disclosure or merge authority.
use super::super::super::{checks, head_token, pull_reviews};
use super::*;
use fgit_authority::TerminalOutcome;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::preparation::{MergeMetadata, MergePreparation};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_identity::agent::{AgentCredentialId, PULLS_FEEDBACK_READ};
use fgit_types::{DecisionOutcome, PrincipalId, RefName, RepositoryAuthorityHeadId};

const REASON: &str = "Please revise <untrusted>request text</untrusted>.";

fn authority(node: &OneNode) -> RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.command_request_context(None)))
        .unwrap()
        .basis()
        .id()
}

fn accepted(terminal: TerminalOutcome) {
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

struct FeedbackFixture {
    fixture: Fixture,
    options: Options,
    credential: AgentCredentialId,
}

impl FeedbackFixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let fixture = Fixture::new(format);
        let administrator = NodeTools::open(fixture.options.clone()).unwrap();
        let node = &administrator.node;
        let context = node.command_request_context(None);
        let source = RefName::try_new(b"refs/heads/agent/topic").unwrap();
        let target = RefName::try_new(b"refs/heads/main").unwrap();
        let metadata = MergeMetadata {
            author: "A <a@example.invalid>".into(),
            committer: "A <a@example.invalid>".into(),
            timestamp: 2,
            message: b"feedback fixture\n".to_vec(),
        };
        let candidate = node
            .runtime()
            .block_on(node.prepare_trusted_patch_in(
                &context,
                &source,
                fixture.tip,
                [0x81; 16],
                b"diff --git a/feedback b/feedback\nnew file mode 100644\n--- /dev/null\n+++ b/feedback\n@@ -0,0 +1 @@\n+review this change\n",
                &metadata,
                Default::default(),
            ))
            .unwrap();
        let published = node
            .runtime()
            .block_on(node.apply_workspace_bundle_durable_in(
                &context,
                SPONSOR,
                b"feedback-source",
                &source,
                fixture.tip,
                candidate.candidate_commit,
                candidate.bundle_bytes(),
            ))
            .unwrap();
        accepted(published.commands[0].terminal);
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &context,
                &operator(SPONSOR, "feedback-open"),
                &PullRequestCommand {
                    number: PullRequestNumber::FIRST,
                    expected_version: ExpectedVersion::NewStream,
                    action: PullRequestAction::Open,
                    data: PullRequestData {
                        source_ref: source.clone(),
                        target_ref: target.clone(),
                        source_tip: candidate.candidate_commit,
                        target_tip: fixture.tip,
                        title: "Feedback without write authority".into(),
                        body: "Read canonical reviewer decisions.".into(),
                    },
                },
                Default::default(),
            ))
            .unwrap();
        accepted(terminal);
        let prepared = node
            .runtime()
            .block_on(node.prepare_merge_bundle_in(
                &context,
                &target,
                &source,
                &Default::default(),
                &metadata,
                Default::default(),
            ))
            .unwrap();
        let MergePreparation::Clean(plan) = prepared.outcome else {
            panic!("clean feedback candidate");
        };
        let policy_epoch = node
            .runtime()
            .block_on(node.materialize_admission_in(&context))
            .unwrap()
            .basis()
            .body()
            .policy_epoch;
        for (index, decision) in [ReviewDecision::Approve, ReviewDecision::RequestChanges]
            .into_iter()
            .enumerate()
        {
            let reviewer = PrincipalId::from_bytes([0xe1 + index as u8; 16]);
            let (_, terminal) = node
                .runtime()
                .block_on(node.admit_candidate_review_durable_in(
                    &context,
                    &operator(reviewer, &format!("feedback-review-{index}")),
                    &CandidateReviewCommand {
                        candidate: CandidateBinding {
                            merge_base: plan.base,
                            commit: plan.commit,
                        },
                        review: ReviewCommand {
                            expected_version: ExpectedVersion::NewStream,
                            subject: ReviewSubject {
                                pull_request: PullRequestNumber::FIRST,
                                pull_request_version: AggregateVersion::FIRST,
                                source_ref: source.clone(),
                                target_ref: target.clone(),
                                source_tip: candidate.candidate_commit,
                                target_tip: fixture.tip,
                                policy_epoch,
                            },
                            decision,
                            reason: REASON.into(),
                        },
                    },
                    prepared.bundle.as_deref(),
                    Default::default(),
                ))
                .unwrap();
            accepted(terminal);
        }
        let credential = issue(
            node,
            &token(0x83),
            grant(node, PULLS_FEEDBACK_READ),
            "feedback-only",
        );
        // Freeze every previously available non-publication bit. A previously
        // issued mask cannot acquire the new disclosure after an upgrade.
        issue(node, &token(0x84), grant(node, 0x6fff), "feedback-old-mask");
        let mut expired = grant(node, PULLS_FEEDBACK_READ);
        expired.issued_at -= 120;
        expired.expires_at = expired.issued_at + 60;
        issue(node, &token(0x85), expired, "feedback-expired");
        administrator.close().unwrap();
        let mut options = fixture.replacement(0x83);
        options.writes = Default::default();
        options.issues = false;
        options.discussions = false;
        options.outcomes = false;
        Self {
            fixture,
            options,
            credential,
        }
    }
}

fn query() -> Object {
    object([
        ("number", text("1")),
        ("limit", super::super::super::json::number(1)),
    ])
    .object()
    .unwrap()
    .clone()
}

#[test]
fn feedback_reads_real_reviews_with_pinned_pages_and_no_other_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = FeedbackFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = authority(&backend.node);
        let first = backend.call(pull_reviews::NAME, &query()).unwrap();
        let fields = first.object().unwrap();
        assert_eq!(fields["found"], Value::Bool(true));
        assert_eq!(fields["pull_request_version"], text("1"));
        assert_eq!(fields["merge_permission"], Value::Null);
        assert_eq!(fields["approvals_satisfy_policy"], Value::Null);
        let Value::Array(rows) = &fields["reviews"] else {
            panic!("review rows");
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].object().unwrap()["decision"], text("approve"));
        assert_eq!(rows[0].object().unwrap()["reason"], text(REASON));
        let mut continuation = query();
        continuation.insert("after".into(), fields["next_after"].clone());
        assert!(backend.call(pull_reviews::NAME, &continuation).is_err());
        continuation.insert("expected_head".into(), fields["snapshot_token"].clone());
        let second = backend.call(pull_reviews::NAME, &continuation).unwrap();
        let Value::Array(rows) = &second.object().unwrap()["reviews"] else {
            panic!("continued review rows")
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].object().unwrap()["decision"],
            text("request-changes")
        );
        assert_eq!(second.object().unwrap()["complete"], Value::Bool(true));
        assert_eq!(
            second.object().unwrap()["snapshot_token"],
            fields["snapshot_token"]
        );

        let checks = backend.call(checks::NAME, &query()).unwrap();
        assert_eq!(checks.object().unwrap()["found"], Value::Bool(true));
        assert_eq!(
            checks.object().unwrap()["source_current"],
            Value::Bool(true)
        );
        assert_eq!(checks.object().unwrap()["merge_permission"], Value::Null);
        assert_eq!(
            checks.object().unwrap()["snapshot_token"],
            text(head_token(before))
        );
        let reservation = backend.agent.as_ref().unwrap().response.as_ref().unwrap();
        let session = reservation.authenticated_session();
        let witness = session.authenticated_session().unwrap().authentication();
        let witness = witness.agent_provenance().unwrap();
        assert_eq!(witness.agent(), AGENT);
        assert_eq!(witness.sponsor(), SPONSOR);
        assert_eq!(witness.credential_id(), fixture.credential);
        assert!(reservation.mcp_source_read_context(&backend.node).is_err());
        assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
        assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
        assert_eq!(authority(&backend.node), before);

        // A completed response is not an active request, even for the same
        // tool. Direct native handlers must not obtain trusted-local context.
        for handler in [pull_reviews::call, checks::call] {
            assert_eq!(
                handler(&backend, &query()).unwrap_err().code,
                "agent_request_required"
            );
        }
        backend.options.source = true;
        for name in [
            "frankengit_pull_show",
            "frankengit_source_blob",
            "frankengit_pull_check_evidence",
        ] {
            assert_eq!(
                backend.call(name, &Object::new()).unwrap_err().code,
                "agent_operation_not_granted"
            );
        }
        for name in ["frankengit_pull_review", "frankengit_pull_merge"] {
            assert_eq!(
                backend.call(name, &Object::new()).unwrap_err().code,
                "tool_not_granted"
            );
        }
        backend.options.pulls = false;
        for name in [pull_reviews::NAME, checks::NAME] {
            assert!(!backend.tools().iter().any(|tool| tool.name == name));
            assert_eq!(
                backend.call(name, &query()).unwrap_err().code,
                "tool_not_granted"
            );
        }
        assert_eq!(authority(&backend.node), before);
        backend.close().unwrap();
    }
}

#[test]
fn feedback_requires_the_new_grant_and_retains_expiry_revocation_and_active_operation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = FeedbackFixture::new(format);
        for (byte, code) in [
            (0x84, "agent_operation_not_granted"),
            (0x85, "agent_credential_unavailable"),
        ] {
            let mut backend = NodeTools::open(fixture.fixture.replacement(byte)).unwrap();
            for name in [pull_reviews::NAME, checks::NAME] {
                assert_eq!(backend.call(name, &query()).unwrap_err().code, code);
            }
            backend.close().unwrap();
        }
        let mut backend = NodeTools::open(fixture.fixture.options.clone()).unwrap();
        backend
            .call("frankengit_pull_list", &Object::new())
            .unwrap();
        let other = backend.agent.as_mut().unwrap().response.take().unwrap();
        backend.agent.as_mut().unwrap().request = Some(other);
        for handler in [pull_reviews::call, checks::call] {
            assert!(handler(&backend, &query()).is_err());
        }
        backend.agent.as_mut().unwrap().request = None;
        backend.call(checks::NAME, &query()).unwrap();
        let mut request = backend.agent.as_mut().unwrap().response.take().unwrap();
        request.constrain_deadline(Instant::now() - Duration::from_secs(1));
        backend.agent.as_mut().unwrap().request = Some(request);
        for handler in [pull_reviews::call, checks::call] {
            assert!(handler(&backend, &query()).is_err());
        }
        backend.agent.as_mut().unwrap().request = None;
        backend.close().unwrap();

        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        revoke(&backend.node, fixture.credential, "feedback-revoke");
        let before = authority(&backend.node);
        for name in [pull_reviews::NAME, checks::NAME] {
            assert_eq!(
                backend.call(name, &query()).unwrap_err().code,
                "agent_credential_unavailable"
            );
        }
        assert_eq!(authority(&backend.node), before);
        backend.close().unwrap();
    }
}
