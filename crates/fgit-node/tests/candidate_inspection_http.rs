#![forbid(unsafe_code)]
//! Actual TCP -> native PR inspection -> verified candidate bytes. Independent
//! review/merge remain separate transactions; no canned inspection engine.
#[path = "candidate_inspection_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::review::{ComparisonMode, ReviewOptions};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm};
use fgit_wire::visibility::RefVisibility;

fn unhex(value: &str) -> Vec<u8> {
    value.as_bytes().chunks_exact(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}
fn open_local(node: &OneNode, candidate: &Candidate) {
    let command = PullRequestCommand { number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open, data: candidate.data.clone() };
    let session = LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(b"open-inspection".to_vec()).unwrap());
    let result = node.runtime().block_on(node.admit_pull_request_durable_in(&node.request_context(), &session, &command, Default::default())).unwrap();
    assert!(matches!(result.1.outcome, DecisionOutcome::Committed { .. }));
}

#[test]
fn inspected_result_is_not_the_source_diff_and_does_not_vote_or_stage_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, candidate) = resolved(&root, format, TEXT);
        let before = generation(&node);
        let before_outbox = node.runtime().block_on(node.materialize_admission()).unwrap().snapshot().outbox.len();
        let path = root.0.join("credentials"); let header = credentials(&node, &path);
        let server = Server::start(node, &path, 5, true, false);
        open(&server.client, &candidate); // 1
        let original = inspect(&server.client, &candidate, 'd', false); // 2
        status(&original, 200);
        assert!(original.body.contains("\"type\":\"candidate_inspection\""));
        assert!(original.body.contains("\"all_changed_paths\":true"));
        assert!(original.body.contains("\"merge_authorized\":false"));
        assert!(original.body.contains("\"transaction_created\":false"));
        assert!(original.body.contains(&format!("\"path_hex\":\"{}\"", hex(PATH))));
        assert!(original.body.contains(&format!("\"before_hex\":\"{}\"", hex(b"left\n"))));
        assert!(original.body.contains(&format!("\"after_hex\":\"{}\"", hex(TEXT))));
        assert!(!original.body.contains(&format!("\"after_hex\":\"{}\"", hex(b"right\n"))), "review must show the resolved result, not topic's content");
        assert!(original.body.contains(&format!("\"mode\":{}", 0o100755)));
        let commit = unhex(json_text(&original.body, "candidate_commit_body_hex"));
        assert_eq!(git_object_id(format, GitObjectKind::Commit, &commit), candidate.binding.commit);
        assert!(commit.ends_with(b"Actual inspected candidate\n"));
        let parents = format!("\"parents\":[\"{}\",\"{}\"]", candidate.data.target_tip, candidate.data.source_tip);
        assert!(original.body.contains(&parents));
        assert_eq!(inspect(&server.client, &candidate, 'd', true), original); // 3
        let votes = get(&server.client, "/api/v1/pulls/1/reviews", 'b'); // 4
        status(&votes, 200); assert!(votes.body.contains("\"reviews\":[]"));
        let missing = exchange(&server.client, &inspect_bytes(&server.client, 2, 'd', &common(&candidate), Some(&candidate.bundle), false), true); // 5
        status(&missing, 404); assert!(!missing.body.contains("candidate_commit_body_hex"));
        assert_eq!(server.finish().accepted_sessions(), 5);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1, "PR opening only; inspection has no canonical decision");
        assert!(node.read_git_object(candidate.binding.commit).is_err());
        assert!(node.read_git_object(git_object_id(format, GitObjectKind::Blob, TEXT)).is_err());
        let absent = LoopbackReceiveSession::authenticated(FOREIGN, IdempotencyKey::new(b"read-only-candidate-inspection".to_vec()).unwrap());
        assert!(matches!(node.runtime().block_on(node.recover_transaction_in(&node.request_context(), &absent)).unwrap(), RequestRecovery::KeyNotObserved));
        let server = Server::start(node, &path, 7, true, false);
        assert_eq!(inspect(&server.client, &candidate, 'd', false), original); // 1
        replace(&path, &(header + &row('a', OWNER, "pulls-read,pulls-write")
            + &row('b', REVIEWER, "reviews-read,reviews-write") + &row('c', MERGER, "merges-write")
            + &row('9', FOREIGN, "read,pulls-read")));
        status(&inspect(&server.client, &candidate, 'd', false), 401); // 2
        assert_eq!(inspect(&server.client, &candidate, '9', true), original); // 3
        accepted(&send(&server.client, "reviews/approve", 'b', "actual-vote", &review_form(&candidate, 0), Some(&candidate.bundle), false)); // 4
        let after_vote = inspect(&server.client, &candidate, '9', false); // 5
        status(&after_vote, 200);
        assert_ne!(token(&after_vote), token(&original));
        assert_eq!(json_text(&after_vote.body, "candidate_commit_body_hex"), json_text(&original.body, "candidate_commit_body_hex"));
        accepted(&send(&server.client, "merge", 'c', "actual-merge", &merge_form(&candidate, &[REVIEWER]), Some(&candidate.bundle), true)); // 6
        let stale = inspect(&server.client, &candidate, '9', false); // 7
        status(&stale, 409); assert!(stale.body.contains("inspection_subject_moved"));
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 3);
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs[&candidate.data.target_ref], candidate.binding.commit);
        assert_eq!(selected.snapshot().refs[&candidate.data.source_ref], candidate.data.source_tip);
        assert_eq!(selected.snapshot().outbox.len(), before_outbox + 3);
        node.shutdown().unwrap();
    }
}

#[test]
fn corrupt_mismatched_and_incomplete_uploads_never_disclose_a_partial_inspection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, candidate) = resolved(&root, format, TEXT); open_local(&node, &candidate);
        let before = generation(&node);
        let path = root.0.join("credentials"); credentials(&node, &path);
        let server = Server::start(node, &path, 9, true, false);
        let command = common(&candidate);
        let mut broken = candidate.bundle.clone(); *broken.last_mut().unwrap() ^= 1;
        let corrupt = exchange(&server.client, &inspect_bytes(&server.client, 1, 'd', &command, Some(&broken), false), true); // 1
        status(&corrupt, 400);
        let changed = command.replace(&format!("candidate_commit={}", candidate.binding.commit), &format!("candidate_commit={}", "e".repeat(format.digest_len() * 2)));
        status(&exchange(&server.client, &inspect_bytes(&server.client, 1, 'd', &changed, Some(&candidate.bundle), true), true), 400); // 2
        let changed = command.replace("pull_request_version=1", "pull_request_version=2");
        status(&exchange(&server.client, &inspect_bytes(&server.client, 1, 'd', &changed, Some(&candidate.bundle), false), true), 409); // 3
        let changed = command.replace(&format!("policy_epoch={}", candidate.epoch.get()), "policy_epoch=2");
        status(&exchange(&server.client, &inspect_bytes(&server.client, 1, 'd', &changed, Some(&candidate.bundle), false), true), 409); // 4
        status(&exchange(&server.client, &inspect_bytes(&server.client, 1, 'd', &command, None, false), true), 400); // 5
        let body = multipart(&command, Some(&candidate.bundle), false);
        let headers = format!("Content-Type: multipart/form-data; boundary=inspect-boundary\r\nContent-Length: {}\r\n", body.len() + 1);
        status(&exchange(&server.client, &request(&server.client, "POST", "/api/v1/pulls/1/inspect", 'd', &headers, &body), true), 400); // 6
        let truncated = &body[..body.len() - 4];
        let headers = format!("Content-Type: multipart/form-data; boundary=inspect-boundary\r\nContent-Length: {}\r\n", truncated.len());
        status(&exchange(&server.client, &request(&server.client, "POST", "/api/v1/pulls/1/inspect", 'd', &headers, truncated), true), 400); // 7
        let changed = command + "&paths=hide-the-resolved-file";
        let hidden = exchange(&server.client, &inspect_bytes(&server.client, 1, 'd', &changed, Some(&candidate.bundle), false), true); // 8
        assert!(matches!(hidden.status, 400 | 413));
        status(&inspect(&server.client, &candidate, 'd', false), 200); // 9
        assert!(!corrupt.body.contains("\"type\":\"candidate_inspection\""));
        assert!(!corrupt.body.contains("\"outcome_unknown\":true"));
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before);
        assert!(node.read_git_object(candidate.binding.commit).is_err()); node.shutdown().unwrap();
    }
}

#[test]
fn inspection_scopes_are_not_unioned_and_authentication_precedes_continue() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = resolved(&root, GitHashAlgorithm::Sha1, TEXT); let before = generation(&node);
    let path = root.0.join("credentials"); credentials(&node, &path);
    let disabled = Server::start(node, &path, 1, false, false);
    status(&withheld(&disabled.client, 'd', "", 1024), 403); disabled.finish();
    let node = reopen(&config);
    let server = Server::start(node, &path, 8, true, false);
    for token in ['a', 'b', 'c', 'e', 'f'] { status(&withheld(&server.client, token, "", 1024), 403); } // 1..5
    status(&withheld(&server.client, '0', "", 1024), 401); // 6
    let key = withheld(&server.client, 'd', "Idempotency-Key: not-a-mutation\r\n", 1024); // 7
    status(&key, 400); assert!(key.body.contains("inspection_has_no_transaction_key"));
    status(&withheld(&server.client, 'd', "", 65 * 1024 * 1024), 413); // 8
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
}

#[test]
fn binary_candidates_are_visible_changes_not_successful_empty_text_diffs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, candidate) = resolved(&root, format, b"\0\xffbinary\r\n"); open_local(&node, &candidate);
        let before = generation(&node);
        let path = root.0.join("credentials"); credentials(&node, &path);
        let server = Server::start(node, &path, 1, true, false);
        let reply = inspect(&server.client, &candidate, 'd', false); status(&reply, 200);
        assert!(reply.body.contains("\"type\":\"binary\""));
        assert!(reply.body.contains("\"body_included\":false"));
        assert!(!reply.body.contains("\"hunks\":[]"));
        assert!(reply.body.contains(&hex(PATH)));
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before);
        assert!(node.read_git_object(candidate.binding.commit).is_err()); node.shutdown().unwrap();
    }
}

#[test]
fn node_inspection_refuses_filters_hidden_refs_stale_subjects_cancellation_and_exhaustion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, candidate) = resolved(&root, format, TEXT);
        open_local(&node, &candidate); let before = generation(&node);
        let subject = subject(&candidate);
        let request = node.request_context(); let visible = RefVisibility::new();
        let mut options = ReviewOptions::default(); options.paths.push(PATH.to_vec());
        assert!(node.runtime().block_on(node.inspect_pull_request_bundle_in(&request, &subject,
            candidate.binding, &candidate.bundle, &visible, &options)).is_err());
        options.paths.clear(); options.mode = ComparisonMode::MergeBase;
        assert!(node.runtime().block_on(node.inspect_pull_request_bundle_in(&request, &subject,
            candidate.binding, &candidate.bundle, &visible, &options)).is_err());
        let options = ReviewOptions::default();
        let mut hidden = RefVisibility::new(); hidden.push_rule(candidate.data.source_ref.as_bytes(), &Default::default()).unwrap();
        assert!(node.runtime().block_on(node.inspect_pull_request_bundle_in(&request, &subject,
            candidate.binding, &candidate.bundle, &hidden, &options)).is_err());
        let mut stale = subject.clone(); stale.pull_request_version = AggregateVersion::try_new(2).unwrap();
        assert!(node.runtime().block_on(node.inspect_pull_request_bundle_in(&request, &stale,
            candidate.binding, &candidate.bundle, &visible, &options)).is_err());
        let cancelled = node.request_context(); cancelled.cancel();
        assert!(node.runtime().block_on(node.inspect_pull_request_bundle_in(&cancelled, &subject,
            candidate.binding, &candidate.bundle, &visible, &options)).is_err());
        let mut low = options.clone(); low.limits.max_output_bytes = 1;
        assert!(node.runtime().block_on(node.inspect_pull_request_bundle_in(&request, &subject,
            candidate.binding, &candidate.bundle, &visible, &low)).is_err());
        let valid = node.runtime().block_on(node.inspect_pull_request_bundle_in(&request, &subject,
            candidate.binding, &candidate.bundle, &visible, &options)).unwrap();
        assert_eq!(valid.review.pull_request, Some((PullRequestNumber::FIRST, AggregateVersion::FIRST)));
        assert_eq!(valid.review.comparison.entries.len(), 1);
        assert_eq!(generation(&node), before);
        assert!(node.read_git_object(candidate.binding.commit).is_err()); node.shutdown().unwrap();
    }
}
