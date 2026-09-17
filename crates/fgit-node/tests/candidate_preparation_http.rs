#![forbid(unsafe_code)]
//! Real remote preparation -> candidate download -> review -> coupled merge.
//! Native preparation is NOT called locally in the main TCP workflow.
#[path = "candidate_preparation_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::{MergeMetadata, MergePreparation, PreparationLimits};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeWorkspaceRefusal};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PolicyEpoch};
use fgit_wire::visibility::RefVisibility;

#[test]
fn remote_candidate_is_deterministic_unstaged_and_reviewable_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let before = generation(&node);
        let before_outbox = node.runtime().block_on(node.materialize_admission()).unwrap().snapshot().outbox.len();
        let path = root.0.join("credentials"); configure(&node, &path);
        let server = Server::start(node, &path, 4, true, true);
        committed(&post(&server.client, 1, "open", 'a', "open-remote-preparation", &form(&data, 0), false)); // 1
        // The policy coordinate is obtained remotely, not from local node state.
        let reviews = get(&server.client, "/api/v1/pulls/1/reviews", 'b'); // 2
        status(&reviews, 200);
        let epoch = PolicyEpoch::try_new(numeric(&reviews.body, "policy_epoch")).unwrap();
        let command = preparation_form(&data, epoch);
        let original = prepare(&server.client, 1, 'd', &command, false); // 3
        let (candidate, metadata) = extract(&original, data.clone());
        assert_eq!(candidate.epoch, epoch);
        assert_eq!(prepare(&server.client, 1, 'd', &command, true), original); // 4
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1, "only PR creation is a publication");
        assert!(node.read_git_object(candidate.binding.commit).is_err(), "downloaded candidate is not staged");
        assert_eq!(node.runtime().block_on(node.materialize_admission()).unwrap().snapshot().refs[&data.target_ref], data.target_tip);
        let no_transaction = LoopbackReceiveSession::authenticated(FOREIGN,
            IdempotencyKey::new(b"read-only-candidate-preparation".to_vec()).unwrap());
        assert!(matches!(node.runtime().block_on(node.recover_transaction_in(
            &node.request_context(), &no_transaction)).unwrap(), RequestRecovery::KeyNotObserved));
        let server = Server::start(node, &path, 7, true, true);
        assert_eq!(prepare(&server.client, 1, 'd', &command, false), original); // 1
        let vote = send(&server.client, "reviews/approve", 'b', "approve-remote", &review_form(&candidate, 0), Some(&candidate.bundle), true); // 2
        accepted(&vote);
        assert_eq!(send(&server.client, "reviews/approve", 'b', "approve-remote", &review_form(&candidate, 0), None, false), vote); // 3
        let merge = merge_form(&candidate, &[REVIEWER]);
        let published = send(&server.client, "merge", 'c', "merge-remote", &merge, Some(&candidate.bundle), false); // 4
        accepted(&published);
        assert_eq!(send(&server.client, "merge", 'c', "merge-remote", &merge, None, false), published); // 5
        let pr = get(&server.client, "/api/v1/pulls/1", 'a'); // 6
        status(&pr, 200); assert!(pr.body.contains("\"state\":\"merged\""));
        let stale = prepare(&server.client, 1, 'd', &command, false); // 7
        assert_eq!(stale.status, 409);
        assert!(String::from_utf8(stale.body).unwrap().contains("preparation_subject_moved"));
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 3, "PR, approval and coupled merge only");
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs[&data.target_ref], candidate.binding.commit);
        assert_eq!(selected.snapshot().refs[&data.source_ref], data.source_tip);
        assert_eq!(selected.snapshot().outbox.len(), before_outbox + 3);
        assert!(node.read_git_object(candidate.binding.commit).is_ok());
        assert!(metadata.contains("\"published\":false"), "preparation receipt never changes meaning after merge");
        node.shutdown().unwrap();
    }
}

fn withheld(endpoint: &Endpoint, token: char, extra: &str, length: usize) -> BinaryReply {
    binary_exchange(endpoint, &request(endpoint, "POST", "/api/v1/pulls/1/prepare", token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{extra}"), &[]), false)
}
#[test]
fn both_read_grants_and_complete_envelopes_are_required_before_preparation() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, data) = fixture(&root, GitHashAlgorithm::Sha1); let before = generation(&node);
    let path = root.0.join("credentials");
    replace(&path, &(header(&node) + &row('a', OWNER, "pulls-read,pulls-write")
        + &row('b', REVIEWER, "reviews-read,reviews-write") + &row('c', MERGER, "merges-write")
        + &row('d', FOREIGN, "read,pulls-read") + &row('e', FOREIGN, "read") + &row('f', FOREIGN, "pulls-read")));
    let server = Server::start(node, &path, 11, true, false);
    committed(&post(&server.client, 1, "open", 'a', "open", &form(&data, 0), false)); // 1
    for token in ['a', 'e', 'f', 'c'] { // 2..5; equal principals do not union different token grants.
        let denied = withheld(&server.client, token, "", 1024);
        assert_eq!(denied.status, 403);
        assert!(!denied.head.contains("100 Continue"));
    }
    assert_eq!(withheld(&server.client, 'z', "", 1024).status, 401); // 6
    assert_eq!(withheld(&server.client, 'd', "Idempotency-Key: not-a-mutation\r\n", 1024).status, 400); // 7
    assert_eq!(withheld(&server.client, 'd', "", 262145).status, 413); // 8
    let command = preparation_form(&data, PolicyEpoch::FIRST);
    let truncated = request(&server.client, "POST", "/api/v1/pulls/1/prepare", 'd',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n", command.len() + 1), command.as_bytes());
    assert_eq!(binary_exchange(&server.client, &truncated, true).status, 400); // 9
    let mut wrong = command.clone(); wrong = wrong.replace("pull_request_version=1", "pull_request_version=2");
    let stale = prepare(&server.client, 1, 'd', &wrong, true); // 10
    assert_eq!(stale.status, 409);
    let body = String::from_utf8(stale.body).unwrap();
    assert!(body.contains("\"outcome_unknown\":false"));
    assert!(!body.contains("\"outcome\":\"refused\""));
    assert_eq!(prepare(&server.client, 999, 'd', &command, false).status, 404); // 11
    assert_eq!(server.finish().accepted_sessions(), 11);
    let node = reopen(&config); assert_eq!(generation(&node), before + 1);
    let disabled = Server::start(node, &path, 1, false, false);
    assert_eq!(withheld(&disabled.client, 'd', "", 1024).status, 403);
    disabled.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before + 1); node.shutdown().unwrap();
}

#[test]
fn native_conflicts_and_already_integrated_sources_return_no_candidate_or_decision() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for conflict in [false, true] {
            let root = Scratch::new(); let config = root.config(format);
            let (node, data) = non_clean_fixture(&root, format, conflict); let before = generation(&node);
            let path = root.0.join("credentials"); configure(&node, &path);
            let server = Server::start(node, &path, 4, true, false);
            committed(&post(&server.client, 1, "open", 'a', "open", &form(&data, 0), false));
            let reviews = get(&server.client, "/api/v1/pulls/1/reviews", 'b'); status(&reviews, 200);
            let epoch = PolicyEpoch::try_new(numeric(&reviews.body, "policy_epoch")).unwrap();
            let command = preparation_form(&data, epoch);
            let first = prepare(&server.client, 1, 'd', &command, true);
            assert_eq!(first.status, if conflict { 409 } else { 200 });
            assert!(first.head.contains("Content-Type: application/json"));
            let metadata = std::str::from_utf8(&first.body).unwrap();
            assert!(metadata.contains("\"candidate\":null,\"bundle\":null"));
            assert!(metadata.contains("\"transaction_created\":false"));
            if conflict {
                assert!(metadata.contains("\"state\":\"conflicted\""));
                assert!(metadata.contains("\"path_hex\":\"66696c65ff2e747874\""));
                assert!(!metadata.contains('\u{fffd}'), "raw paths cannot undergo lossy conversion");
            } else { assert!(metadata.contains("\"state\":\"already_up_to_date\"")); }
            assert_eq!(prepare(&server.client, 1, 'd', &command, false), first);
            server.finish();
            let node = reopen(&config); assert_eq!(generation(&node), before + 1);
            let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
            assert_eq!(selected.snapshot().refs[&data.target_ref], data.target_tip);
            assert_eq!(selected.snapshot().refs[&data.source_ref], data.source_tip);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn hidden_sources_changed_coordinates_cancellation_and_work_limits_never_stage_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, data) = fixture(&root, format);
        let request = node.request_context();
        let session = LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(b"open-local-check".to_vec()).unwrap());
        let command = PullRequestCommand { number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream, action: PullRequestAction::Open, data: data.clone() };
        let (_, terminal) = node.runtime().block_on(node.admit_pull_request_durable_in(
            &request, &session, &command, Default::default())).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        let before = generation(&node);
        let epoch = node.runtime().block_on(node.materialize_admission()).unwrap().basis().body().policy_epoch;
        let subject = ReviewSubject { pull_request: PullRequestNumber::FIRST, pull_request_version: AggregateVersion::FIRST,
            policy_epoch: epoch, source_ref: data.source_ref.clone(), target_ref: data.target_ref.clone(),
            source_tip: data.source_tip, target_tip: data.target_tip };
        let metadata = MergeMetadata { author: "Fixture <fixture@example.invalid>".into(),
            committer: "Fixture <fixture@example.invalid>".into(), timestamp: 1, message: b"local check\n".to_vec() };
        let prepared = node.runtime().block_on(node.prepare_pull_request_bundle_in(&request, &subject,
            &RefVisibility::new(), &metadata, PreparationLimits::default())).unwrap();
        let MergePreparation::Clean(plan) = prepared.outcome else { panic!("candidate") };
        assert!(node.read_git_object(plan.commit).is_err());
        for change in 0..3 {
            let mut stale = subject.clone();
            match change { 0 => stale.policy_epoch = epoch.next().unwrap(),
                1 => stale.pull_request_version = AggregateVersion::FIRST.next().unwrap(),
                _ => stale.source_tip = data.target_tip }
            assert!(matches!(node.runtime().block_on(node.prepare_pull_request_bundle_in(&request, &stale,
                &RefVisibility::new(), &metadata, PreparationLimits::default())), Err(NodeWorkspaceRefusal::StaleWorkspaceBase)));
        }
        let mut hidden = RefVisibility::new(); hidden.push_rule(data.source_ref.as_bytes(), &Default::default()).unwrap();
        assert!(matches!(node.runtime().block_on(node.prepare_pull_request_bundle_in(&request, &subject,
            &hidden, &metadata, PreparationLimits::default())), Err(NodeWorkspaceRefusal::RefUnavailable)));
        let tight = PreparationLimits { max_commits: 1, ..PreparationLimits::default() };
        assert!(node.runtime().block_on(node.prepare_pull_request_bundle_in(&request, &subject,
            &RefVisibility::new(), &metadata, tight)).is_err());
        let cancelled = node.request_context(); cancelled.cancel();
        assert!(node.runtime().block_on(node.prepare_pull_request_bundle_in(&cancelled, &subject,
            &RefVisibility::new(), &metadata, PreparationLimits::default())).is_err());
        assert_eq!(generation(&node), before);
        assert!(node.read_git_object(plan.commit).is_err());
        node.shutdown().unwrap();
    }
}
