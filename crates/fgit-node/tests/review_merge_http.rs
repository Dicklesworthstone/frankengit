#![forbid(unsafe_code)]
//! Actual TCP requests, native candidate bundles and embedded authority. Review
//! snapshots cannot bypass current votes or canonical mandatory protection.
#[path = "review_merge_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, OutcomeLookup};
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm};
use std::io::{Read, Write};

#[test]
fn withdrawal_blocks_merge_despite_retained_approval_then_renewal_publishes_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, candidate) = prepared(&root, format);
        let before = generation(&node);
        let outbox = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .snapshot()
            .outbox
            .len();
        let path = root.0.join("credentials");
        configure(&node, &path);
        let server = Server::start(node, &path, 4, true, false);
        open(&server.client, &candidate); // 1
        let original = send(
            &server.client,
            "reviews/approve",
            'b',
            "approve",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            false,
        ); // 2
        accepted(&original);
        assert!(
            original
                .body
                .contains("\"type\":\"candidate_review_publication\"")
        );
        assert!(original.body.contains(&REVIEWER.to_string()));
        // Terminal retries need the same semantics, not another candidate upload.
        assert_eq!(
            send(
                &server.client,
                "reviews/approve",
                'b',
                "approve",
                &review_form(&candidate, 0),
                None,
                false
            ),
            original
        ); // 3
        let first = get(&server.client, "/api/v1/pulls/1/reviews?limit=1", 'b'); // 4
        status(&first, 200);
        assert!(first.body.contains("\"decision\":\"approve\""));
        assert!(first.body.contains("\"freshness\":\"current\""));
        assert!(first.body.contains("\"merge_authorized\":false"));
        let pin = token(&first);
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 2);
        assert!(
            node.read_git_object(candidate.binding.commit).is_err(),
            "review does not import the candidate"
        );
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs[&candidate.data.target_ref],
            candidate.data.target_tip
        );
        let server = Server::start(node, &path, 11, true, true);
        accepted(&send(
            &server.client,
            "reviews/withdraw",
            'b',
            "withdraw",
            &review_form(&candidate, 1),
            None,
            false,
        )); // 1
        let retained_route = format!("/api/v1/pulls/1/reviews?limit=1&expected_head={pin}");
        assert_eq!(get(&server.client, &retained_route, 'b'), first); // 2
        let merge = merge_form(&candidate, &[REVIEWER]);
        let blocked = send(
            &server.client,
            "merge",
            'c',
            "withdrawn-merge",
            &merge,
            Some(&candidate.bundle),
            false,
        ); // 3
        refused(&blocked);
        assert_eq!(
            send(
                &server.client,
                "merge",
                'c',
                "withdrawn-merge",
                &merge,
                None,
                false
            ),
            blocked
        ); // 4
        accepted(&send(
            &server.client,
            "reviews/approve",
            'b',
            "renew",
            &review_form(&candidate, 2),
            Some(&candidate.bundle),
            true,
        )); // 5
        let published = send(
            &server.client,
            "merge",
            'c',
            "accepted-merge",
            &merge,
            Some(&candidate.bundle),
            true,
        ); // 6
        accepted(&published);
        assert!(
            published
                .body
                .contains("\"type\":\"reviewed_merge_publication\"")
        );
        assert_eq!(
            send(
                &server.client,
                "merge",
                'c',
                "accepted-merge",
                &merge,
                None,
                false
            ),
            published
        ); // 7
        let pr = get(&server.client, "/api/v1/pulls/1", 'a'); // 8
        status(&pr, 200);
        assert!(pr.body.contains("\"version\":2,\"state\":\"merged\""));
        assert!(pr.body.contains(&candidate.binding.commit.to_string()));
        let current = get(&server.client, "/api/v1/pulls/1/reviews", 'b'); // 9
        status(&current, 200);
        assert!(
            current
                .body
                .contains("\"freshness\":\"pull_request_closed\"")
        );
        assert_eq!(get(&server.client, &retained_route, 'b'), first); // 10
        let recovery = lookup(&server.client, 'c', "accepted-merge"); // 11
        status(&recovery, 200);
        assert!(recovery.body.contains("\"state\":\"committed\""));
        assert_eq!(server.finish().accepted_sessions(), 11);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 6,
            "PR, three review transitions, refused merge, committed merge only"
        );
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&candidate.data.target_ref],
            candidate.binding.commit
        );
        assert_eq!(
            selected.snapshot().refs[&candidate.data.source_ref],
            candidate.data.source_tip
        );
        assert_eq!(selected.snapshot().outbox.len(), outbox + 5);
        assert!(node.read_git_object(candidate.binding.commit).is_ok());
        node.shutdown().unwrap();
    }
}

fn withheld(endpoint: &Endpoint, action: &str, token: char) -> Reply {
    let bytes = request(
        endpoint,
        "POST",
        &format!("/api/v1/pulls/1/{action}"),
        token,
        "Content-Type: multipart/form-data; boundary=review-boundary\r\nContent-Length: 1024\r\nIdempotency-Key: withheld\r\nExpect: 100-continue\r\n",
        &[],
    );
    let reply = exchange(endpoint, &bytes, false);
    assert!(!reply.raw.contains("100 Continue"));
    reply
}

#[test]
fn deployment_scope_and_complete_binary_envelopes_precede_review_admission() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha256);
    let (node, candidate) = prepared(&root, GitHashAlgorithm::Sha256);
    let before = generation(&node);
    let path = root.0.join("credentials");
    configure(&node, &path);
    let disabled = Server::start(node, &path, 3, false, false);
    status(&get(&disabled.client, "/api/v1/pulls/1/reviews", 'f'), 403);
    status(&withheld(&disabled.client, "reviews/approve", 'b'), 403);
    status(&withheld(&disabled.client, "merge", 'c'), 403);
    assert_eq!(disabled.finish().refused_sessions(), 3);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 13, true, false);
    open(&server.client, &candidate); // 1
    status(&get(&server.client, "/api/v1/pulls/1/reviews", 'd'), 403); // 2: all old grants confer no review authority.
    status(&withheld(&server.client, "reviews/approve", 'f'), 403); // 3: read is not vote.
    status(&withheld(&server.client, "merge", 'b'), 403); // 4: vote is not code publication.
    status(&withheld(&server.client, "reviews/approve", 'c'), 403); // 5: publication is not vote.
    status(&get(&server.client, "/api/v1/pulls/1/reviews", 'c'), 403); // 6: publication is not review read.
    let form = review_form(&candidate, 0);
    let mut malformed = mutation_bytes(
        &server.client,
        "reviews/approve",
        'b',
        "bad-part",
        &form,
        Some(&candidate.bundle),
        false,
    );
    let index = malformed
        .windows(b"name=\"command\"".len())
        .position(|v| v == b"name=\"command\"")
        .unwrap();
    malformed[index + 6] = b'x'; // Unknown part, same Content-Length and otherwise complete framing.
    status(&exchange(&server.client, &malformed, true), 400); // 7
    let mut truncated = mutation_bytes(
        &server.client,
        "reviews/approve",
        'b',
        "truncated",
        &form,
        Some(&candidate.bundle),
        false,
    );
    truncated.pop();
    status(&exchange(&server.client, &truncated, true), 400); // 8
    status(
        &send(
            &server.client,
            "reviews/approve",
            'b',
            "identity-in-form",
            &(form.clone() + "&reviewer=admin"),
            Some(&candidate.bundle),
            false,
        ),
        400,
    ); // 9
    let missing = send(
        &server.client,
        "reviews/approve",
        'b',
        "missing-bundle",
        &form,
        None,
        false,
    ); // 10
    status(&missing, 503);
    assert!(missing.body.contains("\"outcome_unknown\":true"));
    accepted(&send(
        &server.client,
        "reviews/approve",
        'e',
        "actual-review",
        &form,
        Some(&candidate.bundle),
        true,
    )); // 11
    status(&get(&server.client, "/api/v1/pulls/1/reviews", 'e'), 403); // 12: write does not imply read.
    let page = get(&server.client, "/api/v1/pulls/1/reviews", 'b'); // 13
    status(&page, 200);
    assert!(page.body.contains(&SECOND.to_string()));
    assert!(!page.body.contains(&format!("\"reviewer\":\"{REVIEWER}\"")));
    assert_eq!(server.finish().accepted_sessions(), 13);
    let node = reopen(&config);
    assert_eq!(
        generation(&node),
        before + 2,
        "only the PR and actually validated vote publish"
    );
    assert!(node.read_git_object(candidate.binding.commit).is_err());
    node.shutdown().unwrap();
}

#[test]
fn a_lost_merge_reply_is_recovered_after_restart_and_write_revocation_without_a_bundle() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, candidate) = prepared(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        let header = configure(&node, &path);
        let server = Server::start(node, &path, 3, true, false);
        open(&server.client, &candidate);
        accepted(&send(
            &server.client,
            "reviews/approve",
            'b',
            "vote-before-loss",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            false,
        ));
        let bytes = mutation_bytes(
            &server.client,
            "merge",
            'c',
            "lost-merge-reply",
            &merge_form(&candidate, &[REVIEWER]),
            Some(&candidate.bundle),
            false,
        );
        let mut socket = connection(&server.client);
        socket.write_all(&bytes).unwrap();
        let mut first = [0; 1];
        socket.read_exact(&mut first).unwrap();
        assert_eq!(first, [b'H']); // No JSON outcome or transaction ID was learned.
        drop(socket);
        server.finish();
        let node = reopen(&config);
        let session = LoopbackReceiveSession::authenticated(
            MERGER,
            IdempotencyKey::new(b"lost-merge-reply".to_vec()).unwrap(),
        );
        let known = node
            .runtime()
            .block_on(node.recover_transaction_in(&node.request_context(), &session))
            .unwrap();
        let fgit_authority::key_recovery::RequestRecovery::Recovered(known) = known else {
            panic!("real merge seal");
        };
        let OutcomeLookup::Decided(terminal) = known.outcome() else {
            panic!("real merge outcome");
        };
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        replace(&path, &(header + &row('f', MERGER, "outcomes-read")));
        let server = Server::start(node, &path, 4, false, true);
        let recovered = lookup(&server.client, 'f', "lost-merge-reply"); // 1
        status(&recovered, 200);
        assert!(
            recovered
                .body
                .contains(&format!("\"tx_id\":\"{}\"", known.tx_id()))
        );
        assert!(recovered.body.contains("\"state\":\"committed\""));
        assert!(recovered.body.contains("\"request_reexecuted\":false"));
        assert_eq!(lookup(&server.client, 'f', "lost-merge-reply"), recovered); // 2
        status(&get(&server.client, "/api/v1/pulls/1/reviews", 'f'), 403); // 3
        status(&lookup(&server.client, 'c', "lost-merge-reply"), 401); // 4
        server.finish();
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 3,
            "open, approve, merge; recovery publishes nothing"
        );
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs[&candidate.data.target_ref],
            candidate.binding.commit
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn a_merge_grant_and_weaker_requested_reviewer_list_cannot_bypass_mandatory_protection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, mut candidate) = prepared(&root, format);
        let session = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"local-open".to_vec()).unwrap(),
        );
        let opening = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: candidate.data.clone(),
        };
        let (_, result) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &session,
                &opening,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(result.outcome, DecisionOutcome::Committed { .. }));
        let policy = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: candidate.epoch,
            protection: ReviewProtection {
                administrators: vec![OWNER],
                branches: vec![ProtectedBranch {
                    name: candidate.data.target_ref.clone(),
                    reviewers: vec![REVIEWER, SECOND],
                }],
            },
        };
        let session = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"install-mandatory".to_vec()).unwrap(),
        );
        let (_, result) = node
            .runtime()
            .block_on(node.admit_review_protection_durable_in(
                &node.request_context(),
                &session,
                &policy,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(result.outcome, DecisionOutcome::Committed { .. }));
        candidate.epoch = node
            .runtime()
            .block_on(node.read_review_protection_in(&node.request_context()))
            .unwrap()
            .policy_epoch;
        let before = generation(&node);
        let path = root.0.join("credentials");
        configure(&node, &path);
        let server = Server::start(node, &path, 6, true, false);
        accepted(&send(
            &server.client,
            "reviews/approve",
            'b',
            "first-required",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            false,
        )); // 1
        let weaker = merge_form(&candidate, &[REVIEWER]);
        let blocked = send(
            &server.client,
            "merge",
            'c',
            "weaker-requirements",
            &weaker,
            Some(&candidate.bundle),
            true,
        ); // 2
        refused(&blocked);
        accepted(&send(
            &server.client,
            "reviews/approve",
            'e',
            "second-required",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            true,
        )); // 3
        assert_eq!(
            send(
                &server.client,
                "merge",
                'c',
                "weaker-requirements",
                &weaker,
                None,
                false
            ),
            blocked
        ); // 4
        accepted(&send(
            &server.client,
            "merge",
            'c',
            "all-mandates-satisfied",
            &weaker,
            Some(&candidate.bundle),
            false,
        )); // 5
        let pr = get(&server.client, "/api/v1/pulls/1", 'a'); // 6
        status(&pr, 200);
        assert!(pr.body.contains("\"state\":\"merged\""));
        server.finish();
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 4,
            "two votes, one canonical refusal, one merge"
        );
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs[&candidate.data.target_ref],
            candidate.binding.commit
        );
        node.shutdown().unwrap();
    }
}
