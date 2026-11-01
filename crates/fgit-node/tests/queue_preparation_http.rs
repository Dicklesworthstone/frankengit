#![forbid(unsafe_code)]
//! Exact queue-head construction over real HTTP, followed by independent review
//! and atomic landing. No local candidate preparation substitutes for the route.
#[path = "queue_preparation_http/support.rs"]
mod support;
use support::*;

use fgit_authority::key_recovery::RequestRecovery;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::event::queue::QueueAction;
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::{
    AggregateVersion, ExpectedVersion, ForgeEventPayload, PullRequestNumber, QueueNumber,
};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PolicyEpoch};

#[test]
fn remote_exact_queue_head_yields_large_unstaged_artifact_then_reviewed_atomic_landing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = QueueFixture::new(format, true, true, true);
        let original_generation = generation(f.node());
        let original = f
            .node()
            .runtime()
            .block_on(f.node().materialize_admission())
            .unwrap();
        let original_refs = original.snapshot().refs.clone();
        let original_outbox = original.snapshot().outbox.len();
        let original_objects = original.selected_closure().closure().objects().clone();
        let expected_tree = f.expected_tree();
        let profile = match format {
            GitHashAlgorithm::Sha1 => "path-merge-v1",
            GitHashAlgorithm::Sha256 => "exact-renames-v1",
        };
        let command = f.form(&large_message()) + &format!("&profile={profile}");
        let server = f.start(4, true);
        let selected = get(&server.client, "/api/v1/queues/1", 'a');
        status(&selected, 200);
        assert!(selected.body.contains("\"order\":[1,2]"));
        let nonhead = queue_prepare(
            &server.client,
            &replace_field(&command, "pull_request", "2"),
            false,
        );
        assert_eq!(nonhead.status, 409);
        assert!(!nonhead.head.contains("multipart/mixed"));
        let first = queue_prepare(&server.client, &command, false);
        let (candidate, metadata) = extract(&first, f.data.clone());
        assert!(
            candidate.bundle.len() > 24 * 1024,
            "exercise the binary path beyond MCP inline capacity"
        );
        assert_ne!(candidate.binding.commit, f.data.source_tip);
        assert_ne!(candidate.binding.commit, f.data.target_tip);
        assert_eq!(candidate.binding.merge_base, f.native.base);
        let value = document(metadata.as_bytes());
        assert_eq!(text_field(&value, "profile"), profile);
        assert_eq!(
            text_field(field(&value, "candidate"), "tree"),
            expected_tree.to_string()
        );
        assert_eq!(text_field(&value, "snapshot_token"), token(&selected));
        let (path, landing_command) = landing(&metadata);
        assert!(landing_command.contains(&format!("expected_commit={}", candidate.binding.commit)));
        assert_eq!(queue_prepare(&server.client, &command, true), first);
        assert_eq!(server.finish().accepted_sessions(), 4);

        f.reopen();
        assert_eq!(generation(f.node()), original_generation);
        let after = f
            .node()
            .runtime()
            .block_on(f.node().materialize_admission())
            .unwrap();
        assert_eq!(after.snapshot().refs, original_refs);
        assert_eq!(after.snapshot().outbox.len(), original_outbox);
        assert_eq!(
            after.selected_closure().closure().objects(),
            &original_objects
        );
        assert!(
            f.node().read_git_object(candidate.binding.commit).is_err(),
            "download did not stage native objects"
        );
        assert!(matches!(
            f.node()
                .runtime()
                .block_on(f.node().recover_transaction_in(
                    &f.node().request_context(),
                    &session(FOREIGN, "queue-read-no-publication")
                ))
                .unwrap(),
            RequestRecovery::KeyNotObserved
        ));

        // The same exact request is deterministic across server and node restart.
        let server = f.start(7, true);
        assert_eq!(queue_prepare(&server.client, &command, false), first);
        let unreviewed = land(
            &server.client,
            &path,
            "unreviewed-remote-queue",
            &landing_command,
            Some(&candidate.bundle),
            false,
        );
        refused(&unreviewed);
        assert!(unreviewed.body.contains("\"refs_changed\":false"));
        accepted(&send(
            &server.client,
            "reviews/approve",
            'b',
            "review-remote-queue",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            true,
        ));
        let published = land(
            &server.client,
            &path,
            "land-remote-queue",
            &landing_command,
            Some(&candidate.bundle),
            true,
        );
        accepted(&published);
        assert!(
            published
                .body
                .contains("\"name\":\"land-candidate\",\"method\":\"merge-commit\"")
        );
        assert!(published.body.contains("\"refs_changed\":true"));
        assert_eq!(
            land(
                &server.client,
                &path,
                "land-remote-queue",
                &landing_command,
                None,
                false
            ),
            published
        );
        let queue = get(&server.client, "/api/v1/queues/1", 'a');
        status(&queue, 200);
        assert!(queue.body.contains("\"version\":4"));
        assert!(queue.body.contains("\"order\":[2]"));
        let stale = queue_prepare(&server.client, &command, false);
        assert_eq!(stale.status, 409);
        assert!(!stale.head.contains("multipart/mixed"));
        assert_eq!(server.finish().accepted_sessions(), 7);

        f.reopen();
        assert_eq!(
            generation(f.node()),
            original_generation + 3,
            "one refusal, one review, one queue landing"
        );
        let after = f
            .node()
            .runtime()
            .block_on(f.node().materialize_admission())
            .unwrap();
        let mut expected_refs = original_refs;
        expected_refs.insert(f.data.target_ref.clone(), candidate.binding.commit);
        assert_eq!(after.snapshot().refs, expected_refs);
        let commit = f.node().read_git_object(candidate.binding.commit).unwrap();
        let commit = std::str::from_utf8(commit.payload()).unwrap();
        assert!(commit.starts_with(&format!(
            "tree {expected_tree}\nparent {}\nparent {}\n",
            f.data.target_tip, f.data.source_tip,
        )));
        let history = f
            .node()
            .runtime()
            .block_on(f.node().snapshot_history_in(&f.node().request_context()))
            .unwrap();
        let landed = history.last().unwrap();
        assert_eq!(landed.batch.decisions.len(), 1);
        assert_eq!(landed.batch.committed_rcrs.len(), 1);
        assert_eq!(landed.forge_events.len(), 3);
        assert!(matches!(&landed.forge_events[0].payload,
            ForgeEventPayload::MergeQueueChangedNative(change)
                if matches!(&change.action, QueueAction::BatchFormed { entries, .. } if entries == &[PullRequestNumber::FIRST])));
        assert!(
            matches!(&landed.forge_events[1].payload, ForgeEventPayload::MergeCommittedNative(merge)
            if merge.merge_commit == candidate.binding.commit && merge.source_tip == f.data.source_tip && merge.target_tip_before == f.data.target_tip)
        );
        assert!(matches!(&landed.forge_events[2].payload,
            ForgeEventPayload::MergeQueueChangedNative(change)
                if matches!(&change.action, QueueAction::BatchLanded { entries, target_tip, .. }
                    if entries == &[PullRequestNumber::FIRST] && *target_tip == candidate.binding.commit)));

        let server = f.start(1, true);
        assert_eq!(
            land(
                &server.client,
                &path,
                "land-remote-queue",
                &landing_command,
                None,
                false
            ),
            published
        );
        server.finish();
        f.reopen();
        assert_eq!(generation(f.node()), original_generation + 3);
    }
}

#[test]
fn source_pull_and_queue_read_grants_are_required_before_any_continue_or_body() {
    let mut f = QueueFixture::new(GitHashAlgorithm::Sha1, false, true, false);
    let before = generation(f.node());
    let body = f.form(MESSAGE);
    let server = f.start(12, true);
    // Identical principals on several credentials cannot combine their scopes.
    // Queue management/landing and review grants do not substitute for reads.
    for token in ['d', 'e', 'f', 'b', 'c', '0'] {
        let denied = withheld(&server.client, token, "", 4096);
        assert_eq!(denied.status, 403, "{token}: {:?}", denied);
        assert!(!denied.head.contains("100 Continue"));
    }
    assert_eq!(withheld(&server.client, 'z', "", 4096).status, 401);
    let keyed = withheld(
        &server.client,
        'a',
        "Idempotency-Key: read-cannot-publish\r\n",
        4096,
    );
    assert_eq!(keyed.status, 400);
    assert!(!keyed.head.contains("100 Continue"));
    let oversized = withheld(&server.client, 'a', "", 256 * 1024 + 1);
    assert_eq!(oversized.status, 413);
    assert!(!oversized.head.contains("100 Continue"));
    // The allowed credential has no write/landing grant, and landing is disabled.
    let allowed = queue_prepare(&server.client, &body, false);
    let (_, metadata) = extract(&allowed, f.data.clone());
    landing(&metadata);
    let oversized_chunked = queue_prepare(&server.client, &"a".repeat(256 * 1024 + 1), true);
    assert_eq!(oversized_chunked.status, 413);
    let forged = queue_prepare(&server.client, &(body + "&principal=attacker"), false);
    assert_eq!(forged.status, 400);
    assert_eq!(server.finish().accepted_sessions(), 12);
    f.reopen();
    assert_eq!(generation(f.node()), before);
    assert!(matches!(
        f.node()
            .runtime()
            .block_on(f.node().recover_transaction_in(
                &f.node().request_context(),
                &session(FOREIGN, "read-cannot-publish")
            ))
            .unwrap(),
        RequestRecovery::KeyNotObserved
    ));
}

#[test]
fn queue_and_pull_deployment_switches_are_independent_read_boundaries() {
    for (queues, pulls) in [(false, true), (true, false)] {
        let mut f = QueueFixture::new(GitHashAlgorithm::Sha1, false, queues, false);
        let before = generation(f.node());
        let server = f.start(1, pulls);
        let denied = withheld(&server.client, 'a', "", 4096);
        assert_eq!(denied.status, 403);
        assert!(!denied.head.contains("100 Continue"));
        server.finish();
        f.reopen();
        assert_eq!(generation(f.node()), before);
    }
}

#[derive(Clone, Copy, Debug)]
enum Moved {
    Queue,
    PullRequest,
    Source,
    Target,
    Policy,
}
#[test]
fn actual_queue_pull_ref_and_policy_changes_refuse_the_original_preparation_subject() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for moved in [
            Moved::Queue,
            Moved::PullRequest,
            Moved::Source,
            Moved::Target,
            Moved::Policy,
        ] {
            let mut f = QueueFixture::new(format, false, true, false);
            let body = f.form(MESSAGE);
            let node = f.node();
            match moved {
                Moved::Queue => {
                    let command = QueueCommand {
                        number: QueueNumber::FIRST,
                        target_ref: f.data.target_ref.clone(),
                        expected_version: ExpectedVersion::Exactly(
                            AggregateVersion::try_new(2).unwrap(),
                        ),
                        action: QueueCommandAction::Reorder {
                            order: vec![
                                PullRequestNumber::try_new(2).unwrap(),
                                PullRequestNumber::FIRST,
                            ],
                        },
                    };
                    let (_, outcome) = node
                        .runtime()
                        .block_on(node.admit_queue_durable_in(
                            &node.request_context(),
                            &session(ADMIN, "move-queue"),
                            &command,
                            Default::default(),
                        ))
                        .unwrap();
                    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
                }
                Moved::PullRequest => {
                    let command = PullRequestCommand {
                        number: PullRequestNumber::FIRST,
                        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                        action: PullRequestAction::Update,
                        data: f.data.clone(),
                    };
                    let (_, outcome) = node
                        .runtime()
                        .block_on(node.admit_pull_request_durable_in(
                            &node.request_context(),
                            &session(ADMIN, "move-pr"),
                            &command,
                            Default::default(),
                        ))
                        .unwrap();
                    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
                }
                Moved::Source => advance(
                    node,
                    &f.data.source_ref,
                    f.data.source_tip,
                    ADMIN,
                    "advance-source",
                ),
                Moved::Target => advance(
                    node,
                    &f.data.target_ref,
                    f.data.target_tip,
                    ADMIN,
                    "advance-target",
                ),
                Moved::Policy => protect(node, &f.data, ADMIN),
            }
            let before = generation(node);
            let selected = node
                .runtime()
                .block_on(node.materialize_admission())
                .unwrap();
            let refs = selected.snapshot().refs.clone();
            let objects = selected.selected_closure().closure().objects().clone();
            let server = f.start(1, true);
            let response = queue_prepare(&server.client, &body, false);
            assert_eq!(
                response.status,
                409,
                "{moved:?}: {}",
                String::from_utf8_lossy(&response.body)
            );
            assert!(response.head.contains("application/json"));
            assert!(!response.head.contains("multipart/mixed"));
            server.finish();
            f.reopen();
            assert_eq!(generation(f.node()), before, "{moved:?}");
            let selected = f
                .node()
                .runtime()
                .block_on(f.node().materialize_admission())
                .unwrap();
            assert_eq!(selected.snapshot().refs, refs);
            assert_eq!(selected.selected_closure().closure().objects(), &objects);
        }
    }
}

#[test]
fn conflicts_and_already_integrated_heads_return_exact_reports_without_landing_artifacts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for conflict in [false, true] {
            let root = Scratch::new();
            let (node, data) = non_clean_fixture(&root, format, conflict);
            seed_queue(&node, &data, OWNER);
            let before = generation(&node);
            let body = preparation(&node, &data, PolicyEpoch::FIRST, MESSAGE);
            let credentials = root.0.join("queue-credentials");
            grants(
                &credentials,
                &header(&node).replace("credentials-v1", "credentials-v2"),
                &data.target_ref,
            );
            let config = root.config(format).with_http_queue_management();
            node.shutdown().unwrap();
            let server = Server::start(reopen(&config), &credentials, 2, true, false);
            let first = queue_prepare(&server.client, &body, true);
            assert_eq!(first.status, if conflict { 409 } else { 200 });
            assert!(first.head.contains("application/json"));
            let value = document(&first.body);
            assert_eq!(text_field(&value, "type"), "queue_merge_preparation");
            assert_eq!(
                text_field(&value, "state"),
                if conflict {
                    "conflicted"
                } else {
                    "already_up_to_date"
                }
            );
            for field_name in ["candidate", "bundle", "landing"] {
                assert!(matches!(
                    field(&value, field_name),
                    fgit_schema::json::Value::Null
                ));
            }
            assert_eq!(
                field(&value, "transaction_created"),
                &fgit_schema::json::Value::Bool(false)
            );
            assert_eq!(
                field(&value, "objects_staged"),
                &fgit_schema::json::Value::Bool(false)
            );
            if conflict {
                let text = std::str::from_utf8(&first.body).unwrap();
                assert!(text.contains("\"path_hex\":\"66696c65ff2e747874\""));
                assert!(!text.contains('\u{fffd}'));
            }
            assert_eq!(queue_prepare(&server.client, &body, false), first);
            server.finish();
            let node = reopen(&config);
            assert_eq!(generation(&node), before);
            let selected = node
                .runtime()
                .block_on(node.materialize_admission())
                .unwrap();
            assert_eq!(selected.snapshot().refs[&data.source_ref], data.source_tip);
            assert_eq!(selected.snapshot().refs[&data.target_ref], data.target_tip);
            node.shutdown().unwrap();
        }
    }
}
