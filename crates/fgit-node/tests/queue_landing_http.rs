#![forbid(unsafe_code)]
//! Real authenticated TCP queue landing, reference ceilings and durable recovery.
#[path = "queue_landing_http/support.rs"]
mod support;
use support::*;

use std::io::Write;
use std::net::Shutdown;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_forge::event::queue::QueueAction;
use fgit_forge::{ForgeEventPayload, QueueNumber};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{GitHashAlgorithm, RepositoryIncarnationId};

fn verify_landing(node: &OneNode, candidate: &Candidate, version: u64, order: &[u64]) {
    let request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    assert_eq!(
        materialized.snapshot().refs[&candidate.data.target_ref],
        candidate.data.source_tip
    );
    assert_eq!(
        materialized.snapshot().refs[&candidate.data.source_ref],
        candidate.data.source_tip
    );
    let queue = node
        .runtime()
        .block_on(node.read_queue_in(&request, &Default::default(), QueueNumber::FIRST, None))
        .unwrap();
    let selected = queue.queue.unwrap();
    assert_eq!(selected.version.get(), version);
    assert_eq!(
        selected
            .deterministic_order()
            .iter()
            .map(|number| number.get())
            .collect::<Vec<_>>(),
        order
    );
    assert!(selected.active_batch.is_none());
    let pulls = node
        .runtime()
        .block_on(node.read_pull_requests_in(
            &request,
            &Default::default(),
            0,
            100,
            Some(queue.source_head),
        ))
        .unwrap();
    let merged = &pulls.pull_requests[0].event;
    assert_eq!(merged.version.get(), 2);
    let ForgeEventPayload::MergeCommittedNative(merge) = &merged.payload else {
        panic!("landing must publish the PR's actual native merge");
    };
    assert_eq!(merge.merge_commit, candidate.data.source_tip);
    assert_eq!(merge.source_tip, candidate.data.source_tip);
    assert_eq!(merge.target_tip_before, candidate.data.target_tip);
    assert_eq!(pulls.pull_requests[1].event.version.get(), 1);
}

#[test]
fn http_lands_one_exact_queue_head_and_recovers_lost_response_after_restart_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, candidate, config) = initialized(&root, format, true, true, false);
        let incarnation = node.repository_incarnation_id();
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let original_refs = before.snapshot().refs.clone();
        let original_closure = before.selected_closure().closure().clone();
        let credentials = root.0.join("credentials");
        queue_credentials(
            &node,
            &credentials,
            &format!("exact:{}", hex(candidate.data.target_ref.as_bytes())),
        );
        let body = landing_form(&candidate, incarnation);
        let server = Server::start(node, &credentials, 11, false, true);
        let client = &server.client;
        let historical = get(client, "/api/v1/queues/1", 'a'); // 1
        status(&historical, 200);
        let pin = token(&historical);
        status(
            &queue_post(client, "land", 'b', "management-only", &body, false),
            403,
        ); // 2
        status(
            &queue_post(client, "land", 'f', "old-grants", &body, false),
            403,
        ); // 3
        let stale_body = body.replace("expected_version=2", "expected_version=1");
        let stale = queue_post(client, "land", 'c', "stale-queue", &stale_body, false); // 4
        refused_landing(&stale, "EvidenceStale");
        refused_landing(
            &queue_post(
                client,
                "land",
                'c',
                "stale-pr",
                &body.replace(
                    "expected_pull_request_version=1",
                    "expected_pull_request_version=2",
                ),
                false,
            ),
            "EvidenceStale",
        ); // 5
        refused_landing(
            &queue_post(
                client,
                "land",
                'c',
                "stale-policy",
                &body.replace("expected_policy_epoch=1", "expected_policy_epoch=2"),
                false,
            ),
            "EvidenceStale",
        ); // 6
        refused_landing(
            &queue_post(
                client,
                "land",
                'c',
                "nonhead",
                &body.replace("pull_request=1&", "pull_request=2&"),
                false,
            ),
            "ProtectedRefTransitionDenied",
        ); // 7
        refused_landing(
            &queue_post(
                client,
                "land",
                'c',
                "wrong-source",
                &body.replace(
                    &candidate.data.source_tip.to_string(),
                    &"aa".repeat(format.digest_len()),
                ),
                false,
            ),
            "EvidenceStale",
        ); // 8
        refused_landing(
            &queue_post(
                client,
                "land",
                'c',
                "wrong-target",
                &body.replace(
                    &candidate.data.target_tip.to_string(),
                    &"bb".repeat(format.digest_len()),
                ),
                false,
            ),
            "EvidenceStale",
        ); // 9
        let mut lost = connection(client);
        lost.write_all(&queue_wire(
            client,
            "land",
            'c',
            "lost-landing",
            &body,
            false,
        ))
        .unwrap(); // 10
        lost.shutdown(Shutdown::Write).unwrap();
        drop(lost);
        let original = queue_post(client, "land", 'c', "lost-landing", &body, true); // 11
        landed(&original);
        assert!(!original.body.contains("lost-landing"));
        assert_eq!(server.finish().accepted_sessions(), 11);

        let node = reopen(&config);
        verify_landing(&node, &candidate, 4, &[2]);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let mut expected_refs = original_refs;
        expected_refs.insert(candidate.data.target_ref.clone(), candidate.data.source_tip);
        assert_eq!(selected.snapshot().refs, expected_refs);
        assert_eq!(selected.selected_closure().closure(), &original_closure);
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&node.request_context()))
            .unwrap();
        let landed_batch = history.last().unwrap();
        assert_eq!(landed_batch.batch.decisions.len(), 1);
        assert_eq!(landed_batch.batch.committed_rcrs.len(), 1);
        assert_eq!(landed_batch.forge_events.len(), 3);
        assert!(
            matches!(&landed_batch.forge_events[0].payload, ForgeEventPayload::MergeQueueChangedNative(change) if matches!(&change.action, QueueAction::BatchFormed { entries, .. } if entries.len() == 1 && entries[0].get() == 1))
        );
        assert!(matches!(
            &landed_batch.forge_events[1].payload,
            ForgeEventPayload::MergeCommittedNative(_)
        ));
        assert!(
            matches!(&landed_batch.forge_events[2].payload, ForgeEventPayload::MergeQueueChangedNative(change) if matches!(&change.action, QueueAction::BatchLanded { entries, target_tip, .. } if entries.len() == 1 && *target_tip == candidate.data.source_tip))
        );

        let server = Server::start(node, &credentials, 7, false, true);
        let client = &server.client;
        let current = get(client, "/api/v1/queues/1", 'a'); // 1
        assert!(current.body.contains("\"version\":4"));
        assert!(current.body.contains("\"order\":[2]"));
        assert_eq!(
            get(
                client,
                &format!("/api/v1/queues/1?expected_head={pin}"),
                'a'
            ),
            historical
        ); // 2
        let dequeue = format!(
            "expected_incarnation={incarnation}&object_format={}&expected_version=4&target_ref={}&pull_request=2&reason=withdrawn",
            format.as_str(),
            encode(candidate.data.target_ref.as_bytes())
        );
        let removed = queue_post(client, "dequeue", 'b', "remove-survivor", &dequeue, false); // 3
        accepted(&removed);
        assert!(removed.body.contains("\"refs_changed\":false"));
        assert_eq!(
            queue_post(client, "land", 'c', "lost-landing", &body, false),
            original
        ); // 4
        assert_eq!(
            queue_post(client, "land", 'c', "stale-queue", &stale_body, true),
            stale
        ); // 5
        let reused = queue_post(
            client,
            "land",
            'c',
            "lost-landing",
            &body.replace("expected_version=2", "expected_version=5"),
            false,
        ); // 6
        status(&reused, 409);
        assert!(reused.body.contains("idempotency_key_reuse"));
        let recovered = lookup(client, 'd', "lost-landing"); // 7
        status(&recovered, 200);
        assert!(recovered.body.contains("committed"));
        let original_tx = original
            .body
            .split_once("\"tx_id\":\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        assert!(recovered.body.contains(original_tx));
        assert_eq!(server.finish().accepted_sessions(), 7);
        let node = reopen(&config);
        verify_landing(&node, &candidate, 5, &[]);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs,
            expected_refs
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn landing_deployment_and_credentials_are_independent_and_ref_scope_never_consumes_a_denied_key() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, candidate, config) = initialized(&root, format, false, false, false);
        let incarnation = node.repository_incarnation_id();
        let credentials = root.0.join("credentials");
        let binding = queue_credentials(&node, &credentials, "all");
        let body = landing_form(&candidate, incarnation);
        let early = |client: &Endpoint| {
            request(
                client,
                "POST",
                "/api/v1/queues/1/land",
                'c',
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 60000\r\nExpect: 100-continue\r\nIdempotency-Key: early\r\n",
                &[],
            )
        };
        let server = Server::start(node, &credentials, 1, false, false);
        let denied = exchange(&server.client, &early(&server.client), true);
        status(&denied, 403);
        assert!(!denied.raw.contains("100 Continue"));
        server.finish();

        let config = config.with_http_queue_landings();
        let node = reopen(&config);
        let before = generation(&node);
        write_credentials(&credentials, &binding, "none");
        let server = Server::start(node, &credentials, 20, false, true);
        let client = &server.client;
        let denied = queue_post(client, "land", 'c', "scope-reusable", &body, false); // 1
        status(&denied, 403);
        assert!(denied.body.contains("ref_write_scope_denied"));
        let absent = lookup(client, 'd', "scope-reusable"); // 2
        status(&absent, 200);
        assert!(absent.body.contains("key_not_observed"));
        write_credentials(
            &credentials,
            &binding,
            &format!("exact:{}", hex(candidate.data.source_ref.as_bytes())),
        );
        let wrong_target = queue_post(client, "land", 'c', "scope-reusable", &body, true); // 3
        status(&wrong_target, 403);
        assert!(wrong_target.body.contains("ref_write_scope_denied"));
        let permitted = if format == GitHashAlgorithm::Sha1 {
            format!("exact:{}", hex(candidate.data.target_ref.as_bytes()))
        } else {
            format!("prefix:{}", hex(b"refs/heads/"))
        };
        write_credentials(&credentials, &binding, &permitted);
        let original = queue_post(client, "land", 'c', "scope-reusable", &body, false); // 4
        landed(&original);
        write_credentials(&credentials, &binding, "none");
        status(
            &queue_post(client, "land", 'c', "scope-reusable", &body, false),
            403,
        ); // 5
        let recovered = lookup(client, 'd', "scope-reusable"); // 6
        status(&recovered, 200);
        assert!(recovered.body.contains("committed"));
        status(&get(client, "/api/v1/queues/1", 'a'), 403); // 7
        status(
            &queue_post(client, "enqueue", 'b', "no-management", &body, false),
            403,
        ); // 8
        status(
            &queue_post(client, "land", 'f', "old-grants", &body, false),
            403,
        ); // 9
        replace(&credentials, &binding);
        let revoked = exchange(client, &early(client), true); // 10
        status(&revoked, 401);
        assert!(!revoked.raw.contains("100 Continue"));
        replace(&credentials, "invalid credentials\n");
        status(&exchange(client, &early(client), true), 503); // 11
        let foreign = binding.replace(
            &incarnation.to_string(),
            &RepositoryIncarnationId::from_bytes([9; 16]).to_string(),
        );
        write_credentials(&credentials, &foreign, "all");
        status(&exchange(client, &early(client), true), 503); // 12
        write_credentials(
            &credentials,
            &binding,
            &format!("prefix:{}", hex(b"refs/heads/")),
        );
        assert_eq!(
            queue_post(client, "land", 'c', "scope-reusable", &body, true),
            original
        ); // 13
        let no_key = request(
            client,
            "POST",
            "/api/v1/queues/1/land",
            'c',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
                body.len()
            ),
            body.as_bytes(),
        );
        status(&exchange(client, &no_key, true), 400); // 14
        let cross_site = String::from_utf8(queue_wire(
            client,
            "land",
            'c',
            "never-sealed",
            &body,
            false,
        ))
        .unwrap()
        .replace(
            "Host: local\r\n",
            "Host: local\r\nOrigin: https://untrusted.example\r\n",
        );
        status(&exchange(client, cross_site.as_bytes(), true), 403); // 15
        let wrong_format = body.replace(
            &format!("object_format={}", format.as_str()),
            "object_format=invalid",
        );
        status(
            &queue_post(client, "land", 'c', "never-sealed", &wrong_format, false),
            400,
        ); // 16
        let wrong_incarnation = body.replace(
            &incarnation.to_string(),
            &RepositoryIncarnationId::from_bytes([8; 16]).to_string(),
        );
        status(
            &queue_post(
                client,
                "land",
                'c',
                "never-sealed",
                &wrong_incarnation,
                false,
            ),
            409,
        ); // 17
        status(
            &queue_post(
                client,
                "land",
                'c',
                "never-sealed",
                &format!("{body}&principal=attacker"),
                false,
            ),
            400,
        ); // 18
        status(
            &queue_post(
                client,
                "land",
                'c',
                "never-sealed",
                &body.replace(
                    &candidate.data.source_tip.to_string(),
                    &candidate.data.target_tip.to_string(),
                ),
                false,
            ),
            400,
        ); // 19
        let foreign = lookup(client, 'f', "scope-reusable"); // 20
        status(&foreign, 200);
        assert!(foreign.body.contains("key_not_observed"));
        assert_eq!(server.finish().accepted_sessions(), 20);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before + 1,
            "only the authorized landing creates an authority decision"
        );
        verify_landing(&node, &candidate, 4, &[2]);
        let unobserved = node
            .runtime()
            .block_on(node.recover_transaction_in(
                &node.request_context(),
                &LoopbackReceiveSession::authenticated(
                    MERGER,
                    IdempotencyKey::new(b"never-sealed".to_vec()).unwrap(),
                ),
            ))
            .unwrap();
        assert_eq!(unobserved, RequestRecovery::KeyNotObserved);
        node.shutdown().unwrap();
    }
}

#[test]
fn http_queue_landing_requires_an_actual_exact_candidate_review_and_preserves_the_old_refusal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, candidate, config) = initialized(&root, format, false, true, true);
        let credentials = root.0.join("credentials");
        queue_credentials(
            &node,
            &credentials,
            &format!("exact:{}", hex(candidate.data.target_ref.as_bytes())),
        );
        let body = landing_form(&candidate, node.repository_incarnation_id());
        let server = Server::start(node, &credentials, 4, true, false);
        let client = &server.client;
        let original = queue_post(client, "land", 'c', "before-review", &body, false); // 1
        refused_landing(&original, "EvidenceMissing");
        accepted(&send(
            client,
            "reviews/approve",
            'e',
            "review-exact-source",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            true,
        )); // 2
        assert_eq!(
            queue_post(client, "land", 'c', "before-review", &body, true),
            original
        ); // 3
        landed(&queue_post(
            client,
            "land",
            'c',
            "reviewed-landing",
            &body,
            false,
        )); // 4
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        verify_landing(&node, &candidate, 4, &[2]);
        node.shutdown().unwrap();
    }
}
