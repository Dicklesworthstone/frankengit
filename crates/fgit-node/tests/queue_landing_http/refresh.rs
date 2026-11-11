//! Real credential, framing, durable publication and original-outcome recovery.
use super::support::*;
use std::io::Write;
use std::net::Shutdown;

use fgit_admission::merge::native::queue::QueueLandingCommand;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::{
    AggregateVersion, ExpectedVersion, ForgeEventPayload, PullRequestNumber, QueueNumber,
};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, RepositoryIncarnationId};

fn refresh_form(candidate: &Candidate, incarnation: RepositoryIncarnationId) -> String {
    format!(
        concat!(
            "expected_incarnation={}&object_format={}&expected_version=4&expected_policy_epoch={}",
            "&pull_request=2&expected_pull_request_version=1&source_ref={}&target_ref={}",
            "&expected_source_tip={}&expected_recorded_target_tip={}&expected_target_tip={}",
            "&title={}&body={}"
        ),
        incarnation,
        candidate.data.source_tip.algorithm().as_str(),
        candidate.epoch.get(),
        encode(candidate.data.source_ref.as_bytes()),
        encode(candidate.data.target_ref.as_bytes()),
        candidate.data.source_tip,
        candidate.data.target_tip,
        candidate.data.source_tip,
        encode(candidate.data.title.as_bytes()),
        encode(candidate.data.body.as_bytes()),
    )
}

#[test]
fn http_refresh_preserves_fifo_and_recovers_its_original_result_after_metadata_changes_and_restart()
{
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, candidate, config) = initialized(&root, format, true, true, false);
        let incarnation = node.repository_incarnation_id();
        let landing = QueueLandingCommand {
            number: QueueNumber::FIRST,
            expected_version: AggregateVersion::try_new(2).unwrap(),
            expected_policy_epoch: candidate.epoch,
            pull_request: PullRequestNumber::FIRST,
            expected_pull_request_version: AggregateVersion::FIRST,
            source_ref: candidate.data.source_ref.clone(),
            head_tip: candidate.data.source_tip,
            target_ref: candidate.data.target_ref.clone(),
            expected_target_tip: candidate.data.target_tip,
        };
        let (_, landed) = node
            .runtime()
            .block_on(node.land_queue_head_durable_in(
                &node.request_context(),
                &LoopbackReceiveSession::authenticated(
                    OWNER,
                    IdempotencyKey::new(b"refresh-http-land-first".to_vec()).unwrap(),
                ),
                &landing,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(landed.outcome, DecisionOutcome::Committed { .. }));
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let queued = node
            .runtime()
            .block_on(node.read_queue_in(
                &node.request_context(),
                &Default::default(),
                QueueNumber::FIRST,
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert_eq!(queued.version.get(), 4);
        assert_eq!(
            queued.deterministic_order(),
            vec![PullRequestNumber::try_new(2).unwrap()],
        );
        let credentials = root.0.join("credentials");
        let scoped =
            |token, services: &str| format!("{} none\n", row(token, OWNER, services).trim_end());
        replace(
            &credentials,
            &(header(&node).replace("credentials-v1", "credentials-v2")
                + &scoped('b', "queues-write")
                + &scoped('d', "outcomes-read")
                + &scoped('e', "pulls-write")
                + &scoped('f', "pulls-write,queues-write")),
        );
        let body = refresh_form(&candidate, incarnation);
        let stale_body = body.replace("expected_version=4", "expected_version=3");
        let server = Server::start(node, &credentials, 5, true, true);
        let client = &server.client;
        status(
            &queue_post(client, "refresh", 'b', "queue-only", &body, false),
            403,
        );
        status(
            &queue_post(client, "refresh", 'e', "pull-only", &body, false),
            403,
        );
        let stale = queue_post(client, "refresh", 'f', "stale-refresh", &stale_body, false);
        refused(&stale);
        assert!(stale.body.contains("\"refusal_code\":\"EvidenceStale\""));
        assert!(stale.body.contains("\"pull_request_changed\":false"));
        let mut lost = connection(client);
        lost.write_all(&queue_wire(
            client,
            "refresh",
            'f',
            "lost-refresh",
            &body,
            false,
        ))
        .unwrap();
        lost.shutdown(Shutdown::Write).unwrap();
        drop(lost);
        let original = queue_post(client, "refresh", 'f', "lost-refresh", &body, true);
        accepted(&original);
        assert!(original.body.contains("\"name\":\"refresh\""));
        assert!(original.body.contains("\"queue_changed\":false"));
        assert!(original.body.contains("\"refs_changed\":false"));
        assert!(original.body.contains("\"pull_request_changed\":true"));
        assert!(original.body.contains("\"historical_outcome\":true"));
        assert!(!original.body.contains("lost-refresh"));
        assert_eq!(server.finish().accepted_sessions(), 5);

        let node = reopen(&config);
        let after = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(after.snapshot().refs, before.snapshot().refs);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(
            after.basis().body().ref_root,
            before.basis().body().ref_root
        );
        assert_eq!(
            after.selected_closure().closure(),
            before.selected_closure().closure(),
        );
        assert_eq!(
            node.runtime()
                .block_on(node.read_queue_in(
                    &node.request_context(),
                    &Default::default(),
                    QueueNumber::FIRST,
                    None,
                ))
                .unwrap()
                .queue,
            Some(queued.clone()),
        );
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&node.request_context()))
            .unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.decisions.len(), 1);
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.forge_events.len(), 1);
        assert!(matches!(
            &last.forge_events[0].payload,
            ForgeEventPayload::PullRequestChangedNative(change)
                if change.action == PullRequestAction::Update
                    && change.data.target_tip == candidate.data.source_tip
        ));
        let pulls = node
            .runtime()
            .block_on(node.read_pull_requests_in(
                &node.request_context(),
                &Default::default(),
                0,
                100,
                None,
            ))
            .unwrap();
        let refreshed = pulls
            .pull_requests
            .iter()
            .find(|pull| pull.number.get() == 2)
            .unwrap();
        assert_eq!(refreshed.event.version.get(), 2);
        let mut expected_data = candidate.data.clone();
        expected_data.target_tip = candidate.data.source_tip;
        assert_eq!(refreshed.data.as_ref(), Some(&expected_data));

        // A later ordinary metadata edit must never be overwritten by retrying
        // the already committed refresh with its complete original payload.
        expected_data.title.push_str(" (edited after refresh)");
        let changed = PullRequestCommand {
            number: PullRequestNumber::try_new(2).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap()),
            action: PullRequestAction::Update,
            data: expected_data.clone(),
        };
        let (_, edited) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &LoopbackReceiveSession::authenticated(
                    OWNER,
                    IdempotencyKey::new(b"edit-after-http-refresh".to_vec()).unwrap(),
                ),
                &changed,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(edited.outcome, DecisionOutcome::Committed { .. }));
        node.shutdown().unwrap();
        let node = reopen(&config);
        let settled_generation = generation(&node);
        let server = Server::start(node, &credentials, 4, true, true);
        let client = &server.client;
        assert_eq!(
            queue_post(client, "refresh", 'f', "lost-refresh", &body, false),
            original,
        );
        assert_eq!(
            queue_post(client, "refresh", 'f', "stale-refresh", &stale_body, true),
            stale,
        );
        let reused = queue_post(
            client,
            "refresh",
            'f',
            "lost-refresh",
            &body.replace("expected_version=4", "expected_version=5"),
            false,
        );
        status(&reused, 409);
        assert!(reused.body.contains("idempotency_key_reuse"));
        let recovered = lookup(client, 'd', "lost-refresh");
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
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        assert_eq!(generation(&node), settled_generation);
        let pulls = node
            .runtime()
            .block_on(node.read_pull_requests_in(
                &node.request_context(),
                &Default::default(),
                0,
                100,
                None,
            ))
            .unwrap();
        let current = pulls
            .pull_requests
            .iter()
            .find(|pull| pull.number.get() == 2)
            .unwrap();
        assert_eq!(current.event.version.get(), 3);
        assert_eq!(current.data.as_ref(), Some(&expected_data));
        assert_eq!(
            node.runtime()
                .block_on(node.read_queue_in(
                    &node.request_context(),
                    &Default::default(),
                    QueueNumber::FIRST,
                    None,
                ))
                .unwrap()
                .queue,
            Some(queued),
        );
        node.shutdown().unwrap();
    }
}
