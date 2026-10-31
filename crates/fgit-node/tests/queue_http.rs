#![forbid(unsafe_code)]
//! Real TCP credentials -> queue admission -> persisted canonical state.
#[path = "pull_request_http/support.rs"]
mod support;

use std::io::Write;
use std::net::Shutdown;

use fgit_authority::IdempotencyKey;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, RepositoryIncarnationId};
use support::*;

fn initialized(
    root: &Scratch,
    format: GitHashAlgorithm,
    enabled: bool,
) -> (OneNode, PullRequestData, NodeConfig) {
    let (node, data) = fixture(root, format);
    for number in [7, 8] {
        let session = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(format!("queue-http-pr-{number}").into_bytes()).unwrap(),
        );
        let command = PullRequestCommand {
            number: PullRequestNumber::try_new(number).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: data.clone(),
        };
        let result = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &session,
                &command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            result.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
    }
    node.shutdown().unwrap();
    let config = if enabled {
        root.config(format).with_http_queue_management()
    } else {
        root.config(format)
    };
    (reopen(&config), data, config)
}

fn queue_grants(node: &OneNode, path: &std::path::Path) -> String {
    let binding = header(node);
    replace(
        path,
        &(binding.clone()
            + &row('a', OWNER, "queues-read")
            + &row('b', FOREIGN, "queues-write")
            + &row('c', FOREIGN, "outcomes-read")
            + &row(
                'd',
                OWNER,
                "read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write,protection-read,protection-write,lfs-read,lfs-write,artifact-read",
            )),
    );
    binding
}

fn base(data: &PullRequestData, incarnation: RepositoryIncarnationId, version: u64) -> String {
    format!(
        "expected_incarnation={incarnation}&object_format={}&expected_version={version}&target_ref={}",
        data.source_tip.algorithm().as_str(),
        encode(data.target_ref.as_bytes())
    )
}
fn enqueue(
    data: &PullRequestData,
    incarnation: RepositoryIncarnationId,
    version: u64,
    pr: u64,
) -> String {
    format!(
        "{}&pull_request={pr}&expected_pull_request_version=1&source_ref={}&expected_source_tip={}&expected_target_tip={}",
        base(data, incarnation, version),
        encode(data.source_ref.as_bytes()),
        data.source_tip,
        data.target_tip
    )
}
fn queue_wire(
    endpoint: &Endpoint,
    number: u64,
    action: &str,
    token: char,
    key: Option<&str>,
    body: &str,
    chunked: bool,
) -> Vec<u8> {
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.as_bytes().chunks(13) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".into())
    } else {
        (
            body.as_bytes().to_vec(),
            format!("Content-Length: {}\r\n", body.len()),
        )
    };
    let key = key.map_or(String::new(), |key| format!("Idempotency-Key: {key}\r\n"));
    request(
        endpoint,
        "POST",
        &format!("/api/v1/queues/{number}/{action}"),
        token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}{key}"),
        &wire,
    )
}
fn queue_post(
    endpoint: &Endpoint,
    number: u64,
    action: &str,
    token: char,
    key: &str,
    body: &str,
    chunked: bool,
) -> Reply {
    exchange(
        endpoint,
        &queue_wire(endpoint, number, action, token, Some(key), body, chunked),
        true,
    )
}
fn queue_committed(reply: &Reply) {
    status(reply, 200);
    assert!(reply.body.contains("\"type\":\"merge_queue_publication\""));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    assert!(reply.body.contains("\"refs_changed\":false"));
    assert!(reply.body.contains("\"delivery_acknowledged\":null"));
}

#[test]
fn queue_http_persists_exact_order_snapshots_actor_retries_and_outcomes_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, data, config) = initialized(&root, format, true);
        let incarnation = node.repository_incarnation_id();
        let refs = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .snapshot()
            .refs
            .clone();
        let credentials = root.0.join("credentials");
        queue_grants(&node, &credentials);
        let server = Server::start(node, &credentials, 25, false, true);
        let client = &server.client;
        let first_body = enqueue(&data, incarnation, 0, 7);
        let original = queue_post(
            client,
            1,
            "enqueue",
            'b',
            "original-queue-key",
            &first_body,
            false,
        ); // 1
        queue_committed(&original);
        assert!(
            original
                .body
                .contains(&format!("\"principal_id\":\"{FOREIGN}\""))
        );
        assert!(!original.body.contains("original-queue-key"));
        assert_eq!(
            queue_post(
                client,
                1,
                "enqueue",
                'b',
                "original-queue-key",
                &first_body,
                true
            ),
            original
        ); // 2
        queue_committed(&queue_post(
            client,
            1,
            "enqueue",
            'b',
            "second-entry",
            &enqueue(&data, incarnation, 1, 8),
            false,
        )); // 3
        queue_committed(&queue_post(
            client,
            2,
            "enqueue",
            'b',
            "second-queue",
            &first_body,
            false,
        )); // 4
        let page = get(client, "/api/v1/queues?limit=1", 'a'); // 5
        status(&page, 200);
        assert!(page.body.contains("\"next_after\":1"));
        let pinned = token(&page);
        let reordered = format!("{}&entry=8&entry=7", base(&data, incarnation, 2));
        queue_committed(&queue_post(
            client, 1, "reorder", 'b', "reorder", &reordered, false,
        )); // 6
        let historical = get(
            client,
            &format!("/api/v1/queues/1?expected_head={pinned}"),
            'a',
        ); // 7
        status(&historical, 200);
        assert!(historical.body.contains("\"version\":2"));
        assert!(historical.body.contains("\"order\":[7,8]"));
        assert!(
            historical
                .body
                .contains(&format!("\"enqueued_by\":\"{FOREIGN}\""))
        );
        let current = get(client, "/api/v1/queues/1", 'a'); // 8
        status(&current, 200);
        assert!(current.body.contains("\"order\":[8,7]"));
        let next = get(
            client,
            &format!("/api/v1/queues?limit=1&after=1&expected_head={pinned}"),
            'a',
        ); // 9
        status(&next, 200);
        assert_eq!(token(&next), pinned);
        assert!(next.body.contains("\"number\":2"));
        let stale_body = format!(
            "{}&pull_request=8&reason=withdrawn",
            base(&data, incarnation, 2)
        );
        let stale = queue_post(client, 1, "dequeue", 'b', "stale", &stale_body, false); // 10
        status(&stale, 409);
        assert!(stale.body.contains("\"refusal_code\":\"EvidenceStale\""));
        assert_eq!(
            queue_post(client, 1, "dequeue", 'b', "stale", &stale_body, true),
            stale
        ); // 11
        queue_committed(&queue_post(
            client,
            1,
            "dequeue",
            'b',
            "dequeue",
            &format!(
                "{}&pull_request=8&reason=withdrawn",
                base(&data, incarnation, 3)
            ),
            false,
        )); // 12
        assert_eq!(
            queue_post(
                client,
                1,
                "enqueue",
                'b',
                "original-queue-key",
                &first_body,
                false
            ),
            original
        ); // 13
        let reused = queue_post(
            client,
            1,
            "enqueue",
            'b',
            "original-queue-key",
            &format!("{first_body}&priority=5"),
            false,
        ); // 14
        status(&reused, 409);
        assert!(reused.body.contains("idempotency_key_reuse"));
        assert!(!reused.body.contains("\"outcome\":\"refused\""));
        let absent = get(client, "/api/v1/queues/99", 'a'); // 15
        status(&absent, 404);
        assert!(absent.body.contains("\"found\":false"));
        let recovered = exchange(
            client,
            &request(
                client,
                "POST",
                "/api/v1/outcomes",
                'c',
                "Idempotency-Key: original-queue-key\r\nContent-Length: 0\r\n",
                &[],
            ),
            true,
        ); // 16
        status(&recovered, 200);
        assert!(recovered.body.contains("committed"));
        status(&get(client, "/api/v1/queues", 'b'), 403); // 17
        status(
            &queue_post(client, 1, "enqueue", 'a', "read-only", &first_body, false),
            403,
        ); // 18
        status(
            &queue_post(client, 1, "enqueue", 'd', "old-grants", &first_body, false),
            403,
        ); // 19
        let stale_pr = enqueue(&data, incarnation, 4, 8).replace(
            "expected_pull_request_version=1",
            "expected_pull_request_version=2",
        );
        let stale_pr_reply = queue_post(client, 1, "enqueue", 'b', "stale-pr", &stale_pr, false); // 20
        status(&stale_pr_reply, 409);
        assert!(stale_pr_reply.body.contains("EvidenceStale"));
        status(&get(client, "/api/v1/queues?after=1", 'a'), 400); // 21
        let foreign_incarnation = RepositoryIncarnationId::from_bytes([9; 16]);
        let wrong_inc = queue_post(
            client,
            1,
            "enqueue",
            'b',
            "wrong-incarnation",
            &enqueue(&data, foreign_incarnation, 4, 8),
            false,
        ); // 22
        status(&wrong_inc, 409);
        assert!(wrong_inc.body.contains("repository_incarnation_mismatch"));
        let spoofed = queue_post(
            client,
            1,
            "enqueue",
            'b',
            "actor-spoof",
            &format!("{}&principal={OWNER}", enqueue(&data, incarnation, 4, 8)),
            false,
        ); // 23
        status(&spoofed, 400);
        let lost_body = enqueue(&data, incarnation, 4, 8);
        let mut lost = connection(client);
        lost.write_all(&queue_wire(
            client,
            1,
            "enqueue",
            'b',
            Some("lost-reply"),
            &lost_body,
            false,
        ))
        .unwrap(); // 24
        lost.shutdown(Shutdown::Write).unwrap();
        drop(lost);
        queue_committed(&queue_post(
            client,
            1,
            "enqueue",
            'b',
            "lost-reply",
            &lost_body,
            false,
        )); // 25
        server.finish();

        let node = reopen(&config);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs,
            refs
        );
        let queue = node
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
        assert_eq!(queue.version.get(), 5);
        assert_eq!(queue.entries.len(), 2);
        assert!(
            queue
                .entries
                .iter()
                .all(|entry| entry.enqueued_by == FOREIGN)
        );
        let server = Server::start(node, &credentials, 2, false, false);
        assert_eq!(
            queue_post(
                &server.client,
                1,
                "enqueue",
                'b',
                "original-queue-key",
                &first_body,
                true
            ),
            original
        );
        let reopened = get(&server.client, "/api/v1/queues/1", 'a');
        status(&reopened, 200);
        assert!(reopened.body.contains("\"version\":5"));
        server.finish();
    }
}

#[test]
fn queue_http_ceiling_revocation_incarnation_and_early_authentication_fail_closed() {
    let root = Scratch::new();
    let (node, data, config) = initialized(&root, GitHashAlgorithm::Sha1, false);
    let incarnation = node.repository_incarnation_id();
    let credentials = root.0.join("credentials");
    let binding = queue_grants(&node, &credentials);
    let server = Server::start(node, &credentials, 1, false, false);
    status(&get(&server.client, "/api/v1/queues", 'a'), 403);
    server.finish();

    let node = reopen(&config.with_http_queue_management());
    let before = generation(&node);
    let server = Server::start(node, &credentials, 8, false, false);
    let client = &server.client;
    let body = enqueue(&data, incarnation, 0, 7);
    status(&get(client, "/api/v1/queues", 'f'), 401); // 1
    let no_key = exchange(
        client,
        &queue_wire(client, 1, "enqueue", 'b', None, &body, false),
        true,
    ); // 2
    status(&no_key, 400);
    // Request-supplied identity and malformed bodies never acquire a seal.
    let unknown = queue_post(
        client,
        1,
        "enqueue",
        'b',
        "reusable-input-key",
        &format!("{body}&trusted_local=true"),
        false,
    ); // 3
    status(&unknown, 400);
    replace(
        &credentials,
        &(binding.clone() + &row('a', OWNER, "queues-read")),
    );
    let early = request(
        client,
        "POST",
        "/api/v1/queues/1/enqueue",
        'b',
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 60000\r\nExpect: 100-continue\r\nIdempotency-Key: revoked\r\n",
        &[],
    );
    let denied = exchange(client, &early, true); // 4
    status(&denied, 401);
    assert!(!denied.raw.contains("100 Continue"));
    replace(&credentials, "malformed credentials\n");
    status(&get(client, "/api/v1/queues", 'a'), 503); // 5
    let wrong = binding.replace(
        &incarnation.to_string(),
        &RepositoryIncarnationId::from_bytes([9; 16]).to_string(),
    );
    replace(&credentials, &(wrong + &row('a', OWNER, "queues-read")));
    status(&get(client, "/api/v1/queues", 'a'), 503); // 6
    // v2 none restricts ref writes, not explicitly granted metadata intent.
    let scoped = binding.replace("credentials-v1", "credentials-v2");
    let row = row('b', FOREIGN, "queues-write");
    replace(&credentials, &format!("{scoped}{} none\n", row.trim_end()));
    let valid = queue_post(
        client,
        1,
        "enqueue",
        'b',
        "reusable-input-key",
        &body,
        false,
    ); // 7
    queue_committed(&valid);
    let mut cross_site = queue_wire(client, 1, "enqueue", 'b', Some("cross-site"), &body, false);
    let text = String::from_utf8(cross_site).unwrap().replace(
        "Host: local\r\n",
        "Host: local\r\nOrigin: https://untrusted.example\r\n",
    );
    cross_site = text.into_bytes();
    status(&exchange(client, &cross_site, true), 403); // 8
    server.finish();
    let node = reopen(&root.config(GitHashAlgorithm::Sha1));
    assert_eq!(generation(&node), before + 1);
    let queue = node
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
    assert_eq!(queue.version.get(), 1);
    node.shutdown().unwrap();
}
