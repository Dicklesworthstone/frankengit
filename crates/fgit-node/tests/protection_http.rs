#![forbid(unsafe_code)]
//! Native TCP policy administration against the real persisted authority store.

#[path = "pull_request_http/support.rs"]
mod support;

use fgit_authority::IdempotencyKey;
use fgit_forge::ExpectedVersion;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, RefName};
use support::*;

const PATH: &str = "/api/v1/protection";

fn assert_committed(reply: &Reply) {
    status(reply, 200);
    assert!(
        reply
            .body
            .contains("\"type\":\"review_protection_publication\""),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains("\"outcome\":\"committed\""),
        "{}",
        reply.body
    );
}

fn init(root: &Scratch, format: GitHashAlgorithm, enabled: bool) -> OneNode {
    let mut config = root.config(format);
    if enabled {
        config = config.with_http_protection_admin();
    }
    let (mut node, _) = OneNode::init(config).unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    node
}

fn install(node: &OneNode) -> u64 {
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: before.policy_epoch,
        protection: ReviewProtection {
            administrators: vec![OWNER],
            branches: vec![ProtectedBranch {
                name: RefName::try_new(b"refs/heads/main").unwrap(),
                reviewers: vec![FOREIGN],
            }],
        },
    };
    let session = LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(b"local-policy-bootstrap".to_vec()).unwrap(),
    );
    let result = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    before.policy_epoch.next().unwrap().get()
}

fn policy_form(version: u64, epoch: u64, administrator: PrincipalId, clear: bool) -> String {
    let policy = if clear {
        "clear=true".into()
    } else {
        let reference: String = b"refs/heads/main"
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("required_reviewer={reference}:{FOREIGN}")
    };
    format!(
        "expected_version={version}&expected_epoch={epoch}&administrator={administrator}&{policy}"
    )
}

fn post_policy(endpoint: &Endpoint, token: char, key: Option<&str>, body: &str) -> Reply {
    let key = key.map_or(String::new(), |key| format!("Idempotency-Key: {key}\r\n"));
    let headers = format!(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n{key}",
        body.len()
    );
    exchange(
        endpoint,
        &request(endpoint, "POST", PATH, token, &headers, body.as_bytes()),
        true,
    )
}

#[test]
fn remote_scope_never_bootstraps_canonical_policy_ownership() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let node = init(&root, format, true);
        let credentials = root.0.join("credentials");
        replace(
            &credentials,
            &(header(&node) + &row('a', OWNER, "protection-read,protection-write")),
        );
        let server = Server::start(node, &credentials, 4, false, false);
        let absent = get(&server.client, PATH, 'a');
        status(&absent, 200);
        assert!(absent.body.contains("\"installed\":false"));
        let bootstrap = post_policy(
            &server.client,
            'a',
            Some("remote-bootstrap"),
            &policy_form(0, 1, OWNER, false),
        );
        status(&bootstrap, 403);
        assert!(bootstrap.body.contains("local_bootstrap_required"));
        let invented = post_policy(
            &server.client,
            'a',
            Some("invented-predecessor"),
            &policy_form(1, 1, OWNER, false),
        );
        status(&invented, 409);
        let still_absent = get(&server.client, PATH, 'a');
        status(&still_absent, 200);
        assert!(still_absent.body.contains("\"installed\":false"));
        assert_eq!(server.finish().accepted_sessions(), 4);
    }
}

#[test]
fn administration_scope_and_deployment_ceiling_are_independent() {
    let root = Scratch::new();
    let node = init(&root, GitHashAlgorithm::Sha1, false);
    let epoch = install(&node);
    let credentials = root.0.join("credentials");
    replace(
        &credentials,
        &(header(&node) + &row('a', OWNER, "protection-read,protection-write")),
    );
    let server = Server::start(node, &credentials, 2, true, true);
    status(&get(&server.client, PATH, 'a'), 403);
    status(
        &post_policy(
            &server.client,
            'a',
            Some("disabled-service"),
            &policy_form(1, epoch, OWNER, true),
        ),
        403,
    );
    assert_eq!(server.finish().accepted_sessions(), 2);
}

#[test]
fn canonical_admin_rotation_retries_revocation_and_restart_work_over_real_http() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format).with_http_protection_admin();
        let node = init(&root, format, true);
        let epoch = install(&node);
        let credentials = root.0.join("credentials");
        let header = header(&node);
        replace(
            &credentials,
            &(header.clone()
                + &row('a', OWNER, "protection-read")
                + &row('b', OWNER, "protection-write")
                + &row('c', FOREIGN, "protection-write")
                + &row(
                    'd',
                    FOREIGN,
                    "read,receive,issues-read,issues-write,pulls-read,pulls-write,reviews-read,reviews-write,merges-write",
                )
                + &row('e', OWNER, "outcomes-read")),
        );
        let server = Server::start(node, &credentials, 21, true, true);
        let client = &server.client;
        let initial = get(client, PATH, 'a');
        status(&initial, 200);
        let head = initial
            .body
            .split("\"source_head\":\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let pinned = get(client, &format!("{PATH}?expected_head={head}"), 'a');
        status(&pinned, 200);
        assert_eq!(pinned.body, initial.body, "the returned head token round-trips");
        status(&get(client, PATH, 'b'), 403); // write is not read
        let rotation = policy_form(1, epoch, FOREIGN, false);
        status(
            &post_policy(client, 'a', Some("reader-write"), &rotation),
            403,
        );
        status(&get(client, PATH, 'd'), 403);
        status(
            &post_policy(client, 'd', Some("code-admin"), &rotation),
            403,
        );
        status(
            &post_policy(client, 'c', Some("self-authorize"), &rotation),
            409,
        );
        status(&post_policy(client, 'b', None, &rotation), 400);
        status(
            &post_policy(
                client,
                'b',
                Some("wrong-epoch"),
                &policy_form(1, epoch + 1, FOREIGN, false),
            ),
            409,
        );
        status(
            &post_policy(
                client,
                'b',
                Some("wrong-version"),
                &policy_form(2, epoch, FOREIGN, false),
            ),
            409,
        );
        let first = post_policy(client, 'b', Some("rotate-admin"), &rotation);
        assert_committed(&first);
        let retry = post_policy(client, 'b', Some("rotate-admin"), &rotation);
        assert_eq!(
            retry.body, first.body,
            "a historical retry survives removal of its administrator"
        );
        status(
            &post_policy(
                client,
                'b',
                Some("rotate-admin"),
                &policy_form(1, epoch, FOREIGN, true),
            ),
            409,
        );
        status(
            &post_policy(
                client,
                'b',
                Some("removed-admin"),
                &policy_form(2, epoch + 1, OWNER, true),
            ),
            409,
        );
        let clear = post_policy(
            client,
            'c',
            Some("new-admin-clear"),
            &policy_form(2, epoch + 1, FOREIGN, true),
        );
        assert_committed(&clear);
        status(
            &get(client, &format!("{PATH}?expected_head={head}"), 'a'),
            409,
        );
        let current = get(client, PATH, 'a');
        status(&current, 200);
        assert!(current.body.contains("\"version\":\"3\""));
        assert!(current.body.contains("\"enabled\":false"));
        assert!(
            current
                .body
                .contains(&format!("\"administrators\":[\"{FOREIGN}\"]"))
        );
        replace(
            &credentials,
            &(header.clone()
                + &row('a', OWNER, "protection-read")
                + &row('c', FOREIGN, "protection-write")
                + &row('e', OWNER, "outcomes-read")
                + &row('f', OWNER, "protection-write")),
        );
        status(
            &post_policy(client, 'b', Some("rotate-admin"), &rotation),
            401,
        );
        let token_rotated = post_policy(client, 'f', Some("rotate-admin"), &rotation);
        assert_eq!(token_rotated.body, first.body);
        let recovered = exchange(
            client,
            &request(
                client,
                "POST",
                "/api/v1/outcomes",
                'e',
                "Idempotency-Key: rotate-admin\r\nContent-Length: 0\r\n",
                &[],
            ),
            true,
        );
        status(&recovered, 200);
        assert!(recovered.body.contains("committed"));
        let again = get(client, PATH, 'a');
        assert_eq!(
            again.body, current.body,
            "token changes and terminal retries never republish"
        );
        assert_eq!(server.finish().accepted_sessions(), 21);
        let reopened = reopen(&config);
        let server = Server::start(reopened, &credentials, 3, false, true);
        assert_eq!(get(&server.client, PATH, 'a').body, current.body);
        assert_eq!(
            post_policy(&server.client, 'f', Some("rotate-admin"), &rotation).body,
            first.body
        );
        assert_eq!(get(&server.client, PATH, 'a').body, current.body);
        assert_eq!(server.finish().accepted_sessions(), 3);
    }
}

#[test]
fn browser_credentials_cross_site_requests_and_chunked_forms_keep_existing_boundaries() {
    let root = Scratch::new();
    let node = init(&root, GitHashAlgorithm::Sha1, true);
    let epoch = install(&node);
    let credentials = root.0.join("credentials");
    replace(
        &credentials,
        &(header(&node) + &row('a', OWNER, "protection-read,protection-write")),
    );
    let server = Server::start(node, &credentials, 5, false, false);
    let client = &server.client;
    let before = get(client, PATH, 'a'); // 1
    let body = policy_form(1, epoch, OWNER, true);
    let headers = format!(
        "Origin: https://foreign.invalid\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: cross-site\r\n",
        body.len()
    );
    status(
        &exchange(
            client,
            &request(client, "POST", PATH, 'a', &headers, body.as_bytes()),
            true,
        ),
        403,
    ); // 2
    let raw = String::from_utf8(request(client, "GET", PATH, 'a', "", &[]))
        .unwrap()
        .replace(
            &format!("Bearer {}", "a".repeat(64)),
            // A valid provisioned token in HTTP Basic must still be refused;
            // this checks the transport boundary, not an invalid password.
            "Basic dXNlcjphYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh",
        );
    status(&exchange(client, raw.as_bytes(), true), 401); // 3
    assert_eq!(get(client, PATH, 'a').body, before.body); // 4
    let wire = format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
    let headers = "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nIdempotency-Key: chunked-clear\r\n";
    assert_committed(&exchange(
        client,
        &request(client, "POST", PATH, 'a', headers, wire.as_bytes()),
        true,
    )); // 5
    assert_eq!(server.finish().accepted_sessions(), 5);
}
