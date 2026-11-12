//! Real canonical source grants can acquire the commit for portable source
//! membership without acquiring history, arbitrary-object or publication scope.
use super::*;
use crate::smart_http::server::source;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head};

fn body_bytes(value: &Value) -> Vec<u8> {
    field(value, "body_hex")
        .text()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn sponsored_current_commit_matches_source_coordinates_and_preserves_closed_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let fixture = Fixture::new(&root, format);
        let common = format!("object_format={}&ref=refs/heads/main", format.as_str());
        let response = fixture.post(&fixture.source, "commit", &common);
        status(&response, 200);
        let value = decode(&response);
        assert_eq!(field(&value, "type").text(), Some("source_commit"));
        assert_eq!(
            field(&value, "object_id").text(),
            Some(fixture.commit.to_string().as_str())
        );
        assert_eq!(
            field(&value, "author_identity_verified"),
            &Value::Bool(false)
        );
        assert_eq!(field(&value, "read_only"), &Value::Bool(true));
        assert_eq!(field(&value, "transaction_created"), &Value::Bool(false));
        assert_eq!(field(&value, "published"), &Value::Bool(false));
        assert!(rows(field(&value, "parents")).is_empty());
        let body = body_bytes(&value);
        assert_eq!(
            git_object_id(format, GitObjectKind::Commit, &body),
            fixture.commit
        );
        assert_eq!(body, format!(
            "tree {}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nagent source credential fixture\n",
            field(&value, "root_tree").text().unwrap(),
        ).into_bytes());
        let pin = field(&value, "snapshot_token").text().unwrap();
        let pinned = format!(
            "{common}&expected_head={pin}&expected_commit={}",
            fixture.commit
        );
        let tree = fixture.post(&fixture.source, "tree", &pinned);
        status(&tree, 200);
        let tree = decode(&tree);
        for name in [
            "tenant_id",
            "repository_id",
            "repository_incarnation",
            "object_format",
            "ref",
            "ref_hex",
            "source_head",
            "snapshot_token",
            "source_rcr",
            "source_commit",
            "root_tree",
        ] {
            assert_eq!(field(&value, name), field(&tree, name), "{name}");
        }
        let again = fixture.post(&fixture.source, "commit", &pinned);
        status(&again, 200);
        assert_eq!(decode(&again), value);

        for (token, expected) in [
            (&fixture.metadata, 403),
            (&fixture.legacy, 403),
            (&fixture.expired, 401),
        ] {
            let refused = fixture.post(token, "commit", &common);
            status(&refused, expected);
            assert!(!refused.contains("body_hex"));
        }
        status(&fixture.post(&fixture.source, "log", &common), 403);
        for extra in [
            "&object_id=aa",
            "&commit=aa",
            "&path_hex=61",
            "&limit=1",
            "&after=0",
            "&sponsor_id=admin",
        ] {
            let refused = fixture.post(&fixture.source, "commit", &format!("{common}{extra}"));
            status(&refused, 400);
            assert!(!refused.contains("body_hex"));
        }
        let moved = fixture.post(
            &fixture.source,
            "commit",
            &format!(
                "{common}&expected_commit={}",
                field(&value, "root_tree").text().unwrap(),
            ),
        );
        api_error(&moved, 409, "source_error", "source_commit_moved");
        let missing = fixture.post(
            &fixture.source,
            "commit",
            &common.replace("heads/main", "heads/absent"),
        );
        status(&missing, 404);

        // The new operation also retains the ordinary operator read profile.
        let ordinary = "f".repeat(64);
        let mut selected = fixture.selected.clone();
        selected.credentials = CredentialSource::Static {
            digest: sha256_digest(ordinary.as_bytes()),
            principal: actor(1),
        };
        let route = std::str::from_utf8(&selected.route).unwrap();
        let ordinary = exchange(
            &selected,
            &ordinary,
            "POST",
            &format!("{route}/api/v1/source/commit"),
            &pinned,
            None,
        );
        status(&ordinary, 200);
        assert_eq!(decode(&ordinary), value);
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        node.shutdown().unwrap();
    }
}

#[test]
fn current_commit_http_execution_preserves_exact_output_limit_and_original_agent_deadline() {
    let root = Scratch::new();
    let fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let node = reopen(fixture.config.clone());
    let body = b"object_format=sha256&ref=refs/heads/main";
    let raw = format!(
        "POST {}/api/v1/source/commit HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        std::str::from_utf8(&fixture.selected.route).unwrap(),
        body.len(),
    );
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let selected = source::Request::parse(&envelope).unwrap();
    assert_eq!(selected.agent_operation(), Some(SOURCE_READ));
    let mut request = node
        .runtime()
        .block_on(node.authenticate_agent_request_in(
            &node.request_context(),
            fixture.source.as_bytes(),
            &IdempotencyKey::new(b"current-commit-read-budget".to_vec()).unwrap(),
            SOURCE_READ,
            sha256_digest(raw.as_bytes()),
            256 * 1024,
            MAXIMUM as u64,
        ))
        .unwrap();
    let session = request.authenticated_session();
    let execute = |session: &LoopbackReceiveSession, maximum| {
        source::execute(
            &node,
            &selected,
            session,
            None,
            None,
            BodyFraming::ContentLength(body.len() as u64),
            &mut body.as_slice(),
            HttpLimits::default(),
            maximum,
        )
    };
    let success = execute(&session, MAXIMUM as u64).unwrap();
    let mut wire = Vec::new();
    success.send(&mut wire, HttpVersion::Http11).unwrap();
    let wire = String::from_utf8(wire).unwrap();
    let exact = wire.split_once("\r\n\r\n").unwrap().1.len() as u64;
    assert!(execute(&session, exact).is_ok());
    let refusal = execute(&session, exact - 1).err().unwrap();
    assert_eq!(refusal.status, Status::TooLarge);
    request.constrain_deadline(std::time::Instant::now());
    let expired = request.authenticated_session();
    // execute creates a fresh HTTP phase deadline, but its authority context
    // must inherit the already-expired verified request instead of renewing it.
    let refusal = execute(&expired, MAXIMUM as u64).err().unwrap();
    assert_eq!(refusal.status, Status::Timeout);
    assert_eq!(generation(&node), fixture.generation);
    node.shutdown().unwrap();
    fixture.selected.nodes.close().unwrap();
}

#[test]
fn current_commit_reauthenticates_rotation_and_refuses_the_old_snapshot() {
    let root = Scratch::new();
    let fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let common = "object_format=sha256&ref=refs/heads/main";
    let first = fixture.post(&fixture.source, "commit", common);
    status(&first, 200);
    let first = decode(&first);
    let snapshot = field(&first, "snapshot_token").text().unwrap();
    let node = reopen(fixture.config.clone());
    let rotated = format!("fgagent_{}", "e".repeat(64));
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(rotated.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(fixture.grant),
        },
        fixture.grant.sponsor,
        "current-commit-rotation",
    );
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(fixture.source.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(1).unwrap()),
            action: AgentCredentialAction::Revoke(fixture.grant),
        },
        fixture.grant.sponsor,
        "current-commit-revoke",
    );
    let after = generation(&node);
    node.shutdown().unwrap();
    api_error(
        &fixture.post(&fixture.source, "commit", common),
        401,
        "source_error",
        "unauthorized",
    );
    api_error(
        &fixture.post(
            &rotated,
            "commit",
            &format!("{common}&expected_head={snapshot}"),
        ),
        409,
        "source_error",
        "source_snapshot_moved",
    );
    let current = fixture.post(
        &rotated,
        "commit",
        &format!("{common}&expected_commit={}", fixture.commit),
    );
    status(&current, 200);
    assert_eq!(body_bytes(&decode(&current)), body_bytes(&first));
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(generation(&node), after);
    node.shutdown().unwrap();
}
