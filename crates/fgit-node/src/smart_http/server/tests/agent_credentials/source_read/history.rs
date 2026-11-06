//! Canonical history credentials cross the real HTTP gateway and native read
//! boundary without gaining current-source, PR, transport or mutation scopes.
use super::*;
use crate::smart_http::server::source;
use fgit_identity::agent::SOURCE_HISTORY_READ;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head};

struct HistoryCredential {
    bearer: String,
    legacy: String,
    expired: String,
    grant: AgentCredentialGrant,
}

fn issue_history(fixture: &mut Fixture) -> HistoryCredential {
    let node = reopen(fixture.config.clone());
    let bearer = format!("fgagent_{}", "e1".repeat(32));
    let legacy = format!("fgagent_{}", "e2".repeat(32));
    let expired = format!("fgagent_{}", "e3".repeat(32));
    let grant = AgentCredentialGrant {
        operations: SOURCE_HISTORY_READ,
        ..fixture.grant
    };
    for (token, issued, key) in [
        (bearer.as_str(), grant, "issue-history-only"),
        (
            legacy.as_str(),
            AgentCredentialGrant {
                operations: 0x00ff,
                ..grant
            },
            "issue-frozen-prior-scopes",
        ),
        (
            expired.as_str(),
            AgentCredentialGrant {
                issued_at: grant.issued_at - 120,
                expires_at: grant.issued_at - 60,
                ..grant
            },
            "issue-expired-history",
        ),
    ] {
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(token.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: AgentCredentialAction::Issue(issued),
            },
            grant.sponsor,
            key,
        );
    }
    fixture.generation = generation(&node);
    node.shutdown().unwrap();
    HistoryCredential {
        bearer,
        legacy,
        expired,
        grant,
    }
}

fn forms(fixture: &Fixture, snapshot: &str) -> Vec<(&'static str, String)> {
    let format = fixture.commit.algorithm().as_str();
    let common = format!("object_format={format}&ref=refs/heads/main");
    let historical = format!(
        "{common}&expected_head={snapshot}&expected_ref_tip={}&at_commit={}",
        fixture.commit, fixture.commit,
    );
    vec![
        ("log", common.clone()),
        (
            "blame",
            format!(
                "{common}&path_hex={}&line_start=0&line_end=2",
                hex(b"source.rs")
            ),
        ),
        ("historical-tree", historical.clone()),
        (
            "historical-blob",
            format!("{historical}&path_hex={}", hex(b"source.rs")),
        ),
        (
            "diff",
            format!(
                "object_format={format}&before_ref=refs/heads/main&after_ref=refs/tags/release"
            ),
        ),
    ]
}

fn snapshot(fixture: &Fixture, credential: &HistoryCredential) -> String {
    let common = format!(
        "object_format={}&ref=refs/heads/main",
        fixture.commit.algorithm().as_str()
    );
    let response = fixture.post(&credential.bearer, "log", &common);
    status(&response, 200);
    field(&decode(&response), "snapshot_token")
        .text()
        .unwrap()
        .to_owned()
}

#[test]
fn sponsored_http_history_routes_require_their_independent_scope_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let history = issue_history(&mut fixture);
        let snapshot = snapshot(&fixture, &history);
        for (action, form) in forms(&fixture, &snapshot) {
            let response = fixture.post(&history.bearer, action, &form);
            status(&response, 200);
            let value = decode(&response);
            assert_eq!(field(&value, "read_only"), &Value::Bool(true));
            match action {
                "log" => assert_eq!(rows(field(&value, "commits")).len(), 1),
                "blame" => {
                    assert_eq!(field(&value, "content_hex"), &Value::String(hex(SOURCE)))
                }
                "historical-tree" | "historical-blob" => {
                    assert_eq!(
                        field(&value, "at_commit").text(),
                        Some(fixture.commit.to_string().as_str())
                    );
                    assert_eq!(
                        field(&value, "selection").text(),
                        Some("visible-ref-ancestor-v1")
                    );
                    if action == "historical-blob" {
                        assert_eq!(
                            field(field(&value, "source"), "content_hex").text(),
                            Some(hex(SOURCE).as_str())
                        );
                    }
                }
                "diff" => assert_eq!(field(&value, "entry_count").unsigned(), Some(0)),
                _ => unreachable!(),
            }
            for (token, expected) in [
                (&fixture.source, 403),
                (&fixture.metadata, 403),
                (&history.legacy, 403),
                (&history.expired, 401),
            ] {
                let refused = fixture.post(token, action, &form);
                status(&refused, expected);
                assert!(!refused.contains(&hex(SOURCE)));
            }
        }
        for action in [
            "commit",
            "tree",
            "blob",
            "search",
            "refs",
            "agent-context",
            "bundle/export",
            "rebase/prepare",
            "cherry-pick/prepare",
        ] {
            status(
                &fixture.post(
                    &history.bearer,
                    action,
                    &format!("object_format={}", format.as_str()),
                ),
                403,
            );
        }
        for (method, suffix, body) in [
            ("GET", "/info/refs?service=git-upload-pack", ""),
            ("POST", "/git-receive-pack", "0000"),
            ("GET", "/api/v1/issues", ""),
            ("GET", "/api/v1/pulls", ""),
            ("POST", "/api/v1/pulls/1/diff", "object_format=sha256"),
        ] {
            status(
                &fixture.request(&history.bearer, method, suffix, body, None),
                403,
            );
        }
        let mut disabled = fixture.selected.clone();
        disabled.services = disabled.services.with(RepositoryHttpService::Source, false);
        let route = std::str::from_utf8(&disabled.route).unwrap();
        status(
            &exchange(
                &disabled,
                &history.bearer,
                "POST",
                &format!("{route}/api/v1/source/log"),
                &format!("object_format={}&ref=refs/heads/main", format.as_str()),
                None,
            ),
            403,
        );
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        node.shutdown().unwrap();
    }
}

#[test]
fn sponsored_http_history_output_limits_and_original_request_deadlines_are_retained() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let history = issue_history(&mut fixture);
    let snapshot = snapshot(&fixture, &history);
    let node = reopen(fixture.config.clone());
    for (action, body) in forms(&fixture, &snapshot) {
        let raw = format!(
            "POST {}/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
            std::str::from_utf8(&fixture.selected.route).unwrap(),
            history.bearer,
            body.len(),
        );
        let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let selected = source::Request::parse(&envelope).unwrap();
        assert_eq!(selected.agent_operation(), Some(SOURCE_HISTORY_READ));
        let mut request = node
            .runtime()
            .block_on(node.authenticate_agent_request_in(
                &node.request_context(),
                history.bearer.as_bytes(),
                &IdempotencyKey::new(format!("history-read-budget-{action}").into_bytes()).unwrap(),
                SOURCE_HISTORY_READ,
                sha256_digest(raw.as_bytes()),
                256 * 1024,
                MAXIMUM as u64,
            ))
            .unwrap();
        let mut granted = fixture.selected.clone();
        granted.credentials = CredentialSource::AgentRequest {
            digest: sha256_digest(history.bearer.as_bytes()),
            grant: crate::smart_http::server::credentials::Grant::agent(&request),
        };
        let (_, current_source) =
            source::authenticate(&selected, &envelope, raw.as_bytes(), &granted).unwrap();
        assert!(current_source.is_none());
        let session = request.authenticated_session();
        let execute = |session: &LoopbackReceiveSession, maximum| {
            source::execute(
                &node,
                &selected,
                session,
                None,
                BodyFraming::ContentLength(body.len() as u64),
                &mut body.as_bytes(),
                HttpLimits::default(),
                maximum,
            )
        };
        let success = execute(&session, MAXIMUM as u64).unwrap();
        let mut wire = Vec::new();
        success.send(&mut wire, HttpVersion::Http11).unwrap();
        let wire = String::from_utf8(wire).unwrap();
        let exact = wire.split_once("\r\n\r\n").unwrap().1.len() as u64;
        assert!(execute(&session, exact).is_ok(), "{action}");
        assert_eq!(
            execute(&session, exact - 1).err().unwrap().status,
            Status::TooLarge,
            "{action}"
        );
        request.constrain_deadline(std::time::Instant::now() - Duration::from_secs(1));
        assert!(
            execute(&request.authenticated_session(), MAXIMUM as u64).is_err(),
            "{action}"
        );
    }
    assert_eq!(generation(&node), fixture.generation);
    node.shutdown().unwrap();
    fixture.selected.nodes.close().unwrap();
}

#[test]
fn sponsored_http_history_revocation_reauthenticates_and_invalidates_old_snapshot_pins() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let history = issue_history(&mut fixture);
    let snapshot = snapshot(&fixture, &history);
    let node = reopen(fixture.config.clone());
    let replacement = format!("fgagent_{}", "e4".repeat(32));
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(replacement.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(history.grant),
        },
        history.grant.sponsor,
        "rotate-history-reader",
    );
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(history.bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(history.grant),
        },
        history.grant.sponsor,
        "revoke-history-reader",
    );
    let after = generation(&node);
    node.shutdown().unwrap();
    for (action, body) in forms(&fixture, &snapshot) {
        status(&fixture.post(&history.bearer, action, &body), 401);
    }
    for action in ["historical-tree", "historical-blob"] {
        let (_, body) = forms(&fixture, &snapshot)
            .into_iter()
            .find(|(name, _)| *name == action)
            .unwrap();
        status(&fixture.post(&replacement, action, &body), 409);
    }
    status(
        &fixture.post(
            &replacement,
            "log",
            "object_format=sha256&ref=refs/heads/main",
        ),
        200,
    );
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(generation(&node), after);
    node.shutdown().unwrap();
}
