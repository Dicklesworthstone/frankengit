use super::*;

#[test]
fn bounded_wait_uses_the_native_limit_and_preserves_all_query_parameters() {
    let token = format!("alg:1:{}", "ab".repeat(32));
    let target = format!(
        "/repo.git/api/v1/events?profile=collaboration-v2&after=2:3&limit=7&expected_head={token}&wait_ms={}",
        OneNode::MAX_FORGE_EVENT_WAIT_MS
    );
    let bytes = raw("GET", &target, "");
    let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
    let query = Request::parse(&envelope).unwrap();
    assert_eq!(query.after, Some((2, 3)));
    assert_eq!(query.limit, 7);
    assert_eq!(query.wait_ms, OneNode::MAX_FORGE_EVENT_WAIT_MS);
    assert_eq!(
        query.expected_head,
        Some(issues::parse_snapshot(&token).unwrap())
    );
    assert_eq!(
        query.disclosure_profile,
        ForgeEventDisclosureProfile::CollaborationV2
    );
    for target in [
        "/repo.git/api/v1/events",
        "/repo.git/api/v1/events?wait_ms=0",
    ] {
        let bytes = raw("GET", target, "");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(Request::parse(&envelope).unwrap().wait_ms, 0);
    }
    for value in [
        "30001",
        "18446744073709551616",
        "-1",
        "1.0",
        "1e3",
        "01",
        "",
    ] {
        let target = format!("/repo.git/api/v1/events?wait_ms={value}");
        let bytes = raw("GET", &target, "");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        let error = Request::parse(&envelope).unwrap_err();
        assert_eq!(error.code, "invalid_event_wait", "{value}");
        assert_eq!(error.status, Status::BadRequest);
    }
    for query in ["wait_ms=1&wait_ms=2", "wait_ms=1&%77ait_ms=2"] {
        let target = format!("/repo.git/api/v1/events?{query}");
        let bytes = raw("GET", &target, "");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(
            Request::parse(&envelope).unwrap_err().status,
            Status::BadRequest
        );
    }
    assert_eq!(read_error("invalid_event_wait").status, Status::BadRequest);
}

#[test]
fn waiting_read_rechecks_revoked_changed_and_reassigned_credentials_before_disclosure() {
    let scratch = Scratch::new();
    let incarnation = RepositoryIncarnationId::from_bytes([0xc4; 16]);
    let binding = Binding {
        tenant: TenantId::from_bytes([0xc1; 16]),
        repository: RepositoryId::from_bytes([0xc2; 16]),
        incarnation,
    };
    let profile = scratch.profile(
        scratch.config(GitHashAlgorithm::Sha1),
        incarnation,
        "issues-read,pulls-read",
    );
    let bytes = raw("GET", "/repo.git/api/v1/events?wait_ms=100", &bearer());
    let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
    let query = Request::parse(&envelope).unwrap();
    let original = authenticate(&profile, &envelope, &query).unwrap();
    assert!(revalidate_wait_grant(&profile, &envelope, &query, original).is_ok());
    scratch.credentials(binding, "issues-read");
    let error = revalidate_wait_grant(&profile, &envelope, &query, original).unwrap_err();
    assert_eq!(error.status, Status::Forbidden);
    assert_eq!(error.code, "event_grant_changed");
    let narrowed = authenticate(&profile, &envelope, &query).unwrap();
    assert!(revalidate_wait_grant(&profile, &envelope, &query, narrowed).is_ok());
    scratch.credentials(binding, "issues-read,pulls-read");
    assert_eq!(
        revalidate_wait_grant(&profile, &envelope, &query, narrowed)
            .unwrap_err()
            .code,
        "event_grant_changed",
        "broadening a grant must not silently reuse the old cursor contract"
    );
    let credentials = scratch.0.join("credentials");
    let reassigned = fs::read_to_string(&credentials).unwrap().replace(
        &PrincipalId::from_bytes([0xc3; 16]).to_string(),
        &PrincipalId::from_bytes([0xc5; 16]).to_string(),
    );
    fs::write(credentials, reassigned).unwrap();
    assert_eq!(
        revalidate_wait_grant(&profile, &envelope, &query, original)
            .unwrap_err()
            .code,
        "event_grant_changed"
    );
    scratch.credentials(binding, "");
    assert_eq!(
        revalidate_wait_grant(&profile, &envelope, &query, original)
            .unwrap_err()
            .status,
        Status::Unauthorized
    );
    scratch.credentials(binding, "issues-read,pulls-read");
    assert!(revalidate_wait_grant(&profile, &envelope, &query, original).is_ok());
    assert!(!scratch.0.join("node").exists());
}

#[test]
fn native_http_wait_returns_ready_pages_and_preserves_the_tail_on_timeout() {
    use crate::LoopbackReceiveSession;
    use fgit_authority::IdempotencyKey;
    use fgit_forge::{
        ExpectedVersion, IssueNumber,
        event::issue::{IssueAction, IssueCommand},
    };

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let incarnation = node.repository_incarnation_id();
        let request = node.request_context();
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xc3; 16]),
            IdempotencyKey::new(b"http-event-wait".to_vec()).unwrap(),
        );
        let command = IssueCommand {
            number: IssueNumber::try_new(1).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "Wait fixture".into(),
                body: "Canonical event".into(),
                labels: vec![],
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default()))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let page = node
            .runtime()
            .block_on(node.read_scoped_forge_events_in(&request, None, 20, None, true, false))
            .unwrap();
        let (sequence, index) = page.resume_after().unwrap();
        let tail = format!("{sequence}:{index}");
        let empty = node
            .runtime()
            .block_on(node.read_scoped_forge_events_in(
                &request,
                page.resume_after(),
                20,
                Some(page.source_head()),
                true,
                false,
            ))
            .unwrap()
            .to_json()
            .unwrap();
        node.shutdown().unwrap();
        let profile = scratch.profile(config, incarnation, "issues-read");
        for (target, expected) in [
            (
                format!(
                    "/repo.git/api/v1/events?wait_ms={}",
                    OneNode::MAX_FORGE_EVENT_WAIT_MS
                ),
                page.to_json().unwrap(),
            ),
            (
                format!("/repo.git/api/v1/events?after={tail}&wait_ms=10"),
                empty,
            ),
        ] {
            let bytes = raw("GET", &target, &bearer());
            let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
            let mut output = Vec::new();
            assert_eq!(serve(&profile, &envelope, &[], &mut output), Ok(()));
            let response = String::from_utf8(output).unwrap();
            assert_eq!(response.split_once("\r\n\r\n").unwrap().1, expected);
        }
        profile.nodes.close().unwrap();
    }
}
