//! Sponsored feedback uses an independent grant over real HTTP requests. The
//! native readers retain their canonical snapshot and visibility boundaries.
use super::*;
use crate::smart_http::server::pulls;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_identity::agent::{PULLS_FEEDBACK_READ, PULLS_READ};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head};

struct FeedbackCredential {
    bearer: String,
    prior: String,
    expired: String,
    grant: AgentCredentialGrant,
}

fn issue_feedback(fixture: &mut Fixture) -> FeedbackCredential {
    let node = reopen(fixture.config.clone());
    let session = |key: &str| {
        LoopbackReceiveSession::authenticated(
            actor(1),
            IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
        )
    };
    let source = RefName::try_new(b"refs/heads/feedback-topic").unwrap();
    let branches = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &node.request_context(),
            &session("feedback-create-topic"),
            &[RefCommand {
                name: source.clone(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(fixture.commit),
                force: false,
            }],
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        branches.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session("feedback-open-pr"),
            &PullRequestCommand {
                number: PullRequestNumber::FIRST,
                expected_version: ExpectedVersion::NewStream,
                action: PullRequestAction::Open,
                data: PullRequestData {
                    source_ref: source,
                    target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                    source_tip: fixture.commit,
                    target_tip: fixture.commit,
                    title: "Feedback without publication".into(),
                    body: "No reviewer or workflow has approved this PR.".into(),
                },
            },
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
    let bearer = format!("fgagent_{}", "f4".repeat(32));
    let prior = format!("fgagent_{}", "f5".repeat(32));
    let expired = format!("fgagent_{}", "f6".repeat(32));
    let grant = AgentCredentialGrant {
        operations: PULLS_FEEDBACK_READ,
        ..fixture.grant
    };
    for (token, issued, key) in [
        (&bearer, grant, "issue-feedback-reader"),
        (
            &prior,
            AgentCredentialGrant {
                operations: 0x6fff,
                ..grant
            },
            "issue-prior-feedback-mask",
        ),
        (
            &expired,
            AgentCredentialGrant {
                issued_at: grant.issued_at - 120,
                expires_at: grant.issued_at - 60,
                ..grant
            },
            "issue-expired-feedback",
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
    FeedbackCredential {
        bearer,
        prior,
        expired,
        grant,
    }
}

#[test]
fn sponsored_feedback_http_reads_require_new_scope_without_other_disclosures() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let feedback = issue_feedback(&mut fixture);
        let mut snapshot = None;
        for family in ["reviews", "checks"] {
            let suffix = format!("/api/v1/pulls/1/{family}?limit=1");
            let response = fixture.request(&feedback.bearer, "GET", &suffix, "", None);
            status(&response, 200);
            let value = decode(&response);
            assert_eq!(field(&value, "found"), &Value::Bool(true));
            assert_eq!(field(&value, family), &Value::Array(Vec::new()));
            if family == "reviews" {
                assert_eq!(field(&value, "pull_request_version"), &json::number(1));
                assert_eq!(field(&value, "merge_authorized"), &Value::Bool(false));
                assert_eq!(field(&value, "next_after"), &Value::Null);
            } else {
                assert_eq!(field(&value, "pull_request_version").text(), Some("1"));
                assert_eq!(field(&value, "merge_permission"), &Value::Null);
                assert_eq!(field(&value, "complete"), &Value::Bool(true));
            }
            let head = field(&value, "snapshot_token").text().unwrap().to_owned();
            if let Some(previous) = &snapshot {
                assert_eq!(previous, &head);
            } else {
                snapshot = Some(head.clone());
            }
            let pinned = fixture.request(
                &feedback.bearer,
                "GET",
                &format!("{suffix}&expected_head={head}"),
                "",
                None,
            );
            status(&pinned, 200);
            assert_eq!(decode(&pinned), value);
            for (token, code) in [
                (&fixture.source, 403),
                (&fixture.legacy, 403),
                (&feedback.prior, 403),
                (&feedback.expired, 401),
            ] {
                status(&fixture.request(token, "GET", &suffix, "", None), code);
            }

            let mut selected = fixture.selected.clone();
            selected.services = selected.services.with(RepositoryHttpService::Source, false);
            let route = std::str::from_utf8(&selected.route).unwrap();
            status(
                &exchange(
                    &selected,
                    &feedback.bearer,
                    "GET",
                    &format!("{route}{suffix}"),
                    "",
                    None,
                ),
                200,
            );
            selected.services = selected.services.with(RepositoryHttpService::Pulls, false);
            status(
                &exchange(
                    &selected,
                    &feedback.bearer,
                    "GET",
                    &format!("{route}{suffix}"),
                    "",
                    None,
                ),
                403,
            );
        }
        let evidence = format!(
            "/api/v1/pulls/1/checks/evidence?check={}&expected_head={}",
            fgit_forge::event::workflow_check::WorkflowCheckId::from_bytes([0x11; 32]),
            snapshot.unwrap()
        );
        for (method, suffix, bytes) in [
            ("GET", "/api/v1/pulls/1", ""),
            ("GET", evidence.as_str(), ""),
            ("POST", "/api/v1/pulls/1/reviews/approve", ""),
            ("POST", "/api/v1/pulls/1/merge", ""),
            ("POST", "/api/v1/source/blob", "object_format=sha256"),
            ("POST", "/git-receive-pack", "0000"),
        ] {
            status(
                &fixture.request(&feedback.bearer, method, suffix, bytes, None),
                403,
            );
        }
        status(
            &fixture.request(
                &feedback.bearer,
                "GET",
                "/api/v1/pulls/1/checks",
                "",
                Some("reads-have-no-transaction"),
            ),
            400,
        );
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        node.shutdown().unwrap();
    }
}

#[test]
fn sponsored_feedback_http_preserves_witness_original_deadline_and_output_ceiling() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let feedback = issue_feedback(&mut fixture);
    let node = reopen(fixture.config.clone());
    for family in ["reviews", "checks"] {
        let raw = format!(
            "GET {}/api/v1/pulls/1/{family} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\n\r\n",
            std::str::from_utf8(&fixture.selected.route).unwrap(),
            feedback.bearer
        );
        let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let selected = pulls::Request::parse(&envelope).unwrap().unwrap();
        assert_eq!(selected.agent_operation(), Some(PULLS_FEEDBACK_READ));
        assert!(selected.preserves_deadline());
        assert!(!selected.is_mutation());
        let mut request = node
            .runtime()
            .block_on(node.authenticate_agent_request_in(
                &node.request_context(),
                feedback.bearer.as_bytes(),
                &IdempotencyKey::new(format!("feedback-budget-{family}").into_bytes()).unwrap(),
                PULLS_FEEDBACK_READ,
                sha256_digest(raw.as_bytes()),
                256 * 1024,
                MAXIMUM as u64,
            ))
            .unwrap();
        for operation in [PULLS_READ, SOURCE_READ] {
            assert!(request.check_operation(&node, operation).is_err());
        }
        let mut granted = fixture.selected.clone();
        granted.credentials = CredentialSource::AgentRequest {
            digest: sha256_digest(feedback.bearer.as_bytes()),
            grant: crate::smart_http::server::credentials::Grant::agent(&request),
        };
        let session = pulls::authenticate(&selected, &envelope, raw.as_bytes(), &granted).unwrap();
        let authentication = session.authenticated_session().unwrap().authentication();
        let witness = authentication.agent_provenance().unwrap();
        assert_eq!(witness.agent(), feedback.grant.agent);
        assert_eq!(witness.sponsor(), feedback.grant.sponsor);
        assert_eq!(
            witness.credential_id(),
            agent_credential_id(feedback.bearer.as_bytes()).unwrap()
        );
        let deadline = GitDaemonSessionDeadline::new(
            node.git_daemon_session_timeout,
            GitDaemonSessionWorkScaling::FLAT,
        );
        let execute = |session: &LoopbackReceiveSession, maximum| {
            pulls::execute(
                &node,
                &selected,
                session,
                BodyFraming::ContentLength(0),
                &mut "".as_bytes(),
                HttpLimits::default(),
                maximum,
                &deadline,
            )
        };
        let mut wire = Vec::new();
        execute(&session, MAXIMUM as u64)
            .unwrap()
            .send(&mut wire, HttpVersion::Http11)
            .unwrap();
        let wire = String::from_utf8(wire).unwrap();
        let exact = wire.split_once("\r\n\r\n").unwrap().1.len() as u64;
        assert!(execute(&session, exact).is_ok());
        assert_eq!(
            execute(&session, exact - 1).err().unwrap().status,
            Status::TooLarge
        );
        request.constrain_deadline(std::time::Instant::now() - Duration::from_secs(1));
        assert!(execute(&request.authenticated_session(), MAXIMUM as u64).is_err());
    }
    assert_eq!(generation(&node), fixture.generation);
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(feedback.bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(feedback.grant),
        },
        feedback.grant.sponsor,
        "revoke-feedback-reader",
    );
    node.shutdown().unwrap();
    for family in ["reviews", "checks"] {
        status(
            &fixture.request(
                &feedback.bearer,
                "GET",
                &format!("/api/v1/pulls/1/{family}"),
                "",
                None,
            ),
            401,
        );
    }
    fixture.selected.nodes.close().unwrap();
}
