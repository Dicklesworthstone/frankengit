//! Sponsored PR diffs use a separate canonical grant, real HTTP framing and
//! the same native comparison of recorded tips as ordinary operator readers.
use super::*;
use crate::smart_http::server::pulls;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::preparation::MergeMetadata;
use fgit_identity::agent::{PULLS_DIFF_READ, PULLS_READ, SOURCE_HISTORY_READ};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head};

const TOPIC: &[u8] = b"refs/heads/review-topic";
const CHANGE: &[u8] = b"review only this source\n";

struct DiffCredential {
    bearer: String,
    prior: String,
    expired: String,
    tip: GitOid,
    grant: AgentCredentialGrant,
}

fn session(retry: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        actor(1),
        IdempotencyKey::new(retry.as_bytes().to_vec()).unwrap(),
    )
}

fn edit(node: &OneNode, before: GitOid, path: &str, retry: &str) -> GitOid {
    let reference = RefName::try_new(TOPIC).unwrap();
    let request = node.request_context();
    let patch = format!(
        "diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+review only this source\n"
    );
    let candidate = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            &reference,
            before,
            [0xf1; 16],
            patch.as_bytes(),
            &MergeMetadata {
                author: "A <a@example.invalid>".into(),
                committer: "A <a@example.invalid>".into(),
                timestamp: 2,
                message: b"PR source fixture\n".to_vec(),
            },
            Default::default(),
        ))
        .unwrap();
    let result = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            actor(1),
            retry.as_bytes(),
            &reference,
            before,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    candidate.candidate_commit
}

fn issue_diff(fixture: &mut Fixture) -> DiffCredential {
    let node = reopen(fixture.config.clone());
    let branch = RefCommand {
        name: RefName::try_new(TOPIC).unwrap(),
        expected_old: ExpectedOld::Absent,
        proposed_new: ProposedNew::Update(fixture.commit),
        force: false,
    };
    let branch = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &node.request_context(),
            &session("diff-create-topic"),
            &[branch],
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        branch.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let tip = edit(
        &node,
        fixture.commit,
        "candidate.txt",
        "diff-create-candidate",
    );
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session("diff-open-pr"),
            &PullRequestCommand {
                number: PullRequestNumber::FIRST,
                expected_version: ExpectedVersion::NewStream,
                action: PullRequestAction::Open,
                data: PullRequestData {
                    source_ref: RefName::try_new(TOPIC).unwrap(),
                    target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                    source_tip: tip,
                    target_tip: fixture.commit,
                    title: "Read exact PR source".into(),
                    body: "Not an approval".into(),
                },
            },
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let bearer = format!("fgagent_{}", "f1".repeat(32));
    let prior = format!("fgagent_{}", "f2".repeat(32));
    let expired = format!("fgagent_{}", "f3".repeat(32));
    let grant = AgentCredentialGrant {
        operations: PULLS_DIFF_READ,
        ..fixture.grant
    };
    for (token, issued, key) in [
        (&bearer, grant, "issue-diff-reader"),
        (
            &prior,
            AgentCredentialGrant {
                operations: 0x0fff,
                ..grant
            },
            "issue-prior-diff-mask",
        ),
        (
            &expired,
            AgentCredentialGrant {
                issued_at: grant.issued_at - 120,
                expires_at: grant.issued_at - 60,
                ..grant
            },
            "issue-expired-diff",
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
    DiffCredential {
        bearer,
        prior,
        expired,
        tip,
        grant,
    }
}

fn body(fixture: &Fixture) -> String {
    format!(
        "object_format={}&expected_version=1",
        fixture.commit.algorithm().as_str()
    )
}

#[test]
fn sponsored_http_pull_diff_uses_recorded_tips_and_preserves_existing_scope_boundaries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let diff = issue_diff(&mut fixture);
        let form = body(&fixture);
        let read = |token: &str, form: &str| {
            fixture.request(token, "POST", "/api/v1/pulls/1/diff", form, None)
        };
        let response = read(&diff.bearer, &form);
        status(&response, 200);
        let value = decode(&response);
        assert_eq!(
            field(&value, "requested_before").text(),
            Some(fixture.commit.to_string().as_str())
        );
        assert_eq!(
            field(&value, "requested_after").text(),
            Some(diff.tip.to_string().as_str())
        );
        assert_eq!(field(&value, "entry_count").unsigned(), Some(1));
        assert_eq!(field(&value, "published"), &Value::Bool(false));
        assert_eq!(field(&value, "approval_created"), &Value::Bool(false));
        assert!(response.contains(&hex(CHANGE)));
        let snapshot = field(&value, "snapshot_token").text().unwrap();
        for (token, expected) in [
            (&fixture.source, 403),
            (&fixture.legacy, 403),
            (&diff.prior, 403),
            (&diff.expired, 401),
        ] {
            let refusal = read(token, &form);
            status(&refusal, expected);
            assert!(!refusal.contains(&hex(CHANGE)));
        }
        status(
            &read(&diff.bearer, &format!("object_format={}", format.as_str())),
            400,
        );
        status(
            &read(
                &diff.bearer,
                &form.replace("expected_version=1", "expected_version=2"),
            ),
            409,
        );
        status(
            &fixture.request(
                &diff.bearer,
                "POST",
                "/api/v1/pulls/1/diff",
                &form,
                Some("not-a-transaction"),
            ),
            400,
        );
        for (method, suffix, bytes) in [
            ("GET", "/api/v1/pulls/1", ""),
            ("POST", "/api/v1/source/blob", "object_format=sha256"),
            ("POST", "/api/v1/source/diff", "object_format=sha256"),
            ("POST", "/git-receive-pack", "0000"),
            ("GET", "/info/refs?service=git-upload-pack", ""),
        ] {
            status(
                &fixture.request(&diff.bearer, method, suffix, bytes, None),
                403,
            );
        }
        for service in [RepositoryHttpService::Source, RepositoryHttpService::Pulls] {
            let mut disabled = fixture.selected.clone();
            disabled.services = disabled.services.with(service, false);
            let route = std::str::from_utf8(&disabled.route).unwrap();
            status(
                &exchange(
                    &disabled,
                    &diff.bearer,
                    "POST",
                    &format!("{route}/api/v1/pulls/1/diff"),
                    &form,
                    None,
                ),
                403,
            );
        }
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        let moved = edit(&node, diff.tip, "later.txt", "move-diff-topic");
        assert_ne!(moved, diff.tip);
        let after = generation(&node);
        node.shutdown().unwrap();
        status(
            &read(&diff.bearer, &format!("{form}&expected_head={snapshot}")),
            409,
        );
        let response = read(&diff.bearer, &form);
        status(&response, 200);
        let value = decode(&response);
        assert_eq!(
            field(&value, "requested_after").text(),
            Some(diff.tip.to_string().as_str())
        );
        assert_eq!(field(&value, "entry_count").unsigned(), Some(1));
        assert!(!response.contains(&hex(b"later.txt")));
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), after);
        node.shutdown().unwrap();
    }
}

#[test]
fn sponsored_http_pull_diff_preserves_agent_witness_deadline_and_output_limit() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let diff = issue_diff(&mut fixture);
    let body = body(&fixture);
    let node = reopen(fixture.config.clone());
    let raw = format!(
        "POST {}/api/v1/pulls/1/diff HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        std::str::from_utf8(&fixture.selected.route).unwrap(),
        diff.bearer,
        body.len()
    );
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let selected = pulls::Request::parse(&envelope).unwrap().unwrap();
    assert_eq!(selected.agent_operation(), Some(PULLS_DIFF_READ));
    assert!(selected.preserves_deadline());
    let mut request = node
        .runtime()
        .block_on(node.authenticate_agent_request_in(
            &node.request_context(),
            diff.bearer.as_bytes(),
            &IdempotencyKey::new(b"diff-budget".to_vec()).unwrap(),
            PULLS_DIFF_READ,
            sha256_digest(raw.as_bytes()),
            256 * 1024,
            MAXIMUM as u64,
        ))
        .unwrap();
    for scope in [PULLS_READ, SOURCE_HISTORY_READ] {
        assert!(request.check_operation(&node, scope).is_err());
    }
    let mut granted = fixture.selected.clone();
    granted.credentials = CredentialSource::AgentRequest {
        digest: sha256_digest(diff.bearer.as_bytes()),
        grant: crate::smart_http::server::credentials::Grant::agent(&request),
    };
    let session = pulls::authenticate(&selected, &envelope, raw.as_bytes(), &granted).unwrap();
    let authentication = session.authenticated_session().unwrap().authentication();
    let witness = authentication.agent_provenance().unwrap();
    assert_eq!(witness.agent(), diff.grant.agent);
    assert_eq!(witness.sponsor(), diff.grant.sponsor);
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let execute = |session: &LoopbackReceiveSession, maximum| {
        pulls::execute(
            &node,
            &selected,
            session,
            BodyFraming::ContentLength(body.len() as u64),
            &mut body.as_bytes(),
            HttpLimits::default(),
            maximum,
            &deadline,
        )
    };
    let result = execute(&session, MAXIMUM as u64).unwrap();
    let mut wire = Vec::new();
    result.send(&mut wire, HttpVersion::Http11).unwrap();
    let wire = String::from_utf8(wire).unwrap();
    let exact = wire.split_once("\r\n\r\n").unwrap().1.len() as u64;
    assert!(execute(&session, exact).is_ok());
    assert_eq!(
        execute(&session, exact - 1).err().unwrap().status,
        Status::TooLarge
    );
    request.constrain_deadline(std::time::Instant::now() - Duration::from_secs(1));
    assert!(execute(&request.authenticated_session(), MAXIMUM as u64).is_err());
    assert_eq!(generation(&node), fixture.generation);
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(diff.bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(diff.grant),
        },
        diff.grant.sponsor,
        "revoke-diff-reader",
    );
    node.shutdown().unwrap();
    status(
        &fixture.request(&diff.bearer, "POST", "/api/v1/pulls/1/diff", &body, None),
        401,
    );
    fixture.selected.nodes.close().unwrap();
}
