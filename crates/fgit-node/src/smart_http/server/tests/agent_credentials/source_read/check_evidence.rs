//! Sponsored diagnostics disclose one real failed check through its canonical
//! PR snapshot, without granting general artifact or source access.

use super::*;
use crate::smart_http::server::{credentials::Grant, pulls};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::workflow_check::{
    NativeWorkflowCheck, WorkflowCheckConclusion, WorkflowCheckId, WorkflowCheckRecord,
};
use fgit_identity::agent::{PULLS_CHECK_EVIDENCE_READ, PULLS_FEEDBACK_READ, PULLS_READ};
use fgit_runner::coordinator::CheckRunStatus;
use fgit_runner::workflow::{JobOutcome, WorkflowLimits};
use fgit_types::RepositoryAuthorityHeadId;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head};

const PRIVATE_LOG: &[u8] = b"PRIVATE-FAILED-CHECK-OUTPUT";

struct FailedCheck {
    bearer: String,
    feedback: String,
    prior: String,
    expired: String,
    grant: AgentCredentialGrant,
    data: PullRequestData,
    id: WorkflowCheckId,
    record: WorkflowCheckRecord,
    head: RepositoryAuthorityHeadId,
}

fn selected_head(node: &OneNode) -> RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .basis()
        .id()
}

fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}

fn query(number: u64, check: WorkflowCheckId, head: RepositoryAuthorityHeadId) -> String {
    format!(
        "/api/v1/pulls/{number}/checks/evidence?check={check}&expected_head={}",
        head_token(head)
    )
}

fn publish_pr(node: &OneNode, command: &PullRequestCommand, key: &str) {
    let session = LoopbackReceiveSession::authenticated(
        actor(1),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    );
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session,
            command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn failed_check(root: &Scratch, fixture: &mut Fixture) -> FailedCheck {
    use std::os::unix::fs::PermissionsExt;

    let node = reopen(fixture.config.clone());
    let format = fixture.commit.algorithm();
    let source = root.0.join("check-evidence-source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), "ref: refs/heads/check-evidence\n").unwrap();
    fs::write(
        source.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => {
                "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
            }
        },
    )
    .unwrap();
    let workflow = b"name: diagnostics\non: push\njobs:\n  failure:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf PRIVATE-FAILED-CHECK-OUTPUT; false\n";
    let blob = loose(&source, format, GitObjectKind::Blob, workflow);
    let tree = loose(
        &source,
        format,
        GitObjectKind::Tree,
        &[b"100644 workflow.yml\0".as_slice(), blob.as_bytes()].concat(),
    );
    let body = format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nfailed-check source\n"
    );
    let source_tip = loose(&source, format, GitObjectKind::Commit, body.as_bytes());
    fs::write(
        source.join("refs/heads/check-evidence"),
        format!("{source_tip}\n"),
    )
    .unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &source,
            actor(1),
            b"sponsored-check-evidence-source",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    let source_ref = RefName::try_new(b"refs/heads/check-evidence").unwrap();
    let runs = root.0.join("check-evidence-runs");
    fs::create_dir(&runs).unwrap();
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).unwrap();
    let run = node
        .runtime()
        .block_on(node.run_trusted_workflow_in(
            &node.request_context(),
            &source_ref,
            b"workflow.yml",
            [0x71; 16],
            &runs,
            &[b"workflow.yml".to_vec()],
            (None, Some(source_tip)),
            WorkflowLimits {
                total_output_bytes: 8192,
                ..Default::default()
            },
        ))
        .unwrap();
    assert_eq!(run.execution.jobs.len(), 1);
    assert_eq!(run.execution.jobs[0].outcome, JobOutcome::Failed);
    assert_eq!(
        run.execution.jobs[0].steps[0].observation.stdout,
        PRIVATE_LOG
    );
    let mut journal = run.open_check_journal(None, &|| true).unwrap();
    let history = journal
        .read_history(None, None, 128, 1024 * 1024, &|| true)
        .unwrap();
    let mut records = Vec::new();
    for entry in history.entries() {
        for (index, fact) in entry.batch().facts().iter().enumerate() {
            if fact.status == CheckRunStatus::Completed {
                let evidence = journal
                    .read_evidence(fact.receipt_commitment.unwrap())
                    .unwrap();
                records.push(
                    OneNode::workflow_check_record_from_batch(
                        source_ref.clone(),
                        entry.batch(),
                        index,
                        &evidence,
                        &|| true,
                    )
                    .unwrap(),
                );
            }
        }
    }
    assert_eq!(records.len(), 1);
    let record = records.pop().unwrap();
    assert_eq!(record.conclusion, WorkflowCheckConclusion::Failure);
    let id = NativeWorkflowCheck {
        actor: actor(1),
        record: record.clone(),
    }
    .id();
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_trusted_workflow_check_in(
            &node.request_context(),
            &LoopbackReceiveSession::authenticated(
                actor(1),
                IdempotencyKey::new(b"sponsored-failed-check".to_vec()).unwrap(),
            ),
            &record,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let data = PullRequestData {
        source_ref,
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip,
        target_tip: fixture.commit,
        title: "Inspect one failed workflow".into(),
        body: "Diagnostic evidence does not approve or execute anything.".into(),
    };
    publish_pr(
        &node,
        &PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: data.clone(),
        },
        "sponsored-check-evidence-open",
    );
    let bearer = format!("fgagent_{}", "d1".repeat(32));
    let feedback = format!("fgagent_{}", "d2".repeat(32));
    let prior = format!("fgagent_{}", "d3".repeat(32));
    let expired = format!("fgagent_{}", "d4".repeat(32));
    let grant = AgentCredentialGrant {
        operations: PULLS_CHECK_EVIDENCE_READ,
        ..fixture.grant
    };
    for (token, selected, key) in [
        (&bearer, grant, "issue-check-evidence"),
        (
            &feedback,
            AgentCredentialGrant {
                operations: PULLS_FEEDBACK_READ,
                ..grant
            },
            "issue-check-feedback",
        ),
        (
            &prior,
            AgentCredentialGrant {
                // Every legacy operation that needs no source ceiling,
                // including feedback, keeps its original disclosure meaning.
                operations: 0xefff,
                ..grant
            },
            "issue-pre-evidence-mask",
        ),
        (
            &expired,
            AgentCredentialGrant {
                issued_at: grant.issued_at - 120,
                expires_at: grant.issued_at - 60,
                ..grant
            },
            "issue-expired-check-evidence",
        ),
    ] {
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(token.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: AgentCredentialAction::Issue(selected),
            },
            grant.sponsor,
            key,
        );
    }
    fixture.generation = generation(&node);
    let head = selected_head(&node);
    drop(journal);
    node.shutdown().unwrap();
    FailedCheck {
        bearer,
        feedback,
        prior,
        expired,
        grant,
        data,
        id,
        record,
        head,
    }
}

fn assert_evidence(response: &str, check: &FailedCheck, head: RepositoryAuthorityHeadId) {
    status(response, 200);
    let value = decode(response);
    assert_eq!(
        field(&value, "type").text(),
        Some("pull_request_check_evidence")
    );
    assert_eq!(field(&value, "read_only"), &Value::Bool(true));
    assert_eq!(
        field(&value, "evidence_hex").text(),
        Some(hex(&check.record.evidence).as_str())
    );
    let page = field(&value, "page");
    assert_eq!(
        field(page, "snapshot_token").text(),
        Some(head_token(head).as_str())
    );
    assert_eq!(
        field(page, "source_tip").text(),
        Some(check.data.source_tip.to_string().as_str())
    );
    assert_eq!(field(page, "source_current"), &Value::Bool(true));
    assert_eq!(field(page, "merge_permission"), &Value::Null);
    let checks = rows(field(page, "checks"));
    assert_eq!(checks.len(), 1);
    assert_eq!(
        field(&checks[0], "id").text(),
        Some(check.id.to_string().as_str())
    );
    assert_eq!(field(&checks[0], "conclusion").text(), Some("failure"));
    assert_eq!(
        field(&checks[0], "evidence_sha256").text(),
        Some(hex(&sha256_digest(&check.record.evidence)).as_str())
    );
    assert_eq!(
        field(&checks[0], "evidence_bytes").text(),
        Some(check.record.evidence.len().to_string().as_str())
    );
    let report = field(&value, "report");
    let json = field(report, "json").text().unwrap();
    let offset = usize::try_from(field(report, "offset").unsigned().unwrap()).unwrap();
    assert_eq!(field(report, "bytes").unsigned(), Some(json.len() as u64));
    assert_eq!(&check.record.evidence[offset..], json.as_bytes());
    assert!(
        json.contains(&hex(PRIVATE_LOG)),
        "failed stdout must survive exactly"
    );
    assert!(response.contains("Cache-Control: no-store\r\n"));
    assert!(response.contains("Vary: Authorization\r\n"));
}

#[test]
fn sponsored_failed_check_http_requires_independent_evidence_scope() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let check = failed_check(&root, &mut fixture);
        let selected = query(1, check.id, check.head);
        let response = fixture.request(&check.bearer, "GET", &selected, "", None);
        assert_evidence(&response, &check, check.head);
        for token in [
            &fixture.source,
            &fixture.metadata,
            &fixture.legacy,
            &check.feedback,
            &check.prior,
        ] {
            let denied = fixture.request(token, "GET", &selected, "", None);
            status(&denied, 403);
            assert!(!denied.contains("evidence_hex"));
            assert!(!denied.contains("source_tip"));
        }
        status(
            &fixture.request(&check.expired, "GET", &selected, "", None),
            401,
        );
        let summary = fixture.request(&check.feedback, "GET", "/api/v1/pulls/1/checks", "", None);
        status(&summary, 200);
        assert!(summary.contains("\"conclusion\":\"failure\""));
        assert!(!summary.contains("\"evidence_hex\":"));
        assert!(!summary.contains(&hex(PRIVATE_LOG)));
        for (method, suffix, body) in [
            ("GET", "/api/v1/pulls/1/checks", ""),
            ("GET", "/api/v1/pulls/1/reviews", ""),
            ("GET", "/api/v1/pulls/1", ""),
            ("POST", "/api/v1/pulls/1/reviews/approve", ""),
            ("POST", "/api/v1/pulls/1/merge", ""),
            ("POST", "/api/v1/source/blob", "object_format=sha256"),
            ("GET", "/info/refs?service=git-upload-pack", ""),
            ("POST", "/git-receive-pack", "0000"),
        ] {
            status(
                &fixture.request(&check.bearer, method, suffix, body, None),
                403,
            );
        }
        let unknown = fixture.request(
            &check.bearer,
            "GET",
            &query(1, WorkflowCheckId::from_bytes([0; 32]), check.head),
            "",
            None,
        );
        let absent = fixture.request(
            &check.bearer,
            "GET",
            &query(2, check.id, check.head),
            "",
            None,
        );
        status(&unknown, 404);
        assert_eq!(unknown, absent);
        assert!(!unknown.contains("evidence_hex"));
        assert!(!unknown.contains("source_tip"));
        status(
            &fixture.request(
                &check.bearer,
                "GET",
                &format!("/api/v1/pulls/1/checks/evidence?check={}", check.id),
                "",
                None,
            ),
            400,
        );
        status(
            &fixture.request(&check.bearer, "GET", &selected, "", Some("read-has-no-key")),
            400,
        );
        let mut disabled = fixture.selected.clone();
        disabled.services = disabled.services.with(RepositoryHttpService::Source, false);
        let target = format!(
            "{}{}",
            std::str::from_utf8(&disabled.route).unwrap(),
            selected
        );
        assert_evidence(
            &exchange(&disabled, &check.bearer, "GET", &target, "", None),
            &check,
            check.head,
        );
        disabled.services = disabled.services.with(RepositoryHttpService::Pulls, false);
        status(
            &exchange(&disabled, &check.bearer, "GET", &target, "", None),
            403,
        );
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(check.bearer.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: AgentCredentialAction::Revoke(check.grant),
            },
            check.grant.sponsor,
            "revoke-check-evidence",
        );
        let revoked_generation = generation(&node);
        node.shutdown().unwrap();
        // A broad legacy host row cannot revive a revoked canonical bearer.
        fixture.selected.credentials = CredentialSource::Static {
            digest: sha256_digest(check.bearer.as_bytes()),
            principal: actor(4),
        };
        status(
            &fixture.request(&check.bearer, "GET", &selected, "", None),
            401,
        );
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), revoked_generation);
        node.shutdown().unwrap();
    }
}

#[test]
fn sponsored_failed_check_http_retains_the_snapshot_and_current_branch_visibility() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let check = failed_check(&root, &mut fixture);
        let selected = query(1, check.id, check.head);
        let original = fixture.request(&check.bearer, "GET", &selected, "", None);
        assert_evidence(&original, &check, check.head);
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        let mut updated = check.data.clone();
        updated.title = "PR metadata after diagnostics snapshot".into();
        publish_pr(
            &node,
            &PullRequestCommand {
                number: PullRequestNumber::FIRST,
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: PullRequestAction::Update,
                data: updated,
            },
            "update-after-check-evidence-pin",
        );
        let current = selected_head(&node);
        let updated_generation = generation(&node);
        node.shutdown().unwrap();
        let retained = fixture.request(&check.bearer, "GET", &selected, "", None);
        assert_eq!(retained, original);
        let fresh = fixture.request(&check.bearer, "GET", &query(1, check.id, current), "", None);
        assert_evidence(&fresh, &check, current);
        assert_eq!(
            field(field(&decode(&fresh), "page"), "pull_request_version").text(),
            Some("2")
        );
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), updated_generation);
        node.shutdown().unwrap();
        for (index, hidden) in [
            check.data.source_ref.as_bytes(),
            check.data.target_ref.as_bytes(),
        ]
        .into_iter()
        .enumerate()
        {
            let node = reopen(fixture.config.clone());
            let policy = fgit_codec::HiddenRefPolicyBody {
                rules: vec![hidden.to_vec()],
            };
            let context = node.request_context();
            let tx = fgit_types::TxId::from_internal_object_id(fgit_types::InternalObjectId::new(
                fgit_codec::harness::algorithm(),
                fgit_types::TxId::DOMAIN_TAG,
                fgit_types::CANONICAL_CODEC_VERSION,
                fgit_types::DigestBytes::try_new(&[0x61 + u8::try_from(index).unwrap(); 32])
                    .unwrap(),
            ))
            .unwrap();
            node.runtime()
                .block_on(
                    fgit_admission::merge::native::protection::publish_hidden_ref_policy_async(
                        &node.authority,
                        context.authority(),
                        &node.head_key,
                        node.tenant_id,
                        Some(&policy),
                        tx,
                    ),
                )
                .unwrap();
            let hidden_head = selected_head(&node);
            let hidden_generation = generation(&node);
            drop(context);
            node.shutdown().unwrap();
            // Retained snapshots do not cross a policy epoch. At the current
            // epoch either hidden branch conceals the entire selected check.
            status(
                &fixture.request(&check.bearer, "GET", &selected, "", None),
                409,
            );
            let denied = fixture.request(
                &check.bearer,
                "GET",
                &query(1, check.id, hidden_head),
                "",
                None,
            );
            let absent = fixture.request(
                &check.bearer,
                "GET",
                &query(2, check.id, hidden_head),
                "",
                None,
            );
            status(&denied, 404);
            assert_eq!(denied, absent);
            assert!(!denied.contains("source_tip"));
            assert!(!denied.contains("evidence_hex"));
            fixture.selected.nodes.close().unwrap();
            let node = reopen(fixture.config.clone());
            assert_eq!(generation(&node), hidden_generation);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn sponsored_failed_check_http_preserves_provenance_output_bound_and_original_deadline() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let check = failed_check(&root, &mut fixture);
    let node = reopen(fixture.config.clone());
    let raw = format!(
        "GET {}{} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\n\r\n",
        std::str::from_utf8(&fixture.selected.route).unwrap(),
        query(1, check.id, check.head),
        check.bearer,
    );
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let selected = pulls::Request::parse(&envelope).unwrap().unwrap();
    assert_eq!(selected.agent_operation(), Some(PULLS_CHECK_EVIDENCE_READ));
    assert!(selected.preserves_deadline());
    assert!(!selected.is_mutation());
    let mut request = node
        .runtime()
        .block_on(node.authenticate_agent_request_in(
            &node.request_context(),
            check.bearer.as_bytes(),
            &IdempotencyKey::new(b"failed-check-diagnostic-budget".to_vec()).unwrap(),
            PULLS_CHECK_EVIDENCE_READ,
            sha256_digest(raw.as_bytes()),
            256 * 1024,
            MAXIMUM as u64,
        ))
        .unwrap();
    for operation in [PULLS_READ, PULLS_FEEDBACK_READ, SOURCE_READ] {
        assert!(request.check_operation(&node, operation).is_err());
    }
    let grant = Grant::agent(&request);
    assert!(!grant.permits_artifact_read());
    assert!(!grant.permits_pulls(false));
    let mut granted = fixture.selected.clone();
    granted.credentials = CredentialSource::AgentRequest {
        digest: sha256_digest(check.bearer.as_bytes()),
        grant,
    };
    let session = pulls::authenticate(&selected, &envelope, raw.as_bytes(), &granted).unwrap();
    let authentication = session.authenticated_session().unwrap().authentication();
    let witness = authentication.agent_provenance().unwrap();
    assert_eq!(witness.agent(), check.grant.agent);
    assert_eq!(witness.sponsor(), check.grant.sponsor);
    assert_eq!(
        witness.credential_id(),
        agent_credential_id(check.bearer.as_bytes()).unwrap()
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
    let mut response = Vec::new();
    execute(&session, MAXIMUM as u64)
        .unwrap()
        .send(&mut response, HttpVersion::Http11)
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert_evidence(&response, &check, check.head);
    let exact = response.split_once("\r\n\r\n").unwrap().1.len() as u64;
    assert!(execute(&session, exact).is_ok());
    assert_eq!(
        execute(&session, exact - 1).err().unwrap().status,
        Status::TooLarge
    );
    request.constrain_deadline(std::time::Instant::now() - Duration::from_secs(1));
    assert!(execute(&request.authenticated_session(), MAXIMUM as u64).is_err());
    assert_eq!(generation(&node), fixture.generation);
    node.shutdown().unwrap();
    fixture.selected.nodes.close().unwrap();
}
