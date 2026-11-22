//! Explicit task-branch grants cross real HTTP framing and native admission.
//! Existing source publication never acquires branch-creation authority.

use super::*;
use crate::smart_http::server::source;
use fgit_forge::preparation::MergeMetadata;
use fgit_identity::agent::{
    OUTCOMES_READ, PULLS_FEEDBACK_READ, SOURCE_BRANCH_CREATE, SOURCE_PUBLISH,
    SourcePublicationScope,
};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head};

const TASK: &[u8] = b"refs/heads/agent-task";

struct Creator {
    bearer: String,
    grant: AgentCredentialGrant,
    scope: SourcePublicationScope,
}

fn issue(fixture: &mut Fixture, byte: &str, operations: u32, selector: &str) -> Creator {
    let node = reopen(fixture.config.clone());
    let bearer = format!("fgagent_{}", byte.repeat(32));
    let scope = SourcePublicationScope::new(selector, vec![b"created.txt".to_vec()]).unwrap();
    let grant = AgentCredentialGrant {
        operations,
        ..fixture.grant
    };
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::issuance(grant, Some(scope.clone())),
        },
        grant.sponsor,
        &format!("issue-http-branch-{byte}"),
    );
    fixture.generation = generation(&node);
    node.shutdown().unwrap();
    Creator {
        bearer,
        grant,
        scope,
    }
}

fn form(reference: &[u8], target: GitOid) -> String {
    format!(
        "object_format={}&ref={}&new_commit={target}",
        target.algorithm().as_str(),
        std::str::from_utf8(reference).unwrap(),
    )
}

fn create(fixture: &Fixture, token: &str, body: &str, key: &str) -> String {
    fixture.request(
        token,
        "POST",
        "/api/v1/source/branches/create",
        body,
        Some(key),
    )
}

fn committed(response: &str) -> Value {
    status(response, 200);
    let receipt = decode(response);
    assert_eq!(field(&receipt, "type").text(), Some("branch_publication"));
    assert_eq!(field(&receipt, "operation").text(), Some("create"));
    assert_eq!(field(&receipt, "outcome").text(), Some("committed"));
    assert_eq!(field(&receipt, "atomic"), &Value::Bool(true));
    assert_eq!(field(&receipt, "terminal"), &Value::Bool(true));
    assert_eq!(field(&receipt, "forge_transition"), &Value::Bool(false));
    receipt
}

fn refs(node: &OneNode) -> std::collections::BTreeMap<RefName, GitOid> {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .snapshot()
        .refs
        .clone()
}

#[test]
fn explicit_http_branch_creation_recovers_original_sponsorship_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let selector = format!("exact:{}", hex(TASK));
        let creator = issue(
            &mut fixture,
            "e1",
            SOURCE_BRANCH_CREATE | OUTCOMES_READ,
            &selector,
        );
        let publisher = issue(&mut fixture, "e2", SOURCE_PUBLISH, &selector);
        // The complete prior mask includes independent PR feedback, but its
        // legacy scoped encoding must never acquire the new branch operation.
        let prior_operations = 0xffff;
        assert_eq!(prior_operations & PULLS_FEEDBACK_READ, PULLS_FEEDBACK_READ);
        assert_eq!(prior_operations & SOURCE_BRANCH_CREATE, 0);
        let prior = issue(&mut fixture, "e7", prior_operations, &selector);
        let body = form(TASK, fixture.commit);
        let key = "create-agent-task";

        status(
            &fixture.request(
                &creator.bearer,
                "POST",
                "/api/v1/source/branches/create",
                &body,
                None,
            ),
            400,
        );
        for service in [
            RepositoryHttpService::Source,
            RepositoryHttpService::Receive,
        ] {
            let mut limited = fixture.selected.clone();
            limited.services = limited.services.with(service, false);
            let route = std::str::from_utf8(&limited.route).unwrap();
            status(
                &exchange(
                    &limited,
                    &creator.bearer,
                    "POST",
                    &format!("{route}/api/v1/source/branches/create"),
                    &body,
                    Some(key),
                ),
                403,
            );
        }
        for token in [
            &fixture.source,
            &fixture.metadata,
            &fixture.legacy,
            &publisher.bearer,
            &prior.bearer,
        ] {
            status(&create(&fixture, token, &body, key), 403);
        }
        for action in [
            "branches/update",
            "branches/delete",
            "branches/rename",
            "branches/transaction",
            "tags/lightweight",
            "tags/delete",
        ] {
            status(
                &fixture.request(
                    &creator.bearer,
                    "POST",
                    &format!("/api/v1/source/{action}"),
                    &body,
                    Some(key),
                ),
                403,
            );
        }
        status(
            &fixture.request(
                &creator.bearer,
                "POST",
                "/git-receive-pack",
                "0000",
                Some(key),
            ),
            403,
        );
        status(
            &fixture.post(
                &creator.bearer,
                "tree",
                &format!("object_format={}&ref=refs/heads/main", format.as_str()),
            ),
            403,
        );

        let receipt = committed(&create(&fixture, &creator.bearer, &body, key));
        assert_eq!(
            field(&receipt, "principal_id").text(),
            Some(creator.grant.agent.to_string().as_str())
        );
        let update = &rows(field(&receipt, "updates"))[0];
        assert_eq!(field(update, "ref_hex").text(), Some(hex(TASK).as_str()));
        assert_eq!(field(update, "expected_commit"), &Value::Null);
        assert_eq!(
            field(update, "new_commit").text(),
            Some(fixture.commit.to_string().as_str())
        );
        let duplicate = create(&fixture, &creator.bearer, &body, "different-create-key");
        status(&duplicate, 409);
        assert_eq!(
            field(&decode(&duplicate), "outcome").text(),
            Some("refused")
        );
        let outcome = fixture.request(&creator.bearer, "POST", "/api/v1/outcomes", "", Some(key));
        let original = original_provenance(&outcome).to_owned();
        for evidence in [
            format!("\"agent\":\"{}\"", creator.grant.agent),
            format!("\"sponsor\":\"{}\"", creator.grant.sponsor),
            format!(
                "\"credential_id\":\"{}\"",
                agent_credential_id(creator.bearer.as_bytes()).unwrap()
            ),
        ] {
            assert!(original.contains(&evidence), "{original}");
        }

        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(
            refs(&node)[&RefName::try_new(TASK).unwrap()],
            fixture.commit
        );
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(creator.bearer.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: AgentCredentialAction::revocation(creator.grant, Some(creator.scope)),
            },
            creator.grant.sponsor,
            "revoke-http-branch-creator",
        );
        node.shutdown().unwrap();
        // A colliding ordinary receive credential cannot rescue revoked agent
        // authentication. A live replacement recovers the original decision,
        // even when its new ref ceiling would refuse a new task-branch request.
        fixture.selected.credentials = CredentialSource::Static {
            digest: sha256_digest(creator.bearer.as_bytes()),
            principal: actor(4),
        };
        let replacement = issue(
            &mut fixture,
            "e3",
            SOURCE_BRANCH_CREATE | OUTCOMES_READ,
            &format!("exact:{}", hex(b"refs/heads/another-task")),
        );
        status(&create(&fixture, &creator.bearer, &body, key), 401);
        assert_eq!(
            committed(&create(&fixture, &replacement.bearer, &body, key)),
            receipt
        );
        let recovered = fixture.request(
            &replacement.bearer,
            "POST",
            "/api/v1/outcomes",
            "",
            Some(key),
        );
        assert_eq!(original_provenance(&recovered), original);
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        let current = refs(&node);
        assert_eq!(current[&RefName::try_new(TASK).unwrap()], fixture.commit);
        assert_eq!(
            current[&RefName::try_new(b"refs/heads/main").unwrap()],
            fixture.commit
        );
        assert!(!current.contains_key(&RefName::try_new(b"refs/heads/another-task").unwrap()));
        assert_eq!(generation(&node), fixture.generation);
        node.shutdown().unwrap();
    }
}

fn advance_main(node: &OneNode, base: GitOid) -> GitOid {
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let context = node.request_context();
    let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(
        &context,
        &reference,
        base,
        [0xe4; 16],
        b"diff --git a/created.txt b/created.txt\nnew file mode 100644\n--- /dev/null\n+++ b/created.txt\n@@ -0,0 +1 @@\n+task source\n",
        &MergeMetadata {
            author: "A <a@example.invalid>".into(),
            committer: "A <a@example.invalid>".into(),
            timestamp: 2,
            message: b"Advance main for task creation\n".to_vec(),
        },
        Default::default(),
    )).unwrap();
    let result = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &context,
            actor(1),
            b"advance-main-for-task-creation",
            &reference,
            base,
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

#[test]
fn http_task_creation_enforces_namespace_and_current_visible_branch_tip() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let creator = issue(
        &mut fixture,
        "e4",
        SOURCE_BRANCH_CREATE,
        &format!("prefix:{}", hex(b"refs/heads/tasks/")),
    );
    for (index, reference) in [
        b"refs/heads/tasks-other/one".as_slice(),
        b"refs/heads/tasks",
    ]
    .iter()
    .enumerate()
    {
        let response = create(
            &fixture,
            &creator.bearer,
            &form(reference, fixture.commit),
            &format!("outside-task-namespace-{index}"),
        );
        status(&response, 409);
        let receipt = decode(&response);
        assert_eq!(field(&receipt, "outcome").text(), Some("refused"));
        assert_eq!(
            field(&receipt, "code").text(),
            Some("CapabilityScopeViolation")
        );
    }
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    let current = advance_main(&node, fixture.commit);
    let before_preflight = generation(&node);
    node.shutdown().unwrap();
    let target = b"refs/heads/tasks/one";
    let missing = git_object_id(
        GitHashAlgorithm::Sha256,
        GitObjectKind::Commit,
        b"absent task target",
    );
    let blob = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, SOURCE);
    let mut refusals = Vec::new();
    // The prior commit is still reachable and has a visible lightweight tag.
    // Neither condition grants task creation from an arbitrary historical ID.
    for (index, oid) in [fixture.commit, blob, missing].into_iter().enumerate() {
        let response = create(
            &fixture,
            &creator.bearer,
            &form(target, oid),
            &format!("unavailable-task-tip-{index}"),
        );
        status(&response, 404);
        refusals.push(response);
    }
    assert!(refusals.windows(2).all(|pair| pair[0] == pair[1]));
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(generation(&node), before_preflight);
    assert!(!refs(&node).contains_key(&RefName::try_new(target).unwrap()));
    node.shutdown().unwrap();
    committed(&create(
        &fixture,
        &creator.bearer,
        &form(target, current),
        "create-namespace-task",
    ));

    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    let policy = fgit_codec::HiddenRefPolicyBody {
        rules: vec![b"refs/heads/main".to_vec(), target.to_vec()],
    };
    let context = node.request_context();
    node.runtime()
        .block_on(
            fgit_admission::merge::native::protection::publish_hidden_ref_policy_async(
                &node.authority,
                context.authority(),
                &node.head_key,
                node.tenant_id,
                Some(&policy),
                fgit_codec::harness::tx_id(),
            ),
        )
        .unwrap();
    let after_hidden = generation(&node);
    drop(context);
    node.shutdown().unwrap();
    let next = b"refs/heads/tasks/two";
    let hidden = create(
        &fixture,
        &creator.bearer,
        &form(next, current),
        "hidden-task-source",
    );
    let absent = create(
        &fixture,
        &creator.bearer,
        &form(next, missing),
        "absent-task-source",
    );
    status(&hidden, 404);
    assert_eq!(hidden, absent);
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(generation(&node), after_hidden);
    assert!(!refs(&node).contains_key(&RefName::try_new(next).unwrap()));
    node.shutdown().unwrap();
}

#[test]
fn http_task_creation_retains_live_proof_retry_key_budget_and_ingress_deadline() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let selector = format!("exact:{}", hex(TASK));
    let creator = issue(&mut fixture, "e5", SOURCE_BRANCH_CREATE, &selector);
    let publisher = issue(&mut fixture, "e6", SOURCE_PUBLISH, &selector);
    let node = reopen(fixture.config.clone());
    let body = form(TASK, fixture.commit);
    let key = IdempotencyKey::new(b"original-task-request".to_vec()).unwrap();
    let route = std::str::from_utf8(&fixture.selected.route).unwrap();
    let raw = format!(
        "POST {route}/api/v1/source/branches/create HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: original-task-request\r\n\r\n",
        creator.bearer,
        body.len(),
    );
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let selected = source::Request::parse(&envelope).unwrap();
    let authenticate = |token: &str, operation: u32, input_limit: u64| {
        node.runtime()
            .block_on(node.authenticate_agent_request_in(
                &node.request_context(),
                token.as_bytes(),
                &key,
                operation,
                sha256_digest(raw.as_bytes()),
                input_limit,
                MAXIMUM as u64,
            ))
            .unwrap()
    };
    let mut request = authenticate(&creator.bearer, SOURCE_BRANCH_CREATE, MAXIMUM as u64);
    let mut granted = fixture.selected.clone();
    granted.credentials = CredentialSource::AgentRequest {
        digest: sha256_digest(creator.bearer.as_bytes()),
        grant: crate::smart_http::server::credentials::Grant::agent(&request),
    };
    let (session, read) =
        source::authenticate(&selected, &envelope, raw.as_bytes(), &granted).unwrap();
    assert!(read.is_none());
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let execute = |session: &LoopbackReceiveSession,
                   proof: Option<&crate::agent_credentials::AgentRequest>,
                   ingress: &GitDaemonSessionDeadline| {
        source::execute(
            &node,
            &selected,
            session,
            None,
            proof,
            BodyFraming::ContentLength(body.len() as u64),
            &mut body.as_bytes(),
            HttpLimits::default(),
            MAXIMUM as u64,
            ingress,
        )
    };
    assert_eq!(
        execute(&session, None, &deadline).err().unwrap().status,
        Status::Forbidden
    );
    let changed_key =
        request.session(IdempotencyKey::new(b"substituted-task-key".to_vec()).unwrap());
    assert_eq!(
        execute(&changed_key, Some(&request), &deadline)
            .err()
            .unwrap()
            .status,
        Status::Forbidden
    );
    let publication = authenticate(&publisher.bearer, SOURCE_PUBLISH, MAXIMUM as u64);
    assert_eq!(
        execute(
            &publication.authenticated_session(),
            Some(&publication),
            &deadline
        )
        .err()
        .unwrap()
        .status,
        Status::Forbidden,
    );
    let payload_size = TASK.len() + fixture.commit.algorithm().digest_len();
    assert!(body.len() > payload_size);
    let bounded = authenticate(&creator.bearer, SOURCE_BRANCH_CREATE, payload_size as u64);
    assert_eq!(
        execute(&bounded.authenticated_session(), Some(&bounded), &deadline)
            .err()
            .unwrap()
            .status,
        Status::TooLarge,
    );
    let mut expired_ingress = deadline.clone();
    expired_ingress.started = std::time::Instant::now()
        .checked_sub(expired_ingress.budget() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        execute(&session, Some(&request), &expired_ingress)
            .err()
            .unwrap()
            .status,
        Status::Timeout
    );
    request.constrain_deadline(std::time::Instant::now());
    assert_eq!(
        execute(&request.authenticated_session(), Some(&request), &deadline)
            .err()
            .unwrap()
            .status,
        Status::Forbidden,
    );
    assert!(execute(&session, Some(&request), &deadline).is_err());
    assert_eq!(generation(&node), fixture.generation);
    assert!(!refs(&node).contains_key(&RefName::try_new(TASK).unwrap()));
    node.shutdown().unwrap();
}
