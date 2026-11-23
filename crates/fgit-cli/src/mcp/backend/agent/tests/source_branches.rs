//! Scoped task-branch creation crosses the real credential ledger, native
//! admission and MCP protocol. No operator creates the agent's task branch.
use super::super::super::{candidate, checks, hex, json, outcomes, pull_reviews, source_writes};
use super::*;
use fgit_forge::ExpectedVersion;
use fgit_identity::agent::{
    AgentCredentialAction, AgentCredentialCommand, AgentCredentialId, SourcePublicationScope,
    agent_credential_id,
};
use fgit_types::{GitOid, RefName};
use std::collections::BTreeMap;

const REFERENCE: &str = "refs/heads/agent/task";
const RETRY: &str = "create-sponsored-task";
const PATCH: &str = "diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-agent MCP fixture\n+independent sponsored task\n";

fn issue_scoped(
    node: &OneNode,
    byte: u8,
    operations: u32,
    ref_prefix: &[u8],
    retry: &str,
) -> AgentCredentialId {
    let id = agent_credential_id(token(byte).as_bytes()).unwrap();
    let scope = (operations & (SOURCE_BRANCH_CREATE | SOURCE_PUBLISH) != 0).then(|| {
        SourcePublicationScope::new(
            &format!("prefix:{}", hex(ref_prefix)),
            vec![b"file".to_vec()],
        )
        .unwrap()
    });
    credential(
        node,
        AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::issuance(grant(node, operations), scope),
        },
        retry,
    );
    id
}

struct BranchFixture {
    fixture: Fixture,
    options: Options,
    credential: AgentCredentialId,
}

impl BranchFixture {
    fn new(format: GitHashAlgorithm, operations: u32) -> Self {
        let fixture = Fixture::new(format);
        let administrator = NodeTools::open(fixture.options.clone()).unwrap();
        let credential = issue_scoped(
            &administrator.node,
            0x81,
            operations,
            b"refs/heads/agent/",
            "issue-task-branch-creator",
        );
        administrator.close().unwrap();
        let mut options = fixture.replacement(0x81);
        options.issues = false;
        options.discussions = false;
        options.pulls = operations & PULLS_FEEDBACK_READ != 0;
        options.source = operations & SOURCE_CANDIDATES != 0;
        options.outcomes = operations & OUTCOMES_READ != 0;
        options.writes = Default::default();
        options.writes.source = true;
        options.writes.pulls = operations & PULLS_WRITE != 0;
        Self {
            fixture,
            options,
            credential,
        }
    }

    fn creation(&self, reference: &str, retry: &str) -> Object {
        object([
            ("reference", text(reference)),
            ("target", text(self.fixture.tip.to_string())),
            ("idempotency_key", text(retry)),
        ])
        .object()
        .unwrap()
        .clone()
    }

    fn preparation(&self, reference: &str) -> Object {
        object([
            ("operation", text("prepare_patch")),
            ("reference", text(reference)),
            ("expected_base", text(self.fixture.tip.to_string())),
            ("patch", text(PATCH)),
            ("author", text("Agent <agent@example.invalid>")),
            ("committer", text("Agent <agent@example.invalid>")),
            ("timestamp", text("2")),
            ("message_hex", text(hex(b"complete sponsored task\n"))),
        ])
        .object()
        .unwrap()
        .clone()
    }
}

fn refs(backend: &NodeTools) -> BTreeMap<RefName, GitOid> {
    backend
        .node
        .runtime()
        .block_on(
            backend
                .node
                .materialize_admission_in(&backend.node.request_context()),
        )
        .unwrap()
        .snapshot()
        .refs
        .clone()
}

fn invoke(
    server: &mut Server,
    backend: &mut NodeTools,
    id: u64,
    name: &str,
    args: &Object,
) -> Value {
    let message = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([
                ("name", text(name)),
                ("arguments", Value::Object(args.clone())),
            ]),
        ),
    ])
    .encode(json::MAX_INPUT)
    .unwrap();
    let response = server.receive(backend, message.as_bytes()).unwrap();
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false), "{response:?}");
    result["structuredContent"].clone()
}

fn reservation(backend: &NodeTools, operation: u32, retry: &str) -> AgentRequest {
    backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_agent_request_in(
            &backend.node.command_request_context(None),
            token(0x81).as_bytes(),
            &key(retry),
            operation,
            [0x82; 32],
            INPUT_BYTES,
            OUTPUT_BYTES,
        ))
        .unwrap()
}

#[test]
fn sponsored_mcp_creates_edits_publishes_and_opens_its_own_task_branch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = BranchFixture::new(
            format,
            SOURCE_BRANCH_CREATE
                | SOURCE_CANDIDATES
                | SOURCE_PUBLISH
                | PULLS_WRITE
                | PULLS_FEEDBACK_READ
                | OUTCOMES_READ,
        );
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let reference = RefName::try_new(REFERENCE.as_bytes()).unwrap();
        assert!(!refs(&backend).contains_key(&reference));
        let mut server = Server::new(&mut backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"task-branch-agent","version":"1"}}}"#).unwrap();
        server.receive(
            &mut backend,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        let creation = fixture.creation(REFERENCE, RETRY);
        let created = invoke(
            &mut server,
            &mut backend,
            2,
            source_writes::CREATE,
            &creation,
        );
        committed(&created);
        let fields = created.object().unwrap();
        assert_eq!(fields["action"], text("create"));
        assert_eq!(fields["atomic"], Value::Bool(true));
        assert_eq!(fields["historical_outcome"], Value::Bool(true));
        assert_eq!(fields["current_refs_asserted"], Value::Bool(false));
        assert_eq!(refs(&backend)[&reference], fixture.fixture.tip);
        let original = provenance(&backend, RETRY);
        let witness = original.agent_provenance().unwrap();
        assert_eq!(witness.agent(), AGENT);
        assert_eq!(witness.sponsor(), SPONSOR);
        assert_eq!(witness.credential_id(), fixture.credential);
        assert!(backend.is_mutation(source_writes::CREATE));
        assert!(backend.agent.as_ref().unwrap().request.is_none());
        assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
        assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
        assert!(!created.encode(MAX_RESPONSE).unwrap().contains(&token(0x81)));

        let prepared = invoke(
            &mut server,
            &mut backend,
            3,
            candidate::NAME,
            &fixture.preparation(REFERENCE),
        );
        let prepared = prepared.object().unwrap();
        let mut inspection = prepared["publication_arguments"].object().unwrap().clone();
        inspection.insert("operation".into(), text("inspect"));
        inspection.insert(
            "expected_bundle_sha256".into(),
            prepared["bundle_sha256"].clone(),
        );
        let inspected = invoke(&mut server, &mut backend, 4, candidate::NAME, &inspection);
        let mut publication = inspected.object().unwrap()["publication_arguments"]
            .object()
            .unwrap()
            .clone();
        publication.insert("idempotency_key".into(), text("publish-sponsored-task"));
        let candidate =
            GitOid::from_hex(format, publication["expected_candidate"].text().unwrap()).unwrap();
        assert!(backend.node.read_git_object(candidate).is_err());
        assert_eq!(refs(&backend)[&reference], fixture.fixture.tip);
        committed(&invoke(
            &mut server,
            &mut backend,
            5,
            source_writes::PUBLISH,
            &publication,
        ));
        assert_eq!(refs(&backend)[&reference], candidate);
        let mut pull = pull_opening(&fixture.fixture, 81, "open-sponsored-task-pull");
        pull.insert("source_reference".into(), text(REFERENCE));
        pull.insert("expected_source".into(), text(candidate.to_string()));
        committed(&invoke(
            &mut server,
            &mut backend,
            6,
            "frankengit_pull_open",
            &pull,
        ));

        // The new high-bit creation grant coexists with the independently
        // granted legacy feedback bit, without turning observations into approval.
        let feedback = object([("number", text("81"))]).object().unwrap().clone();
        for (id, name) in [(7, checks::NAME), (8, pull_reviews::NAME)] {
            let observed = invoke(&mut server, &mut backend, id, name, &feedback);
            assert_eq!(observed.object().unwrap()["found"], Value::Bool(true));
            assert_eq!(observed.object().unwrap()["merge_permission"], Value::Null);
        }

        // A creation retry recovers the original decision after subsequent work;
        // it cannot reset the task branch to its starting point.
        assert_eq!(
            invoke(
                &mut server,
                &mut backend,
                9,
                source_writes::CREATE,
                &creation
            ),
            created
        );
        assert_eq!(refs(&backend)[&reference], candidate);
        issue_scoped(
            &backend.node,
            0x82,
            SOURCE_BRANCH_CREATE | OUTCOMES_READ,
            b"refs/heads/other/",
            "rotate-task-creator",
        );
        revoke(
            &backend.node,
            fixture.credential,
            "revoke-original-task-creator",
        );
        assert_eq!(
            backend
                .call(source_writes::CREATE, &creation)
                .unwrap_err()
                .code,
            "agent_credential_unavailable"
        );
        backend.close().unwrap();

        let replacement = fixture.fixture.replacement(0x82);
        let mut options = fixture.options.clone();
        options.agent_token_file = replacement.agent_token_file;
        let mut reopened = NodeTools::open(options).unwrap();
        assert_eq!(
            reopened.call(source_writes::CREATE, &creation).unwrap(),
            created
        );
        assert_eq!(refs(&reopened)[&reference], candidate);
        assert_eq!(provenance(&reopened, RETRY), original);
        let outcome = reopened
            .call("frankengit_transaction_outcome", &recovery(RETRY))
            .unwrap();
        committed(&outcome);
        let recorded = outcome.object().unwrap()["principal_provenance"]
            .object()
            .unwrap();
        assert_eq!(
            recorded["agent_provenance"].object().unwrap()["credential_id"],
            text(fixture.credential.to_string())
        );
        reopened.close().unwrap();
    }
}

#[test]
fn task_branch_creation_needs_its_independent_grant_and_source_write_ceiling() {
    let fixture = BranchFixture::new(GitHashAlgorithm::Sha256, SOURCE_BRANCH_CREATE);
    let mut creator = NodeTools::open(fixture.options.clone()).unwrap();
    let args = fixture.creation(REFERENCE, RETRY);
    let before = refs(&creator);
    let older_grants = [
        0xffff,
        SOURCE_PUBLISH,
        SOURCE_CANDIDATES,
        SOURCE_READ,
        PULLS_WRITE,
        PULLS_FEEDBACK_READ,
    ];
    for (index, operation) in older_grants.iter().enumerate() {
        issue_scoped(
            &creator.node,
            0x90 + index as u8,
            *operation,
            b"refs/heads/agent/",
            &format!("issue-pre-creation-scope-{index}"),
        );
    }
    assert!(
        !creator.options.source,
        "write-only creation must not require source-read launch authority"
    );
    assert_eq!(
        creator
            .call(
                source_writes::PUBLISH,
                &recovery("not-publication-authority")
            )
            .unwrap_err()
            .code,
        "agent_operation_not_granted"
    );
    creator.close().unwrap();
    for (index, _) in older_grants.iter().enumerate() {
        let mut options = fixture.fixture.replacement(0x90 + index as u8);
        options.writes.source = true;
        let mut older = NodeTools::open(options).unwrap();
        assert_eq!(
            older.call(source_writes::CREATE, &args).unwrap_err().code,
            "agent_operation_not_granted"
        );
        assert_eq!(refs(&older), before);
        older.close().unwrap();
    }
    let mut options = fixture.options.clone();
    options.writes.source = false;
    // Keep a valid launch group while disabling the source mutation ceiling.
    options.source = true;
    let mut disabled = NodeTools::open(options).unwrap();
    assert!(
        !disabled
            .tools()
            .iter()
            .any(|tool| tool.name == source_writes::CREATE)
    );
    assert_eq!(
        disabled
            .call(source_writes::CREATE, &args)
            .unwrap_err()
            .code,
        "tool_not_granted"
    );
    assert_eq!(
        source_writes::call(&disabled, source_writes::CREATE, &args)
            .unwrap_err()
            .code,
        "tool_not_granted"
    );
    disabled.close().unwrap();

    let mut creator = NodeTools::open(fixture.options.clone()).unwrap();
    let tool = source_writes::agent_branch_tool();
    let schema = tool.schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let properties = schema["properties"].object().unwrap();
    for forbidden in [
        "initial",
        "force",
        "expected_old",
        "commands",
        "bundle_hex_chunks",
    ] {
        assert!(!properties.contains_key(forbidden));
    }
    assert!(
        matches!(&schema["required"], Value::Array(required) if required.contains(&text("target")) && required.contains(&text("idempotency_key")))
    );
    committed(&creator.call(source_writes::CREATE, &args).unwrap());
    creator.close().unwrap();
}

#[test]
fn task_branch_creation_respects_ref_scope_absence_and_visible_target() {
    let fixture = BranchFixture::new(
        GitHashAlgorithm::Sha1,
        SOURCE_BRANCH_CREATE | SOURCE_CANDIDATES,
    );
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = refs(&backend);
    for (reference, retry) in [
        ("refs/heads/outside/task", "outside-destination-scope"),
        ("refs/heads/agent/topic", "cannot-overwrite-topic"),
    ] {
        let args = fixture.creation(reference, retry);
        let refused = backend.call(source_writes::CREATE, &args).unwrap();
        assert_eq!(refused.object().unwrap()["outcome"], text("refused"));
        assert_eq!(
            refused.object().unwrap()["ref_transaction_committed"],
            Value::Bool(false)
        );
        assert!(backend.result_is_error(source_writes::CREATE, &refused));
        assert_eq!(backend.call(source_writes::CREATE, &args).unwrap(), refused);
        assert_eq!(refs(&backend), before);
    }
    let prepared = backend
        .call(
            candidate::NAME,
            &fixture.preparation("refs/heads/agent/topic"),
        )
        .unwrap();
    let candidate = prepared.object().unwrap()["publication_arguments"]
        .object()
        .unwrap()["expected_candidate"]
        .clone();
    let oid = GitOid::from_hex(fixture.options.format, candidate.text().unwrap()).unwrap();
    assert!(backend.node.read_git_object(oid).is_err());
    let mut unstaged = fixture.creation(REFERENCE, "cannot-create-from-unpublished-candidate");
    unstaged.insert("target".into(), candidate);
    assert!(backend.call(source_writes::CREATE, &unstaged).is_err());
    assert_eq!(refs(&backend), before);
    assert!(backend.node.read_git_object(oid).is_err());

    // Exact byte names use the same canonical ceiling and native operation.
    let mut allowed = fixture.creation(REFERENCE, RETRY);
    allowed.remove("reference");
    allowed.insert("reference_hex".into(), text(hex(REFERENCE.as_bytes())));
    committed(&backend.call(source_writes::CREATE, &allowed).unwrap());
    assert_eq!(
        refs(&backend)[&RefName::try_new(REFERENCE.as_bytes()).unwrap()],
        fixture.fixture.tip
    );
    backend.close().unwrap();
}

#[test]
fn task_branch_handler_retains_original_operation_key_and_deadline() {
    let fixture = BranchFixture::new(
        GitHashAlgorithm::Sha256,
        SOURCE_BRANCH_CREATE | SOURCE_PUBLISH | SOURCE_CANDIDATES,
    );
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let args = fixture.creation(REFERENCE, RETRY);
    let before = refs(&backend);
    assert_eq!(
        source_writes::call(&backend, source_writes::CREATE, &args)
            .unwrap_err()
            .code,
        "agent_request_required"
    );
    let completed = reservation(&backend, SOURCE_BRANCH_CREATE, RETRY);
    backend.agent.as_mut().unwrap().response = Some(completed);
    assert_eq!(
        source_writes::call(&backend, source_writes::CREATE, &args)
            .unwrap_err()
            .code,
        "agent_request_required"
    );
    backend.agent.as_mut().unwrap().response = None;
    for (operation, retry, expected) in [
        (SOURCE_PUBLISH, RETRY, "agent_operation_not_granted"),
        (SOURCE_CANDIDATES, RETRY, "agent_operation_not_granted"),
        (
            SOURCE_BRANCH_CREATE,
            "another-key",
            "agent_request_key_mismatch",
        ),
    ] {
        let request = reservation(&backend, operation, retry);
        backend.agent.as_mut().unwrap().request = Some(request);
        assert_eq!(
            source_writes::call(&backend, source_writes::CREATE, &args)
                .unwrap_err()
                .code,
            expected
        );
        backend.agent.as_mut().unwrap().request = None;
    }
    backend.options.outcomes = true;
    let creation = reservation(&backend, SOURCE_BRANCH_CREATE, RETRY);
    backend.agent.as_mut().unwrap().request = Some(creation);
    assert_eq!(
        outcomes::call(&backend, &recovery(RETRY)).unwrap_err().code,
        "agent_operation_not_granted"
    );
    backend.agent.as_mut().unwrap().request = None;
    let mut expired = reservation(&backend, SOURCE_BRANCH_CREATE, RETRY);
    expired.constrain_deadline(Instant::now() - Duration::from_secs(1));
    expired.constrain_deadline(Instant::now() + Duration::from_secs(300));
    backend.agent.as_mut().unwrap().request = Some(expired);
    assert!(!backend.command_context().is_live());
    assert!(source_writes::call(&backend, source_writes::CREATE, &args).is_err());
    assert_eq!(refs(&backend), before);
    backend.agent.as_mut().unwrap().request = None;

    revoke(
        &backend.node,
        fixture.credential,
        "revoke-before-closed-task-dispatch",
    );
    for forbidden in [
        "initial",
        "force",
        "expected_old",
        "commands",
        "bundle_hex_chunks",
    ] {
        let mut altered = args.clone();
        altered.insert(forbidden.into(), Value::Null);
        assert_eq!(
            backend
                .call(source_writes::CREATE, &altered)
                .unwrap_err()
                .code,
            "unknown_argument"
        );
        assert_eq!(
            source_writes::call(&backend, source_writes::CREATE, &altered)
                .unwrap_err()
                .code,
            "unknown_argument"
        );
    }
    for name in [
        source_writes::UPDATE,
        source_writes::DELETE,
        source_writes::RENAME,
        source_writes::TRANSACTION,
        source_writes::PUBLISH_REBASE,
        "frankengit_tag_create",
    ] {
        assert!(!backend.tools().iter().any(|tool| tool.name == name));
        assert_eq!(
            backend.call(name, &args).unwrap_err().code,
            "tool_not_granted"
        );
    }
    assert_eq!(refs(&backend), before);
    backend.close().unwrap();
}
