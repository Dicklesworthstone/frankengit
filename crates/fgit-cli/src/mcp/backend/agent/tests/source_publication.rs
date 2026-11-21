//! The MCP publisher uses a current scoped credential and ordinary durable
//! admission. Candidate bytes and launch flags never supply native authority.
use super::super::super::{candidate, hex, outcomes, source_writes};
use super::*;
use fgit_forge::ExpectedVersion;
use fgit_forge::preparation::MergeMetadata;
use fgit_identity::agent::{
    AgentCredentialAction, AgentCredentialCommand, AgentCredentialId, SourcePublicationScope,
    agent_credential_id,
};
use fgit_types::{GitOid, RefName};
use std::collections::BTreeMap;

const REFERENCE: &str = "refs/heads/agent/topic";
const PATCH: &str = "diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-agent MCP fixture\n+scoped MCP publication\n";
const RETRY: &str = "scoped-mcp-publication";

fn issue_source(
    node: &OneNode,
    byte: u8,
    operations: u16,
    prefixes: &[&[u8]],
    retry: &str,
) -> AgentCredentialId {
    let id = agent_credential_id(token(byte).as_bytes()).unwrap();
    let scope = SourcePublicationScope::new(
        &format!("exact:{}", hex(REFERENCE.as_bytes())),
        prefixes.iter().map(|prefix| prefix.to_vec()).collect(),
    )
    .unwrap();
    credential(
        node,
        AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::issuance(grant(node, operations), Some(scope)),
        },
        retry,
    );
    id
}

struct PublicationFixture {
    fixture: Fixture,
    options: Options,
    credential: AgentCredentialId,
}
impl PublicationFixture {
    fn new(format: GitHashAlgorithm, operations: u16, prefixes: &[&[u8]]) -> Self {
        let fixture = Fixture::new(format);
        let administrator = NodeTools::open(fixture.options.clone()).unwrap();
        let credential = issue_source(
            &administrator.node,
            0x71,
            operations,
            prefixes,
            "issue-scoped-publisher",
        );
        administrator.close().unwrap();
        let mut options = fixture.replacement(0x71);
        options.issues = false;
        options.discussions = false;
        options.pulls = false;
        options.source = true;
        options.outcomes = operations & OUTCOMES_READ != 0;
        options.writes = Default::default();
        options.writes.source = true;
        Self {
            fixture,
            options,
            credential,
        }
    }

    fn preparation(&self) -> Object {
        object([
            ("operation", text("prepare_patch")),
            ("reference", text(REFERENCE)),
            ("expected_base", text(self.fixture.tip.to_string())),
            ("patch", text(PATCH)),
            ("author", text("Author <author@example.invalid>")),
            ("committer", text("Committer <committer@example.invalid>")),
            ("timestamp", text("2")),
            ("message_hex", text(hex(b"scoped source publication\n"))),
        ])
        .object()
        .unwrap()
        .clone()
    }

    fn trusted_candidate(&self, backend: &NodeTools, reference: &str, retry: &str) -> Object {
        let prepared = backend
            .node
            .runtime()
            .block_on(backend.node.prepare_trusted_patch_in(
                &backend.node.command_request_context(None),
                &RefName::try_new(reference.as_bytes()).unwrap(),
                self.fixture.tip,
                [0x73; 16],
                PATCH.as_bytes(),
                &MergeMetadata {
                    author: "Author <author@example.invalid>".into(),
                    committer: "Committer <committer@example.invalid>".into(),
                    timestamp: 2,
                    message: b"scoped source publication\n".to_vec(),
                },
                Default::default(),
            ))
            .unwrap();
        object([
            ("reference", text(reference)),
            ("expected_base", text(self.fixture.tip.to_string())),
            (
                "expected_candidate",
                text(prepared.candidate_commit.to_string()),
            ),
            ("idempotency_key", text(retry)),
            (
                "bundle_hex_chunks",
                Value::Array(
                    prepared
                        .bundle_bytes()
                        .chunks(8192)
                        .map(|chunk| text(hex(chunk)))
                        .collect(),
                ),
            ),
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

fn reservation(backend: &NodeTools, operation: u16, retry: &str) -> AgentRequest {
    backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_agent_request_in(
            &backend.node.command_request_context(None),
            token(0x71).as_bytes(),
            &key(retry),
            operation,
            [0x74; 32],
            INPUT_BYTES,
            OUTPUT_BYTES,
        ))
        .unwrap()
}

#[test]
fn sponsored_publication_schema_requires_existing_base_and_keeps_operator_initial() {
    let tool = source_writes::agent_tool();
    assert_eq!(tool.name, source_writes::PUBLISH);
    let schema = tool.schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    assert!(
        !schema["properties"]
            .object()
            .unwrap()
            .contains_key("initial")
    );
    assert!(
        matches!(&schema["required"], Value::Array(required) if required.contains(&text("expected_base")))
    );
    let operator = source_writes::tools()
        .into_iter()
        .find(|tool| tool.name == source_writes::PUBLISH)
        .unwrap();
    assert!(
        operator.schema.object().unwrap()["properties"]
            .object()
            .unwrap()
            .contains_key("initial")
    );
    assert!(is_write(SOURCE_PUBLISH));
}

#[test]
fn sponsored_mcp_prepares_inspects_publishes_and_recovers_original_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = PublicationFixture::new(
            format,
            SOURCE_CANDIDATES | SOURCE_PUBLISH | OUTCOMES_READ,
            &[b"file"],
        );
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = refs(&backend);
        let prepared = backend
            .call(candidate::NAME, &fixture.preparation())
            .unwrap();
        let prepared = prepared.object().unwrap();
        let mut inspection = prepared["publication_arguments"].object().unwrap().clone();
        inspection.insert("operation".into(), text("inspect"));
        inspection.insert(
            "expected_bundle_sha256".into(),
            prepared["bundle_sha256"].clone(),
        );
        let inspected = backend.call(candidate::NAME, &inspection).unwrap();
        assert_eq!(refs(&backend), before);
        let mut args = inspected.object().unwrap()["publication_arguments"]
            .object()
            .unwrap()
            .clone();
        args.insert("idempotency_key".into(), text(RETRY));
        let candidate =
            GitOid::from_hex(format, args["expected_candidate"].text().unwrap()).unwrap();
        assert!(backend.node.read_git_object(candidate).is_err());
        let published = backend.call(source_writes::PUBLISH, &args).unwrap();
        committed(&published);
        assert!(backend.is_mutation(source_writes::PUBLISH));
        assert!(!backend.result_is_error(source_writes::PUBLISH, &published));
        let fields = published.object().unwrap();
        assert_eq!(fields["type"], text("source_publication"));
        assert_eq!(fields["atomic"], Value::Bool(true));
        assert_eq!(fields["current_refs_asserted"], Value::Bool(false));
        assert_eq!(fields["bundle_validation_receipt"], Value::Null);
        assert_eq!(
            refs(&backend)[&RefName::try_new(REFERENCE.as_bytes()).unwrap()],
            candidate
        );
        let original = provenance(&backend, RETRY);
        let witness = original.agent_provenance().unwrap();
        assert_eq!(witness.agent(), AGENT);
        assert_eq!(witness.sponsor(), SPONSOR);
        assert_eq!(witness.credential_id(), fixture.credential);
        assert_eq!(
            backend.call(source_writes::PUBLISH, &args).unwrap(),
            published
        );
        assert!(backend.agent.as_ref().unwrap().request.is_none());
        assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
        assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
        assert!(
            !published
                .encode(MAX_RESPONSE)
                .unwrap()
                .contains(&token(0x71))
        );

        // Rotation changes the current credential, never the historical
        // publication's agent/sponsor witness or its exact original key.
        issue_source(
            &backend.node,
            0x72,
            SOURCE_PUBLISH | OUTCOMES_READ,
            &[b"other"],
            "rotate-scoped-publisher",
        );
        revoke(
            &backend.node,
            fixture.credential,
            "revoke-original-publisher",
        );
        assert_eq!(
            backend
                .call(source_writes::PUBLISH, &args)
                .unwrap_err()
                .code,
            "agent_credential_unavailable"
        );
        backend.close().unwrap();
        let replacement = fixture.fixture.replacement(0x72);
        let mut options = fixture.options.clone();
        options.agent_token_file = replacement.agent_token_file;
        let mut reopened = NodeTools::open(options).unwrap();
        assert_eq!(
            reopened.call(source_writes::PUBLISH, &args).unwrap(),
            published
        );
        let recovered = reopened
            .call("frankengit_transaction_outcome", &recovery(RETRY))
            .unwrap();
        committed(&recovered);
        let fields = recovered.object().unwrap();
        assert_eq!(fields["provenance_error"], Value::Null);
        let recorded = fields["principal_provenance"].object().unwrap();
        assert_eq!(recorded["state"], text("recorded"));
        assert_eq!(recorded["principal_id"], text(AGENT.to_string()));
        assert_eq!(recorded["authentication"], text("agent_credential"));
        let recorded_agent = recorded["agent_provenance"].object().unwrap();
        assert_eq!(recorded_agent["agent"], text(AGENT.to_string()));
        assert_eq!(recorded_agent["sponsor"], text(SPONSOR.to_string()));
        assert_eq!(
            recorded_agent["credential_id"],
            text(fixture.credential.to_string())
        );
        assert_eq!(provenance(&reopened, RETRY), original);
        reopened.close().unwrap();
    }
}

#[test]
fn source_publication_needs_its_independent_credential_and_launch_grant() {
    let fixture = PublicationFixture::new(GitHashAlgorithm::Sha1, SOURCE_PUBLISH, &[b"file"]);
    let backend = NodeTools::open(fixture.options.clone()).unwrap();
    let args = fixture.trusted_candidate(&backend, REFERENCE, "no-inherited-publication");
    let before = refs(&backend);
    backend.close().unwrap();

    // The pre-existing broad credential deliberately lacks source-publish.
    let mut options = fixture.fixture.options.clone();
    options.writes.source = true;
    let mut legacy = NodeTools::open(options).unwrap();
    assert_eq!(
        legacy.call(source_writes::PUBLISH, &args).unwrap_err().code,
        "agent_operation_not_granted"
    );
    assert_eq!(refs(&legacy), before);
    legacy.close().unwrap();

    let mut options = fixture.options.clone();
    options.writes.source = false;
    let mut disabled = NodeTools::open(options).unwrap();
    assert!(
        !disabled
            .tools()
            .iter()
            .any(|tool| tool.name == source_writes::PUBLISH)
    );
    assert_eq!(
        disabled
            .call(source_writes::PUBLISH, &args)
            .unwrap_err()
            .code,
        "tool_not_granted"
    );
    assert_eq!(
        source_writes::call(&disabled, source_writes::PUBLISH, &args)
            .unwrap_err()
            .code,
        "tool_not_granted"
    );
    disabled.close().unwrap();

    let mut publisher = NodeTools::open(fixture.options.clone()).unwrap();
    for (name, input) in [
        ("frankengit_source_blob", Object::new()),
        (candidate::NAME, fixture.preparation()),
    ] {
        assert_eq!(
            publisher.call(name, &input).unwrap_err().code,
            "agent_operation_not_granted"
        );
    }
    let published = publisher.call(source_writes::PUBLISH, &args).unwrap();
    committed(&published);
    publisher.close().unwrap();
}

#[test]
fn source_publication_checks_actual_paths_and_exact_ref_without_moving_refs() {
    let fixture = PublicationFixture::new(GitHashAlgorithm::Sha256, SOURCE_PUBLISH, &[b"allowed"]);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = refs(&backend);
    for (reference, retry) in [
        (REFERENCE, "out-of-path-scope"),
        ("refs/heads/main", "out-of-ref-scope"),
    ] {
        let args = fixture.trusted_candidate(&backend, reference, retry);
        let refused = backend.call(source_writes::PUBLISH, &args).unwrap();
        let fields = refused.object().unwrap();
        assert_eq!(fields["outcome"], text("refused"));
        assert_eq!(fields["refusal_code"], text("CapabilityScopeViolation"));
        assert_eq!(fields["ref_transaction_committed"], Value::Bool(false));
        assert!(backend.result_is_error(source_writes::PUBLISH, &refused));
        assert_eq!(refs(&backend), before);
        assert_eq!(
            backend.call(source_writes::PUBLISH, &args).unwrap(),
            refused
        );
    }
    backend.close().unwrap();
}

#[test]
fn source_publication_rejects_initial_and_rebase_before_credential_lookup() {
    let fixture = PublicationFixture::new(GitHashAlgorithm::Sha1, SOURCE_PUBLISH, &[b"file"]);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let args = fixture.trusted_candidate(&backend, REFERENCE, "closed-source-profile");
    revoke(
        &backend.node,
        fixture.credential,
        "revoke-before-closed-dispatch",
    );
    let before = refs(&backend);
    for initial in [Value::Bool(true), Value::Bool(false), Value::Null] {
        let mut initial_args = args.clone();
        initial_args.insert("initial".into(), initial);
        assert_eq!(
            backend
                .call(source_writes::PUBLISH, &initial_args)
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
        assert_eq!(
            source_writes::call(&backend, source_writes::PUBLISH, &initial_args)
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
    }
    for name in [
        source_writes::PUBLISH_REBASE,
        source_writes::CREATE,
        source_writes::UPDATE,
        source_writes::DELETE,
        source_writes::RENAME,
        source_writes::TRANSACTION,
        "frankengit_tag_create",
    ] {
        assert!(!backend.tools().iter().any(|tool| tool.name == name));
        assert_eq!(
            backend.call(name, &args).unwrap_err().code,
            "tool_not_granted"
        );
    }
    assert_eq!(refs(&backend), before);
    assert!(backend.agent.as_ref().unwrap().request.is_none());
    backend.close().unwrap();
}

#[test]
fn source_publication_direct_handler_retains_operation_key_and_original_deadline() {
    let fixture = PublicationFixture::new(
        GitHashAlgorithm::Sha256,
        SOURCE_CANDIDATES | SOURCE_PUBLISH,
        &[b"file"],
    );
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let args = fixture.trusted_candidate(&backend, REFERENCE, RETRY);
    let before = refs(&backend);
    assert_eq!(
        source_writes::call(&backend, source_writes::PUBLISH, &args)
            .unwrap_err()
            .code,
        "agent_request_required"
    );
    for (operation, retry, expected) in [
        (SOURCE_CANDIDATES, RETRY, "agent_operation_not_granted"),
        (SOURCE_PUBLISH, "another-key", "agent_request_key_mismatch"),
    ] {
        let request = reservation(&backend, operation, retry);
        backend.agent.as_mut().unwrap().request = Some(request);
        assert_eq!(
            source_writes::call(&backend, source_writes::PUBLISH, &args)
                .unwrap_err()
                .code,
            expected
        );
        backend.agent.as_mut().unwrap().request = None;
    }
    // The same key and agent identity cannot turn publication authority into
    // independent outcome disclosure when a direct handler bypasses discovery.
    backend.options.outcomes = true;
    let publication = reservation(&backend, SOURCE_PUBLISH, RETRY);
    backend.agent.as_mut().unwrap().request = Some(publication);
    assert_eq!(
        outcomes::call(&backend, &recovery(RETRY)).unwrap_err().code,
        "agent_operation_not_granted"
    );
    backend.agent.as_mut().unwrap().request = None;
    let mut expired = reservation(&backend, SOURCE_PUBLISH, RETRY);
    expired.constrain_deadline(Instant::now() - Duration::from_secs(1));
    expired.constrain_deadline(Instant::now() + Duration::from_secs(300));
    backend.agent.as_mut().unwrap().request = Some(expired);
    assert!(!backend.command_context().is_live());
    assert!(source_writes::call(&backend, source_writes::PUBLISH, &args).is_err());
    assert_eq!(refs(&backend), before);
    backend.agent.as_mut().unwrap().request = None;
    backend.close().unwrap();
}
