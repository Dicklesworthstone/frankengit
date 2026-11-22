//! Real failed workflow bytes cross sponsored MCP calls under their own
//! disclosure grant. Operator artifact custody is never substituted for it.

use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::ExpectedVersion;
use fgit_identity::agent::{
    AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant, AgentCredentialId,
    PULLS_CHECK_EVIDENCE_READ, PULLS_FEEDBACK_READ, SponsorKind, agent_credential_id,
};
use fgit_node::LoopbackReceiveSession;
use fgit_types::DecisionOutcome;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AGENT: PrincipalId = PrincipalId::from_bytes([0x68; 16]);
const SPONSOR: PrincipalId = PrincipalId::from_bytes([0x67; 16]);
const OUTPUT_BYTES: u64 = crate::mcp::protocol::MAX_RESPONSE as u64 + 1;

struct Credential {
    bearer: String,
    id: AgentCredentialId,
    grant: AgentCredentialGrant,
    options: Options,
}

fn publish_credential(backend: &NodeTools, command: &AgentCredentialCommand, key: &str) {
    let (_, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_agent_credential_durable_in(
            &backend.node.request_context(),
            &LoopbackReceiveSession::authenticated(
                SPONSOR,
                IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
            ),
            command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn issue(
    administrator: &NodeTools,
    fixture: &Fixture,
    byte: u8,
    operations: u32,
    expired: bool,
) -> Credential {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grant = AgentCredentialGrant {
        agent: AGENT,
        sponsor: SPONSOR,
        sponsor_kind: SponsorKind::Human,
        tenant: fixture.options.tenant,
        repository: fixture.options.repository,
        incarnation: administrator.node.repository_incarnation_id(),
        issued_at: now - if expired { 120 } else { 1 },
        expires_at: if expired { now - 60 } else { now + 3600 },
        operations,
    };
    let bearer = format!("fgagent_{}", format!("{byte:02x}").repeat(32));
    let id = agent_credential_id(bearer.as_bytes()).unwrap();
    publish_credential(
        administrator,
        &AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(grant),
        },
        &format!("issue-evidence-{byte:02x}"),
    );
    let path = fixture.root.join(format!("evidence-{byte:02x}.token"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    writeln!(file, "{bearer}").unwrap();
    let mut options = fixture.options.clone();
    options.agent_token_file = Some(path);
    options.artifacts = false;
    options.artifact_root = None;
    options.validate_access().unwrap();
    Credential {
        bearer,
        id,
        grant,
        options,
    }
}

fn revoke(backend: &NodeTools, credential: &Credential) {
    publish_credential(
        backend,
        &AgentCredentialCommand {
            id: credential.id,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(credential.grant),
        },
        "revoke-evidence-reader",
    );
}

fn server(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sponsored-evidence-test","version":"1"}}}"#).unwrap();
    server.receive(
        backend,
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    server
}

fn digest_refusal(server: &mut Server, backend: &mut NodeTools, arguments: &Object) {
    let mut wrong = arguments.clone();
    wrong.insert("expected_evidence_sha256".into(), text("00".repeat(32)));
    let request = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(3)),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(NAME)), ("arguments", Value::Object(wrong))]),
        ),
    ])
    .encode(4096)
    .unwrap();
    let response = server.receive(backend, request.as_bytes()).unwrap();
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(true));
    let encoded = response.encode(64 * 1024).unwrap();
    assert!(encoded.contains("check_evidence_identity_mismatch"));
    assert!(!encoded.contains("content_hex"));
    assert!(!encoded.contains("MCP-CHECK-FAILED"));
    assert!(backend.agent.as_ref().unwrap().response.is_none());
}

#[test]
fn sponsored_mcp_reads_real_failed_check_ranges_without_general_disclosure_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut administrator = NodeTools::open(fixture.options.clone()).unwrap();
        let reader = issue(
            &administrator,
            &fixture,
            0x91,
            PULLS_CHECK_EVIDENCE_READ,
            false,
        );
        // The full old non-publication mask includes feedback, but never the
        // independently added execution-output disclosure bit.
        let prior = issue(&administrator, &fixture, 0x92, 0xefff, false);
        let feedback = issue(&administrator, &fixture, 0x93, PULLS_FEEDBACK_READ, false);
        let expired = issue(
            &administrator,
            &fixture,
            0x94,
            PULLS_CHECK_EVIDENCE_READ,
            true,
        );
        let (listed, arguments) = listed_selection(&mut administrator);
        let before = head(&administrator);
        administrator.close().unwrap();

        for (credential, code) in [
            (&prior, "agent_operation_not_granted"),
            (&feedback, "agent_operation_not_granted"),
            (&expired, "agent_credential_unavailable"),
        ] {
            let mut backend = NodeTools::open(credential.options.clone()).unwrap();
            assert!(backend.tools().iter().any(|tool| tool.name == NAME));
            assert_eq!(backend.call(NAME, &arguments).unwrap_err().code, code);
            assert_eq!(head(&backend), before);
            backend.close().unwrap();
        }

        let mut backend = NodeTools::open(reader.options.clone()).unwrap();
        assert!(backend.tools().iter().any(|tool| tool.name == NAME));
        assert!(!backend.is_mutation(NAME));
        assert!(!backend.options.artifacts);
        assert!(backend.options.artifact_root.is_none());
        assert_eq!(
            call(&backend, &arguments).unwrap_err().code,
            "agent_request_required"
        );
        let mut server = server(&mut backend);
        let full = invoke(&mut server, &mut backend, arguments.clone());
        assert_no_authority(&full);
        assert_eq!(full.object().unwrap()["page"], listed);
        assert_eq!(
            full.object().unwrap()["content_hex"].text(),
            Some(hex(&fixture.evidence).as_str())
        );
        assert!(
            !full
                .encode(MAX_RESULT_BYTES)
                .unwrap()
                .contains(&reader.bearer)
        );
        let span = full.object().unwrap()["report_span"].object().unwrap();
        let offset =
            usize::try_from(json::decimal(span["offset"].text().unwrap()).unwrap()).unwrap();
        let report = std::str::from_utf8(&fixture.evidence[offset..]).unwrap();
        assert_eq!(
            span["bytes"].text(),
            Some(report.len().to_string().as_str())
        );
        for text in [
            hex(b"MCP-CHECK-FAILED"),
            hex(b"MCP-CHECK-ERROR"),
            "\"exit_code\":7".into(),
        ] {
            assert!(report.contains(&text));
        }
        let mut assembled = Vec::new();
        let mut chunk = arguments.clone();
        chunk.insert("limit".into(), json::number(257));
        loop {
            chunk.insert("offset".into(), text(assembled.len().to_string()));
            let value = invoke(&mut server, &mut backend, chunk.clone());
            assert_no_authority(&value);
            let fields = value.object().unwrap();
            assert_eq!(fields["page"], listed);
            assert_eq!(fields["report_span"], full.object().unwrap()["report_span"]);
            let bytes = unhex(fields["content_hex"].text().unwrap(), 65536).unwrap();
            assert!(!bytes.is_empty() && bytes.len() <= 257);
            assert_eq!(
                fields["byte_count"].text(),
                Some(bytes.len().to_string().as_str())
            );
            assembled.extend(bytes);
            if fields["next_offset"] == Value::Null {
                break;
            }
            assert_eq!(
                fields["next_offset"].text(),
                Some(assembled.len().to_string().as_str())
            );
        }
        assert_eq!(assembled, fixture.evidence);
        digest_refusal(&mut server, &mut backend, &arguments);

        // Launch groups only restrict the canonical grant. Enabling a broad
        // source group cannot turn diagnostic evidence into metadata or code.
        backend.options.source = true;
        for name in [
            "frankengit_pull_show",
            "frankengit_pull_checks",
            "frankengit_pull_reviews",
            "frankengit_source_blob",
        ] {
            assert_eq!(
                backend.call(name, &Object::new()).unwrap_err().code,
                "agent_operation_not_granted"
            );
        }
        backend.options.artifacts = true;
        for name in [
            "frankengit_artifact_read",
            "frankengit_artifact_inspect",
            "frankengit_pull_review",
            "frankengit_pull_merge",
        ] {
            assert!(!backend.tools().iter().any(|tool| tool.name == name));
            assert_eq!(
                backend.call(name, &Object::new()).unwrap_err().code,
                "tool_not_granted"
            );
        }
        // The loaded sponsored identity survives edits to mutable launch flags.
        backend.options.agent_token_file = None;
        assert_eq!(
            call(&backend, &arguments).unwrap_err().code,
            "agent_request_required"
        );
        backend.options.agent_token_file = reader.options.agent_token_file.clone();
        backend.options.artifacts = false;
        backend.options.source = false;
        backend.options.pulls = false;
        assert!(!backend.tools().iter().any(|tool| tool.name == NAME));
        assert_eq!(
            backend.call(NAME, &arguments).unwrap_err().code,
            "tool_not_granted"
        );
        backend.options.pulls = true;
        assert_eq!(head(&backend), before);

        fixture.advance_source(&backend);
        let moved = head(&backend);
        assert_ne!(moved, before);
        assert_eq!(invoke(&mut server, &mut backend, arguments.clone()), full);
        let mut stale = arguments.clone();
        stale.insert("expected_head".into(), text(head_token(moved)));
        assert_eq!(
            backend.call(NAME, &stale).unwrap_err().code,
            "pull_check_evidence_unavailable"
        );
        assert_eq!(head(&backend), moved);
        backend.close().unwrap();

        let mut reopened = NodeTools::open(reader.options.clone()).unwrap();
        assert_eq!(reopened.call(NAME, &arguments).unwrap(), full);
        assert_eq!(head(&reopened), moved);
        revoke(&reopened, &reader);
        let revoked = head(&reopened);
        assert_eq!(
            reopened.call(NAME, &arguments).unwrap_err().code,
            "agent_credential_unavailable"
        );
        assert_eq!(head(&reopened), revoked);
        reopened.close().unwrap();
    }
}

#[test]
fn sponsored_check_evidence_preserves_original_response_reservation_and_active_operation() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut administrator = NodeTools::open(fixture.options.clone()).unwrap();
    let reader = issue(
        &administrator,
        &fixture,
        0xa1,
        PULLS_CHECK_EVIDENCE_READ,
        false,
    );
    let feedback = issue(&administrator, &fixture, 0xa2, PULLS_FEEDBACK_READ, false);
    let (_, arguments) = listed_selection(&mut administrator);
    let before = head(&administrator);
    administrator.close().unwrap();
    let mut backend = NodeTools::open(reader.options.clone()).unwrap();
    backend.call(NAME, &arguments).unwrap();
    assert!(backend.agent.as_ref().unwrap().request.is_none());
    let reservation = backend.agent.as_ref().unwrap().response.as_ref().unwrap();
    let session = reservation.authenticated_session();
    let authentication = session.authenticated_session().unwrap().authentication();
    let witness = authentication.agent_provenance().unwrap();
    assert_eq!(witness.agent(), AGENT);
    assert_eq!(witness.sponsor(), SPONSOR);
    assert_eq!(witness.credential_id(), reader.id);
    assert!(reservation.mcp_source_read_context(&backend.node).is_err());
    assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
    assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
    assert_eq!(
        call(&backend, &arguments).unwrap_err().code,
        "agent_request_required"
    );
    let mut original = backend.agent.as_mut().unwrap().response.take().unwrap();
    original.constrain_deadline(Instant::now() - Duration::from_secs(1));
    original.constrain_deadline(Instant::now() + Duration::from_secs(300));
    backend.agent.as_mut().unwrap().response = Some(original);
    assert!(backend.response_checkpoint(0).is_err());
    let expired = backend.agent.as_mut().unwrap().response.take().unwrap();
    backend.agent.as_mut().unwrap().request = Some(expired);
    assert!(call(&backend, &arguments).is_err());
    backend.agent.as_mut().unwrap().request = None;

    let wrong_operation = backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_agent_request_in(
            &backend.node.request_context(),
            feedback.bearer.as_bytes(),
            &IdempotencyKey::new(b"feedback-cannot-disclose-evidence".to_vec()).unwrap(),
            PULLS_FEEDBACK_READ,
            fgit_crypto::sha256_digest(b"selected feedback summary"),
            4096,
            OUTPUT_BYTES,
        ))
        .unwrap();
    backend.agent.as_mut().unwrap().request = Some(wrong_operation);
    assert_eq!(
        call(&backend, &arguments).unwrap_err().code,
        "agent_operation_not_granted"
    );
    backend.agent.as_mut().unwrap().request = None;
    // A fresh ordinary call authenticates again; it never widens or revives
    // either the expired request or the feedback-only request retained above.
    backend.call(NAME, &arguments).unwrap();
    assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
    backend.finish_response();
    assert!(backend.agent.as_ref().unwrap().response.is_none());
    assert_eq!(
        call(&backend, &arguments).unwrap_err().code,
        "agent_request_required"
    );
    assert_eq!(head(&backend), before);
    backend.close().unwrap();
}
