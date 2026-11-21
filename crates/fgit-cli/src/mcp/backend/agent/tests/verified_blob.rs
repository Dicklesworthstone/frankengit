//! Canonical sponsored proof grants cross the real persisted MCP adapter.
use super::super::super::{head_token, hex, verified_blob};
use super::*;
use fgit_identity::agent::{
    AgentCredentialId, SOURCE_HISTORY_READ, SOURCE_READ, SOURCE_VERIFIED_READ,
};
use fgit_types::{RefName, RepositoryAuthorityHeadId, RootLayoutVersion};
use fgit_verified_read::blob::{decode_verified_blob_envelope, verify_blob_against_head};

const NAME: &str = "frankengit_source_verified_blob";
const BYTES: &[u8] = b"agent MCP fixture\n";

fn authority(node: &OneNode) -> RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .basis()
        .id()
}

fn query(head: RepositoryAuthorityHeadId) -> Object {
    object([
        ("reference", text("refs/heads/main")),
        ("path_hex", text(hex(b"file"))),
        ("expected_head", text(head_token(head))),
    ])
    .object()
    .unwrap()
    .clone()
}

fn chunks(value: &Object, field: &str) -> Vec<u8> {
    let Value::Array(rows) = &value[field] else {
        panic!("hex chunks required")
    };
    rows.iter()
        .flat_map(|row| {
            let hex = row.text().unwrap();
            (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

struct ProofFixture {
    fixture: Fixture,
    options: Options,
    id: AgentCredentialId,
}
impl ProofFixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let fixture = Fixture::with_layout(format, RootLayoutVersion::RefStateMerkleV2);
        let administrator = NodeTools::open(fixture.options.clone()).unwrap();
        let id = issue(
            &administrator.node,
            &token(0x71),
            grant(&administrator.node, SOURCE_VERIFIED_READ),
            "proof-only",
        );
        for (byte, scope) in [
            (0x72, SOURCE_READ),
            (0x73, SOURCE_HISTORY_READ),
            (0x74, 0x0fff),
        ] {
            issue(
                &administrator.node,
                &token(byte),
                grant(&administrator.node, scope),
                &format!("proof-denied-{byte}"),
            );
        }
        let expired = fgit_identity::agent::AgentCredentialGrant {
            issued_at: now() - 120,
            expires_at: now() - 60,
            ..grant(&administrator.node, SOURCE_VERIFIED_READ)
        };
        issue(&administrator.node, &token(0x75), expired, "proof-expired");
        administrator.close().unwrap();
        let mut options = fixture.replacement(0x71);
        options.source = true;
        Self {
            fixture,
            options,
            id,
        }
    }
}

#[test]
fn sponsored_verified_blob_delivers_complete_independently_verified_proof_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = ProofFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = authority(&backend.node);
        assert_eq!(
            operation(&backend.options, NAME),
            Some(SOURCE_VERIFIED_READ)
        );
        assert!(backend.tools().iter().any(|tool| tool.name == NAME));
        assert!(!backend.is_mutation(NAME));
        let value = backend.call(NAME, &query(before)).unwrap();
        let result = value.object().unwrap();
        let frame = chunks(result, "proof_hex_chunks");
        let envelope = decode_verified_blob_envelope(&frame).unwrap();
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let verified = verify_blob_against_head(before, &reference, b"file", &envelope).unwrap();
        assert_eq!(verified.bytes, BYTES);
        assert_eq!(verified.source_commit, fixture.fixture.tip);
        assert_eq!(chunks(result, "bytes_hex_chunks"), BYTES);
        assert_eq!(
            result["independent_verification_required"],
            Value::Bool(true)
        );
        for field in [
            "repository_changed",
            "objects_staged",
            "published",
            "approval_granted",
        ] {
            assert_eq!(result[field], Value::Bool(false));
        }
        let reservation = backend.agent.as_ref().unwrap().response.as_ref().unwrap();
        assert!(
            reservation
                .check_operation(&backend.node, SOURCE_VERIFIED_READ)
                .is_ok()
        );
        assert!(reservation.mcp_source_read_context(&backend.node).is_err());
        assert!(reservation.source_candidates(&backend.node).is_err());
        let session = reservation.authenticated_session();
        let authentication = session.authenticated_session().unwrap().authentication();
        let witness = authentication.agent_provenance().unwrap();
        assert_eq!(witness.agent(), AGENT);
        assert_eq!(witness.sponsor(), SPONSOR);
        assert_eq!(witness.credential_id(), fixture.id);
        assert_eq!(authority(&backend.node), before);
        backend.close().unwrap();
    }
}

#[test]
fn sponsored_verified_blob_requires_explicit_scope_and_launch_ceiling_without_read_escalation() {
    let fixture = ProofFixture::new(GitHashAlgorithm::Sha256);
    for byte in [0x72, 0x73, 0x74] {
        let mut options = fixture.fixture.replacement(byte);
        options.source = true;
        let mut backend = NodeTools::open(options).unwrap();
        assert!(backend.tools().iter().any(|tool| tool.name == NAME));
        assert_eq!(
            backend.call(NAME, &Object::new()).unwrap_err().code,
            "agent_operation_not_granted"
        );
        backend.close().unwrap();
    }
    let mut expired = fixture.fixture.replacement(0x75);
    expired.source = true;
    let mut backend = NodeTools::open(expired).unwrap();
    assert_eq!(
        backend.call(NAME, &Object::new()).unwrap_err().code,
        "agent_credential_unavailable"
    );
    backend.close().unwrap();
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let head = authority(&backend.node);
    for name in [
        "frankengit_source_blob",
        "frankengit_source_compare",
        "frankengit_pull_diff",
        "frankengit_pull_list",
    ] {
        assert_eq!(
            backend.call(name, &Object::new()).unwrap_err().code,
            "agent_operation_not_granted",
            "{name}"
        );
    }
    let mut missing = query(head);
    missing.insert("path_hex".into(), text(hex(b"missing")));
    assert_eq!(
        backend.call(NAME, &missing).unwrap_err().code,
        "source_unavailable"
    );
    let mut limited = query(head);
    limited.insert(
        "max_blob_bytes".into(),
        super::super::super::json::number((BYTES.len() - 1) as u64),
    );
    assert_eq!(
        backend.call(NAME, &limited).unwrap_err().code,
        "verified_blob_byte_limit"
    );
    backend.options.source = false;
    assert!(!backend.tools().iter().any(|tool| tool.name == NAME));
    assert_eq!(
        backend.call(NAME, &Object::new()).unwrap_err().code,
        "tool_not_granted"
    );
    assert_eq!(authority(&backend.node), head);
    backend.close().unwrap();
}

#[test]
fn sponsored_verified_blob_preserves_original_expiry_completed_custody_and_current_revocation() {
    let fixture = ProofFixture::new(GitHashAlgorithm::Sha256);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let head = authority(&backend.node);
    let args = query(head);
    backend.call(NAME, &args).unwrap();
    let profile = backend.agent.as_ref().unwrap();
    assert!(response_checkpoint(profile, OUTPUT_BYTES).is_ok());
    assert!(response_checkpoint(profile, OUTPUT_BYTES + 1).is_err());
    // A completed proof response cannot grant a new direct handler invocation.
    assert_eq!(
        verified_blob::call(&backend, &args).unwrap_err().code,
        "agent_request_required"
    );
    // Clearing a mutable launch flag cannot replace the loaded canonical identity
    // with the ordinary trusted-local handler's context.
    backend.options.agent_token_file = None;
    assert_eq!(
        verified_blob::call(&backend, &args).unwrap_err().code,
        "agent_request_required"
    );
    let mut original = backend.agent.as_mut().unwrap().response.take().unwrap();
    original.constrain_deadline(std::time::Instant::now() - std::time::Duration::from_secs(1));
    backend.agent.as_mut().unwrap().request = Some(original);
    assert!(verified_blob::call(&backend, &args).is_err());
    backend.agent.as_mut().unwrap().request = None;
    backend.options.agent_token_file = fixture.options.agent_token_file.clone();
    assert_eq!(authority(&backend.node), head);
    // Canonical movement invalidates the supplied proof pin before any response.
    issue(
        &backend.node,
        &token(0x76),
        grant(&backend.node, SOURCE_READ),
        "advance-proof-head",
    );
    assert_eq!(
        backend.call(NAME, &args).unwrap_err().code,
        "source_snapshot_moved"
    );
    let current = query(authority(&backend.node));
    assert!(backend.call(NAME, &current).is_ok());
    revoke(&backend.node, fixture.id, "revoke-proof-reader");
    assert_eq!(
        backend.call(NAME, &current).unwrap_err().code,
        "agent_credential_unavailable"
    );
    backend.close().unwrap();
}
