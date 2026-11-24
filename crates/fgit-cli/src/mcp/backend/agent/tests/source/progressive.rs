//! Buffered progressive reads retain canonical sponsorship, original index
//! provenance and response custody without acquiring another source grant.
use super::*;

const NAME: &str = SOURCE_TOOLS[7];

fn progressive() -> Object {
    let mut args = query(NAME);
    args.insert("operation".into(), text("progressive"));
    args.insert("symbol_name_hex".into(), text(hex(b"Thing")));
    args.insert("symbol_policy".into(), text("required"));
    args
}

fn phases(value: &Value) -> &[Value] {
    rows(field(value, &["phases"]))
}

fn initial(value: &Value) -> &Value {
    field(&phases(value)[0], &["answer"])
}

fn assert_authorized(value: &Value, tip: GitOid) {
    let initial = initial(value);
    assert_eq!(field(initial, &["source_commit"]), &text(tip.to_string()));
    assert_eq!(
        field(initial, &["authorization", "host"]).text(),
        Some(HOST)
    );
    assert_eq!(
        field(initial, &["authorization", "principal"]),
        &text(AGENT.to_string())
    );
    assert_eq!(
        field(initial, &["authorization", "scope"]).text(),
        Some("whole-repository")
    );
    assert_eq!(
        field(initial, &["authorization", "reusable_capability"]),
        &Value::Bool(false)
    );
    assert!(!rows(field(initial, &["content", "hits"])).is_empty());
    assert_eq!(
        field(value, &["source_material_untrusted"]),
        &Value::Bool(true)
    );
    let encoded = value
        .encode(super::super::super::OUTPUT_BYTES as usize)
        .unwrap();
    assert!(!encoded.contains("fgagent_"));
}

#[test]
fn sponsored_progressive_preserves_source_labels_and_reuses_original_generations_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = SourceFixture::new(format, true);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let args = progressive();
        let before = backend
            .node
            .runtime()
            .block_on(backend.node.authenticate_authority_head())
            .unwrap();
        let result = backend.call(NAME, &args).unwrap();
        assert_authorized(&result, fixture.tip);
        assert!(!backend.result_is_error(NAME, &result));
        assert_eq!(
            field(&result, &["refinement_succeeded"]),
            &Value::Bool(true)
        );
        assert_eq!(
            field(&phases(&result)[1], &["answer", "retrieval"]),
            initial(&result)
        );
        let files = rows(field(&phases(&result)[1], &["answer", "files"]));
        assert!(files.iter().any(|file| {
            rows(field(file, &["excerpts"]))
                .iter()
                .any(|excerpt| field(excerpt, &["untrusted_bytes_hex"]) == &text(hex(FILE)))
        }));
        assert!(backend.agent.as_ref().unwrap().request.is_none());
        let response = backend.agent.as_ref().unwrap().response.as_ref().unwrap();
        let read = response.mcp_source_read_context(&backend.node).unwrap();
        assert_eq!(read.principal(), Some(AGENT));
        assert_eq!(read.sponsor(), Some(SPONSOR));
        assert_eq!(
            read.agent_authentication().unwrap().credential_id(),
            fixture.credential_id
        );
        assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
        assert_eq!(
            backend.call_granted(NAME, &args).unwrap_err().code,
            "agent_request_required"
        );
        let after = backend
            .node
            .runtime()
            .block_on(backend.node.authenticate_authority_head())
            .unwrap();
        assert_eq!(before.receipt(), after.receipt());

        // An unrelated canonical event changes the current source observation,
        // not either immutable index generation or its original source label.
        issue(
            &backend.node,
            &token(0x4e),
            grant(&backend.node, ISSUES_READ),
            "progressive-metadata",
        );
        assert_eq!(
            backend.call(NAME, &args).unwrap_err().code,
            "source_index_stale"
        );
        let mut current_args = args.clone();
        current_args.insert("index_source".into(), text("current-native-v1"));
        let current_before = backend
            .node
            .runtime()
            .block_on(backend.node.authenticate_authority_head())
            .unwrap();
        let current = backend.call(NAME, &current_args).unwrap();
        assert_authorized(&current, fixture.tip);
        assert_eq!(
            field(initial(&current), &["index_source"]).text(),
            Some("current-native-v1")
        );
        assert_ne!(
            field(initial(&current), &["snapshot_token"]),
            field(initial(&result), &["snapshot_token"])
        );
        assert_eq!(
            field(initial(&current), &["generation_vector"]),
            field(initial(&result), &["generation_vector"])
        );
        for index in ["lexical", "symbols"] {
            assert_eq!(
                field(
                    initial(&current),
                    &["index_sources", index, "snapshot_token"]
                ),
                field(initial(&result), &["snapshot_token"])
            );
        }
        assert_eq!(
            field(&phases(&current)[1], &["answer", "retrieval"]),
            initial(&current)
        );
        current_args.insert("context_max_source_bytes".into(), json::number(1));
        let failed = backend.call(NAME, &current_args).unwrap();
        assert_authorized(&failed, fixture.tip);
        for key in [
            "source_commit",
            "root_tree",
            "snapshot_token",
            "generation_vector",
            "index_sources",
        ] {
            assert_eq!(
                field(initial(&failed), &[key]),
                field(initial(&current), &[key])
            );
        }
        // Limits are part of a new call's canonical request commitment. Labels
        // must be rebound for this invocation, never copied from the prior one.
        assert_ne!(
            field(initial(&failed), &["authorization", "binding"]),
            field(initial(&current), &["authorization", "binding"])
        );
        assert!(backend.result_is_error(NAME, &failed));
        assert_eq!(
            field(&phases(&failed)[1], &["code"]).text(),
            Some("resource_limit")
        );
        assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
        let current_after = backend
            .node
            .runtime()
            .block_on(backend.node.authenticate_authority_head())
            .unwrap();
        assert_eq!(current_before.receipt(), current_after.receipt());

        // Keeping useful Initial data cannot extend the completed reservation.
        let mut response = backend.agent.as_mut().unwrap().response.take().unwrap();
        response.constrain_deadline(Instant::now() - Duration::from_secs(1));
        response.constrain_deadline(Instant::now() + Duration::from_secs(300));
        assert!(response.mcp_source_read_context(&backend.node).is_err());
        backend.agent.as_mut().unwrap().response = Some(response);
        assert!(backend.response_checkpoint(0).is_err());
        assert_eq!(
            backend.call_granted(NAME, &current_args).unwrap_err().code,
            "agent_request_required"
        );
        backend.begin_message();
        assert!(backend.agent.as_ref().unwrap().response.is_none());
        backend.close().unwrap();
    }
}

#[test]
fn progressive_requires_both_launch_grant_and_current_canonical_read_credential() {
    let fixture = SourceFixture::new(GitHashAlgorithm::Sha256, true);
    let mut options = fixture.options.clone();
    options.agent_token_file = fixture.fixture.replacement(0x42).agent_token_file;
    let mut metadata_only = NodeTools::open(options).unwrap();
    assert_eq!(
        metadata_only.call(NAME, &progressive()).unwrap_err().code,
        "agent_operation_not_granted"
    );
    assert!(metadata_only.agent.as_ref().unwrap().response.is_none());
    metadata_only.close().unwrap();
    let mut options = fixture.options.clone();
    options.source = false;
    let mut disabled = NodeTools::open(options).unwrap();
    assert_eq!(
        disabled.call(NAME, &progressive()).unwrap_err().code,
        "tool_not_granted"
    );
    assert!(disabled.agent.as_ref().unwrap().response.is_none());
    disabled.close().unwrap();
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    assert!(backend.call(NAME, &progressive()).is_ok());
    revoke(
        &backend.node,
        fixture.credential_id,
        "revoke-progressive-source",
    );
    assert_eq!(
        backend.call(NAME, &progressive()).unwrap_err().code,
        "agent_credential_unavailable"
    );
    assert!(backend.agent.as_ref().unwrap().response.is_none());
    let mut expired = grant(&backend.node, SOURCE_READ);
    expired.issued_at = now() - 3;
    expired.expires_at = now() - 1;
    issue(
        &backend.node,
        &token(0x4f),
        expired,
        "issue-expired-progressive",
    );
    backend.close().unwrap();
    let mut options = fixture.options.clone();
    options.agent_token_file = fixture.fixture.replacement(0x4f).agent_token_file;
    let mut expired = NodeTools::open(options).unwrap();
    assert_eq!(
        expired.call(NAME, &progressive()).unwrap_err().code,
        "agent_credential_unavailable"
    );
    assert!(expired.agent.as_ref().unwrap().response.is_none());
    expired.close().unwrap();
}

#[test]
fn sponsored_missing_index_refuses_before_initial_and_retains_no_response_custody() {
    let fixture = SourceFixture::new(GitHashAlgorithm::Sha1, false);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_authority_head())
        .unwrap();
    assert_eq!(
        backend.call(NAME, &progressive()).unwrap_err().code,
        "source_index_uninitialized"
    );
    assert!(backend.agent.as_ref().unwrap().request.is_none());
    assert!(backend.agent.as_ref().unwrap().response.is_none());
    let after = backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_authority_head())
        .unwrap();
    assert_eq!(before.receipt(), after.receipt());
    backend.close().unwrap();
}
