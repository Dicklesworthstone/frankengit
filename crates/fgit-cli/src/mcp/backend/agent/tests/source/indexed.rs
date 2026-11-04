//! Sponsored persisted-index reads use real credentials, source and generations.
//! Adapter authorization cannot be recovered from a completed or unrelated call.
use super::*;

const LEXICAL: &str = "frankengit_source_search_index";
const SYMBOLS: &str = "frankengit_source_symbols";

fn lexical(mode: &str, channel: &str) -> Object {
    let mut args = query(LEXICAL);
    args.insert("source_mode".into(), text(mode));
    args.insert("channel".into(), text(channel));
    args.insert("limit".into(), json::number(1));
    args
}

fn symbols(mode: &str) -> Object {
    let mut args = query(SYMBOLS);
    args.insert("source_mode".into(), text(mode));
    args
}

pub(super) fn queries() -> Vec<(&'static str, Object)> {
    vec![
        (LEXICAL, lexical("exact", "content")),
        (LEXICAL, lexical("revalidated", "content")),
        (SYMBOLS, symbols("indexed-exact")),
        (SYMBOLS, symbols("indexed-current")),
    ]
}

pub(super) fn stale(name: &str) -> &'static str {
    if name == SYMBOLS {
        "symbol_index_stale"
    } else {
        "source_index_stale"
    }
}

fn head_bytes(backend: &NodeTools) -> Vec<u8> {
    backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .body()
        .to_vec()
}

fn continuation(args: &Object, page: &Value) -> Object {
    let mut next = args.clone();
    for (input, output) in [
        ("expected_head", "snapshot_token"),
        ("expected_commit", "source_commit"),
        ("index_token", "index_token"),
        ("index_number", "index_number"),
        ("after", "next_after"),
    ] {
        next.insert(input.into(), field(page, &[output]).clone());
    }
    next
}

fn with_floor(mut args: Object, response: &Value) -> Object {
    for (input, output) in [
        ("minimum_index_token", "index_token"),
        ("minimum_index_number", "index_number"),
    ] {
        args.insert(input.into(), field(response, &[output]).clone());
    }
    args
}

fn assert_read(value: &Value, tip: GitOid) {
    assert_eq!(field(value, &["source_commit"]), &text(tip.to_string()));
    assert_eq!(field(value, &["read_only"]), &Value::Bool(true));
    assert_eq!(field(value, &["transaction_created"]), &Value::Bool(false));
    assert_eq!(field(value, &["published"]), &Value::Bool(false));
    assert_eq!(field(value, &["coverage_complete"]), &Value::Bool(true));
}

#[test]
fn sponsored_indexes_page_and_search_both_formats_without_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = SourceFixture::new(format, true);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = head_bytes(&backend);
        for mode in ["exact", "revalidated"] {
            for channel in ["content", "path"] {
                let args = lexical(mode, channel);
                let first = backend.call(LEXICAL, &args).unwrap();
                assert_read(&first, fixture.tip);
                assert_eq!(field(&first, &["returned_hits"]), &text("1"));
                assert_eq!(
                    field(&rows(field(&first, &["hits"]))[0], &["path_hex"]),
                    &text(hex(b"src/Thing.rs"))
                );
                let floored = with_floor(args.clone(), &first);
                assert!(backend.call(LEXICAL, &floored).is_ok());
                if channel == "content" {
                    assert_eq!(field(&first, &["complete"]), &Value::Bool(false));
                    let next = continuation(&args, &first);
                    for missing in [
                        "expected_head",
                        "expected_commit",
                        "index_token",
                        "index_number",
                    ] {
                        let mut invalid = next.clone();
                        invalid.remove(missing);
                        assert!(backend.call(LEXICAL, &invalid).is_err(), "{missing}");
                    }
                    let second = backend.call(LEXICAL, &next).unwrap();
                    assert_read(&second, fixture.tip);
                    assert_eq!(field(&second, &["complete"]), &Value::Bool(true));
                    assert_eq!(field(&second, &["next_after"]), &Value::Null);
                    assert_eq!(
                        field(&rows(field(&second, &["hits"]))[0], &["path_hex"]),
                        &text(hex(b"src/comment.rs"))
                    );
                    for pin in [
                        "snapshot_token",
                        "source_commit",
                        "index_token",
                        "index_number",
                    ] {
                        assert_eq!(field(&first, &[pin]), field(&second, &[pin]), "{pin}");
                    }
                } else {
                    assert_eq!(field(&first, &["complete"]), &Value::Bool(true));
                    assert_eq!(field(&first, &["next_after"]), &Value::Null);
                }
            }
        }
        for mode in ["indexed-exact", "indexed-current"] {
            let args = symbols(mode);
            let found = backend.call(SYMBOLS, &args).unwrap();
            assert_read(&found, fixture.tip);
            assert_eq!(field(&found, &["complete"]), &Value::Bool(true));
            assert_eq!(field(&found, &["match_count"]), &text("1"));
            assert_eq!(
                field(&rows(field(&found, &["matches"]))[0], &["path_hex"]),
                &text(hex(b"src/Thing.rs"))
            );
            assert!(backend.call(SYMBOLS, &with_floor(args, &found)).is_ok());
        }
        // Each invocation leaves only a response reservation, never authority
        // that a directly reached handler can use for another source read.
        assert!(backend.agent.as_ref().unwrap().request.is_none());
        assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
        assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();
    }
}

#[test]
fn sponsored_indexes_preserve_generation_and_original_source_through_metadata_and_rotation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = SourceFixture::new(format, true);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let originals: Vec<_> = [
            (LEXICAL, lexical("revalidated", "content")),
            (SYMBOLS, symbols("indexed-current")),
        ]
        .into_iter()
        .map(|(name, args)| {
            let original = backend.call(name, &args).unwrap();
            (name, args, original)
        })
        .collect();
        issue(
            &backend.node,
            &token(0x47),
            grant(&backend.node, ISSUES_READ),
            "indexed-unrelated-metadata",
        );
        let after_metadata = head_bytes(&backend);
        for (name, args) in [
            (LEXICAL, lexical("exact", "content")),
            (SYMBOLS, symbols("indexed-exact")),
        ] {
            assert_eq!(backend.call(name, &args).unwrap_err().code, stale(name));
        }
        for (name, args, original) in &originals {
            let mut pinned = args.clone();
            pinned.insert(
                "expected_head".into(),
                field(original, &["snapshot_token"]).clone(),
            );
            assert_eq!(
                backend.call(name, &pinned).unwrap_err().code,
                "source_snapshot_moved"
            );
            let current = backend
                .call(name, &with_floor(args.clone(), original))
                .unwrap();
            assert_read(&current, fixture.tip);
            assert_eq!(
                field(&current, &["distinct_provenance"]),
                &Value::Bool(true)
            );
            for coordinate in ["source_commit", "index_token", "index_number"] {
                assert_eq!(
                    field(&current, &[coordinate]),
                    field(original, &[coordinate])
                );
            }
            assert_ne!(
                field(&current, &["snapshot_token"]),
                field(original, &["snapshot_token"])
            );
            assert_eq!(
                field(&current, &["indexed_source", "snapshot_token"]),
                field(original, &["snapshot_token"])
            );
            assert_eq!(
                field(&current, &["current_source", "snapshot_token"]),
                field(&current, &["snapshot_token"])
            );
            let mut unavailable = with_floor(args.clone(), original);
            let number: u64 = field(original, &["index_number"])
                .text()
                .unwrap()
                .parse()
                .unwrap();
            unavailable.insert(
                "minimum_index_number".into(),
                text((number + 1).to_string()),
            );
            assert!(backend.call(name, &unavailable).is_err());
            let mut tiny = args.clone();
            tiny.insert("max_payload_bytes".into(), json::number(1));
            assert!(backend.call(name, &tiny).is_err());
        }
        assert_eq!(
            backend
                .call(LEXICAL, &continuation(&originals[0].1, &originals[0].2))
                .unwrap_err()
                .code,
            "source_snapshot_moved"
        );
        assert_eq!(head_bytes(&backend), after_metadata);
        revoke(
            &backend.node,
            fixture.credential_id,
            "revoke-indexed-source",
        );
        issue(
            &backend.node,
            &token(0x44),
            grant(&backend.node, SOURCE_READ),
            "rotate-indexed-source",
        );
        let after_rotation = head_bytes(&backend);
        for (name, args) in queries() {
            assert_eq!(
                backend.call(name, &args).unwrap_err().code,
                "agent_credential_unavailable"
            );
        }
        assert_eq!(head_bytes(&backend), after_rotation);
        backend.close().unwrap();
        let mut revoked = NodeTools::open(fixture.options.clone()).unwrap();
        for (name, args) in queries() {
            assert_eq!(
                revoked.call(name, &args).unwrap_err().code,
                "agent_credential_unavailable"
            );
        }
        revoked.close().unwrap();
        let mut options = fixture.options.clone();
        options.agent_token_file = fixture.fixture.replacement(0x44).agent_token_file;
        let mut replacement = NodeTools::open(options).unwrap();
        for (name, args, original) in originals {
            let found = replacement
                .call(name, &with_floor(args, &original))
                .unwrap();
            assert_read(&found, fixture.tip);
            assert_eq!(
                field(&found, &["index_token"]),
                field(&original, &["index_token"])
            );
            assert_eq!(
                field(&found, &["indexed_source", "snapshot_token"]),
                field(&original, &["snapshot_token"])
            );
        }
        assert_eq!(head_bytes(&replacement), after_rotation);
        replacement.close().unwrap();
    }
}

#[test]
fn direct_index_handlers_require_an_active_live_source_request_before_parsing_or_io() {
    let fixture = SourceFixture::new(GitHashAlgorithm::Sha1, true);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = head_bytes(&backend);
    backend
        .call(LEXICAL, &lexical("revalidated", "content"))
        .unwrap();
    for (name, args) in queries() {
        assert_eq!(
            backend.call_granted(name, &args).unwrap_err().code,
            "agent_request_required"
        );
    }
    let mut request = backend.agent.as_mut().unwrap().response.take().unwrap();
    request.constrain_deadline(Instant::now() - Duration::from_secs(1));
    request.constrain_deadline(Instant::now() + Duration::from_secs(300));
    backend.agent.as_mut().unwrap().request = Some(request);
    for (name, args) in queries() {
        assert_eq!(
            backend.call_granted(name, &args).unwrap_err().code,
            "agent_authentication_unavailable"
        );
    }
    backend.agent.as_mut().unwrap().request = None;
    assert_eq!(head_bytes(&backend), before);
    backend.close().unwrap();

    let mut options = fixture.options.clone();
    options.agent_token_file = fixture.fixture.replacement(0x42).agent_token_file;
    options.issues = true;
    let mut metadata = NodeTools::open(options).unwrap();
    metadata
        .call("frankengit_issue_list", &Object::new())
        .unwrap();
    // Retain an authentic live reservation for the wrong operation. This must
    // fail even if central dispatch is bypassed and the result indexes exist.
    let metadata_request = metadata.agent.as_mut().unwrap().response.take();
    metadata.agent.as_mut().unwrap().request = metadata_request;
    for (name, args) in queries() {
        assert_eq!(
            metadata.call_granted(name, &args).unwrap_err().code,
            "agent_operation_not_granted"
        );
    }
    metadata.agent.as_mut().unwrap().request = None;
    for (name, args) in queries() {
        assert_eq!(
            metadata.call(name, &args).unwrap_err().code,
            "agent_operation_not_granted"
        );
    }
    assert_eq!(head_bytes(&metadata), before);
    metadata.close().unwrap();
}

#[test]
fn sponsored_persisted_read_modes_never_build_missing_indexes() {
    let fixture = SourceFixture::new(GitHashAlgorithm::Sha256, false);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = head_bytes(&backend);
    for _ in 0..2 {
        for (name, args) in queries() {
            assert_eq!(
                backend.call(name, &args).unwrap_err().code,
                if name == SYMBOLS {
                    "symbol_index_uninitialized"
                } else {
                    "source_index_uninitialized"
                }
            );
        }
    }
    assert_eq!(head_bytes(&backend), before);
    backend.close().unwrap();
}
