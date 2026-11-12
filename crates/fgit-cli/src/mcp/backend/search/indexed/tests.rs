//! Closed MCP input, exact counters, coverage and native-document boundary checks.
//! Persisted source/index behavior is exercised separately by integration_tests.
use super::*;
use fgit_schema::mcp::{PaginationRules, ReadMutationClass};
use fgit_types::GitHashAlgorithm;
use std::collections::BTreeSet;

fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Object {
    let Value::Object(value) = object(pairs) else {
        unreachable!()
    };
    value
}
fn base() -> Object {
    fields([
        ("reference", text("refs/heads/main")),
        ("terms_hex", Value::Array(vec![text(hex(b"NEEDLE"))])),
    ])
}
fn token(byte: &str) -> String {
    format!("alg:1:{}", byte.repeat(64))
}
fn pins(args: &mut Object) {
    args.insert("expected_head".into(), text(token("a")));
    args.insert("expected_commit".into(), text("b".repeat(40)));
    args.insert("index_token".into(), text(token("e")));
    args.insert("index_number".into(), text("1"));
}
fn parse(args: &Object) -> Result<input::Query, ToolError> {
    input::parse(args, GitHashAlgorithm::Sha1)
}
fn array_mut(value: &mut Value) -> &mut Vec<Value> {
    let Value::Array(rows) = value else {
        panic!("expected array")
    };
    rows
}
fn object_mut(value: &mut Value) -> &mut Object {
    let Value::Object(fields) = value else {
        panic!("expected object")
    };
    fields
}
fn hit(doc: &mut Object) -> &mut Object {
    object_mut(&mut array_mut(doc.get_mut("hits").unwrap())[0])
}
fn scope() -> output::Scope {
    output::Scope {
        tenant: "1".repeat(32),
        repository: "2".repeat(32),
        incarnation: "3".repeat(32),
        format: GitHashAlgorithm::Sha1,
    }
}
fn source_coordinates() -> Object {
    fields([
        ("tenant_id", text("1".repeat(32))),
        ("repository_id", text("2".repeat(32))),
        ("repository_incarnation", text("3".repeat(32))),
        ("object_format", text("sha1")),
        ("ref_hex", text(hex(b"refs/heads/main"))),
        ("source_head", text("verified-head")),
        ("snapshot_token", text(token("a"))),
        ("source_rcr", text("verified-rcr")),
        ("forge_position_root", text("verified-forge-root")),
        ("source_commit", text("b".repeat(40))),
        ("root_tree", text("c".repeat(40))),
    ])
}
fn native(mode: input::Mode, number: u64) -> Object {
    let identity = |value| match mode {
        input::Mode::Exact => json::number(value),
        input::Mode::Revalidated => text(value.to_string()),
    };
    let mut doc = fields([
        ("type", text(mode.result_type())),
        ("schema_version", json::number(1)),
        ("profile", text(mode.profile())),
        ("tenant_id", text("1".repeat(32))),
        ("repository_id", text("2".repeat(32))),
        ("repository_incarnation", text("3".repeat(32))),
        ("object_format", text("sha1")),
        ("ref", text("refs/heads/main")),
        ("ref_hex", text(hex(b"refs/heads/main"))),
        ("source_head", text("verified-head")),
        ("snapshot_token", text(token("a"))),
        ("source_rcr", text("verified-rcr")),
        ("source_commit", text("b".repeat(40))),
        ("root_tree", text("c".repeat(40))),
        ("index_token", text(token("e"))),
        ("index_number", identity(number)),
        ("selected_index_token", text(token("e"))),
        ("selected_index_number", identity(number)),
        ("read_only", Value::Bool(true)),
        ("transaction_created", Value::Bool(false)),
        ("published", Value::Bool(false)),
        ("channel", text("content")),
        ("after", Value::Null),
        ("limit", json::number(20)),
        ("returned_hits", json::number(1)),
        ("complete", Value::Bool(true)),
        ("next_after", Value::Null),
        ("indexed_documents", json::number(1)),
        ("indexed_source_bytes", json::number(6)),
        ("non_regular_entries", json::number(0)),
        ("segments_read", json::number(1)),
        ("payload_bytes_read", json::number(100)),
        ("generation_bytes_read", json::number(100)),
        ("work_units", json::number(10)),
        ("terms_hex", Value::Array(vec![text(hex(b"needle"))])),
        ("path_prefix_hex", Value::Array(Vec::new())),
        (
            "hits",
            Value::Array(vec![object([
                ("document_id", identity(number)),
                ("path_hex", text(hex(b"file.txt"))),
                ("blob", text("d".repeat(40))),
                ("content_bytes", json::number(6)),
                (
                    "spans",
                    Value::Array(vec![object([
                        ("query_index", json::number(0)),
                        ("byte_offset", json::number(0)),
                        ("byte_length", json::number(6)),
                    ])]),
                ),
            ])]),
        ),
    ]);
    if mode == input::Mode::Revalidated {
        doc.insert("source_mode".into(), text(mode.label()));
        doc.insert("current_source".into(), Value::Object(source_coordinates()));
        doc.insert("indexed_source".into(), Value::Object(source_coordinates()));
        doc.insert("distinct_provenance".into(), Value::Bool(false));
    }
    doc
}
fn decoded(doc: Object, query: &input::Query) -> Result<Value, ToolError> {
    let document = Value::Object(doc).encode(MAX_RESULT_BYTES).unwrap();
    output::decode(&document, query, &scope())
}

#[test]
fn closed_arguments_preserve_native_query_semantics_and_independent_limits() {
    let mut args = base();
    args.insert(
        "terms_hex".into(),
        Value::Array(vec![text(hex(b"NEEDLE")), text(hex(b"needle"))]),
    );
    args.insert(
        "path_prefixes_hex".into(),
        Value::Array(vec![text(hex(b"src")), text(hex(b"src"))]),
    );
    let query = parse(&args).unwrap();
    assert_eq!(query.mode, input::Mode::Revalidated);
    assert_eq!(query.query.terms(), &[b"needle".to_vec()]);
    assert_eq!(query.query.prefixes(), &[b"src".to_vec()]);
    assert_eq!(
        (query.limit, query.max_work, query.max_payload_bytes),
        (20, MAX_WORK, DEFAULT_PAYLOAD)
    );
    assert!(
        query
            .fields
            .contains(&("source_mode".into(), "revalidated".into()))
    );
    assert!(query.fields.contains(&("channel".into(), "content".into())));
    assert_eq!(
        query
            .fields
            .iter()
            .filter(|(name, _)| name == "term_hex")
            .count(),
        2
    );
    assert!(query.fields.iter().all(|(name, _)| name != "object_format"));

    for name in [
        "object_format",
        "principal",
        "storage",
        "build",
        "force",
        "agent_token",
        "idempotency_key",
        "needle_hex",
    ] {
        let mut args = base();
        args.insert(name.into(), text("forbidden"));
        assert_eq!(parse(&args).unwrap_err().code, "unknown_argument", "{name}");
    }
    for (name, value, code) in [
        ("terms_hex", text("aa"), "expected_array"),
        ("terms_hex", Value::Array(vec![]), "invalid_index_query"),
        (
            "terms_hex",
            Value::Array(vec![json::number(1)]),
            "expected_string",
        ),
        (
            "terms_hex",
            Value::Array(vec![text("abCD")]),
            "invalid_hex_bytes",
        ),
        (
            "terms_hex",
            Value::Array(vec![text(hex(b"a b"))]),
            "invalid_index_query",
        ),
        ("source_mode", text("fallback"), "invalid_index_source_mode"),
        ("channel", text("semantic"), "unsupported_index_channel"),
        ("reference", text("main"), "invalid_ref"),
    ] {
        let mut args = base();
        args.insert(name.into(), value);
        assert_eq!(parse(&args).unwrap_err().code, code, "{name}");
    }
}

#[test]
fn every_page_and_byte_ceiling_has_an_accepted_boundary_twin() {
    for (name, maximum) in [
        ("limit", MAX_PAGE),
        ("max_work", MAX_WORK),
        ("max_payload_bytes", MAX_PAYLOAD),
    ] {
        let mut args = base();
        args.insert(name.into(), json::number(maximum));
        assert!(parse(&args).is_ok(), "{name}");
        for value in [
            json::number(0),
            json::number(maximum + 1),
            text("1"),
            Value::Null,
            Value::Number("1.0".into()),
        ] {
            args.insert(name.into(), value);
            assert_eq!(
                parse(&args).unwrap_err().code,
                "invalid_index_limit",
                "{name}"
            );
        }
    }
    let mut args = base();
    let word = vec![b'x'; 128];
    args.insert("terms_hex".into(), Value::Array(vec![text(hex(&word)); 32]));
    assert!(parse(&args).is_ok());
    args.insert("terms_hex".into(), Value::Array(vec![text(hex(&word)); 33]));
    assert!(parse(&args).is_err());
    args.insert(
        "terms_hex".into(),
        Value::Array(vec![text(hex(&vec![b'x'; 129]))]),
    );
    assert!(parse(&args).is_err());
    let reference = format!("refs/heads/{}", "x".repeat(1024 - "refs/heads/".len()));
    args = base();
    args.insert("reference".into(), text(&reference));
    assert!(parse(&args).is_ok());
    args.insert("reference".into(), text(format!("{reference}x")));
    assert!(parse(&args).is_err());
    args = base();
    let component = vec![b'x'; 64];
    args.insert(
        "path_prefixes_hex".into(),
        Value::Array(vec![text(hex(&component)); 128]),
    );
    assert!(parse(&args).is_ok());
    let prefixes = array_mut(args.get_mut("path_prefixes_hex").unwrap());
    prefixes[0] = text(hex(&vec![b'x'; 65]));
    assert_eq!(parse(&args).unwrap_err().code, "invalid_search_scope");
}

#[test]
fn continuation_requires_all_original_pins_and_lossless_positive_decimal_positions() {
    for missing in [
        "expected_head",
        "expected_commit",
        "index_token",
        "index_number",
    ] {
        let mut args = base();
        pins(&mut args);
        args.insert("after".into(), text("1"));
        args.remove(missing);
        assert!(parse(&args).is_err(), "{missing}");
    }
    for number in ["9007199254740993", "18446744073709551615"] {
        let mut args = base();
        pins(&mut args);
        args.insert("index_number".into(), text(number));
        args.insert("minimum_index_token".into(), text(token("f")));
        args.insert("minimum_index_number".into(), text(number));
        args.insert("after".into(), text(number));
        let query = parse(&args).unwrap();
        assert_eq!(query.after.unwrap().to_string(), number);
        assert_eq!(query.generation.unwrap().1.to_string(), number);
    }
    for number in ["0", "01", "-1", "+1", "1e2", "1.0", "18446744073709551616"] {
        let mut args = base();
        pins(&mut args);
        args.insert("after".into(), text(number));
        assert_eq!(
            parse(&args).unwrap_err().code,
            "invalid_decimal_string",
            "{number}"
        );
    }
    let mut args = base();
    args.insert("minimum_index_number".into(), text("1"));
    assert_eq!(
        parse(&args).unwrap_err().code,
        "incomplete_index_generation"
    );
    args = base();
    args.insert("expected_commit".into(), text("0".repeat(40)));
    assert_eq!(parse(&args).unwrap_err().code, "invalid_expected_commit");
}

#[test]
fn output_is_lossless_in_both_native_modes_and_states_coverage_explicitly() {
    for mode in [input::Mode::Exact, input::Mode::Revalidated] {
        let mut args = base();
        args.insert("source_mode".into(), text(mode.label()));
        let query = parse(&args).unwrap();
        let result = decoded(native(mode, u64::MAX), &query).unwrap();
        let doc = result.object().unwrap();
        assert_eq!(doc["index_number"].text(), Some("18446744073709551615"));
        assert_eq!(
            doc["selected_index_number"].text(),
            Some("18446744073709551615")
        );
        assert_eq!(doc["returned_hits"].text(), Some("1"));
        assert_eq!(doc["coverage_complete"], Value::Bool(true));
        assert_eq!(doc["omitted_files"].text(), Some("0"));
        assert_eq!(doc["counter_encoding"].text(), Some("decimal-strings-v1"));
        assert_eq!(doc["source_mode"].text(), Some(mode.label()));
        let Value::Array(hits) = &doc["hits"] else {
            unreachable!()
        };
        assert_eq!(
            hits[0].object().unwrap()["document_id"].text(),
            Some("18446744073709551615")
        );
        let Value::Array(spans) = &hits[0].object().unwrap()["spans"] else {
            unreachable!()
        };
        assert_eq!(spans[0].object().unwrap()["byte_offset"].text(), Some("0"));
    }
}

#[test]
fn output_requires_coherent_full_pages_and_refuses_scope_or_provenance_drift() {
    let mut args = base();
    args.insert("limit".into(), json::number(1));
    let query = parse(&args).unwrap();
    let mut good = native(input::Mode::Revalidated, 1);
    good.insert("limit".into(), json::number(1));
    good.insert("complete".into(), Value::Bool(false));
    good.insert("next_after".into(), text("1"));
    assert!(decoded(good.clone(), &query).is_ok());
    for variant in 0..12 {
        let mut bad = good.clone();
        match variant {
            0 => {
                bad.insert("next_after".into(), Value::Null);
            }
            1 => {
                bad.insert("complete".into(), Value::Bool(true));
            }
            2 => {
                bad.insert("returned_hits".into(), json::number(0));
            }
            3 => {
                bad.insert("tenant_id".into(), text("4".repeat(32)));
            }
            4 => {
                bad.insert("object_format".into(), text("sha256"));
            }
            5 => {
                bad.insert("terms_hex".into(), Value::Array(vec![text(hex(b"other"))]));
            }
            6 => {
                bad.insert(
                    "payload_bytes_read".into(),
                    json::number(DEFAULT_PAYLOAD + 1),
                );
            }
            7 => {
                bad.insert("work_units".into(), json::number(MAX_WORK + 1));
            }
            8 => {
                bad.insert("distinct_provenance".into(), Value::Bool(true));
            }
            9 => {
                object_mut(bad.get_mut("indexed_source").unwrap())
                    .insert("source_commit".into(), text("f".repeat(40)));
            }
            10 => {
                hit(&mut bad).insert("document_id".into(), text("0"));
            }
            _ => {
                hit(&mut bad).insert("content_bytes".into(), json::number(5));
            }
        }
        assert_eq!(
            decoded(bad, &query).unwrap_err().code,
            "invalid_index_report",
            "{variant}"
        );
    }
    // A forge-only advance can retain an index without forging its provenance.
    let mut moved = good;
    let indexed = object_mut(moved.get_mut("indexed_source").unwrap());
    indexed.insert("source_head".into(), text("older-head"));
    indexed.insert("snapshot_token".into(), text(token("f")));
    indexed.insert("source_rcr".into(), text("older-rcr"));
    indexed.insert("forge_position_root".into(), text("older-forge-root"));
    moved.insert("distinct_provenance".into(), Value::Bool(true));
    assert!(decoded(moved, &query).is_ok());
}

fn omission(index: usize) -> Value {
    object([
        (
            "path_hex",
            text(hex(
                format!("vendor/{index:06}-{}", "x".repeat(64)).as_bytes()
            )),
        ),
        ("blob", text("f".repeat(40))),
        ("source_bytes", json::number(129)),
        ("reason", text("file_bytes")),
        ("limit", json::number(128)),
    ])
}
fn partial(rows: Vec<Value>) -> Object {
    let mut doc = native(input::Mode::Revalidated, 1);
    doc.insert("schema_version".into(), json::number(2));
    doc.insert(
        "index_profile".into(),
        text("ascii-word-postings-omissions-v1"),
    );
    doc.insert("coverage_complete".into(), Value::Bool(false));
    doc.insert("omitted_files".into(), json::number(rows.len() as u64));
    doc.insert(
        "omitted_source_bytes".into(),
        json::number(rows.len() as u64 * 129),
    );
    doc.insert("omissions".into(), Value::Array(rows));
    doc
}

#[test]
fn pagination_completion_never_erases_whole_corpus_omissions() {
    let query = parse(&base()).unwrap();
    let mut doc = partial(vec![omission(1)]);
    doc.insert("hits".into(), Value::Array(vec![]));
    doc.insert("returned_hits".into(), json::number(0));
    let value = decoded(doc.clone(), &query).unwrap();
    let fields = value.object().unwrap();
    assert_eq!(fields["complete"], Value::Bool(true));
    assert_eq!(fields["coverage_complete"], Value::Bool(false));
    assert_eq!(fields["omitted_files"].text(), Some("1"));
    assert_eq!(fields["omitted_source_bytes"].text(), Some("129"));
    for change in 0..4 {
        let mut bad = doc.clone();
        match change {
            0 => {
                bad.insert("coverage_complete".into(), Value::Bool(true));
            }
            1 => {
                bad.insert("omissions".into(), Value::Array(vec![]));
            }
            2 => {
                bad.insert("omitted_source_bytes".into(), json::number(128));
            }
            _ => {
                bad.insert("schema_version".into(), json::number(1));
            }
        }
        assert!(decoded(bad, &query).is_err(), "{change}");
    }
}

#[test]
fn normalization_has_its_own_one_mib_output_bound_and_never_truncates_coverage() {
    let query = parse(&base()).unwrap();
    let overhead = Value::Object(partial(vec![]))
        .encode(MAX_RESULT_BYTES)
        .unwrap()
        .len();
    let row_bytes = omission(0).encode(MAX_RESULT_BYTES).unwrap().len() + 1;
    // Leave enough room for the decimal row count, but less than the expansion
    // caused by quoting two exact counters in every retained omission.
    let count = (MAX_RESULT_BYTES - overhead - 2048) / row_bytes;
    assert!(count > 1024 && count < 10_000);
    let doc = partial((0..count).map(omission).collect());
    let encoded = Value::Object(doc).encode(MAX_RESULT_BYTES).unwrap();
    assert!(encoded.len() <= MAX_RESULT_BYTES);
    assert_eq!(
        output::decode(&encoded, &query, &scope()).unwrap_err().code,
        "index_result_limit"
    );
}

#[test]
fn served_schema_registry_and_actual_output_keys_remain_in_parity() {
    let served = tool();
    let contract = fgit_schema::mcp::find_tool(NAME).unwrap();
    assert_eq!(contract.read_mutation, ReadMutationClass::ReadOnly);
    assert_eq!(contract.pagination, PaginationRules::SnapshotBoundCursor);
    assert_eq!(contract.budget.max_output_bytes, MAX_RESULT_BYTES as u32);
    let schema = served.schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let declared: BTreeSet<_> = contract
        .input_fields
        .iter()
        .map(|field| field.name)
        .collect();
    let properties = schema["properties"].object().unwrap();
    assert_eq!(declared, properties.keys().map(String::as_str).collect());
    assert_eq!(declared, input::FIELDS.iter().copied().collect());
    let required: BTreeSet<_> = contract
        .input_fields
        .iter()
        .filter(|field| field.required)
        .map(|field| field.name)
        .collect();
    assert_eq!(required, ["reference", "terms_hex"].into_iter().collect());

    for mode in [input::Mode::Exact, input::Mode::Revalidated] {
        let mut args = base();
        args.insert("source_mode".into(), text(mode.label()));
        let query = parse(&args).unwrap();
        let result = decoded(native(mode, 1), &query).unwrap();
        let fields = result.object().unwrap();
        let output_keys: BTreeSet<_> = contract
            .output_fields
            .iter()
            .filter(|field| field.required || mode == input::Mode::Revalidated)
            .map(|field| field.name)
            .collect();
        assert_eq!(output_keys, fields.keys().map(String::as_str).collect());
    }
}

#[test]
fn request_errors_remain_distinct_from_missing_stale_and_over_budget_indexes() {
    for code in [
        "invalid_index_limit",
        "unknown_index_field",
        "unsupported_index_channel",
        "incomplete_index_generation",
        "index_continuation_requires_pins",
    ] {
        assert!(refusal(code).invalid, "{code}");
    }
    for code in [
        "source_index_uninitialized",
        "source_index_stale",
        "index_checkpoint_unavailable",
        "resource_limit",
        "request_timeout",
        "repository_unavailable",
    ] {
        assert!(!refusal(code).invalid, "{code}");
    }
}
