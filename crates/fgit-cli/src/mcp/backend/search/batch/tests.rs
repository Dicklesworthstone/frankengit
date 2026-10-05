use super::*;
use fgit_types::RepositoryCommitId;

fn fields<const N: usize>(fields: [(&str, Value); N]) -> Object {
    let Value::Object(value) = object(fields) else { unreachable!() };
    value
}
fn input() -> Object {
    fields([
        ("reference", text("refs/heads/main")),
        ("needles_hex", Value::Array(vec![text("61"), text("7a"), text("61")])),
        ("max_matches", json::number(1)),
    ])
}
fn token() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(), CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    )
}
fn oid(byte: u8) -> GitOid {
    GitOid::from_hex(GitHashAlgorithm::Sha256, &format!("{byte:02x}").repeat(32)).unwrap()
}
fn setup() -> (Selection, SourceQueryBatch, SourceSearchBatchReport) {
    let (selection, queries) = parse(&input(), GitHashAlgorithm::Sha256).unwrap();
    let mut report = queries.empty_report(
        RepositoryId::from_bytes([2; 16]),
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).unwrap(), CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[8; 32]).unwrap(),
        ),
        oid(1), oid(2),
    );
    report.files_selected = 1;
    report.files_read = 1;
    report.bytes_read = 2;
    report.bytes_searched = 2;
    let found = SourceMatch {
        path: vec![255], blob: oid(3), byte_offset: 0, line: 1, byte_column: 1,
        excerpt: b"aa".to_vec(), excerpt_offset: 0, match_length: 1,
    };
    for i in [0, 2] {
        report.results[i].matches.push(found.clone());
        report.results[i].completion = SearchCompletion::MatchLimit;
    }
    (selection, queries, report)
}
fn rendered(selection: &Selection, queries: &SourceQueryBatch, report: &SourceSearchBatchReport) -> Result<Object, ToolError> {
    render(RepositoryId::from_bytes([2; 16]), GitHashAlgorithm::Sha256, token(), selection, queries, report)
}

#[test]
fn duplicate_needles_preserve_slots_and_absence_is_not_made_partial() {
    let (selection, queries, report) = setup();
    let output = rendered(&selection, &queries, &report).unwrap();
    let Value::Array(slots) = &output["results"] else { unreachable!() };
    assert_eq!(slots.len(), 3);
    for (i, slot) in slots.iter().enumerate() {
        let slot = slot.object().unwrap();
        assert_eq!(slot["query_index"].text(), Some(i.to_string().as_str()));
        assert_eq!(slot["complete"], Value::Bool(i == 1));
        assert_eq!(slot["match_count"].text(), Some(if i == 1 { "0" } else { "1" }));
    }
    assert_eq!(output["complete"], Value::Bool(false));
    assert_eq!(output["truncated_reason"].text(), Some("match_limit"));
    assert_eq!(output["match_count"].text(), Some("2"));
    assert_eq!(output["files_read"].text(), Some("1"));
    assert_eq!(output["bytes_read"].text(), Some("2"));
    assert_eq!(output["profile"].text(), Some("literal-bytes-batch-v1"));
}

#[test]
fn batch_requires_nonempty_bounded_ordered_literal_array_and_aggregate_ceiling() {
    for (key, value) in [
        ("needles_hex", Value::Array(vec![])),
        ("needles_hex", Value::Array(vec![text("61"); 33])),
        ("needles_hex", Value::Array(vec![Value::Null])),
        ("needles_hex", Value::Array(vec![text("0a")])),
        ("needles_hex", Value::Array(vec![text("")])),
        ("needles_hex", Value::Array(vec![text("FF")])),
        ("needles_hex", Value::Array(vec![text("61".repeat(257))])),
        ("needles_hex", text("61")),
        ("needle_hex", text("61")),
        ("principal", text("admin")),
        ("max_matches", json::number(67)),
    ] {
        let mut request = input();
        request.insert(key.into(), value);
        assert!(parse(&request, GitHashAlgorithm::Sha256).is_err(), "accepted {key}");
    }
    let mut request = input();
    request.remove("max_matches");
    request.insert("needles_hex".into(), Value::Array(vec![text("61"); 32]));
    let (selected, queries) = parse(&request, GitHashAlgorithm::Sha256).unwrap();
    assert_eq!(selected.limits.max_matches, 5);
    assert_eq!(queries.queries().len(), 32);
    request.insert("max_matches".into(), json::number(7));
    assert_eq!(parse(&request, GitHashAlgorithm::Sha256).err().unwrap().code, "batch_match_limit");
}

#[test]
fn batch_rejects_reordered_missing_or_mislabelled_query_results() {
    for change in 0..5 {
        let (selection, queries, mut report) = setup();
        match change {
            0 => { report.results.swap(0, 1); }
            1 => { report.results.pop(); }
            2 => { report.results[0].matches.clear(); }
            3 => { report.files_selected = 2; }
            _ => { report.results[1].needle = b"other".to_vec(); }
        }
        assert!(rendered(&selection, &queries, &report).is_err());
    }
}

#[test]
fn empty_selected_tree_is_a_complete_batch_with_all_query_slots() {
    let (selection, queries, observed) = setup();
    let report = queries.empty_report(observed.repository, observed.source_rcr, observed.source_commit, observed.source_tree);
    let output = rendered(&selection, &queries, &report).unwrap();
    assert_eq!(output["complete"], Value::Bool(true));
    assert_eq!(output["match_count"].text(), Some("0"));
    assert_eq!(output["query_count"].text(), Some("3"));
    assert_eq!(output["truncated_reason"], Value::Null);
}

#[test]
fn batch_checks_exact_repository_and_snapshot_binding() {
    let (mut selection, queries, mut report) = setup();
    selection.expected_commit = Some(oid(9));
    assert!(rendered(&selection, &queries, &report).is_err());
    selection.expected_commit = None;
    report.repository = RepositoryId::from_bytes([99; 16]);
    assert_eq!(rendered(&selection, &queries, &report).unwrap_err().code, "repository_binding_mismatch");
}

#[test]
fn batch_has_one_aggregate_retained_payload_budget_not_one_per_query() {
    let mut request = input();
    request.insert("needles_hex".into(), Value::Array(vec![text("61"); 32]));
    request.insert("max_matches".into(), json::number(5));
    let (selection, queries) = parse(&request, GitHashAlgorithm::Sha256).unwrap();
    let (_, _, template) = setup();
    let mut report = queries.empty_report(template.repository, template.source_rcr, template.source_commit, template.source_tree);
    report.files_selected = 1;
    report.files_read = 1;
    report.bytes_read = 5;
    report.bytes_searched = 5;
    for result in &mut report.results {
        for offset in 0..5 {
            result.matches.push(SourceMatch {
                path: (0..32).map(|_| "x".repeat(63)).collect::<Vec<_>>().join("/").into_bytes(),
                blob: oid(3), byte_offset: offset,
                line: 1, byte_column: offset + 1,
                excerpt: b"aaaaa".to_vec(), excerpt_offset: 0, match_length: 1,
            });
        }
    }
    assert_eq!(rendered(&selection, &queries, &report).unwrap_err().code, "resource_limit");
}

#[test]
fn batch_schema_preserves_common_limits_and_excludes_single_needle() {
    let descriptor = tool();
    assert_eq!(descriptor.name, BATCH_NAME);
    let schema = descriptor.schema.object().unwrap();
    let properties = schema["properties"].object().unwrap();
    assert!(!properties.contains_key("needle_hex"));
    assert!(properties.contains_key("needles_hex"));
    assert!(properties.contains_key("expected_head"));
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    assert_eq!(properties["max_matches"].object().unwrap()["default"], json::number(5));
}
