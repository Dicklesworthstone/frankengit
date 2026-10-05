use super::*;
use fgit_types::RepositoryCommitId;

fn args<const N: usize>(fields: [(&str, Value); N]) -> Object {
    let Value::Object(value) = object(fields) else { unreachable!() };
    value
}
fn input() -> Object {
    args([
        ("reference", text("refs/heads/main")),
        ("needle_hex", text("00ff")),
    ])
}
fn token() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    )
}
fn oid(byte: u8) -> GitOid {
    GitOid::from_hex(GitHashAlgorithm::Sha256, &format!("{byte:02x}").repeat(32)).unwrap()
}
fn report() -> SourceSearchReport {
    SourceSearchReport {
        repository: RepositoryId::from_bytes([2; 16]),
        source_rcr: RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).unwrap(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[8; 32]).unwrap(),
        ),
        source_commit: oid(1),
        source_tree: oid(2),
        matches: vec![SourceMatch {
            path: vec![255],
            blob: oid(3),
            byte_offset: 0,
            line: 1,
            byte_column: 1,
            excerpt: vec![0, 255, 10],
            excerpt_offset: 0,
            match_length: 2,
        }],
        completion: SearchCompletion::Complete,
        files_selected: 1,
        files_read: 1,
        bytes_read: 3,
        bytes_searched: 3,
        non_regular_entries: 2,
    }
}
fn rendered(input: &Object, report: &SourceSearchReport) -> Result<Object, ToolError> {
    let (selection, query) = parse(input, GitHashAlgorithm::Sha256)?;
    render(RepositoryId::from_bytes([2; 16]), GitHashAlgorithm::Sha256, token(), &selection, &query, report)
}

#[test]
fn search_rejects_ambient_authority_coercions_and_unsupported_queries() {
    for (name, value) in [
        ("principal", text("admin")), ("storage", text("/etc")),
        ("repository_id", text("other")), ("regex", text(".*")),
        ("offset", text("1")), ("reference", text("/etc/passwd")),
        ("reference", text("HEAD")), ("needle_hex", text("")),
        ("needle_hex", text("FF")), ("needle_hex", text("0")),
        ("needle_hex", text("0a")), ("needle_hex", text("61".repeat(257))),
        ("max_matches", json::number(0)), ("max_matches", json::number(101)),
        ("max_files", json::number(20_001)), ("max_files", text("1")),
        ("max_total_bytes", json::number(67_108_865)),
        ("max_file_bytes", json::number(8_388_609)),
        ("ignore_ascii_case", text("false")), ("ignore_ascii_case", Value::Null),
        ("path_prefixes_hex", text("737263")),
        ("path_prefixes_hex", Value::Array(vec![text(hex(b"../secret"))])),
        ("path_prefixes_hex", Value::Array(vec![text(hex(b"/etc"))])),
        ("path_prefixes_hex", Value::Array(vec![text("")])),
        ("path_prefixes_hex", Value::Array(vec![text("61"); 33])),
        ("expected_commit", text("00".repeat(32))),
        ("expected_commit", text("01".repeat(20))),
        ("expected_head", text("alg:01:aa")),
    ] {
        let mut request = input();
        request.insert(name.into(), value);
        assert!(parse(&request, GitHashAlgorithm::Sha256).is_err(), "accepted {name}");
    }
    let mut missing = input();
    missing.remove("needle_hex");
    assert!(parse(&missing, GitHashAlgorithm::Sha256).is_err());
}

#[test]
fn validated_query_preserves_bytes_and_normalizes_only_path_scope() {
    let mut request = input();
    request.insert("ignore_ascii_case".into(), Value::Bool(true));
    request.insert("path_prefixes_hex".into(), Value::Array(vec![text("ff"), text("ff")]));
    request.insert("expected_commit".into(), text(oid(1).to_string()));
    request.insert("expected_head".into(), text(head_token(token())));
    let (selected, query) = parse(&request, GitHashAlgorithm::Sha256).unwrap();
    assert_eq!(query.needle(), &[0, 255]);
    assert_eq!(query.case(), SearchCase::AsciiInsensitive);
    assert_eq!(query.prefixes().len(), 1);
    assert_eq!(query.prefixes()[0].as_bytes(), &[255]);
    assert_eq!(selected.expected_head, Some(token()));
    assert_eq!(selected.expected_commit, Some(oid(1)));
}

#[test]
fn binary_matches_keep_exact_bytes_and_one_based_positions() {
    let value = rendered(&input(), &report()).unwrap();
    let Value::Array(matches) = &value["matches"] else { unreachable!() };
    let found = matches[0].object().unwrap();
    assert_eq!(found["path_hex"].text(), Some("ff"));
    assert_eq!(found["excerpt_hex"].text(), Some("00ff0a"));
    assert_eq!(found["excerpt_utf8"], Value::Null);
    assert_eq!(found["byte_offset"].text(), Some("0"));
    assert_eq!(found["line"].text(), Some("1"));
    assert_eq!(found["byte_column"].text(), Some("1"));
    assert_eq!(value["complete"], Value::Bool(true));
    assert_eq!(value["truncated_reason"], Value::Null);
    assert_eq!(value["non_regular_entries"].text(), Some("2"));
}

#[test]
fn match_limit_is_partial_and_cannot_be_disguised_as_empty_success() {
    let mut request = input();
    request.insert("max_matches".into(), json::number(1));
    let mut observed = report();
    observed.completion = SearchCompletion::MatchLimit;
    let value = rendered(&request, &observed).unwrap();
    assert_eq!(value["complete"], Value::Bool(false));
    assert_eq!(value["truncated_reason"].text(), Some("match_limit"));
    observed.matches.clear();
    assert!(rendered(&request, &observed).is_err());
    observed.completion = SearchCompletion::Complete;
    let value = rendered(&request, &observed).unwrap();
    assert_eq!(value["complete"], Value::Bool(true));
    assert_eq!(value["match_count"].text(), Some("0"));
}

#[test]
fn report_binding_and_work_counters_fail_closed() {
    let mut observed = report();
    observed.repository = RepositoryId::from_bytes([99; 16]);
    assert_eq!(rendered(&input(), &observed).unwrap_err().code, "repository_binding_mismatch");
    let mut pinned = input();
    pinned.insert("expected_commit".into(), text(oid(4).to_string()));
    assert!(rendered(&pinned, &report()).is_err());
    for (selected, read, bytes, searched) in [(0, 1, 3, 3), (2, 1, 3, 3), (1, 1, 3, 4), (20_001, 20_001, 3, 3)] {
        let mut observed = report();
        observed.files_selected = selected;
        observed.files_read = read;
        observed.bytes_read = bytes;
        observed.bytes_searched = searched;
        assert!(rendered(&input(), &observed).is_err());
    }
    let mut observed = report();
    observed.source_tree = GitOid::from_hex(GitHashAlgorithm::Sha1, &"01".repeat(20)).unwrap();
    assert!(rendered(&input(), &observed).is_err());
}

#[test]
fn invalid_match_coordinates_payload_order_and_scope_are_rejected() {
    for change in 0..8 {
        let mut observed = report();
        let found = &mut observed.matches[0];
        match change {
            0 => found.path = b"../secret".to_vec(),
            1 => found.line = 0,
            2 => found.byte_column = 0,
            3 => found.excerpt_offset = 1,
            4 => found.match_length = 1,
            5 => found.excerpt[0] = 1,
            6 => found.byte_offset = usize::MAX,
            _ => found.blob = GitOid::from_hex(GitHashAlgorithm::Sha1, &"01".repeat(20)).unwrap(),
        }
        assert!(rendered(&input(), &observed).is_err());
    }
    let mut observed = report();
    observed.matches.push(observed.matches[0].clone());
    assert!(rendered(&input(), &observed).is_err());
    let mut request = input();
    request.insert("path_prefixes_hex".into(), Value::Array(vec![text(hex(b"src"))]));
    let mut observed = report();
    observed.matches[0].path = b"src2/file".to_vec();
    assert!(rendered(&request, &observed).is_err());
    observed.matches[0].path = b"src/file".to_vec();
    assert!(rendered(&request, &observed).is_ok());
}

#[test]
fn retained_payload_and_encoded_response_have_independent_hard_limits() {
    let query = SourceQuery::new(&[0, 255], SearchCase::Exact, &[]).unwrap();
    let mut retained = MAX_RETAINED_BYTES;
    let observed = report();
    assert_eq!(render_matches(&query, SearchLimits::default(), GitHashAlgorithm::Sha256, &observed.matches, SearchCompletion::Complete, &mut retained).unwrap_err().code, "resource_limit");
    let huge = args([("payload", text("a".repeat(MAX_RESULT_BYTES)))]);
    assert_eq!(bounded_result(huge).unwrap_err().code, "resource_limit");
}

#[test]
fn failures_are_sanitized_not_empty_searches() {
    for (refusal, code) in [
        (NodeWorkspaceRefusal::RefUnavailable, "reference_unavailable"),
        (NodeWorkspaceRefusal::SourceBrowse(Box::new(SourceBrowseError::SnapshotMoved)), "snapshot_moved"),
        (NodeWorkspaceRefusal::SourceBrowse(Box::new(SourceBrowseError::CommitMoved)), "source_commit_moved"),
        (NodeWorkspaceRefusal::SourceSearch(Box::new(SearchError::Budget("private/path"))), "resource_limit"),
        (NodeWorkspaceRefusal::SourceSearch(Box::new(SearchError::Cancelled)), "read_cancelled"),
    ] {
        let error = read_error(refusal);
        assert_eq!(error.code, code);
        assert!(!error.invalid);
    }
}

#[test]
fn tool_schema_disallows_unknown_authority_fields() {
    let descriptors = tools();
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].name, NAME);
    let schema = descriptors[0].schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let properties = schema["properties"].object().unwrap();
    assert!(!properties.contains_key("principal"));
    assert!(!properties.contains_key("storage"));
    assert!(properties.contains_key("expected_head"));
}
