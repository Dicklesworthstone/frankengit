use super::*;
use fgit_forge::preparation::{ConflictKind, MergeConflict, MergeEntry};

fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(pairs) else { unreachable!() };
    fields
}
fn side(path: &[u8], choice: &str) -> Value {
    object([("path_hex", text(hex(path))), ("choice", text(choice))])
}
fn file(path: &[u8], bytes: &[u8]) -> Value {
    object([
        ("path_hex", text(hex(path))), ("choice", text("file")), ("mode", text("100755")),
        ("bytes_hex_chunks", Value::Array(bytes.chunks(CHUNK_BYTES).map(|part| text(hex(part))).collect())),
    ])
}
fn args(format: GitHashAlgorithm, rows: Vec<Value>) -> Object {
    fields([
        ("operation", text(RESOLVE)), ("number", text("1")), ("expected_version", text("1")),
        ("source_reference", text("refs/heads/topic")), ("target_reference", text("refs/heads/main")),
        ("expected_source", text("11".repeat(format.digest_len()))),
        ("expected_target", text("22".repeat(format.digest_len()))),
        ("merge_base", text("33".repeat(format.digest_len()))), ("policy_epoch", text("1")),
        ("resolutions", Value::Array(rows)), ("author", text("A <a@example.invalid>")),
        ("committer", text("C <c@example.invalid>")), ("timestamp", text("2")),
        ("message_hex", text(hex(b"resolve\n"))),
    ])
}

#[test]
fn explicit_side_binary_and_empty_file_choices_remain_distinct_and_canonical() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let args = args(format, vec![file(b"z", b"\xff\0\r\n"), side(b"b", "delete"), file(b"a", b"")]);
        let parsed = input::parse(&args, format).unwrap();
        assert_eq!(parsed.resolutions.iter().map(|row| row.path.as_slice()).collect::<Vec<_>>(), [b"a", b"b", b"z"]);
        assert_eq!(parsed.resolutions[0].choice, ResolutionChoice::File { mode: 0o100755, bytes: vec![] });
        assert_eq!(parsed.resolutions[1].choice, ResolutionChoice::Delete);
        assert_eq!(parsed.resolutions[2].choice, ResolutionChoice::File { mode: 0o100755, bytes: b"\xff\0\r\n".to_vec() });
        for (name, choice) in [("base", ResolutionChoice::Base), ("ours", ResolutionChoice::Ours), ("theirs", ResolutionChoice::Theirs)] {
            let parsed = input::parse(&self::args(format, vec![side(b"raw-\xff", name)]), format).unwrap();
            assert_eq!(parsed.resolutions[0].choice, choice);
        }
    }
}

#[test]
fn closed_shapes_reject_authority_overrides_missing_fields_and_unsafe_or_partial_sets() {
    let format = GitHashAlgorithm::Sha256;
    let original = args(format, vec![side(b"README", "ours")]);
    for field in ["operation", "number", "expected_version", "expected_source", "expected_target", "source_reference",
        "target_reference", "policy_epoch", "merge_base", "author", "committer", "timestamp", "message_hex", "resolutions"]
    {
        let mut bad = original.clone(); bad.remove(field);
        assert!(input::parse(&bad, format).is_err(), "missing {field}");
    }
    for field in ["principal", "force", "decision", "idempotency_key", "candidate_commit", "bundle_hex_chunks",
        "review_version", "required_reviewers", "paths_hex", "comparison", "merge_profile", "bundle_path", "expected_base"]
    {
        let mut bad = original.clone(); bad.insert(field.into(), Value::Null);
        assert_eq!(input::parse(&bad, format).err().unwrap().code, "unknown_argument", "{field}");
    }
    for rows in [vec![], vec![side(b"same", "ours"), side(b"same", "theirs")],
        vec![side(b"a", "ours"), side(b"a-", "ours"), side(b"a/b", "ours")],
        vec![side(b"../outside", "ours")], vec![side(b"x/.GiT/config", "ours")],
        vec![side(b"", "ours")], vec![side(b"README", "automatic")], vec![Value::Null],
    ] {
        assert!(input::parse(&args(format, rows), format).is_err());
    }
    let mut extra = fields([("path_hex", text(hex(b"README"))), ("choice", text("ours")), ("mode", text("100644"))]);
    assert!(input::parse(&args(format, vec![Value::Object(extra.clone())]), format).is_err());
    extra.insert("choice".into(), text("file"));
    assert!(input::parse(&args(format, vec![Value::Object(extra.clone())]), format).is_err(), "empty file must be explicit");
    extra.insert("bytes_hex_chunks".into(), Value::Array(vec![]));
    extra.insert("mode".into(), text("120000"));
    assert!(input::parse(&args(format, vec![Value::Object(extra)]), format).is_err());
}

#[test]
fn aggregate_raw_bytes_chunks_and_both_phase_limits_are_independently_bounded() {
    let format = GitHashAlgorithm::Sha1;
    let half = vec![0xaa; MAX_BUNDLE_BYTES / 2];
    let too_large = args(format, vec![file(b"a", &half), file(b"b", &half)]);
    assert_eq!(input::parse(&too_large, format).err().unwrap().code, "resolution_byte_limit");
    let exact = vec![0xbb; MAX_BUNDLE_BYTES - 1];
    assert!(input::parse(&args(format, vec![file(b"x", &exact)]), format).is_ok());
    for chunks in [vec![text("AA")], vec![text("0")], vec![text("")], vec![json::number(1)],
        vec![text("00"); MAX_CHUNKS + 1], vec![text("00".repeat(CHUNK_BYTES + 1))]]
    {
        let row = object([("path_hex", text("61")), ("choice", text("file")),
            ("mode", text("100644")), ("bytes_hex_chunks", Value::Array(chunks))]);
        assert!(input::parse(&args(format, vec![row]), format).is_err());
    }
    for field in ["max_commits", "max_tree_entries", "max_preparation_bytes", "max_review_bytes", "max_changes", "max_diff_work"] {
        for value in [Value::Null, text("1"), json::number(0), json::number(u64::MAX)] {
            let mut bad = args(format, vec![side(b"README", "ours")]); bad.insert(field.into(), value);
            assert!(input::parse(&bad, format).is_err(), "{field}");
        }
    }
    let mut query = args(format, vec![side(b"README", "ours")]);
    query.insert("max_preparation_bytes".into(), json::number(128));
    query.insert("max_review_bytes".into(), json::number(64));
    query.insert("context_lines".into(), json::number(0));
    let input = input::parse(&query, format).unwrap();
    assert_eq!(input.limits.max_output_bytes, 128);
    let mut inspection = Object::new(); input.inspection_limits(&mut inspection);
    assert_eq!(inspection["max_output_bytes"].unsigned(), Some(64));
    assert_eq!(inspection["context_lines"].unsigned(), Some(0));
    let wire = object([("jsonrpc", text("2.0")), ("id", json::number(1)), ("method", text("tools/call")),
        ("params", object([("name", text(NAME)), ("arguments", Value::Object(args(format, vec![file(b"x", &exact)])))])),
    ]).encode(json::MAX_INPUT).unwrap();
    assert!(json::parse(wire.as_bytes()).is_ok());
}

#[test]
fn discovery_advertises_exact_conflicts_and_explicit_empty_regular_files() {
    let schema = schema();
    let body = schema.object().unwrap();
    assert_eq!(body["additionalProperties"], Value::Bool(false));
    let properties = body["properties"].object().unwrap();
    assert_eq!(properties["operation"].object().unwrap()["const"].text(), Some(RESOLVE));
    let Value::Array(required) = &body["required"] else { unreachable!() };
    for name in ["merge_base", "resolutions", "author", "committer", "timestamp", "message_hex"] {
        assert!(required.contains(&text(name)));
    }
    for name in ["idempotency_key", "decision", "principal", "force", "merge_profile"] {
        assert!(!properties.contains_key(name));
    }
    let resolutions = properties["resolutions"].object().unwrap();
    assert_eq!(resolutions["maxItems"].unsigned(), Some(64));
    let Value::Array(choices) = &resolutions["items"].object().unwrap()["oneOf"] else { unreachable!() };
    let file = choices[1].object().unwrap()["properties"].object().unwrap();
    assert_eq!(file["bytes_hex_chunks"].object().unwrap()["minItems"].unsigned(), Some(0));
    assert!(schema.encode(16 * 1024).is_ok());
}

#[test]
fn receipts_require_the_exact_set_and_matching_side_or_verified_file_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let entry = |bytes: &[u8]| MergeEntry { name: b"file".to_vec(), mode: 0o100644,
            oid: git_object_id(format, GitObjectKind::Blob, bytes) };
        let conflict = MergeConflict { path: b"src/file".to_vec(), kind: ConflictKind::Content,
            base: Some(entry(b"base")), ours: Some(entry(b"ours")), theirs: Some(entry(b"theirs")) };
        let mut requested = ConflictResolution { path: conflict.path.clone(), choice: ResolutionChoice::Ours };
        let mut observed = ResolvedPath { conflict: conflict.clone(), choice: ResolutionKind::Ours, result: conflict.ours.clone() };
        assert!(receipts(format, &[requested.clone()], &[observed.clone()]).is_ok());
        assert!(receipts(format, &[requested.clone()], &[]).is_err());
        assert!(receipts(format, &[requested.clone()], &[observed.clone(), observed.clone()]).is_err());
        observed.result = conflict.theirs.clone();
        assert!(receipts(format, &[requested.clone()], &[observed.clone()]).is_err());
        observed.result = None;
        assert!(receipts(format, &[requested.clone()], &[observed.clone()]).is_err());
        observed.choice = ResolutionKind::Delete; requested.choice = ResolutionChoice::Delete;
        assert!(receipts(format, &[requested.clone()], &[observed.clone()]).is_ok());
        observed.choice = ResolutionKind::File;
        requested.choice = ResolutionChoice::File { mode: 0o100644, bytes: b"\0\xff".to_vec() };
        observed.result = Some(entry(b"\0\xff"));
        assert!(receipts(format, &[requested.clone()], &[observed.clone()]).is_ok());
        observed.result.as_mut().unwrap().name = b"another".to_vec();
        assert!(receipts(format, &[requested.clone()], &[observed.clone()]).is_err());
        observed.result = Some(entry(b"different"));
        assert!(receipts(format, &[requested.clone()], &[observed.clone()]).is_err());
        observed.conflict.path = b"undeclared".to_vec();
        assert!(receipts(format, &[requested], &[observed]).is_err());
    }
}
