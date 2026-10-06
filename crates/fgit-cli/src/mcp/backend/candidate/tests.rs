use super::*;

fn args<const N: usize>(values: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(values) else { unreachable!() };
    fields
}
fn valid(format: GitHashAlgorithm) -> Object {
    args([
        ("operation", text("prepare_patch")),
        ("reference", text("refs/heads/topic")),
        ("expected_base", text("ab".repeat(format.digest_len()))),
        ("patch", text("an exact patch is parsed by the native engine")),
        ("author", text("Author <author@example.invalid>")),
        ("committer", text("Committer <committer@example.invalid>")),
        ("timestamp", text("1")),
        ("message_hex", text(hex(b"change\n"))),
    ])
}
#[test]
fn both_hash_domains_and_raw_branch_patch_and_message_bytes_are_preserved() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut input = valid(format);
        input.remove("reference");
        input.insert("reference_hex".into(), text(hex(b"refs/heads/\xff")));
        input.remove("patch");
        input.insert("patch_hex_chunks".into(), Value::Array(vec![text("00ff"), text("0d0a")]));
        input.insert("message_hex".into(), text("ff0a"));
        let parsed = prepare::parse(&input, format).unwrap();
        assert_eq!(parsed.reference.as_bytes(), b"refs/heads/\xff");
        assert_eq!(parsed.patch, [0, 255, 13, 10]);
        assert_eq!(parsed.metadata.message, [255, 10]);
        assert_eq!(raw_oid(parsed.base), "ab".repeat(format.digest_len()));
    }
}
#[test]
fn commit_authorship_cannot_become_authentication_or_a_host_effect() {
    for name in ["principal", "storage", "tenant_id", "repository_id", "workspace_id",
        "idempotency_key", "force", "expected_head", "shell", "capability"]
    {
        let mut input = valid(GitHashAlgorithm::Sha1);
        input.insert(name.into(), text("untrusted"));
        assert_eq!(prepare::parse(&input, GitHashAlgorithm::Sha1).err().unwrap().code, "unknown_argument");
    }
}
#[test]
fn every_required_field_and_exactly_one_encoding_are_enforced() {
    for name in ["operation", "reference", "expected_base", "patch", "author", "committer", "timestamp", "message_hex"] {
        let mut input = valid(GitHashAlgorithm::Sha1);
        input.remove(name);
        assert!(prepare::parse(&input, GitHashAlgorithm::Sha1).is_err(), "{name}");
    }
    for (name, value) in [
        ("reference_hex", text(hex(b"refs/heads/topic"))),
        ("patch_hex_chunks", Value::Array(vec![text("61")])),
        ("operation", text("publish")),
        ("reference", text("/etc/passwd")),
        ("reference", text("refs/tags/release")),
        ("expected_base", text("00".repeat(20))),
        ("expected_base", text("ab".repeat(32))),
        ("expected_base", text("AB".repeat(20))),
    ] {
        let mut input = valid(GitHashAlgorithm::Sha1);
        input.insert(name.into(), value);
        assert!(prepare::parse(&input, GitHashAlgorithm::Sha1).is_err(), "{name}");
    }
}
#[test]
fn metadata_is_explicit_bounded_and_cannot_inject_commit_headers() {
    for (name, value) in [
        ("timestamp", json::number(1)), ("timestamp", text("01")),
        ("timestamp", text("0")), ("timestamp", text("18446744073709551616")),
        ("timestamp", text(u64::MAX.to_string())),
        ("author", text("A <a@example.invalid>\nparent forged")),
        ("committer", text("ambient git config")), ("message_hex", text("")),
        ("message_hex", text("00")), ("message_hex", text("61".repeat(4097))),
        ("patch", text("a".repeat(16 * 1024 + 1))), ("patch", Value::Null),
    ] {
        let mut input = valid(GitHashAlgorithm::Sha1);
        input.insert(name.into(), value);
        assert!(prepare::parse(&input, GitHashAlgorithm::Sha1).is_err(), "{name}");
    }
    let mut input = valid(GitHashAlgorithm::Sha1);
    input.insert("timestamp".into(), text(i64::MAX.to_string()));
    assert!(prepare::parse(&input, GitHashAlgorithm::Sha1).is_ok());
}
#[test]
fn chunk_bounds_round_trip_all_bytes_without_truncation() {
    for length in [1, CHUNK_BYTES, CHUNK_BYTES + 1, MAX_BUNDLE_BYTES] {
        let bytes: Vec<_> = (0..length).map(|n| (n % 256) as u8).collect();
        let encoded = encoded_chunks(&bytes).unwrap();
        assert_eq!(chunks(&args([("bytes", encoded)]), "bytes").unwrap(), bytes);
    }
    assert!(encoded_chunks(&[]).is_err());
    assert!(encoded_chunks(&vec![1; MAX_BUNDLE_BYTES + 1]).is_err());
    for parts in [vec![], vec![text("")], vec![text("0")], vec![text("FF")],
        vec![text("gg")], vec![json::number(1)], vec![text("61"); 4],
        vec![text("61".repeat(CHUNK_BYTES + 1))]]
    {
        assert!(chunks(&args([("bytes", Value::Array(parts))]), "bytes").is_err());
    }
}
#[test]
fn publication_arguments_fit_the_input_envelope_and_never_choose_a_retry_key() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = GitOid::from_hex(format, &"ab".repeat(format.digest_len())).unwrap();
        let candidate = GitOid::from_hex(format, &"cd".repeat(format.digest_len())).unwrap();
        let reference = RefName::try_new(b"refs/heads/topic").unwrap();
        let bytes = vec![255; MAX_BUNDLE_BYTES];
        let value = publication_arguments(&reference, base, candidate, &bytes).unwrap();
        let fields = value.object().unwrap();
        assert!(!fields.contains_key("idempotency_key"));
        assert_eq!(branch(fields, "reference", "reference_hex").unwrap(), reference);
        assert_eq!(oid(fields, "expected_base", format).unwrap(), base);
        assert_eq!(oid(fields, "expected_candidate", format).unwrap(), candidate);
        assert_eq!(chunks(fields, "bundle_hex_chunks").unwrap(), bytes);
        let mut fields = fields.clone();
        fields.insert("idempotency_key".into(), text("explicit-original-key"));
        let wire = object([
            ("jsonrpc", text("2.0")), ("id", json::number(1)), ("method", text("tools/call")),
            ("params", object([("name", text("frankengit_source_publish")), ("arguments", Value::Object(fields))])),
        ]).encode(json::MAX_INPUT).unwrap();
        assert!(json::parse(wire.as_bytes()).is_ok());
    }
}
