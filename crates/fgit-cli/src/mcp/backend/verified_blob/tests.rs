//! Input closure, native byte grammar and fail-closed result classification.
use super::*;

fn args() -> Object {
    let algorithm =
        fgit_crypto::internal_algorithm_id(fgit_crypto::IdentityDomain::RepositoryAuthorityHead);
    object([
        ("reference", text("refs/heads/main")),
        ("path_hex", text(hex(b"src/main.rs"))),
        (
            "expected_head",
            text(format!(
                "alg:{}:{}",
                algorithm.code_point(),
                "11".repeat(32)
            )),
        ),
    ])
    .object()
    .unwrap()
    .clone()
}

#[test]
fn selector_bytes_are_exact_and_head_never_defaults_to_server_state() {
    let original = args();
    let query = input::parse(&original).unwrap();
    assert_eq!(query.reference.as_bytes(), b"refs/heads/main");
    assert_eq!(query.path.as_slice(), b"src/main.rs");
    assert_eq!(query.max_blob_bytes, DEFAULT_BLOB_BYTES);
    assert_eq!(
        head_token(query.expected_head),
        original["expected_head"].text().unwrap()
    );
    let mut raw = original.clone();
    raw.remove("reference");
    raw.insert("reference_hex".into(), text(hex(b"refs/heads/raw-\xff")));
    raw.insert("path_hex".into(), text(hex(b"dir/file-\xff")));
    let query = input::parse(&raw).unwrap();
    assert_eq!(query.reference.as_bytes(), b"refs/heads/raw-\xff");
    assert_eq!(query.path.as_slice(), b"dir/file-\xff");
    raw.remove("expected_head");
    assert_eq!(input::parse(&raw).unwrap_err().code, "snapshot_required");
}

#[test]
fn exact_one_full_reference_and_native_path_grammar_are_enforced() {
    for mutation in [
        ("reference", text("HEAD")),
        ("reference", text("heads/main")),
        ("reference", text("refs/heads/bad..name")),
        ("reference", text("refs/heads/bad name")),
        ("reference", text("refs/heads/main.lock")),
        (
            "reference",
            text(format!("refs/heads/{}", "a".repeat(MAX_REF_BYTES))),
        ),
        ("reference", text(format!("refs/heads/{}", "é".repeat(512)))),
        ("reference_hex", text(hex(b"refs/heads/extra"))),
        ("reference", Value::Null),
    ] {
        let mut request = args();
        request.insert(mutation.0.into(), mutation.1);
        assert!(input::parse(&request).is_err());
    }
    let mut missing = args();
    missing.remove("reference");
    assert_eq!(
        input::parse(&missing).unwrap_err().code,
        "exactly_one_reference_encoding_required"
    );
    for path in [
        Vec::new(),
        b"/absolute".to_vec(),
        b"trailing/".to_vec(),
        b"a//b".to_vec(),
        b".".to_vec(),
        b"a/../b".to_vec(),
        b"a\0b".to_vec(),
        vec![b'x'; 256],
        vec![b'x'; MAX_PATH_BYTES + 1],
        vec!["a"; 65].join("/").into_bytes(),
    ] {
        let mut request = args();
        request.insert("path_hex".into(), text(hex(&path)));
        assert!(input::parse(&request).is_err(), "{path:?}");
    }
    for invalid_hex in ["0", "ffFF", "gg", "0x00"] {
        let mut request = args();
        request.insert("path_hex".into(), text(invalid_hex));
        assert_eq!(
            input::parse(&request).unwrap_err().code,
            "invalid_hex_bytes"
        );
    }
    for path in [
        vec!["x".repeat(240); 17].join("/").into_bytes(),
        vec!["a"; 64].join("/").into_bytes(),
        vec![0xff; 255],
    ] {
        let mut request = args();
        request.insert("path_hex".into(), text(hex(&path)));
        assert_eq!(input::parse(&request).unwrap().path, path);
    }
}

#[test]
fn limits_unknown_fields_and_ranges_cannot_widen_complete_read() {
    for value in [
        json::number(0),
        json::number((MAX_BLOB_BYTES + 1) as u64),
        text("16384"),
        Value::Number("1.5".into()),
        Value::Number("-1".into()),
        Value::Bool(true),
        Value::Null,
    ] {
        let mut request = args();
        request.insert("max_blob_bytes".into(), value);
        assert_eq!(
            input::parse(&request).unwrap_err().code,
            "invalid_blob_limit"
        );
    }
    for maximum in [1, MAX_BLOB_BYTES] {
        let mut request = args();
        request.insert("max_blob_bytes".into(), json::number(maximum as u64));
        assert_eq!(input::parse(&request).unwrap().max_blob_bytes, maximum);
    }
    for name in [
        "offset",
        "limit",
        "force",
        "object_id",
        "principal",
        "storage",
        "idempotency_key",
        "visibility",
    ] {
        let mut request = args();
        request.insert(name.into(), text("untrusted"));
        assert_eq!(input::parse(&request).unwrap_err().code, "unknown_argument");
    }
    for value in ["", "not-a-head", "alg:01:1111"] {
        let mut request = args();
        request.insert("expected_head".into(), text(value));
        assert!(input::parse(&request).is_err());
    }
}

#[test]
fn hidden_or_absent_source_and_native_failure_never_become_empty_success() {
    use fgit_node::VerifiedBlobReadRefusal as Refusal;
    for refusal in [Refusal::RefUnavailable, Refusal::PathUnavailable] {
        let error = read_refusal(refusal);
        assert_eq!(error.code, "source_unavailable");
        assert!(!error.invalid);
    }
    assert_eq!(
        read_refusal(Refusal::SnapshotMoved).code,
        "source_snapshot_moved"
    );
    assert_eq!(
        read_refusal(Refusal::UnsupportedLayout).code,
        "verified_blob_layout_unavailable"
    );
    assert_eq!(
        proof_refusal(VerifiedBlobRefusal::Cancelled).code,
        "verified_blob_cancelled"
    );
    assert_eq!(
        proof_refusal(VerifiedBlobRefusal::ObjectHashMismatch).code,
        "verified_blob_proof_refused"
    );
    assert_eq!(
        proof_refusal(VerifiedBlobRefusal::BoundExceeded("test")).code,
        "verified_blob_native_limit"
    );
}
