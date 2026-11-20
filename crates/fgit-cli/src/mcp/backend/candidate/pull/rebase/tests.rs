//! Parser and response bounds do not grant source reads or publication.
use super::*;

fn args(format: GitHashAlgorithm) -> Object {
    let Value::Object(fields) = object([
        ("operation", text(REBASE_PREPARE)),
        ("profile", text("path-v1")),
        ("number", text("1")),
        ("expected_version", text("1")),
        ("source_reference", text("refs/heads/topic")),
        ("target_reference", text("refs/heads/main")),
        ("expected_source", text("11".repeat(format.digest_len()))),
        ("expected_target", text("22".repeat(format.digest_len()))),
        ("upstream", text("33".repeat(format.digest_len()))),
        ("policy_epoch", text("1")),
        ("empty", text("stop")),
        ("committer", text("Committer <committer@example.invalid>")),
        ("timestamp", text("2")),
    ]) else {
        unreachable!()
    };
    fields
}

#[test]
fn exact_pr_rebase_parser_requires_explicit_policy_and_never_accepts_publication_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let valid = args(format);
        let parsed = parse(&valid, format).unwrap();
        assert_eq!(parsed.limits.max_commits, MAX_COMMITS);
        for field in valid.keys() {
            let mut bad = valid.clone();
            bad.remove(field);
            assert!(parse(&bad, format).is_err(), "{field}");
        }
        for field in [
            "principal",
            "idempotency_key",
            "bundle_path",
            "force",
            "author",
            "message_hex",
            "resolutions",
        ] {
            let mut bad = valid.clone();
            bad.insert(field.into(), text("injected"));
            assert!(parse(&bad, format).is_err(), "{field}");
        }
        for (field, value) in [
            ("max_commits", json::number(257)),
            ("max_edges", json::number(0)),
            ("max_preparation_bytes", json::number(1_048_577)),
            ("profile", text("linear-v1")),
            ("empty", text("guess")),
            ("committer", text("bad\nidentity")),
            ("upstream", valid["expected_source"].clone()),
            ("target_reference", valid["source_reference"].clone()),
        ] {
            let mut bad = valid.clone();
            bad.insert(field.into(), value);
            assert!(parse(&bad, format).is_err(), "{field}");
        }
        for empty in ["stop", "drop", "keep"] {
            let mut permitted = valid.clone();
            permitted.insert("empty".into(), text(empty));
            assert!(parse(&permitted, format).is_ok());
        }
    }
}

#[test]
fn rebase_discovery_is_closed_and_output_requires_live_bounded_work() {
    for inspecting in [false, true] {
        let descriptor = schema(inspecting);
        let fields = descriptor.object().unwrap();
        assert_eq!(fields["additionalProperties"], Value::Bool(false));
        let properties = fields["properties"].object().unwrap();
        for forbidden in [
            "principal",
            "bundle_path",
            "paths_hex",
            "comparison",
            "force",
        ] {
            assert!(!properties.contains_key(forbidden));
        }
    }
    assert_eq!(
        bounded(Value::Null, &mut || false).unwrap_err().code,
        "rebase_cancelled"
    );
    assert_eq!(
        bounded(text("x".repeat(MAX_RESULT_BYTES)), &mut || true)
            .unwrap_err()
            .code,
        "rebase_result_limit"
    );
    assert_eq!(bounded(Value::Null, &mut || true).unwrap(), Value::Null);
}
