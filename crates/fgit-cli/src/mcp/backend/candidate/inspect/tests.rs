use super::*;
fn valid(format: GitHashAlgorithm) -> Object {
    let Value::Object(args) = object([
        ("operation", text("inspect")), ("reference", text("refs/heads/topic")),
        ("expected_base", text("ab".repeat(format.digest_len()))),
        ("expected_candidate", text("cd".repeat(format.digest_len()))),
        ("bundle_hex_chunks", Value::Array(vec![text("ff00")])),
    ]) else { unreachable!() };
    args
}
#[test]
fn inspection_requires_independent_native_coordinates_and_lossless_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let args = valid(format);
        let parsed = parse(&args, format).unwrap();
        assert_eq!(parsed.bundle, [255, 0]);
        assert_eq!(parsed.options.mode, ComparisonMode::Direct);
        assert!(parsed.options.paths.is_empty());
        for name in ["operation", "reference", "expected_base", "expected_candidate", "bundle_hex_chunks"] {
            let mut absent = args.clone(); absent.remove(name);
            assert!(parse(&absent, format).is_err(), "{name}");
        }
        let mut same = args.clone();
        same.insert("expected_candidate".into(), same["expected_base"].clone());
        assert_eq!(parse(&same, format).err().unwrap().code, "candidate_must_change_tip");
        let mut foreign = args;
        foreign.insert("expected_candidate".into(), text("cd".repeat(if format == GitHashAlgorithm::Sha1 { 32 } else { 20 })));
        assert!(parse(&foreign, format).is_err());
    }
}
#[test]
fn filters_metadata_effects_and_pr_authority_cannot_enter_full_inspection() {
    for name in ["paths_hex", "comparison", "principal", "number", "expected_version",
        "idempotency_key", "force", "patch", "author", "storage", "approval"]
    {
        let mut args = valid(GitHashAlgorithm::Sha1);
        args.insert(name.into(), text("untrusted"));
        assert_eq!(parse(&args, GitHashAlgorithm::Sha1).err().unwrap().code, "unknown_argument");
    }
}
#[test]
fn transport_digest_pin_is_checked_without_trusting_pack_headers() {
    let mut args = valid(GitHashAlgorithm::Sha1);
    let digest = hex(&sha256_digest(&[255, 0]));
    args.insert("expected_bundle_sha256".into(), text(&digest));
    assert!(parse(&args, GitHashAlgorithm::Sha1).is_ok());
    for bad in ["0".repeat(64), digest.to_uppercase(), "00".into(), "gg".repeat(32)] {
        args.insert("expected_bundle_sha256".into(), text(bad));
        assert!(parse(&args, GitHashAlgorithm::Sha1).is_err());
    }
    args.remove("expected_bundle_sha256");
    args.insert("expected_head".into(), text("alg:01:aa"));
    assert!(parse(&args, GitHashAlgorithm::Sha1).is_err());
}
#[test]
fn caller_budgets_can_only_narrow_the_closed_inspection_profile() {
    for &(name, _, minimum, maximum) in LIMITS {
        for value in [minimum, maximum] {
            let mut args = valid(GitHashAlgorithm::Sha1);
            args.insert(name.into(), json::number(value as u64));
            assert!(parse(&args, GitHashAlgorithm::Sha1).is_ok(), "{name}={value}");
        }
        for value in [json::number(maximum as u64 + 1), text("1"), Value::Null] {
            let mut args = valid(GitHashAlgorithm::Sha1);
            args.insert(name.into(), value);
            assert!(parse(&args, GitHashAlgorithm::Sha1).is_err(), "{name}");
        }
        if minimum > 0 {
            let mut args = valid(GitHashAlgorithm::Sha1);
            args.insert(name.into(), json::number(0));
            assert!(parse(&args, GitHashAlgorithm::Sha1).is_err());
        }
    }
}
