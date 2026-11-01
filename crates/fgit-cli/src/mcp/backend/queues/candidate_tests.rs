//! Landing is an exact native candidate command, never an execution claim.
use super::super::super::json::{self, text};
use super::tests::{args, incarnation};
use super::*;

#[test]
fn candidate_guards_are_complete_and_cannot_smuggle_authority_or_refresh() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = args(LAND_CANDIDATE, format);
        let command = parse_candidate_landing(&original, format, incarnation()).unwrap();
        assert_eq!(command.number.get(), 1);
        assert_eq!(command.expected_version.get(), 2);
        assert_eq!(command.pull_request.get(), 7);
        assert_eq!(command.expected_pull_request_version.get(), 3);
        assert_eq!(command.expected_policy_epoch.get(), 4);
        assert_eq!(
            command.merge.base_tip.to_string(),
            "cc".repeat(format.digest_len())
        );
        assert_eq!(
            command.merge.merge_commit.to_string(),
            "dd".repeat(format.digest_len())
        );
        for field in [
            "number",
            "expected_version",
            "expected_incarnation",
            "object_format",
            "idempotency_key",
            "target_reference",
            "source_reference",
            "pull_request",
            "expected_pull_request_version",
            "expected_source",
            "expected_target",
            "expected_policy_epoch",
            "merge_base",
            "candidate_commit",
        ] {
            let mut missing = original.clone();
            missing.remove(field);
            assert!(
                parse_candidate_landing(&missing, format, incarnation()).is_err(),
                "{field}"
            );
        }
        for field in [
            "actor",
            "principal",
            "required_reviewers",
            "checks",
            "successful_checks",
            "method",
            "force",
            "policy_epoch",
            "queue_number",
            "refresh",
            "bundle",
        ] {
            let mut invalid = original.clone();
            invalid.insert(field.into(), text("untrusted"));
            assert_eq!(
                parse_candidate_landing(&invalid, format, incarnation())
                    .unwrap_err()
                    .code,
                "unknown_argument",
                "{field}"
            );
        }
        for (field, value) in [
            ("number", text("0")),
            ("pull_request", text("0")),
            ("expected_version", text("0")),
            ("expected_version", text((u64::MAX - 1).to_string())),
            ("expected_pull_request_version", text("0")),
            ("expected_pull_request_version", text(u64::MAX.to_string())),
            ("expected_policy_epoch", text("0")),
            ("expected_policy_epoch", text("04")),
            ("expected_policy_epoch", json::number(4)),
            ("expected_incarnation", text("ef".repeat(16))),
            ("object_format", text("invalid")),
            ("idempotency_key", text("")),
            ("source_reference", text("refs/heads/main")),
        ] {
            let mut invalid = original.clone();
            invalid.insert(field.into(), value);
            assert!(
                parse_candidate_landing(&invalid, format, incarnation()).is_err(),
                "{field}"
            );
        }
        for field in [
            "expected_source",
            "expected_target",
            "merge_base",
            "candidate_commit",
        ] {
            for value in [
                "00".repeat(format.digest_len()),
                "AA".repeat(format.digest_len()),
                "ee".repeat(if format == GitHashAlgorithm::Sha1 {
                    32
                } else {
                    20
                }),
            ] {
                let mut invalid = original.clone();
                invalid.insert(field.into(), text(value));
                assert!(
                    parse_candidate_landing(&invalid, format, incarnation()).is_err(),
                    "{field}"
                );
            }
        }
        for value in ["aa", "bb", "cc"] {
            let mut invalid = original.clone();
            invalid.insert(
                "candidate_commit".into(),
                text(value.repeat(format.digest_len())),
            );
            assert_eq!(
                parse_candidate_landing(&invalid, format, incarnation())
                    .unwrap_err()
                    .code,
                "invalid_queue_command"
            );
        }
        // A target that is the merge base is allowed; native proof decides
        // whether the selected two-parent commit has exactly these parents.
        let mut possible = original;
        possible.insert("merge_base".into(), text("bb".repeat(format.digest_len())));
        possible.insert("expected_version".into(), text((u64::MAX - 2).to_string()));
        possible.insert(
            "expected_pull_request_version".into(),
            text((u64::MAX - 1).to_string()),
        );
        assert!(parse_candidate_landing(&possible, format, incarnation()).is_ok());
    }
}

#[test]
fn native_bundle_envelope_is_bounded_and_optional_only_for_terminal_resolution() {
    let format = GitHashAlgorithm::Sha256;
    let original = args(LAND_CANDIDATE, format);
    let expected = parse_candidate_landing(&original, format, incarnation()).unwrap();
    for chunks in [None, Some(Value::Array(vec![]))] {
        let mut recovery = original.clone();
        recovery.remove("bundle_hex_chunks");
        if let Some(value) = chunks {
            recovery.insert("bundle_hex_chunks".into(), value);
        }
        let (_, Command::CandidateLanding { command, bundle }) =
            input::parse(LAND_CANDIDATE, &recovery, format, incarnation()).unwrap()
        else {
            panic!()
        };
        assert_eq!(command, expected);
        assert!(bundle.is_empty());
    }
    let mut maximum = original.clone();
    maximum.insert(
        "bundle_hex_chunks".into(),
        Value::Array(vec![text("ab".repeat(8192)); 3]),
    );
    let (_, Command::CandidateLanding { bundle, .. }) =
        input::parse(LAND_CANDIDATE, &maximum, format, incarnation()).unwrap()
    else {
        panic!()
    };
    assert_eq!(bundle, vec![0xab; 24 * 1024]);
    for value in [
        Value::Null,
        text("abcd"),
        Value::Array(vec![text("")]),
        Value::Array(vec![text("a")]),
        Value::Array(vec![text("aB")]),
        Value::Array(vec![text("gg")]),
        Value::Array(vec![json::number(10)]),
        Value::Array(vec![text("ab"); 4]),
        Value::Array(vec![text("ab".repeat(8193))]),
    ] {
        let mut invalid = original.clone();
        invalid.insert("bundle_hex_chunks".into(), value);
        assert!(
            parse_candidate_landing(&invalid, format, incarnation())
                .unwrap_err()
                .invalid
        );
    }
    // Valid framing is not a forged object proof: native intake, not this
    // adapter, decides whether the bytes are a valid committed Git closure.
    let mut arbitrary = original;
    arbitrary.insert(
        "bundle_hex_chunks".into(),
        Value::Array(vec![text("00"), text("ff")]),
    );
    let (_, Command::CandidateLanding { bundle, .. }) =
        input::parse(LAND_CANDIDATE, &arbitrary, format, incarnation()).unwrap()
    else {
        panic!()
    };
    assert_eq!(bundle, [0, 255]);
}

#[test]
fn candidate_landing_shares_only_the_independent_landing_ceiling() {
    for read in [false, true] {
        for write in [false, true] {
            for land in [false, true] {
                let grants = QueueGrants { read, write, land };
                assert_eq!(permitted(grants, LAND_CANDIDATE), land);
                assert_eq!(is_mutation(grants, LAND_CANDIDATE), land);
                let discovered = tools(grants);
                assert_eq!(
                    discovered.iter().any(|tool| tool.name == LAND_CANDIDATE),
                    land
                );
                assert_eq!(discovered.iter().any(|tool| tool.name == LAND), land);
            }
        }
    }
    let schema = schema::for_tool(LAND_CANDIDATE);
    let schema = schema.object().unwrap();
    let properties = schema["properties"].object().unwrap();
    let Value::Array(required) = &schema["required"] else {
        panic!()
    };
    assert!(!required.contains(&text("bundle_hex_chunks")));
    assert!(required.contains(&text("candidate_commit")));
    assert!(required.contains(&text("merge_base")));
    let chunks = properties["bundle_hex_chunks"].object().unwrap();
    assert_eq!(chunks["maxItems"].unsigned(), Some(3));
    assert_eq!(
        chunks["items"].object().unwrap()["maxLength"].unsigned(),
        Some(16_384)
    );
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
}
