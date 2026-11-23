use super::*;

fn input(format: GitHashAlgorithm) -> Object {
    let Value::Object(fields) = object([
        ("operation", text(QUEUE_PREPARE)),
        ("queue_number", text("7")),
        ("expected_queue_version", text("5")),
        ("number", text("11")),
        ("expected_version", text("3")),
        ("source_reference", text("refs/heads/topic")),
        ("target_reference", text("refs/heads/main")),
        ("expected_source", text("11".repeat(format.digest_len()))),
        ("expected_target", text("22".repeat(format.digest_len()))),
        ("policy_epoch", text("2")),
        ("author", text("A <a@example.invalid>")),
        ("committer", text("C <c@example.invalid>")),
        ("timestamp", text("1")),
        ("message_hex", text(hex(b"queue merge\n"))),
    ]) else {
        unreachable!()
    };
    fields
}

#[test]
fn queue_preparation_closes_the_subject_and_two_parent_method_before_io() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = input(format);
        let parsed = parse(&original, format).unwrap();
        assert_eq!(parsed.number.get(), 7);
        assert_eq!(parsed.expected_version.get(), 5);
        assert_eq!(parsed.preparation.selection.subject.pull_request.get(), 11);
        assert_eq!(parsed.preparation.style, MergeCommitStyle::TwoParent);
        for name in original.keys() {
            let mut missing = original.clone();
            missing.remove(name);
            assert!(parse(&missing, format).is_err(), "missing {name}");
        }
        for name in [
            "idempotency_key",
            "principal",
            "approved",
            "required_reviewers",
            "bundle_path",
            "bundle_url",
            "candidate_commit",
            "merge_base",
            "force",
        ] {
            let mut injected = original.clone();
            injected.insert(name.into(), text("not an authority"));
            assert_eq!(
                parse(&injected, format).unwrap_err().code,
                "unknown_argument"
            );
        }
        for (name, value) in [
            ("operation", text(PREPARE)),
            ("queue_number", text("0")),
            ("queue_number", text("07")),
            ("queue_number", json::number(7)),
            ("queue_number", text("18446744073709551616")),
            ("expected_queue_version", text("0")),
            ("expected_queue_version", text((u64::MAX - 1).to_string())),
            ("expected_version", text(u64::MAX.to_string())),
            ("method", text("squash")),
            ("method", text("fast-forward")),
            ("max_output_bytes", json::number(0)),
            ("merge_profile", text("auto")),
        ] {
            let mut bad = original.clone();
            bad.insert(name.into(), value);
            assert!(parse(&bad, format).is_err(), "{name}");
        }
        let mut last = original.clone();
        last.insert(
            "expected_queue_version".into(),
            text((u64::MAX - 2).to_string()),
        );
        last.insert("method".into(), text("merge-commit"));
        last.insert("merge_profile".into(), text("exact-renames-v1"));
        assert!(parse(&last, format).is_ok());
    }
}

#[test]
fn builtin_attributes_queue_selection_keeps_the_shared_schema_and_original_guards() {
    let schema = schema();
    let properties = schema.object().unwrap()["properties"].object().unwrap();
    let profile = properties["merge_profile"].object().unwrap();
    let Value::Array(choices) = &profile["enum"] else {
        panic!("merge profile schema must enumerate supported versions")
    };
    assert!(choices.contains(&text("builtin-attributes-v1")));
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut args = input(format);
        let baseline = parse(&args, format).unwrap();
        args.insert("merge_profile".into(), text("builtin-attributes-v1"));
        let selected = parse(&args, format).unwrap();
        assert_eq!(
            selected.preparation.profile,
            MergeProfile::BuiltinAttributesV1
        );
        assert_eq!(selected.number, baseline.number);
        assert_eq!(selected.expected_version, baseline.expected_version);
        assert_eq!(
            selected.preparation.selection.subject,
            baseline.preparation.selection.subject
        );
        assert_eq!(selected.preparation.metadata, baseline.preparation.metadata);
        assert_eq!(selected.preparation.style, MergeCommitStyle::TwoParent);
        args.insert("method".into(), text("squash"));
        assert_eq!(
            parse(&args, format).unwrap_err().code,
            "queue_requires_merge_commit"
        );
    }
}

#[test]
fn generated_landing_arguments_preserve_distinct_queue_pr_and_candidate_coordinates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut original = input(format);
        original.remove("source_reference");
        original.insert(
            "source_reference_hex".into(),
            text(hex(b"refs/heads/raw-\xff")),
        );
        let input = parse(&original, format).unwrap();
        let incarnation = RepositoryIncarnationId::from_bytes([0x5a; 16]);
        let candidate = CandidateBinding {
            merge_base: GitOid::from_hex(format, &"33".repeat(format.digest_len())).unwrap(),
            commit: GitOid::from_hex(format, &"44".repeat(format.digest_len())).unwrap(),
        };
        let bytes = vec![0xab; MAX_BUNDLE_BYTES];
        let value = publication_arguments(&input, incarnation, candidate, &bytes).unwrap();
        let fields = value.object().unwrap();
        assert_eq!(fields["number"].text(), Some("7"));
        assert_eq!(fields["expected_version"].text(), Some("5"));
        assert_eq!(fields["pull_request"].text(), Some("11"));
        assert_eq!(fields["expected_pull_request_version"].text(), Some("3"));
        assert_eq!(fields["expected_policy_epoch"].text(), Some("2"));
        assert_eq!(chunks(fields, "bundle_hex_chunks").unwrap(), bytes);
        for absent in [
            "idempotency_key",
            "operation",
            "method",
            "principal",
            "decision",
            "required_reviewers",
            "approved",
            "expected_head",
            "queue_number",
        ] {
            assert!(!fields.contains_key(absent), "{absent}");
        }
        let mut offered = fields.clone();
        offered.insert("idempotency_key".into(), text("caller-owned-key"));
        let parsed = queues::parse_candidate_landing(&offered, format, incarnation).unwrap();
        assert_eq!(parsed.number, input.number);
        assert_eq!(parsed.expected_version, input.expected_version);
        assert_eq!(parsed.merge.source_ref.as_bytes(), b"refs/heads/raw-\xff");
        assert_eq!(parsed.merge.merge_commit, candidate.commit);
        assert_eq!(parsed.merge.base_tip, candidate.merge_base);
        assert!(
            Value::Object(offered)
                .encode(json::MAX_INPUT - 2048)
                .is_ok()
        );
        for commit in [
            input.preparation.selection.subject.source_tip,
            candidate.merge_base,
        ] {
            assert!(
                publication_arguments(
                    &input,
                    incarnation,
                    CandidateBinding {
                        commit,
                        ..candidate
                    },
                    &bytes,
                )
                .is_err()
            );
        }
        assert!(publication_arguments(&input, incarnation, candidate, &[]).is_err());
        assert!(
            publication_arguments(
                &input,
                incarnation,
                candidate,
                &vec![0; MAX_BUNDLE_BYTES + 1],
            )
            .is_err()
        );
    }
}

#[test]
fn discovery_requires_exact_queue_guards_and_advertises_no_mutation_inputs() {
    let value = schema();
    let fields = value.object().unwrap();
    assert_eq!(fields["additionalProperties"], Value::Bool(false));
    let properties = fields["properties"].object().unwrap();
    assert_eq!(
        properties["method"].object().unwrap()["const"].text(),
        Some("merge-commit")
    );
    let Value::Array(required) = &fields["required"] else {
        unreachable!()
    };
    for field in [
        "queue_number",
        "expected_queue_version",
        "number",
        "expected_version",
        "policy_epoch",
    ] {
        assert!(required.contains(&text(field)), "{field}");
    }
    for field in [
        "principal",
        "idempotency_key",
        "bundle_hex_chunks",
        "required_reviewers",
    ] {
        assert!(!properties.contains_key(field));
    }
}
