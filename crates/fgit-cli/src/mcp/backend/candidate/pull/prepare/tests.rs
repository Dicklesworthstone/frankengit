use super::*;

fn input(format: GitHashAlgorithm) -> Object {
    let Value::Object(fields) = object([
        ("operation", text(PREPARE)),
        ("number", text("1")),
        ("expected_version", text("3")),
        ("source_reference", text("refs/heads/topic")),
        ("target_reference", text("refs/heads/main")),
        ("expected_source", text("11".repeat(format.digest_len()))),
        ("expected_target", text("22".repeat(format.digest_len()))),
        ("policy_epoch", text("2")),
        ("author", text("A <a@example.invalid>")),
        ("committer", text("C <c@example.invalid>")),
        ("timestamp", text("1")),
        ("message_hex", text(hex(b"merge\n"))),
    ]) else {
        unreachable!()
    };
    fields
}
#[test]
fn preparation_requires_every_subject_coordinate_and_independent_commit_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let good = input(format);
        assert!(parse(&good, format).is_ok());
        for field in good.keys() {
            let mut missing = good.clone();
            missing.remove(field);
            assert!(parse(&missing, format).is_err(), "{field}");
        }
        for field in [
            "principal",
            "reviewer",
            "approved",
            "force",
            "bundle_path",
            "idempotency_key",
            "candidate_commit",
            "merge_base",
            "review_version",
            "required_reviewers",
            "patch",
            "paths_hex",
        ] {
            let mut bad = good.clone();
            bad.insert(field.into(), text("not authority"));
            assert!(parse(&bad, format).is_err(), "{field}");
        }
        for field in ["expected_source", "expected_target"] {
            for value in [
                Value::Null,
                json::number(1),
                text("latest"),
                text("00".repeat(format.digest_len())),
                text("AB".repeat(format.digest_len())),
            ] {
                let mut bad = good.clone();
                bad.insert(field.into(), value);
                assert!(parse(&bad, format).is_err(), "{field}");
            }
        }
        let mut raw = good.clone();
        raw.remove("source_reference");
        raw.insert(
            "source_reference_hex".into(),
            text(hex(b"refs/heads/raw-\xff")),
        );
        assert_eq!(
            parse(&raw, format)
                .unwrap()
                .selection
                .subject
                .source_ref
                .as_bytes(),
            b"refs/heads/raw-\xff"
        );
        raw.insert("source_reference".into(), text("refs/heads/also"));
        assert!(parse(&raw, format).is_err());
    }
}
#[test]
fn explicit_profiles_and_native_work_limits_are_closed_before_io() {
    let format = GitHashAlgorithm::Sha1;
    let good = input(format);
    for profile in ["path-merge-v1", "exact-renames-v1"] {
        let mut args = good.clone();
        args.insert("merge_profile".into(), text(profile));
        assert!(parse(&args, format).is_ok());
    }
    for (field, maximum) in [
        ("max_commits", 4096),
        ("max_tree_entries", 100_000),
        ("max_output_bytes", 1_048_576),
        ("max_conflicts", 64),
    ] {
        for value in [
            json::number(0),
            json::number(maximum + 1),
            text("1"),
            Value::Null,
        ] {
            let mut args = good.clone();
            args.insert(field.into(), value);
            assert!(parse(&args, format).is_err(), "{field}");
        }
        let mut edge = good.clone();
        edge.insert(field.into(), json::number(maximum));
        assert!(parse(&edge, format).is_ok());
    }
    for (field, value) in [
        ("merge_profile", text("recursive")),
        ("number", text("0")),
        ("policy_epoch", text("0")),
        ("expected_version", text("0")),
        ("message_hex", text("00")),
        ("timestamp", text("0")),
    ] {
        let mut args = good.clone();
        args.insert(field.into(), value);
        assert!(parse(&args, format).is_err(), "{field}");
    }
    let schema = schema();
    let schema = schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let properties = schema["properties"].object().unwrap();
    assert!(!properties.contains_key("idempotency_key"));
    assert!(properties.contains_key("expected_head"));
}
#[test]
fn conflicts_and_up_to_date_results_cannot_smuggle_a_publishable_artifact() {
    let format = GitHashAlgorithm::Sha1;
    let parsed = parse(&input(format), format).unwrap();
    let base = GitOid::from_hex(format, &"33".repeat(format.digest_len())).unwrap();
    let conflict = fgit_forge::preparation::MergeConflict {
        path: b"file".to_vec(),
        kind: ConflictKind::Content,
        base: None,
        ours: Some(MergeEntry {
            name: b"file".to_vec(),
            mode: 0o100644,
            oid: parsed.selection.subject.target_tip,
        }),
        theirs: Some(MergeEntry {
            name: b"file".to_vec(),
            mode: 0o100644,
            oid: parsed.selection.subject.source_tip,
        }),
    };
    let outcome = MergePreparation::Conflicted {
        base,
        conflicts: vec![conflict.clone()],
    };
    assert_eq!(
        render(format, &parsed, &outcome, None).unwrap()["state"].text(),
        Some("conflicted")
    );
    assert!(render(format, &parsed, &outcome, Some(b"forged bundle")).is_err());
    let bad = MergePreparation::Conflicted {
        base,
        conflicts: Vec::new(),
    };
    assert!(render(format, &parsed, &bad, None).is_err());
    let mut bad_path = conflict;
    bad_path.path = b"../outside".to_vec();
    assert!(
        render(
            format,
            &parsed,
            &MergePreparation::Conflicted {
                base,
                conflicts: vec![bad_path]
            },
            None
        )
        .is_err()
    );
    let same = MergePreparation::AlreadyUpToDate {
        target: parsed.selection.subject.target_tip,
    };
    let result = render(format, &parsed, &same, None).unwrap();
    assert_eq!(result["candidate_arguments"], Value::Null);
    assert_eq!(result["publication_arguments"], Value::Null);
    assert!(render(format, &parsed, &same, Some(b"forged bundle")).is_err());
    assert!(
        render(
            format,
            &parsed,
            &MergePreparation::AlreadyUpToDate { target: base },
            None
        )
        .is_err()
    );
}
#[test]
fn the_shared_candidate_arguments_fit_review_and_merge_without_minting_authority() {
    let format = GitHashAlgorithm::Sha256;
    let parsed = parse(&input(format), format).unwrap();
    let candidate = CandidateBinding {
        merge_base: GitOid::from_hex(format, &"33".repeat(format.digest_len())).unwrap(),
        commit: GitOid::from_hex(format, &"44".repeat(format.digest_len())).unwrap(),
    };
    let bytes = vec![0xab; MAX_BUNDLE_BYTES];
    let result = candidate_arguments(&parsed.selection.subject, candidate, &bytes).unwrap();
    let fields = result.object().unwrap();
    assert_eq!(
        reviews::subject(fields, format).unwrap(),
        (parsed.selection.subject.clone(), candidate)
    );
    assert_eq!(reviews::bundle(fields).unwrap(), bytes);
    for field in [
        "operation",
        "idempotency_key",
        "principal",
        "decision",
        "required_reviewers",
        "review_version",
        "expected_head",
    ] {
        assert!(!fields.contains_key(field), "{field}");
    }
    assert!(candidate_arguments(&parsed.selection.subject, candidate, &[]).is_err());
    assert!(
        candidate_arguments(
            &parsed.selection.subject,
            candidate,
            &vec![0; MAX_BUNDLE_BYTES + 1]
        )
        .is_err()
    );
}

#[test]
fn returned_arguments_leave_room_for_real_mutation_envelopes_at_native_reference_limits() {
    let format = GitHashAlgorithm::Sha256;
    let mut parsed = parse(&input(format), format).unwrap();
    let candidate = CandidateBinding {
        merge_base: GitOid::from_hex(format, &"33".repeat(format.digest_len())).unwrap(),
        commit: GitOid::from_hex(format, &"44".repeat(format.digest_len())).unwrap(),
    };
    let longest = fgit_types::refs::MAX_REF_NAME_LEN - b"refs/heads/".len();
    parsed.selection.subject.source_ref =
        RefName::try_new(format!("refs/heads/{}", "a".repeat(longest)).as_bytes()).unwrap();
    parsed.selection.subject.target_ref =
        RefName::try_new(format!("refs/heads/{}", "b".repeat(longest)).as_bytes()).unwrap();
    let bytes = vec![0xab; MAX_BUNDLE_BYTES];
    let value = publication_arguments(&parsed.selection.subject, candidate, &bytes, MergeCommitStyle::Squash).unwrap();
    let mut fields = value.object().unwrap().clone();
    fields.insert(
        "idempotency_key".into(),
        text("k".repeat(common::MAX_KEY_BYTES)),
    );
    fields.insert(
        "required_reviewers".into(),
        Value::Array(
            (1..=32)
                .map(|n| text(fgit_types::PrincipalId::from_bytes([n; 16]).to_string()))
                .collect(),
        ),
    );
    let message = object([
        ("jsonrpc", text("2.0")),
        ("id", text("i".repeat(128))),
        ("method", text("tools/call")),
        (
            "params",
            object([
                ("name", text("frankengit_pull_merge_reviewed")),
                ("arguments", Value::Object(fields)),
            ]),
        ),
    ]);
    let bytes = message.encode(json::MAX_INPUT).unwrap();
    assert_eq!(json::parse(bytes.as_bytes()).unwrap(), message);
    assert!(
        RefName::try_new(format!("refs/heads/{}", "a".repeat(longest + 1)).as_bytes()).is_err()
    );
}

#[test]
fn merge_methods_are_closed_and_independent_of_tree_profiles() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let good = input(format);
        let baseline = parse(&good, format).unwrap();
        assert_eq!(baseline.style, MergeCommitStyle::TwoParent);
        for (method, style) in [
            ("merge-commit", MergeCommitStyle::TwoParent),
            ("squash", MergeCommitStyle::Squash),
        ] {
            for (profile, expected_profile) in [
                ("path-merge-v1", MergeProfile::PathMergeV1),
                ("exact-renames-v1", MergeProfile::ExactRenamesV1),
            ] {
                let mut args = good.clone();
                args.insert("method".into(), text(method));
                args.insert("merge_profile".into(), text(profile));
                let parsed = parse(&args, format).unwrap();
                assert_eq!(parsed.style, style);
                assert_eq!(parsed.profile, expected_profile);
                assert_eq!(parsed.selection.subject, baseline.selection.subject);
                assert_eq!(parsed.metadata, baseline.metadata);
            }
        }
        for value in [
            Value::Null, Value::Bool(true), json::number(1), text(""),
            text("Squash"), text("fast-forward-only"), text("rebase"),
        ] {
            let mut args = good.clone();
            args.insert("method".into(), value);
            assert!(parse(&args, format).is_err());
        }
    }
    let descriptor = schema();
    let fields = descriptor.object().unwrap();
    let method = fields["properties"].object().unwrap()["method"].object().unwrap();
    assert_eq!(method["default"].text(), Some("merge-commit"));
    assert_eq!(method["enum"], Value::Array(vec![text("merge-commit"), text("squash")]));
    let Value::Array(required) = &fields["required"] else { unreachable!() };
    assert!(!required.contains(&text("method")));
}

#[test]
fn publication_templates_bind_method_without_contaminating_exact_review_arguments() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let parsed = parse(&input(format), format).unwrap();
        let candidate = CandidateBinding {
            merge_base: GitOid::from_hex(format, &"33".repeat(format.digest_len())).unwrap(),
            commit: GitOid::from_hex(format, &"44".repeat(format.digest_len())).unwrap(),
        };
        let bytes = vec![0xab; MAX_BUNDLE_BYTES];
        let review = candidate_arguments(&parsed.selection.subject, candidate, &bytes).unwrap();
        assert!(!review.object().unwrap().contains_key("method"));
        for style in [MergeCommitStyle::TwoParent, MergeCommitStyle::Squash] {
            let publication = publication_arguments(&parsed.selection.subject, candidate, &bytes, style).unwrap();
            let mut fields = publication.object().unwrap().clone();
            assert_eq!(fields.remove("method").unwrap().text(), Some(merge_method_name(style)));
            assert_eq!(Value::Object(fields), review);
            publication.encode(json::MAX_INPUT - 4096).unwrap();
        }
    }
}

#[test]
fn clean_rendering_rejects_a_plan_with_a_different_parent_method() {
    use fgit_forge::preparation::{PlannedMergeObject, PreparedMerge};
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut args = input(format);
        args.insert("method".into(), text("squash"));
        let parsed = parse(&args, format).unwrap();
        let tree = GitOid::from_hex(format, &"55".repeat(format.digest_len())).unwrap();
        let base = GitOid::from_hex(format, &"33".repeat(format.digest_len())).unwrap();
        let body = format!(
            "tree {tree}\nparent {}\nauthor A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\nmerge\n",
            parsed.selection.subject.target_tip
        ).into_bytes();
        let commit = git_object_id(format, GitObjectKind::Commit, &body);
        let plan = PreparedMerge {
            style: MergeCommitStyle::Squash,
            base,
            target: parsed.selection.subject.target_tip,
            source: parsed.selection.subject.source_tip,
            tree,
            commit,
            objects: vec![PlannedMergeObject { id: commit, kind: GitObjectKind::Commit, body }],
        };
        let outcome = MergePreparation::Clean(plan.clone());
        let result = render(format, &parsed, &outcome, Some(b"transport bytes")).unwrap();
        assert_eq!(result["parents"], Value::Array(vec![text(raw_oid(plan.target))]));
        assert_eq!(
            result["publication_arguments"].object().unwrap()["method"].text(),
            Some("squash")
        );
        let mut mismatched = plan;
        mismatched.style = MergeCommitStyle::TwoParent;
        assert!(render(format, &parsed, &MergePreparation::Clean(mismatched), Some(b"transport bytes")).is_err());
    }
}
