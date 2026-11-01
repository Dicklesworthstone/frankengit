use super::*;

fn workflow_args(format: GitHashAlgorithm, conclusion: &str) -> Vec<String> {
    vec![
        "not-created-workflow-bisect-root".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--trusted-local".into(),
        "--check-job".into(),
        "build \"release\" / λ".into(),
        "--check-ref".into(),
        "refs/heads/ci".into(),
        "--check-commit".into(),
        "ab".repeat(format.digest_len()),
        "--check-publisher".into(),
        "12".repeat(16),
        "--check-graph".into(),
        "34".repeat(32),
        "--check-conclusion".into(),
        conclusion.into(),
    ]
}

fn replace(args: &mut [String], flag: &str, value: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}

#[test]
fn every_workflow_conclusion_preserves_exact_coordinates_in_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for (text, expected) in [
            ("action_required", WorkflowCheckConclusion::ActionRequired),
            ("success", WorkflowCheckConclusion::Success),
            ("failure", WorkflowCheckConclusion::Failure),
            ("cancelled", WorkflowCheckConclusion::Cancelled),
            ("timed_out", WorkflowCheckConclusion::TimedOut),
        ] {
            let parsed = parse(&workflow_args(format, text)).unwrap();
            assert_eq!(parsed.query.start, DecisionSequence::FIRST);
            assert_eq!(parsed.query.end, None);
            assert_eq!(parsed.query.max_probes, MAX_PROBES);
            assert_eq!(parsed.query.expected_head, None);
            assert_eq!(parsed.incarnation, None);
            assert_eq!(
                parsed.query.predicate,
                Predicate::WorkflowCheck {
                    source_ref: RefName::try_new(b"refs/heads/ci").unwrap(),
                    source_commit: GitOid::from_hex(format, &"ab".repeat(format.digest_len()))
                        .unwrap(),
                    publisher: PrincipalId::from_bytes([0x12; 16]),
                    graph_root: [0x34; 32],
                    job: "build \"release\" / λ".into(),
                    conclusion: expected,
                }
            );
        }
    }
}

#[test]
fn all_snapshot_and_range_options_fit_with_a_complete_workflow_selector() {
    let expected_head = RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[3; 32]).unwrap(),
    );
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for end in ["9", "latest"] {
            let mut args = workflow_args(format, "failure");
            args.extend([
                "--start".into(),
                "2".into(),
                "--end".into(),
                end.into(),
                "--max-probes".into(),
                "17".into(),
                "--expected-head".into(),
                format!("head:alg:1:codec:1.0:{}", "03".repeat(32)),
                "--expected-incarnation".into(),
                "44".repeat(16),
            ]);
            // Three positionals, one switch, five global pairs, six selector pairs.
            assert_eq!(args.len(), 26);
            let parsed = parse(&args).unwrap();
            assert_eq!(parsed.storage, PathBuf::from(&args[0]));
            assert_eq!(parsed.tenant, TenantId::from_bytes([0x11; 16]));
            assert_eq!(parsed.repository, RepositoryId::from_bytes([0x22; 16]));
            assert_eq!(parsed.query.start.get(), 2);
            assert_eq!(
                parsed.query.end.map(|end| end.get()),
                (end == "9").then_some(9)
            );
            assert_eq!(parsed.query.max_probes, 17);
            assert_eq!(parsed.query.expected_head, Some(expected_head));
            assert_eq!(
                parsed.incarnation,
                Some(RepositoryIncarnationId::from_bytes([0x44; 16]))
            );
            args.push("--unused".into());
            assert_eq!(parse(&args).err().as_deref(), Some(USAGE));
        }
    }
}

#[test]
fn workflow_option_order_does_not_change_the_typed_query() {
    let args = workflow_args(GitHashAlgorithm::Sha256, "timed_out");
    let expected = parse(&args).unwrap().query;
    let pairs: Vec<_> = args[4..].chunks_exact(2).collect();
    for rotation in 0..pairs.len() {
        let mut reordered = args[..3].to_vec();
        for pair in pairs.iter().cycle().skip(rotation).take(pairs.len()) {
            reordered.extend_from_slice(pair);
        }
        reordered.push("--trusted-local".into());
        assert_eq!(parse(&reordered).unwrap().query, expected);
    }
}

#[test]
fn every_workflow_coordinate_is_required_once_and_needs_a_value() {
    let complete = workflow_args(GitHashAlgorithm::Sha1, "failure");
    for index in (4..complete.len()).step_by(2) {
        let mut missing_pair = complete.clone();
        missing_pair.drain(index..index + 2);
        assert!(parse(&missing_pair).is_err(), "missing {}", complete[index]);

        let mut missing_value = complete.clone();
        missing_value.remove(index + 1);
        assert!(
            parse(&missing_value).is_err(),
            "value for {}",
            complete[index]
        );

        let mut duplicate = complete.clone();
        duplicate.extend_from_slice(&complete[index..index + 2]);
        assert!(
            parse(&duplicate)
                .err()
                .unwrap()
                .contains("duplicate option"),
            "duplicate {}",
            complete[index]
        );
    }
    let mut untrusted = complete.clone();
    untrusted.remove(3);
    assert!(parse(&untrusted).is_err());
    let mut duplicate_authorization = complete;
    duplicate_authorization.push("--trusted-local".into());
    assert!(parse(&duplicate_authorization).is_err());
}

#[test]
fn workflow_selectors_cannot_mix_with_other_predicates_or_unknown_coordinates() {
    for extra in [
        vec!["--ref", "refs/heads/main", "--absent"],
        vec!["--policy-at-least", "1"],
        vec!["--issue", "1", "--state", "closed"],
        vec!["--pull", "1", "--state", "merged"],
        vec!["--state", "closed"],
        vec!["--absent"],
        vec!["--check-run", "run"],
        vec!["--check-attempt", "attempt"],
        vec!["--check-actor", "12"],
        vec!["--assume-monotone"],
        vec!["--execute", "false"],
    ] {
        let mut args = workflow_args(GitHashAlgorithm::Sha1, "failure");
        args.extend(extra.iter().map(|value| value.to_string()));
        assert!(parse(&args).is_err(), "{extra:?}");
    }
}

#[test]
fn malformed_workflow_coordinates_are_refused_before_repository_access() {
    let invalid = [
        (
            "--check-ref",
            vec![
                "".into(),
                "main".into(),
                "refs/tags/v1".into(),
                "refs/heads/".into(),
                "refs/heads/../main".into(),
                "refs/heads/bad.lock".into(),
                "refs/heads/a\nb".into(),
                "refs/heads/a\0b".into(),
            ],
        ),
        (
            "--check-commit",
            vec![
                "".into(),
                "0".repeat(40),
                "0".repeat(64),
                "A".repeat(40),
                "a".repeat(41),
                "g".repeat(64),
                "é".repeat(20),
            ],
        ),
        (
            "--check-publisher",
            vec![
                "".into(),
                "12".repeat(32),
                "1".repeat(31),
                "A".repeat(32),
                "g".repeat(32),
                "é".repeat(16),
            ],
        ),
        (
            "--check-graph",
            vec![
                "".into(),
                "12".repeat(16),
                "1".repeat(63),
                "A".repeat(64),
                "g".repeat(64),
                "é".repeat(32),
            ],
        ),
        (
            "--check-job",
            vec![
                "".into(),
                "line\nbreak".into(),
                "tab\tjob".into(),
                "nul\0job".into(),
                "delete\u{7f}job".into(),
                "c1\u{85}job".into(),
                "x".repeat(MAX_CHECK_JOB_BYTES + 1),
                "λ".repeat(MAX_CHECK_JOB_BYTES / 2 + 1),
            ],
        ),
        (
            "--check-conclusion",
            vec![
                "".into(),
                "SUCCESS".into(),
                "passed".into(),
                "skipped".into(),
                "action-required".into(),
                "timed-out".into(),
                "failure\n".into(),
            ],
        ),
    ];
    for (flag, values) in invalid {
        for value in values {
            let mut args = workflow_args(GitHashAlgorithm::Sha1, "failure");
            replace(&mut args, flag, &value);
            assert!(parse(&args).is_err(), "{flag} {value:?}");
        }
    }
}

#[test]
fn workflow_job_bytes_and_opaque_zero_coordinates_follow_the_record_contract() {
    for job in [
        "x".repeat(MAX_CHECK_JOB_BYTES),
        "λ".repeat(MAX_CHECK_JOB_BYTES / 2),
        " $(false); `false` --check-graph ".into(),
    ] {
        let mut args = workflow_args(GitHashAlgorithm::Sha256, "action_required");
        replace(&mut args, "--check-job", &job);
        replace(&mut args, "--check-publisher", &"0".repeat(32));
        replace(&mut args, "--check-graph", &"0".repeat(64));
        let parsed = parse(&args).unwrap();
        let Predicate::WorkflowCheck {
            publisher,
            graph_root,
            job: actual,
            ..
        } = parsed.query.predicate
        else {
            panic!("wrong predicate");
        };
        assert_eq!(publisher, PrincipalId::from_bytes([0; 16]));
        assert_eq!(graph_root, [0; 32]);
        assert_eq!(actual, job);
    }
}

#[test]
fn command_argument_byte_bounds_are_preserved() {
    let mut args = workflow_args(GitHashAlgorithm::Sha1, "failure");
    args[0] = "x".repeat(8192);
    assert!(parse(&args).is_ok());
    args[0].push('x');
    assert_eq!(parse(&args).err().as_deref(), Some(USAGE));
    let oversized = vec!["x".repeat(8192); 6];
    assert_eq!(parse(&oversized).err().as_deref(), Some(USAGE));
}
