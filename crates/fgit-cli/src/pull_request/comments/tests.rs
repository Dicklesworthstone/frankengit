use super::*;
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_node::PullRequestCommentView;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm,
    RepositoryAuthorityHeadId,
};

fn args(append: bool) -> Vec<String> {
    let mut args = vec![
        if append { "comment" } else { "comments" }.into(),
        "node".into(),
        "11".repeat(16),
        "22".repeat(16),
        "7".into(),
        "--trusted-local".into(),
    ];
    if append {
        args.extend([
            "--principal".into(),
            "33".repeat(16),
            "--idempotency-key".into(),
            "private-key".into(),
            "--expected-version".into(),
            "0".into(),
            "--body".into(),
            " é\r\n<script>literal</script> \n".into(),
        ]);
    }
    args
}
fn replace(args: &mut [String], flag: &str, value: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}
fn head() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    )
}

#[test]
fn comment_inputs_preserve_body_and_discussion_version_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut input = args(true);
        input.extend(["--object-format".into(), format.as_str().into()]);
        let parsed = options::parse(&input).unwrap();
        assert_eq!(parsed.format, format);
        let Operation::Append { command, key, .. } = parsed.operation else {
            panic!("append")
        };
        assert_eq!(command.number.get(), 7);
        assert_eq!(command.body, " é\r\n<script>literal</script> \n");
        assert_eq!(command.expected_version, ExpectedVersion::NewStream);
        assert!(command.anchor.is_none());
        assert_eq!(key, b"private-key");
        replace(&mut input, "--expected-version", "9007199254740993");
        let Operation::Append { command, .. } = options::parse(&input).unwrap().operation else {
            panic!("append")
        };
        assert_eq!(
            command.expected_version,
            ExpectedVersion::Exactly(AggregateVersion::try_new(9_007_199_254_740_993).unwrap())
        );
    }
}

#[test]
fn incomplete_ambiguous_or_authority_widening_comment_input_refuses() {
    for flag in [
        "--principal",
        "--idempotency-key",
        "--expected-version",
        "--body",
    ] {
        let mut input = args(true);
        let index = input.iter().position(|arg| arg == flag).unwrap();
        input.drain(index..index + 2);
        assert!(options::parse(&input).is_err(), "missing {flag}");
    }
    for (flag, value) in [
        ("--expected-version", "01"),
        ("--expected-version", "18446744073709551615"),
        ("--body", " \r\n\t"),
        ("--body", "a\0b"),
        ("--principal", "invalid"),
    ] {
        let mut input = args(true);
        replace(&mut input, flag, value);
        assert!(options::parse(&input).is_err(), "{flag}");
    }
    for flag in [
        "--expected-version",
        "--body-file",
        "--force",
        "--expected-source",
        "--after",
    ] {
        let mut input = args(true);
        input.extend([flag.into(), "1".into()]);
        assert!(options::parse(&input).is_err(), "{flag}");
    }
    let mut untrusted = args(true);
    untrusted.retain(|arg| arg != "--trusted-local");
    assert!(options::parse(&untrusted).is_err());
    let mut bounded = args(true);
    replace(&mut bounded, "--body", &"x".repeat(65_536));
    assert!(options::parse(&bounded).is_ok());
    replace(&mut bounded, "--body", &"é".repeat(32_769));
    assert!(options::parse(&bounded).is_err());
}

#[test]
fn reads_require_a_pinned_continuation_and_refuse_write_options() {
    let mut input = args(false);
    input.extend(["--after".into(), "1".into()]);
    assert!(options::parse(&input).is_err());
    input.extend(["--expected-head".into(), head_token(head())]);
    assert!(options::parse(&input).is_ok());
    for (flag, value) in [
        ("--limit", "0"),
        ("--limit", "101"),
        ("--body", "comment"),
        ("--principal", &"33".repeat(16)),
        ("--expected-version", "0"),
    ] {
        let mut invalid = args(false);
        invalid.extend([flag.into(), value.into()]);
        assert!(options::parse(&invalid).is_err(), "{flag}");
    }
}

#[test]
fn read_reports_keep_high_water_separate_from_page_completion_and_reject_bad_windows() {
    let options = options::parse(&args(false)).unwrap();
    let mut page = PullRequestCommentsPage {
        number: PullRequestNumber::try_new(7).unwrap(),
        source_head: head(),
        discussion_version: Some(AggregateVersion::try_new(1).unwrap()),
        comments: vec![PullRequestCommentView {
            version: AggregateVersion::try_new(1).unwrap(),
            actor: PrincipalId::from_bytes([3; 16]),
            body: "\"untrusted\"\n\u{202e}".into(),
            anchor: None,
            anchor_status: None,
        }],
        next_after: None,
    };
    let rendered = read_report(&options, "incarnation", Some(&page)).unwrap();
    assert!(rendered.contains("\"discussion_version\":\"1\""));
    assert!(rendered.contains("\"complete\":true"));
    assert!(rendered.contains("\\u202e"));
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains("private-key"));
    page.number = PullRequestNumber::try_new(8).unwrap();
    assert!(read_report(&options, "incarnation", Some(&page)).is_err());
    page.number = options.number;
    page.comments[0].version = AggregateVersion::try_new(2).unwrap();
    assert!(read_report(&options, "incarnation", Some(&page)).is_err());
    let absent = read_report(&options, "incarnation", None).unwrap();
    assert!(absent.contains("\"found\":false"));
    assert!(absent.contains("\"discussion_version\":null"));
}

fn anchor_args(format: GitHashAlgorithm) -> Vec<(String, String)> {
    let bytes = match format {
        GitHashAlgorithm::Sha1 => 20,
        GitHashAlgorithm::Sha256 => 32,
    };
    [
        ("--anchor-pull-request-version", "1".into()),
        (
            "--anchor-source-ref-hex",
            super::super::options::hex(b"refs/heads/topic"),
        ),
        (
            "--anchor-target-ref-hex",
            super::super::options::hex(b"refs/heads/main"),
        ),
        ("--anchor-source-tip", "11".repeat(bytes)),
        ("--anchor-target-tip", "22".repeat(bytes)),
        ("--anchor-compared-base", "22".repeat(bytes)),
        ("--anchor-comparison", "direct".into()),
        (
            "--anchor-path-hex",
            super::super::options::hex(b"src/\xff.rs"),
        ),
        ("--anchor-side", "after".into()),
        ("--anchor-blob", "33".repeat(bytes)),
        ("--anchor-mode", "100644".into()),
        ("--anchor-byte-start", "0".into()),
        ("--anchor-byte-end", "6".into()),
        ("--anchor-line-start", "0".into()),
        ("--anchor-line-count", "1".into()),
    ]
    .into_iter()
    .map(|(field, value)| (field.into(), value))
    .collect()
}

fn anchored_input(format: GitHashAlgorithm) -> Vec<String> {
    let mut input = args(true);
    input.extend(["--object-format".into(), format.as_str().into()]);
    for (field, value) in anchor_args(format) {
        input.extend([field, value]);
    }
    input
}

#[test]
fn exact_source_anchor_is_an_optional_complete_bounded_cli_group() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = anchored_input(format);
        let Operation::Append { command, .. } = options::parse(&input).unwrap().operation else {
            panic!("append")
        };
        let anchor = command.anchor.as_ref().unwrap();
        assert_eq!(anchor.source_tip.algorithm(), format);
        assert_eq!(anchor.path, b"src/\xff.rs");
        assert_eq!(
            (
                anchor.byte_start,
                anchor.byte_end,
                anchor.line_start,
                anchor.line_count
            ),
            (0, 6, 0, 1)
        );
        assert_eq!(command.body, " é\r\n<script>literal</script> \n");
        for (missing, _) in anchor_args(format) {
            let mut incomplete = input.clone();
            let position = incomplete
                .iter()
                .position(|value| value == &missing)
                .unwrap();
            incomplete.drain(position..position + 2);
            assert!(options::parse(&incomplete).is_err(), "missing {missing}");
            let mut duplicate = input.clone();
            duplicate.extend([missing.clone(), "1".into()]);
            assert!(options::parse(&duplicate).is_err(), "duplicate {missing}");
        }
        for (field, value) in [
            ("--anchor-pull-request-version", "0"),
            ("--anchor-line-count", "0"),
            ("--anchor-line-count", "129"),
            ("--anchor-line-start", "01"),
            ("--anchor-byte-end", "0"),
            ("--anchor-byte-end", "65537"),
            ("--anchor-mode", "160000"),
            ("--anchor-mode", "0100644"),
            ("--anchor-path-hex", "FF"),
            ("--anchor-path-hex", "2e2e2f66696c65"),
            ("--anchor-side", "guess"),
            ("--anchor-comparison", "remapped"),
        ] {
            let mut invalid = input.clone();
            replace(&mut invalid, field, value);
            assert!(options::parse(&invalid).is_err(), "{field}={value}");
        }
        let mut wrong_format = input;
        replace(
            &mut wrong_format,
            "--anchor-blob",
            &"44".repeat(if format == GitHashAlgorithm::Sha1 {
                32
            } else {
                20
            }),
        );
        assert!(options::parse(&wrong_format).is_err());
    }
    for (field, value) in anchor_args(GitHashAlgorithm::Sha1) {
        let mut read = args(false);
        read.extend([field, value]);
        assert!(options::parse(&read).is_err());
    }
}

#[test]
fn comment_reports_preserve_exact_anchor_identity_and_explicit_outdated_status() {
    use fgit_forge::event::pull_request_comment::SourceCommentStatus;
    let Operation::Append { command, .. } = options::parse(&anchored_input(GitHashAlgorithm::Sha1))
        .unwrap()
        .operation
    else {
        panic!("append")
    };
    let options = options::parse(&args(false)).unwrap();
    let mut page = PullRequestCommentsPage {
        number: options.number,
        source_head: head(),
        discussion_version: Some(AggregateVersion::FIRST),
        comments: vec![PullRequestCommentView {
            version: AggregateVersion::FIRST,
            actor: PrincipalId::from_bytes([3; 16]),
            body: command.body,
            anchor: command.anchor,
            anchor_status: Some(SourceCommentStatus::Exact),
        }],
        next_after: None,
    };
    let exact = read_report(&options, "incarnation", Some(&page)).unwrap();
    assert!(exact.contains("\"anchor_status\":\"exact\""));
    assert!(exact.contains("\"line_start\":\"0\""));
    assert!(exact.contains("\"path_hex\":\"7372632fff2e7273\""));
    assert!(exact.contains(SOURCE_COMMENT_PROFILE));
    page.comments[0].anchor_status = Some(SourceCommentStatus::Outdated);
    let outdated = read_report(&options, "incarnation", Some(&page)).unwrap();
    assert_eq!(
        outdated,
        exact.replace(
            "\"anchor_status\":\"exact\"",
            "\"anchor_status\":\"outdated\""
        )
    );
    page.comments[0].anchor_status = None;
    assert!(read_report(&options, "incarnation", Some(&page)).is_err());
}

fn independent_input(format: GitHashAlgorithm, anchored: bool) -> Vec<String> {
    let mut input = if anchored {
        anchored_input(format)
    } else {
        let mut input = args(true);
        input.extend(["--object-format".into(), format.as_str().into()]);
        input
    };
    input[0] = "append-comment".into();
    let index = input
        .iter()
        .position(|value| value == "--expected-version")
        .unwrap();
    input.drain(index..index + 2);
    input
}

#[test]
fn append_comment_is_explicit_and_preserves_literal_body_and_optional_source_anchor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for anchored in [false, true] {
            let input = independent_input(format, anchored);
            let parsed = options::parse(&input).unwrap();
            assert_eq!(parsed.format, format);
            let Operation::AppendComment {
                principal,
                key,
                command,
                body_file,
            } = parsed.operation
            else {
                panic!("version-independent append")
            };
            assert_eq!(command.number.get(), 7);
            assert_eq!(command.body, " é\r\n<script>literal</script> \n");
            assert_eq!(command.anchor.is_some(), anchored);
            assert_eq!(principal, PrincipalId::from_bytes([0x33; 16]));
            assert_eq!(key, b"private-key");
            assert!(body_file.is_none());
            command.commitment_event(principal).unwrap();
            if let Some(anchor) = command.anchor {
                assert_eq!(anchor.source_tip.algorithm(), format);
                assert_eq!(anchor.path, b"src/\xff.rs");
                assert_eq!(anchor.pull_request_version, AggregateVersion::FIRST);
            }
            let mut exact_without_version = input.clone();
            exact_without_version[0] = "comment".into();
            assert!(options::parse(&exact_without_version).is_err());
            for version in ["0", "1", "18446744073709551615"] {
                let mut injected = input.clone();
                injected.extend(["--expected-version".into(), version.into()]);
                assert!(options::parse(&injected).is_err());
            }
        }
    }
    let mut help = Vec::new();
    assert_eq!(
        run(&["append-comment".into(), "--help".into()], &mut help).unwrap(),
        0
    );
    assert!(
        String::from_utf8(help)
            .unwrap()
            .contains("usage: fg pr append-comment")
    );
}

#[test]
fn append_comment_refuses_authority_overrides_missing_fields_and_partial_anchors() {
    let input = independent_input(GitHashAlgorithm::Sha1, false);
    for field in ["--principal", "--idempotency-key", "--body"] {
        let mut missing = input.clone();
        let index = missing.iter().position(|value| value == field).unwrap();
        missing.drain(index..index + 2);
        assert!(options::parse(&missing).is_err(), "missing {field}");
    }
    for field in [
        "--force",
        "--title",
        "--source-tip",
        "--after",
        "--expected-head",
    ] {
        let mut injected = input.clone();
        injected.extend([field.into(), "untrusted".into()]);
        assert!(options::parse(&injected).is_err(), "{field}");
    }
    let mut untrusted = input.clone();
    untrusted.retain(|arg| arg != "--trusted-local");
    assert!(options::parse(&untrusted).is_err());
    for body in ["", " \r\n\t", "a\0b"] {
        let mut invalid = input.clone();
        replace(&mut invalid, "--body", body);
        assert!(options::parse(&invalid).is_err());
    }
    let mut bounded = input;
    replace(&mut bounded, "--body", &"x".repeat(65_536));
    assert!(options::parse(&bounded).is_ok());
    replace(&mut bounded, "--body", &"é".repeat(32_769));
    assert!(options::parse(&bounded).is_err());
    for (field, _) in anchor_args(GitHashAlgorithm::Sha1) {
        let mut missing = independent_input(GitHashAlgorithm::Sha1, true);
        let index = missing.iter().position(|value| value == &field).unwrap();
        missing.drain(index..index + 2);
        assert!(options::parse(&missing).is_err(), "missing {field}");
    }
}

#[test]
fn append_comment_validates_body_files_before_opening_or_sealing_a_node() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "fg-pr-append-body-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let body = root.join("body");
    std::fs::write(&body, " \r\n\t").unwrap();
    let mut input = independent_input(GitHashAlgorithm::Sha1, false);
    let index = input.iter().position(|value| value == "--body").unwrap();
    input[index] = "--body-file".into();
    input[index + 1] = body.to_str().unwrap().into();
    input[1] = root.join("must-not-open").to_str().unwrap().into();
    let parsed = options::parse(&input).unwrap();
    let Operation::AppendComment {
        command, body_file, ..
    } = parsed.operation
    else {
        panic!("append")
    };
    assert!(command.body.is_empty());
    assert_eq!(body_file.as_deref(), Some(body.as_path()));
    let error = run(&input, &mut Vec::new()).unwrap_err();
    assert!(error.contains("comment must contain nonblank"));
    assert!(!root.join("must-not-open").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn append_receipts_keep_original_terminal_identity_without_inventing_discussion_positions() {
    use fgit_types::{DecisionSequence, RefusalCode, RefusalRecordId, RepositoryCommitId};
    let parsed = options::parse(&independent_input(GitHashAlgorithm::Sha1, true)).unwrap();
    let Operation::AppendComment {
        principal, command, ..
    } = &parsed.operation
    else {
        panic!("append")
    };
    let algorithm = DigestAlgorithmId::try_new(1).unwrap();
    let digest = |seed| DigestBytes::try_new(&[seed; 32]).unwrap();
    let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest(1));
    for outcome in [
        DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest(2),
            ),
        },
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceStale,
            refusal_record_id: RefusalRecordId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest(3),
            ),
        },
    ] {
        let terminal = TerminalOutcome {
            decision_sequence: DecisionSequence::FIRST,
            outcome,
        };
        let receipt = append_report(
            &parsed,
            "incarnation",
            *principal,
            None,
            command.anchor.as_ref(),
            tx,
            &terminal,
            None,
        );
        assert!(receipt.contains("\"action\":\"append-comment\""));
        assert!(receipt.contains("\"expected_version\":null,\"comment_version\":null"));
        assert!(receipt.contains(&tx.to_string()));
        assert!(receipt.contains("\"historical_outcome\":true"));
        assert!(receipt.contains("\"refs_changed\":false"));
        assert!(receipt.contains(SOURCE_COMMENT_PROFILE));
        assert!(!receipt.contains("private-key"));
        let exact = append_report(
            &parsed,
            "incarnation",
            *principal,
            Some(ExpectedVersion::NewStream),
            None,
            tx,
            &terminal,
            None,
        );
        assert!(exact.contains("\"action\":\"comment\""));
        assert!(exact.contains("\"expected_version\":\"0\""));
        assert!(!exact.contains("comment_version"));
    }
}
