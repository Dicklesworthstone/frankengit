use super::options::{ReadOptions, head_token, parse, parse_head};
use super::*;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueEdit, apply_event};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, GitHashAlgorithm, PrincipalId, RefusalCode,
    RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCommitId,
};
use std::sync::atomic::{AtomicU64, Ordering};
fn input(action: &str) -> Vec<String> {
    let mut args = vec![
        action.into(),
        "unopened-node".into(),
        "11".repeat(16),
        "22".repeat(16),
    ];
    if action != "list" {
        args.push("7".into());
    }
    args.push("--trusted-local".into());
    if !matches!(action, "list" | "show") {
        args.extend([
            "--principal".into(),
            "33".repeat(16),
            "--idempotency-key".into(),
            "private-issue-key".into(),
            "--expected-version".into(),
            if action == "open" {
                "0".into()
            } else {
                "1".into()
            },
        ]);
    }
    match action {
        "open" => args
            .extend(["--title", "A precise issue", "--body", "line\r\né 🦀\n"].map(str::to_owned)),
        "edit" => args.extend(["--title", "Changed title"].map(str::to_owned)),
        "comment" => args.extend(["--body", "Exact comment\n"].map(str::to_owned)),
        _ => {}
    }
    args
}
fn replace(args: &mut [String], key: &str, value: &str) {
    let at = args.iter().position(|arg| arg == key).unwrap();
    args[at + 1] = value.into();
}
fn mutation(options: &Options) -> &Mutation {
    let Operation::Mutate(mutation) = &options.operation else {
        panic!("mutation fixture");
    };
    mutation
}
fn read(options: &Options) -> &ReadOptions {
    let Operation::Read(read) = &options.operation else {
        panic!("read fixture");
    };
    read
}
fn head(seed: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[seed; 32]).unwrap(),
    )
}
fn terminal(committed: bool) -> (TxId, TerminalOutcome) {
    let algorithm = DigestAlgorithmId::try_new(1).unwrap();
    let digest = |seed| DigestBytes::try_new(&[seed; 32]).unwrap();
    let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest(1));
    let outcome = if committed {
        DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest(2),
            ),
        }
    } else {
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceStale,
            refusal_record_id: RefusalRecordId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest(3),
            ),
        }
    };
    (
        tx,
        TerminalOutcome {
            decision_sequence: DecisionSequence::FIRST,
            outcome,
        },
    )
}

#[test]
fn every_mutation_retains_its_exact_action_and_both_repository_hash_formats() {
    for format in ["sha1", "sha256"] {
        for action in ["open", "edit", "close", "reopen", "comment"] {
            let mut args = input(action);
            args.extend(["--object-format", format].map(str::to_owned));
            let parsed = parse(&args).unwrap();
            assert_eq!(
                parsed.format,
                if format == "sha1" {
                    GitHashAlgorithm::Sha1
                } else {
                    GitHashAlgorithm::Sha256
                }
            );
            let value = mutation(&parsed);
            assert_eq!(value.command.action.name(), action);
            assert_eq!(value.key, b"private-issue-key");
            value.command.proposed_event(value.principal).unwrap();
            if let IssueAction::Open { body, .. } = &value.command.action {
                assert_eq!(body, "line\r\né 🦀\n");
            }
            if let IssueAction::Edit(edit) = &value.command.action {
                assert_eq!(edit.body, None);
                assert_eq!(edit.labels, None);
            }
        }
    }
}
#[test]
fn label_order_is_canonical_but_omitted_and_cleared_edit_fields_remain_distinct() {
    let mut args = input("open");
    args.extend(["--label", "zeta", "--label", "alpha"].map(str::to_owned));
    let mut ordered = input("open");
    ordered.extend(["--label", "alpha", "--label", "zeta"].map(str::to_owned));
    assert_eq!(
        mutation(&parse(&args).unwrap()).command,
        mutation(&parse(&ordered).unwrap()).command
    );
    args.extend(["--label", "alpha"].map(str::to_owned));
    assert!(parse(&args).is_err());
    let mut args = input("edit");
    args.extend(["--body", "", "--clear-labels"].map(str::to_owned));
    let parsed = parse(&args).unwrap();
    let IssueAction::Edit(edit) = &mutation(&parsed).command.action else {
        panic!("edit");
    };
    assert_eq!(edit.body.as_deref(), Some(""));
    assert_eq!(edit.labels, Some(Vec::new()));
    args.extend(["--label", "alpha"].map(str::to_owned));
    assert!(parse(&args).is_err());
}
#[test]
fn trust_required_fields_and_inapplicable_or_duplicate_arguments_refuse() {
    for action in ["open", "edit", "close", "reopen", "comment", "list", "show"] {
        let mut args = input(action);
        args.retain(|arg| arg != "--trusted-local");
        assert!(parse(&args).is_err());
    }
    for flag in [
        "--principal",
        "--idempotency-key",
        "--expected-version",
        "--title",
        "--body",
    ] {
        let mut args = input("open");
        let i = args.iter().position(|arg| arg == flag).unwrap();
        args.drain(i..i + 2);
        assert!(parse(&args).is_err(), "missing {flag}");
    }
    for action in ["open", "edit", "close", "reopen", "comment", "list", "show"] {
        let mut args = input(action);
        args.extend(["--force", "true"].map(str::to_owned));
        assert!(parse(&args).is_err());
        let mut args = input(action);
        args.push("--trusted-local".into());
        assert!(parse(&args).is_err());
    }
    for action in ["close", "reopen", "list", "show"] {
        let mut args = input(action);
        args.extend(["--body", "unused"].map(str::to_owned));
        assert!(parse(&args).is_err());
    }
    let mut args = input("edit");
    let at = args.iter().position(|arg| arg == "--title").unwrap();
    args.drain(at..at + 2);
    assert!(parse(&args).is_err());
}
#[test]
fn versions_text_bounds_and_file_shape_are_validated_before_node_io() {
    for version in [
        "0",
        "01",
        "-1",
        "18446744073709551615",
        "18446744073709551616",
    ] {
        let mut args = input("close");
        replace(&mut args, "--expected-version", version);
        assert!(parse(&args).is_err());
    }
    let mut args = input("open");
    replace(&mut args, "--body", &"x".repeat(MAX_BODY_BYTES));
    assert!(parse(&args).is_ok());
    replace(&mut args, "--body", &"x".repeat(MAX_BODY_BYTES + 1));
    assert!(parse(&args).is_err());
    for value in ["", "\n", "bad\0body"] {
        let mut args = input("comment");
        replace(&mut args, "--body", value);
        assert!(parse(&args).is_err());
    }
    let mut args = input("comment");
    let at = args.iter().position(|arg| arg == "--body").unwrap();
    args[at] = "--body-file".into();
    args[at + 1] = "/does-not-exist/content".into();
    assert!(parse(&args).is_ok(), "the parser does not read files");
    args.extend(["--body", "conflict"].map(str::to_owned));
    assert!(parse(&args).is_err());
}
#[test]
fn head_tokens_and_both_read_cursors_require_snapshot_pins() {
    assert_eq!(parse_head(&head_token(head(1))).unwrap(), head(1));
    for token in ["alg:01:ab", "alg:1:", "alg:1:AA", "alg:1:0", "wrong"] {
        assert!(parse_head(token).is_err());
    }
    for (verb, cursor) in [("list", "--after"), ("show", "--after-version")] {
        let mut args = input(verb);
        args.extend([cursor, "1"].map(str::to_owned));
        assert!(parse(&args).is_err());
        args.extend(["--expected-head".into(), head_token(head(1))]);
        let parsed = parse(&args).unwrap();
        assert_eq!(read(&parsed).after, 1);
        assert_eq!(read(&parsed).expected_head, Some(head(1)));
    }
}
#[test]
fn read_responses_refuse_moved_heads_wrong_numbers_gaps_and_false_cursors() {
    let parsed = parse(&input("open")).unwrap();
    let change = mutation(&parsed);
    let event = change.command.proposed_event(change.principal).unwrap();
    let state = apply_event(None, &event).unwrap();
    let listed = parse(&input("list")).unwrap();
    let shown = parse(&input("show")).unwrap();
    assert!(
        output::list(
            &listed,
            read(&listed),
            head(1),
            &[state.clone(), state.clone()],
            None
        )
        .is_err()
    );
    assert!(output::list(&listed, read(&listed), head(1), &[state.clone()], Some(7)).is_err());
    assert!(output::history(&shown, read(&shown), head(1), Some(&state), &[], None).is_err());
    assert!(
        output::history(
            &shown,
            read(&shown),
            head(1),
            Some(&state),
            &[event.clone()],
            Some(1)
        )
        .is_err()
    );
    let mut wrong = state.clone();
    wrong.number = IssueNumber::try_new(8).unwrap();
    assert!(
        output::history(
            &shown,
            read(&shown),
            head(1),
            Some(&wrong),
            &[event.clone()],
            None
        )
        .is_err()
    );
    let (missing, exit) = output::history(&shown, read(&shown), head(1), None, &[], None).unwrap();
    assert_eq!(exit, 4);
    assert!(missing.contains("\"found\":false"));
    let mut args = input("show");
    args.extend(["--expected-head".into(), head_token(head(1))]);
    let pinned = parse(&args).unwrap();
    assert!(
        output::history(
            &pinned,
            read(&pinned),
            head(2),
            Some(&state),
            &[event],
            None
        )
        .is_err()
    );
}
#[test]
fn history_keeps_comment_bytes_and_does_not_invent_unchanged_edit_fields() {
    let parsed = parse(&input("open")).unwrap();
    let opened = mutation(&parsed);
    let first = opened.command.proposed_event(opened.principal).unwrap();
    let initial = apply_event(None, &first).unwrap();
    let comment = "quote\"\r\n\u{1b}\u{202e} é";
    let command = IssueCommand {
        number: opened.command.number,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: IssueAction::Comment {
            body: comment.into(),
        },
    };
    let second = command
        .proposed_event(PrincipalId::from_bytes([0x44; 16]))
        .unwrap();
    let state = apply_event(Some(&initial), &second).unwrap();
    let shown = parse(&input("show")).unwrap();
    let (json, exit) = output::history(
        &shown,
        read(&shown),
        head(1),
        Some(&state),
        &[first, second],
        None,
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert!(!json.chars().any(char::is_control));
    assert!(json.contains("\\u001b") && json.contains("\\u202e"));
    assert_eq!(state.comments, 1);
    assert_eq!(state.body, initial.body);
    let edit = IssueAction::Edit(IssueEdit {
        title: Some("next".into()),
        ..IssueEdit::default()
    });
    assert_eq!(edit.name(), "edit");
}
#[test]
fn terminal_output_and_shutdown_errors_preserve_committed_and_refused_identities() {
    struct Broken {
        write: bool,
    }
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.write {
                Err(std::io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    let parsed = parse(&input("open")).unwrap();
    for committed in [true, false] {
        let (tx, terminal) = terminal(committed);
        let json = output::mutation(&parsed, mutation(&parsed), tx, &terminal, None);
        assert!(!json.contains("private-issue-key"));
        assert!(json.contains("\"refs_changed\":false"));
        for write in [true, false] {
            let error = finish_mutation(
                &mut Broken { write },
                &parsed,
                mutation(&parsed),
                tx,
                &terminal,
                Some("shutdown-marker"),
            )
            .unwrap_err();
            assert!(error.contains(&tx.to_string()) && error.contains("shutdown-marker"));
            assert!(error.contains(if committed {
                "is committed"
            } else {
                "canonical refusal"
            }));
        }
    }
}
#[test]
fn body_files_preserve_utf8_and_empty_content_and_refuse_overflow_or_symlinks() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "fg-issue-body-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let body = root.join("body");
    for bytes in [b"".as_slice(), "line\r\né 🦀".as_bytes()] {
        fs::write(&body, bytes).unwrap();
        assert_eq!(read_body_file(&body).unwrap().as_bytes(), bytes);
    }
    fs::write(&body, vec![b'x'; MAX_BODY_BYTES]).unwrap();
    assert_eq!(read_body_file(&body).unwrap().len(), MAX_BODY_BYTES);
    fs::write(&body, vec![b'x'; MAX_BODY_BYTES + 1]).unwrap();
    assert!(read_body_file(&body).is_err());
    fs::write(&body, [0xff]).unwrap();
    assert!(read_body_file(&body).is_err());
    fs::write(&body, [0]).unwrap();
    assert!(read_body_file(&body).is_err());
    #[cfg(unix)]
    {
        let link = root.join("link");
        std::os::unix::fs::symlink(&body, &link).unwrap();
        assert!(read_body_file(&link).is_err());
    }
    assert!(read_body_file(&root).is_err());
    fs::remove_dir_all(root).unwrap();
}
