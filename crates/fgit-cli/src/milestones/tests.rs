use super::options::Options;
use super::*;
use fgit_admission::merge::native::milestones::MilestoneSummary;
use fgit_forge::event::milestone::{MilestoneAction, MilestoneEdit, apply_event};
use fgit_forge::{AggregateVersion, ExpectedVersion, MilestoneNumber};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, RepositoryAuthorityHeadId, RepositoryCommitId,
};

fn args(action: &str, extra: &[&str]) -> Vec<String> {
    let mut out = vec![
        action.to_owned(),
        "unopened-node".into(),
        "11".repeat(16),
        "22".repeat(16),
    ];
    if action != "list" {
        out.push("7".into());
    }
    out.push("--trusted-local".into());
    if !matches!(action, "list" | "show") {
        out.extend([
            "--principal".into(),
            "33".repeat(16),
            "--idempotency-key".into(),
            "stable-private-key".into(),
            "--expected-version".into(),
            if action == "open" { "0" } else { "1" }.into(),
        ]);
    }
    out.extend(extra.iter().map(|s| (*s).to_owned()));
    out
}

fn mutation(options: &Options) -> &options::Mutation {
    let Operation::Mutate(mutation) = &options.operation else {
        panic!("mutation")
    };
    mutation
}

fn head(seed: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[seed; 32]).unwrap(),
    )
}

#[test]
fn parses_complete_lifecycle_and_distinguishes_preserved_cleared_and_set_fields() {
    for format in ["sha1", "sha256"] {
        let open = options::parse(&args(
            "open",
            &[
                "--title",
                "Release 🦀",
                "--body",
                "\r\n<script>data</script>",
                "--due-at",
                "253402300799",
                "--object-format",
                format,
            ],
        ))
        .unwrap();
        assert_eq!(open.format.as_str(), format);
        assert_eq!(
            mutation(&open).command.expected_version,
            ExpectedVersion::NewStream
        );
        assert_eq!(
            mutation(&open).command.action,
            MilestoneAction::Open {
                title: "Release 🦀".into(),
                body: "\r\n<script>data</script>".into(),
                due_at: Some(253402300799),
            }
        );
        let edit = options::parse(&args("edit", &["--body", "", "--clear-due-at"])).unwrap();
        assert_eq!(
            mutation(&edit).command.action,
            MilestoneAction::Edit(MilestoneEdit {
                title: None,
                body: Some(String::new()),
                due_at: Some(None),
            })
        );
        let epoch = options::parse(&args("edit", &["--due-at", "0"])).unwrap();
        assert_eq!(
            mutation(&epoch).command.action,
            MilestoneAction::Edit(MilestoneEdit {
                title: None,
                body: None,
                due_at: Some(Some(0)),
            })
        );
        let title = options::parse(&args("edit", &["--title", "Renamed"])).unwrap();
        assert_eq!(
            mutation(&title).command.action,
            MilestoneAction::Edit(MilestoneEdit {
                title: Some("Renamed".into()),
                body: None,
                due_at: None,
            })
        );
        for action in ["close", "reopen"] {
            let parsed = options::parse(&args(action, &[])).unwrap();
            assert_eq!(mutation(&parsed).command.action.name(), action);
            assert_eq!(
                mutation(&parsed).command.expected_version,
                ExpectedVersion::Exactly(AggregateVersion::FIRST)
            );
        }
    }
}

#[test]
fn refuses_unknown_duplicate_unbounded_and_inapplicable_options_before_io() {
    for (action, fields) in [
        ("open", vec!["--title", "Release"]),
        ("open", vec!["--title", "", "--body", ""]),
        (
            "open",
            vec!["--title", "Release", "--body", "", "--clear-due-at"],
        ),
        (
            "open",
            vec![
                "--title",
                "Release",
                "--body",
                "",
                "--due-at",
                "253402300800",
            ],
        ),
        ("edit", vec![]),
        ("edit", vec!["--due-at", "01"]),
        ("edit", vec!["--due-at", "-1"]),
        ("edit", vec!["--due-at", "18446744073709551616"]),
        ("edit", vec!["--clear-due-at", "--due-at", "1"]),
        ("edit", vec!["--clear-due-at", "--clear-due-at"]),
        ("edit", vec!["--body", "a", "--body-file", "file"]),
        ("close", vec!["--title", "new"]),
        ("close", vec!["--grant", "admin"]),
        ("show", vec!["--after-version", "1"]),
        ("list", vec!["--after", "1"]),
        ("list", vec!["--limit", "0"]),
        ("list", vec!["--limit", "101"]),
        ("list", vec!["--limit", "1", "--limit", "2"]),
        ("show", vec!["--after", "0"]),
    ] {
        assert!(
            options::parse(&args(action, &fields)).is_err(),
            "{action}: {fields:?}"
        );
    }
    let mut untrusted = args("list", &[]);
    untrusted.pop();
    assert!(options::parse(&untrusted).is_err());
    for (action, version) in [
        ("open", "1"),
        ("close", "0"),
        ("close", "18446744073709551615"),
    ] {
        let mut input = args(
            action,
            if action == "open" {
                &["--title", "Release", "--body", ""]
            } else {
                &[]
            },
        );
        let at = input
            .iter()
            .position(|s| s == "--expected-version")
            .unwrap();
        input[at + 1] = version.into();
        assert!(options::parse(&input).is_err());
    }
}

#[test]
fn read_output_binds_progress_and_contiguous_history_to_the_exact_snapshot() {
    let options = options::parse(&args(
        "open",
        &["--title", "Release", "--body", "<script>text</script>"],
    ))
    .unwrap();
    let m = mutation(&options);
    let event = m.command.proposed_event(m.principal).unwrap();
    let summary = MilestoneSummary {
        milestone: apply_event(None, &event).unwrap(),
        open_issues: 3,
        closed_issues: 2,
    };
    let read = options::ReadOptions {
        number: Some(MilestoneNumber::try_new(7).unwrap()),
        after: 0,
        limit: 50,
        expected_head: Some(head(5)),
    };
    let (json, exit) = output::history(
        &options,
        &read,
        head(5),
        Some(&summary),
        std::slice::from_ref(&event),
        None,
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert!(json.contains("\"open_issues\":3,\"closed_issues\":2"));
    assert!(json.contains("\"due_at\":null"));
    assert!(json.contains("\"version\":1"));
    assert!(
        output::history(
            &options,
            &read,
            head(6),
            Some(&summary),
            std::slice::from_ref(&event),
            None
        )
        .is_err()
    );
    assert!(output::history(&options, &read, head(5), Some(&summary), &[], None).is_err());
    assert!(output::history(&options, &read, head(5), None, &[event], None).is_err());
    let (missing, exit) = output::history(&options, &read, head(5), None, &[], None).unwrap();
    assert_eq!(exit, 4);
    assert!(missing.contains("\"found\":false,\"milestone\":null"));
    let list = options::ReadOptions {
        number: None,
        after: 0,
        limit: 1,
        expected_head: Some(head(5)),
    };
    assert!(
        output::list(
            &options,
            &list,
            head(5),
            std::slice::from_ref(&summary),
            Some(7)
        )
        .is_ok()
    );
    assert!(output::list(&options, &list, head(5), &[summary], Some(8)).is_err());
}

#[test]
fn failed_receipt_delivery_retains_the_original_canonical_outcome() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed consumer"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let algorithm = DigestAlgorithmId::try_new(1).unwrap();
    let tx = TxId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[1; 32]).unwrap(),
    );
    let terminal = TerminalOutcome {
        decision_sequence: DecisionSequence::FIRST,
        outcome: DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[2; 32]).unwrap(),
            ),
        },
    };
    let error = finish_receipt(&mut Broken, "{}", tx, &terminal, None).unwrap_err();
    assert!(
        error.contains(&tx.to_string())
            && error.contains("is committed")
            && error.contains("receipt output failed")
    );
    let mut out = Vec::new();
    assert!(
        finish_receipt(&mut out, "{}", tx, &terminal, Some("cleanup failure"))
            .unwrap_err()
            .contains("is committed")
    );
    assert_eq!(out, b"{}\n");
}
