use super::options::Options;
use super::*;
use fgit_forge::event::discussion::{
    DiscussionAction, DiscussionCommand, DiscussionEdit, apply_event,
};
use fgit_forge::{AggregateVersion, DiscussionNumber, ExpectedVersion};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{CANONICAL_CODEC_VERSION, RepositoryAuthorityHeadId};

fn args(action: &str, extra: &[&str]) -> Vec<String> {
    let mut result = vec![
        action.into(),
        "unopened-node".into(),
        "11".repeat(16),
        "22".repeat(16),
    ];
    if action != "list" {
        result.push("7".into());
    }
    result.push("--trusted-local".into());
    if !matches!(action, "list" | "show") {
        result.extend([
            "--principal".into(),
            "33".repeat(16),
            "--idempotency-key".into(),
            "stable-private-key".into(),
        ]);
        if action != "append-comment" {
            result.extend([
                "--expected-version".into(),
                if action == "open" { "0" } else { "1" }.into(),
            ]);
        }
    }
    result.extend(extra.iter().map(|value| (*value).to_owned()));
    result
}
fn mutation(options: &Options) -> &options::Mutation {
    let Operation::Mutate(value) = &options.operation else {
        panic!("mutation");
    };
    value
}
fn exact(options: &Options) -> &DiscussionCommand {
    let MutationCommand::Exact(command) = &mutation(options).command else {
        panic!("exact-version mutation");
    };
    command
}
fn head(seed: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[seed; 32]).unwrap(),
    )
}

#[test]
fn parses_exact_discussion_lifecycle_and_preserves_description_bytes() {
    for format in ["sha1", "sha256"] {
        let opened = options::parse(&args(
            "open",
            &[
                "--title",
                "Design 🦀",
                "--body",
                "é\r\n<script>data</script>",
                "--object-format",
                format,
            ],
        ))
        .unwrap();
        assert_eq!(opened.format.as_str(), format);
        assert_eq!(exact(&opened).expected_version, ExpectedVersion::NewStream);
        assert_eq!(
            exact(&opened).action,
            DiscussionAction::Open {
                title: "Design 🦀".into(),
                body: "é\r\n<script>data</script>".into(),
            }
        );
        let edited = options::parse(&args("edit", &["--body", ""])).unwrap();
        assert_eq!(
            exact(&edited).action,
            DiscussionAction::Edit(DiscussionEdit {
                title: None,
                body: Some(String::new())
            })
        );
        let renamed = options::parse(&args("edit", &["--title", "Renamed"])).unwrap();
        assert_eq!(
            exact(&renamed).action,
            DiscussionAction::Edit(DiscussionEdit {
                title: Some("Renamed".into()),
                body: None
            })
        );
        let comment = options::parse(&args("comment", &["--body", "Exact\r\nreply"])).unwrap();
        assert_eq!(
            exact(&comment).action,
            DiscussionAction::Comment {
                body: "Exact\r\nreply".into()
            }
        );
        for action in ["close", "reopen", "lock", "unlock"] {
            let parsed = options::parse(&args(action, &[])).unwrap();
            assert_eq!(exact(&parsed).action.name(), action);
            assert_eq!(
                exact(&parsed).expected_version,
                ExpectedVersion::Exactly(AggregateVersion::FIRST)
            );
        }
    }
}

#[test]
fn append_comments_bind_exact_text_without_accepting_a_predecessor() {
    for format in ["sha1", "sha256"] {
        let parsed = options::parse(&args(
            "append-comment",
            &[
                "--body",
                "Independent é\r\nreply",
                "--object-format",
                format,
            ],
        ))
        .unwrap();
        let command = &mutation(&parsed).command;
        let MutationCommand::Append(intent) = command else {
            panic!("explicit append intent required");
        };
        assert_eq!(parsed.format.as_str(), format);
        assert_eq!(intent.number.get(), 7);
        assert_eq!(intent.body, "Independent é\r\nreply");
        assert_eq!(options::expected_version(command), None);
        assert_eq!(mutation(&parsed).key, b"stable-private-key");
    }
    for fields in [
        vec![],
        vec!["--body", "   "],
        vec!["--body", "reply", "--expected-version", "1"],
        vec!["--body", "reply", "--title", "rename"],
        vec!["--body", "reply", "--body-file", "unopened"],
    ] {
        assert!(options::parse(&args("append-comment", &fields)).is_err());
    }
    let mut parsed = options::parse(&args("append-comment", &["--body-file", "unopened"])).unwrap();
    let Operation::Mutate(mutation) = &mut parsed.operation else {
        panic!("append mutation");
    };
    assert!(mutation.body_file.is_some());
    *options::body_slot(&mut mutation.command).unwrap() = "File reply\r\n".into();
    mutation.command.validate(mutation.principal).unwrap();
    let MutationCommand::Append(intent) = &mutation.command else {
        panic!("append body custody");
    };
    assert_eq!(intent.body, "File reply\r\n");
}

#[test]
fn rejects_incomplete_versions_cross_family_fields_and_unsafe_continuations_before_io() {
    for (action, extra) in [
        ("open", vec!["--title", "Missing body"]),
        ("open", vec!["--title", "", "--body", ""]),
        ("edit", vec![]),
        ("comment", vec![]),
        ("comment", vec!["--body", ""]),
        ("comment", vec!["--body", "reply", "--title", "rename"]),
        ("edit", vec!["--label", "issue-only"]),
        ("edit", vec!["--due-at", "1"]),
        ("edit", vec!["--body", "body", "--body-file", "file"]),
        ("lock", vec!["--body", "ignored"]),
        ("unlock", vec!["--grant", "admin"]),
        ("show", vec!["--after-version", "1"]),
        ("list", vec!["--after", "1"]),
        ("list", vec!["--limit", "0"]),
        ("list", vec!["--limit", "101"]),
        ("list", vec!["--limit", "1", "--limit", "2"]),
        ("show", vec!["--after", "0"]),
    ] {
        assert!(
            options::parse(&args(action, &extra)).is_err(),
            "{action}: {extra:?}"
        );
    }
    let mut untrusted = args("list", &[]);
    untrusted.pop();
    assert!(options::parse(&untrusted).is_err());
    for (action, version) in [
        ("open", "1"),
        ("close", "0"),
        ("lock", "01"),
        ("close", "18446744073709551615"),
    ] {
        let mut input = args(
            action,
            if action == "open" {
                &["--title", "Title", "--body", ""]
            } else {
                &[]
            },
        );
        let at = input
            .iter()
            .position(|value| value == "--expected-version")
            .unwrap();
        input[at + 1] = version.into();
        assert!(options::parse(&input).is_err());
    }
    let file = options::parse(&args(
        "comment",
        &["--body-file", "not-opened-during-parse"],
    ))
    .unwrap();
    assert!(mutation(&file).body_file.is_some());
}

#[test]
fn read_output_requires_bound_snapshot_and_exact_contiguous_history() {
    let options = options::parse(&args(
        "open",
        &["--title", "Design", "--body", "<script>text</script>"],
    ))
    .unwrap();
    let m = mutation(&options);
    let event = exact(&options).proposed_event(m.principal).unwrap();
    let snapshot = apply_event(None, &event).unwrap();
    let read = options::ReadOptions {
        number: Some(DiscussionNumber::try_new(7).unwrap()),
        after: 0,
        limit: 50,
        expected_head: Some(head(5)),
    };
    let (json, exit) = output::history(
        &options,
        &read,
        head(5),
        Some(&snapshot),
        std::slice::from_ref(&event),
        None,
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert!(json.contains("\"scope\":\"repository_discussions\""));
    assert!(json.contains("\"comments\":0,\"locked\":false"));
    assert!(json.contains("\"version\":1"));
    assert!(
        output::history(
            &options,
            &read,
            head(6),
            Some(&snapshot),
            std::slice::from_ref(&event),
            None
        )
        .is_err()
    );
    assert!(output::history(&options, &read, head(5), Some(&snapshot), &[], None).is_err());
    assert!(output::history(&options, &read, head(5), None, &[event], None).is_err());
    let (missing, exit) = output::history(&options, &read, head(5), None, &[], None).unwrap();
    assert_eq!(exit, 4);
    assert!(missing.contains("\"found\":false,\"discussion\":null"));
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
            std::slice::from_ref(&snapshot),
            Some(7)
        )
        .is_ok()
    );
    assert!(output::list(&options, &list, head(5), &[snapshot], Some(8)).is_err());
}
