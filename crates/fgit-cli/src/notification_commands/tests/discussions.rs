//! The CLI drives real reopened canonical stores; same-number domains stay separate.
use super::*;
use fgit_forge::DiscussionNumber;
use fgit_forge::event::discussion::{DiscussionAction, DiscussionCommand};
use fgit_forge::event::notification::{NotificationTarget, NotificationTargetKind};

#[test]
fn every_inbox_operation_accepts_a_strict_kind_with_issue_as_the_default() {
    for operation in [
        "list",
        "show",
        "subscribe",
        "mute",
        "automatic",
        "read",
        "unread",
    ] {
        let mut args = arguments(operation, &[]);
        if !matches!(operation, "list" | "show") {
            args.extend([
                "--expected-version".into(),
                "0".into(),
                "--idempotency-key".into(),
                "original".into(),
            ]);
        }
        if operation == "read" {
            args.extend(["--read-through".into(), "1".into()]);
        }
        assert_eq!(
            options::parse(&args).unwrap().kind,
            NotificationTargetKind::Issue
        );
        let mut discussion = args.clone();
        discussion.extend(["--kind".into(), "discussion".into()]);
        let parsed = options::parse(&discussion).unwrap();
        assert_eq!(parsed.kind, NotificationTargetKind::Discussion);
        let target = match parsed.operation {
            Operation::Read(read) => read.target,
            Operation::Mutate(mutation) => Some(mutation.command.target),
        };
        assert_eq!(
            target,
            (operation != "list").then_some(NotificationTarget::Discussion(
                DiscussionNumber::try_new(7).unwrap()
            ))
        );
        for bad in ["", "Discussion", "pull", "issue,discussion"] {
            let mut invalid = args.clone();
            invalid.extend(["--kind".into(), bad.into()]);
            assert!(options::parse(&invalid).is_err());
        }
        discussion.extend(["--kind".into(), "issue".into()]);
        assert!(options::parse(&discussion).is_err());
    }
}

fn publish(fixture: &Fixture, before: u64, key: &str, action: DiscussionAction) {
    let mut node = OneNode::open_existing(Fixture::config_at(&fixture.root)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let command = DiscussionCommand {
        number: DiscussionNumber::try_new(7).unwrap(),
        expected_version: if before == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(before).unwrap())
        },
        action,
    };
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x44; 16]),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    );
    let request = fgit_cli::command_request_context(&node);
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_discussion_durable_in(
            &request,
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
    node.shutdown().unwrap();
}

#[test]
fn discussion_preferences_survive_lost_output_and_reopen_without_touching_same_number_issue() {
    let fixture = Fixture::new();
    publish(
        &fixture,
        0,
        "discussion-open",
        DiscussionAction::Open {
            title: "Independent discussion é".into(),
            body: "Literal discussion bytes".into(),
        },
    );
    let discussion = &["--kind", "discussion"];
    let first = fixture.call("show", discussion);
    assert_eq!(
        first.object().unwrap()["type"].text(),
        Some("discussion_notification_thread")
    );
    assert_eq!(
        first.object().unwrap()["target_kind"].text(),
        Some("discussion")
    );
    let row = rows(&first)[0].object().unwrap();
    assert_eq!(row["discussion_version"].text(), Some("1"));
    assert!(!row.contains_key("issue_version"));
    assert_eq!(row["preference_version"], Value::Null);

    let issue_receipt = fixture.call(
        "subscribe",
        &[
            "--expected-version",
            "0",
            "--idempotency-key",
            "issue-subscribe",
        ],
    );
    assert_eq!(
        issue_receipt.object().unwrap()["type"].text(),
        Some("notification_publication")
    );
    assert!(!issue_receipt.object().unwrap().contains_key("target_kind"));
    let subscribe = [
        "--kind",
        "discussion",
        "--expected-version",
        "0",
        "--idempotency-key",
        "discussion-subscribe",
    ];
    let lost = run_to(&fixture.args("subscribe", &subscribe), &mut BrokenOutput).unwrap_err();
    assert!(lost.contains("committed"), "{lost}");
    let receipt = fixture.call("subscribe", &subscribe);
    assert_eq!(
        receipt.object().unwrap()["type"].text(),
        Some("discussion_notification_publication")
    );
    assert_eq!(
        receipt.object().unwrap()["target_kind"].text(),
        Some("discussion")
    );
    assert_eq!(receipt, fixture.call("subscribe", &subscribe));

    let crossing = run_to(
        &fixture.args(
            "subscribe",
            &[
                "--kind",
                "issue",
                "--expected-version",
                "0",
                "--idempotency-key",
                "discussion-subscribe",
            ],
        ),
        &mut Vec::new(),
    );
    assert!(
        !matches!(crossing, Ok(0)),
        "a retry key cannot switch target domains"
    );
    fixture.call(
        "read",
        &[
            "--kind",
            "discussion",
            "--expected-version",
            "1",
            "--idempotency-key",
            "discussion-read",
            "--read-through",
            "1",
        ],
    );
    assert_eq!(
        rows(&fixture.call("show", discussion))[0].object().unwrap()["unread"],
        Value::Bool(false)
    );
    let issue = fixture.call("show", &[]);
    assert_eq!(
        issue.object().unwrap()["type"].text(),
        Some("notification_thread")
    );
    assert!(!issue.object().unwrap().contains_key("target_kind"));
    let issue_row = rows(&issue)[0].object().unwrap();
    assert_eq!(issue_row["preference_version"].text(), Some("1"));
    assert_eq!(issue_row["issue_version"].text(), Some("1"));
    assert!(!issue_row.contains_key("discussion_version"));
    assert_eq!(issue_row["read_through"], Value::Null);
    assert_eq!(issue_row["unread"], Value::Bool(true));

    publish(
        &fixture,
        1,
        "discussion-reply",
        DiscussionAction::Comment {
            body: "Later activity must remain unread".into(),
        },
    );
    let unread = fixture.call("list", &["--kind", "discussion", "--unread-only"]);
    assert_eq!(
        unread.object().unwrap()["type"].text(),
        Some("discussion_notification_inbox")
    );
    assert_eq!(
        unread.object().unwrap()["target_kind"].text(),
        Some("discussion")
    );
    assert_eq!(rows(&unread).len(), 1);
    let row = rows(&unread)[0].object().unwrap();
    assert_eq!(row["discussion_version"].text(), Some("2"));
    assert_eq!(row["read_through"].text(), Some("1"));
    assert_eq!(row["latest_other_version"].text(), Some("2"));
    let mut future = Vec::new();
    assert_eq!(
        run_to(
            &fixture.args(
                "read",
                &[
                    "--kind",
                    "discussion",
                    "--expected-version",
                    "2",
                    "--idempotency-key",
                    "future-discussion-read",
                    "--read-through",
                    "3",
                ]
            ),
            &mut future
        )
        .unwrap(),
        3
    );
    assert_eq!(
        json::parse(&future).unwrap().object().unwrap()["outcome"].text(),
        Some("refused")
    );

    fixture.call(
        "mute",
        &[
            "--kind",
            "discussion",
            "--expected-version",
            "2",
            "--idempotency-key",
            "discussion-mute",
        ],
    );
    assert!(rows(&fixture.call("list", discussion)).is_empty());
    let muted = fixture.call("list", &["--kind", "discussion", "--include-muted"]);
    assert_eq!(
        rows(&muted)[0].object().unwrap()["mode"].text(),
        Some("muted")
    );
    assert_eq!(
        rows(&muted)[0].object().unwrap()["read_through"].text(),
        Some("1")
    );
    assert_eq!(rows(&fixture.call("list", &[])).len(), 1);
    fixture.call(
        "automatic",
        &[
            "--kind",
            "discussion",
            "--expected-version",
            "3",
            "--idempotency-key",
            "discussion-automatic",
        ],
    );
    assert!(rows(&fixture.call("list", discussion)).is_empty());
    fixture.call(
        "unread",
        &[
            "--kind",
            "discussion",
            "--expected-version",
            "4",
            "--idempotency-key",
            "discussion-unread",
        ],
    );
    let final_state = fixture.call("show", discussion);
    let row = rows(&final_state)[0].object().unwrap();
    assert_eq!(row["mode"].text(), Some("participating"));
    assert_eq!(row["read_through"], Value::Null);
    assert_eq!(row["preference_version"].text(), Some("5"));
    assert_eq!(receipt, fixture.call("subscribe", &subscribe));
    assert_eq!(
        rows(&fixture.call("show", discussion))[0].object().unwrap()["preference_version"].text(),
        Some("5")
    );
}
