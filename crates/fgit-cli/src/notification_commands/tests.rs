use super::*;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::notification::{NotificationAction, NotificationMode};
use fgit_forge::{AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_schema::json::{self, Value};
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

fn arguments(action: &str, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        action.into(),
        "unopened-node".into(),
        "11".repeat(16),
        "22".repeat(16),
    ];
    if action != "list" {
        args.push("7".into());
    }
    args.extend([
        "--trusted-local".into(),
        "--principal".into(),
        "33".repeat(16),
    ]);
    args.extend(extra.iter().map(|value| (*value).to_owned()));
    args
}
#[test]
fn self_identity_exact_versions_and_explicit_read_prefix_are_required_before_io() {
    for action in ["subscribe", "mute", "automatic", "read", "unread"] {
        let mut args = arguments(
            action,
            &["--expected-version", "0", "--idempotency-key", "same-key"],
        );
        if action == "read" {
            args.extend(["--read-through".into(), "1".into()]);
        }
        let Operation::Mutate(mutation) = options::parse(&args).unwrap().operation else {
            panic!()
        };
        assert_eq!(
            mutation.command.expected_version,
            ExpectedVersion::NewStream
        );
        assert_eq!(options::action_name(mutation.command.action), action);
        assert_eq!(mutation.key, b"same-key");
        for flag in ["--principal", "--expected-version", "--idempotency-key"] {
            let mut missing = args.clone();
            let index = missing.iter().position(|value| value == flag).unwrap();
            missing.drain(index..index + 2);
            assert!(options::parse(&missing).is_err());
        }
        let mut untrusted = args.clone();
        untrusted.retain(|value| value != "--trusted-local");
        assert!(options::parse(&untrusted).is_err());
        for extra in [
            vec!["--recipient", "44"],
            vec!["--actor", "44"],
            vec!["--include-muted"],
            vec!["--expected-version", "2"],
        ] {
            let mut invalid = args.clone();
            invalid.extend(extra.into_iter().map(str::to_owned));
            assert!(options::parse(&invalid).is_err());
        }
    }
    for prefix in ["0", "01", "-1", "1.0", "18446744073709551616"] {
        assert!(
            options::parse(&arguments(
                "read",
                &[
                    "--expected-version",
                    "0",
                    "--idempotency-key",
                    "read",
                    "--read-through",
                    prefix
                ]
            ))
            .is_err()
        );
    }
    assert!(
        options::parse(&arguments(
            "read",
            &["--expected-version", "0", "--idempotency-key", "read"]
        ))
        .is_err()
    );
    assert!(
        options::parse(&arguments(
            "unread",
            &[
                "--expected-version",
                "1",
                "--idempotency-key",
                "read",
                "--read-through",
                "1"
            ]
        ))
        .is_err()
    );
    let Operation::Mutate(unread) = options::parse(&arguments(
        "unread",
        &["--expected-version", "1", "--idempotency-key", "read"],
    ))
    .unwrap()
    .operation
    else {
        panic!()
    };
    assert_eq!(
        unread.command.action,
        NotificationAction::SetReadThrough(None)
    );
    let Operation::Mutate(automatic) = options::parse(&arguments(
        "automatic",
        &["--expected-version", "1", "--idempotency-key", "auto"],
    ))
    .unwrap()
    .operation
    else {
        panic!()
    };
    assert_eq!(
        automatic.command.action,
        NotificationAction::SetMode(NotificationMode::Participating)
    );
}
#[test]
fn continuation_binds_the_exact_snapshot_and_rejects_inapplicable_flags() {
    let pin = format!("alg:1:{}", "44".repeat(32));
    let Operation::Read(read) = options::parse(&arguments(
        "list",
        &[
            "--after",
            "7",
            "--expected-head",
            &pin,
            "--limit",
            "1",
            "--unread-only",
            "--include-muted",
        ],
    ))
    .unwrap()
    .operation
    else {
        panic!()
    };
    assert_eq!((read.after, read.limit, read.number), (7, 1, None));
    assert!(read.expected_head.is_some() && read.unread_only && read.include_muted);
    for extra in [
        vec!["--after", "7"],
        vec!["--limit", "0"],
        vec!["--limit", "101"],
        vec!["--expected-version", "0"],
        vec!["--principal", "44"],
    ] {
        assert!(options::parse(&arguments("list", &extra)).is_err());
    }
    assert!(
        options::parse(&arguments(
            "show",
            &["--after", "7", "--expected-head", &pin]
        ))
        .is_err()
    );
    assert!(options::parse(&arguments("show", &["--unread-only"])).is_err());
}
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    incarnation: RepositoryIncarnationId,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-inbox-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let (mut node, _) = OneNode::init(Self::config_at(&root)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let incarnation = node.repository_incarnation_id();
        Self::issue(
            &node,
            0,
            "seed",
            IssueAction::Open {
                title: "Literal \"é\" <script>".into(),
                body: "Issue text is data".into(),
                labels: vec![],
            },
        );
        node.shutdown().unwrap();
        Self { root, incarnation }
    }
    fn config_at(root: &std::path::Path) -> NodeConfig {
        NodeConfig::new(
            root.join("node"),
            TenantId::from_bytes([0x11; 16]),
            RepositoryId::from_bytes([0x22; 16]),
        )
        .with_worker_threads(2)
    }
    fn issue(node: &OneNode, before: u64, key: &str, action: IssueAction) {
        let command = IssueCommand {
            number: IssueNumber::try_new(7).unwrap(),
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
        let request = fgit_cli::command_request_context(node);
        let (_, outcome) = node
            .runtime()
            .block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default()))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
    }
    fn args(&self, action: &str, extra: &[&str]) -> Vec<String> {
        let mut args = arguments(action, extra);
        args[1] = self.root.join("node").to_str().unwrap().to_owned();
        args.extend([
            "--expected-incarnation".into(),
            self.incarnation.to_string(),
        ]);
        args
    }
    fn call(&self, action: &str, extra: &[&str]) -> Value {
        let mut out = Vec::new();
        assert_eq!(run_to(&self.args(action, extra), &mut out).unwrap(), 0);
        json::parse(&out).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
fn rows(reply: &Value) -> &[Value] {
    let Value::Array(rows) = &reply.object().unwrap()["threads"] else {
        panic!("missing threads")
    };
    rows
}
struct BrokenOutput;
impl Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("lost output"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn native_cli_preserves_read_prefix_and_recovers_commit_after_lost_output() {
    let fixture = Fixture::new();
    assert!(rows(&fixture.call("list", &[])).is_empty());
    assert_eq!(
        rows(&fixture.call("show", &[]))[0].object().unwrap()["preference_version"],
        Value::Null
    );
    let subscribe = fixture.args(
        "subscribe",
        &[
            "--expected-version",
            "0",
            "--idempotency-key",
            "subscribe-once",
        ],
    );
    let lost = run_to(&subscribe, &mut BrokenOutput).unwrap_err();
    assert!(lost.contains("committed"), "{lost}");
    let original = fixture.call(
        "subscribe",
        &[
            "--expected-version",
            "0",
            "--idempotency-key",
            "subscribe-once",
        ],
    );
    assert_eq!(
        original.object().unwrap()["outcome"].text(),
        Some("committed")
    );
    assert_eq!(
        original,
        fixture.call(
            "subscribe",
            &[
                "--expected-version",
                "0",
                "--idempotency-key",
                "subscribe-once"
            ]
        )
    );
    let subscribed = fixture.call("show", &[]);
    assert_eq!(
        rows(&subscribed)[0].object().unwrap()["preference_version"].text(),
        Some("1")
    );
    assert_eq!(
        rows(&subscribed)[0].object().unwrap()["unread"],
        Value::Bool(true)
    );
    fixture.call(
        "read",
        &[
            "--expected-version",
            "1",
            "--idempotency-key",
            "read-prefix",
            "--read-through",
            "1",
        ],
    );
    assert_eq!(
        rows(&fixture.call("show", &[]))[0].object().unwrap()["unread"],
        Value::Bool(false)
    );
    let mut node = OneNode::open_existing(Fixture::config_at(&fixture.root)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    Fixture::issue(
        &node,
        1,
        "later-activity",
        IssueAction::Comment {
            body: "Another principal replied".into(),
        },
    );
    node.shutdown().unwrap();
    let later = fixture.call("list", &["--unread-only"]);
    assert_eq!(rows(&later).len(), 1);
    assert_eq!(
        rows(&later)[0].object().unwrap()["read_through"].text(),
        Some("1")
    );
    assert_eq!(
        rows(&later)[0].object().unwrap()["latest_other_version"].text(),
        Some("2")
    );
    fixture.call(
        "mute",
        &["--expected-version", "2", "--idempotency-key", "mute"],
    );
    assert!(rows(&fixture.call("list", &[])).is_empty());
    let muted = fixture.call("list", &["--include-muted"]);
    assert_eq!(
        rows(&muted)[0].object().unwrap()["mode"].text(),
        Some("muted")
    );
    assert_eq!(
        rows(&muted)[0].object().unwrap()["read_through"].text(),
        Some("1")
    );
    fixture.call(
        "automatic",
        &["--expected-version", "3", "--idempotency-key", "automatic"],
    );
    assert!(rows(&fixture.call("list", &[])).is_empty());
    fixture.call(
        "unread",
        &["--expected-version", "4", "--idempotency-key", "unread"],
    );
    let final_state = fixture.call("show", &[]);
    assert_eq!(
        rows(&final_state)[0].object().unwrap()["read_through"],
        Value::Null
    );
    assert_eq!(
        rows(&final_state)[0].object().unwrap()["mode"].text(),
        Some("participating")
    );
}
