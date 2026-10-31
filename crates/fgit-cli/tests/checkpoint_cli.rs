#![forbid(unsafe_code)]
//! Fresh fg processes exercising persisted outcome checkpoints and admission.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_schema::json::{self, Value};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";
static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frankengit-checkpoint-cli-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 fixture path")
}

fn fg(args: &[&str], code: i32) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_fg"))
        .args(args)
        .output()
        .expect("run real fg process");
    assert_eq!(
        output.status.code(),
        Some(code),
        "args={args:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn value(output: Output) -> Value {
    let value = json::parse(&output.stdout).expect("complete JSON receipt");
    assert_eq!(field(&value, "node_closed"), &Value::Bool(true));
    value
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    &value.object().expect("JSON object")[key]
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).text().expect("JSON string")
}

fn count(value: &Value, key: &str) -> u64 {
    field(value, key).unsigned().expect("unsigned JSON number")
}

fn checkpoint(root: &Path, extra: &[&str], code: i32) -> Output {
    let mut args = vec![
        "checkpoint",
        "outcomes",
        text(root),
        TENANT,
        REPOSITORY,
        "--trusted-local",
    ];
    args.extend_from_slice(extra);
    fg(&args, code)
}

fn refused(output: Output) -> String {
    assert!(
        output.stdout.is_empty(),
        "refused checkpoint emitted success"
    );
    let error = json::parse(&output.stderr).expect("structured checkpoint refusal");
    assert_eq!(string(&error, "type"), "outcome_checkpoint_error");
    assert_eq!(field(&error, "complete"), &Value::Bool(false));
    string(&error, "error").to_owned()
}

fn read_issues(root: &Path, format: &str) -> Value {
    value(fg(
        &[
            "issue",
            "list",
            text(root),
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            format,
        ],
        0,
    ))
}

fn mutation(
    root: &Path,
    format: &str,
    verb: &str,
    key: &str,
    version: &str,
    fields: &[&str],
    code: i32,
) -> Value {
    let mut args = vec![
        "issue",
        verb,
        text(root),
        TENANT,
        REPOSITORY,
        "7",
        "--trusted-local",
        "--object-format",
        format,
        "--principal",
        PRINCIPAL,
        "--idempotency-key",
        key,
        "--expected-version",
        version,
    ];
    args.extend_from_slice(fields);
    value(fg(&args, code))
}

fn same_terminal(left: &Value, right: &Value) {
    for key in [
        "tx_id",
        "decision_sequence",
        "repository_commit_id",
        "refusal_record_id",
        "refusal_code",
        "outcome",
    ] {
        assert_eq!(field(left, key), field(right, key), "{key}");
    }
}

fn assert_checkpoint(receipt: &Value, decisions: u64, published: bool) {
    assert_eq!(string(receipt, "type"), "outcome_checkpoint");
    assert_eq!(field(receipt, "complete"), &Value::Bool(true));
    assert_eq!(field(receipt, "published"), &Value::Bool(published));
    assert_eq!(string(receipt, "backup_profile"), "DecisionHistoryOnly");
    assert_eq!(string(receipt, "scope"), "outcome_index_maintenance");
    assert_eq!(count(receipt, "decisions"), decisions);
    assert!(string(receipt, "source_head").starts_with("alg:"));
    assert!(string(receipt, "published_head").starts_with("alg:"));
    assert!(string(receipt, "checkpoint_root").starts_with("alg:"));
}

#[test]
fn help_and_invalid_arguments_do_not_initialize_storage() {
    let scratch = Scratch::new();
    let absent = scratch.0.join("absent");
    for args in [
        vec!["checkpoint", "--help"],
        vec!["checkpoint", "outcomes", "--help"],
    ] {
        let output = fg(&args, 0);
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.starts_with("usage: fg checkpoint outcomes"));
        assert!(help.contains("DecisionHistoryOnly"));
        assert!(help.contains("does not prove non-publication"));
    }
    refused(fg(
        &["checkpoint", "outcomes", text(&absent), TENANT, REPOSITORY],
        2,
    ));
    for extra in [
        vec!["--max-decisions", "0"],
        vec!["--max-decisions", "65537"],
        vec!["--max-bytes", "0"],
        vec!["--max-bytes", "16777217"],
        vec!["--expected-head", "unqualified"],
        vec!["--timeout-secs", "3601"],
        vec!["--trusted-local"],
        vec!["--max-bytes", "1", "--max-bytes", "2"],
        vec!["--prune", "true"],
    ] {
        refused(checkpoint(&absent, &extra, 2));
        assert!(
            !absent.exists(),
            "invalid arguments created repository state"
        );
    }
}

#[test]
fn empty_native_repositories_checkpoint_once_in_both_formats() {
    for format in ["sha1", "sha256"] {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        fg(&["init", text(&root), TENANT, REPOSITORY, format], 0);
        let first = value(checkpoint(&root, &[], 0));
        assert_checkpoint(&first, 0, true);
        assert_ne!(
            field(&first, "source_head"),
            field(&first, "published_head")
        );
        let again = value(checkpoint(
            &root,
            &["--expected-head", string(&first, "published_head")],
            0,
        ));
        assert_checkpoint(&again, 0, false);
        for key in [
            "published_head",
            "authority_generation",
            "checkpoint_root",
            "capsule_id",
        ] {
            assert_eq!(field(&first, key), field(&again, key), "{key}");
        }
        assert_eq!(
            field(&again, "source_head"),
            field(&again, "published_head")
        );
        assert!(
            refused(checkpoint(
                &root,
                &["--expected-head", string(&first, "source_head")],
                2,
            ))
            .contains("HeadMoved")
        );
    }
}

#[test]
fn checkpoint_preserves_terminal_retries_and_later_admission_in_both_formats() {
    for format in ["sha1", "sha256"] {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        fg(&["init", text(&root), TENANT, REPOSITORY, format], 0);
        let open_fields = [
            "--title",
            "Retained decisions",
            "--body",
            "Native checkpoint fixture",
        ];
        let opened = mutation(
            &root,
            format,
            "open",
            "checkpoint-open",
            "0",
            &open_fields,
            0,
        );
        let stale = mutation(&root, format, "close", "checkpoint-refused", "2", &[], 3);
        let before = read_issues(&root, format);
        let source = string(&before, "snapshot_token");

        assert!(refused(checkpoint(&root, &["--max-decisions", "1"], 2)).contains("LimitExceeded"));
        assert!(refused(checkpoint(&root, &["--max-bytes", "1"], 2)).contains("LimitExceeded"));
        let mut unknown = source.to_owned();
        let last = unknown.pop().unwrap();
        unknown.push(if last == '0' { '1' } else { '0' });
        assert!(
            refused(checkpoint(&root, &["--expected-head", &unknown], 2)).contains("HeadMoved")
        );
        refused(fg(
            &[
                "--timeout-secs",
                "0.000000001",
                "checkpoint",
                "outcomes",
                text(&root),
                TENANT,
                REPOSITORY,
                "--trusted-local",
                "--timeout-secs",
                "3600",
            ],
            2,
        ));
        assert_eq!(
            string(&read_issues(&root, format), "snapshot_token"),
            source
        );

        let first = value(checkpoint(&root, &["--expected-head", source], 0));
        assert_checkpoint(&first, 2, true);
        assert_eq!(string(&first, "source_head"), source);
        assert!(count(&first, "leaf_objects") > 0);
        assert!(count(&first, "leaf_bytes") > 0);
        let selected = string(&first, "published_head");
        assert_ne!(selected, source);
        let after = read_issues(&root, format);
        assert_eq!(string(&after, "snapshot_token"), selected);
        assert_eq!(field(&before, "issues"), field(&after, "issues"));

        let again = value(checkpoint(&root, &["--expected-head", selected], 0));
        assert_checkpoint(&again, 2, false);
        for key in [
            "published_head",
            "authority_generation",
            "checkpoint_root",
            "capsule_id",
        ] {
            assert_eq!(field(&first, key), field(&again, key), "{key}");
        }
        same_terminal(
            &opened,
            &mutation(
                &root,
                format,
                "open",
                "checkpoint-open",
                "0",
                &open_fields,
                0,
            ),
        );
        same_terminal(
            &stale,
            &mutation(&root, format, "close", "checkpoint-refused", "2", &[], 3),
        );
        assert_eq!(
            string(&read_issues(&root, format), "snapshot_token"),
            selected
        );

        mutation(
            &root,
            format,
            "comment",
            "checkpoint-after",
            "1",
            &["--body", "Admission after the retained prefix"],
            0,
        );
        let advanced = read_issues(&root, format);
        let advanced_head = string(&advanced, "snapshot_token");
        assert_ne!(advanced_head, selected);
        assert!(
            refused(checkpoint(&root, &["--expected-head", selected], 2)).contains("HeadMoved")
        );
        let second = value(checkpoint(&root, &["--expected-head", advanced_head], 0));
        assert_checkpoint(&second, 3, true);
        assert_eq!(string(&second, "source_head"), advanced_head);
        assert_ne!(
            field(&first, "checkpoint_root"),
            field(&second, "checkpoint_root")
        );
        assert!(count(&second, "authority_generation") > count(&first, "authority_generation"));

        // A selected checkpoint is still subject to explicitly narrowed bounds.
        assert!(refused(checkpoint(&root, &["--max-decisions", "2"], 2)).contains("LimitExceeded"));
        assert_eq!(
            string(&read_issues(&root, format), "snapshot_token"),
            string(&second, "published_head"),
        );
    }
}
