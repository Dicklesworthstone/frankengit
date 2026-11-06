#![forbid(unsafe_code)]
//! Fresh fg processes settle actual durable submission debt through the native
//! owner. No successful journal is truncated to manufacture an interrupted ACK.

#[path = "agent_settle_cli/fixture.rs"]
mod fixture;

use fgit_agent::LogicalTime;
use fgit_agent::effect_journal::EffectJournalPosition;
use fgit_crypto::{GitHashAlgorithm, Sha1, Sha256};
use fgit_node::OneNode;
use fgit_schema::json::{self, Value};
use fgit_types::DecisionOutcome;
use fixture::*;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::{Command, Output};

fn invoke(args: &[String], code: i32) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_fg"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn decode(bytes: &[u8]) -> Value {
    json::parse_with(
        bytes,
        json::Limits {
            input: 1024 * 1024,
            depth: 16,
            nodes: 4096,
            items: 1024,
            string: 16 * 1024,
        },
    )
    .unwrap()
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    &value.object().unwrap()[key]
}

fn replace(args: &[String], flag: &str, value: String) -> Vec<String> {
    let mut copy = args.to_vec();
    let at = copy.iter().position(|argument| argument == flag).unwrap();
    copy[at + 1] = value;
    copy
}

fn with_tail(args: &[String], tail: EffectJournalPosition) -> Vec<String> {
    let args = replace(args, "--expected-tail-entries", tail.entries.to_string());
    let args = replace(&args, "--expected-tail-bytes", tail.bytes.to_string());
    replace(&args, "--expected-tail-digest", hex(&tail.digest))
}

fn tail_value(tail: EffectJournalPosition) -> Value {
    json::object([
        ("entries", json::number(tail.entries)),
        ("bytes", json::number(tail.bytes)),
        ("digest", json::text(hex(&tail.digest))),
    ])
}

fn refused(args: &[String]) -> Value {
    let output = invoke(args, 2);
    assert!(
        output.stdout.is_empty(),
        "refused cleanup must emit no successful acknowledgement receipt"
    );
    let document = decode(&output.stderr);
    assert_eq!(
        field(&document, "type").text(),
        Some("agent_settlement_error")
    );
    assert_eq!(field(&document, "complete"), &Value::Bool(false));
    document
}

fn common(document: &Value, fixture: &Fixture) {
    assert_eq!(field(document, "type").text(), Some("agent_settlement"));
    assert_eq!(
        field(document, "profile").text(),
        Some("native-agent-publication-settlement-v1")
    );
    assert_eq!(field(document, "complete"), &Value::Bool(true));
    assert_eq!(
        field(document, "publication_authorized"),
        &Value::Bool(false)
    );
    assert_eq!(
        field(document, "resumption_authorized"),
        &Value::Bool(false)
    );
    assert_eq!(
        field(document, "run_quiescence_established"),
        &Value::Bool(false)
    );
    assert_eq!(
        field(field(document, "publication"), "tx_id").text(),
        Some(fixture.tx.to_string().as_str())
    );
}

fn terminal(document: &Value, fixture: &Fixture) {
    let publication = field(document, "publication");
    let expected = fixture.decision.unwrap();
    let actual = field(publication, "canonical_terminal");
    assert_eq!(
        field(actual, "decision_sequence"),
        &json::number(expected.decision_sequence.get())
    );
    match expected.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => {
            assert_eq!(
                field(publication, "canonical_status").text(),
                Some("committed")
            );
            assert_eq!(
                field(actual, "repository_commit_id").text(),
                Some(repository_commit_id.to_string().as_str())
            );
            assert_eq!(field(actual, "refusal_record_id"), &Value::Null);
        }
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => {
            assert_eq!(
                field(publication, "canonical_status").text(),
                Some("refused")
            );
            assert_eq!(
                field(actual, "refusal_record_id").text(),
                Some(refusal_record_id.to_string().as_str())
            );
            assert_eq!(
                field(actual, "refusal_code"),
                &json::number(u64::from(code.code_point()))
            );
            assert_eq!(field(actual, "repository_commit_id"), &Value::Null);
        }
    }
}

fn canonical<A: GitHashAlgorithm>(mode: Mode, partial_ack: bool) {
    let fixture = fixture_with_acknowledgement::<A>(mode, false);
    let code = if matches!(mode, Mode::Committed) {
        0
    } else {
        3
    };
    let files = fixture.files();
    let head = fixture.head_bytes();
    let original_bytes = fs::read(fixture.journal_path()).unwrap();
    assert_eq!(original_bytes.len() as u64, fixture.tail.bytes);

    // The unchanged read-only command reports the known terminal alongside real
    // retained responsibility, and does not opportunistically append an ACK.
    let recovery = decode(&invoke(&fixture.arguments(), code).stdout);
    assert_eq!(
        field(field(&recovery, "journal_responsibility"), "state").text(),
        Some("deferred_externally")
    );
    assert_eq!(
        field(field(&recovery, "journal_responsibility"), "debt_retained"),
        &Value::Bool(true)
    );
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);

    let (expected_tail, frame) = fixture.expected_ack();
    assert_eq!(expected_tail.entries, fixture.tail.entries + 1);
    assert!(expected_tail.bytes > fixture.tail.bytes);
    assert!(!frame.is_empty());
    let mut expected_bytes = original_bytes;
    expected_bytes.extend_from_slice(&frame);
    if partial_ack {
        // Fault injection only appends an actual prefix of the production ACK.
        // It models an interrupted write; no already-ACKed history is removed.
        let mut journal = OpenOptions::new()
            .append(true)
            .open(fixture.journal_path())
            .unwrap();
        journal.write_all(&frame[..frame.len() / 2]).unwrap();
        journal.sync_all().unwrap();
        drop(journal);
        let strict = invoke(&fixture.arguments(), 2);
        assert!(
            strict.stdout.is_empty(),
            "general recovery must stay strict"
        );
    }

    let mut args = fixture.settlement_arguments();
    args.extend(["--max-output-bytes".into(), "8192".into()]);
    let first = invoke(&args, code);
    assert!(first.stderr.is_empty());
    let document = decode(&first.stdout);
    common(&document, &fixture);
    terminal(&document, &fixture);
    let journal = field(&document, "journal");
    assert_eq!(field(journal, "input_tail"), &tail_value(fixture.tail));
    assert_eq!(field(journal, "current_tail"), &tail_value(expected_tail));
    assert_eq!(
        field(journal, "acknowledgement_confirmed"),
        &Value::Bool(true)
    );
    assert_eq!(
        field(journal, "input_already_acknowledged"),
        &Value::Bool(false)
    );
    assert_eq!(field(journal, "inventory_complete"), &Value::Bool(true));
    let responsibility = field(&document, "journal_responsibility");
    for grade in ["budget_reserved", "budget_consumed"] {
        assert_eq!(
            field(responsibility, grade),
            field(field(&recovery, "journal_responsibility"), grade),
            "settlement must preserve the original reservation and consumed budget"
        );
    }
    assert_eq!(field(responsibility, "state").text(), Some("acknowledged"));
    assert_eq!(field(responsibility, "debt_retained"), &Value::Bool(false));
    let inventory = field(field(&document, "original_run"), "authenticated_inventory");
    assert_eq!(
        field(inventory, "expires_at_logical_time"),
        &json::number(10_000)
    );
    assert_eq!(field(inventory, "refreshed"), &Value::Bool(false));
    assert_eq!(fs::read(fixture.journal_path()).unwrap(), expected_bytes);
    assert_eq!(fixture.head_bytes(), head);
    let settled_files = fixture.files();
    for (path, original) in &files {
        if path != &fixture.journal_path() {
            assert_eq!(
                settled_files.get(path),
                Some(original),
                "only the ACK file changes"
            );
        }
    }

    // A lost first receipt is safely retried with the original independent
    // anchors, even when the first attempt wrote the complete ACK.
    assert_eq!(invoke(&args, code).stdout, first.stdout);
    assert_eq!(fixture.files(), settled_files);
    assert_eq!(fixture.head_bytes(), head);
    let current = decode(&invoke(&with_tail(&args, expected_tail), code).stdout);
    common(&current, &fixture);
    terminal(&current, &fixture);
    assert_eq!(
        field(field(&current, "journal"), "input_already_acknowledged"),
        &Value::Bool(true)
    );
    assert_eq!(
        field(field(&current, "journal"), "current_tail"),
        &tail_value(expected_tail)
    );
    assert_eq!(fixture.files(), settled_files);

    let current_read = with_tail(&fixture.arguments(), expected_tail);
    let recovered = decode(&invoke(&current_read, code).stdout);
    assert_eq!(
        field(field(&recovered, "journal_responsibility"), "state").text(),
        Some("acknowledged")
    );
    assert_eq!(
        field(field(&recovered, "journal_responsibility"), "debt_retained"),
        &Value::Bool(false)
    );
    assert_eq!(fixture.files(), settled_files);
    assert_eq!(fixture.head_bytes(), head);
}

#[test]
fn committed_and_refused_debt_settles_in_fresh_processes_for_both_formats() {
    canonical::<Sha1>(Mode::Committed, false);
    canonical::<Sha256>(Mode::Committed, false);
    canonical::<Sha1>(Mode::Refused, false);
    canonical::<Sha256>(Mode::Refused, false);
}

#[test]
fn partial_exact_ack_is_completed_once_without_weakening_general_recovery() {
    canonical::<Sha1>(Mode::Committed, true);
    canonical::<Sha256>(Mode::Refused, true);
}

fn undecided<A: GitHashAlgorithm>() {
    let fixture = fixture_with_acknowledgement::<A>(Mode::Reserved, false);
    let head = fixture.head_bytes();
    for extra in [false, true] {
        if extra {
            let mut journal = OpenOptions::new()
                .append(true)
                .open(fixture.journal_path())
                .unwrap();
            journal.write_all(&[0x91]).unwrap();
            journal.sync_all().unwrap();
        }
        let files = fixture.files();
        let output = invoke(&fixture.settlement_arguments(), 4);
        assert!(output.stderr.is_empty());
        let document = decode(&output.stdout);
        common(&document, &fixture);
        assert_eq!(
            field(field(&document, "publication"), "canonical_status").text(),
            Some("undecided")
        );
        assert_eq!(
            field(field(&document, "publication"), "canonical_terminal"),
            &Value::Null
        );
        let journal = field(&document, "journal");
        assert_eq!(field(journal, "input_tail"), &tail_value(fixture.tail));
        assert_eq!(field(journal, "current_tail"), &Value::Null);
        assert_eq!(field(journal, "inventory_complete"), &Value::Bool(false));
        assert_eq!(
            field(journal, "acknowledgement_confirmed"),
            &Value::Bool(false)
        );
        assert_eq!(field(journal, "input_already_acknowledged"), &Value::Null);
        assert_eq!(fixture.files(), files);
        assert_eq!(fixture.head_bytes(), head);
    }
}

#[test]
fn undecided_submission_leaves_every_byte_and_unclassified_suffix_unchanged() {
    undecided::<Sha1>();
    undecided::<Sha256>();
}

#[test]
fn wrong_principal_anchor_effect_and_output_budget_cannot_write_an_ack() {
    let fixture = fixture_with_acknowledgement::<Sha1>(Mode::Committed, false);
    let args = fixture.settlement_arguments();
    let files = fixture.files();
    let head = fixture.head_bytes();
    for (flag, value) in [
        ("--principal", "99".repeat(16)),
        ("--expected-run", "99".repeat(32)),
        ("--expected-tail-digest", "99".repeat(32)),
        (
            "--expected-tail-entries",
            (fixture.tail.entries - 1).to_string(),
        ),
        (
            "--expected-tail-bytes",
            (fixture.tail.bytes - 1).to_string(),
        ),
        ("--effect-id", "99".repeat(16)),
        ("--observed-at", "0".into()),
    ] {
        refused(&replace(&args, flag, value));
        assert_eq!(fixture.files(), files);
        assert_eq!(fixture.head_bytes(), head);
    }
    let mut small = args.clone();
    small.extend(["--max-output-bytes".into(), "16".into()]);
    refused(&small);
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);
    invoke(&args, 0);
}

#[test]
fn cancelled_cold_owner_does_not_touch_original_pending_debt() {
    let fixture = fixture_with_acknowledgement::<Sha256>(Mode::Committed, false);
    let files = fixture.files();
    let head = fixture.head_bytes();
    let node = OneNode::open_existing(fixture.config()).unwrap();
    let cancelled = node.command_request_context(None);
    cancelled.cancel();
    assert!(
        node.runtime()
            .block_on(
                node.settle_recovered_agent_ref_transaction_for_principal_in(
                    &cancelled,
                    &fixture.directory(),
                    fixture.run,
                    &fixture.run_commitment,
                    fixture.tail,
                    fixture.effect,
                    OWNER,
                    LogicalTime::new(OBSERVED_AT),
                )
            )
            .is_err()
    );
    node.shutdown().unwrap();
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);
    invoke(&fixture.settlement_arguments(), 0);
}

#[test]
fn unrelated_or_extra_suffix_is_preserved_and_never_blessed() {
    let fixture = fixture_with_acknowledgement::<Sha1>(Mode::Committed, false);
    let (_, frame) = fixture.expected_ack();
    let mut journal = OpenOptions::new()
        .append(true)
        .open(fixture.journal_path())
        .unwrap();
    journal.write_all(&frame).unwrap();
    journal.write_all(&[0xff]).unwrap();
    journal.sync_all().unwrap();
    drop(journal);
    let files = fixture.files();
    let head = fixture.head_bytes();
    refused(&fixture.settlement_arguments());
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);
}

#[test]
fn a_reserved_effect_is_not_started_by_observing_an_operator_terminal() {
    let fixture = fixture::<Sha1>(Mode::Reserved);
    fixture.publish_original_as_operator();
    let files = fixture.files();
    let head = fixture.head_bytes();
    refused(&fixture.settlement_arguments());
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);
    let read = decode(&invoke(&fixture.arguments(), 0).stdout);
    assert_eq!(
        field(field(&read, "journal_responsibility"), "state").text(),
        Some("reserved")
    );
    assert_eq!(fixture.files(), files);
}

#[test]
fn a_live_journal_owner_blocks_cleanup_without_writing_or_refreshing_authority() {
    let fixture = fixture_with_acknowledgement::<Sha1>(Mode::Committed, false);
    let files = fixture.files();
    let head = fixture.head_bytes();
    let journal = OpenOptions::new()
        .read(true)
        .append(true)
        .open(fixture.journal_path())
        .unwrap();
    journal.try_lock().unwrap();
    refused(&fixture.settlement_arguments());
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);
    drop(journal);
    invoke(&fixture.settlement_arguments(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn failed_stdout_preserves_the_durable_ack_and_original_anchor_retry() {
    let fixture = fixture_with_acknowledgement::<Sha256>(Mode::Committed, false);
    let head = fixture.head_bytes();
    let mut expected_bytes = fs::read(fixture.journal_path()).unwrap();
    let (expected_tail, frame) = fixture.expected_ack();
    expected_bytes.extend_from_slice(&frame);
    let args = fixture.settlement_arguments();
    let output = Command::new(env!("CARGO_BIN_EXE_fg"))
        .args(&args)
        .stdout(std::process::Stdio::from(
            OpenOptions::new().write(true).open("/dev/full").unwrap(),
        ))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let document = decode(&output.stderr);
    assert_eq!(
        field(&document, "type").text(),
        Some("agent_settlement_error")
    );
    let error = field(&document, "error").text().unwrap();
    assert!(error.contains("output incomplete"), "{error}");
    assert!(error.contains("ACK was synchronized"), "{error}");
    assert!(
        error.contains(&format!("entries={}", expected_tail.entries)),
        "{error}"
    );
    assert!(
        error.contains(&format!("bytes={}", expected_tail.bytes)),
        "{error}"
    );
    assert!(error.contains(&hex(&expected_tail.digest)), "{error}");
    assert_eq!(fs::read(fixture.journal_path()).unwrap(), expected_bytes);
    assert_eq!(fixture.head_bytes(), head);
    let settled_files = fixture.files();

    let retry = decode(&invoke(&args, 0).stdout);
    common(&retry, &fixture);
    terminal(&retry, &fixture);
    assert_eq!(
        field(field(&retry, "journal"), "current_tail"),
        &tail_value(expected_tail)
    );
    assert_eq!(fixture.files(), settled_files);
    assert_eq!(fixture.head_bytes(), head);
}
