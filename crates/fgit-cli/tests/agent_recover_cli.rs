#![forbid(unsafe_code)]
//! Fresh fg subprocesses authenticate actual persisted native run/journal
//! custody and ordinary canonical outcomes; no reference authority is used.

#[path = "agent_recover_cli/fixture.rs"]
mod fixture;

use fgit_crypto::{GitHashAlgorithm, Sha1, Sha256};
use fgit_schema::json::{self, Value};
use fgit_types::DecisionOutcome;
use fixture::*;
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
fn refused(args: &[String]) {
    let output = invoke(args, 2);
    assert!(
        output.stdout.is_empty(),
        "failed recovery must not emit an unverified receipt"
    );
    let error = decode(&output.stderr);
    assert_eq!(field(&error, "type").text(), Some("agent_recovery_error"));
    assert_eq!(field(&error, "complete"), &Value::Bool(false));
}
fn common(document: &Value, fixture: &Fixture) {
    assert_eq!(field(document, "type").text(), Some("agent_recovery"));
    assert_eq!(
        field(document, "profile").text(),
        Some("native-agent-publication-recovery-v1")
    );
    assert_eq!(field(document, "complete"), &Value::Bool(true));
    assert_eq!(field(document, "read_only"), &Value::Bool(true));
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
        field(field(document, "journal"), "anchor_matched"),
        &Value::Bool(true)
    );
    assert_eq!(
        field(field(document, "journal"), "mutated"),
        &Value::Bool(false)
    );
    assert_eq!(
        field(field(document, "original_run"), "commitment").text(),
        Some(hex(&fixture.run_commitment).as_str())
    );
    assert_eq!(
        field(field(document, "original_run"), "refreshed"),
        &Value::Bool(false)
    );
    assert_eq!(
        field(field(document, "publication"), "tx_id").text(),
        Some(fixture.tx.to_string().as_str())
    );
    assert_eq!(
        field(
            field(document, "journal_responsibility"),
            "acknowledgement_appended"
        ),
        &Value::Bool(false)
    );
    assert_eq!(
        field(
            field(document, "journal_responsibility"),
            "settlement_performed"
        ),
        &Value::Bool(false)
    );
}

fn canonical<A: GitHashAlgorithm>(mode: Mode) {
    let fixture = fixture::<A>(mode);
    let files = fixture.files();
    let head = fixture.head_bytes();
    let code = if matches!(mode, Mode::Committed) {
        0
    } else {
        3
    };
    let output = invoke(&fixture.arguments(), code);
    assert!(output.stderr.is_empty());
    let document = decode(&output.stdout);
    common(&document, &fixture);
    let publication = field(&document, "publication");
    let terminal = field(publication, "canonical_terminal");
    let expected = fixture.decision.unwrap();
    assert_eq!(
        field(terminal, "decision_sequence"),
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
                field(terminal, "repository_commit_id").text(),
                Some(repository_commit_id.to_string().as_str())
            );
            assert_eq!(field(terminal, "refusal_record_id"), &Value::Null);
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
                field(terminal, "refusal_record_id").text(),
                Some(refusal_record_id.to_string().as_str())
            );
            assert_eq!(
                field(terminal, "refusal_code"),
                &json::number(u64::from(code.code_point()))
            );
            assert_eq!(field(terminal, "repository_commit_id"), &Value::Null);
        }
    }
    assert_eq!(
        field(field(&document, "journal_responsibility"), "state").text(),
        Some("acknowledged")
    );
    assert_eq!(
        field(field(&document, "journal_responsibility"), "debt_retained"),
        &Value::Bool(false)
    );
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);
    // Stable repeated lookup is read-only and does not generate a fresh run or
    // observation timestamp in an invented logical-time domain.
    assert_eq!(invoke(&fixture.arguments(), code).stdout, output.stdout);
}

#[test]
fn original_committed_and_refused_outcomes_survive_native_reopen_in_both_formats() {
    canonical::<Sha1>(Mode::Committed);
    canonical::<Sha256>(Mode::Committed);
    canonical::<Sha1>(Mode::Refused);
    canonical::<Sha256>(Mode::Refused);
}

fn retained_debt<A: GitHashAlgorithm>() {
    let fixture = fixture::<A>(Mode::Reserved);
    let files = fixture.files();
    let head = fixture.head_bytes();
    let output = invoke(&fixture.arguments(), 4);
    assert!(output.stderr.is_empty());
    let undecided = decode(&output.stdout);
    common(&undecided, &fixture);
    assert_eq!(
        field(field(&undecided, "publication"), "canonical_status").text(),
        Some("undecided")
    );
    assert_eq!(
        field(field(&undecided, "publication"), "canonical_terminal"),
        &Value::Null
    );
    let debt = field(&undecided, "journal_responsibility");
    assert_eq!(field(debt, "state").text(), Some("reserved"));
    assert_eq!(field(debt, "debt_retained"), &Value::Bool(true));
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);

    // An independent authorized operator completes the same ordinary request.
    // That canonical fact must not rewrite the original agent journal's debt.
    let terminal = fixture.publish_original_as_operator();
    let published_head = fixture.head_bytes();
    let committed = decode(&invoke(&fixture.arguments(), 0).stdout);
    common(&committed, &fixture);
    assert_eq!(
        field(field(&committed, "publication"), "canonical_status").text(),
        Some("committed")
    );
    assert_eq!(
        field(
            field(field(&committed, "publication"), "canonical_terminal"),
            "decision_sequence"
        ),
        &json::number(terminal.decision_sequence.get())
    );
    assert_eq!(field(&committed, "journal_responsibility"), debt);
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), published_head);
}

#[test]
fn canonical_terminal_does_not_erase_anchored_journal_debt() {
    retained_debt::<Sha1>();
    retained_debt::<Sha256>();
}

#[test]
fn wrong_anchors_principal_effect_limits_and_truncated_journal_refuse_without_output() {
    let fixture = fixture::<Sha1>(Mode::Committed);
    let args = fixture.arguments();
    let files = fixture.files();
    let head = fixture.head_bytes();
    for (flag, value) in [
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
        ("--principal", "99".repeat(16)),
        ("--effect-id", "99".repeat(16)),
    ] {
        refused(&replace(&args, flag, value));
    }
    let mut missing = args.clone();
    let at = missing
        .iter()
        .position(|argument| argument == "--expected-tail-digest")
        .unwrap();
    missing.drain(at..at + 2);
    refused(&missing);
    let mut small = args.clone();
    small.extend(["--max-output-bytes".into(), "16".into()]);
    refused(&small);
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);

    let journal = fixture
        .directory()
        .join(format!("{:032x}.fg-agent-journal", fixture.run.value()));
    let bytes = std::fs::read(&journal).unwrap();
    std::fs::write(&journal, &bytes[..bytes.len() - 1]).unwrap();
    refused(&args);
    std::fs::write(&journal, &bytes).unwrap();
    assert_eq!(fixture.files(), files);
    assert_eq!(fixture.head_bytes(), head);
}

#[cfg(unix)]
#[test]
fn explicitly_selected_symlink_directory_and_journal_are_refused() {
    let fixture = fixture::<Sha1>(Mode::Committed);
    let args = fixture.arguments();
    let alias = fixture.scratch.0.join("journal-alias");
    std::os::unix::fs::symlink(fixture.directory(), &alias).unwrap();
    let mut directory_alias = args.clone();
    directory_alias[5] = alias.to_str().unwrap().into();
    refused(&directory_alias);
    let journal = fixture
        .directory()
        .join(format!("{:032x}.fg-agent-journal", fixture.run.value()));
    let original = fixture.scratch.0.join("journal-original");
    std::fs::rename(&journal, &original).unwrap();
    std::os::unix::fs::symlink(&original, &journal).unwrap();
    refused(&args);
}
