//! Explicit cold cleanup of a real never-started publication reservation.

use super::*;

fn assert_abort(document: &Value, fixture: &Fixture, tail: EffectJournalPosition, already: bool) {
    assert_eq!(field(document, "type").text(), Some("agent_settlement"));
    assert_eq!(
        field(document, "profile").text(),
        Some("native-agent-reservation-abort-v1")
    );
    assert_eq!(field(document, "action").text(), Some("abort-reserved"));
    assert_eq!(field(document, "complete"), &Value::Bool(true));
    for field_name in [
        "publication_authorized",
        "resumption_authorized",
        "run_quiescence_established",
    ] {
        assert_eq!(field(document, field_name), &Value::Bool(false));
    }
    let publication = field(document, "publication");
    assert_eq!(
        field(publication, "tx_id").text(),
        Some(fixture.tx.to_string().as_str())
    );
    assert_eq!(
        field(publication, "canonical_status").text(),
        Some("not_observed")
    );
    assert_eq!(field(publication, "canonical_terminal"), &Value::Null);
    assert_eq!(
        field(publication, "canonical_cancellation_established"),
        &Value::Bool(false)
    );
    let journal = field(document, "journal");
    assert_eq!(field(journal, "current_tail"), &tail_value(tail));
    assert_eq!(field(journal, "abort_confirmed"), &Value::Bool(true));
    assert_eq!(
        field(journal, "input_already_aborted"),
        &Value::Bool(already)
    );
    assert_eq!(field(journal, "inventory_complete"), &Value::Bool(true));
    assert_eq!(
        field(journal, "acknowledgement_confirmed"),
        &Value::Bool(false)
    );
    assert_eq!(field(journal, "input_already_acknowledged"), &Value::Null);
    let responsibility = field(document, "journal_responsibility");
    assert_eq!(field(responsibility, "state").text(), Some("aborted"));
    assert_eq!(field(responsibility, "debt_retained"), &Value::Bool(false));
    let run = field(field(document, "original_run"), "authenticated_inventory");
    assert_eq!(field(run, "expires_at_logical_time"), &json::number(10_000));
    assert_eq!(field(run, "refreshed"), &Value::Bool(false));
}

fn abort_reserved<A: GitHashAlgorithm>(partial: bool) {
    // The ordinary Reserved fixture reaches the native pre-start deadline
    // refusal. The no-acknowledgement fixture intentionally starts submission
    // for ACK recovery tests and is not an abortable reservation.
    let fixture = fixture::<A>(Mode::Reserved);
    let head = fixture.head_bytes();
    let before = fixture.files();
    let original = fs::read(fixture.journal_path()).unwrap();
    let recovery = decode(&invoke(&fixture.arguments(), 4).stdout);
    let (tail, frame) = fixture.expected_abort();
    assert_eq!(tail.entries, fixture.tail.entries + 1);
    assert!(!frame.is_empty());
    let mut expected = original;
    expected.extend_from_slice(&frame);
    if partial {
        let mut file = OpenOptions::new()
            .append(true)
            .open(fixture.journal_path())
            .unwrap();
        file.write_all(&frame[..frame.len() / 2]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(
            invoke(&fixture.arguments(), 2).stdout.is_empty(),
            "read-only recovery stays strict"
        );
    }
    let mut args = fixture.abort_arguments();
    args.extend(["--max-output-bytes".into(), "8192".into()]);
    let output = invoke(&args, 0);
    assert!(output.stderr.is_empty());
    let document = decode(&output.stdout);
    assert_abort(&document, &fixture, tail, false);
    assert_eq!(
        field(field(&document, "journal"), "input_tail"),
        &tail_value(fixture.tail)
    );
    for budget in ["budget_reserved", "budget_consumed"] {
        assert_eq!(
            field(field(&document, "journal_responsibility"), budget),
            field(field(&recovery, "journal_responsibility"), budget),
            "cleanup preserves the original budget accounting"
        );
    }
    assert_eq!(fs::read(fixture.journal_path()).unwrap(), expected);
    assert_eq!(fixture.head_bytes(), head);
    let settled = fixture.files();
    assert_eq!(settled.len(), before.len());
    for (path, bytes) in &before {
        if path != &fixture.journal_path() {
            assert_eq!(settled.get(path), Some(bytes));
        }
    }
    // A lost response and a complete previous append are the same exact retry.
    assert_eq!(invoke(&args, 0).stdout, output.stdout);
    let later = replace(&args, "--observed-at", (OBSERVED_AT + 1).to_string());
    assert_abort(&decode(&invoke(&later, 0).stdout), &fixture, tail, false);
    assert_abort(
        &decode(&invoke(&with_tail(&args, tail), 0).stdout),
        &fixture,
        tail,
        true,
    );
    let read = decode(&invoke(&with_tail(&fixture.arguments(), tail), 4).stdout);
    assert_eq!(
        field(field(&read, "journal_responsibility"), "state").text(),
        Some("aborted")
    );
    assert_eq!(
        field(field(&read, "journal_responsibility"), "debt_retained"),
        &Value::Bool(false)
    );
    assert_eq!(fixture.files(), settled);
    assert_eq!(fixture.head_bytes(), head);
}

#[test]
fn prestart_reservations_abort_in_fresh_processes_and_retry_exactly_for_both_formats() {
    abort_reserved::<Sha1>(false);
    abort_reserved::<Sha256>(false);
    abort_reserved::<Sha1>(true);
    abort_reserved::<Sha256>(true);
}

#[test]
fn aborted_reservation_does_not_cancel_or_deny_an_independent_canonical_publication() {
    fn check<A: GitHashAlgorithm>() {
        let fixture = fixture::<A>(Mode::Reserved);
        let published = fixture.publish_original_as_operator();
        let head = fixture.head_bytes();
        let (tail, _) = fixture.expected_abort();
        assert_abort(
            &decode(&invoke(&fixture.abort_arguments(), 0).stdout),
            &fixture,
            tail,
            false,
        );
        assert_eq!(fixture.head_bytes(), head);
        let recovered = decode(&invoke(&with_tail(&fixture.arguments(), tail), 0).stdout);
        let publication = field(&recovered, "publication");
        assert_eq!(
            field(publication, "canonical_status").text(),
            Some("committed")
        );
        let terminal = field(publication, "canonical_terminal");
        assert_eq!(
            field(terminal, "decision_sequence"),
            &json::number(published.decision_sequence.get())
        );
        assert_eq!(
            field(field(&recovered, "journal_responsibility"), "state").text(),
            Some("aborted")
        );
        assert_eq!(fixture.head_bytes(), head);
    }
    check::<Sha1>();
    check::<Sha256>();
}

#[test]
fn started_and_acknowledged_publications_never_fall_back_to_abort() {
    for mode in [Mode::Committed, Mode::Refused] {
        for acknowledge in [false, true] {
            let fixture = fixture_with_acknowledgement::<Sha256>(mode, acknowledge);
            let before = fixture.files();
            let head = fixture.head_bytes();
            refused(&fixture.abort_arguments());
            assert_eq!(fixture.files(), before);
            assert_eq!(fixture.head_bytes(), head);
            // The right action remains usable; refusal does not damage custody.
            invoke(
                &fixture.settlement_arguments(),
                if matches!(mode, Mode::Committed) {
                    0
                } else {
                    3
                },
            );
            assert_eq!(fixture.head_bytes(), head);
        }
    }
}

#[test]
fn wrong_operator_anchor_unknown_suffix_and_small_output_cannot_abort() {
    let fixture = fixture::<Sha1>(Mode::Reserved);
    let args = fixture.abort_arguments();
    let before = fixture.files();
    let head = fixture.head_bytes();
    for (flag, value) in [
        ("--principal", "99".repeat(16)),
        ("--effect-id", "99".repeat(16)),
        ("--expected-run", "99".repeat(32)),
        ("--expected-tail-digest", "99".repeat(32)),
        ("--action", "cancel".into()),
    ] {
        refused(&replace(&args, flag, value));
        assert_eq!(fixture.files(), before);
    }
    let mut small = args.clone();
    small.extend(["--max-output-bytes".into(), "8191".into()]);
    refused(&small);
    assert_eq!(fixture.files(), before);
    let (_, frame) = fixture.expected_abort();
    let mut corrupt = frame;
    *corrupt.last_mut().unwrap() ^= 1;
    let mut file = OpenOptions::new()
        .append(true)
        .open(fixture.journal_path())
        .unwrap();
    file.write_all(&corrupt).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let corrupted = fixture.files();
    refused(&args);
    assert_eq!(
        fixture.files(),
        corrupted,
        "never truncate or rewrite an unknown suffix"
    );
    assert_eq!(fixture.head_bytes(), head);
}

#[cfg(target_os = "linux")]
#[test]
fn lost_abort_stdout_retains_the_exact_durable_tail_and_safe_retry() {
    let fixture = fixture::<Sha256>(Mode::Reserved);
    let head = fixture.head_bytes();
    let (tail, frame) = fixture.expected_abort();
    let mut expected = fs::read(fixture.journal_path()).unwrap();
    expected.extend_from_slice(&frame);
    let args = fixture.abort_arguments();
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
    assert!(
        error.contains("was aborted at synchronized journal tail"),
        "{error}"
    );
    assert!(
        error.contains("canonical transaction status was not observed"),
        "{error}"
    );
    assert!(
        error.contains(&format!("entries={}", tail.entries)),
        "{error}"
    );
    assert!(error.contains(&format!("bytes={}", tail.bytes)), "{error}");
    assert!(error.contains(&hex(&tail.digest)), "{error}");
    assert_eq!(fs::read(fixture.journal_path()).unwrap(), expected);
    assert_eq!(fixture.head_bytes(), head);
    let before_retry = fixture.files();
    assert_abort(&decode(&invoke(&args, 0).stdout), &fixture, tail, false);
    assert_eq!(fixture.files(), before_retry);
    assert_eq!(fixture.head_bytes(), head);
}
