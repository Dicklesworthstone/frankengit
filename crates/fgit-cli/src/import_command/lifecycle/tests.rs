//! Output-only lifecycle fault injection; real signal/storage cases live in E2E.
use super::*;
use fgit_authority::TerminalOutcome;
use fgit_codec::harness::{commit_id, refusal_record_id, tx_id};
use fgit_types::RefusalCode;
use fgit_types::numeric::DecisionSequence;
use std::io;

fn options(json: bool) -> Options {
    let mut raw = [
        "node",
        &"11".repeat(16),
        &"22".repeat(16),
        &"33".repeat(16),
        "private-key",
        "private-source",
    ]
    .map(str::to_owned)
    .to_vec();
    if json {
        raw.push("--json".into());
    }
    super::super::parse(&raw).unwrap()
}
fn decision(committed: bool) -> receipt::AtomicImportDecision {
    receipt::AtomicImportDecision {
        tx_id: tx_id(),
        command_count: 2,
        terminal: TerminalOutcome {
            decision_sequence: DecisionSequence::FIRST,
            outcome: if committed {
                DecisionOutcome::Committed {
                    repository_commit_id: commit_id(),
                }
            } else {
                DecisionOutcome::Refused {
                    code: RefusalCode::ExpectedOldRefMismatch,
                    refusal_record_id: refusal_record_id(),
                }
            },
        },
    }
}
fn incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([0x44; 16])
}
#[test]
fn clean_completion_preserves_exact_receipt_and_original_exit_codes() {
    for committed in [true, false] {
        let options = options(true);
        let decision = decision(committed);
        let mut bytes = Vec::new();
        assert_eq!(
            finish(&mut bytes, &options, incarnation(), &decision, None, None).unwrap(),
            if committed { 0 } else { 3 }
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                "{}\n",
                receipt::render(&options, incarnation(), &decision, None)
            )
        );
    }
    let mut bytes = Vec::new();
    assert_eq!(
        finish(
            &mut bytes,
            &options(false),
            incarnation(),
            &decision(true),
            None,
            None
        )
        .unwrap(),
        0
    );
    assert_eq!(bytes, b"published 2 source-import ref commands\n");
}
#[test]
fn observer_failure_keeps_commit_or_refusal_and_does_not_misreport_node_close() {
    for committed in [true, false] {
        let mut bytes = Vec::new();
        let decision = decision(committed);
        let error = finish(
            &mut bytes,
            &options(true),
            incarnation(),
            &decision,
            None,
            Some("observer failed"),
        )
        .unwrap_err();
        assert!(error.contains(&describe(decision.tx_id, &decision.terminal)));
        assert!(error.contains("observer failed") && error.contains("do not assume rollback"));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"terminal\":true") && text.contains("\"node_closed\":true"));
        assert!(text.contains(if committed {
            "\"state\":\"committed\""
        } else {
            "\"state\":\"refused\""
        }));
        assert!(!text.contains("private-key") && !text.contains("private-source"));
    }
}
#[test]
fn shutdown_and_observer_failures_both_survive_known_publication() {
    let mut bytes = Vec::new();
    let decision = decision(true);
    let error = finish(
        &mut bytes,
        &options(true),
        incarnation(),
        &decision,
        Some("node failed"),
        Some("observer failed"),
    )
    .unwrap_err();
    assert!(
        error.contains("node failed")
            && error.contains("observer failed")
            && error.contains(&tx_id().to_string())
    );
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"node_closed\":false") && text.contains("\"state\":\"committed\""));
}
#[test]
fn plain_output_retains_original_success_or_refusal_when_cleanup_fails() {
    let mut bytes = Vec::new();
    let error = finish(
        &mut bytes,
        &options(false),
        incarnation(),
        &decision(true),
        None,
        Some("observer failed"),
    )
    .unwrap_err();
    assert_eq!(bytes, b"published 2 source-import ref commands\n");
    assert!(error.contains(&tx_id().to_string()));
    bytes.clear();
    let error = finish(
        &mut bytes,
        &options(false),
        incarnation(),
        &decision(false),
        Some("node failed"),
        Some("observer failed"),
    )
    .unwrap_err();
    assert!(bytes.is_empty());
    assert!(
        error.contains("ExpectedOldRefMismatch")
            && error.contains("node failed")
            && error.contains("observer failed")
    );
}
#[test]
fn output_failure_retains_all_cleanup_errors_and_known_transaction() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for json in [true, false] {
        let error = finish(
            &mut Broken,
            &options(json),
            incarnation(),
            &decision(true),
            Some("node failed"),
            Some("observer failed"),
        )
        .unwrap_err();
        assert!(
            error.contains("receipt output failed")
                && error.contains("node failed")
                && error.contains("observer failed")
        );
        assert!(error.contains(&describe(tx_id(), &decision(true).terminal)));
    }
}
