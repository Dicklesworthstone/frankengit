//! Output-only fixtures. Native publication/recovery belongs to the E2E suite.
use super::*;
use crate::publication_support::{describe, write_terminal_receipt};
use fgit_codec::harness::{commit_id, refusal_record_id, tx_id};
use fgit_types::RefusalCode;
use fgit_types::numeric::DecisionSequence;
use std::io::{self, Write};

fn options() -> Options {
    super::super::parse(
        &[
            "private-node",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "33333333333333333333333333333333",
            "DO-NOT-PRINT-RETRY-KEY",
            "private-source",
            "--json",
        ]
        .map(str::to_owned),
    )
    .unwrap()
}
fn committed() -> TerminalOutcome {
    TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(7).unwrap(),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: commit_id(),
        },
    }
}
fn refused() -> TerminalOutcome {
    TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(8).unwrap(),
        outcome: DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch,
            refusal_record_id: refusal_record_id(),
        },
    }
}
fn incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([0x44; 16])
}

#[test]
fn atomic_mapping_requires_nonempty_and_identical_terminal_results() {
    let commands = [(tx_id(), committed()); 3];
    let result = checked_atomic(true, &[tx_id()], &commands).unwrap();
    assert_eq!(result.tx_id, tx_id());
    assert_eq!(result.terminal, committed());
    assert_eq!(result.command_count, 3);
    assert!(checked_atomic(false, &[tx_id()], &commands).is_err());
    assert!(checked_atomic(true, &[], &commands).is_err());
    assert!(checked_atomic(true, &[tx_id(), tx_id()], &commands).is_err());
    assert!(checked_atomic(true, &[tx_id()], &[]).is_err());
    assert!(
        checked_atomic(
            true,
            &[tx_id()],
            &[(tx_id(), committed()), (tx_id(), refused())]
        )
        .is_err()
    );
    let mut different_sequence = committed();
    different_sequence.decision_sequence = DecisionSequence::try_new(9).unwrap();
    assert!(
        checked_atomic(
            true,
            &[tx_id()],
            &[(tx_id(), committed()), (tx_id(), different_sequence)]
        )
        .is_err()
    );
    // Distinct typed fixture identity, without pretending a real seal was made.
    let internal = fgit_types::InternalObjectId::new(
        fgit_codec::harness::algorithm(),
        TxId::DOMAIN_TAG,
        fgit_types::CANONICAL_CODEC_VERSION,
        *fgit_codec::harness::digest_of(0x91).bytes(),
    );
    let other_tx = TxId::from_internal_object_id(internal).unwrap();
    assert!(checked_atomic(true, &[other_tx], &commands).is_err());
    assert!(checked_atomic(true, &[tx_id()], &[(tx_id(), refused()); 3]).is_ok());
}

#[test]
fn committed_receipt_has_exact_identity_and_no_private_arguments() {
    let decision = checked_atomic(true, &[tx_id()], &[(tx_id(), committed()); 2]).unwrap();
    let rendered = render(&options(), incarnation(), &decision, None);
    let expected = format!(
        concat!(
            "{{\"type\":\"source_import_outcome\",\"schema_version\":1,",
            "\"tenant_id\":\"11111111111111111111111111111111\",",
            "\"repository_id\":\"22222222222222222222222222222222\",",
            "\"repository_incarnation_id\":\"44444444444444444444444444444444\",",
            "\"principal_id\":\"33333333333333333333333333333333\",",
            "\"atomic\":true,\"command_count\":2,\"tx_id\":{},",
            "\"state\":\"committed\",\"terminal\":true,\"decision_sequence\":7,",
            "\"repository_commit_id\":{},\"refusal_record_id\":null,",
            "\"refusal_code\":null,\"refusal_code_point\":null,",
            "\"node_closed\":true,\"cleanup_error\":null}}"
        ),
        quote(&tx_id().to_string()),
        quote(&commit_id().to_string()),
    );
    assert_eq!(rendered, expected);
    for _ in 0..8 {
        assert_eq!(render(&options(), incarnation(), &decision, None), rendered);
    }
    assert!(!rendered.contains("DO-NOT-PRINT"));
    assert!(!rendered.contains("private-source"));
    assert!(!rendered.contains("private-node"));
}

#[test]
fn refusal_and_cleanup_are_separate_from_the_immutable_decision() {
    let decision = checked_atomic(true, &[tx_id()], &[(tx_id(), refused())]).unwrap();
    let report = render(
        &options(),
        incarnation(),
        &decision,
        Some("disk\n\"error\"\u{202e}"),
    );
    assert!(report.contains("\"state\":\"refused\",\"terminal\":true,\"decision_sequence\":8"));
    assert!(report.contains("\"repository_commit_id\":null"));
    assert!(report.contains(&format!(
        "\"refusal_record_id\":{}",
        quote(&refusal_record_id().to_string())
    )));
    assert!(report.contains("\"refusal_code\":\"ExpectedOldRefMismatch\""));
    assert!(report.contains("\"node_closed\":false"));
    assert!(report.contains("disk\\u000a\\\"error\\\"\\u202e"));
    let committed = checked_atomic(true, &[tx_id()], &[(tx_id(), committed())]).unwrap();
    let report = render(
        &options(),
        incarnation(),
        &committed,
        Some("shutdown failed"),
    );
    assert!(report.contains("\"state\":\"committed\""));
    assert!(report.contains("\"node_closed\":false"));
}

struct BrokenOutput {
    fail_flush: bool,
}
impl Write for BrokenOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_flush {
            Ok(bytes.len())
        } else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "lost output"))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "lost flush"))
    }
}

#[test]
fn write_and_flush_failure_preserve_the_exact_terminal_knowledge() {
    for terminal in [committed(), refused()] {
        let decision = checked_atomic(true, &[tx_id()], &[(tx_id(), terminal)]).unwrap();
        let report = render(&options(), incarnation(), &decision, None);
        for fail_flush in [false, true] {
            let error = write_terminal_receipt(
                &mut BrokenOutput { fail_flush },
                &report,
                tx_id(),
                &terminal,
            )
            .unwrap_err();
            assert!(error.contains(&describe(tx_id(), &terminal)));
            assert!(error.contains("receipt output failed"));
        }
    }
}
