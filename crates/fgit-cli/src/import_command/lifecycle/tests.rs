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

/// A byte-limit refusal names --max-expanded-mib with the lower bound the
/// refusal proves. Every refusal before sealing is classified as publishing
/// nothing; the command text keeps the non-commit caveat only for a failure
/// after admission began (frankengit-6sl7).
#[test]
fn byte_limit_refusals_name_the_profile_flag_and_only_admission_failures_are_uncertain() {
    use fgit_node::{LooseGitImportRefusal, NodeSourceImportRefusal};
    const MIB: u64 = 1024 * 1024;
    let limit_refusal = |limit: u64, observed: u64| {
        NodeSourceImportRefusal::Staging(Box::new(
            LooseGitImportRefusal::TotalObjectBytesExceeded { limit, observed },
        ))
    };

    // charmed.git under the default profile: the walk stopped at 538,027,779.
    let Failure::Refused(text) = failure(&limit_refusal(512 * MIB, 538_027_779), None) else {
        panic!("a staging refusal precedes sealing");
    };
    assert!(text.starts_with("reachable object bytes 538027779 exceed import limit 536870912"));
    assert!(
        text.contains("the default import profile admits 512 MiB"),
        "{text}"
    );
    assert!(
        text.contains("rerun with --max-expanded-mib 514 or more"),
        "{text}"
    );
    assert!(text.contains("may need more than 514 MiB"), "{text}");

    // An explicit profile one byte short names the next MiB.
    let Failure::Refused(text) = failure(&limit_refusal(MIB, MIB + 1), Some(MIB)) else {
        panic!("a staging refusal precedes sealing");
    };
    assert!(text.contains("the selected profile admits 1 MiB"), "{text}");
    assert!(
        text.contains("rerun with --max-expanded-mib 2 or more"),
        "{text}"
    );

    // Past the largest profile there is no flag value to suggest.
    let largest = 16_384 * MIB;
    let Failure::Refused(text) = failure(&limit_refusal(largest, largest + 1), Some(largest))
    else {
        panic!("a staging refusal precedes sealing");
    };
    assert!(
        text.contains("needs more than the largest profile"),
        "{text}"
    );
    assert!(!text.contains("rerun with"), "{text}");

    // Other refusals before sealing carry no hint.
    for refusal in [
        NodeSourceImportRefusal::Staging(Box::new(LooseGitImportRefusal::ObjectLimitExceeded {
            limit: 5,
        })),
        NodeSourceImportRefusal::Validation(RefusalCode::ExpectedOldRefMismatch),
        NodeSourceImportRefusal::ObjectCountOutOfRange { count: 7 },
    ] {
        assert_eq!(
            failure(&refusal, None),
            Failure::Refused(refusal.to_string())
        );
    }

    let refused = super::super::describe_failure(Failure::Refused("staged".into()), None, None);
    assert!(refused.contains("nothing was published"), "{refused}");
    assert!(!refused.contains("not proof of non-commit"), "{refused}");
    let uncertain =
        super::super::describe_failure(Failure::Uncertain("admission".into()), None, None);
    assert!(uncertain.contains("not proof of non-commit"), "{uncertain}");
    assert!(!uncertain.contains("nothing was published"), "{uncertain}");
}
