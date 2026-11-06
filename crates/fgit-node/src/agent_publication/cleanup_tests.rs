//! A real child process stops after ordinary native admission, while the
//! journal still holds deferred submission responsibility. Cold cleanup must
//! acknowledge that original outcome without reopening an issuing broker.

use super::*;
use fgit_agent::{
    effect_journal::EffectJournalPosition,
    ref_publication::prepare_recovered_ref_transaction_acknowledgement,
};
use std::{io::Write, process::Command, time::Instant};

#[test]
#[ignore = "child helper invoked with an independent controller directory"]
fn crash_after_native_admission_before_journal_ack() {
    let scratch = Scratch(PathBuf::from(
        std::env::var_os("FG_AGENT_CLEANUP_ROOT").expect("child fixture"),
    ));
    let mode = std::env::var("FG_AGENT_CLEANUP_OUTCOME").unwrap();
    match std::env::var("FG_AGENT_CLEANUP_FORMAT").unwrap().as_str() {
        "sha1" => crash_before_ack::<Sha1>(&scratch, &mode),
        "sha256" => crash_before_ack::<Sha256>(&scratch, &mode),
        _ => panic!("child object format"),
    }
}

fn crash_before_ack<A: GitHashAlgorithm>(scratch: &Scratch, mode: &str) -> ! {
    let (node, source) = node(scratch, A::OBJECT_FORMAT, true);
    let branch = if mode == "refused" {
        b"refs/heads/absent".as_slice()
    } else {
        b"refs/heads/main".as_slice()
    };
    let change = prepared::<A>(&node, &source, branch, false);
    let approved = approval(&change, b"cold-cleanup-original-submission");
    let chain = chain(10_000, true);
    let directory = scratch.journal("journal");
    let mut broker = broker(&node, &change, &directory);
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    let request = node.command_request_context(Some(
        crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
    ));
    let prepared = node
        .runtime()
        .block_on(node.prepare_agent_ref_transaction_trusted_local_in(
            &request,
            &mut broker,
            &clock,
            input(&change, &approved, &chain),
        ))
        .unwrap();
    let PreparedNativeAgentPublication::Ready(publication) = prepared else {
        panic!("first publication retains real validated object custody");
    };
    let tail = broker.durable_position().unwrap().unwrap();
    let run = change.transaction.run();
    let mut pins = Vec::new();
    pins.extend_from_slice(&run.run_id().value().to_be_bytes());
    pins.extend_from_slice(run.commitment().unwrap().as_bytes());
    pins.extend_from_slice(&tail.entries.to_be_bytes());
    pins.extend_from_slice(&tail.bytes.to_be_bytes());
    pins.extend_from_slice(&tail.digest);
    pins.extend_from_slice(&publication.binding().effect_id().value().to_be_bytes());
    let mut controller = fs::File::create(scratch.0.join("controller-pins")).unwrap();
    controller.write_all(&pins).unwrap();
    controller.sync_all().unwrap();
    fs::File::open(&scratch.0).unwrap().sync_all().unwrap();
    if mode != "undecided" {
        // The same production admission boundary as dispatch, deliberately
        // stopping before its immediately following pending.reconcile_async.
        let admission = node
            .runtime()
            .block_on(node.admit_basis_bound_loopback_receive_publishing_in(
                &request,
                &publication.session,
                &publication.validated,
                AdmissionLimits::default(),
                Some(&publication.staging),
            ))
            .unwrap();
        assert_eq!(admission.session.tx_ids, [publication.binding().tx_id()]);
        assert_eq!(
            matches!(
                admission.commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            ),
            mode == "committed"
        );
    }
    assert_eq!(broker.durable_position().unwrap().unwrap(), tail);
    assert_eq!(broker.dispatch_authorizations().len(), 1);
    // No destructors, synthetic journal truncation or copied in-memory broker.
    // The OS releases custody after all acknowledged bytes were synchronized.
    std::process::exit(0);
}

fn crashed_fixture(
    scratch: &Scratch,
    format: Format,
    outcome: &str,
) -> (RunId, [u8; 32], EffectJournalPosition, EffectId) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "agent_publication::tests::cleanup::crash_after_native_admission_before_journal_ack",
            "--nocapture",
        ])
        .env("FG_AGENT_CLEANUP_ROOT", &scratch.0)
        .env(
            "FG_AGENT_CLEANUP_FORMAT",
            if format == Format::Sha1 {
                "sha1"
            } else {
                "sha256"
            },
        )
        .env("FG_AGENT_CLEANUP_OUTCOME", outcome)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "native crash fixture failed: {status}");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("native crash fixture exceeded its bounded lifetime");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Independent controller receipt from the original live run and broker,
    // never a digest or tail recovered from either of the journal's files.
    let pins = fs::read(scratch.0.join("controller-pins")).unwrap();
    assert_eq!(pins.len(), 112);
    (
        RunId::new(u128::from_be_bytes(pins[..16].try_into().unwrap())),
        pins[16..48].try_into().unwrap(),
        EffectJournalPosition {
            entries: u64::from_be_bytes(pins[48..56].try_into().unwrap()),
            bytes: u64::from_be_bytes(pins[56..64].try_into().unwrap()),
            digest: pins[64..96].try_into().unwrap(),
        },
        EffectId::new(u128::from_be_bytes(pins[96..].try_into().unwrap())),
    )
}

#[test]
fn cold_native_commit_and_refusal_clear_only_original_debt_and_retry_exact_ack() {
    for format in [Format::Sha1, Format::Sha256] {
        for outcome in ["committed", "refused"] {
            let scratch = Scratch::new();
            let (run_id, run_pin, old_tail, effect) = crashed_fixture(&scratch, format, outcome);
            let node = OneNode::open_existing(scratch.config(format)).unwrap();
            let request = node.request_context();
            let directory = scratch.0.join("journal");
            let path = directory.join(format!("{:032x}.fg-agent-journal", run_id.value()));
            let original = node
                .runtime()
                .block_on(
                    node.recover_agent_journal_in(&request, &directory, run_id, &run_pin, old_tail),
                )
                .unwrap();
            let now = LogicalTime::new(10_001);
            let wrong_principal = PrincipalId::from_bytes([0x84; 16]);
            let unchanged = fs::read(&path).unwrap();
            assert!(matches!(
                node.runtime().block_on(
                    node.settle_recovered_agent_ref_transaction_for_principal_in(
                        &request,
                        &directory,
                        run_id,
                        &run_pin,
                        old_tail,
                        effect,
                        wrong_principal,
                        now,
                    )
                ),
                Err(NativeRecoveredRefTransactionRefusal::Observation(
                    RefTransactionObservationRefusal::Binding
                ))
            ));
            assert_eq!(fs::read(&path).unwrap(), unchanged);
            let locked = fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(&path)
                .unwrap();
            locked.try_lock().unwrap();
            assert!(
                matches!(
                    node.runtime().block_on(
                        node.settle_recovered_agent_ref_transaction_for_principal_in(
                            &request,
                            &directory,
                            run_id,
                            &run_pin,
                            old_tail,
                            effect,
                            wrong_principal,
                            now,
                        )
                    ),
                    Err(NativeRecoveredRefTransactionRefusal::Journal(
                        crate::agent_journal::AgentJournalHostRefusal::Busy
                    ))
                ),
                "principal validation requires exclusive journal custody"
            );
            drop(locked);
            assert_eq!(fs::read(&path).unwrap(), unchanged);
            assert!(!original.original_run().is_open_at(now));
            let before = original.reconciliation_report(now).unwrap();
            assert!(before.has_unsettled_effects());
            let observation = node
                .runtime()
                .block_on(
                    node.observe_recovered_agent_ref_transaction_in(&request, &original, effect),
                )
                .unwrap()
                .unwrap();
            let prepared = prepare_recovered_ref_transaction_acknowledgement(
                original.original_run(),
                original.journal(),
                &observation,
                now,
            )
            .unwrap();
            let expected_tail = prepared.after_position();
            if outcome == "refused" {
                // Fault model: an earlier cleanup died partway through this
                // one exact frame. The production helper must finish it.
                let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
                file.write_all(&prepared.frame()[..prepared.frame().len() / 2])
                    .unwrap();
                file.sync_all().unwrap();
                assert!(
                    node.runtime()
                        .block_on(node.recover_agent_journal_in(
                            &request, &directory, run_id, &run_pin, old_tail,
                        ))
                        .is_err(),
                    "ordinary recovery stays strict"
                );
            }
            let unchanged = fs::read(&path).unwrap();
            let cancelled = node.request_context();
            cancelled.cancel();
            assert!(
                node.runtime()
                    .block_on(node.settle_recovered_agent_ref_transaction_in(
                        &cancelled, &directory, run_id, &run_pin, old_tail, effect, now,
                    ))
                    .is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), unchanged);
            let authority = node
                .runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap();

            for (tail, already_acknowledged) in
                [(old_tail, false), (old_tail, false), (expected_tail, true)]
            {
                // The original caller check applies before completion of a
                // partial ACK, synchronization of a complete suffix, and the
                // no-op path anchored at the acknowledged successor.
                let unchanged = fs::read(&path).unwrap();
                assert!(matches!(
                    node.runtime().block_on(
                        node.settle_recovered_agent_ref_transaction_for_principal_in(
                            &request,
                            &directory,
                            run_id,
                            &run_pin,
                            tail,
                            effect,
                            wrong_principal,
                            now,
                        )
                    ),
                    Err(NativeRecoveredRefTransactionRefusal::Observation(
                        RefTransactionObservationRefusal::Binding
                    ))
                ));
                assert_eq!(fs::read(&path).unwrap(), unchanged);
                let result = node
                    .runtime()
                    .block_on(
                        node.settle_recovered_agent_ref_transaction_for_principal_in(
                            &request, &directory, run_id, &run_pin, tail, effect, OWNER, now,
                        ),
                    )
                    .unwrap();
                let NativeRecoveredRefTransactionSettlement::Acknowledged {
                    observation: settled,
                    recovered,
                    already_acknowledged: actual,
                } = result
                else {
                    panic!("known terminal must clear the original debt");
                };
                assert_eq!(settled, observation);
                assert_eq!(actual, already_acknowledged);
                assert_eq!(recovered.journal().position(), expected_tail);
                let report = recovered.reconciliation_report(now).unwrap();
                assert!(!report.has_unsettled_effects());
                assert_eq!(
                    report.cumulative_budget_consumed(),
                    before.cumulative_budget_consumed()
                );
                assert_eq!(fs::metadata(&path).unwrap().len(), expected_tail.bytes);
                assert_eq!(
                    node.runtime()
                        .block_on(node.authenticate_authority_head())
                        .unwrap()
                        .receipt(),
                    authority.receipt()
                );
            }
            let mut extra = fs::OpenOptions::new().append(true).open(&path).unwrap();
            extra.write_all(&[0xff]).unwrap();
            extra.sync_all().unwrap();
            drop(extra);
            let malformed = fs::read(&path).unwrap();
            assert!(matches!(
                node.runtime()
                    .block_on(node.settle_recovered_agent_ref_transaction_in(
                        &request, &directory, run_id, &run_pin, old_tail, effect, now,
                    )),
                Err(NativeRecoveredRefTransactionRefusal::Persistence(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), malformed);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn undecided_cold_submission_does_not_append_or_expose_an_incomplete_inventory() {
    let scratch = Scratch::new();
    let format = Format::Sha256;
    let (run_id, run_pin, tail, effect) = crashed_fixture(&scratch, format, "undecided");
    let node = OneNode::open_existing(scratch.config(format)).unwrap();
    let request = node.request_context();
    let directory = scratch.0.join("journal");
    let path = directory.join(format!("{:032x}.fg-agent-journal", run_id.value()));
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0x91]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let before = fs::read(&path).unwrap();
    let authority = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    assert!(matches!(
        node.runtime().block_on(
            node.settle_recovered_agent_ref_transaction_for_principal_in(
                &request,
                &directory,
                run_id,
                &run_pin,
                tail,
                effect,
                PrincipalId::from_bytes([0x84; 16]),
                LogicalTime::new(10_001),
            )
        ),
        Err(NativeRecoveredRefTransactionRefusal::Observation(
            RefTransactionObservationRefusal::Binding
        ))
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    let result = node
        .runtime()
        .block_on(
            node.settle_recovered_agent_ref_transaction_for_principal_in(
                &request,
                &directory,
                run_id,
                &run_pin,
                tail,
                effect,
                OWNER,
                LogicalTime::new(10_001),
            ),
        )
        .unwrap();
    assert!(
        matches!(result, NativeRecoveredRefTransactionSettlement::Undecided { effect_id, .. } if effect_id == effect)
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        node.runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt(),
        authority.receipt()
    );
    node.shutdown().unwrap();
}
