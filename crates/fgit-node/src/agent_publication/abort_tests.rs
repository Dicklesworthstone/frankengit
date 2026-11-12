//! Cold, actual-file abort of a native reservation. A child exits without
//! running destructors, so the parent restores persisted original authority
//! and an independently retained tail rather than an in-memory issuing broker.

use super::*;
use fgit_agent::{
    EffectTerminalOutcome,
    effect_journal::{EffectJournalPersistenceRefusal, EffectJournalPosition},
    ref_publication::{RefTransactionAbortRefusal, prepare_recovered_ref_transaction_abort},
};
use fgit_resource::ObligationState;
use std::{io::Write, path::Path, process::Command, time::Instant};

#[derive(Clone, Copy)]
struct Pins {
    run: RunId,
    commitment: [u8; 32],
    reserved: EffectJournalPosition,
    current: EffectJournalPosition,
    effect: EffectId,
}

fn append_position(bytes: &mut Vec<u8>, position: EffectJournalPosition) {
    bytes.extend_from_slice(&position.entries.to_be_bytes());
    bytes.extend_from_slice(&position.bytes.to_be_bytes());
    bytes.extend_from_slice(&position.digest);
}

fn read_position(bytes: &[u8]) -> EffectJournalPosition {
    assert_eq!(bytes.len(), 48);
    EffectJournalPosition {
        entries: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
        bytes: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        digest: bytes[16..].try_into().unwrap(),
    }
}

#[test]
#[ignore = "child helper invoked with an independent controller directory"]
fn crash_with_original_native_reservation() {
    let scratch = Scratch(PathBuf::from(
        std::env::var_os("FG_AGENT_ABORT_ROOT").expect("child fixture"),
    ));
    let mode = std::env::var("FG_AGENT_ABORT_MODE").unwrap();
    match std::env::var("FG_AGENT_ABORT_FORMAT").unwrap().as_str() {
        "sha1" => crash_reserved::<Sha1>(&scratch, &mode),
        "sha256" => crash_reserved::<Sha256>(&scratch, &mode),
        _ => panic!("child object format"),
    }
}

fn crash_reserved<A: GitHashAlgorithm>(scratch: &Scratch, mode: &str) -> ! {
    let (node, source) = node(scratch, A::OBJECT_FORMAT, true);
    let change = prepared::<A>(&node, &source, reference().as_bytes(), false);
    let approved = approval(&change, b"cold-original-native-reservation");
    let chain = chain(1_000, true);
    let directory = scratch.journal("journal");
    let mut broker = broker(&node, &change, &directory);
    let clock = node
        .trusted_local_agent_publication_clock(LogicalTime::new(20), Duration::from_secs(1))
        .unwrap();
    // The real native deadline gate follows durable reservation and precedes
    // irreversible start. It returns the original, still-unstarted owner.
    let request = node.command_request_context(Some(
        crate::GitDaemonSessionTimeout::try_new(Duration::from_secs(3_600)).unwrap(),
    ));
    let error = node
        .runtime()
        .block_on(node.publish_agent_ref_transaction_trusted_local_in(
            &request,
            &mut broker,
            &clock,
            input(&change, &approved, &chain),
        ))
        .unwrap_err();
    let NativeAgentPublicationError::Reserved {
        reservation,
        reason: NativeAgentPublicationRefusal::AuthorizationDeadlineUnbound,
    } = error
    else {
        panic!("the native gate must retain an exact reservation: {error:?}");
    };
    let reserved = broker.durable_position().unwrap().unwrap();
    let effect = reservation.binding().effect_id();
    assert_eq!(broker.records().len(), 1);
    assert_eq!(
        broker.records()[0].obligation_state,
        ObligationState::Reserved
    );
    assert_eq!(broker.records()[0].budget_consumed, ResourceVector::ZERO);
    assert!(broker.dispatch_authorizations().is_empty());
    let run = change.transaction.run();
    let (_reserved_owner, _started_owner) = if mode == "started" {
        // Start the original typed reservation through its real broker. These
        // durable Commit/Defer frames must defeat the older Reserved anchor,
        // even though this fixture never invokes ordinary repository admission.
        let revocations = node
            .runtime()
            .block_on(node.agent_publication_revocations_in(
                &node.request_context(),
                run,
                LogicalTime::new(20),
            ))
            .unwrap();
        let pending = broker
            .start_ref_transaction(*reservation, &chain, &revocations, LogicalTime::new(20))
            .unwrap();
        assert_eq!(
            broker.records()[0].obligation_state,
            ObligationState::DeferredExternally
        );
        assert_eq!(broker.dispatch_authorizations().len(), 1);
        (None, Some(pending))
    } else {
        assert_eq!(mode, "reserved");
        (Some(reservation), None)
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&run.run_id().value().to_be_bytes());
    bytes.extend_from_slice(run.commitment().unwrap().as_bytes());
    append_position(&mut bytes, reserved);
    append_position(&mut bytes, broker.durable_position().unwrap().unwrap());
    bytes.extend_from_slice(&effect.value().to_be_bytes());
    let mut controller = fs::File::create(scratch.0.join("abort-controller-pins")).unwrap();
    controller.write_all(&bytes).unwrap();
    controller.sync_all().unwrap();
    fs::File::open(&scratch.0).unwrap().sync_all().unwrap();
    // No destructor, explicit in-memory abort, synthetic tail or issuing-broker
    // restore runs before the next process obtains exclusive file custody.
    std::process::exit(0);
}

fn crashed(scratch: &Scratch, format: Format, mode: &str) -> Pins {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "agent_publication::tests::abort::crash_with_original_native_reservation",
            "--nocapture",
        ])
        .env("FG_AGENT_ABORT_ROOT", &scratch.0)
        .env(
            "FG_AGENT_ABORT_FORMAT",
            if format == Format::Sha1 {
                "sha1"
            } else {
                "sha256"
            },
        )
        .env("FG_AGENT_ABORT_MODE", mode)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "native reservation child failed: {status}"
            );
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("native reservation child exceeded its bounded lifetime");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let bytes = fs::read(scratch.0.join("abort-controller-pins")).unwrap();
    assert_eq!(bytes.len(), 160);
    Pins {
        run: RunId::new(u128::from_be_bytes(bytes[..16].try_into().unwrap())),
        commitment: bytes[16..48].try_into().unwrap(),
        reserved: read_position(&bytes[48..96]),
        current: read_position(&bytes[96..144]),
        effect: EffectId::new(u128::from_be_bytes(bytes[144..].try_into().unwrap())),
    }
}

fn copy_journal(scratch: &Scratch, label: &str) -> PathBuf {
    let destination = scratch.journal(label);
    for entry in fs::read_dir(scratch.0.join("journal")).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
    }
    destination
}

fn journal_path(directory: &Path, pins: Pins) -> PathBuf {
    directory.join(format!("{:032x}.fg-agent-journal", pins.run.value()))
}

fn append(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn abort(
    node: &OneNode,
    request: &NodeRequestContext,
    directory: &Path,
    pins: Pins,
    tail: EffectJournalPosition,
    principal: PrincipalId,
) -> Result<NativeRecoveredRefTransactionAbort, NativeRecoveredRefTransactionAbortRefusal> {
    node.runtime()
        .block_on(node.abort_recovered_agent_ref_transaction_for_principal_in(
            request,
            directory,
            pins.run,
            &pins.commitment,
            tail,
            pins.effect,
            principal,
            LogicalTime::new(10_001),
        ))
}

#[test]
fn cold_reserved_abort_recovers_partial_and_complete_suffixes_after_expiry() {
    for format in [Format::Sha1, Format::Sha256] {
        let scratch = Scratch::new();
        let pins = crashed(&scratch, format, "reserved");
        assert_eq!(pins.current, pins.reserved);
        let node = OneNode::open_existing(scratch.config(format)).unwrap();
        let request = node.request_context();
        let original = node
            .runtime()
            .block_on(node.recover_agent_journal_in(
                &request,
                &scratch.0.join("journal"),
                pins.run,
                &pins.commitment,
                pins.reserved,
            ))
            .unwrap();
        let now = LogicalTime::new(10_001);
        assert!(!original.original_run().is_open_at(now));
        let before = original.reconciliation_report(now).unwrap();
        assert!(before.has_unsettled_effects());
        let prepared = prepare_recovered_ref_transaction_abort(
            original.original_run(),
            original.journal(),
            pins.effect,
            now,
        )
        .unwrap();
        let expected = prepared.after_position();
        let authority = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        for (label, suffix) in [
            ("empty", &prepared.frame()[..0]),
            ("partial", &prepared.frame()[..prepared.frame().len() / 2]),
            ("complete", prepared.frame()),
        ] {
            let directory = copy_journal(&scratch, label);
            let path = journal_path(&directory, pins);
            append(&path, suffix);
            if !suffix.is_empty() {
                assert!(
                    node.runtime()
                        .block_on(node.recover_agent_journal_in(
                            &request,
                            &directory,
                            pins.run,
                            &pins.commitment,
                            pins.reserved,
                        ))
                        .is_err(),
                    "ordinary recovery must remain strict"
                );
            }
            let unchanged = fs::read(&path).unwrap();
            let locked = fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(&path)
                .unwrap();
            locked.try_lock().unwrap();
            assert!(matches!(
                abort(&node, &request, &directory, pins, pins.reserved, OWNER),
                Err(NativeRecoveredRefTransactionAbortRefusal::Journal(
                    crate::agent_journal::AgentJournalHostRefusal::Busy
                ))
            ));
            assert_eq!(fs::read(&path).unwrap(), unchanged);
            drop(locked);
            for (tail, already_aborted) in [
                (pins.reserved, false),
                (pins.reserved, false),
                (expected, true),
            ] {
                let unchanged = fs::read(&path).unwrap();
                assert!(matches!(
                    abort(
                        &node,
                        &request,
                        &directory,
                        pins,
                        tail,
                        PrincipalId::from_bytes([0x84; 16]),
                    ),
                    Err(NativeRecoveredRefTransactionAbortRefusal::Binding)
                ));
                assert_eq!(fs::read(&path).unwrap(), unchanged);
                let cancelled = node.request_context();
                cancelled.cancel();
                assert!(matches!(
                    abort(&node, &cancelled, &directory, pins, tail, OWNER),
                    Err(NativeRecoveredRefTransactionAbortRefusal::Journal(
                        crate::agent_journal::AgentJournalHostRefusal::Cancelled
                    ))
                ));
                assert_eq!(fs::read(&path).unwrap(), unchanged);
                let result = abort(&node, &request, &directory, pins, tail, OWNER).unwrap();
                assert_eq!(result.binding, *prepared.binding());
                assert_eq!(result.already_aborted, already_aborted);
                assert_eq!(result.recovered.journal().position(), expected);
                assert_eq!(result.recovered.original_run(), original.original_run());
                let report = result.recovered.reconciliation_report(now).unwrap();
                assert!(!report.has_unsettled_effects());
                assert!(!report.run_open_at_observation());
                assert_eq!(
                    report.cumulative_budget_reserved(),
                    before.cumulative_budget_reserved()
                );
                assert_eq!(report.cumulative_budget_consumed(), ResourceVector::ZERO);
                let record = &result.recovered.journal().records()[0];
                assert_eq!(record.obligation_state, ObligationState::Aborted);
                assert_eq!(
                    record.terminal_outcome,
                    Some(EffectTerminalOutcome::Aborted)
                );
                assert!(record.output_commitments.is_empty());
                assert_eq!(fs::metadata(&path).unwrap().len(), expected.bytes);
                assert_eq!(
                    node.runtime()
                        .block_on(node.authenticate_authority_head())
                        .unwrap()
                        .receipt(),
                    authority.receipt()
                );
            }
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn unknown_and_extra_suffixes_cannot_be_truncated_into_a_reserved_abort() {
    for format in [Format::Sha1, Format::Sha256] {
        let scratch = Scratch::new();
        let pins = crashed(&scratch, format, "reserved");
        let node = OneNode::open_existing(scratch.config(format)).unwrap();
        let request = node.request_context();
        let original = node
            .runtime()
            .block_on(node.recover_agent_journal_in(
                &request,
                &scratch.0.join("journal"),
                pins.run,
                &pins.commitment,
                pins.reserved,
            ))
            .unwrap();
        let prepared = prepare_recovered_ref_transaction_abort(
            original.original_run(),
            original.journal(),
            pins.effect,
            LogicalTime::new(10_001),
        )
        .unwrap();
        let mut extra = prepared.frame().to_vec();
        extra.push(0xff);
        for (label, suffix) in [("unknown", &[0x91][..]), ("extra", extra.as_slice())] {
            let directory = copy_journal(&scratch, label);
            let path = journal_path(&directory, pins);
            append(&path, suffix);
            let unchanged = fs::read(&path).unwrap();
            let error = abort(&node, &request, &directory, pins, pins.reserved, OWNER).unwrap_err();
            assert!(matches!(
                error,
                NativeRecoveredRefTransactionAbortRefusal::Persistence(ref failure)
                    if failure.reason() == EffectJournalPersistenceRefusal::Binding
            ));
            assert_eq!(fs::read(&path).unwrap(), unchanged);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn started_submission_refuses_abort_at_both_older_reserved_and_current_tails() {
    for format in [Format::Sha1, Format::Sha256] {
        let scratch = Scratch::new();
        let pins = crashed(&scratch, format, "started");
        assert!(pins.current.entries > pins.reserved.entries);
        let node = OneNode::open_existing(scratch.config(format)).unwrap();
        let request = node.request_context();
        let directory = scratch.0.join("journal");
        let path = journal_path(&directory, pins);
        let unchanged = fs::read(&path).unwrap();
        let authority = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let old = abort(&node, &request, &directory, pins, pins.reserved, OWNER).unwrap_err();
        assert!(matches!(
            old,
            NativeRecoveredRefTransactionAbortRefusal::Persistence(ref failure)
                if failure.reason() == EffectJournalPersistenceRefusal::Binding
        ));
        assert_eq!(fs::read(&path).unwrap(), unchanged);
        assert!(matches!(
            abort(&node, &request, &directory, pins, pins.current, OWNER),
            Err(NativeRecoveredRefTransactionAbortRefusal::Preparation(
                RefTransactionAbortRefusal::State(ObligationState::DeferredExternally)
            ))
        ));
        assert_eq!(fs::read(&path).unwrap(), unchanged);
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap()
                .receipt(),
            authority.receipt()
        );
        node.shutdown().unwrap();
    }
}
