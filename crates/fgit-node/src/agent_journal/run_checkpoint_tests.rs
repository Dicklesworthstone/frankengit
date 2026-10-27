#![forbid(unsafe_code)]
//! Reference-authority authentication and the exact native checkpoint/journal
//! file modules. These are real file operations, not persisted-node evidence.

use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use fgit_agent::{
    AgentInstanceId, AuthorityReadReceipt, Capability, CapabilityId, ClassSet,
    CurrentAuthorityRevocationCheckedEffectBroker, EffectId, EffectRequest, IntentRun, LogicalTime,
    OperationClass, RunId,
    run_checkpoint::{
        MAX_RUN_CHECKPOINT_BYTES, MAX_RUN_CHECKPOINT_HEAD_BYTES, RunCheckpoint,
        RunCheckpointRefusal,
    },
};
use fgit_authority::{
    AuthenticatedHead, AuthorityStore, AuthorityVersionToken, CasOutcome, HeadInit, HeadKey,
    HeadReadReceipt, MemoryAuthorityStore, StoreInstanceId, authority_head_identity,
    initialize_repository, outcome_index_root,
};
use fgit_codec::{RepositoryAuthorityHeadBody, encode_body};
use fgit_resource::{Grade, RegionId, ResourceVector};
use fgit_types::{HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryId};

use super::{checkpoint, file};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-run-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (MemoryAuthorityStore, HeadKey, AuthenticatedHead, IntentRun) {
    let root = outcome_index_root(&[]).unwrap();
    let body = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([29; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(337));
    let key = HeadKey::new(b"run-checkpoint-reference".to_vec()).unwrap();
    let HeadInit::Created(read) = initialize_repository(&store, &key, &body).unwrap() else {
        panic!("fresh store");
    };
    let authenticated = store.authenticate_head_receipt(&read).unwrap();
    let authority = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(7),
        [19; 32],
    )
    .unwrap();
    let mut budget = ResourceVector::ZERO;
    for (i, grade) in Grade::ALL.into_iter().enumerate() {
        budget = budget.with(grade, 500 + i as u64);
    }
    let run = IntentRun::new_authenticated(
        RunId::new(91),
        authority,
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        budget,
        LogicalTime::new(100),
    )
    .unwrap();
    (store, key, authenticated, run)
}

#[test]
fn exact_original_run_restores_after_authority_advancement_and_expiry() {
    let (store, key, authenticated, run) = fixture();
    let expected = *run.commitment().unwrap().as_bytes();
    let bytes = RunCheckpoint::capture(&run, &authenticated)
        .unwrap()
        .encode()
        .unwrap();
    let original = run;
    let mut next = authenticated.body().unwrap();
    next.predecessor_head_id = Some(authority_head_identity(&next).unwrap());
    next.generation = HeadGeneration::try_new(2).unwrap();
    assert!(matches!(
        store
            .compare_exchange_head(
                &key,
                authenticated.receipt().token(),
                next.generation,
                &encode_body(&next).unwrap()
            )
            .unwrap(),
        CasOutcome::Committed(_)
    ));
    let saved = RunCheckpoint::decode(&bytes).unwrap();
    assert_eq!(saved.encode().unwrap(), bytes);
    let restored = saved.restore(&store, &key, &expected).unwrap();
    assert_eq!(restored, original);
    assert!(!restored.is_open_at(LogicalTime::new(101)));
    assert_eq!(
        restored
            .authority_read_receipt()
            .unwrap()
            .authority_head_generation(),
        HeadGeneration::FIRST
    );
}

#[test]
fn checkpoint_never_authenticates_a_forged_or_foreign_backend_receipt() {
    let (store, key, authenticated, run) = fixture();
    let saved = RunCheckpoint::capture(&run, &authenticated).unwrap();
    let expected = *run.commitment().unwrap().as_bytes();
    let foreign = MemoryAuthorityStore::new(StoreInstanceId::from_raw(338));
    assert!(matches!(
        saved.restore(&foreign, &key, &expected),
        Err(RunCheckpointRefusal::Authority(_))
    ));
    assert!(matches!(
        saved.restore(
            &store,
            &HeadKey::new(b"another-slot".to_vec()).unwrap(),
            &expected
        ),
        Err(RunCheckpointRefusal::Binding)
    ));
    let forged = HeadReadReceipt::new(
        key.clone(),
        AuthorityVersionToken::from_opaque_bytes([44; 16]),
        authenticated.receipt().generation(),
        authenticated.receipt().body().to_vec(),
    );
    let forged = AuthenticatedHead::new(forged, authenticated.verified_against());
    let authority =
        AuthorityReadReceipt::from_authenticated_head(&forged, LogicalTime::new(7), [19; 32])
            .unwrap();
    let untrusted = IntentRun::new_authenticated(
        run.run_id(),
        authority,
        run.allowed_operation_classes(),
        run.resource_budget(),
        run.expiry(),
    )
    .unwrap();
    let checkpoint = RunCheckpoint::capture(&untrusted, &forged).unwrap();
    assert!(matches!(
        checkpoint.restore(&store, &key, untrusted.commitment().unwrap().as_bytes()),
        Err(RunCheckpointRefusal::Authority(_))
    ));
    assert_eq!(saved.restore(&store, &key, &expected).unwrap(), run);
}

#[test]
fn complete_run_pin_rejects_rewritten_scope_budget_expiry_and_read_observation() {
    let (store, key, authenticated, run) = fixture();
    let expected = *run.commitment().unwrap().as_bytes();
    let mut candidates = vec![
        IntentRun::new_authenticated(
            run.run_id(),
            run.authority_read_receipt().unwrap().clone(),
            ClassSet::from_classes(&[
                OperationClass::ReadCanonicalObject,
                OperationClass::ExternalIntegration,
            ]),
            run.resource_budget(),
            run.expiry(),
        )
        .unwrap(),
        IntentRun::new_authenticated(
            run.run_id(),
            run.authority_read_receipt().unwrap().clone(),
            run.allowed_operation_classes(),
            run.resource_budget().with(Grade::MoneyMicros, 9999),
            run.expiry(),
        )
        .unwrap(),
        IntentRun::new_authenticated(
            run.run_id(),
            run.authority_read_receipt().unwrap().clone(),
            run.allowed_operation_classes(),
            run.resource_budget(),
            LogicalTime::new(1000),
        )
        .unwrap(),
    ];
    let changed_read = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(8),
        [20; 32],
    )
    .unwrap();
    candidates.push(
        IntentRun::new_authenticated(
            run.run_id(),
            changed_read,
            run.allowed_operation_classes(),
            run.resource_budget(),
            run.expiry(),
        )
        .unwrap(),
    );
    for changed in candidates {
        let saved = RunCheckpoint::capture(&changed, &authenticated).unwrap();
        assert!(matches!(
            saved.restore(&store, &key, &expected),
            Err(RunCheckpointRefusal::Binding)
        ));
        // Even replacing the checkpoint's claimed commitment with the known
        // original one cannot turn changed fields into that original run.
        let mut bytes = saved.encode().unwrap();
        let offset = b"frankengit-agent-run-checkpoint\0".len() + 1 + 16;
        bytes[offset..offset + 32].copy_from_slice(&expected);
        let saved = RunCheckpoint::decode(&bytes).unwrap();
        assert!(matches!(
            saved.restore(&store, &key, &expected),
            Err(RunCheckpointRefusal::Binding)
        ));
    }
    assert_eq!(
        RunCheckpoint::capture(&run, &authenticated)
            .unwrap()
            .restore(&store, &key, &expected)
            .unwrap(),
        run
    );
}

#[test]
fn different_original_head_cannot_be_paired_with_a_run() {
    let (store, key, authenticated, run) = fixture();
    let mut next = authenticated.body().unwrap();
    next.predecessor_head_id = Some(authority_head_identity(&next).unwrap());
    next.generation = HeadGeneration::try_new(2).unwrap();
    let CasOutcome::Committed(read) = store
        .compare_exchange_head(
            &key,
            authenticated.receipt().token(),
            next.generation,
            &encode_body(&next).unwrap(),
        )
        .unwrap()
    else {
        panic!("head advance");
    };
    let later = store.authenticate_head_receipt(&read).unwrap();
    assert!(matches!(
        RunCheckpoint::capture(&run, &later),
        Err(RunCheckpointRefusal::Binding)
    ));
    assert!(RunCheckpoint::capture(&run, &authenticated).is_ok());
}

#[test]
fn every_truncation_unknown_version_extra_suffix_and_oversized_input_refuse() {
    let (_, _, authenticated, run) = fixture();
    let bytes = RunCheckpoint::capture(&run, &authenticated)
        .unwrap()
        .encode()
        .unwrap();
    for n in 0..bytes.len() {
        assert!(RunCheckpoint::decode(&bytes[..n]).is_err(), "prefix {n}");
    }
    let mut changed = bytes.clone();
    changed[b"frankengit-agent-run-checkpoint\0".len()] = 2;
    assert!(matches!(
        RunCheckpoint::decode(&changed),
        Err(RunCheckpointRefusal::Format)
    ));
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(matches!(
        RunCheckpoint::decode(&changed),
        Err(RunCheckpointRefusal::Format)
    ));
    assert!(matches!(
        RunCheckpoint::decode(&vec![0; MAX_RUN_CHECKPOINT_BYTES + 1]),
        Err(RunCheckpointRefusal::Limit)
    ));
    let prefix = b"frankengit-agent-run-checkpoint\0".len() + 1 + 16 + 32 + 8;
    let mut changed = bytes.clone();
    changed[prefix..prefix + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(matches!(
        RunCheckpoint::decode(&changed),
        Err(RunCheckpointRefusal::Limit)
    ));
    let body_length = prefix + 2 + authenticated.receipt().key().as_bytes().len() + 16 + 8;
    let mut changed = bytes.clone();
    changed[body_length..body_length + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        RunCheckpoint::decode(&changed),
        Err(RunCheckpointRefusal::Limit)
    ));
    let oversized = AuthenticatedHead::new(
        HeadReadReceipt::new(
            authenticated.receipt().key().clone(),
            authenticated.receipt().token(),
            authenticated.receipt().generation(),
            vec![0; MAX_RUN_CHECKPOINT_HEAD_BYTES + 1],
        ),
        authenticated.verified_against(),
    );
    assert!(matches!(
        RunCheckpoint::capture(&run, &oversized),
        Err(RunCheckpointRefusal::Limit)
    ));
    assert_eq!(
        RunCheckpoint::decode(&bytes).unwrap().encode().unwrap(),
        bytes
    );
}

#[test]
fn actual_files_restore_journal_without_the_original_run_object() {
    let scratch = Scratch::new();
    let (store, key, authenticated, run) = fixture();
    let run_id = run.run_id();
    let expected = *run.commitment().unwrap().as_bytes();
    checkpoint::create(
        &scratch.0,
        &RunCheckpoint::capture(&run, &authenticated).unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    let sink = file::FileEffectJournal::create(&scratch.0, &run, Box::new(|| Ok(()))).unwrap();
    let capability = Capability::issue(
        CapabilityId::new(1),
        run.allowed_operation_classes(),
        run.resource_budget(),
        LogicalTime::new(7),
        run.expiry(),
    )
    .unwrap();
    let mut broker = CurrentAuthorityRevocationCheckedEffectBroker::open_with_journal(
        run,
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap();
    let grant = broker
        .request_low_risk(
            &capability,
            LogicalTime::new(9),
            &EffectRequest {
                effect_id: EffectId::new(1),
                parent_effect_id: None,
                operation: OperationClass::ReadCanonicalObject,
                cost: ResourceVector::single(Grade::Bytes, 64),
                input_commitment: [54; 32],
            },
        )
        .unwrap();
    assert_eq!(
        broker.abort_low_risk(grant).unwrap().amount(),
        ResourceVector::single(Grade::Bytes, 64)
    );
    let tail = broker.durable_position().unwrap().unwrap();
    assert!(broker.close().is_quiescent());
    drop(authenticated);
    let saved = checkpoint::read(&scratch.0, run_id, &expected, &|| Ok(())).unwrap();
    let restored = saved.restore(&store, &key, &expected).unwrap();
    let history = file::recover(&scratch.0, &restored, Some(tail), &|| Ok(())).unwrap();
    let report = history
        .reconciliation_report(&restored, LogicalTime::new(200))
        .unwrap();
    assert_eq!(report.counts().aborted(), 1);
    assert!(!report.run_open_at_observation());
    assert_eq!(report.run_commitment().as_bytes(), &expected);
    let mut incorrect_tail = tail;
    incorrect_tail.entries += 1;
    assert!(file::recover(&scratch.0, &restored, Some(incorrect_tail), &|| Ok(())).is_err());
    assert!(matches!(
        checkpoint::create(&scratch.0, &saved, &|| Ok(())),
        Err(file::AgentJournalHostRefusal::Exists)
    ));
}

#[test]
fn native_checkpoint_refuses_cancellation_replacement_and_wrong_run_pin() {
    let scratch = Scratch::new();
    let (_, _, authenticated, run) = fixture();
    let saved = RunCheckpoint::capture(&run, &authenticated).unwrap();
    assert!(matches!(
        checkpoint::create(&scratch.0, &saved, &|| Err(
            file::AgentJournalHostRefusal::Cancelled
        )),
        Err(file::AgentJournalHostRefusal::Cancelled)
    ));
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    let checks = Cell::new(0);
    assert!(matches!(
        checkpoint::create(&scratch.0, &saved, &|| {
            checks.set(checks.get() + 1);
            if checks.get() == 3 {
                Err(file::AgentJournalHostRefusal::Cancelled)
            } else {
                Ok(())
            }
        }),
        Err(file::AgentJournalHostRefusal::Cancelled)
    ));
    // Cancellation after sync is not evidence that the file does not exist.
    let pin = *run.commitment().unwrap().as_bytes();
    assert_eq!(
        checkpoint::read(&scratch.0, run.run_id(), &pin, &|| Ok(())).unwrap(),
        saved
    );
    assert!(matches!(
        checkpoint::read(&scratch.0, run.run_id(), &[99; 32], &|| Ok(())),
        Err(file::AgentJournalHostRefusal::Binding)
    ));
    assert!(matches!(
        checkpoint::create(&scratch.0, &saved, &|| Ok(())),
        Err(file::AgentJournalHostRefusal::Exists)
    ));
}

#[test]
fn native_checkpoint_refuses_truncation_oversize_and_symlink() {
    let scratch = Scratch::new();
    let (_, _, authenticated, run) = fixture();
    let saved = RunCheckpoint::capture(&run, &authenticated).unwrap();
    let path = scratch
        .0
        .join(format!("{:032x}.fg-agent-run", run.run_id().value()));
    let pin = *run.commitment().unwrap().as_bytes();
    checkpoint::create(&scratch.0, &saved, &|| Ok(())).unwrap();
    fs::write(&path, &saved.encode().unwrap()[..30]).unwrap();
    assert!(checkpoint::read(&scratch.0, run.run_id(), &pin, &|| Ok(())).is_err());
    fs::write(&path, vec![0; MAX_RUN_CHECKPOINT_BYTES + 1]).unwrap();
    assert!(matches!(
        checkpoint::read(&scratch.0, run.run_id(), &pin, &|| Ok(())),
        Err(file::AgentJournalHostRefusal::Limit)
    ));
    #[cfg(unix)]
    {
        fs::remove_file(&path).unwrap();
        let target = scratch.0.join("actual");
        fs::write(&target, saved.encode().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, &path).unwrap();
        assert!(matches!(
            checkpoint::read(&scratch.0, run.run_id(), &pin, &|| Ok(())),
            Err(file::AgentJournalHostRefusal::Path)
        ));
    }
}
