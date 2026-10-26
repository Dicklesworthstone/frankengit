//! Real shared planner, seals, bounded batches, CAS and read-only recovery over
//! the reference authority. This is not native transport or power-loss evidence.
use super::*;
use crate::policy_bridge::receive_session::{
    self,
    recovery::{self, SessionRecovery, SessionRecoveryFailure},
};
use fgit_authority::{MemoryStoreConfig, RequestRejection, SealFailure, idempotency_binding_key};

fn configured(body_bytes: usize) -> (AsyncMemory, SharedCanonical, Projection) {
    let (mut store, staging, projection) = setup(&[]);
    let initial = read_basis(&store.inner, &context().head_key)
        .unwrap()
        .0
        .body()
        .clone();
    store.inner = MemoryAuthorityStore::with_config(MemoryStoreConfig {
        instance: StoreInstanceId::from_raw(112),
        limits: AuthorityLimits {
            immutable_slots: 262_144,
            body_bytes,
            ..AuthorityLimits::default()
        },
        ..MemoryStoreConfig::default()
    });
    initialize_repository(&store.inner, &context().head_key, &initial).unwrap();
    (store, staging, projection)
}
fn large_receive(store: &AsyncMemory, count: usize) -> BasisBoundValidatedReceive {
    // Absent deletes are actual independently committed no-ops. Keeping the
    // ref state empty isolates session capacity from quadratic full-ref fixture
    // storage; mixed create/refusal semantics are covered by adjacent tests.
    validated(
        store,
        (0..count)
            .rev()
            .map(|n| command(&format!("refs/heads/session-{n:05}"), 0, 0))
            .collect(),
        true,
    )
}
fn descriptor_key() -> ImmutableKey {
    let context = context();
    let mut key = b"fg/receive-session/v1/".to_vec();
    key.extend_from_slice(context.tenant_id.as_bytes());
    key.extend_from_slice(context.repository_id.as_bytes());
    key.extend_from_slice(context.principal_id.as_bytes());
    key.extend_from_slice(context.idempotency_key.digest().bytes().as_bytes());
    ImmutableKey::new(key).unwrap()
}
fn original_binding_key() -> ImmutableKey {
    let context = context();
    idempotency_binding_key(
        context.tenant_id,
        context.repository_id,
        context.principal_id,
        &context.idempotency_key,
    )
    .unwrap()
}
fn present(store: &MemoryAuthorityStore, key: &ImmutableKey) -> Vec<u8> {
    let ImmutableRead::Present(bytes) = store.read_immutable(key).unwrap() else {
        panic!("expected stored body")
    };
    bytes
}
fn reuse(error: &receive_session::InterruptedSession) -> bool {
    matches!(error.admission_error(), AdmissionError::Seal(failure)
        if matches!(failure.as_ref(), SealFailure::Rejected(rejection)
            if matches!(rejection.as_ref(), RequestRejection::IdempotencyKeyReuse { .. })))
}

#[test]
fn complete_4097_and_16384_sessions_keep_independent_decisions_and_recover_exactly() {
    for count in [MAX_ADMISSION_COMMANDS + 1, MAX_RECEIVE_SESSION_COMMANDS] {
        let (store, staging, projection) = configured(AuthorityLimits::default().body_bytes);
        let receive = large_receive(&store, count);
        let result = run(&store, &projection, &receive).unwrap();
        assert_eq!(result.commands.len(), count);
        assert!(
            result.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        assert!(current_refs(&store, &staging).is_empty());
        let batches = count.div_ceil(crate::microbatch::MAX_BATCH_DECISIONS);
        assert_eq!(store.publications.load(Ordering::SeqCst), batches);
        // This reference projection stages its canonical evidence separately in
        // SharedCanonical. Authority slots here are original+descriptor, one
        // child binding/seal/outcome per command, and batch+head per CAS. The
        // production durable-evidence slot budget is deliberately larger.
        assert_eq!(
            store.immutable_created.load(Ordering::SeqCst),
            3 * count + 2 * batches + 2
        );
        assert!(store.immutable_created.load(Ordering::SeqCst) < store.limits().immutable_slots);
        let binding = present(&store.inner, &original_binding_key());
        let mut input = Decoder::new(&binding, fgit_codec::DecodeLimits::DEFAULT);
        let identity =
            TxId::from_internal_object_id(input.read_internal_object_id().unwrap()).unwrap();
        input.finish().unwrap();
        let whole_seal =
            fgit_authority::seal_key(context().tenant_id, context().repository_id, identity)
                .unwrap();
        assert!(
            matches!(
                store.inner.read_immutable(&whole_seal).unwrap(),
                ImmutableRead::Absent
            ),
            "a session carrier must never mint a whole-session seal"
        );
        let last =
            receive_session::non_atomic_command_key(&context().idempotency_key, count - 1).unwrap();
        let recovered_last = ready(fgit_authority::key_recovery::recover_request_async(
            &store,
            &(),
            &context().head_key,
            fgit_authority::key_recovery::RecoveryScope {
                tenant_id: context().tenant_id,
                repository_id: context().repository_id,
                principal_id: context().principal_id,
            },
            &last,
            &|| Ok(()),
        ))
        .unwrap();
        assert_eq!(
            recovered_last.terminal(),
            Some(result.commands[count - 1].terminal)
        );
        store.immutable_reads.store(0, Ordering::SeqCst);
        store.head_reads.store(0, Ordering::SeqCst);
        let SessionRecovery::Recovered(recovered) =
            ready(recovery::recover(&store, &(), &context(), &|| Ok(()))).unwrap()
        else {
            panic!("session descriptor exists")
        };
        assert!(recovered.all_terminal());
        assert_eq!(recovered.identity(), identity);
        assert_eq!(recovered.commands().len(), count);
        for (index, command) in recovered.commands().iter().enumerate() {
            assert_eq!(command.index(), index);
            assert_eq!(
                command.reference().as_bytes(),
                receive.validated.request.commands[index].ref_name
            );
            assert_eq!(
                command.recovery().terminal(),
                Some(result.commands[index].terminal)
            );
        }
        // One canonical batch/head walk serves every child. This count includes
        // original+descriptor verification, descriptor child bindings and the
        // authority's independent binding/seal/accelerator checks.
        assert_eq!(
            store.immutable_reads.load(Ordering::SeqCst),
            4 * count + 2 * batches + 3
        );
        assert_eq!(store.head_reads.load(Ordering::SeqCst), 3);
        if count == MAX_ADMISSION_COMMANDS + 1 {
            assert_eq!(run(&store, &projection, &receive).unwrap(), result);
            assert_eq!(
                store.publications.load(Ordering::SeqCst),
                batches,
                "retry adds no decision"
            );
        }
    }
}

#[test]
fn changed_large_session_or_cross_version_retry_is_rejected_before_new_child_binding() {
    for initial_count in [MAX_ADMISSION_COMMANDS, MAX_ADMISSION_COMMANDS + 1] {
        let (store, _, projection) = configured(AuthorityLimits::default().body_bytes);
        let original = large_receive(&store, initial_count);
        store.interrupt_put_at.store(2, Ordering::SeqCst); // Original key exists; no child exists.
        assert!(run(&store, &projection, &original).is_err());
        assert_eq!(store.immutable_created.load(Ordering::SeqCst), 1);
        for mutation in 0..5 {
            if initial_count == MAX_ADMISSION_COMMANDS && mutation == 0 {
                continue;
            }
            let mut commands = original.validated.request.commands.clone();
            match mutation {
                0 => commands.swap(0, 1),
                1 => commands.push(command("refs/heads/appended", 0, 0)),
                2 => {
                    commands.pop();
                }
                3 => commands[0].new = oid(7),
                _ => {}
            }
            let mut changed = validated(&store, commands, true);
            if mutation == 4 {
                changed
                    .validated
                    .request
                    .push_options
                    .push(b"changed-option".to_vec());
            }
            let error = run(&store, &projection, &changed).unwrap_err();
            assert!(
                reuse(&error),
                "count {initial_count}, mutation {mutation}: {error}"
            );
            assert_eq!(store.publications.load(Ordering::SeqCst), 0);
            assert_eq!(store.immutable_created.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn interrupted_original_child_and_descriptor_writes_remain_retryable_without_partial_publication() {
    let count = MAX_ADMISSION_COMMANDS + 1;
    for (at, lost_response) in [
        (1, false),
        (2, false),
        (count + 2, false),
        (count + 2, true),
    ] {
        let (store, _, projection) = configured(AuthorityLimits::default().body_bytes);
        let receive = large_receive(&store, count);
        if lost_response {
            store.lose_put_response_at.store(at, Ordering::SeqCst);
        } else {
            store.interrupt_put_at.store(at, Ordering::SeqCst);
        }
        let interrupted = run(&store, &projection, &receive).unwrap_err();
        assert!(interrupted.completed_commands().is_empty());
        assert_eq!(store.publications.load(Ordering::SeqCst), 0);
        let observation = ready(recovery::recover(&store, &(), &context(), &|| Ok(()))).unwrap();
        if lost_response {
            let SessionRecovery::Recovered(known) = observation else {
                panic!("lost descriptor response still stored the descriptor")
            };
            assert_eq!(known.commands().len(), count);
            assert!(!known.all_terminal());
        } else {
            assert_eq!(observation, SessionRecovery::NotObserved);
        }
        let resumed = run(&store, &projection, &receive).unwrap();
        assert_eq!(&resumed.session, interrupted.session().unwrap());
        assert!(
            resumed.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        assert_eq!(
            store.publications.load(Ordering::SeqCst),
            count.div_ceil(crate::microbatch::MAX_BATCH_DECISIONS)
        );
    }
}

#[test]
fn recovery_refuses_validly_reencoded_chunk_or_permutation_with_the_wrong_original_binding() {
    let count = MAX_ADMISSION_COMMANDS + 1;
    let (source, _, projection) = configured(AuthorityLimits::default().body_bytes);
    let receive = large_receive(&source, count);
    source
        .lose_put_response_at
        .store(count + 2, Ordering::SeqCst);
    assert!(run(&source, &projection, &receive).is_err());
    let original_binding = present(&source.inner, &original_binding_key());
    let original_descriptor = present(&source.inner, &descriptor_key());
    for mutation in 0..2 {
        let (store, _, _) = configured(AuthorityLimits::default().body_bytes);
        store
            .inner
            .put_if_absent(&original_binding_key(), &original_binding)
            .unwrap();
        let mut changed = original_descriptor.clone();
        if mutation == 0 {
            let start = changed.len() - count * size_of::<u16>();
            let first = [changed[start], changed[start + 1]];
            changed[start] = changed[start + 2];
            changed[start + 1] = changed[start + 3];
            changed[start + 2] = first[0];
            changed[start + 3] = first[1];
        } else {
            let name = b"refs/heads/session-00000";
            let start = changed
                .windows(name.len())
                .position(|bytes| bytes == name)
                .unwrap();
            changed[start + name.len() - 1] = b'-'; // Still unique, valid and globally sorted.
        }
        store
            .inner
            .put_if_absent(&descriptor_key(), &changed)
            .unwrap();
        assert!(matches!(
            ready(recovery::recover(&store, &(), &context(), &|| Ok(()))),
            Err(SessionRecoveryFailure::Integrity("descriptor/key binding"))
        ));
        assert_eq!(store.publications.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn a_smaller_backend_body_budget_and_cancelled_preflight_reserve_no_session_key() {
    let count = MAX_ADMISSION_COMMANDS + 1;
    let (store, _, projection) = configured(64 * 1024);
    let receive = large_receive(&store, count);
    let error = run(&store, &projection, &receive).unwrap_err();
    assert!(
        matches!(error.admission_error(), AdmissionError::SessionDescriptorBytesExceeded { limit, observed } if *limit == 64 * 1024 && observed > limit)
    );
    assert_eq!(store.put_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        store.inner.read_immutable(&original_binding_key()).unwrap(),
        ImmutableRead::Absent
    ));
    let (permitted, _, permitted_projection) = configured(AuthorityLimits::default().body_bytes);
    let twin = large_receive(&permitted, count);
    permitted_projection.interrupt_at.store(1, Ordering::SeqCst);
    let stopped = run(&permitted, &permitted_projection, &twin).unwrap_err();
    assert!(matches!(
        stopped.admission_error(),
        AdmissionError::AsyncProjectionUnavailable(RefusalCode::CancellationInProgress)
    ));
    assert!(!present(&permitted.inner, &descriptor_key()).is_empty());
    let (cancelled, _, projection) = configured(AuthorityLimits::default().body_bytes);
    let receive = large_receive(&cancelled, count);
    let probes = AtomicUsize::new(0);
    let checkpoint = || {
        if probes.fetch_add(1, Ordering::SeqCst) >= 17 {
            Err(RefusalCode::CancellationInProgress)
        } else {
            Ok(())
        }
    };
    let error = ready(receive_session::admit_with_checkpoint(
        &cancelled,
        &(),
        &context(),
        &receive,
        AdmissionLimits::default(),
        &projection,
        &checkpoint,
    ))
    .unwrap_err();
    assert!(matches!(
        error.admission_error(),
        AdmissionError::AsyncProjectionUnavailable(RefusalCode::CancellationInProgress)
    ));
    assert!(error.session().is_none());
    assert_eq!(cancelled.put_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_cancelled_child_binding_loop_keeps_retryable_keys_and_no_published_prefix() {
    let (store, _, projection) = configured(AuthorityLimits::default().body_bytes);
    let receive = large_receive(&store, MAX_ADMISSION_COMMANDS + 1);
    let checkpoint = || {
        if store.put_calls.load(Ordering::SeqCst) >= 2 {
            Err(RefusalCode::ResourceBudgetExceeded)
        } else {
            Ok(())
        }
    };
    let error = ready(receive_session::admit_with_checkpoint(
        &store,
        &(),
        &context(),
        &receive,
        AdmissionLimits::default(),
        &projection,
        &checkpoint,
    ))
    .unwrap_err();
    assert!(matches!(
        error.admission_error(),
        AdmissionError::AsyncProjectionUnavailable(RefusalCode::ResourceBudgetExceeded)
    ));
    assert!(error.completed_commands().is_empty());
    assert_eq!(store.immutable_created.load(Ordering::SeqCst), 2);
    assert_eq!(store.publications.load(Ordering::SeqCst), 0);
    assert_eq!(
        ready(recovery::recover(&store, &(), &context(), &|| Ok(()))).unwrap(),
        SessionRecovery::NotObserved
    );
    let resumed = run(&store, &projection, &receive).unwrap();
    assert_eq!(&resumed.session, error.session().unwrap());
    assert!(
        resumed
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
}
