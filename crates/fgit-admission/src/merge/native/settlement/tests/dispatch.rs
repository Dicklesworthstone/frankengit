//! Actual authority publication with scripted transport observations. These
//! exercise CAS/recovery semantics; the CLI tests separately exercise real HTTP.
use super::*;
use crate::merge::native::dispatch::{
    DispatchResult, DispatchRoute, DispatchTransport, dispatch_outbox_async,
};

struct Routes {
    definitions: Vec<DispatchRoute>,
    outcomes: VecDeque<DeliveryVerdict>,
    calls: Vec<(u64, u32)>,
    probes: usize,
    stopped: Option<Arc<AtomicBool>>,
}
impl Routes {
    fn new(count: u64, outcomes: impl IntoIterator<Item = DeliveryVerdict>) -> Self {
        Self {
            definitions: (1..=count)
                .map(|id| DispatchRoute {
                    id,
                    binding: digest_of(id as u8),
                    max_attempts: 2,
                    initial_delay_millis: 100,
                    max_delay_millis: 100,
                })
                .collect(),
            outcomes: outcomes.into_iter().collect(),
            calls: vec![],
            probes: 0,
            stopped: None,
        }
    }
}
impl DispatchTransport<()> for Routes {
    fn destination(&self) -> AsciiSlug {
        AsciiSlug::from_static("forge-projection")
    }
    fn routes(&self) -> &[DispatchRoute] {
        &self.definitions
    }
    fn deliver<'a>(
        &'a mut self,
        (): &'a (),
        route: u64,
        _: &'a DeliveryRequest<'_>,
        attempt: u32,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> impl Future<Output = Result<(DeliveryVerdict, Vec<u8>), RefusalCode>> + 'a {
        async move {
            checkpoint()?;
            self.calls.push((route, attempt));
            if let Some(stop) = &self.stopped {
                stop.store(true, Ordering::SeqCst);
            }
            Ok((
                self.outcomes.pop_front().expect("unexpected send"),
                b"actual scripted observation".to_vec(),
            ))
        }
    }
    fn probe<'a>(
        &'a mut self,
        (): &'a (),
        _: u64,
        _: &'a DeliveryRequest<'_>,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> impl Future<Output = Result<(ProbeVerdict, Vec<u8>), RefusalCode>> + 'a {
        async move {
            checkpoint()?;
            self.probes += 1;
            Ok((ProbeVerdict::Unknown, b"non-probing weak receiver".to_vec()))
        }
    }
}
fn drive(
    f: &Fixture,
    routes: &mut Routes,
    allowance: u32,
    at: u64,
) -> Result<DispatchResult, AdmissionError> {
    run(dispatch_outbox_async(
        &f.store,
        &(),
        &f.context,
        f.key,
        &f.projection(MaterializationFault::None),
        routes,
        allowance,
        Default::default(),
        &|| {
            if f.store.stopped.load(Ordering::SeqCst) {
                Err(RefusalCode::CancellationInProgress)
            } else {
                Ok(())
            }
        },
        &|| Ok(at),
    ))
}
#[test]
fn weak_route_set_retires_atomically_and_recovers_original_outcome_without_io() {
    for verdict in [
        DeliveryVerdict::Accepted,
        DeliveryVerdict::PermanentRejection,
    ] {
        let f = Fixture::new();
        let before = f.basis().id();
        let mut routes = Routes::new(1, [verdict]);
        let first = drive(&f, &mut routes, 1, 100).unwrap();
        assert_ne!(f.basis().id(), before);
        assert_eq!(routes.calls, [(1, 1)]);
        assert!(first.progress.finished_effect_root().is_some());
        let expected = if verdict == DeliveryVerdict::Accepted {
            ObligationState::Acknowledged
        } else {
            ObligationState::TerminallyFailed
        };
        assert_eq!(first.effect.as_ref().unwrap().state(), expected);
        assert!(
            run(delivery::read_in(&f.store, &(), &f.basis(), &|| false))
                .unwrap()
                .outbox
                .entries()
                .is_empty()
        );
        assert_eq!(f.effect(), first.effect.clone().unwrap());
        let selected = f.basis().id();
        let resumed = drive(&f, &mut routes, 1, 101).unwrap();
        assert_eq!(resumed.effect, first.effect);
        assert_eq!(resumed.sends, 0);
        assert_eq!(routes.probes, 0);
        assert_eq!(f.basis().id(), selected);
    }
}
#[test]
fn delivered_member_keeps_sibling_pending_across_invocations_and_backoff() {
    let f = Fixture::new();
    let mut routes = Routes::new(
        2,
        [
            DeliveryVerdict::Accepted,
            DeliveryVerdict::TransientFailure,
            DeliveryVerdict::Accepted,
        ],
    );
    let first = drive(&f, &mut routes, 2, 100).unwrap();
    assert!(first.effect.is_none());
    assert_eq!(routes.calls, [(1, 1), (2, 1)]);
    assert_eq!(f.effect().state(), ObligationState::DeferredExternally);
    let same = f.basis().id();
    assert_eq!(drive(&f, &mut routes, 2, 100).unwrap().sends, 0);
    assert_eq!(same, f.basis().id());
    let second = drive(&f, &mut routes, 2, 1000).unwrap();
    assert_eq!(
        second.effect.unwrap().state(),
        ObligationState::Acknowledged
    );
    assert_eq!(routes.calls, [(1, 1), (2, 1), (2, 2)]);
}
#[test]
fn stopped_after_canonical_marker_never_sends_on_recovery_and_keeps_unknown_active() {
    let f = Fixture::new();
    let mut routes = Routes::new(1, []);
    f.stop_after(StopAfter::InFlight(1));
    assert!(drive(&f, &mut routes, 1, 100).is_err());
    assert!(routes.calls.is_empty());
    f.resume();
    let resumed = drive(&f, &mut routes, 1, 101).unwrap();
    assert_eq!(resumed.effect.unwrap().state(), ObligationState::Escalated);
    assert_eq!(routes.probes, 1);
    assert!(routes.calls.is_empty());
    assert_eq!(
        run(delivery::read_in(&f.store, &(), &f.basis(), &|| false))
            .unwrap()
            .outbox
            .entries()
            .len(),
        1
    );
}
#[test]
fn lost_post_send_observation_escalates_instead_of_replaying_a_possibly_accepted_send() {
    let f = Fixture::new();
    let mut routes = Routes::new(1, [DeliveryVerdict::Accepted]);
    routes.stopped = Some(Arc::clone(&f.store.stopped));
    assert!(drive(&f, &mut routes, 1, 100).is_err());
    assert_eq!(routes.calls, [(1, 1)]);
    f.resume();
    routes.stopped = None;
    let recovered = drive(&f, &mut routes, 10, 101).unwrap();
    assert_eq!(
        recovered.effect.unwrap().state(),
        ObligationState::Escalated
    );
    assert_eq!(routes.calls, [(1, 1)]);
    assert_eq!(routes.probes, 1);
}
#[test]
fn persisted_observation_can_finish_after_cancellation_without_resending() {
    let f = Fixture::new();
    let mut routes = Routes::new(1, [DeliveryVerdict::Accepted]);
    f.stop_after(StopAfter::Terminal);
    assert!(drive(&f, &mut routes, 1, 100).is_err());
    f.resume();
    let recovered = drive(&f, &mut routes, 1, 101).unwrap();
    assert_eq!(
        recovered.effect.unwrap().state(),
        ObligationState::Acknowledged
    );
    assert_eq!(routes.calls, [(1, 1)]);
    assert_eq!(routes.probes, 0);
}
#[test]
fn owner_policy_and_route_membership_changes_refuse_without_io_or_authority_change() {
    let f = Fixture::new();
    let mut routes = Routes::new(1, []);
    drive(&f, &mut routes, 0, 100).unwrap();
    let before = f.basis().id();
    routes.definitions[0].max_attempts = 3;
    assert!(drive(&f, &mut routes, 1, 101).is_err());
    routes.definitions[0].max_attempts = 2;
    let mut context = f.context.clone();
    context.principal_id = PrincipalId::from_bytes([77; 16]);
    assert!(
        run(dispatch_outbox_async(
            &f.store,
            &(),
            &context,
            f.key,
            &f.projection(MaterializationFault::None),
            &mut routes,
            1,
            Default::default(),
            &|| Ok(()),
            &|| Ok(101)
        ))
        .is_err()
    );
    routes.definitions.push(DispatchRoute {
        id: 2,
        ..routes.definitions[0].clone()
    });
    assert!(drive(&f, &mut routes, 1, 101).is_err());
    assert!(routes.calls.is_empty());
    assert_eq!(before, f.basis().id());
}
#[test]
fn strong_driver_cannot_take_over_weak_route_progress() {
    let f = Fixture::new();
    drive(&f, &mut Routes::new(1, []), 0, 100).unwrap();
    let before = f.basis().id();
    let mut strong = success(f.key);
    assert!(
        f.deliver(&mut strong, 2, MaterializationFault::None)
            .is_err()
    );
    assert!(strong.calls.is_empty());
    assert_eq!(before, f.basis().id());
}

fn replay_intent(f: &Fixture) -> crate::merge::native::dispatch::replay::ReplayIntent {
    let source = f.effect();
    crate::merge::native::dispatch::replay::ReplayIntent {
        source: f.key,
        destination: AsciiSlug::from_static("forge-projection"),
        payload: source.payload_root(),
        expected_source_effect: source.root().unwrap(),
        route_id: 1,
        route_binding: digest_of(1),
    }
}
fn enqueue(
    f: &Fixture,
    intent: &crate::merge::native::dispatch::replay::ReplayIntent,
) -> Result<AsciiSlug, AdmissionError> {
    run(
        crate::merge::native::dispatch::replay::enqueue_replay_async(
            &f.store,
            &(),
            &f.context,
            intent,
            &f.projection(MaterializationFault::None),
            Default::default(),
            &|| {
                if f.store.stopped.load(Ordering::SeqCst) {
                    Err(RefusalCode::CancellationInProgress)
                } else {
                    Ok(())
                }
            },
        ),
    )
}
fn replay_routes(outcome: DeliveryVerdict) -> Routes {
    let mut r = Routes::new(1, [outcome]);
    r.definitions[0].max_attempts = 1;
    r.definitions[0].initial_delay_millis = 0;
    r.definitions[0].max_delay_millis = 0;
    r
}
fn drive_replay(
    f: &Fixture,
    key: AsciiSlug,
    routes: &mut Routes,
) -> Result<DispatchResult, AdmissionError> {
    run(dispatch_outbox_async(
        &f.store,
        &(),
        &f.context,
        key,
        &f.projection(MaterializationFault::None),
        routes,
        1,
        Default::default(),
        &|| Ok(()),
        &|| Ok(10_000),
    ))
}
#[test]
fn explicit_replay_creates_a_new_sealed_identity_and_preserves_original_terminal_outcome() {
    let f = Fixture::new();
    drive(
        &f,
        &mut Routes::new(1, [DeliveryVerdict::PermanentRejection]),
        1,
        100,
    )
    .unwrap();
    let original = f.effect();
    let original_forge = f.basis().body().forge_position_root;
    let intent = replay_intent(&f);
    let key = enqueue(&f, &intent).unwrap();
    assert_ne!(key, f.key);
    assert_eq!(f.effect(), original);
    assert_eq!(f.basis().body().forge_position_root, original_forge);
    let first_head = f.basis().id();
    assert_eq!(enqueue(&f, &intent).unwrap(), key);
    assert_eq!(first_head, f.basis().id());
    let mut routes = replay_routes(DeliveryVerdict::Accepted);
    let result = drive_replay(&f, key, &mut routes).unwrap();
    assert_eq!(
        result.effect.unwrap().state(),
        ObligationState::Acknowledged
    );
    assert_eq!(f.effect(), original);
    let terminal_head = f.basis().id();
    assert_eq!(enqueue(&f, &intent).unwrap(), key);
    assert_eq!(drive_replay(&f, key, &mut routes).unwrap().sends, 0);
    assert_eq!(routes.calls, [(1, 1)]);
    assert_eq!(terminal_head, f.basis().id());
    let changed = crate::merge::native::dispatch::replay::ReplayIntent {
        route_binding: digest_of(99),
        ..intent
    };
    assert!(enqueue(&f, &changed).is_err());
    assert_eq!(terminal_head, f.basis().id());
}
#[test]
fn replay_sealed_route_cannot_be_taken_over_and_missing_request_refuses_before_send() {
    let f = Fixture::new();
    drive(
        &f,
        &mut Routes::new(1, [DeliveryVerdict::PermanentRejection]),
        1,
        100,
    )
    .unwrap();
    let key = enqueue(&f, &replay_intent(&f)).unwrap();
    let before = f.basis().id();
    let mut routes = replay_routes(DeliveryVerdict::Accepted);
    let mut other_owner = f.context.clone();
    other_owner.principal_id = PrincipalId::from_bytes([0xee; 16]);
    assert!(
        run(dispatch_outbox_async(
            &f.store,
            &(),
            &other_owner,
            key,
            &f.projection(MaterializationFault::None),
            &mut routes,
            1,
            Default::default(),
            &|| Ok(()),
            &|| Ok(10_000),
        ))
        .is_err()
    );
    assert!(routes.calls.is_empty());
    assert_eq!(before, f.basis().id());
    routes.definitions[0].max_attempts = 2;
    assert!(drive_replay(&f, key, &mut routes).is_err());
    assert!(routes.calls.is_empty());
    assert_eq!(before, f.basis().id());
    routes.definitions[0].max_attempts = 1;
    let mut extra = routes.definitions[0].clone();
    extra.id = 2;
    routes.definitions.push(extra);
    assert!(drive_replay(&f, key, &mut routes).is_err());
    assert!(routes.calls.is_empty());
    assert_eq!(before, f.basis().id());
    routes.definitions.pop();
    routes.definitions[0].binding = digest_of(99);
    assert!(drive_replay(&f, key, &mut routes).is_err());
    assert!(routes.calls.is_empty());
    routes.definitions[0].binding = digest_of(1);
    let state = run(delivery::read_in(&f.store, &(), &f.basis(), &|| false)).unwrap();
    let tx = state.outbox.entry(key).unwrap().tx_id();
    let seal = run(fgit_authority::read_seal_async(
        &f.store,
        &(),
        f.context.tenant_id,
        f.context.repository_id,
        tx,
    ))
    .unwrap()
    .unwrap();
    *f.store.missing_body.lock().unwrap() = Some(
        storage::body_key(
            crate::merge::native::dispatch::replay::REPLAY_REQUEST_NAMESPACE,
            f.context.repository_id,
            seal.canonical_request_digest,
        )
        .unwrap(),
    );
    assert!(drive_replay(&f, key, &mut routes).is_err());
    assert!(routes.calls.is_empty());
    assert_eq!(before, f.basis().id());
    *f.store.missing_body.lock().unwrap() = None;
    assert_eq!(routes.probes, 0);
    assert_eq!(
        drive_replay(&f, key, &mut routes)
            .unwrap()
            .effect
            .unwrap()
            .state(),
        ObligationState::Acknowledged
    );
}
#[test]
fn cancelled_replay_admission_keeps_source_and_can_resume_same_intent() {
    let f = Fixture::new();
    drive(
        &f,
        &mut Routes::new(1, [DeliveryVerdict::PermanentRejection]),
        1,
        100,
    )
    .unwrap();
    let original = f.effect();
    let before = f.basis().id();
    let intent = replay_intent(&f);
    f.store.stopped.store(true, Ordering::SeqCst);
    assert!(enqueue(&f, &intent).is_err());
    assert_eq!(before, f.basis().id());
    assert_eq!(original, f.effect());
    f.store.stopped.store(false, Ordering::SeqCst);
    let key = enqueue(&f, &intent).unwrap();
    let mut routes = replay_routes(DeliveryVerdict::Accepted);
    assert_eq!(
        drive_replay(&f, key, &mut routes)
            .unwrap()
            .effect
            .unwrap()
            .state(),
        ObligationState::Acknowledged
    );
    assert_eq!(routes.calls, [(1, 1)]);
    assert_eq!(original, f.effect());
}
#[test]
fn replay_does_not_authorize_committed_or_acknowledged_sources() {
    let f = Fixture::new();
    let before = f.basis().id();
    assert!(enqueue(&f, &replay_intent(&f)).is_err());
    assert_eq!(f.basis().id(), before);
    let f = Fixture::new();
    drive(&f, &mut Routes::new(1, [DeliveryVerdict::Accepted]), 1, 100).unwrap();
    let before = f.basis().id();
    assert!(enqueue(&f, &replay_intent(&f)).is_err());
    assert_eq!(before, f.basis().id());
}
#[test]
fn changed_canonical_transport_binding_refuses_while_identical_binding_can_resume() {
    let f = Fixture::new();
    let mut routes = Routes::new(1, []);
    drive(&f, &mut routes, 0, 100).unwrap();
    let before = f.basis().id();
    routes.definitions[0].binding = digest_of(200);
    assert!(drive(&f, &mut routes, 1, 100).is_err());
    assert_eq!(before, f.basis().id());
    assert!(routes.calls.is_empty());
    routes.definitions[0].binding = digest_of(1);
    routes.outcomes.push_back(DeliveryVerdict::Accepted);
    assert_eq!(
        drive(&f, &mut routes, 1, 100)
            .unwrap()
            .effect
            .unwrap()
            .state(),
        ObligationState::Acknowledged
    );
}

#[test]
fn false_original_creation_position_is_not_a_valid_absence_of_weak_progress() {
    for invalid in [false, true] {
        let f = Fixture::with_false_creation_position(invalid);
        let basis = f.basis();
        let state = run(delivery::read_in(&f.store, &(), &basis, &|| false)).unwrap();
        let result = run(crate::merge::native::dispatch::read_dispatch_progress(
            &f.store,
            &(),
            &basis,
            state.outbox.entry(f.key).unwrap(),
            &|| false,
        ));
        if invalid {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), None);
        }
    }
}

// This deliberately bypasses only the MODEL writer to plant an authenticated
// invalid record. The production reader must reject staged-only predecessors.
fn publish_unchecked_progress(
    f: &Fixture,
    body: &crate::merge::native::dispatch::CanonicalDispatchProgress,
) {
    let root = body.root().unwrap();
    let mut context = f.context.clone();
    context.idempotency_key = fgit_authority::IdempotencyKey::new(
        format!(
            "planted/{}",
            fgit_crypto::lowercase_hex(root.bytes().as_bytes())
        )
        .into_bytes(),
    )
    .unwrap();
    let semantic = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        vec![],
        vec![],
        vec![
            ScopedEntry::new(
                AsciiSlug::from_static("outbox"),
                AsciiSlug::from_static("fenced-dispatch"),
                root.bytes().as_bytes(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let attempt = SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: context.idempotency_key.clone(),
        request: semantic.clone(),
    };
    let sealed = run(fgit_authority::seal_request_async(&f.store, &(), &attempt)).unwrap();
    let (basis, head, authenticated) =
        run(crate::read_basis_async(&f.store, &(), &context.head_key)).unwrap();
    let cumulative = run(fgit_authority::collect_cumulative_outcomes_async(
        &f.store,
        &(),
        &context.head_key,
    ))
    .unwrap();
    let projection = f.projection(MaterializationFault::None);
    let snapshot = run(projection.snapshot_async(&f.store, &(), &basis, &authenticated)).unwrap();
    let empty = PermittedObjectClosure::default();
    let closure = ValidatedClosure {
        objects: empty.objects().clone(),
        object_closure_root: crate::permitted_object_closure_root(&empty).unwrap(),
    };
    let lowered = LoweredRequest {
        semantic,
        idempotency_key: context.idempotency_key.clone(),
    };
    let PublicationPreparation::Commit(prepared) = crate::prepare_publication_from_snapshot(
        &context,
        &lowered,
        &closure,
        sealed.tx_id(),
        &snapshot,
    )
    .unwrap() else {
        panic!("planted empty fold")
    };
    let mut materialization = run(projection.materialize_commit_async(
        &f.store,
        &(),
        &basis,
        &prepared.request,
        &prepared.fold,
        &closure,
    ))
    .unwrap();
    run(stage_runtime_evidence(
        &f.store,
        &(),
        &context,
        body,
        &|| Ok(()),
    ))
    .unwrap();
    materialization.record.invariant_evidence_root = root;
    materialization.record.outbox_effect_root = root;
    let mut plan = PublicationPlan::open(basis).unwrap();
    plan.commit(materialization.record);
    let publication = plan
        .seal(
            &CryptoBodyIdentity,
            materialization.roots,
            &cumulative,
            head.token(),
        )
        .unwrap();
    assert_eq!(
        run(publication::publish_owned(
            &f.store,
            &(),
            &context,
            head.token(),
            &publication,
            sealed.tx_id()
        ))
        .unwrap(),
        Some(true)
    );
}
#[test]
fn an_observation_cannot_skip_its_unpublished_dispatch_predecessor() {
    let f = Fixture::new();
    let mut routes = Routes::new(1, []);
    let initial = drive(&f, &mut routes, 0, 100).unwrap().progress;
    let staged = initial.dispatch(1, 101).unwrap();
    run(stage_runtime_evidence(
        &f.store,
        &(),
        &f.context,
        &staged,
        &|| Ok(()),
    ))
    .unwrap();
    let forged = staged
        .observe(
            1,
            102,
            Observation::Delivery(DeliveryVerdict::Accepted),
            b"claimed observation on an unselected marker".to_vec(),
        )
        .unwrap();
    publish_unchecked_progress(&f, &forged);
    let before = f.basis().id();
    assert!(drive(&f, &mut routes, 1, 103).is_err());
    assert!(routes.calls.is_empty());
    assert_eq!(f.basis().id(), before);
    // Near-identical permitted chain selects its marker before the observation.
    let valid = Fixture::new();
    let mut transport = Routes::new(1, [DeliveryVerdict::Accepted]);
    assert_eq!(
        drive(&valid, &mut transport, 1, 103)
            .unwrap()
            .effect
            .unwrap()
            .state(),
        ObligationState::Acknowledged
    );
}

#[test]
fn repeated_explicit_attempts_reference_the_original_event_instead_of_a_replay_chain() {
    let f = Fixture::new();
    drive(
        &f,
        &mut Routes::new(1, [DeliveryVerdict::PermanentRejection]),
        1,
        100,
    )
    .unwrap();
    let intent = replay_intent(&f);
    let first = enqueue(&f, &intent).unwrap();
    let failure = drive_replay(
        &f,
        first,
        &mut replay_routes(DeliveryVerdict::PermanentRejection),
    )
    .unwrap()
    .effect
    .unwrap();
    let nested = crate::merge::native::dispatch::replay::ReplayIntent {
        source: first,
        expected_source_effect: failure.root().unwrap(),
        ..intent
    };
    let before = f.basis().id();
    let mut context = f.context.clone();
    context.idempotency_key =
        fgit_authority::IdempotencyKey::new(b"second-explicit-replay".to_vec()).unwrap();
    assert!(
        run(
            crate::merge::native::dispatch::replay::enqueue_replay_async(
                &f.store,
                &(),
                &context,
                &nested,
                &f.projection(MaterializationFault::None),
                Default::default(),
                &|| Ok(())
            )
        )
        .is_err()
    );
    assert_eq!(f.basis().id(), before);
    context.idempotency_key =
        fgit_authority::IdempotencyKey::new(b"next-original-replay".to_vec()).unwrap();
    let second = run(
        crate::merge::native::dispatch::replay::enqueue_replay_async(
            &f.store,
            &(),
            &context,
            &intent,
            &f.projection(MaterializationFault::None),
            Default::default(),
            &|| Ok(()),
        ),
    )
    .unwrap();
    assert_ne!(second, first);
    assert_ne!(second, f.key);
    assert_eq!(
        drive_replay(&f, second, &mut replay_routes(DeliveryVerdict::Accepted))
            .unwrap()
            .effect
            .unwrap()
            .state(),
        ObligationState::Acknowledged
    );
    assert_eq!(f.effect().state(), ObligationState::TerminallyFailed);
}

// The helper bypasses only the MODEL replay writer to plant one authenticated
// replay-creation RCR. All source bodies/receipts exist and are valid, but its
// failed source outcome has never been selected by an authority-head CAS.
fn publish_replay_with_only_staged_failed_source(f: &Fixture) -> AsciiSlug {
    use crate::merge::native::dispatch::replay::{REPLAY_CLASS, REPLAY_REQUEST_NAMESPACE};

    let original = f.effect();
    assert_eq!(original.state(), ObligationState::Committed);
    let destination = AsciiSlug::from_static("forge-projection");
    let deferred = original.transition(LifecycleEvent::Defer, None).unwrap();
    let source_receipt = CanonicalOutboxDeliveryReceipt::try_new(
        f.context.repository_id,
        f.key,
        destination,
        original.payload_root(),
        storage::root(&deferred).unwrap(),
        OutboxDeliveryDisposition::TerminallyRefused,
        b"valid receipt for an UNSELECTED failed source".to_vec(),
    )
    .unwrap();
    let failed = deferred
        .transition(
            LifecycleEvent::FailTerminally,
            Some(storage::root(&source_receipt).unwrap()),
        )
        .unwrap();
    for body in [&deferred, &failed] {
        run(storage::stage_body(
            &f.store,
            &(),
            f.context.repository_id,
            delivery::EFFECT_NAMESPACE,
            body,
        ))
        .unwrap();
    }
    run(storage::stage_body(
        &f.store,
        &(),
        f.context.repository_id,
        delivery::RECEIPT_NAMESPACE,
        &source_receipt,
    ))
    .unwrap();
    assert_eq!(
        f.effect(),
        original,
        "staging must not publish source failure"
    );

    // Construct exactly the typed replay request independently of the private
    // ReplayIntent::request helper. No missing alias or malformed request may
    // accidentally be the reason the provenance lookup refuses.
    let digest_value = |d: Digest| {
        let mut bytes = d.algorithm().code_point().to_be_bytes().to_vec();
        bytes.push(d.bytes().len() as u8);
        bytes.extend_from_slice(d.bytes().as_bytes());
        bytes
    };
    let scoped = |key, value: Vec<u8>| {
        ScopedEntry::new(AsciiSlug::from_static("outbox-replay"), key, value).unwrap()
    };
    let semantic = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        f.context.object_format,
        true,
        vec![],
        vec![],
        vec![
            scoped(
                AsciiSlug::from_static("source-key"),
                f.key.as_bytes().to_vec(),
            ),
            scoped(
                AsciiSlug::from_static("source-effect"),
                digest_value(storage::root(&failed).unwrap()),
            ),
            scoped(
                AsciiSlug::from_static("payload"),
                digest_value(original.payload_root()),
            ),
            scoped(
                AsciiSlug::from_static("destination"),
                destination.as_bytes().to_vec(),
            ),
            scoped(
                AsciiSlug::from_static("route-id"),
                1_u64.to_be_bytes().to_vec(),
            ),
            scoped(
                AsciiSlug::from_static("route-binding"),
                digest_value(digest_of(1)),
            ),
        ],
    )
    .unwrap();
    let mut context = f.context.clone();
    context.idempotency_key =
        fgit_authority::IdempotencyKey::new(b"planted-staged-source-replay".to_vec()).unwrap();
    let attempt = SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: context.idempotency_key.clone(),
        request: semantic.clone(),
    };
    let sealed = run(fgit_authority::seal_request_async(&f.store, &(), &attempt)).unwrap();
    let (basis, head, authenticated) =
        run(crate::read_basis_async(&f.store, &(), &context.head_key)).unwrap();
    let cumulative = run(fgit_authority::collect_cumulative_outcomes_async(
        &f.store,
        &(),
        &context.head_key,
    ))
    .unwrap();
    let projection = f.projection(MaterializationFault::None);
    let snapshot = run(projection.snapshot_async(&f.store, &(), &basis, &authenticated)).unwrap();
    let closure = PermittedObjectClosure::default();
    let closure = ValidatedClosure {
        objects: closure.objects().clone(),
        object_closure_root: crate::permitted_object_closure_root(&closure).unwrap(),
    };
    let lowered = LoweredRequest {
        semantic: semantic.clone(),
        idempotency_key: context.idempotency_key.clone(),
    };
    let PublicationPreparation::Commit(prepared) = crate::prepare_publication_from_snapshot(
        &context,
        &lowered,
        &closure,
        sealed.tx_id(),
        &snapshot,
    )
    .unwrap() else {
        panic!("planted replay requires an otherwise valid empty transaction fold")
    };
    let mut materialization = run(projection.materialize_commit_async(
        &f.store,
        &(),
        &basis,
        &prepared.request,
        &prepared.fold,
        &closure,
    ))
    .unwrap();
    assert!(
        run(storage::read_events(
            &f.store,
            &(),
            context.repository_id,
            materialization.record.forge_event_batch_root,
        ))
        .unwrap()
        .events
        .is_empty(),
        "the replay creation must not create a second forge event"
    );

    let key = fgit_codec::derive_outbox_delivery_key(fgit_codec::OutboxDeliveryIdentityInput::new(
        context.repository_id,
        REPLAY_CLASS,
        destination,
        original.payload_root(),
        sealed.tx_id(),
        basis.body().latest_committed_rcr_id,
    ))
    .unwrap();
    assert_ne!(key, f.key);
    let effect = CanonicalOutboxEffectState::committed(
        context.repository_id,
        key,
        sealed.tx_id(),
        original.payload_root(),
    );
    let root = storage::root(&effect).unwrap();
    let state = run(delivery::read_in(&f.store, &(), &basis, &|| false)).unwrap();
    let mut entries = state.outbox.entries().to_vec();
    entries.push(CanonicalOutboxStateEntry::new(
        key,
        REPLAY_CLASS,
        destination,
        original.payload_root(),
        sealed.tx_id(),
        basis.body().latest_committed_rcr_id,
        root,
        None,
    ));
    entries.sort_by_key(|e| e.delivery_key());
    let outbox = CanonicalOutboxState::try_new(context.repository_id, entries).unwrap();
    run(storage::stage_body(
        &f.store,
        &(),
        context.repository_id,
        delivery::EFFECT_NAMESPACE,
        &effect,
    ))
    .unwrap();
    materialization.roots.outbox_root = run(storage::stage_body(
        &f.store,
        &(),
        context.repository_id,
        delivery::OUTBOX_NAMESPACE,
        &outbox,
    ))
    .unwrap();
    let retained_request = run(storage::stage_body(
        &f.store,
        &(),
        context.repository_id,
        REPLAY_REQUEST_NAMESPACE,
        &semantic,
    ))
    .unwrap();
    assert_eq!(
        retained_request,
        materialization.record.canonical_request_digest
    );
    run(stage_runtime_evidence(
        &f.store,
        &(),
        &context,
        &effect,
        &|| Ok(()),
    ))
    .unwrap();
    materialization.record.invariant_evidence_root = root;
    materialization.record.outbox_effect_root = root;
    let mut plan = PublicationPlan::open(basis).unwrap();
    plan.commit(materialization.record);
    let publication = plan
        .seal(
            &CryptoBodyIdentity,
            materialization.roots,
            &cumulative,
            head.token(),
        )
        .unwrap();
    assert_eq!(
        run(publication::publish_owned(
            &f.store,
            &(),
            &context,
            head.token(),
            &publication,
            sealed.tx_id(),
        ))
        .unwrap(),
        Some(true),
        "plant the malformed semantic provenance through the real model head CAS"
    );
    assert_eq!(f.effect(), original);
    key
}

#[test]
fn staged_source_failure_cannot_authorize_authenticated_replay_creation_history() {
    let invalid = Fixture::new();
    let key = publish_replay_with_only_staged_failed_source(&invalid);
    let before = invalid.basis();
    let state = run(delivery::read_in(&invalid.store, &(), &before, &|| false)).unwrap();
    let entry = state.outbox.entry(key).unwrap();
    let lookup = run(crate::merge::native::dispatch::read_dispatch_progress(
        &invalid.store,
        &(),
        &before,
        entry,
        &|| false,
    ));
    assert!(
        lookup.is_err(),
        "a valid failed-effect body and receipt do not prove canonical source failure"
    );
    assert_eq!(invalid.basis().id(), before.id());
    let mut refused_transport = replay_routes(DeliveryVerdict::Accepted);
    assert!(drive_replay(&invalid, key, &mut refused_transport).is_err());
    assert!(refused_transport.calls.is_empty());
    assert_eq!(refused_transport.probes, 0);
    assert_eq!(invalid.basis().id(), before.id());
    assert_eq!(invalid.effect().state(), ObligationState::Committed);

    // Near-identical permitted case: publish the source failure through the
    // production Weak driver, then enqueue and resolve the new replay normally.
    let valid = Fixture::new();
    drive(
        &valid,
        &mut Routes::new(1, [DeliveryVerdict::PermanentRejection]),
        1,
        100,
    )
    .unwrap();
    let original = valid.effect();
    let key = enqueue(&valid, &replay_intent(&valid)).unwrap();
    let before = valid.basis();
    let state = run(delivery::read_in(&valid.store, &(), &before, &|| false)).unwrap();
    assert_eq!(
        run(crate::merge::native::dispatch::read_dispatch_progress(
            &valid.store,
            &(),
            &before,
            state.outbox.entry(key).unwrap(),
            &|| false,
        ))
        .unwrap(),
        None,
        "a canonically eligible replay has a valid creation but no dispatch yet"
    );
    assert_eq!(valid.basis().id(), before.id());
    let mut permitted_transport = replay_routes(DeliveryVerdict::Accepted);
    assert_eq!(
        drive_replay(&valid, key, &mut permitted_transport)
            .unwrap()
            .effect
            .unwrap()
            .state(),
        ObligationState::Acknowledged
    );
    assert_eq!(permitted_transport.calls, [(1, 1)]);
    assert_eq!(permitted_transport.probes, 0);
    assert_eq!(
        valid.effect(),
        original,
        "the original terminal outcome is immutable"
    );
}

#[test]
fn a_failed_sibling_cannot_authorize_replaying_the_delivered_member() {
    let f = Fixture::new();
    drive(
        &f,
        &mut Routes::new(
            2,
            [
                DeliveryVerdict::Accepted,
                DeliveryVerdict::PermanentRejection,
            ],
        ),
        2,
        100,
    )
    .unwrap();
    let before = f.basis().id();
    let intent = replay_intent(&f);
    assert!(enqueue(&f, &intent).is_err());
    assert_eq!(before, f.basis().id());
    let owed = crate::merge::native::dispatch::replay::ReplayIntent {
        route_id: 2,
        route_binding: digest_of(2),
        ..intent
    };
    let mut context = f.context.clone();
    context.idempotency_key =
        fgit_authority::IdempotencyKey::new(b"owed-member-replay".to_vec()).unwrap();
    let key = run(
        crate::merge::native::dispatch::replay::enqueue_replay_async(
            &f.store,
            &(),
            &context,
            &owed,
            &f.projection(MaterializationFault::None),
            Default::default(),
            &|| Ok(()),
        ),
    )
    .unwrap();
    let mut routes = replay_routes(DeliveryVerdict::Accepted);
    routes.definitions[0].id = 2;
    routes.definitions[0].binding = digest_of(2);
    assert_eq!(
        drive_replay(&f, key, &mut routes)
            .unwrap()
            .effect
            .unwrap()
            .state(),
        ObligationState::Acknowledged
    );
    assert_eq!(routes.calls, [(2, 1)]);
}
