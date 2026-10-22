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
    async fn deliver<'a>(
        &'a mut self,
        _: &'a (),
        route: u64,
        _: &'a DeliveryRequest<'_>,
        attempt: u32,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
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
    async fn probe<'a>(
        &'a mut self,
        _: &'a (),
        _: u64,
        _: &'a DeliveryRequest<'_>,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> Result<(ProbeVerdict, Vec<u8>), RefusalCode> {
        checkpoint()?;
        self.probes += 1;
        Ok((ProbeVerdict::Unknown, b"non-probing weak receiver".to_vec()))
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
