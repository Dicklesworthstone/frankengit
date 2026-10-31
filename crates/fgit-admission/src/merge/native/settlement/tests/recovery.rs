//! Recovery of a real selected settlement does not require unrelated older
//! history and never grants ownership of another dispatch.

use super::*;
use fgit_authority::{OutcomeFailure, body_key_for_id, collect_cumulative_outcomes_async};

#[test]
fn a_recent_settlement_recovers_without_older_history_or_new_dispatch_ownership() {
    let fixture = Fixture::new();
    let predecessor = fixture.basis();
    let state = run(delivery::read_in(
        &fixture.store,
        &(),
        &predecessor,
        &|| false,
    ))
    .unwrap();
    let original = state.outbox.entry(fixture.key).unwrap();
    let deferred = fixture
        .effect()
        .transition(LifecycleEvent::Defer, None)
        .unwrap();
    let publish = || {
        run(publish_mutation(
            &fixture.store,
            &(),
            &fixture.context,
            &fixture.projection(MaterializationFault::None),
            original,
            RuntimeMutation::Lifecycle {
                next: &deferred,
                receipt: None,
                progress: None,
            },
            AdmissionLimits::default(),
            &|| Ok(()),
        ))
    };
    assert!(
        publish().unwrap(),
        "only the acknowledged publisher owns its effect"
    );
    let selected = fixture.basis().id();
    assert_ne!(selected, predecessor.id());

    // The selected decision batch remains readable. Only the older head body
    // needed to collect a complete cumulative publication witness is absent.
    *fixture.store.missing_body.lock().unwrap() =
        Some(body_key_for_id(predecessor.id().as_internal_object_id()).unwrap());
    assert_eq!(
        run(collect_cumulative_outcomes_async(
            &fixture.store,
            &(),
            &fixture.context.head_key,
        )),
        Err(OutcomeFailure::StreamBodyMissing { link: "head body" }),
    );
    assert!(
        !publish().unwrap(),
        "recovered terminals cannot authorize another send"
    );
    assert_eq!(
        fixture.basis().id(),
        selected,
        "recovery must not republish the settlement"
    );
}
