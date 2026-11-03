//! Real store/production-driver coverage for x2mv.4.37. The planted transient
//! cells exercise the exact retry wrapper used by AsyncAuthorityStore, then
//! run real SQL. They are not a concurrent-writer throughput campaign.

use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthorityFailure, AuthorityLimits, AuthorityRefusal,
    CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead, HeadReadReceipt, StoreInstanceId,
};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::ClassLimits;
use fgit_statistics::{FallbackTrigger, PolicySelection};
use fsqlite_types::cx::Cx;

use super::{
    EngineError, FsqliteAuthorityStore, OperationRetry, TransientClass, runtime_timer,
    wait_for_retry,
};
use crate::adaptive_retry::{
    CANDIDATE_BACKOFF_BASE_MS, CANDIDATE_BACKOFF_CEILING_MS, DEFAULT_MIN_SUPPORT_OBSERVATIONS,
    FALLBACK_BACKOFF_BASE_MS, FALLBACK_BACKOFF_CEILING_MS,
};
use crate::retry::BackoffPlan;

fn context(node: &NodeRuntime, deadline: Duration) -> Cx {
    let cx = Cx::new();
    let budget = ClassLimits::finite(deadline, 100_000, 1_000_000).at(node.now());
    cx.set_native_cx(node.request_cx_with_budget(budget));
    cx
}

fn fixture() -> (NodeRuntime, FsqliteAuthorityStore, Cx) {
    let node = RuntimeProfile::production(1).build().expect("runtime");
    let cx = context(&node, Duration::from_secs(60));
    let store = node
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            ":memory:",
            StoreInstanceId::from_raw(937),
            AuthorityLimits::default(),
        ))
        .expect("real authority store");
    (node, store, cx)
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("live generation")
}

async fn initialize(store: &FsqliteAuthorityStore, cx: &Cx) -> (HeadKey, HeadReadReceipt) {
    let key = HeadKey::new(b"retry-integration-head".to_vec()).expect("head key");
    let HeadInit::Created(initial) =
        AsyncAuthorityStore::initialize_head(store, cx, &key, generation(1), b"initial")
            .await
            .expect("initialize through production trait")
    else {
        panic!("new head must be created");
    };
    (key, initial)
}

async fn warm(store: &FsqliteAuthorityStore, cx: &Cx, key: &HeadKey) {
    let count = store.contention_retry_snapshot().total_observations;
    for _ in count..u64::from(DEFAULT_MIN_SUPPORT_OBSERVATIONS) {
        AsyncAuthorityStore::read_head(store, cx, key)
            .await
            .expect("real production reads supply support");
    }
    assert_eq!(
        store.contention_retry_snapshot().active_selection,
        PolicySelection::Candidate
    );
}

fn assert_selected_plan(store: &FsqliteAuthorityStore, cx: &Cx, base: u64, ceiling: u64) {
    let retry = OperationRetry::new(store.instance, cx, &store.contention_retry);
    assert_eq!(
        retry.backoff,
        BackoffPlan::new(base, ceiling, retry.backoff.seed()),
        "the production retry state must use the controller's actual bounds"
    );
}

async fn overlap<A: Future, B: Future>(left: A, right: B) -> (A::Output, B::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut a = None;
    let mut b = None;
    poll_fn(|task| {
        if a.is_none()
            && let Poll::Ready(value) = left.as_mut().poll(task)
        {
            a = Some(value);
        }
        if b.is_none()
            && let Poll::Ready(value) = right.as_mut().poll(task)
        {
            b = Some(value);
        }
        if a.is_some() && b.is_some() {
            Poll::Ready((a.take().unwrap(), b.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

#[test]
fn production_trait_selects_adaptive_backoff_without_changing_cas_winners_or_losers() {
    // AC1/3: real overlapping CAS operations in cold fallback and supported
    // candidate epochs retain one committed winner and one exact-token loser.
    for adaptive in [false, true] {
        let (node, mut store, cx) = fixture();
        let peer = context(&node, Duration::from_secs(60));
        node.block_on(async {
            let (key, initial) = initialize(&store, &cx).await;
            if adaptive {
                warm(&store, &cx, &key).await;
                assert_selected_plan(
                    &store,
                    &cx,
                    CANDIDATE_BACKOFF_BASE_MS,
                    CANDIDATE_BACKOFF_CEILING_MS,
                );
            } else {
                assert_selected_plan(
                    &store,
                    &cx,
                    FALLBACK_BACKOFF_BASE_MS,
                    FALLBACK_BACKOFF_CEILING_MS,
                );
            }
            let before = store.contention_retry_snapshot().total_observations;
            let (left, right) = overlap(
                AsyncAuthorityStore::compare_exchange_head(
                    &store,
                    &cx,
                    &key,
                    initial.token(),
                    generation(2),
                    b"left",
                ),
                AsyncAuthorityStore::compare_exchange_head(
                    &store,
                    &peer,
                    &key,
                    initial.token(),
                    generation(2),
                    b"right",
                ),
            )
            .await;
            let winner = match (left.expect("left CAS"), right.expect("right CAS")) {
                (CasOutcome::Committed(receipt), CasOutcome::PredecessorMismatch)
                | (CasOutcome::PredecessorMismatch, CasOutcome::Committed(receipt)) => receipt,
                other => panic!("one winner and one mismatch required: {other:?}"),
            };
            let snapshot = store.contention_retry_snapshot();
            assert_eq!(snapshot.total_observations, before + 2);
            assert_eq!(
                snapshot.contended_observations, 0,
                "a logical CAS mismatch is terminal, not transient engine contention"
            );
            assert_eq!(
                store.read_head(&cx, &key).await.expect("head"),
                HeadRead::Present(winner.clone()),
            );
            store
                .authenticate_head_receipt(&cx, &winner)
                .await
                .expect("issuance");
            let evidence = snapshot.current_evidence.expect("production evidence");
            assert_eq!(evidence.evidence.window.last(), before + 2);
            assert!(
                evidence
                    .to_json_line()
                    .contains("\"toolchain_fingerprint\":")
            );
        });
        node.block_on(store.close(&cx)).expect("close");
    }
}

#[test]
fn production_driver_retries_whole_attempts_and_records_one_actual_cas_observation() {
    // AC1/4: plant classified transient failures at the production wrapper,
    // then commit through the real engine. Retries must not be separate samples.
    let (node, mut store, cx) = fixture();
    node.block_on(async {
        let (key, initial) = initialize(&store, &cx).await;
        warm(&store, &cx, &key).await;
        let before = store.contention_retry_snapshot().total_observations;
        let failures = [
            TransientClass::Busy,
            TransientClass::WriteConflict,
            TransientClass::PageBufferCapacityExhausted,
        ];
        let mut attempts = 0_usize;
        let result = with_transient_retry!(&store, &cx, async {
            attempts += 1;
            if let Some(class) = failures.get(attempts - 1) {
                Err(EngineError::Engine(*class))
            } else {
                store
                    .compare_exchange_head(&cx, &key, initial.token(), generation(2), b"committed")
                    .await
            }
        });
        assert!(matches!(result, Ok(CasOutcome::Committed(_))));
        assert_eq!(attempts, failures.len() + 1);
        let snapshot = store.contention_retry_snapshot();
        assert_eq!(snapshot.total_observations, before + 1);
        assert_eq!(snapshot.contended_observations, 1);
        let log = snapshot.current_evidence.expect("real production log");
        assert_eq!(
            log.evidence.regime.detector_high, 2,
            "three executed retries produce excursion 3 minus CUSUM slack 1"
        );
        assert_eq!(
            AsyncAuthorityStore::compare_exchange_head(
                &store,
                &cx,
                &key,
                initial.token(),
                generation(2),
                b"duplicate",
            )
            .await
            .expect("stale retry"),
            CasOutcome::PredecessorMismatch,
        );
    });
    node.block_on(store.close(&cx)).expect("close");
}

#[test]
fn production_contention_regime_shift_selects_fallback_for_the_next_call() {
    // AC3: observations come from the production retry driver, not direct
    // calls to the statistics controller.
    let (node, mut store, cx) = fixture();
    node.block_on(async {
        let (key, _) = initialize(&store, &cx).await;
        warm(&store, &cx, &key).await;
        for _ in 0..24 {
            let mut attempts = 0;
            with_transient_retry!(&store, &cx, async {
                attempts += 1;
                if attempts <= 3 {
                    Err(EngineError::Engine(TransientClass::BusySnapshot))
                } else {
                    store.read_head(&cx, &key).await
                }
            })
            .expect("whole operation completes after planted contention");
            if store.contention_retry_snapshot().active_selection
                == PolicySelection::Fallback(FallbackTrigger::RegimeAlarm)
            {
                break;
            }
        }
        let snapshot = store.contention_retry_snapshot();
        assert_eq!(
            snapshot.active_selection,
            PolicySelection::Fallback(FallbackTrigger::RegimeAlarm)
        );
        assert_selected_plan(
            &store,
            &cx,
            FALLBACK_BACKOFF_BASE_MS,
            FALLBACK_BACKOFF_CEILING_MS,
        );
        assert_eq!(snapshot.epoch_history.len(), 3);
        assert!(
            snapshot.epoch_history[2]
                .to_json_line()
                .contains("fallback:regime-alarm")
        );
    });
    node.block_on(store.close(&cx)).expect("close");
}

#[test]
fn production_driver_keeps_nonretryable_errors_and_ambiguity_terminal() {
    let (node, mut store, cx) = fixture();
    node.block_on(async {
        for (class, expected) in [
            (
                TransientClass::Permanent,
                AuthorityFailure::Refused(AuthorityRefusal::Unavailable),
            ),
            (
                TransientClass::FreshSnapshotRequired,
                AuthorityFailure::Refused(AuthorityRefusal::Unavailable),
            ),
            (
                TransientClass::OutcomeIndeterminate,
                AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
            ),
            (
                TransientClass::Cancelled,
                AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled),
            ),
        ] {
            let before = store.contention_retry_snapshot().total_observations;
            let mut attempts = 0;
            let result: Result<(), AuthorityFailure> = with_transient_retry!(&store, &cx, async {
                attempts += 1;
                Err(EngineError::Engine(class))
            });
            assert_eq!(result, Err(expected));
            assert_eq!(attempts, 1);
            assert_eq!(
                store.contention_retry_snapshot().total_observations,
                before + 1
            );
        }
        let snapshot = store.contention_retry_snapshot();
        assert_eq!(snapshot.contended_observations, 0);
        assert_eq!(
            snapshot.active_selection,
            PolicySelection::Fallback(FallbackTrigger::EvidenceGap)
        );
    });
    node.block_on(store.close(&cx)).expect("close");
}

#[test]
fn cancellation_during_backoff_wakes_without_starting_another_attempt() {
    for native_cancel in [false, true] {
        let (node, mut store, live) = fixture();
        let cx = context(&node, Duration::from_secs(60));
        node.block_on(async {
            let timer = runtime_timer().expect("runtime timer");
            let wait = asupersync::time::sleep(timer.now(), Duration::from_secs(30));
            let mut waiting = Box::pin(wait_for_retry(&cx, wait));
            poll_fn(|task| {
                assert!(waiting.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            if native_cancel {
                cx.attached_native_cx()
                    .expect("attached native context")
                    .set_cancel_requested(true);
            } else {
                cx.cancel();
            }
            assert_eq!(
                waiting.await,
                Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled))
            );
            let mut attempts = 0;
            let result: Result<(), AuthorityFailure> = with_transient_retry!(&store, &cx, async {
                attempts += 1;
                Err(EngineError::Engine(TransientClass::WriteConflict))
            });
            assert_eq!(
                result,
                Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled))
            );
            assert_eq!(attempts, 1, "the cancelled backoff cannot restart SQL");
            let snapshot = store.contention_retry_snapshot();
            assert_eq!(snapshot.total_observations, 1);
            assert_eq!(snapshot.contended_observations, 1);
            assert_eq!(
                snapshot
                    .current_evidence
                    .unwrap()
                    .evidence
                    .regime
                    .detector_high,
                0,
                "a scheduled but unstarted retry is not an executed retry"
            );
        });
        node.block_on(store.close(&live))
            .expect("close with live owner");
    }
}

#[test]
fn abandoned_production_future_invalidates_support_but_keeps_the_connection_usable() {
    let (node, mut store, cx) = fixture();
    let waiting_cx = context(&node, Duration::from_secs(60));
    node.block_on(async {
        let (key, initial) = initialize(&store, &cx).await;
        warm(&store, &cx, &key).await;
        let before = store.contention_retry_snapshot().total_observations;
        // A future never admitted/polled supplies no observation at all.
        drop(AsyncAuthorityStore::read_head(&store, &waiting_cx, &key));
        assert_eq!(store.contention_retry_snapshot().total_observations, before);
        let owner = store.operation(&cx).await.expect("hold connection owner");
        let mut abandoned = Box::pin(AsyncAuthorityStore::read_head(&store, &waiting_cx, &key));
        poll_fn(|task| {
            assert!(abandoned.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(abandoned);
        let snapshot = store.contention_retry_snapshot();
        assert_eq!(snapshot.total_observations, before + 1);
        assert_eq!(
            snapshot.active_selection,
            PolicySelection::Fallback(FallbackTrigger::EvidenceGap)
        );
        assert_eq!(
            snapshot.current_evidence.unwrap().evidence.window.last(),
            before + 1
        );
        drop(owner);
        assert_eq!(
            AsyncAuthorityStore::read_head(&store, &cx, &key)
                .await
                .expect("live caller still reads"),
            HeadRead::Present(initial),
        );
        assert_selected_plan(
            &store,
            &cx,
            FALLBACK_BACKOFF_BASE_MS,
            FALLBACK_BACKOFF_CEILING_MS,
        );
    });
    node.block_on(store.close(&cx)).expect("close");
}

#[test]
fn production_retry_budget_includes_time_spent_inside_the_failed_attempt() {
    let (node, mut store, live) = fixture();
    node.block_on(async {
        let short = context(&node, Duration::from_millis(10));
        let mut attempts = 0;
        let result: Result<(), AuthorityFailure> = with_transient_retry!(&store, &short, async {
            attempts += 1;
            let timer = runtime_timer().expect("runtime timer");
            asupersync::time::sleep(timer.now(), Duration::from_millis(20)).await;
            Err(EngineError::Engine(TransientClass::DatabaseLocked))
        });
        assert_eq!(
            result,
            Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled))
        );
        assert_eq!(
            attempts, 1,
            "SQL/gate time cannot silently extend the retry allowance"
        );
        let snapshot = store.contention_retry_snapshot();
        assert_eq!(snapshot.total_observations, 1);
        assert_eq!(
            snapshot.contended_observations, 1,
            "an exhausted first transient is still contention even with zero retries"
        );
    });
    node.block_on(store.close(&live)).expect("close");
}
