//! Exclusive ownership of one connection across a complete authority operation.
//!
//! The engine worker orders commands, but does not associate a SQL transaction
//! with its caller. The lease therefore covers reads as well as writes. An
//! unfinished transaction stays marked across future drop; acquiring a lease
//! alone never proves that the worker has finalized it.

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

use asupersync::channel::oneshot;
use asupersync::cx::Cx as NativeCx;
use asupersync::runtime::Runtime;
use asupersync::sync::{LockError, Mutex, OwnedMutexGuard};
use fsqlite_types::cx::{Cx, cap};

use super::{EngineError, TransientClass};

#[derive(Debug, Default)]
struct OperationState {
    unfinalized: bool,
}

#[derive(Debug)]
pub(super) struct OperationGate {
    state: Arc<Mutex<OperationState>>,
}

impl OperationGate {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(OperationState::default())),
        }
    }

    /// Wait without issuing SQL, observing both local and native cancellation.
    pub(super) async fn acquire<Caps>(&self, cx: &Cx<Caps>) -> Result<OperationLease, EngineError>
    where
        Caps: cap::SubsetOf<cap::All>,
        cap::None: cap::SubsetOf<Caps>,
    {
        // Match AsyncConnection's admitted context rather than manufacturing
        // an uncancelled context for a waiter. Masked local contexts are not
        // supported by its async preflight.
        if cx.mask_depth() != 0 {
            return Err(EngineError::Engine(TransientClass::Permanent));
        }
        if cx.is_cancel_requested() {
            return Err(cancelled());
        }
        if Runtime::current_handle().is_none() {
            return Err(EngineError::Engine(TransientClass::Permanent));
        }
        let native = cx
            .attached_native_cx()
            .or_else(NativeCx::current)
            .ok_or(EngineError::Engine(TransientClass::Permanent))?;
        if cx.checkpoint().is_err() || cx.is_cancel_requested() {
            return Err(cancelled());
        }
        let mut lock = std::pin::pin!(OwnedMutexGuard::lock(Arc::clone(&self.state), &native));
        let mut local_cancel = std::pin::pin!(cx.wait_for_local_cancel_request());
        // The sender stays alive and sends nothing. This wait registers the
        // native cancellation wakeup even when the lock owner remains pending.
        let (native_sender, mut native_receiver) = oneshot::channel::<()>();
        let mut native_cancel = std::pin::pin!(native_receiver.recv(&native));
        let result = poll_fn(|task| {
            if local_cancel.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(cancelled()));
            }
            if let Poll::Ready(outcome) = native_cancel.as_mut().poll(task) {
                return Poll::Ready(Err(match outcome {
                    Err(oneshot::RecvError::Cancelled) => cancelled(),
                    _ => EngineError::Engine(TransientClass::Permanent),
                }));
            }
            lock.as_mut().poll(task).map(|result| {
                result
                    .map(|state| OperationLease { state })
                    .map_err(|error| match error {
                        LockError::Cancelled => cancelled(),
                        _ => EngineError::Engine(TransientClass::Permanent),
                    })
            })
        })
        .await;
        drop(native_sender);
        result
    }
}

const fn cancelled() -> EngineError {
    EngineError::Engine(TransientClass::Cancelled)
}

/// A movable guard keeps AsyncAuthorityStore's returned futures Send.
pub(super) struct OperationLease {
    state: OwnedMutexGuard<OperationState>,
}

impl OperationLease {
    pub(super) fn needs_recovery(&self) -> bool {
        self.state.unfinalized
    }

    /// Mark before BEGIN can enter the worker queue, including a dropped await.
    pub(super) fn begin_attempted(&mut self) {
        self.state.unfinalized = true;
    }

    /// Called only after an awaited finalizer or a drained, idle worker state.
    pub(super) fn finalized(&mut self) {
        self.state.unfinalized = false;
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    use fgit_authority::{
        AuthorityLimits, AuthorityRefusal, CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead,
        ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
    };
    use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
    use fgit_runtime::meter::BudgetClass;
    use fsqlite_types::cx::Cx;

    use super::super::FsqliteAuthorityStore;
    use super::{EngineError, TransientClass};

    fn context(node: &NodeRuntime) -> Cx {
        let cx = Cx::new();
        cx.set_native_cx(node.request_cx(BudgetClass::Request));
        cx
    }

    fn fixture() -> (NodeRuntime, FsqliteAuthorityStore, Cx) {
        let node = RuntimeProfile::deterministic().build().expect("runtime");
        let cx = context(&node);
        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                ":memory:",
                StoreInstanceId::from_raw(905),
                AuthorityLimits::default(),
            ))
            .expect("real engine opens");
        (node, store, cx)
    }

    fn key(tag: &[u8]) -> ImmutableKey {
        ImmutableKey::new(tag.to_vec()).expect("bounded key")
    }

    fn generation(value: u64) -> HeadGeneration {
        HeadGeneration::try_new(value).expect("nonzero generation")
    }

    #[test]
    fn runtime_narrowed_native_context_keeps_authority_operations_and_cancellation() {
        use std::sync::Arc;

        use asupersync::cx::Cx as NativeCx;
        use asupersync::cx::cap as native_cap;
        use asupersync::cx::wrappers::narrow;
        use asupersync::runtime::SpawnError;

        let (node, mut store, owner) = fixture();
        let body_key = key(b"restricted-owner");
        let cancelled_key = key(b"restricted-cancelled");
        node.block_on(async {
            let parent = NativeCx::current().expect("owned runtime context");
            let full = Arc::new(node.request_cx(BudgetClass::Request));
            let restricted = narrow::<native_cap::All, native_cap::None>(&full);
            let held = {
                let _guard = restricted.as_ref().clone().set_current_restricted();
                NativeCx::current().expect("restricted context")
            };
            let guard = NativeCx::set_current(Some(held.clone()));
            let current = NativeCx::current().expect("reinstalled context");
            assert!(!current.capabilities().spawn);
            assert!(!current.capabilities().io);
            assert!(!current.capabilities().time);
            assert!(current.timer_driver().is_none());
            assert_eq!(current.budget(), full.budget());
            assert_eq!(current.task_id(), full.task_id());
            assert!(matches!(
                current.spawn(|_| async { 1 }),
                Err(SpawnError::RuntimeUnavailable)
            ));

            // The connection worker is already owned by the store. SQL uses
            // the caller's explicit cancellation/budget context without
            // granting that caller general runtime spawn authority.
            let operation = Cx::new();
            operation.set_native_cx(current);
            assert_eq!(
                store
                    .put_if_absent(&operation, &body_key, b"committed")
                    .await
                    .expect("restricted caller writes through the owned worker"),
                PutOutcome::Created
            );
            assert_eq!(
                store.read_immutable(&operation, &body_key).await,
                Ok(ImmutableRead::Present(b"committed".to_vec()))
            );
            let after = NativeCx::current().expect("caller survives SQL awaits");
            assert!(!after.capabilities().spawn);
            assert!(!after.capabilities().io);
            assert!(!after.capabilities().time);
            assert_eq!(after.budget(), held.budget());

            let cancelled_full = Arc::new(node.request_cx(BudgetClass::Request));
            let cancelled_restricted = narrow::<native_cap::All, native_cap::None>(&cancelled_full);
            let cancelled_native = {
                let _guard = cancelled_restricted
                    .as_ref()
                    .clone()
                    .set_current_restricted();
                NativeCx::current().expect("separate restricted cancellation context")
            };
            cancelled_native.set_cancel_requested(true);
            let cancelled = Cx::new();
            cancelled.set_native_cx(cancelled_native);
            assert_eq!(
                store
                    .put_if_absent(&cancelled, &cancelled_key, b"absent")
                    .await,
                Err(EngineError::Engine(TransientClass::Cancelled))
            );
            assert!(!held.is_cancel_requested());
            assert_eq!(
                store.read_immutable(&operation, &cancelled_key).await,
                Ok(ImmutableRead::Absent)
            );
            drop(guard);
            let restored = NativeCx::current().expect("parent restored");
            assert_eq!(restored.task_id(), parent.task_id());
            assert_eq!(restored.budget(), parent.budget());
            assert_eq!(restored.capabilities().spawn, parent.capabilities().spawn);
            assert_eq!(restored.capabilities().io, parent.capabilities().io);
            assert_eq!(restored.capabilities().time, parent.capabilities().time);
        });
        node.block_on(store.close(&owner))
            .expect("close owned worker");
        drop(owner);
        assert!(node.join_root(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn all_public_reads_wait_until_another_operations_staged_rows_are_rolled_back() {
        let (node, mut store, cx) = fixture();
        let head_key = HeadKey::new(b"head".to_vec()).expect("head key");
        let body_key = key(b"staged");
        node.block_on(async {
            let initial = match store
                .initialize_head(&cx, &head_key, generation(1), b"initial")
                .await
                .expect("initialize")
            {
                HeadInit::Created(receipt) => receipt,
                other => panic!("unexpected initialization: {other:?}"),
            };
            let mut lease = store.operation(&cx).await.expect("owner");
            store.begin(&cx, &mut lease).await.expect("begin");
            assert_eq!(
                store
                    .put_body(&cx, &body_key, b"uncommitted")
                    .await
                    .expect("stage body"),
                PutOutcome::Created
            );
            let staged = match store
                .exchange_head(&cx, &head_key, initial.token(), generation(2), b"staged")
                .await
                .expect("stage head and issuance")
            {
                CasOutcome::Committed(receipt) => receipt,
                other => panic!("unexpected staged exchange: {other:?}"),
            };
            assert!(store.connection.in_transaction());
            {
                let mut body = std::pin::pin!(store.read_immutable(&cx, &body_key));
                let mut head = std::pin::pin!(store.read_head(&cx, &head_key));
                let mut issued = std::pin::pin!(store.authenticate_head_receipt(&cx, &staged));
                poll_fn(|task| {
                    assert!(body.as_mut().poll(task).is_pending(), "body read must wait");
                    assert!(head.as_mut().poll(task).is_pending(), "head read must wait");
                    assert!(
                        issued.as_mut().poll(task).is_pending(),
                        "issuance read must wait"
                    );
                    Poll::Ready(())
                })
                .await;
            }
            let cause = EngineError::Contract(AuthorityRefusal::Unavailable);
            assert_eq!(
                store.rollback_after(&cx, &mut lease, cause.clone()).await,
                cause
            );
            assert!(!lease.needs_recovery());
            drop(lease);
            assert_eq!(
                store.read_immutable(&cx, &body_key).await.expect("read"),
                ImmutableRead::Absent
            );
            assert_eq!(
                store.read_head(&cx, &head_key).await.expect("read"),
                HeadRead::Present(initial)
            );
            assert_eq!(
                store.authenticate_head_receipt(&cx, &staged).await,
                Err(EngineError::Contract(AuthorityRefusal::UnknownVersionToken))
            );
        });
        node.block_on(store.close(&cx)).expect("close");
    }

    #[test]
    fn queued_local_and_native_cancellation_leave_the_current_owner_usable() {
        for cancel_native in [false, true] {
            let (node, mut store, owner) = fixture();
            let queued = context(&node);
            let owner_key = key(b"owner");
            let queued_key = key(b"queued");
            node.block_on(async {
                let mut lease = store.operation(&owner).await.expect("owner");
                store.begin(&owner, &mut lease).await.expect("begin");
                let mut waiting = Box::pin(store.put_if_absent(&queued, &queued_key, b"cancelled"));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                if cancel_native {
                    queued
                        .attached_native_cx()
                        .expect("native context")
                        .set_cancel_requested(true);
                } else {
                    queued.cancel();
                }
                assert_eq!(
                    waiting.await,
                    Err(EngineError::Engine(TransientClass::Cancelled))
                );
                assert!(
                    store.connection.in_transaction(),
                    "waiter cannot roll back the owner"
                );
                assert_eq!(
                    store
                        .put_body(&owner, &owner_key, b"retained")
                        .await
                        .expect("owner still writes"),
                    PutOutcome::Created
                );
                store
                    .commit(&owner, &mut lease)
                    .await
                    .expect("owner commits");
                drop(lease);
                assert_eq!(
                    store
                        .read_immutable(&owner, &queued_key)
                        .await
                        .expect("read"),
                    ImmutableRead::Absent
                );
                assert_eq!(
                    store
                        .read_immutable(&owner, &owner_key)
                        .await
                        .expect("read"),
                    ImmutableRead::Present(b"retained".to_vec())
                );
            });
            node.block_on(store.close(&owner)).expect("close");
        }
    }

    #[test]
    fn failed_cancelled_rollback_stays_quarantined_until_a_live_caller_finalizes() {
        let (node, mut store, live) = fixture();
        let owner = context(&node);
        let body_key = key(b"cancelled-staging");
        node.block_on(async {
            let mut lease = store.operation(&owner).await.expect("owner");
            store.begin(&owner, &mut lease).await.expect("begin");
            assert_eq!(
                store
                    .put_body(&owner, &body_key, b"uncommitted")
                    .await
                    .expect("stage before cancellation"),
                PutOutcome::Created
            );
            owner.cancel();
            let cause = EngineError::Engine(TransientClass::Cancelled);
            assert_eq!(
                store
                    .rollback_after(&owner, &mut lease, cause.clone())
                    .await,
                cause,
                "cleanup does not replace the original ambiguous failure"
            );
            assert!(lease.needs_recovery());
            assert!(store.connection.in_transaction());
            drop(lease);

            assert_eq!(store.read_immutable(&owner, &body_key).await, Err(cause));
            // Inspect ownership state without performing the recovery under
            // test: a refused next caller must not erase the obligation.
            let inspection = store.operations.acquire(&live).await.expect("live lease");
            assert!(inspection.needs_recovery());
            drop(inspection);
            assert_eq!(
                store
                    .read_immutable(&live, &body_key)
                    .await
                    .expect("live caller drains and rolls back"),
                ImmutableRead::Absent
            );
            assert!(!store.connection.in_transaction());
            assert_eq!(
                store
                    .put_if_absent(&live, &body_key, b"committed after recovery")
                    .await
                    .expect("fresh write is permitted"),
                PutOutcome::Created
            );
        });
        node.block_on(store.close(&live)).expect("close");
    }

    #[test]
    fn dropping_a_dispatched_begin_requires_a_worker_barrier_before_reuse() {
        let (node, mut store, cx) = fixture();
        let body_key = key(b"after-drop");
        let mut observed_pending = false;
        for _ in 0..32 {
            let mut lease = node.block_on(store.operation(&cx)).expect("owner");
            let mut begin = Box::pin(store.begin(&cx, &mut lease));
            // With an idle worker and an empty command channel, this first
            // Pending follows command enqueue, not lock waiting. The worker
            // may already have executed BEGIN, but its response is unconsumed.
            let first = node.block_on(poll_fn(|task| Poll::Ready(begin.as_mut().poll(task))));
            drop(begin);
            match first {
                Poll::Pending => {
                    observed_pending = true;
                    assert!(lease.needs_recovery());
                    drop(lease);
                    let cancelled = context(&node);
                    cancelled.cancel();
                    assert_eq!(
                        node.block_on(store.read_immutable(&cancelled, &body_key)),
                        Err(EngineError::Engine(TransientClass::Cancelled))
                    );
                    assert_eq!(
                        node.block_on(store.read_immutable(&cx, &body_key))
                            .expect("live caller recovers"),
                        ImmutableRead::Absent
                    );
                    assert!(
                        !store.connection.in_transaction(),
                        "recovery awaited the worker and rollback"
                    );
                    assert_eq!(
                        node.block_on(store.put_if_absent(&cx, &body_key, b"new"))
                            .expect("new transaction"),
                        PutOutcome::Created
                    );
                    break;
                }
                Poll::Ready(Ok(())) => {
                    // A worker that responds before the first poll ends did
                    // not exercise the intended boundary. Finalize and retry.
                    let cause = EngineError::Contract(AuthorityRefusal::Unavailable);
                    assert_eq!(
                        node.block_on(store.rollback_after(&cx, &mut lease, cause.clone())),
                        cause
                    );
                }
                Poll::Ready(Err(error)) => panic!("BEGIN failed: {error}"),
            }
        }
        assert!(
            observed_pending,
            "no dispatched BEGIN was abandoned; boundary unexercised"
        );
        node.block_on(store.close(&cx)).expect("close");
    }
}
