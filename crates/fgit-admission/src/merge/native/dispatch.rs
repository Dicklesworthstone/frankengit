//! Explicitly owned Weak route execution through canonical RCR publication.
//! No Strong capability is fabricated. An unknown recovered marker escalates.
mod history;
mod profile;
pub(super) use history::{latest as read_progress, verify as verify_progress};
pub use profile::{CanonicalDispatchProgress, DispatchRoute, MAX_ROUTES, RouteProgress};

use super::{delivery, settlement, storage, unavailable};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, AsyncAdmissionProjection};
use fgit_authority::AsyncAuthorityStore;
use fgit_codec::CanonicalOutboxEffectState;
use fgit_resource::settlement::{DeliveryVerdict, Observation, ProbeVerdict};
use fgit_resource::{LifecycleEvent, ObligationState, ReconcileState};
use fgit_types::{AsciiSlug, RefusalCode};
use settlement::{DeliveryRequest, RuntimeMutation};
use std::future::Future;

/// A serial, caller-owned transport set. The invocation retains its local
/// fences and awaits each operation to drain; no task or future is detached.
/// Route IDs and non-secret configuration commitments must remain immutable.
pub trait DispatchTransport<C: Sync + ?Sized> {
    fn destination(&self) -> AsciiSlug;
    fn routes(&self) -> &[DispatchRoute];
    /// Invocation-local scheduling budget. False leaves canonical Pending state
    /// intact and grants no marker or transport responsibility.
    fn can_deliver(&self, _route: u64) -> bool {
        true
    }
    fn deliver<'a>(
        &'a mut self,
        cx: &'a C,
        route: u64,
        request: &'a DeliveryRequest<'_>,
        attempt: u32,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> impl Future<Output = Result<(DeliveryVerdict, Vec<u8>), RefusalCode>> + 'a;
    fn probe<'a>(
        &'a mut self,
        cx: &'a C,
        route: u64,
        request: &'a DeliveryRequest<'_>,
        checkpoint: &'a (dyn Fn() -> Result<(), RefusalCode> + Sync),
    ) -> impl Future<Output = Result<(ProbeVerdict, Vec<u8>), RefusalCode>> + 'a;
}

/// Authenticate the route execution selected by this exact retained entry.
/// `None` is not permission to send; a caller must still atomically claim it.
pub async fn read_dispatch_progress<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &fgit_chronicle::PublicationBasis,
    entry: &fgit_codec::CanonicalOutboxStateEntry,
    cancelled: &C,
) -> Result<Option<CanonicalDispatchProgress>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    read_progress(store, cx, basis, entry, cancelled).await
}

#[derive(Debug)]
pub struct DispatchResult {
    pub progress: CanonicalDispatchProgress,
    pub effect: Option<CanonicalOutboxEffectState>,
    pub sends: u32,
}

/// Publish the route set and Deferred state together, persist each send marker
/// before I/O, and publish actual observations before terminal settlement.
/// `now` supplies an explicit observation clock; retry time is canonical input,
/// not ambient time inside evaluation. A finite send allowance does not reset
/// any route's persisted attempt or schedule. Zero allowance permits recovery.
pub async fn dispatch_outbox_async<S, P, T, C, N>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    key: AsciiSlug,
    projection: &P,
    transport: &mut T,
    send_allowance: u32,
    limits: AdmissionLimits,
    checkpoint: &C,
    now: &N,
) -> Result<DispatchResult, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: AsyncAdmissionProjection<S> + ?Sized,
    T: DispatchTransport<S::Context>,
    C: Fn() -> Result<(), RefusalCode> + Sync,
    N: Fn() -> Result<u64, RefusalCode>,
{
    limits.validate()?;
    if send_allowance > 1000 {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    if transport.routes().is_empty() || transport.routes().len() > MAX_ROUTES {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    let routes = transport.routes().to_vec();
    let mut sends = 0;
    for _ in 0..(profile::MAX_TRANSITIONS + 128) {
        checkpoint().map_err(unavailable)?;
        if transport.routes() != routes {
            return Err(unavailable(RefusalCode::PublicationPolicyRefused));
        }
        let (basis, _, _) = crate::read_basis_async(store, cx, &context.head_key).await?;
        let state = delivery::read_in(store, cx, &basis, &|| checkpoint().is_err()).await?;
        let Some(entry) = state.outbox.entry(key) else {
            let progress =
                history::retired(store, cx, &basis, key, transport.destination(), &|| {
                    checkpoint().is_err()
                })
                .await?
                .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
            if !progress.matches_plan(context.principal_id, &routes) {
                return Err(unavailable(RefusalCode::PublicationPolicyRefused));
            }
            let origin = super::history::read_body(
                store,
                cx,
                context.repository_id,
                delivery::EFFECT_NAMESPACE,
                progress.origin_effect_root(),
                &|| checkpoint().is_err(),
            )
            .await?;
            let (effect, _) = progress.terminal_objects(&origin).map_err(codec)?;
            return Ok(DispatchResult {
                progress,
                effect: Some(effect),
                sends,
            });
        };
        if entry.destination() != transport.destination()
            || entry.effect_class() != AsciiSlug::from_static("forge-event")
        {
            return Err(unavailable(RefusalCode::PublicationPolicyRefused));
        }
        let effect = delivery::read_effect_in(store, cx, context.repository_id, entry, &|| {
            checkpoint().is_err()
        })
        .await?;
        let selected = read_progress(store, cx, &basis, entry, &|| checkpoint().is_err()).await?;
        let Some(mut progress) = selected else {
            if effect.state() != ObligationState::Committed {
                return Err(unavailable(RefusalCode::PublicationPolicyRefused));
            }
            let deferred = effect
                .transition(LifecycleEvent::Defer, None)
                .map_err(codec)?;
            let first = CanonicalDispatchProgress::start(
                context.repository_id,
                key,
                entry.destination(),
                entry.payload_root(),
                storage::root(&deferred)?,
                context.principal_id,
                routes.clone(),
            )
            .map_err(codec)?;
            settlement::publish_mutation(
                store,
                cx,
                context,
                projection,
                entry,
                RuntimeMutation::Dispatch {
                    next: &first,
                    effect: Some(&deferred),
                    receipt: None,
                },
                limits,
                checkpoint,
            )
            .await?;
            continue;
        };
        if !progress.matches_plan(context.principal_id, &routes) {
            return Err(unavailable(RefusalCode::PublicationPolicyRefused));
        }
        if progress.finished_effect_root().is_some() {
            return Ok(DispatchResult {
                progress,
                effect: Some(effect),
                sends,
            });
        }
        if effect.state() != ObligationState::DeferredExternally
            || progress.origin_effect_root() != entry.effect_state_root()
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        if progress.routes().iter().all(|m| m.state.is_terminal()) {
            let (finished, next, receipt) = progress.finish(&effect).map_err(codec)?;
            if settlement::publish_mutation(
                store,
                cx,
                context,
                projection,
                entry,
                RuntimeMutation::Dispatch {
                    next: &finished,
                    effect: Some(&next),
                    receipt: Some(&receipt),
                },
                limits,
                checkpoint,
            )
            .await?
            {
                return Ok(DispatchResult {
                    progress: finished,
                    effect: Some(next),
                    sends,
                });
            }
            continue;
        }
        let at = now().map_err(unavailable)?;
        // Recover all unknown responsibilities before considering another new
        // send. A fresh CAS is the only grant of a dispatch operation.
        let selected = progress
            .routes()
            .iter()
            .find(|m| m.in_flight || matches!(m.state, ReconcileState::Probing { .. }))
            .or_else(|| {
                progress.routes().iter().find(|m| {
                    matches!(m.state, ReconcileState::Pending { .. })
                        && m.not_before_millis <= at
                        && sends < send_allowance
                        && transport.can_deliver(m.route.id)
                })
            });
        let Some(member) = selected else {
            return Ok(DispatchResult {
                progress,
                effect: None,
                sends,
            });
        };
        let route = member.route.id;
        let attempt = member.attempt;
        let fresh = matches!(member.state, ReconcileState::Pending { .. }) && !member.in_flight;
        if fresh {
            let marker = progress.dispatch(route, at).map_err(codec)?;
            if !settlement::publish_mutation(
                store,
                cx,
                context,
                projection,
                entry,
                RuntimeMutation::Dispatch {
                    next: &marker,
                    effect: None,
                    receipt: None,
                },
                limits,
                checkpoint,
            )
            .await?
            {
                continue;
            }
            progress = marker;
        }
        let events =
            storage::read_events(store, cx, context.repository_id, entry.payload_root()).await?;
        let request = DeliveryRequest {
            key,
            destination: entry.destination(),
            payload_root: entry.payload_root(),
            events: &events,
        };
        checkpoint().map_err(unavailable)?;
        let (observation, evidence) = if fresh {
            sends += 1;
            let (verdict, bytes) = transport
                .deliver(cx, route, &request, attempt, checkpoint)
                .await
                .map_err(unavailable)?;
            (Observation::Delivery(verdict), bytes)
        } else {
            let (verdict, bytes) = transport
                .probe(cx, route, &request, checkpoint)
                .await
                .map_err(unavailable)?;
            (Observation::Probe(verdict), bytes)
        };
        checkpoint().map_err(unavailable)?;
        let observed = progress
            .observe(route, now().map_err(unavailable)?, observation, evidence)
            .map_err(codec)?;
        settlement::publish_mutation(
            store,
            cx,
            context,
            projection,
            entry,
            RuntimeMutation::Dispatch {
                next: &observed,
                effect: None,
                receipt: None,
            },
            limits,
            checkpoint,
        )
        .await?;
    }
    Err(unavailable(RefusalCode::ResourceBudgetExceeded))
}
fn codec(_: fgit_codec::CodecRefusal) -> AdmissionError {
    unavailable(RefusalCode::EvidenceInvalid)
}
