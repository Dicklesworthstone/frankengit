//! A canonical, explicitly selected route set over the shared Weak reconciler.
//! The Strong reconciliation schema and its original bytes remain separate.

use std::num::NonZeroU32;
use std::time::Duration;

use fgit_codec::{
    CanonicalBody, CanonicalOutboxDeliveryReceipt, CanonicalOutboxEffectState, CodecRefusal,
    CryptoBodyIdentity, Decoder, Encoder, OutboxDeliveryDisposition, body_id,
};
use fgit_forge::webhook::WebhookRetrySchedule;
use fgit_resource::settlement::Observation;
use fgit_resource::{
    DownstreamIdempotency, LifecycleEvent, ObligationState, ReconcilePlan, ReconcilePolicy,
    ReconcileState,
};
use fgit_types::{AsciiSlug, Digest, DomainTag, PrincipalId, RepositoryId, SchemaFamily};

use super::super::progress::{read_observation, read_state, write_observation, write_state};

pub const MAX_ROUTES: usize = 32;
pub const MAX_TRANSITIONS: u32 = MAX_ROUTES as u32 * 64 + 1;
const MAX_EVIDENCE: usize = 4096;

/// Immutable non-secret endpoint/incarnation/fence/policy commitment. The
/// configured transport supplies its binding; repository text cannot retarget it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchRoute {
    pub id: u64,
    pub binding: Digest,
    pub max_attempts: u32,
    pub initial_delay_millis: u64,
    pub max_delay_millis: u64,
}

impl DispatchRoute {
    fn policy(&self) -> Result<ReconcilePolicy, CodecRefusal> {
        if !(1..=16).contains(&self.max_attempts)
            || self.initial_delay_millis > self.max_delay_millis
            || self.max_delay_millis > 86_400_000
        {
            return Err(invalid("dispatch_route_policy"));
        }
        NonZeroU32::new(self.max_attempts)
            .map(ReconcilePolicy::new)
            .ok_or_else(|| invalid("dispatch_route_policy"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteProgress {
    pub route: DispatchRoute,
    pub state: ReconcileState,
    pub attempt: u32,
    pub in_flight: bool,
    pub not_before_millis: u64,
    pub observed_at_millis: u64,
    pub evidence: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Start,
    Dispatch {
        route: u64,
        at: u64,
    },
    Observe {
        route: u64,
        at: u64,
        observation: Observation,
    },
    Finish {
        effect: Digest,
    },
}

/// Every route belongs to this one authority-selected execution. A delivered
/// member cannot terminalize an unfinished sibling. A missing observation of a
/// persisted marker requires a Weak probe, never a fresh send or budget reset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalDispatchProgress {
    repository: RepositoryId,
    key: AsciiSlug,
    destination: AsciiSlug,
    payload: Digest,
    origin: Digest,
    owner: PrincipalId,
    routes: Vec<RouteProgress>,
    ordinal: u32,
    previous: Option<Digest>,
    action: Action,
}

impl CanonicalDispatchProgress {
    pub fn start(
        repository: RepositoryId,
        key: AsciiSlug,
        destination: AsciiSlug,
        payload: Digest,
        origin: Digest,
        owner: PrincipalId,
        routes: Vec<DispatchRoute>,
    ) -> Result<Self, CodecRefusal> {
        if routes.is_empty() || routes.len() > MAX_ROUTES {
            return Err(invalid("dispatch_route_limit"));
        }
        let body = Self {
            repository,
            key,
            destination,
            payload,
            origin,
            owner,
            routes: routes
                .into_iter()
                .map(|route| RouteProgress {
                    route,
                    state: ReconcileState::Pending { attempt: 1 },
                    attempt: 1,
                    in_flight: false,
                    not_before_millis: 0,
                    observed_at_millis: 0,
                    evidence: Vec::new(),
                })
                .collect(),
            ordinal: 0,
            previous: None,
            action: Action::Start,
        };
        body.validate()?;
        Ok(body)
    }
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository
    }
    #[must_use]
    pub const fn delivery_key(&self) -> AsciiSlug {
        self.key
    }
    #[must_use]
    pub const fn destination(&self) -> AsciiSlug {
        self.destination
    }
    #[must_use]
    pub const fn payload_root(&self) -> Digest {
        self.payload
    }
    #[must_use]
    pub const fn origin_effect_root(&self) -> Digest {
        self.origin
    }
    #[must_use]
    pub const fn owner(&self) -> PrincipalId {
        self.owner
    }
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }
    #[must_use]
    pub const fn predecessor_progress_root(&self) -> Option<Digest> {
        self.previous
    }
    #[must_use]
    pub fn routes(&self) -> &[RouteProgress] {
        &self.routes
    }
    #[must_use]
    pub const fn finished_effect_root(&self) -> Option<Digest> {
        match self.action {
            Action::Finish { effect } => Some(effect),
            _ => None,
        }
    }
    pub fn root(&self) -> Result<Digest, CodecRefusal> {
        let id = body_id(&CryptoBodyIdentity, self)?;
        Ok(Digest::new(id.algorithm(), *id.digest()))
    }
    #[must_use]
    pub fn matches_plan(&self, owner: PrincipalId, routes: &[DispatchRoute]) -> bool {
        self.owner == owner
            && self.routes.len() == routes.len()
            && self.routes.iter().zip(routes).all(|(a, b)| a.route == *b)
    }
    pub(in crate::merge::native) const fn admits_new_send(&self) -> bool {
        matches!(self.action, Action::Start | Action::Dispatch { .. })
    }
    pub fn dispatch(&self, route: u64, at: u64) -> Result<Self, CodecRefusal> {
        self.advance(Action::Dispatch { route, at }, &[])
    }
    pub fn observe(
        &self,
        route: u64,
        at: u64,
        observation: Observation,
        evidence: Vec<u8>,
    ) -> Result<Self, CodecRefusal> {
        self.advance(
            Action::Observe {
                route,
                at,
                observation,
            },
            &evidence,
        )
    }
    fn advance(&self, action: Action, evidence: &[u8]) -> Result<Self, CodecRefusal> {
        self.validate()?;
        if self.finished_effect_root().is_some() || evidence.len() > MAX_EVIDENCE {
            return Err(invalid("dispatch_terminal_or_evidence"));
        }
        let mut next = self.clone();
        next.previous = Some(self.root()?);
        next.ordinal = self
            .ordinal
            .checked_add(1)
            .filter(|n| *n <= MAX_TRANSITIONS)
            .ok_or_else(|| invalid("dispatch_transition_limit"))?;
        match action {
            Action::Start => return Err(invalid("dispatch_repeated_start")),
            Action::Dispatch { route, at } => {
                let member = next
                    .routes
                    .iter_mut()
                    .find(|m| m.route.id == route)
                    .ok_or_else(|| invalid("dispatch_route"))?;
                if !matches!(member.state, ReconcileState::Pending { .. })
                    || member.in_flight
                    || at < member.not_before_millis
                    || at < member.observed_at_millis
                {
                    return Err(invalid("dispatch_not_due"));
                }
                member.in_flight = true;
                member.observed_at_millis = at;
                member.evidence.clear();
            }
            Action::Observe {
                route,
                at,
                observation,
            } => {
                let member = next
                    .routes
                    .iter_mut()
                    .find(|m| m.route.id == route)
                    .ok_or_else(|| invalid("dispatch_route"))?;
                if at < member.observed_at_millis {
                    return Err(invalid("dispatch_clock_regression"));
                }
                let resumed = match (member.state, member.in_flight, observation) {
                    (ReconcileState::Pending { .. }, true, Observation::Delivery(_)) => {
                        member.state
                    }
                    (ReconcileState::Pending { attempt }, true, Observation::Probe(_)) => {
                        ReconcileState::Probing { attempt }
                    }
                    (ReconcileState::Probing { .. }, false, Observation::Probe(_)) => member.state,
                    _ => return Err(invalid("dispatch_observation")),
                };
                let key = super::super::settlement::resource_key(self.key)
                    .map_err(|_| invalid("dispatch_key"))?;
                let mut plan = ReconcilePlan::from_state(
                    key,
                    DownstreamIdempotency::Weak,
                    member.route.policy()?,
                    resumed,
                )
                .map_err(|_| invalid("dispatch_state"))?;
                member.state = plan
                    .observe(observation)
                    .map_err(|_| invalid("dispatch_observation"))?;
                if let ReconcileState::Pending { attempt }
                | ReconcileState::Probing { attempt }
                | ReconcileState::Delivered { attempt } = member.state
                {
                    member.attempt = attempt;
                }
                if matches!(
                    member.state,
                    ReconcileState::Delivered { .. } | ReconcileState::Undeliverable { .. }
                ) && evidence.is_empty()
                {
                    return Err(invalid("dispatch_terminal_evidence"));
                }
                member.in_flight = false;
                member.observed_at_millis = at;
                member.evidence = evidence.to_vec();
                member.not_before_millis = if let ReconcileState::Pending { attempt } = member.state
                {
                    let schedule = WebhookRetrySchedule {
                        max_attempts: member.route.max_attempts,
                        initial_delay: Duration::from_millis(member.route.initial_delay_millis),
                        max_delay: Duration::from_millis(member.route.max_delay_millis),
                    };
                    let mut seed_bytes = self.key.as_bytes().to_vec();
                    seed_bytes.extend_from_slice(&route.to_be_bytes());
                    let hash = fgit_crypto::sha256_digest(&seed_bytes);
                    let mut seed = [0; 8];
                    seed.copy_from_slice(&hash[..8]);
                    let delay = schedule.delay_for_attempt(attempt, u64::from_be_bytes(seed));
                    at.checked_add(
                        u64::try_from(delay.as_millis())
                            .map_err(|_| invalid("dispatch_retry_time"))?,
                    )
                    .ok_or_else(|| invalid("dispatch_retry_time"))?
                } else {
                    0
                };
            }
            Action::Finish { .. } => {
                if self.outcome().is_none() {
                    return Err(invalid("dispatch_unfinished_routes"));
                }
            }
        }
        next.action = action;
        next.validate()?;
        Ok(next)
    }
    pub fn verify_successor_of(&self, previous: &Self) -> Result<(), CodecRefusal> {
        let evidence = if let Action::Observe { route, .. } = self.action {
            &self
                .routes
                .iter()
                .find(|m| m.route.id == route)
                .ok_or_else(|| invalid("dispatch_route"))?
                .evidence[..]
        } else {
            &[]
        };
        if previous.advance(self.action.clone(), evidence)? != *self {
            return Err(invalid("dispatch_predecessor"));
        }
        Ok(())
    }
    fn outcome(&self) -> Option<(LifecycleEvent, OutboxDeliveryDisposition)> {
        if !self.routes.iter().all(|r| r.state.is_terminal()) {
            return None;
        }
        if self
            .routes
            .iter()
            .any(|r| matches!(r.state, ReconcileState::Indeterminate { .. }))
        {
            Some((
                LifecycleEvent::Escalate,
                OutboxDeliveryDisposition::Indeterminate,
            ))
        } else if self
            .routes
            .iter()
            .any(|r| matches!(r.state, ReconcileState::Undeliverable { .. }))
        {
            Some((
                LifecycleEvent::FailTerminally,
                OutboxDeliveryDisposition::TerminallyRefused,
            ))
        } else {
            Some((
                LifecycleEvent::Acknowledge,
                OutboxDeliveryDisposition::Acknowledged,
            ))
        }
    }
    pub fn terminal_objects(
        &self,
        origin: &CanonicalOutboxEffectState,
    ) -> Result<(CanonicalOutboxEffectState, CanonicalOutboxDeliveryReceipt), CodecRefusal> {
        if origin.root()? != self.origin
            || origin.state() != ObligationState::DeferredExternally
            || origin.repository_id() != self.repository
            || origin.delivery_key() != self.key
            || origin.payload_root() != self.payload
        {
            return Err(invalid("dispatch_origin"));
        }
        let (event, disposition) = self
            .outcome()
            .ok_or_else(|| invalid("dispatch_unfinished_routes"))?;
        let progress_root = if self.finished_effect_root().is_some() {
            self.previous.ok_or_else(|| invalid("dispatch_finish"))?
        } else {
            self.root()?
        };
        let evidence = format!("frankengit/fenced-dispatch/v1:{progress_root}").into_bytes();
        let receipt = CanonicalOutboxDeliveryReceipt::try_new(
            self.repository,
            self.key,
            self.destination,
            self.payload,
            self.origin,
            disposition,
            evidence,
        )?;
        let effect = origin.transition(event, Some(receipt.root()?))?;
        if self
            .finished_effect_root()
            .is_some_and(|root| effect.root().ok() != Some(root))
        {
            return Err(invalid("dispatch_finish_binding"));
        }
        Ok((effect, receipt))
    }
    pub fn finish(
        &self,
        origin: &CanonicalOutboxEffectState,
    ) -> Result<
        (
            Self,
            CanonicalOutboxEffectState,
            CanonicalOutboxDeliveryReceipt,
        ),
        CodecRefusal,
    > {
        let (effect, receipt) = self.terminal_objects(origin)?;
        let next = self.advance(
            Action::Finish {
                effect: effect.root()?,
            },
            &[],
        )?;
        Ok((next, effect, receipt))
    }
    fn validate(&self) -> Result<(), CodecRefusal> {
        super::super::settlement::resource_key(self.key).map_err(|_| invalid("dispatch_key"))?;
        if self.routes.is_empty()
            || self.routes.len() > MAX_ROUTES
            || self.ordinal > MAX_TRANSITIONS
            || (self.ordinal == 0) != self.previous.is_none()
            || (self.ordinal == 0) != matches!(self.action, Action::Start)
        {
            return Err(invalid("dispatch_shape"));
        }
        let mut last = None;
        for m in &self.routes {
            if last.is_some_and(|id| id >= m.route.id)
                || m.evidence.len() > MAX_EVIDENCE
                || m.attempt == 0
                || m.attempt > m.route.max_attempts
                || (m.in_flight && !matches!(m.state, ReconcileState::Pending { .. }))
            {
                return Err(invalid("dispatch_member"));
            }
            last = Some(m.route.id);
            let key = super::super::settlement::resource_key(self.key)
                .map_err(|_| invalid("dispatch_key"))?;
            ReconcilePlan::from_state(key, DownstreamIdempotency::Weak, m.route.policy()?, m.state)
                .map_err(|_| invalid("dispatch_member_state"))?;
            if let ReconcileState::Pending { attempt }
            | ReconcileState::Probing { attempt }
            | ReconcileState::Delivered { attempt } = m.state
                && attempt != m.attempt
            {
                return Err(invalid("dispatch_member_attempt"));
            }
            if self.ordinal == 0
                && (m.state != (ReconcileState::Pending { attempt: 1 })
                    || m.attempt != 1
                    || m.in_flight
                    || m.not_before_millis != 0
                    || m.observed_at_millis != 0
                    || !m.evidence.is_empty())
            {
                return Err(invalid("dispatch_start"));
            }
        }
        if self.finished_effect_root().is_some() && self.outcome().is_none() {
            return Err(invalid("dispatch_finish"));
        }
        Ok(())
    }
}

impl CanonicalBody for CanonicalDispatchProgress {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("outbox-fenced-dispatch");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;
    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_opaque_id(self.repository.as_bytes());
        out.write_bytes("dispatch_key", self.key.as_bytes())?;
        out.write_bytes("dispatch_destination", self.destination.as_bytes())?;
        out.write_digest(&self.payload)?;
        out.write_digest(&self.origin)?;
        out.write_opaque_id(self.owner.as_bytes());
        out.write_scalar(self.ordinal);
        out.write_option(self.previous.as_ref(), |out, r| out.write_digest(r))?;
        out.write_scalar(self.routes.len() as u16);
        for m in &self.routes {
            out.write_scalar(m.route.id);
            out.write_digest(&m.route.binding)?;
            out.write_scalar(m.route.max_attempts);
            out.write_scalar(m.route.initial_delay_millis);
            out.write_scalar(m.route.max_delay_millis);
            write_state(out, m.state);
            out.write_scalar(m.attempt);
            out.write_bool(m.in_flight);
            out.write_scalar(m.not_before_millis);
            out.write_scalar(m.observed_at_millis);
            out.write_bytes("dispatch_evidence", &m.evidence)?;
        }
        match self.action {
            Action::Start => out.write_scalar(0_u16),
            Action::Dispatch { route, at } => {
                out.write_scalar(1_u16);
                out.write_scalar(route);
                out.write_scalar(at);
            }
            Action::Observe {
                route,
                at,
                observation,
            } => {
                out.write_scalar(2_u16);
                out.write_scalar(route);
                out.write_scalar(at);
                write_observation(out, observation);
            }
            Action::Finish { effect } => {
                out.write_scalar(3_u16);
                out.write_digest(&effect)?;
            }
        }
        Ok(())
    }
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let key = AsciiSlug::try_new("dispatch_key", input.read_bytes("dispatch_key")?)?;
        let destination = AsciiSlug::try_new(
            "dispatch_destination",
            input.read_bytes("dispatch_destination")?,
        )?;
        let payload = input.read_digest()?;
        let origin = input.read_digest()?;
        let owner = PrincipalId::from_bytes(input.read_opaque_id("principal_id")?);
        let ordinal = input.read_scalar("dispatch_ordinal")?;
        let previous = input.read_option("dispatch_previous", |input| input.read_digest())?;
        let count = input.read_scalar::<u16>("dispatch_routes")?;
        if usize::from(count) > MAX_ROUTES {
            return Err(invalid("dispatch_route_limit"));
        }
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(usize::from(count))
            .map_err(|_| invalid("dispatch_allocation"))?;
        for _ in 0..count {
            let route = DispatchRoute {
                id: input.read_scalar("dispatch_route_id")?,
                binding: input.read_digest()?,
                max_attempts: input.read_scalar("dispatch_max_attempts")?,
                initial_delay_millis: input.read_scalar("dispatch_initial_delay")?,
                max_delay_millis: input.read_scalar("dispatch_max_delay")?,
            };
            let state = read_state(input)?;
            let attempt = input.read_scalar("dispatch_attempt")?;
            let in_flight = input.read_bool("dispatch_in_flight")?;
            let not_before_millis = input.read_scalar("dispatch_not_before")?;
            let observed_at_millis = input.read_scalar("dispatch_observed_at")?;
            let length = input.read_scalar::<u32>("dispatch_evidence")?;
            if u64::from(length) > input.limits().byte_string_bytes.min(MAX_EVIDENCE as u64) {
                return Err(invalid("dispatch_evidence_limit"));
            }
            let evidence = input.take("dispatch_evidence", length as usize)?.to_vec();
            routes.push(RouteProgress {
                route,
                state,
                attempt,
                in_flight,
                not_before_millis,
                observed_at_millis,
                evidence,
            });
        }
        let action = match input.read_scalar::<u16>("dispatch_action")? {
            0 => Action::Start,
            1 => Action::Dispatch {
                route: input.read_scalar("dispatch_route")?,
                at: input.read_scalar("dispatch_at")?,
            },
            2 => Action::Observe {
                route: input.read_scalar("dispatch_route")?,
                at: input.read_scalar("dispatch_at")?,
                observation: read_observation(input)?,
            },
            3 => Action::Finish {
                effect: input.read_digest()?,
            },
            _ => return Err(invalid("dispatch_action")),
        };
        let body = Self {
            repository,
            key,
            destination,
            payload,
            origin,
            owner,
            routes,
            ordinal,
            previous,
            action,
        };
        body.validate()?;
        Ok(body)
    }
}

const fn invalid(field: &'static str) -> CodecRefusal {
    CodecRefusal::VariantUnknown {
        field,
        observed: 0,
        offset: 0,
    }
}

#[cfg(test)]
mod tests;
