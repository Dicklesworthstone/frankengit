//! Canonical reconciliation progress over the shared resource state machine.
//!
//! Each body records a dispatch marker or one actual transport observation.
//! Publication through an RCR and authentication of the predecessor chain are
//! the reader's responsibility; a staged body alone authorizes no transport.

use core::num::NonZeroU32;

use fgit_codec::{CanonicalBody, CodecRefusal, CryptoBodyIdentity, Decoder, Encoder, body_id};
use fgit_resource::settlement::{DeliveryVerdict, Observation, ProbeVerdict};
use fgit_resource::twophase::{EscalationReason, TerminalFailureReason};
use fgit_resource::{DownstreamIdempotency, ReconcilePlan, ReconcilePolicy, ReconcileState};
use fgit_types::{AsciiSlug, Digest, DomainTag, RepositoryId, SchemaFamily};

/// Permanent bound on the number of persisted progress transitions.
pub const MAX_OUTBOX_PROGRESS_TRANSITIONS: u32 = 64;
/// Permanent ceiling for a reconciliation's dispatch budget.
pub const MAX_OUTBOX_PROGRESS_ATTEMPTS: u32 = 16;
/// Maximum evidence retained from any one completed transport operation.
pub const MAX_OUTBOX_PROGRESS_EVIDENCE_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Predecessor {
    root: Digest,
    state: ReconcileState,
    attempt: u32,
    dispatch_in_flight: bool,
    ordinal: u32,
}

/// Immutable progress for one durably deferred canonical outbox obligation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalOutboxProgress {
    repository_id: RepositoryId,
    delivery_key: AsciiSlug,
    destination: AsciiSlug,
    payload_root: Digest,
    origin_effect_root: Digest,
    max_attempts: u32,
    attempt: u32,
    state: ReconcileState,
    dispatch_in_flight: bool,
    ordinal: u32,
    predecessor: Option<Predecessor>,
    observation: Option<Observation>,
    evidence: Vec<u8>,
}

impl CanonicalOutboxProgress {
    /// Starts reconciliation by probing for an earlier call, including a crash
    /// between deferral publication and its first dispatch.
    pub fn start(
        repository_id: RepositoryId,
        delivery_key: AsciiSlug,
        destination: AsciiSlug,
        payload_root: Digest,
        origin_effect_root: Digest,
        policy: ReconcilePolicy,
    ) -> Result<Self, CodecRefusal> {
        let key = super::settlement::resource_key(delivery_key)
            .map_err(|_| invalid("outbox_progress_key", 0))?;
        let body = Self {
            repository_id,
            delivery_key,
            destination,
            payload_root,
            origin_effect_root,
            max_attempts: policy.max_attempts(),
            attempt: 1,
            state: ReconcilePlan::recover(key, DownstreamIdempotency::Strong, policy).state(),
            dispatch_in_flight: false,
            ordinal: 0,
            predecessor: None,
            observation: None,
            evidence: Vec::new(),
        };
        body.validate()?;
        Ok(body)
    }

    /// Records responsibility for the pending dispatch before contacting the
    /// destination. Repeating this marker is refused, not a fresh attempt.
    pub fn mark_dispatch(&self) -> Result<Self, CodecRefusal> {
        let mut next = self.successor()?;
        next.dispatch_in_flight = true;
        next.validate()?;
        Ok(next)
    }

    /// Records a completed delivery or probe through `ReconcilePlan::observe`.
    /// A persisted in-flight dispatch accepts a restart probe at the SAME
    /// attempt; it never resets the budget or fabricates a delivery verdict.
    pub fn observe(
        &self,
        observation: Observation,
        evidence: Vec<u8>,
    ) -> Result<Self, CodecRefusal> {
        let mut next = self.successor()?;
        next.state = self.observed_state(self.state, self.dispatch_in_flight, observation)?;
        next.attempt = state_attempt(next.state).unwrap_or(self.attempt);
        next.dispatch_in_flight = false;
        next.observation = Some(observation);
        next.evidence = evidence;
        next.validate()?;
        Ok(next)
    }

    /// Verifies the exact authenticated predecessor body, its immutable
    /// identity, and every stable obligation and policy binding.
    pub fn verify_successor_of(&self, previous: &Self) -> Result<(), CodecRefusal> {
        self.validate()?;
        previous.validate()?;
        if self.repository_id != previous.repository_id
            || self.delivery_key != previous.delivery_key
            || self.destination != previous.destination
            || self.payload_root != previous.payload_root
            || self.origin_effect_root != previous.origin_effect_root
            || self.max_attempts != previous.max_attempts
            || self.predecessor.as_ref() != Some(&previous.predecessor_description()?)
        {
            return Err(invalid("outbox_progress_predecessor", 0));
        }
        Ok(())
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    /// Stable delivery key used by every transport operation.
    #[must_use]
    pub const fn delivery_key(&self) -> AsciiSlug {
        self.delivery_key
    }
    /// Configured destination bound to the obligation.
    #[must_use]
    pub const fn destination(&self) -> AsciiSlug {
        self.destination
    }
    /// Original payload commitment.
    #[must_use]
    pub const fn payload_root(&self) -> Digest {
        self.payload_root
    }
    /// Deferred lifecycle body whose reconciliation this history owns.
    #[must_use]
    pub const fn origin_effect_root(&self) -> Digest {
        self.origin_effect_root
    }
    /// Persisted policy ceiling, unchanged by restart.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
    /// Current attempt, retained even for terminal states without an ordinal.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
    /// Existing resource reconciler state.
    #[must_use]
    pub const fn state(&self) -> ReconcileState {
        self.state
    }
    /// Whether dispatch responsibility was persisted before its observation.
    #[must_use]
    pub const fn dispatch_in_flight(&self) -> bool {
        self.dispatch_in_flight
    }
    /// Number of immutable transitions after the initial probe state.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }
    /// Exact predecessor progress root, absent only at the start.
    #[must_use]
    pub fn predecessor_progress_root(&self) -> Option<Digest> {
        self.predecessor.as_ref().map(|previous| previous.root)
    }
    /// Actual completed transport observation, absent for start and dispatch marker.
    #[must_use]
    pub const fn observation(&self) -> Option<Observation> {
        self.observation
    }
    /// Original bounded transport evidence, retained byte for byte.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }
    /// Canonical root carried by the authority decision history.
    pub fn root(&self) -> Result<Digest, CodecRefusal> {
        let identity = body_id(&CryptoBodyIdentity, self)?;
        Ok(Digest::new(identity.algorithm(), *identity.digest()))
    }

    fn predecessor_description(&self) -> Result<Predecessor, CodecRefusal> {
        Ok(Predecessor {
            root: self.root()?,
            state: self.state,
            attempt: self.attempt,
            dispatch_in_flight: self.dispatch_in_flight,
            ordinal: self.ordinal,
        })
    }

    fn successor(&self) -> Result<Self, CodecRefusal> {
        self.validate()?;
        let ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or_else(|| invalid("outbox_progress_ordinal", self.ordinal))?;
        let mut next = self.clone();
        next.ordinal = ordinal;
        next.predecessor = Some(self.predecessor_description()?);
        next.observation = None;
        next.evidence.clear();
        Ok(next)
    }

    fn observed_state(
        &self,
        previous: ReconcileState,
        in_flight: bool,
        observation: Observation,
    ) -> Result<ReconcileState, CodecRefusal> {
        let resumed = match (previous, in_flight, observation) {
            (ReconcileState::Pending { .. }, true, Observation::Delivery(_)) => previous,
            (ReconcileState::Pending { attempt }, true, Observation::Probe(_)) => {
                ReconcileState::Probing { attempt }
            }
            (ReconcileState::Probing { .. }, false, Observation::Probe(_)) => previous,
            _ => return Err(invalid("outbox_progress_observation", 0)),
        };
        let policy = self.policy()?;
        let key = super::settlement::resource_key(self.delivery_key)
            .map_err(|_| invalid("outbox_progress_key", 0))?;
        let mut plan =
            ReconcilePlan::from_state(key, DownstreamIdempotency::Strong, policy, resumed)
                .map_err(|_| invalid("outbox_progress_state", 0))?;
        plan.observe(observation)
            .map_err(|_| invalid("outbox_progress_observation", 0))
    }

    fn policy(&self) -> Result<ReconcilePolicy, CodecRefusal> {
        if self.max_attempts > MAX_OUTBOX_PROGRESS_ATTEMPTS {
            return Err(CodecRefusal::CountBoundExceeded {
                field: "outbox_progress_max_attempts",
                observed: u64::from(self.max_attempts),
                limit: u64::from(MAX_OUTBOX_PROGRESS_ATTEMPTS),
            });
        }
        NonZeroU32::new(self.max_attempts)
            .map(ReconcilePolicy::new)
            .ok_or_else(|| invalid("outbox_progress_max_attempts", 0))
    }

    fn validate(&self) -> Result<(), CodecRefusal> {
        self.policy()?;
        super::settlement::resource_key(self.delivery_key)
            .map_err(|_| invalid("outbox_progress_key", 0))?;
        if self.ordinal > MAX_OUTBOX_PROGRESS_TRANSITIONS {
            return Err(CodecRefusal::CountBoundExceeded {
                field: "outbox_progress_ordinal",
                observed: u64::from(self.ordinal),
                limit: u64::from(MAX_OUTBOX_PROGRESS_TRANSITIONS),
            });
        }
        check_state(
            self.state,
            self.attempt,
            self.dispatch_in_flight,
            self.max_attempts,
        )?;
        check_evidence(self.evidence.len())?;
        let Some(previous) = &self.predecessor else {
            if self.ordinal != 0
                || self.state != (ReconcileState::Probing { attempt: 1 })
                || self.attempt != 1
                || self.dispatch_in_flight
                || self.observation.is_some()
                || !self.evidence.is_empty()
            {
                return Err(invalid("outbox_progress_start", 0));
            }
            return Ok(());
        };
        check_state(
            previous.state,
            previous.attempt,
            previous.dispatch_in_flight,
            self.max_attempts,
        )?;
        if previous.ordinal >= MAX_OUTBOX_PROGRESS_TRANSITIONS
            || self.ordinal != previous.ordinal + 1
        {
            return Err(invalid(
                "outbox_progress_predecessor_ordinal",
                previous.ordinal,
            ));
        }
        if let Some(observation) = self.observation {
            let expected =
                self.observed_state(previous.state, previous.dispatch_in_flight, observation)?;
            if self.dispatch_in_flight
                || self.state != expected
                || self.attempt != state_attempt(expected).unwrap_or(previous.attempt)
            {
                return Err(invalid("outbox_progress_result", 0));
            }
            if matches!(
                self.state,
                ReconcileState::Delivered { .. } | ReconcileState::Undeliverable { .. }
            ) && self.evidence.is_empty()
            {
                return Err(invalid("outbox_progress_terminal_evidence", 0));
            }
        } else if !matches!(previous.state, ReconcileState::Pending { .. })
            || previous.dispatch_in_flight
            || !self.dispatch_in_flight
            || self.state != previous.state
            || self.attempt != previous.attempt
            || !self.evidence.is_empty()
        {
            return Err(invalid("outbox_progress_dispatch_marker", 0));
        }
        Ok(())
    }

    fn write_fields(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_bytes("outbox_delivery_key", self.delivery_key.as_bytes())?;
        out.write_bytes("outbox_destination", self.destination.as_bytes())?;
        out.write_digest(&self.payload_root)?;
        out.write_digest(&self.origin_effect_root)?;
        out.write_scalar(self.max_attempts);
        out.write_scalar(self.attempt);
        write_state(out, self.state);
        out.write_bool(self.dispatch_in_flight);
        out.write_scalar(self.ordinal);
        out.write_option(self.predecessor.as_ref(), |out, previous| {
            out.write_digest(&previous.root)?;
            write_state(out, previous.state);
            out.write_scalar(previous.attempt);
            out.write_bool(previous.dispatch_in_flight);
            out.write_scalar(previous.ordinal);
            Ok(())
        })?;
        out.write_option(self.observation.as_ref(), |out, observation| {
            write_observation(out, *observation);
            Ok(())
        })?;
        out.write_bytes("outbox_progress_evidence", &self.evidence)
    }
}

impl CanonicalBody for CanonicalOutboxProgress {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("outbox-reconciliation");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        self.write_fields(out)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let mut body = Self {
            repository_id: RepositoryId::from_bytes(input.read_opaque_id("repository_id")?),
            delivery_key: AsciiSlug::try_new(
                "outbox_delivery_key",
                input.read_bytes("outbox_delivery_key")?,
            )?,
            destination: AsciiSlug::try_new(
                "outbox_destination",
                input.read_bytes("outbox_destination")?,
            )?,
            payload_root: input.read_digest()?,
            origin_effect_root: input.read_digest()?,
            max_attempts: input.read_scalar("outbox_progress_max_attempts")?,
            attempt: input.read_scalar("outbox_progress_attempt")?,
            state: read_state(input)?,
            dispatch_in_flight: input.read_bool("outbox_progress_dispatch_in_flight")?,
            ordinal: input.read_scalar("outbox_progress_ordinal")?,
            predecessor: input.read_option("outbox_progress_predecessor", |input| {
                Ok(Predecessor {
                    root: input.read_digest()?,
                    state: read_state(input)?,
                    attempt: input.read_scalar("outbox_progress_predecessor_attempt")?,
                    dispatch_in_flight: input.read_bool("outbox_progress_predecessor_in_flight")?,
                    ordinal: input.read_scalar("outbox_progress_predecessor_ordinal")?,
                })
            })?,
            observation: input.read_option("outbox_progress_observation", read_observation)?,
            evidence: Vec::new(),
        };
        // Refuse the declared length before allocating or taking the body bytes.
        let length = input.read_scalar::<u32>("outbox_progress_evidence")?;
        let limit = input
            .limits()
            .byte_string_bytes
            .min(MAX_OUTBOX_PROGRESS_EVIDENCE_BYTES as u64);
        if u64::from(length) > limit {
            return Err(CodecRefusal::LengthBoundExceeded {
                field: "outbox_progress_evidence",
                observed: u64::from(length),
                limit,
            });
        }
        body.evidence = input
            .take("outbox_progress_evidence", length as usize)?
            .to_vec();
        body.validate()?;
        Ok(body)
    }
}

fn check_state(
    state: ReconcileState,
    attempt: u32,
    in_flight: bool,
    ceiling: u32,
) -> Result<(), CodecRefusal> {
    if attempt == 0
        || attempt > ceiling
        || state_attempt(state).is_some_and(|value| value != attempt)
        || (in_flight && !matches!(state, ReconcileState::Pending { .. }))
    {
        return Err(invalid("outbox_progress_attempt", attempt));
    }
    Ok(())
}

const fn state_attempt(state: ReconcileState) -> Option<u32> {
    match state {
        ReconcileState::Pending { attempt }
        | ReconcileState::Probing { attempt }
        | ReconcileState::Delivered { attempt } => Some(attempt),
        ReconcileState::Undeliverable { .. } | ReconcileState::Indeterminate { .. } => None,
    }
}

fn check_evidence(length: usize) -> Result<(), CodecRefusal> {
    if length > MAX_OUTBOX_PROGRESS_EVIDENCE_BYTES {
        return Err(CodecRefusal::LengthBoundExceeded {
            field: "outbox_progress_evidence",
            observed: u64::try_from(length).unwrap_or(u64::MAX),
            limit: MAX_OUTBOX_PROGRESS_EVIDENCE_BYTES as u64,
        });
    }
    Ok(())
}

fn write_state(out: &mut Encoder, state: ReconcileState) {
    let (tag, detail): (u16, u32) = match state {
        ReconcileState::Pending { attempt } => (0, attempt),
        ReconcileState::Probing { attempt } => (1, attempt),
        ReconcileState::Delivered { attempt } => (2, attempt),
        ReconcileState::Undeliverable { reason } => (
            3,
            match reason {
                TerminalFailureReason::PermanentDownstreamRejection => 0,
                TerminalFailureReason::ValidityWindowExpired => 1,
                TerminalFailureReason::OperatorDecision => 2,
            },
        ),
        ReconcileState::Indeterminate { reason } => (
            4,
            match reason {
                EscalationReason::IndeterminateDelivery => 0,
                EscalationReason::RetryBudgetExhausted => 1,
                EscalationReason::ProbeContractViolation => 2,
                EscalationReason::PolicyRequiresHuman => 3,
            },
        ),
    };
    out.write_scalar(tag);
    out.write_scalar(detail);
}

fn read_state(input: &mut Decoder<'_>) -> Result<ReconcileState, CodecRefusal> {
    let tag = input.read_scalar::<u16>("outbox_progress_state")?;
    let detail = input.read_scalar::<u32>("outbox_progress_state_detail")?;
    Ok(match tag {
        0 => ReconcileState::Pending { attempt: detail },
        1 => ReconcileState::Probing { attempt: detail },
        2 => ReconcileState::Delivered { attempt: detail },
        3 => ReconcileState::Undeliverable {
            reason: match detail {
                0 => TerminalFailureReason::PermanentDownstreamRejection,
                1 => TerminalFailureReason::ValidityWindowExpired,
                2 => TerminalFailureReason::OperatorDecision,
                _ => return Err(invalid("outbox_progress_failure_reason", detail)),
            },
        },
        4 => ReconcileState::Indeterminate {
            reason: match detail {
                0 => EscalationReason::IndeterminateDelivery,
                1 => EscalationReason::RetryBudgetExhausted,
                2 => EscalationReason::ProbeContractViolation,
                3 => EscalationReason::PolicyRequiresHuman,
                _ => return Err(invalid("outbox_progress_escalation_reason", detail)),
            },
        },
        _ => return Err(invalid("outbox_progress_state", u32::from(tag))),
    })
}

fn write_observation(out: &mut Encoder, observation: Observation) {
    let tag: u16 = match observation {
        Observation::Delivery(DeliveryVerdict::Accepted) => 0,
        Observation::Delivery(DeliveryVerdict::DuplicateSuppressed) => 1,
        Observation::Delivery(DeliveryVerdict::TransientFailure) => 2,
        Observation::Delivery(DeliveryVerdict::PermanentRejection) => 3,
        Observation::Delivery(DeliveryVerdict::AmbiguousTimeout) => 4,
        Observation::Probe(ProbeVerdict::Delivered) => 5,
        Observation::Probe(ProbeVerdict::NotDelivered) => 6,
        Observation::Probe(ProbeVerdict::Unknown) => 7,
    };
    out.write_scalar(tag);
}

fn read_observation(input: &mut Decoder<'_>) -> Result<Observation, CodecRefusal> {
    Ok(
        match input.read_scalar::<u16>("outbox_progress_observation")? {
            0 => Observation::Delivery(DeliveryVerdict::Accepted),
            1 => Observation::Delivery(DeliveryVerdict::DuplicateSuppressed),
            2 => Observation::Delivery(DeliveryVerdict::TransientFailure),
            3 => Observation::Delivery(DeliveryVerdict::PermanentRejection),
            4 => Observation::Delivery(DeliveryVerdict::AmbiguousTimeout),
            5 => Observation::Probe(ProbeVerdict::Delivered),
            6 => Observation::Probe(ProbeVerdict::NotDelivered),
            7 => Observation::Probe(ProbeVerdict::Unknown),
            tag => return Err(invalid("outbox_progress_observation", u32::from(tag))),
        },
    )
}

fn invalid(field: &'static str, observed: u32) -> CodecRefusal {
    CodecRefusal::VariantUnknown {
        field,
        observed,
        offset: 0,
    }
}

#[cfg(test)]
mod tests;
