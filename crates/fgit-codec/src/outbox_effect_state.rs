//! Immutable outbox obligation bodies over the shared resource lifecycle.
//!
//! The outbox index commits each body's root. Publication and predecessor-body
//! authentication belong to the authority reader; decoding validates the local
//! predecessor/state/event relation through `ObligationState::apply`. This
//! representation does not introduce delivery attempts or another state machine.

use fgit_resource::{LifecycleEvent, ObligationState};
use fgit_types::{AsciiSlug, Digest, DomainTag, RepositoryId, SchemaFamily, TxId};

use crate::{CanonicalBody, CodecRefusal, CryptoBodyIdentity, Decoder, Encoder, body_id};

/// Longest post-commit path in the shared lifecycle: defer, escalate, settle.
pub const MAX_OUTBOX_EFFECT_TRANSITIONS: u32 = 3;

/// Canonical persisted state of one already-published delivery obligation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalOutboxEffectState {
    repository_id: RepositoryId,
    delivery_key: AsciiSlug,
    tx_id: TxId,
    payload_root: Digest,
    transition_ordinal: u32,
    state: ObligationState,
    predecessor_root: Option<Digest>,
    predecessor_state: Option<ObligationState>,
    event: Option<LifecycleEvent>,
    evidence_root: Option<Digest>,
}

impl CanonicalOutboxEffectState {
    /// Stages an initial obligation. It becomes canonical only with its outbox
    /// index's authority-head publication.
    #[must_use]
    pub const fn committed(
        repository_id: RepositoryId,
        delivery_key: AsciiSlug,
        tx_id: TxId,
        payload_root: Digest,
    ) -> Self {
        Self {
            repository_id,
            delivery_key,
            tx_id,
            payload_root,
            transition_ordinal: 0,
            state: ObligationState::Committed,
            predecessor_root: None,
            predecessor_state: None,
            event: None,
            evidence_root: None,
        }
    }

    /// Produces an immutable successor using the existing obligation protocol.
    ///
    /// # Errors
    ///
    /// Refuses an illegal lifecycle event, missing acknowledgement evidence,
    /// the permanent ordinal bound, or a canonical identity failure.
    pub fn transition(
        &self,
        event: LifecycleEvent,
        evidence_root: Option<Digest>,
    ) -> Result<Self, CodecRefusal> {
        let state = self.state.apply(event).map_err(|_| invalid_transition(self.state, event))?;
        let next = Self {
            repository_id: self.repository_id,
            delivery_key: self.delivery_key,
            tx_id: self.tx_id,
            payload_root: self.payload_root,
            transition_ordinal: self.transition_ordinal + 1,
            state,
            predecessor_root: Some(self.root()?),
            predecessor_state: Some(self.state),
            event: Some(event),
            evidence_root,
        };
        next.validate()?;
        Ok(next)
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId { self.repository_id }

    /// Stable delivery/idempotency identity.
    #[must_use]
    pub const fn delivery_key(&self) -> AsciiSlug { self.delivery_key }

    /// Original sealed merge transaction; delivery settlement does not change it.
    #[must_use]
    pub const fn tx_id(&self) -> TxId { self.tx_id }

    /// Original immutable event payload.
    #[must_use]
    pub const fn payload_root(&self) -> Digest { self.payload_root }

    /// Number of lifecycle transitions since the initial committed obligation.
    #[must_use]
    pub const fn transition_ordinal(&self) -> u32 { self.transition_ordinal }

    /// Shared obligation lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ObligationState { self.state }

    /// Exact immutable predecessor, absent only for the initial body.
    #[must_use]
    pub const fn predecessor_root(&self) -> Option<Digest> { self.predecessor_root }

    /// Predecessor state to check against the resolved predecessor body.
    #[must_use]
    pub const fn predecessor_state(&self) -> Option<ObligationState> { self.predecessor_state }

    /// Shared lifecycle event producing this successor.
    #[must_use]
    pub const fn event(&self) -> Option<LifecycleEvent> { self.event }

    /// Immutable settlement/reconciliation evidence; acknowledgement requires it.
    #[must_use]
    pub const fn evidence_root(&self) -> Option<Digest> { self.evidence_root }

    /// Deterministic root named by the canonical outbox index.
    ///
    /// # Errors
    ///
    /// Refuses malformed local lifecycle state or canonical identity failure.
    pub fn root(&self) -> Result<Digest, CodecRefusal> {
        let identity = body_id(&CryptoBodyIdentity, self)?;
        Ok(Digest::new(identity.algorithm(), *identity.digest()))
    }

    fn validate(&self) -> Result<(), CodecRefusal> {
        if self.transition_ordinal > MAX_OUTBOX_EFFECT_TRANSITIONS {
            return Err(CodecRefusal::CountBoundExceeded {
                field: "outbox_effect_transition_ordinal",
                observed: u64::from(self.transition_ordinal),
                limit: u64::from(MAX_OUTBOX_EFFECT_TRANSITIONS),
            });
        }
        if self.transition_ordinal == 0 {
            if self.state != ObligationState::Committed
                || self.predecessor_root.is_some()
                || self.predecessor_state.is_some()
                || self.event.is_some()
                || self.evidence_root.is_some()
            {
                return Err(invalid("outbox_effect_initial_state", state_tag(self.state)));
            }
            return Ok(());
        }
        let (Some(_), Some(previous), Some(event)) =
            (self.predecessor_root, self.predecessor_state, self.event)
        else {
            return Err(invalid("outbox_effect_predecessor", 0));
        };
        // Only these states can precede another event in a committed outbox
        // history. Their ordinal follows directly from the shared lifecycle.
        let expected_ordinal = match previous {
            ObligationState::Committed => 1,
            ObligationState::DeferredExternally => 2,
            ObligationState::Escalated => 3,
            ObligationState::Reserved | ObligationState::Acknowledged
            | ObligationState::Aborted | ObligationState::TerminallyFailed
            | ObligationState::Leaked => return Err(invalid_transition(previous, event)),
        };
        if self.transition_ordinal != expected_ordinal {
            return Err(CodecRefusal::VariantUnknown {
                field: "outbox_effect_transition_ordinal",
                observed: self.transition_ordinal,
                offset: 0,
            });
        }
        let resulting = previous.apply(event).map_err(|_| invalid_transition(previous, event))?;
        if resulting != self.state {
            return Err(invalid("outbox_effect_resulting_state", state_tag(self.state)));
        }
        if event == LifecycleEvent::Acknowledge && self.evidence_root.is_none() {
            return Err(invalid("outbox_effect_acknowledgement_evidence", 0));
        }
        Ok(())
    }
}

impl CanonicalBody for CanonicalOutboxEffectState {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("outbox-effect-state");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_bytes("outbox_delivery_key", self.delivery_key.as_bytes())?;
        out.write_internal_object_id(self.tx_id.as_internal_object_id())?;
        out.write_digest(&self.payload_root)?;
        out.write_scalar(self.transition_ordinal);
        out.write_scalar(state_tag(self.state));
        out.write_option(self.predecessor_root.as_ref(), Encoder::write_digest)?;
        out.write_option(self.predecessor_state.as_ref(), |out, state| {
            out.write_scalar(state_tag(*state));
            Ok(())
        })?;
        out.write_option(self.event.as_ref(), |out, event| {
            out.write_scalar(event_tag(*event));
            Ok(())
        })?;
        out.write_option(self.evidence_root.as_ref(), Encoder::write_digest)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let body = Self {
            repository_id: RepositoryId::from_bytes(input.read_opaque_id("repository_id")?),
            delivery_key: AsciiSlug::try_new("outbox_delivery_key", input.read_bytes("outbox_delivery_key")?)?,
            tx_id: TxId::from_internal_object_id(input.read_internal_object_id()?)?,
            payload_root: input.read_digest()?,
            transition_ordinal: input.read_scalar("outbox_effect_transition_ordinal")?,
            state: read_state(input)?,
            predecessor_root: input.read_option("predecessor_effect_state_root", Decoder::read_digest)?,
            predecessor_state: input.read_option("predecessor_effect_state", read_state)?,
            event: input.read_option("outbox_lifecycle_event", read_event)?,
            evidence_root: input.read_option("outbox_effect_evidence", Decoder::read_digest)?,
        };
        body.validate()?;
        Ok(body)
    }
}

const fn state_tag(state: ObligationState) -> u16 {
    match state {
        ObligationState::Reserved => 0,
        ObligationState::Committed => 1,
        ObligationState::DeferredExternally => 2,
        ObligationState::Escalated => 3,
        ObligationState::Acknowledged => 4,
        ObligationState::Aborted => 5,
        ObligationState::TerminallyFailed => 6,
        ObligationState::Leaked => 7,
    }
}

const fn event_tag(event: LifecycleEvent) -> u16 {
    match event {
        LifecycleEvent::Commit => 0,
        LifecycleEvent::Abort => 1,
        LifecycleEvent::Acknowledge => 2,
        LifecycleEvent::Defer => 3,
        LifecycleEvent::Escalate => 4,
        LifecycleEvent::FailTerminally => 5,
        LifecycleEvent::Leak => 6,
    }
}

fn read_state(input: &mut Decoder<'_>) -> Result<ObligationState, CodecRefusal> {
    let offset = input.offset();
    match input.read_scalar::<u16>("outbox_effect_state")? {
        0 => Ok(ObligationState::Reserved),
        1 => Ok(ObligationState::Committed),
        2 => Ok(ObligationState::DeferredExternally),
        3 => Ok(ObligationState::Escalated),
        4 => Ok(ObligationState::Acknowledged),
        5 => Ok(ObligationState::Aborted),
        6 => Ok(ObligationState::TerminallyFailed),
        7 => Ok(ObligationState::Leaked),
        observed => Err(CodecRefusal::VariantUnknown { field: "outbox_effect_state", observed: u32::from(observed), offset }),
    }
}

fn read_event(input: &mut Decoder<'_>) -> Result<LifecycleEvent, CodecRefusal> {
    let offset = input.offset();
    match input.read_scalar::<u16>("outbox_lifecycle_event")? {
        0 => Ok(LifecycleEvent::Commit),
        1 => Ok(LifecycleEvent::Abort),
        2 => Ok(LifecycleEvent::Acknowledge),
        3 => Ok(LifecycleEvent::Defer),
        4 => Ok(LifecycleEvent::Escalate),
        5 => Ok(LifecycleEvent::FailTerminally),
        6 => Ok(LifecycleEvent::Leak),
        observed => Err(CodecRefusal::VariantUnknown { field: "outbox_lifecycle_event", observed: u32::from(observed), offset }),
    }
}

fn invalid(field: &'static str, observed: u16) -> CodecRefusal {
    CodecRefusal::VariantUnknown { field, observed: u32::from(observed), offset: 0 }
}

fn invalid_transition(state: ObligationState, event: LifecycleEvent) -> CodecRefusal {
    CodecRefusal::VariantUnknown {
        field: "outbox_effect_transition",
        observed: (u32::from(state_tag(state)) << 16) | u32::from(event_tag(event)),
        offset: 0,
    }
}
