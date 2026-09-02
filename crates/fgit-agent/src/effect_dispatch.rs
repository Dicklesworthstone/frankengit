//! Irreversible-effect gating over the revocation-aware broker.
//!
//! Accepting an external-effect request and reserving its outbox obligation are
//! not the irreversible boundary. The downstream-visible effect starts when the
//! reservation is dispatched. A revocation receipt that was fresh at request
//! acceptance may be stale by then.
//!
//! [`RevocationCheckedEffectBroker`] therefore wraps the lower-level
//! authorization broker and never exposes its raw [`crate::ReservedOutboxEffect`]
//! on the checked path. The resulting [`RevocationAuthorizedOutboxEffect`] may
//! be aborted without more authority, because abort reduces responsibility. To
//! dispatch, however, the caller must present a newly constructed
//! [`crate::CapabilityEffectAuthorization`] for the exact request at the actual
//! dispatch instant. The chain, leaf capability, complete run, effect identity,
//! inputs, and cost are re-bound before the obligation can commit.
//!
//! Once dispatch commits, later reconciliation remains cleanup rather than a
//! new external effect. [`RevocationAuthorizedDeferredOutboxEffect`] therefore
//! exposes the ordinary deferred obligation together with both authorizations.

use core::fmt;

use fgit_resource::{
    RegionCloseOutcome, RegionId, ReleaseReceipt, ResourceVector, SettledObligation,
    kinds::{DispatchAbortReason, OutboxDispatch, OutboxEffectPermit},
};

use crate::{
    AgentInstanceId, AuthorizedOutboxReservationRefused, Capability,
    CapabilityEffectAuthorization, CapabilityEffectAuthorizationRefusal,
    CapabilityRevocationReceipt, DeferredOutboxEffect, EffectGrant, EffectId,
    EffectJournalEntry, EffectJournalRefusal, EffectRecord, EffectRequest, IntentRun,
    IntentRunCommitment, LogicalTime, OutboxCommitRefused, RevocationAuthorizedEffectGrant,
    RevocationCheckedEffectRefusal, RunId, VerifiedCapabilityChain, VerifiedCapabilityChainId,
};

/// Production-facing broker whose external dispatch path rechecks revocation.
#[derive(Debug)]
pub struct RevocationCheckedEffectBroker {
    run: IntentRun,
    run_commitment: IntentRunCommitment,
    inner: crate::effect_authorization::RevocationCheckedEffectBroker,
    dispatch_authorizations: Vec<CapabilityEffectAuthorization>,
}

impl RevocationCheckedEffectBroker {
    /// Opens a checked broker over one exact complete Intent Run.
    ///
    /// # Errors
    ///
    /// Preserves complete-run identity refusals from the lower-level broker.
    pub fn open(
        run: IntentRun,
        region: RegionId,
        agent_instance_id: AgentInstanceId,
    ) -> Result<Self, RevocationCheckedEffectRefusal> {
        let run_commitment = run.commitment()?;
        let inner = crate::effect_authorization::RevocationCheckedEffectBroker::open(
            run.clone(),
            region,
            agent_instance_id,
        )?;
        Ok(Self {
            run,
            run_commitment,
            inner,
            dispatch_authorizations: Vec::new(),
        })
    }

    /// Requests an operation outside the revocation-gated set.
    pub fn request_low_risk(
        &mut self,
        capability: &Capability,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<EffectGrant, RevocationCheckedEffectRefusal> {
        self.inner.request_low_risk(capability, now, request)
    }

    /// Requests one revocation-gated effect and retains its initial proof.
    pub fn request_high_value(
        &mut self,
        chain: &VerifiedCapabilityChain,
        revocations: &CapabilityRevocationReceipt,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<RevocationAuthorizedEffectGrant, RevocationCheckedEffectRefusal> {
        self.inner
            .request_high_value(chain, revocations, now, request)
    }

    /// Aborts a low-risk grant before it becomes a typed obligation.
    pub fn abort_low_risk(
        &mut self,
        grant: EffectGrant,
    ) -> Result<ReleaseReceipt, RevocationCheckedEffectRefusal> {
        self.inner.abort_low_risk(grant)
    }

    /// Aborts a high-value grant. Revocation cannot prevent cleanup.
    pub fn abort_high_value(
        &mut self,
        grant: RevocationAuthorizedEffectGrant,
    ) -> Result<ReleaseReceipt, RevocationCheckedEffectRefusal> {
        self.inner.abort_high_value(grant)
    }

    /// Converts an authorized external effect into a proof-carrying outbox
    /// reservation.
    ///
    /// The raw reservation remains private. It can be aborted directly, but
    /// dispatch requires [`Self::dispatch_authorized_outbox`] and a fresh proof.
    pub fn reserve_authorized_outbox(
        &mut self,
        grant: RevocationAuthorizedEffectGrant,
        dispatch: OutboxDispatch,
    ) -> Result<RevocationAuthorizedOutboxEffect, AuthorizedOutboxReservationRefused> {
        let initial_authorization = grant.authorization();
        let record = grant.record();
        let request = EffectRequest {
            effect_id: record.effect_id,
            parent_effect_id: record.parent_effect_id,
            operation: record.operation,
            cost: record.budget_reserved,
            input_commitment: record.input_commitment,
        };
        let outbox = self.inner.reserve_authorized_outbox(grant, dispatch)?;
        Ok(RevocationAuthorizedOutboxEffect {
            initial_authorization,
            request,
            outbox,
        })
    }

    /// Commits one outbox dispatch only after a fresh exact-request
    /// authorization at `now`.
    ///
    /// # Errors
    ///
    /// Refuses stale/revoked/substituted authorization, a different capability
    /// ancestry or leaf than the accepted grant, evidence-capacity exhaustion,
    /// and ordinary resource/journal commit failures. Every refusal retains the
    /// live reservation or committed deferred obligation for cleanup.
    pub fn dispatch_authorized_outbox(
        &mut self,
        effect: RevocationAuthorizedOutboxEffect,
        chain: &VerifiedCapabilityChain,
        revocations: &CapabilityRevocationReceipt,
        now: LogicalTime,
        attempt: u32,
        actual: &ResourceVector,
    ) -> Result<RevocationAuthorizedDeferredOutboxEffect, AuthorizedOutboxDispatchRefused> {
        if self.dispatch_authorizations.len()
            >= crate::effect_authorization::MAX_EFFECT_AUTHORIZATIONS
        {
            return Err(AuthorizedOutboxDispatchRefused::AuthorizationLimitExceeded {
                effect: Box::new(effect),
                limit: crate::effect_authorization::MAX_EFFECT_AUTHORIZATIONS,
            });
        }
        let dispatch_authorization = match CapabilityEffectAuthorization::authorize(
            &self.run,
            chain,
            revocations,
            now,
            &effect.request,
        ) {
            Ok(authorization) => authorization,
            Err(source) => {
                return Err(AuthorizedOutboxDispatchRefused::Authorization {
                    effect: Box::new(effect),
                    source,
                });
            }
        };
        if dispatch_authorization.verified_chain_id()
            != effect.initial_authorization.verified_chain_id()
        {
            return Err(AuthorizedOutboxDispatchRefused::CapabilityChainChanged {
                effect: Box::new(effect),
                expected: effect.initial_authorization.verified_chain_id(),
                observed: dispatch_authorization.verified_chain_id(),
            });
        }
        if dispatch_authorization.capability_id()
            != effect.initial_authorization.capability_id()
        {
            return Err(AuthorizedOutboxDispatchRefused::LeafCapabilityChanged {
                effect: Box::new(effect),
                expected: effect.initial_authorization.capability_id(),
                observed: dispatch_authorization.capability_id(),
            });
        }
        if now < dispatch_authorization.authorized_at()
            || now >= dispatch_authorization.valid_until()
        {
            return Err(AuthorizedOutboxDispatchRefused::AuthorizationWindowInvalid {
                effect: Box::new(effect),
                authorized_at: dispatch_authorization.authorized_at(),
                valid_until: dispatch_authorization.valid_until(),
                dispatched_at: now,
            });
        }

        self.dispatch_authorizations.push(dispatch_authorization);
        let RevocationAuthorizedOutboxEffect {
            initial_authorization,
            request,
            outbox,
        } = effect;
        match outbox.dispatch(attempt, actual) {
            Ok(deferred) => Ok(RevocationAuthorizedDeferredOutboxEffect {
                initial_authorization,
                dispatch_authorization,
                request,
                deferred,
            }),
            Err(source) => Err(AuthorizedOutboxDispatchRefused::Commit {
                initial_authorization,
                dispatch_authorization,
                request,
                source,
            }),
        }
    }

    /// Complete run identity served by the checked broker.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Coordination run identity served by the checked broker.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run.run_id()
    }

    /// Accepted effect records in acceptance order.
    #[must_use]
    pub fn records(&self) -> Vec<EffectRecord> {
        self.inner.records()
    }

    /// Initial high-value request authorizations.
    #[must_use]
    pub fn authorizations(&self) -> &[CapabilityEffectAuthorization] {
        self.inner.authorizations()
    }

    /// Successful fresh authorizations attempted at actual dispatch boundaries.
    #[must_use]
    pub fn dispatch_authorizations(&self) -> &[CapabilityEffectAuthorization] {
        &self.dispatch_authorizations
    }

    /// Append-only broker journal without a mutable raw broker handle.
    #[must_use]
    pub fn journal(&self) -> Vec<EffectJournalEntry> {
        self.inner.journal()
    }

    /// Closes the owned region and reports quiescence or containment failure.
    pub fn close(self) -> RegionCloseOutcome {
        self.inner.close()
    }
}

/// Live external-effect reservation carrying its original authorization.
#[must_use = "an authorized outbox effect must be aborted or freshly authorized for dispatch"]
#[derive(Debug)]
pub struct RevocationAuthorizedOutboxEffect {
    initial_authorization: CapabilityEffectAuthorization,
    request: EffectRequest,
    outbox: crate::ReservedOutboxEffect,
}

impl RevocationAuthorizedOutboxEffect {
    /// Initial request-time authorization.
    #[must_use]
    pub const fn initial_authorization(&self) -> CapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Exact effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> EffectId {
        self.request.effect_id
    }

    /// Exact request that must be authorized again at dispatch.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.request
    }

    /// Aborts before downstream dispatch. Revocation cannot block cleanup.
    pub fn abort_unused(
        self,
        reason: DispatchAbortReason,
    ) -> Result<SettledObligation<OutboxEffectPermit>, EffectJournalRefusal> {
        self.outbox.abort_unused(reason)
    }
}

/// Committed external effect retaining request-time and dispatch-time proofs.
#[must_use = "a committed external effect must still be reconciled or escalated"]
#[derive(Debug)]
pub struct RevocationAuthorizedDeferredOutboxEffect {
    initial_authorization: CapabilityEffectAuthorization,
    dispatch_authorization: CapabilityEffectAuthorization,
    request: EffectRequest,
    deferred: DeferredOutboxEffect,
}

impl RevocationAuthorizedDeferredOutboxEffect {
    /// Authorization used when the effect was first accepted.
    #[must_use]
    pub const fn initial_authorization(&self) -> CapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Fresh authorization used at the irreversible dispatch boundary.
    #[must_use]
    pub const fn dispatch_authorization(&self) -> CapabilityEffectAuthorization {
        self.dispatch_authorization
    }

    /// Exact dispatched request.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.request
    }

    /// Transfers the committed obligation into ordinary reconciliation.
    ///
    /// Reconciliation reduces outstanding responsibility and therefore remains
    /// available after later revocation.
    #[must_use]
    pub fn into_deferred(self) -> DeferredOutboxEffect {
        self.deferred
    }
}

/// Why an authorized outbox reservation could not dispatch.
#[must_use]
#[derive(Debug)]
pub enum AuthorizedOutboxDispatchRefused {
    /// Fresh revocation or scope authorization failed before dispatch.
    Authorization {
        /// Still-live reservation.
        effect: Box<RevocationAuthorizedOutboxEffect>,
        /// Exact authorization refusal.
        source: CapabilityEffectAuthorizationRefusal,
    },
    /// Fresh authorization named another verified ancestry.
    CapabilityChainChanged {
        /// Still-live reservation.
        effect: Box<RevocationAuthorizedOutboxEffect>,
        /// Chain that authorized initial acceptance.
        expected: VerifiedCapabilityChainId,
        /// Chain presented at dispatch.
        observed: VerifiedCapabilityChainId,
    },
    /// Fresh authorization named another leaf capability.
    LeafCapabilityChanged {
        /// Still-live reservation.
        effect: Box<RevocationAuthorizedOutboxEffect>,
        /// Initial leaf.
        expected: crate::CapabilityId,
        /// Dispatch leaf.
        observed: crate::CapabilityId,
    },
    /// Fresh authorization did not cover the supplied dispatch instant.
    AuthorizationWindowInvalid {
        /// Still-live reservation.
        effect: Box<RevocationAuthorizedOutboxEffect>,
        /// Authorization instant.
        authorized_at: LogicalTime,
        /// Exclusive authorization deadline.
        valid_until: LogicalTime,
        /// Attempted dispatch instant.
        dispatched_at: LogicalTime,
    },
    /// Dispatch-authorization evidence reached its hard ceiling.
    AuthorizationLimitExceeded {
        /// Still-live reservation.
        effect: Box<RevocationAuthorizedOutboxEffect>,
        /// Maximum retained dispatch authorizations.
        limit: usize,
    },
    /// Ordinary resource or journal commit refusal. The embedded obligation can
    /// be recovered as a reservation or deferred effect through the accessors.
    Commit {
        /// Request-time authorization.
        initial_authorization: CapabilityEffectAuthorization,
        /// Dispatch-time authorization.
        dispatch_authorization: CapabilityEffectAuthorization,
        /// Exact request.
        request: EffectRequest,
        /// Ordinary typed commit refusal retaining the live obligation.
        source: Box<OutboxCommitRefused>,
    },
}

impl AuthorizedOutboxDispatchRefused {
    /// Recovers a reservation when no dispatch committed.
    #[must_use]
    pub fn into_reserved(self) -> Option<RevocationAuthorizedOutboxEffect> {
        match self {
            Self::Authorization { effect, .. }
            | Self::CapabilityChainChanged { effect, .. }
            | Self::LeafCapabilityChanged { effect, .. }
            | Self::AuthorizationWindowInvalid { effect, .. }
            | Self::AuthorizationLimitExceeded { effect, .. } => Some(*effect),
            Self::Commit {
                initial_authorization,
                request,
                source,
                ..
            } => source
                .into_reserved()
                .map(|outbox| RevocationAuthorizedOutboxEffect {
                    initial_authorization,
                    request,
                    outbox,
                }),
        }
    }

    /// Recovers a committed effect when journal mirroring failed after dispatch.
    #[must_use]
    pub fn into_deferred(self) -> Option<RevocationAuthorizedDeferredOutboxEffect> {
        match self {
            Self::Commit {
                initial_authorization,
                dispatch_authorization,
                request,
                source,
            } => source.into_deferred().map(|deferred| {
                RevocationAuthorizedDeferredOutboxEffect {
                    initial_authorization,
                    dispatch_authorization,
                    request,
                    deferred,
                }
            }),
            Self::Authorization { .. }
            | Self::CapabilityChainChanged { .. }
            | Self::LeafCapabilityChanged { .. }
            | Self::AuthorizationWindowInvalid { .. }
            | Self::AuthorizationLimitExceeded { .. } => None,
        }
    }
}

impl fmt::Display for AuthorizedOutboxDispatchRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization { source, .. } => {
                write!(formatter, "outbox dispatch authorization refused: {source}")
            }
            Self::CapabilityChainChanged {
                expected, observed, ..
            } => write!(
                formatter,
                "outbox dispatch chain {observed} differs from accepted chain {expected}"
            ),
            Self::LeafCapabilityChanged {
                expected, observed, ..
            } => write!(
                formatter,
                "outbox dispatch leaf {observed} differs from accepted leaf {expected}"
            ),
            Self::AuthorizationWindowInvalid {
                authorized_at,
                valid_until,
                dispatched_at,
                ..
            } => write!(
                formatter,
                "dispatch at {dispatched_at} is outside authorization {authorized_at}..{valid_until}"
            ),
            Self::AuthorizationLimitExceeded { limit, .. } => write!(
                formatter,
                "dispatch authorization evidence limit {limit} is exhausted"
            ),
            Self::Commit { source, .. } => {
                write!(formatter, "authorized outbox dispatch commit refused: {source:?}")
            }
        }
    }
}

impl core::error::Error for AuthorizedOutboxDispatchRefused {}
