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
//! new external effect. The committed wrapper nevertheless retains both
//! authorizations through reconciliation, escalation, and terminal settlement;
//! no public conversion exposes the raw deferred obligation and drops that
//! evidence.

use core::fmt;

use fgit_resource::{
    DownstreamChannel, ReconcilePlan, RegionCloseOutcome, RegionId, ReleaseReceipt,
    ResourceVector, SettledObligation, TerminalFailureReason,
    kinds::{DispatchAbortReason, DownstreamAck, OutboxDispatch, OutboxEffectPermit},
};
use fgit_types::PrincipalId;

use crate::{
    AgentInstanceId, AuthorizedOutboxReservationRefused, Capability,
    CapabilityEffectAuthorization, CapabilityEffectAuthorizationRefusal,
    CapabilityRevocationReceipt, DeferredOutboxEffect, EffectGrant, EffectId,
    EffectJournalEntry, EffectJournalRefusal, EffectRecord, EffectRequest, EscalatedOutboxEffect,
    ExternalEffectOutcome, IntentRun, IntentRunCommitment, LogicalTime, OutboxCommitRefused,
    ReconciliationRefused, RevocationAuthorizedEffectGrant, RevocationCheckedEffectRefusal,
    RunId, VerifiedCapabilityChain, VerifiedCapabilityChainId,
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
        let expected_chain = effect.initial_authorization.verified_chain_id();
        let observed_chain = dispatch_authorization.verified_chain_id();
        if observed_chain != expected_chain {
            return Err(AuthorizedOutboxDispatchRefused::CapabilityChainChanged {
                effect: Box::new(effect),
                expected: expected_chain,
                observed: observed_chain,
            });
        }
        let expected_leaf = effect.initial_authorization.capability_id();
        let observed_leaf = dispatch_authorization.capability_id();
        if observed_leaf != expected_leaf {
            return Err(AuthorizedOutboxDispatchRefused::LeafCapabilityChanged {
                effect: Box::new(effect),
                expected: expected_leaf,
                observed: observed_leaf,
            });
        }
        let authorized_at = dispatch_authorization.authorized_at();
        let valid_until = dispatch_authorization.valid_until();
        if now < authorized_at || now >= valid_until {
            return Err(AuthorizedOutboxDispatchRefused::AuthorizationWindowInvalid {
                effect: Box::new(effect),
                authorized_at,
                valid_until,
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

    /// Reconciles the committed effect while retaining both authorizations in
    /// every terminal, escalated, and recoverable-refusal value.
    ///
    /// Reconciliation reduces outstanding responsibility and therefore remains
    /// available after later revocation. It does not require a new capability
    /// proof, but it also does not discard the proofs that authorized the
    /// irreversible dispatch.
    pub fn reconcile<C, E>(
        self,
        plan: &mut ReconcilePlan,
        channel: &mut C,
        owner: PrincipalId,
        acknowledgement: E,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<RevocationAuthorizedExternalEffectOutcome, RevocationAuthorizedReconciliationRefused>
    where
        C: DownstreamChannel,
        E: FnOnce(u32) -> DownstreamAck,
    {
        let Self {
            initial_authorization,
            dispatch_authorization,
            request,
            deferred,
        } = self;
        match deferred.reconcile(
            plan,
            channel,
            owner,
            acknowledgement,
            output_commitments,
        ) {
            Ok(ExternalEffectOutcome::Acknowledged(settled)) => {
                Ok(RevocationAuthorizedExternalEffectOutcome::Acknowledged(
                    RevocationAuthorizedSettledOutboxEffect {
                        initial_authorization,
                        dispatch_authorization,
                        request,
                        settled,
                    },
                ))
            }
            Ok(ExternalEffectOutcome::TerminallyFailed(settled)) => {
                Ok(RevocationAuthorizedExternalEffectOutcome::TerminallyFailed(
                    RevocationAuthorizedSettledOutboxEffect {
                        initial_authorization,
                        dispatch_authorization,
                        request,
                        settled,
                    },
                ))
            }
            Ok(ExternalEffectOutcome::Escalated(effect)) => {
                Ok(RevocationAuthorizedExternalEffectOutcome::Escalated(
                    RevocationAuthorizedEscalatedOutboxEffect {
                        initial_authorization,
                        dispatch_authorization,
                        request,
                        effect,
                    },
                ))
            }
            Err(ReconciliationRefused::WrongPlan { effect }) => {
                Err(RevocationAuthorizedReconciliationRefused::WrongPlan {
                    effect: Box::new(Self {
                        initial_authorization,
                        dispatch_authorization,
                        request,
                        deferred: *effect,
                    }),
                })
            }
            Err(ReconciliationRefused::AfterSettlement(source)) => {
                Err(RevocationAuthorizedReconciliationRefused::AfterSettlement {
                    initial_authorization,
                    dispatch_authorization,
                    request,
                    source,
                })
            }
        }
    }
}

/// Reconciliation refusal preserving the proof-carrying effect whenever the
/// obligation remains outstanding.
#[must_use]
#[derive(Debug)]
pub enum RevocationAuthorizedReconciliationRefused {
    /// The plan names another downstream key or idempotency contract.
    WrongPlan {
        /// Still-owned proof-carrying deferred effect.
        effect: Box<RevocationAuthorizedDeferredOutboxEffect>,
    },
    /// The resource obligation settled, but the broker journal could not mirror
    /// the terminal transition. Both authorizations remain attached to the
    /// refusal evidence even though there is no live obligation to retry.
    AfterSettlement {
        /// Request-time authorization.
        initial_authorization: CapabilityEffectAuthorization,
        /// Dispatch-time authorization.
        dispatch_authorization: CapabilityEffectAuthorization,
        /// Exact reconciled request.
        request: EffectRequest,
        /// Journal refusal after settlement.
        source: EffectJournalRefusal,
    },
}

impl RevocationAuthorizedReconciliationRefused {
    /// Recovers the live deferred effect on the wrong-plan path.
    #[must_use]
    pub fn into_effect(self) -> Option<RevocationAuthorizedDeferredOutboxEffect> {
        match self {
            Self::WrongPlan { effect } => Some(*effect),
            Self::AfterSettlement { .. } => None,
        }
    }
}

impl fmt::Display for RevocationAuthorizedReconciliationRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPlan { .. } => formatter.write_str(
                "authorized reconciliation plan does not match the deferred effect",
            ),
            Self::AfterSettlement { source, .. } => write!(
                formatter,
                "authorized effect settled but journal mirroring failed: {source}"
            ),
        }
    }
}

impl core::error::Error for RevocationAuthorizedReconciliationRefused {}

/// Terminal or escalated external-effect outcome retaining both authorization
/// identities.
#[must_use]
#[derive(Debug)]
pub enum RevocationAuthorizedExternalEffectOutcome {
    /// Downstream acknowledgement settled the effect.
    Acknowledged(RevocationAuthorizedSettledOutboxEffect),
    /// The downstream proved permanent failure.
    TerminallyFailed(RevocationAuthorizedSettledOutboxEffect),
    /// Automation stopped with a named owner and live escalated obligation.
    Escalated(RevocationAuthorizedEscalatedOutboxEffect),
}

/// Settled external effect retaining both request-time and dispatch-time
/// authorization evidence.
#[derive(Debug)]
pub struct RevocationAuthorizedSettledOutboxEffect {
    initial_authorization: CapabilityEffectAuthorization,
    dispatch_authorization: CapabilityEffectAuthorization,
    request: EffectRequest,
    settled: SettledObligation<OutboxEffectPermit>,
}

impl RevocationAuthorizedSettledOutboxEffect {
    /// Request-time authorization.
    #[must_use]
    pub const fn initial_authorization(&self) -> CapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Dispatch-time authorization.
    #[must_use]
    pub const fn dispatch_authorization(&self) -> CapabilityEffectAuthorization {
        self.dispatch_authorization
    }

    /// Exact terminal request.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.request
    }

    /// Shared terminal obligation evidence.
    #[must_use]
    pub fn settled(&self) -> &SettledObligation<OutboxEffectPermit> {
        &self.settled
    }

    pub(crate) fn into_settled(self) -> SettledObligation<OutboxEffectPermit> {
        self.settled
    }
}

/// Escalated external effect retaining both authorizations while a named owner
/// carries responsibility.
#[must_use = "an authorized escalated effect must be resolved or reported at close"]
#[derive(Debug)]
pub struct RevocationAuthorizedEscalatedOutboxEffect {
    initial_authorization: CapabilityEffectAuthorization,
    dispatch_authorization: CapabilityEffectAuthorization,
    request: EffectRequest,
    effect: EscalatedOutboxEffect,
}

impl RevocationAuthorizedEscalatedOutboxEffect {
    /// Request-time authorization.
    #[must_use]
    pub const fn initial_authorization(&self) -> CapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Dispatch-time authorization.
    #[must_use]
    pub const fn dispatch_authorization(&self) -> CapabilityEffectAuthorization {
        self.dispatch_authorization
    }

    /// Exact escalated request.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.request
    }

    /// Records a late acknowledgement while retaining both authorizations in
    /// the returned terminal value or post-settlement refusal.
    pub fn resolve_acknowledged(
        self,
        acknowledgement: DownstreamAck,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<RevocationAuthorizedSettledOutboxEffect, RevocationAuthorizedEscalationResolutionRefused>
    {
        let Self {
            initial_authorization,
            dispatch_authorization,
            request,
            effect,
        } = self;
        match effect.resolve_acknowledged(acknowledgement, output_commitments) {
            Ok(settled) => Ok(RevocationAuthorizedSettledOutboxEffect {
                initial_authorization,
                dispatch_authorization,
                request,
                settled,
            }),
            Err(source) => Err(RevocationAuthorizedEscalationResolutionRefused {
                initial_authorization,
                dispatch_authorization,
                request,
                source,
            }),
        }
    }

    /// Records a named owner's permanent-failure decision while retaining both
    /// authorizations.
    pub fn resolve_failed(
        self,
        reason: TerminalFailureReason,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<RevocationAuthorizedSettledOutboxEffect, RevocationAuthorizedEscalationResolutionRefused>
    {
        let Self {
            initial_authorization,
            dispatch_authorization,
            request,
            effect,
        } = self;
        match effect.resolve_failed(reason, output_commitments) {
            Ok(settled) => Ok(RevocationAuthorizedSettledOutboxEffect {
                initial_authorization,
                dispatch_authorization,
                request,
                settled,
            }),
            Err(source) => Err(RevocationAuthorizedEscalationResolutionRefused {
                initial_authorization,
                dispatch_authorization,
                request,
                source,
            }),
        }
    }

    pub(crate) fn into_effect(self) -> EscalatedOutboxEffect {
        self.effect
    }
}

/// Journal-mirror failure after an escalated obligation has already settled,
/// retaining both authorization identities for audit and repair.
#[must_use]
#[derive(Debug)]
pub struct RevocationAuthorizedEscalationResolutionRefused {
    initial_authorization: CapabilityEffectAuthorization,
    dispatch_authorization: CapabilityEffectAuthorization,
    request: EffectRequest,
    source: EffectJournalRefusal,
}

impl RevocationAuthorizedEscalationResolutionRefused {
    /// Request-time authorization.
    #[must_use]
    pub const fn initial_authorization(&self) -> CapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Dispatch-time authorization.
    #[must_use]
    pub const fn dispatch_authorization(&self) -> CapabilityEffectAuthorization {
        self.dispatch_authorization
    }

    /// Exact settled request.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.request
    }

    /// Journal refusal observed after settlement.
    #[must_use]
    pub const fn source(&self) -> EffectJournalRefusal {
        self.source
    }
}

impl fmt::Display for RevocationAuthorizedEscalationResolutionRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "authorized escalated effect settled but journal mirroring failed: {}",
            self.source
        )
    }
}

impl core::error::Error for RevocationAuthorizedEscalationResolutionRefused {}

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
    /// be recovered as a reservation or proof-carrying deferred effect through
    /// the accessors.
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

    /// Recovers a proof-carrying committed effect when journal mirroring failed
    /// after dispatch.
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
