//! Proof-carrying effect lifecycle for current descendant-head revocations.
//!
//! [`crate::descendant_revocation`] proves that a canonical revocation
//! generation is selected by a current authority head which descends from an
//! Intent Run's exact historical basis.  This module keeps that proof attached
//! after the read.  It deliberately exposes no `into_inner` conversion:
//!
//! ```text
//! current-head revocation receipt
//!     -> request authorization
//!     -> live grant
//!     -> outbox reservation
//!     -> fresh dispatch authorization
//!     -> reconciliation or escalation
//!     -> terminal settlement
//! ```
//!
//! Cleanup operations remain available without a fresh authorization because
//! they reduce outstanding responsibility.  Every pre-terminal refusal either
//! retains the live typed obligation or states that the resource transition
//! already settled and only the journal mirror failed.

use core::fmt;

use fgit_resource::{
    DownstreamChannel, ReconcilePlan, ReleaseReceipt, ResourceVector, SettledObligation,
    TerminalFailureReason,
    kinds::{DispatchAbortReason, DownstreamAck, OutboxDispatch, OutboxEffectPermit},
};
use fgit_types::PrincipalId;

use crate::{
    AuthorizedOutboxDispatchRefused, AuthorizedOutboxReservationRefused,
    CapabilityEffectAuthorizationRefusal, CurrentAuthorityCapabilityEffectAuthorization,
    CurrentAuthorityCapabilityRevocationReceipt, DeferredOutboxEffect, EffectId,
    EffectJournalRefusal, EffectRecord, EffectRequest, EscalatedOutboxEffect,
    ExternalEffectOutcome, LogicalTime, ReconciliationRefused,
    RevocationAuthorizedDeferredOutboxEffect, RevocationAuthorizedEffectGrant,
    RevocationAuthorizedOutboxEffect, RevocationCheckedEffectBroker,
    RevocationCheckedEffectRefusal, VerifiedCapabilityChain,
};

/// Why a current-authority high-value request could not become a live grant.
#[derive(Debug)]
pub enum CurrentAuthorityRevocationCheckedEffectRefusal {
    /// The ancestry-bound revocation receipt refused the exact request.
    Authorization(CapabilityEffectAuthorizationRefusal),
    /// The ordinary checked broker refused after the same authorization check.
    Broker(RevocationCheckedEffectRefusal),
}

impl fmt::Display for CurrentAuthorityRevocationCheckedEffectRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(source) => {
                write!(formatter, "current-authority effect authorization refused: {source}")
            }
            Self::Broker(source) => {
                write!(formatter, "current-authority effect broker refused: {source}")
            }
        }
    }
}

impl core::error::Error for CurrentAuthorityRevocationCheckedEffectRefusal {}

impl From<CapabilityEffectAuthorizationRefusal>
    for CurrentAuthorityRevocationCheckedEffectRefusal
{
    fn from(value: CapabilityEffectAuthorizationRefusal) -> Self {
        Self::Authorization(value)
    }
}

impl From<RevocationCheckedEffectRefusal> for CurrentAuthorityRevocationCheckedEffectRefusal {
    fn from(value: RevocationCheckedEffectRefusal) -> Self {
        Self::Broker(value)
    }
}

/// A live high-value grant carrying the current-head authorization that admitted
/// it.
#[must_use = "a current-authority effect grant still owns a broker budget reservation"]
#[derive(Debug)]
pub struct CurrentAuthorityRevocationAuthorizedEffectGrant {
    authorization: CurrentAuthorityCapabilityEffectAuthorization,
    grant: RevocationAuthorizedEffectGrant,
}

impl CurrentAuthorityRevocationAuthorizedEffectGrant {
    /// Ancestry-bound request-time authorization.
    #[must_use]
    pub const fn authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.authorization
    }

    /// Exact broker record created by the same request.
    #[must_use]
    pub const fn record(&self) -> &EffectRecord {
        self.grant.record()
    }
}

impl RevocationCheckedEffectBroker {
    /// Requests one high-value effect while retaining current-head ancestry
    /// evidence in the returned grant.
    ///
    /// The outer authorization runs first, so a stale or newly revoked
    /// capability cannot move broker budget.  The ordinary broker is then called
    /// with the exact inner receipt and therefore reaches the same pure
    /// [`crate::CapabilityEffectAuthorization`] decision core.
    pub fn request_current_authority_high_value(
        &mut self,
        chain: &VerifiedCapabilityChain,
        revocations: &CurrentAuthorityCapabilityRevocationReceipt,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<
        CurrentAuthorityRevocationAuthorizedEffectGrant,
        CurrentAuthorityRevocationCheckedEffectRefusal,
    > {
        let authorization = CurrentAuthorityCapabilityEffectAuthorization::authorize(
            self_run(self),
            chain,
            revocations,
            now,
            request,
        )?;
        let grant = self.request_high_value(
            chain,
            revocations.admitted(),
            now,
            request,
        )?;
        Ok(CurrentAuthorityRevocationAuthorizedEffectGrant {
            authorization,
            grant,
        })
    }

    /// Aborts a current-authority grant before it becomes a typed obligation.
    ///
    /// No new revocation read is required: abort only releases responsibility.
    pub fn abort_current_authority_high_value(
        &mut self,
        grant: CurrentAuthorityRevocationAuthorizedEffectGrant,
    ) -> Result<ReleaseReceipt, RevocationCheckedEffectRefusal> {
        self.abort_high_value(grant.grant)
    }

    /// Converts a current-authority external grant into a proof-carrying outbox
    /// reservation.
    pub fn reserve_current_authority_outbox(
        &mut self,
        grant: CurrentAuthorityRevocationAuthorizedEffectGrant,
        dispatch: OutboxDispatch,
    ) -> Result<
        CurrentAuthorityRevocationAuthorizedOutboxEffect,
        CurrentAuthorityOutboxReservationRefused,
    > {
        let CurrentAuthorityRevocationAuthorizedEffectGrant {
            authorization,
            grant,
        } = grant;
        match self.reserve_authorized_outbox(grant, dispatch) {
            Ok(outbox) => Ok(CurrentAuthorityRevocationAuthorizedOutboxEffect {
                initial_authorization: authorization,
                outbox,
            }),
            Err(source) => Err(CurrentAuthorityOutboxReservationRefused {
                authorization,
                source,
            }),
        }
    }

    /// Dispatches a proof-carrying outbox effect after a fresh current-head
    /// authorization at the irreversible boundary.
    ///
    /// The same exact request, chain, and inner receipt are passed to the
    /// ordinary dispatch core after the ancestry-bound authorization succeeds.
    /// The resulting deferred effect is immediately re-wrapped around the two
    /// current-authority proofs; no raw deferred obligation is exposed.
    pub fn dispatch_current_authority_outbox(
        &mut self,
        effect: CurrentAuthorityRevocationAuthorizedOutboxEffect,
        chain: &VerifiedCapabilityChain,
        revocations: &CurrentAuthorityCapabilityRevocationReceipt,
        now: LogicalTime,
        attempt: u32,
        actual: &ResourceVector,
    ) -> Result<
        CurrentAuthorityRevocationAuthorizedDeferredOutboxEffect,
        CurrentAuthorityOutboxDispatchRefused,
    > {
        let request = effect.request();
        let dispatch_authorization = match CurrentAuthorityCapabilityEffectAuthorization::authorize(
            self_run(self),
            chain,
            revocations,
            now,
            &request,
        ) {
            Ok(authorization) => authorization,
            Err(source) => {
                return Err(CurrentAuthorityOutboxDispatchRefused::Authorization {
                    effect: Box::new(effect),
                    source,
                });
            }
        };
        let CurrentAuthorityRevocationAuthorizedOutboxEffect {
            initial_authorization,
            outbox,
        } = effect;
        match self.dispatch_authorized_outbox(
            outbox,
            chain,
            revocations.admitted(),
            now,
            attempt,
            actual,
        ) {
            Ok(deferred) => {
                let request = deferred.request();
                Ok(CurrentAuthorityRevocationAuthorizedDeferredOutboxEffect {
                    initial_authorization,
                    dispatch_authorization,
                    request,
                    deferred: deferred.into_deferred(),
                })
            }
            Err(source) => Err(CurrentAuthorityOutboxDispatchRefused::Dispatch {
                initial_authorization,
                dispatch_authorization,
                source,
            }),
        }
    }
}

/// Reads the exact run through a stable public broker fact rather than reaching
/// into either of the broker's private layers.
fn self_run(broker: &RevocationCheckedEffectBroker) -> &crate::IntentRun {
    // `run_id` and `run_commitment` are intentionally insufficient here: the
    // pure authorization core needs the complete machine-enforced run.  The
    // broker does not expose it directly, but every accepted record retains its
    // source receipt only after admission; using a record would therefore be a
    // circular precondition.  This helper is implemented by the crate-private
    // accessor below.
    broker.current_run()
}

/// Reservation failure retaining the ancestry-bound request authorization and,
/// when no resource reservation occurred, a recoverable live grant.
#[must_use]
#[derive(Debug)]
pub struct CurrentAuthorityOutboxReservationRefused {
    authorization: CurrentAuthorityCapabilityEffectAuthorization,
    source: AuthorizedOutboxReservationRefused,
}

impl CurrentAuthorityOutboxReservationRefused {
    /// Request-time authorization that preceded the reservation attempt.
    #[must_use]
    pub const fn authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.authorization
    }

    /// Ordinary typed reservation refusal.
    #[must_use]
    pub const fn source(&self) -> &AuthorizedOutboxReservationRefused {
        &self.source
    }

    /// Recovers the live proof-carrying grant when the ordinary refusal retained
    /// one.
    #[must_use]
    pub fn into_authorized_grant(
        self,
    ) -> Option<CurrentAuthorityRevocationAuthorizedEffectGrant> {
        self.source.into_authorized_grant().map(|grant| {
            CurrentAuthorityRevocationAuthorizedEffectGrant {
                authorization: self.authorization,
                grant,
            }
        })
    }
}

impl fmt::Display for CurrentAuthorityOutboxReservationRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "current-authority outbox reservation refused: {}",
            self.source
        )
    }
}

impl core::error::Error for CurrentAuthorityOutboxReservationRefused {}

/// Live outbox reservation carrying its ancestry-bound request authorization.
#[must_use = "a current-authority outbox effect must be aborted or freshly authorized for dispatch"]
#[derive(Debug)]
pub struct CurrentAuthorityRevocationAuthorizedOutboxEffect {
    initial_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    outbox: RevocationAuthorizedOutboxEffect,
}

impl CurrentAuthorityRevocationAuthorizedOutboxEffect {
    /// Current-head authorization used at request acceptance.
    #[must_use]
    pub const fn initial_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Exact effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> EffectId {
        self.outbox.effect_id()
    }

    /// Exact request that must receive a fresh authorization before dispatch.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.outbox.request()
    }

    /// Aborts before any downstream effect.  Later revocation cannot block
    /// cleanup.
    pub fn abort_unused(
        self,
        reason: DispatchAbortReason,
    ) -> Result<SettledObligation<OutboxEffectPermit>, EffectJournalRefusal> {
        self.outbox.abort_unused(reason)
    }
}

/// Dispatch failure retaining enough proof and obligation state for exact
/// cleanup or reconciliation.
#[must_use]
#[derive(Debug)]
pub enum CurrentAuthorityOutboxDispatchRefused {
    /// The fresh current-head authorization failed before dispatch was attempted.
    Authorization {
        /// Still-live proof-carrying reservation.
        effect: Box<CurrentAuthorityRevocationAuthorizedOutboxEffect>,
        /// Exact authorization refusal.
        source: CapabilityEffectAuthorizationRefusal,
    },
    /// The ordinary dispatch core refused.  Its typed value determines whether
    /// the obligation remains reserved or already committed.
    Dispatch {
        /// Request-time current-head authorization.
        initial_authorization: CurrentAuthorityCapabilityEffectAuthorization,
        /// Fresh current-head authorization computed for this dispatch attempt.
        dispatch_authorization: CurrentAuthorityCapabilityEffectAuthorization,
        /// Ordinary typed dispatch refusal retaining the live obligation.
        source: AuthorizedOutboxDispatchRefused,
    },
}

impl CurrentAuthorityOutboxDispatchRefused {
    /// Recovers the still-reserved effect when no dispatch committed.
    #[must_use]
    pub fn into_reserved(self) -> Option<CurrentAuthorityRevocationAuthorizedOutboxEffect> {
        match self {
            Self::Authorization { effect, .. } => Some(*effect),
            Self::Dispatch {
                initial_authorization,
                source,
                ..
            } => source.into_reserved().map(|outbox| {
                CurrentAuthorityRevocationAuthorizedOutboxEffect {
                    initial_authorization,
                    outbox,
                }
            }),
        }
    }

    /// Recovers a committed deferred effect when dispatch occurred before the
    /// ordinary journal mirror refused.
    #[must_use]
    pub fn into_deferred(
        self,
    ) -> Option<CurrentAuthorityRevocationAuthorizedDeferredOutboxEffect> {
        match self {
            Self::Dispatch {
                initial_authorization,
                dispatch_authorization,
                source,
            } => source.into_deferred().map(|deferred| {
                let request = deferred.request();
                CurrentAuthorityRevocationAuthorizedDeferredOutboxEffect {
                    initial_authorization,
                    dispatch_authorization,
                    request,
                    deferred: deferred.into_deferred(),
                }
            }),
            Self::Authorization { .. } => None,
        }
    }
}

impl fmt::Display for CurrentAuthorityOutboxDispatchRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization { source, .. } => write!(
                formatter,
                "current-authority dispatch authorization refused: {source}"
            ),
            Self::Dispatch { source, .. } => write!(
                formatter,
                "current-authority dispatch transition refused: {source}"
            ),
        }
    }
}

impl core::error::Error for CurrentAuthorityOutboxDispatchRefused {}

/// Committed external effect retaining both ancestry-bound authorizations and
/// exposing reconciliation without a raw-deferred escape hatch.
#[must_use = "a current-authority deferred effect must be reconciled or escalated"]
#[derive(Debug)]
pub struct CurrentAuthorityRevocationAuthorizedDeferredOutboxEffect {
    initial_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    dispatch_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    request: EffectRequest,
    deferred: DeferredOutboxEffect,
}

impl CurrentAuthorityRevocationAuthorizedDeferredOutboxEffect {
    /// Request-time current-head authorization.
    #[must_use]
    pub const fn initial_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Fresh authorization used at the irreversible dispatch boundary.
    #[must_use]
    pub const fn dispatch_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.dispatch_authorization
    }

    /// Exact dispatched request.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.request
    }

    /// Reconciles the committed effect while retaining both authorization
    /// identities in every resulting terminal or escalated value.
    pub fn reconcile<C, E>(
        self,
        plan: &mut ReconcilePlan,
        channel: &mut C,
        owner: PrincipalId,
        acknowledgement: E,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<CurrentAuthorityExternalEffectOutcome, CurrentAuthorityReconciliationRefused>
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
                Ok(CurrentAuthorityExternalEffectOutcome::Acknowledged(
                    CurrentAuthoritySettledOutboxEffect {
                        initial_authorization,
                        dispatch_authorization,
                        request,
                        settled,
                    },
                ))
            }
            Ok(ExternalEffectOutcome::TerminallyFailed(settled)) => {
                Ok(CurrentAuthorityExternalEffectOutcome::TerminallyFailed(
                    CurrentAuthoritySettledOutboxEffect {
                        initial_authorization,
                        dispatch_authorization,
                        request,
                        settled,
                    },
                ))
            }
            Ok(ExternalEffectOutcome::Escalated(effect)) => {
                Ok(CurrentAuthorityExternalEffectOutcome::Escalated(
                    CurrentAuthorityEscalatedOutboxEffect {
                        initial_authorization,
                        dispatch_authorization,
                        request,
                        effect,
                    },
                ))
            }
            Err(ReconciliationRefused::WrongPlan { effect }) => {
                Err(CurrentAuthorityReconciliationRefused::WrongPlan {
                    effect: Box::new(Self {
                        initial_authorization,
                        dispatch_authorization,
                        request,
                        deferred: *effect,
                    }),
                })
            }
            Err(ReconciliationRefused::AfterSettlement(source)) => {
                Err(CurrentAuthorityReconciliationRefused::AfterSettlement {
                    initial_authorization,
                    dispatch_authorization,
                    request,
                    source,
                })
            }
        }
    }
}

/// Reconciliation refusal preserving the live proof-carrying effect whenever
/// the obligation remains outstanding.
#[must_use]
#[derive(Debug)]
pub enum CurrentAuthorityReconciliationRefused {
    /// The plan names another downstream key or idempotency contract.
    WrongPlan {
        /// Still-owned proof-carrying deferred effect.
        effect: Box<CurrentAuthorityRevocationAuthorizedDeferredOutboxEffect>,
    },
    /// The resource obligation settled, but the ordinary journal mirror refused.
    /// The proof lineage is retained even though there is no live obligation to
    /// retry.
    AfterSettlement {
        /// Request-time authorization.
        initial_authorization: CurrentAuthorityCapabilityEffectAuthorization,
        /// Dispatch-time authorization.
        dispatch_authorization: CurrentAuthorityCapabilityEffectAuthorization,
        /// Exact reconciled request.
        request: EffectRequest,
        /// Journal refusal after the resource settlement.
        source: EffectJournalRefusal,
    },
}

impl CurrentAuthorityReconciliationRefused {
    /// Recovers the deferred effect on the wrong-plan path.
    #[must_use]
    pub fn into_effect(
        self,
    ) -> Option<CurrentAuthorityRevocationAuthorizedDeferredOutboxEffect> {
        match self {
            Self::WrongPlan { effect } => Some(*effect),
            Self::AfterSettlement { .. } => None,
        }
    }
}

impl fmt::Display for CurrentAuthorityReconciliationRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPlan { .. } => formatter.write_str(
                "current-authority reconciliation plan does not match the deferred effect",
            ),
            Self::AfterSettlement { source, .. } => write!(
                formatter,
                "current-authority effect settled but journal mirroring failed: {source}"
            ),
        }
    }
}

impl core::error::Error for CurrentAuthorityReconciliationRefused {}

/// Terminal or escalated external-effect outcome retaining both current-head
/// authorization identities.
#[must_use]
#[derive(Debug)]
pub enum CurrentAuthorityExternalEffectOutcome {
    /// Downstream acknowledgement settled the effect.
    Acknowledged(CurrentAuthoritySettledOutboxEffect),
    /// The downstream proved permanent failure.
    TerminallyFailed(CurrentAuthoritySettledOutboxEffect),
    /// Automation stopped with a named owner and a live escalated obligation.
    Escalated(CurrentAuthorityEscalatedOutboxEffect),
}

/// Settled external effect retaining complete current-head authorization
/// lineage.
#[derive(Debug)]
pub struct CurrentAuthoritySettledOutboxEffect {
    initial_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    dispatch_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    request: EffectRequest,
    settled: SettledObligation<OutboxEffectPermit>,
}

impl CurrentAuthoritySettledOutboxEffect {
    /// Request-time authorization.
    #[must_use]
    pub const fn initial_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Dispatch-time authorization.
    #[must_use]
    pub const fn dispatch_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.dispatch_authorization
    }

    /// Exact terminal request.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.request
    }

    /// Shared terminal obligation evidence.
    #[must_use]
    pub const fn settled(&self) -> &SettledObligation<OutboxEffectPermit> {
        &self.settled
    }
}

/// Escalated external effect retaining proof lineage while a named owner holds
/// responsibility.
#[must_use = "an escalated current-authority effect must be resolved or reported at close"]
#[derive(Debug)]
pub struct CurrentAuthorityEscalatedOutboxEffect {
    initial_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    dispatch_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    request: EffectRequest,
    effect: EscalatedOutboxEffect,
}

impl CurrentAuthorityEscalatedOutboxEffect {
    /// Request-time authorization.
    #[must_use]
    pub const fn initial_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Dispatch-time authorization.
    #[must_use]
    pub const fn dispatch_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.dispatch_authorization
    }

    /// Exact escalated request.
    #[must_use]
    pub const fn request(&self) -> EffectRequest {
        self.request
    }

    /// Records a late acknowledgement while retaining authorization lineage in
    /// the returned terminal value or refusal evidence.
    pub fn resolve_acknowledged(
        self,
        acknowledgement: DownstreamAck,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<CurrentAuthoritySettledOutboxEffect, CurrentAuthorityEscalationResolutionRefused>
    {
        let Self {
            initial_authorization,
            dispatch_authorization,
            request,
            effect,
        } = self;
        match effect.resolve_acknowledged(acknowledgement, output_commitments) {
            Ok(settled) => Ok(CurrentAuthoritySettledOutboxEffect {
                initial_authorization,
                dispatch_authorization,
                request,
                settled,
            }),
            Err(source) => Err(CurrentAuthorityEscalationResolutionRefused {
                initial_authorization,
                dispatch_authorization,
                request,
                source,
            }),
        }
    }

    /// Records a named owner's permanent-failure decision while retaining proof
    /// lineage.
    pub fn resolve_failed(
        self,
        reason: TerminalFailureReason,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<CurrentAuthoritySettledOutboxEffect, CurrentAuthorityEscalationResolutionRefused>
    {
        let Self {
            initial_authorization,
            dispatch_authorization,
            request,
            effect,
        } = self;
        match effect.resolve_failed(reason, output_commitments) {
            Ok(settled) => Ok(CurrentAuthoritySettledOutboxEffect {
                initial_authorization,
                dispatch_authorization,
                request,
                settled,
            }),
            Err(source) => Err(CurrentAuthorityEscalationResolutionRefused {
                initial_authorization,
                dispatch_authorization,
                request,
                source,
            }),
        }
    }
}

/// Journal-mirror failure after an escalated obligation has already settled,
/// retaining both authorization identities for audit and repair.
#[must_use]
#[derive(Debug)]
pub struct CurrentAuthorityEscalationResolutionRefused {
    initial_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    dispatch_authorization: CurrentAuthorityCapabilityEffectAuthorization,
    request: EffectRequest,
    source: EffectJournalRefusal,
}

impl CurrentAuthorityEscalationResolutionRefused {
    /// Request-time authorization.
    #[must_use]
    pub const fn initial_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.initial_authorization
    }

    /// Dispatch-time authorization.
    #[must_use]
    pub const fn dispatch_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
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

impl fmt::Display for CurrentAuthorityEscalationResolutionRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "current-authority escalated effect settled but journal mirroring failed: {}",
            self.source
        )
    }
}

impl core::error::Error for CurrentAuthorityEscalationResolutionRefused {}
