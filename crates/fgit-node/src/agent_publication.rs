//! Native submission of an ECC-checked agent change by a trusted local host.
//!
//! This profile preserves the independently authorized local operator principal.
//! It does not accept an AgentRequest, convert sponsored bearer credentials into
//! source-write grants, or treat the prepared Rust type as authentication.
//! The broker owns submission responsibility; ordinary admission alone owns
//! preparation, exact-head CAS and the canonical decision.

use core::fmt;
use std::rc::Rc;
use std::time::Duration;

use asupersync::types::Time;
use fgit_admission::evidence::AdmissionAuthentication;
use fgit_admission::{AdmissionLimits, AdmissionResult, BasisBoundValidatedReceive};
use fgit_agent::ref_publication::{
    ObservedRefTransaction, PendingRefTransactionSubmission, RefTransactionBinding,
    RefTransactionEffectRefusal, RefTransactionObservationRefusal,
    RefTransactionReconciliationRefused, RefTransactionResolution, RefTransactionStartRefused,
    ReservedRefTransactionSubmission, SettledRefTransactionSubmission,
    observe_ref_transaction_async,
};
use fgit_agent::{
    AgentRefTransaction, CurrentAuthorityCapabilityEffectAuthorization,
    CurrentAuthorityCapabilityRevocationReadRefusal, CurrentAuthorityRevocationCheckedEffectBroker,
    EffectId, LogicalTime, OperationClass, RunReconciliationReport, VerifiedCapabilityChain,
    read_current_authority_capability_revocations_async,
};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew};
use fgit_crypto::{GitHashAlgorithm, sha256_digest};
use fgit_resource::{Grade, ResourceVector};
use fgit_runtime::NodeRuntime;
use fgit_treefs::ExportPlan;
use fgit_types::PrincipalId;

use crate::{
    AuthenticatedReceiveSession, LoopbackReceiveSession, NodeReceiveTransportRefusal,
    NodeRequestContext, NodeWorkspaceRefusal, OneNode, agent_journal::RecoveredAgentJournal,
    receive_staging::ReceiveStaging,
};

/// Native profile limits, additionally narrowed by node quarantine policy.
pub const MAX_AGENT_PUBLICATION_OBJECTS: usize = 10_000;
pub const MAX_AGENT_PUBLICATION_EXPORT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_AGENT_PUBLICATION_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const CANDIDATE_BYTES: usize = 2 * 1024 * 1024;

/// An independent local-owner approval of exact ECC and candidate bytes.
///
/// The host must obtain these commitments from its review/approval owner, not
/// copy them from untrusted agent input as a substitute for approval. The host
/// also authorizes this real operator principal. Ordinary installed ref policy
/// still decides whether that principal may publish. No bearer scope is widened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedLocalAgentPublicationApproval {
    principal: PrincipalId,
    key: IdempotencyKey,
    publication_binding: [u8; 32],
    candidate_body_sha256: [u8; 32],
}

impl TrustedLocalAgentPublicationApproval {
    #[must_use]
    pub fn new(
        principal: PrincipalId,
        key: IdempotencyKey,
        independently_approved_binding: [u8; 32],
        independently_approved_commit_body_sha256: [u8; 32],
    ) -> Self {
        Self {
            principal,
            key,
            publication_binding: independently_approved_binding,
            candidate_body_sha256: independently_approved_commit_body_sha256,
        }
    }
}

/// Explicit mapping of a trusted host's logical clock to this live node runtime.
///
/// LogicalTime has no implicit seconds/nanoseconds unit. This clock retains its
/// runtime owner, never moves to another node/restart, and uses checked arithmetic.
/// The existing request context must already expire within effect authorization;
/// its original cancellation, parent ownership and quotas are never replaced.
pub struct TrustedLocalAgentPublicationClock<'node> {
    runtime: &'node NodeRuntime,
    owner: Rc<()>,
    logical_origin: LogicalTime,
    runtime_origin: Time,
    nanos_per_tick: u64,
}

impl TrustedLocalAgentPublicationClock<'_> {
    pub fn now(&self) -> Result<LogicalTime, NativeAgentPublicationRefusal> {
        let elapsed = self
            .runtime
            .now()
            .as_nanos()
            .checked_sub(self.runtime_origin.as_nanos())
            .ok_or(NativeAgentPublicationRefusal::Clock)?;
        let ticks = elapsed / self.nanos_per_tick;
        self.logical_origin
            .value()
            .checked_add(ticks)
            .map(LogicalTime::new)
            .ok_or(NativeAgentPublicationRefusal::Clock)
    }

    fn require_request_before(
        &self,
        node: &OneNode,
        request: &NodeRequestContext,
        expiry: LogicalTime,
    ) -> Result<(), NativeAgentPublicationRefusal> {
        if !std::ptr::eq(self.runtime, node.runtime()) {
            return Err(NativeAgentPublicationRefusal::Clock);
        }
        let delta = expiry
            .value()
            .checked_sub(self.logical_origin.value())
            .and_then(|ticks| ticks.checked_mul(self.nanos_per_tick))
            .and_then(|nanos| self.runtime_origin.as_nanos().checked_add(nanos))
            .ok_or(NativeAgentPublicationRefusal::Clock)?;
        let expiry = Time::from_nanos(delta);
        let native = request
            .authority()
            .attached_native_cx()
            .ok_or(NativeAgentPublicationRefusal::AuthorizationDeadlineUnbound)?;
        let deadline = native
            .budget()
            .deadline
            .ok_or(NativeAgentPublicationRefusal::AuthorizationDeadlineUnbound)?;
        if deadline > expiry {
            return Err(NativeAgentPublicationRefusal::AuthorizationDeadlineUnbound);
        }
        if self.runtime.now() >= expiry || !request.is_live() {
            return Err(NativeAgentPublicationRefusal::CancelledOrExpired);
        }
        Ok(())
    }
}

/// All inert inputs for one exact branch creation or single-parent update.
pub struct TrustedLocalAgentPublicationInput<'a, A: GitHashAlgorithm> {
    pub transaction: &'a AgentRefTransaction<A>,
    pub export: &'a ExportPlan<A>,
    pub bundle: &'a [u8],
    pub approval: &'a TrustedLocalAgentPublicationApproval,
    pub chain: &'a VerifiedCapabilityChain,
}

/// Exact live custody retained when responsibility started but ordinary
/// admission was never invoked. Only the native host can construct this owner.
/// It cannot be cloned, reconstructed from a journal, or moved to a new clock.
#[must_use = "resume this exact undispatched publication or retain its pending responsibility"]
#[derive(Debug)]
pub struct UndispatchedNativeAgentPublication {
    pending: PendingRefTransactionSubmission,
    validated: BasisBoundValidatedReceive,
    staging: ReceiveStaging,
    session: LoopbackReceiveSession,
    clock_owner: Rc<()>,
}

impl UndispatchedNativeAgentPublication {
    #[must_use]
    pub fn binding(&self) -> &RefTransactionBinding {
        self.pending.binding()
    }

    /// Discard native object custody and retain observation-only responsibility.
    /// This does not cancel the canonical transaction or settle the obligation.
    #[must_use]
    pub fn into_pending(self) -> PendingRefTransactionSubmission {
        self.pending
    }
}

enum PreparedNativeAgentPublication {
    Recovered(ObservedRefTransaction),
    Ready(UndispatchedNativeAgentPublication),
}

/// Pre-start reason; no variant by itself proves an earlier submission failed.
#[derive(Debug)]
pub enum NativeAgentPublicationRefusal {
    Binding(&'static str),
    Profile(&'static str),
    Clock,
    AuthorizationDeadlineUnbound,
    CancelledOrExpired,
    ExistingSubmissionPending(RefTransactionBinding),
    Workspace(Box<NodeWorkspaceRefusal>),
    Revocations(Box<CurrentAuthorityCapabilityRevocationReadRefusal>),
    Effect(Box<RefTransactionEffectRefusal>),
    Observation(Box<RefTransactionObservationRefusal>),
}

impl fmt::Display for NativeAgentPublicationRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "native checked agent publication refused: {self:?}")
    }
}
impl core::error::Error for NativeAgentPublicationRefusal {}

/// Failures explicitly return every reservation or pending responsibility.
#[must_use]
#[derive(Debug)]
pub enum NativeAgentPublicationError {
    Preflight(NativeAgentPublicationRefusal),
    Reserved {
        reservation: Box<ReservedRefTransactionSubmission>,
        reason: NativeAgentPublicationRefusal,
    },
    Start(Box<RefTransactionStartRefused>),
    /// Responsibility started successfully, but ordinary admission was never
    /// invoked. Only this retained native owner can complete the first dispatch.
    Started {
        publication: Box<UndispatchedNativeAgentPublication>,
        reason: NativeAgentPublicationRefusal,
    },
    /// An authenticated terminal settled responsibility, but its journal mirror
    /// still needs recovery. This cannot return a resumable publication owner.
    Reconciliation(Box<RefTransactionReconciliationRefused>),
}
impl fmt::Display for NativeAgentPublicationError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "native checked publication requires caller resolution: {self:?}"
        )
    }
}
impl core::error::Error for NativeAgentPublicationError {}

/// Admission result and independent responsibility reconciliation are retained.
///
/// An admission error may follow a successful CAS; inspect/reconcile the original
/// TxId. A reconciliation error retains pending debt or the already settled
/// authenticated terminal if only its journal mirror failed. Neither field
/// authorizes reissuing an undecided transaction.
#[must_use]
#[derive(Debug)]
pub struct NativeAgentSubmission {
    pub admission: Result<AdmissionResult, NodeReceiveTransportRefusal>,
    pub responsibility: Result<RefTransactionResolution, RefTransactionReconciliationRefused>,
}

/// Native publication or original-outcome recovery. Ordinary terminal retry is
/// observation-only; a retained live owner can additionally acknowledge that
/// terminal through `Reconciled`, without refreshing authority or dispatching.
#[must_use]
#[derive(Debug)]
pub enum NativeAgentPublicationResult {
    Recovered(ObservedRefTransaction),
    /// A retained, undispatched owner found and acknowledged its original
    /// terminal decision before considering fresh authorization or dispatch.
    Reconciled(Box<SettledRefTransactionSubmission>),
    Submitted(Box<NativeAgentSubmission>),
}

impl OneNode {
    /// Anchor the host's independently chosen logical time/unit to this node.
    /// A zero tick or unrepresentable conversion refuses.
    pub fn trusted_local_agent_publication_clock(
        &self,
        logical_now: LogicalTime,
        tick: Duration,
    ) -> Result<TrustedLocalAgentPublicationClock<'_>, NativeAgentPublicationRefusal> {
        let nanos_per_tick = u64::try_from(tick.as_nanos())
            .ok()
            .filter(|nanos| *nanos != 0)
            .ok_or(NativeAgentPublicationRefusal::Clock)?;
        Ok(TrustedLocalAgentPublicationClock {
            runtime: self.runtime(),
            owner: Rc::new(()),
            logical_origin: logical_now,
            runtime_origin: self.runtime.now(),
            nanos_per_tick,
        })
    }

    /// Submit one ECC-checked change through the ordinary sealed receive path.
    ///
    /// This explicit trusted-local host boundary requires a separate publication
    /// capability, current canonical revocations, exact complete run/journal
    /// custody, the original clean reconciliation report, independently approved
    /// binding/body bytes and a finite original request deadline. Production
    /// quarantine verifies every export object, the actual parent/base tree and
    /// the candidate's sole parent/export tree before irreversible start.
    ///
    /// Current head must still be the prepared run's exact authority basis.
    /// The consumed validation proof forbids authority-equivalent CAS replans,
    /// so a revocation/policy update cannot race past the start check. Host time
    /// expiry is enforced by the unchanged native request deadline through CAS.
    /// Responsibility commits before dispatch; ambiguous completion is retained
    /// and reconciliation observes only the same ordinary TxId.
    pub async fn publish_agent_ref_transaction_trusted_local_in<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        broker: &mut CurrentAuthorityRevocationCheckedEffectBroker,
        clock: &TrustedLocalAgentPublicationClock<'_>,
        input: TrustedLocalAgentPublicationInput<'_, A>,
    ) -> Result<NativeAgentPublicationResult, NativeAgentPublicationError> {
        match self
            .prepare_agent_ref_transaction_trusted_local_in(request, broker, clock, input)
            .await?
        {
            PreparedNativeAgentPublication::Recovered(observed) => {
                Ok(NativeAgentPublicationResult::Recovered(observed))
            }
            PreparedNativeAgentPublication::Ready(publication) => {
                self.dispatch_agent_ref_transaction_in(request, clock, publication)
                    .await
            }
        }
    }

    // Separate owned preparation from the one admission invocation. A failed
    // final gate returns the real validated/staged custody, never recreating it
    // from caller-supplied retry bytes.
    async fn prepare_agent_ref_transaction_trusted_local_in<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        broker: &mut CurrentAuthorityRevocationCheckedEffectBroker,
        clock: &TrustedLocalAgentPublicationClock<'_>,
        input: TrustedLocalAgentPublicationInput<'_, A>,
    ) -> Result<PreparedNativeAgentPublication, NativeAgentPublicationError> {
        let preflight = NativeAgentPublicationError::Preflight;
        if !std::ptr::eq(clock.runtime, self.runtime()) || !request.is_live() {
            return Err(preflight(NativeAgentPublicationRefusal::CancelledOrExpired));
        }
        let transaction = input.transaction;
        let evidence = transaction.publication_evidence();
        let run = transaction.run();
        if transaction.authority_read_receipt().repository_id() != self.repository_id
            || A::OBJECT_FORMAT != self.object_format
            || run.commitment().ok() != Some(broker.run_commitment())
            || evidence.binding_id() != &input.approval.publication_binding
        {
            return Err(preflight(NativeAgentPublicationRefusal::Binding(
                "approval, repository, format or complete broker run differs",
            )));
        }
        let binding = RefTransactionBinding::derive(
            transaction,
            self.tenant_id,
            input.approval.principal,
            input.approval.key.clone(),
        )
        .map_err(|e| preflight(NativeAgentPublicationRefusal::Effect(Box::new(e))))?;
        let mut custody = b"frankengit.native.agent-publication-custody/v1\0".to_vec();
        custody.extend_from_slice(evidence.subject().export_commitment());
        custody.extend_from_slice(&input.approval.candidate_body_sha256);
        let binding = binding
            .with_custody_commitment(sha256_digest(&custody))
            .map_err(|e| {
                preflight(NativeAgentPublicationRefusal::Effect(Box::new(
                    RefTransactionEffectRefusal::Codec(e),
                )))
            })?;
        // Only an effect already retained by THIS broker may bypass fresh
        // publication gates. Recovery does not dispatch or settle its journal.
        let records = broker.records();
        if let Some(record) = records
            .iter()
            .find(|record| record.effect_id == binding.effect_id())
        {
            if record.input_commitment != *binding.input_commitment() {
                return Err(preflight(NativeAgentPublicationRefusal::Binding(
                    "effect identity collision",
                )));
            }
            return match observe_ref_transaction_async(
                &self.authority,
                request.authority(),
                &self.head_key,
                run,
                &binding,
            )
            .await
            {
                Ok(Some(observed)) => Ok(PreparedNativeAgentPublication::Recovered(observed)),
                Ok(None) => Err(preflight(
                    NativeAgentPublicationRefusal::ExistingSubmissionPending(binding),
                )),
                Err(e) => Err(preflight(NativeAgentPublicationRefusal::Observation(
                    Box::new(e),
                ))),
            };
        }
        if !evidence
            .plan()
            .effect_plan()
            .contains(OperationClass::PublishRefTransaction)
        {
            return Err(preflight(NativeAgentPublicationRefusal::Binding(
                "checked plan does not include canonical publication",
            )));
        }
        let report =
            RunReconciliationReport::build(run, records, evidence.reconciliation().observed_at())
                .map_err(|_| {
                preflight(NativeAgentPublicationRefusal::Binding(
                    "invalid broker reconciliation",
                ))
            })?;
        if &report != evidence.reconciliation() || report.has_unsettled_effects() {
            return Err(preflight(NativeAgentPublicationRefusal::Binding(
                "broker effects changed after checked publication preparation",
            )));
        }
        let semantic = transaction.semantic_request();
        let [command] = semantic.ref_commands() else {
            return Err(preflight(NativeAgentPublicationRefusal::Profile(
                "exactly one branch update required",
            )));
        };
        if !semantic.atomic()
            || command.force
            || !command.name.as_bytes().starts_with(b"refs/heads/")
            || !matches!(
                command.expected_old,
                ExpectedOld::Absent | ExpectedOld::Exactly(_)
            )
            || !matches!(command.proposed_new, ProposedNew::Update(_))
        {
            return Err(preflight(NativeAgentPublicationRefusal::Profile(
                "profile requires an atomic, non-force branch creation or exact update",
            )));
        }
        if input.export.object_count() > MAX_AGENT_PUBLICATION_OBJECTS
            || input.bundle.len() > MAX_AGENT_PUBLICATION_BUNDLE_BYTES
        {
            return Err(preflight(NativeAgentPublicationRefusal::Profile(
                "publication input exceeds bounds",
            )));
        }
        let export_bytes = input
            .export
            .objects()
            .try_fold(0usize, |total, object| {
                total
                    .checked_add(object.body().len())
                    .filter(|bytes| *bytes <= MAX_AGENT_PUBLICATION_EXPORT_BYTES)
            })
            .ok_or_else(|| {
                preflight(NativeAgentPublicationRefusal::Profile(
                    "export byte envelope exceeded",
                ))
            })?;
        evidence
            .subject()
            .verify_export(input.export)
            .map_err(|_| {
                preflight(NativeAgentPublicationRefusal::Binding(
                    "export differs from checked ECC subject",
                ))
            })?;
        // Reserve the admitted input plus the maximum expanded candidate/export
        // envelope actually installed on quarantine, not a caller-supplied cost.
        let bytes = input
            .bundle
            .len()
            .checked_add(export_bytes)
            .and_then(|n| n.checked_add(CANDIDATE_BYTES))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| {
                preflight(NativeAgentPublicationRefusal::Profile(
                    "byte accounting overflow",
                ))
            })?;
        let objects = u64::try_from(input.export.object_count())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| {
                preflight(NativeAgentPublicationRefusal::Profile(
                    "object accounting overflow",
                ))
            })?;
        let cost = ResourceVector::ZERO
            .with(Grade::Bytes, bytes)
            .with(Grade::Objects, objects);
        self.receive_publication_admitted().map_err(|e| {
            preflight(NativeAgentPublicationRefusal::Workspace(Box::new(
                NodeWorkspaceRefusal::WorkspacePublication(Box::new(e.into())),
            )))
        })?;
        self.push_quota
            .evaluate(&input.approval.principal)
            .map_err(|e| {
                preflight(NativeAgentPublicationRefusal::Workspace(Box::new(
                    NodeWorkspaceRefusal::WorkspacePublication(Box::new(e.into())),
                )))
            })?;
        let now = clock.now().map_err(preflight)?;
        let revocations = self
            .agent_publication_revocations_in(request, run, now)
            .await
            .map_err(preflight)?;
        if revocations.current_authority_head_id()
            != transaction.authority_read_receipt().authority_head_id()
        {
            return Err(preflight(NativeAgentPublicationRefusal::Binding(
                "prepared authority basis moved",
            )));
        }
        let reservation = broker
            .reserve_ref_transaction(&binding, input.chain, &revocations, now, cost)
            .map_err(|e| preflight(NativeAgentPublicationRefusal::Effect(Box::new(e))))?;
        if let Err(reason) = clock.require_request_before(
            self,
            request,
            reservation
                .initial_authorization()
                .authorization()
                .valid_until(),
        ) {
            return Err(NativeAgentPublicationError::Reserved {
                reservation: Box::new(reservation),
                reason,
            });
        }
        let staging = ReceiveStaging::default();
        let validated = match self
            .quarantine_agent_ref_transaction_in(
                request,
                transaction,
                input.export,
                input.bundle,
                &input.approval.candidate_body_sha256,
                &staging,
            )
            .await
        {
            Ok(validated) => validated,
            Err(e) => {
                return Err(NativeAgentPublicationError::Reserved {
                    reservation: Box::new(reservation),
                    reason: NativeAgentPublicationRefusal::Workspace(Box::new(e)),
                });
            }
        };
        let now = match clock.now() {
            Ok(now) => now,
            Err(reason) => {
                return Err(NativeAgentPublicationError::Reserved {
                    reservation: Box::new(reservation),
                    reason,
                });
            }
        };
        let revocations = match self
            .agent_publication_revocations_in(request, run, now)
            .await
        {
            Ok(receipt) => receipt,
            Err(reason) => {
                return Err(NativeAgentPublicationError::Reserved {
                    reservation: Box::new(reservation),
                    reason,
                });
            }
        };
        if revocations.current_authority_head_id() != validated.validation_basis() {
            return Err(NativeAgentPublicationError::Reserved {
                reservation: Box::new(reservation),
                reason: NativeAgentPublicationRefusal::Binding(
                    "revocation authority moved after quarantine",
                ),
            });
        }
        let now = match clock.now() {
            Ok(now) => now,
            Err(reason) => {
                return Err(NativeAgentPublicationError::Reserved {
                    reservation: Box::new(reservation),
                    reason,
                });
            }
        };
        // Compute the same fresh proof used by start, allowing deadline refusal
        // while the reservation can still be explicitly aborted by its owner.
        let start_authorization = match CurrentAuthorityCapabilityEffectAuthorization::authorize(
            run,
            input.chain,
            &revocations,
            now,
            &binding.request(cost),
        ) {
            Ok(authorization) => authorization,
            Err(e) => {
                return Err(NativeAgentPublicationError::Reserved {
                    reservation: Box::new(reservation),
                    reason: NativeAgentPublicationRefusal::Effect(Box::new(
                        RefTransactionEffectRefusal::FreshAuthorization(Box::new(e)),
                    )),
                });
            }
        };
        if let Err(reason) = clock.require_request_before(
            self,
            request,
            start_authorization.authorization().valid_until(),
        ) {
            return Err(NativeAgentPublicationError::Reserved {
                reservation: Box::new(reservation),
                reason,
            });
        }
        let pending = broker
            .start_ref_transaction(reservation, input.chain, &revocations, now)
            .map_err(|e| NativeAgentPublicationError::Start(Box::new(e)))?;
        let session = LoopbackReceiveSession::Authenticated(
            AuthenticatedReceiveSession::new(input.approval.principal, input.approval.key.clone())
                .with_authentication(AdmissionAuthentication::OperatorAssertion),
        );
        Ok(PreparedNativeAgentPublication::Ready(
            UndispatchedNativeAgentPublication {
                pending,
                validated,
                staging,
                session,
                clock_owner: Rc::clone(&clock.owner),
            },
        ))
    }

    async fn dispatch_agent_ref_transaction_in(
        &self,
        request: &NodeRequestContext,
        clock: &TrustedLocalAgentPublicationClock<'_>,
        publication: UndispatchedNativeAgentPublication,
    ) -> Result<NativeAgentPublicationResult, NativeAgentPublicationError> {
        if !Rc::ptr_eq(&clock.owner, &publication.clock_owner) {
            return Err(NativeAgentPublicationError::Started {
                publication: Box::new(publication),
                reason: NativeAgentPublicationRefusal::Clock,
            });
        }
        if let Err(reason) = clock.require_request_before(
            self,
            request,
            publication
                .pending
                .start_authorization()
                .authorization()
                .valid_until(),
        ) {
            return Err(NativeAgentPublicationError::Started {
                publication: Box::new(publication),
                reason,
            });
        }
        // Crossing this boundary consumes the only native resume owner. Any
        // error from ordinary admission is ambiguous and remains observation-
        // only, even if a particular error looks like an early refusal.
        let UndispatchedNativeAgentPublication {
            pending,
            validated,
            staging,
            session,
            clock_owner: _,
        } = publication;
        let admission = self
            .admit_basis_bound_loopback_receive_publishing_in(
                request,
                &session,
                &validated,
                AdmissionLimits::default(),
                Some(&staging),
            )
            .await;
        let responsibility = pending
            .reconcile_async(&self.authority, request.authority(), &self.head_key)
            .await;
        Ok(NativeAgentPublicationResult::Submitted(Box::new(
            NativeAgentSubmission {
                admission,
                responsibility,
            },
        )))
    }

    /// Resume one live publication whose successful start was followed by a
    /// failed gate before any ordinary admission invocation.
    ///
    /// The opaque owner retains the original validated proof, synced objects,
    /// principal, key and charged obligation. No replacement bundle, export or
    /// request identity is accepted. A terminal outcome is reconciled first;
    /// otherwise the same broker/chain must freshly authorize the original
    /// effect at its exact prepared head. A new finite request deadline must
    /// fit that authorization. The original live clock cannot be replaced.
    ///
    /// An invoked admission never returns this owner. Its ambiguous outcomes,
    /// cold recovery, and journal-mirror start failures remain observation-only.
    /// Dropping this in-flight future also discards native custody and leaves
    /// journal debt; only a returned `Started` error preserves resumability.
    pub async fn resume_undispatched_agent_ref_transaction_in(
        &self,
        request: &NodeRequestContext,
        broker: &mut CurrentAuthorityRevocationCheckedEffectBroker,
        clock: &TrustedLocalAgentPublicationClock<'_>,
        publication: UndispatchedNativeAgentPublication,
        chain: &VerifiedCapabilityChain,
    ) -> Result<NativeAgentPublicationResult, NativeAgentPublicationError> {
        let retain = |publication, reason| NativeAgentPublicationError::Started {
            publication: Box::new(publication),
            reason,
        };
        if !std::ptr::eq(clock.runtime, self.runtime())
            || !Rc::ptr_eq(&clock.owner, &publication.clock_owner)
        {
            return Err(retain(publication, NativeAgentPublicationRefusal::Clock));
        }
        let UndispatchedNativeAgentPublication {
            pending,
            validated,
            staging,
            session,
            clock_owner,
        } = publication;
        let (pending, observation_failure) = match pending
            .reconcile_async(&self.authority, request.authority(), &self.head_key)
            .await
        {
            Ok(RefTransactionResolution::Decided(settled)) => {
                return Ok(NativeAgentPublicationResult::Reconciled(Box::new(settled)));
            }
            Ok(RefTransactionResolution::Pending(pending)) => (pending, None),
            Err(RefTransactionReconciliationRefused::Pending { pending, reason }) => {
                (*pending, Some(reason))
            }
            Err(error @ RefTransactionReconciliationRefused::JournalAfterSettlement { .. }) => {
                return Err(NativeAgentPublicationError::Reconciliation(Box::new(error)));
            }
        };
        let mut publication = UndispatchedNativeAgentPublication {
            pending,
            validated,
            staging,
            session,
            clock_owner,
        };
        if let Some(reason) = observation_failure {
            return Err(retain(
                publication,
                NativeAgentPublicationRefusal::Observation(Box::new(reason)),
            ));
        }
        let now = match clock.now() {
            Ok(now) => now,
            Err(reason) => return Err(retain(publication, reason)),
        };
        let revocations = match self
            .agent_publication_revocations_in(request, publication.pending.run(), now)
            .await
        {
            Ok(revocations) => revocations,
            Err(reason) => return Err(retain(publication, reason)),
        };
        if revocations.current_authority_head_id() != publication.validated.validation_basis() {
            return Err(retain(
                publication,
                NativeAgentPublicationRefusal::Binding("prepared authority basis moved"),
            ));
        }
        let now = match clock.now() {
            Ok(now) => now,
            Err(reason) => return Err(retain(publication, reason)),
        };
        if let Err(reason) = broker.reauthorize_retained_ref_transaction(
            &mut publication.pending,
            chain,
            &revocations,
            now,
        ) {
            return Err(retain(
                publication,
                NativeAgentPublicationRefusal::Effect(Box::new(reason)),
            ));
        }
        self.dispatch_agent_ref_transaction_in(request, clock, publication)
            .await
    }

    async fn agent_publication_revocations_in(
        &self,
        request: &NodeRequestContext,
        run: &fgit_agent::IntentRun,
        now: LogicalTime,
    ) -> Result<
        fgit_agent::CurrentAuthorityCapabilityRevocationReceipt,
        NativeAgentPublicationRefusal,
    > {
        let max_age = run
            .expiry()
            .value()
            .checked_sub(now.value())
            .filter(|age| *age > 0)
            .ok_or(NativeAgentPublicationRefusal::CancelledOrExpired)?;
        read_current_authority_capability_revocations_async(
            &self.authority,
            request.authority(),
            self.tenant_id,
            &self.head_key,
            run,
            now,
            max_age,
            fgit_agent::MAX_CAPABILITY_REVOCATIONS,
            1_024,
        )
        .await
        .map_err(|e| NativeAgentPublicationRefusal::Revocations(Box::new(e)))
    }

    /// Reconcile a live submission with a fresh finite cleanup context, without
    /// authorizing or performing another admission attempt.
    pub async fn reconcile_agent_ref_transaction_in(
        &self,
        request: &NodeRequestContext,
        pending: PendingRefTransactionSubmission,
    ) -> Result<RefTransactionResolution, RefTransactionReconciliationRefused> {
        if pending.binding().seal().tenant_id != self.tenant_id
            || pending.binding().seal().repository_id != self.repository_id
        {
            return Err(RefTransactionReconciliationRefused::Pending {
                pending: Box::new(pending),
                reason: RefTransactionObservationRefusal::Binding,
            });
        }
        pending
            .reconcile_async(&self.authority, request.authority(), &self.head_key)
            .await
    }

    /// Resolve the original TxId from an externally anchored recovered journal.
    /// The caller cannot substitute a TxId or seal. This remains read-only: a
    /// terminal observation does not append ACK to a recovered journal, and an
    /// undecided answer retains cleanup debt rather than resubmitting after expiry.
    pub async fn observe_recovered_agent_ref_transaction_in(
        &self,
        request: &NodeRequestContext,
        recovered: &RecoveredAgentJournal,
        effect: EffectId,
    ) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal> {
        let binding = recovered
            .journal()
            .ref_transactions()
            .get(&effect)
            .ok_or(RefTransactionObservationRefusal::Binding)?;
        if binding.seal().tenant_id != self.tenant_id
            || binding.seal().repository_id != self.repository_id
            || binding.custody_commitment().is_none()
        {
            return Err(RefTransactionObservationRefusal::Binding);
        }
        observe_ref_transaction_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            recovered.original_run(),
            binding,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
