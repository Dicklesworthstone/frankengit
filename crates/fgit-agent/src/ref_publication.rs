//! Checked responsibility for an ordinary ref transaction.
//!
//! Publication preparation remains inert. The separate `PublishRefTransaction`
//! capability authorizes a submission only after a fresh current-authority check.
//! Committing this obligation records responsibility for submission, not a ref
//! update. Only authenticated ordinary authority outcomes settle it. Recovery
//! observes the original TxId. A host retaining exclusive validated, unsubmitted
//! custody can reauthorize its first dispatch without another reservation;
//! this never permits replay of an admission attempt already invoked.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, CumulativeOutcomes, HeadKey, IdempotencyKey, OutcomeLookup, SealFailure,
    TerminalOutcome, outcome_index_root, read_seal_async, resolve_outcome_async,
    resolve_outcome_with_cumulative_async,
};
use fgit_codec::{CodecRefusal, TransactionSealBody, wire::encode_body};
use fgit_crypto::{GitHashAlgorithm, sha256_digest};
use fgit_resource::{
    LifecycleError, ReserveError, ResourceVector, SettledObligation,
    kinds::{NoCandidateReason, RefTransactionSubmission},
};
use fgit_types::{Digest, PrincipalId, TenantId, TxId};

use crate::{
    AgentRefTransaction, CurrentAuthorityCapabilityEffectAuthorization,
    CurrentAuthorityCapabilityRevocationReadRefusal, CurrentAuthorityCapabilityRevocationReceipt,
    CurrentAuthorityRevocationCheckedEffectBroker, CurrentAuthorityRevocationCheckedEffectRefusal,
    EffectId, EffectJournalRefusal, EffectRequest, IntentRun, IntentRunCommitment, LogicalTime,
    OperationClass, VerifiedCapabilityChain,
    broker::ref_publication::{PendingSubmission, ReservedSubmission, StartFailure},
};

mod recovery;
pub use recovery::{
    PreparedRefTransactionAcknowledgement, RecoveredRefTransactionAcknowledgement,
    RefTransactionAcknowledgementSink, RefTransactionRecoveryPersistenceRefused,
    RefTransactionRecoveryRefusal, prepare_recovered_ref_transaction_acknowledgement,
};

/// Exact ordinary seal and checked publication identity retained in the journal.
///
/// This value grants no authority. Its constructor derives the seal from the
/// actual prepared request; no caller supplies a second TxId or request digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefTransactionBinding {
    run_commitment: IntentRunCommitment,
    seal: TransactionSealBody,
    publication_binding: [u8; 32],
    custody_commitment: Option<[u8; 32]>,
    input_commitment: [u8; 32],
}

impl RefTransactionBinding {
    /// Bind the exact prepared request to the host-authenticated principal and
    /// original ordinary idempotency key. The host must independently authorize
    /// the checked publication binding; possession of the prepared type is not
    /// sponsor approval or authentication.
    pub fn derive<A: GitHashAlgorithm>(
        transaction: &AgentRefTransaction<A>,
        tenant: TenantId,
        principal: PrincipalId,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self, RefTransactionEffectRefusal> {
        let run_commitment = transaction
            .run()
            .commitment()
            .map_err(|_| RefTransactionEffectRefusal::Binding)?;
        let (_, seal) = transaction
            .seal_attempt(tenant, principal, idempotency_key)
            .derive()
            .map_err(|error| RefTransactionEffectRefusal::Seal(Box::new(error)))?;
        Self::from_parts(
            run_commitment,
            seal,
            *transaction.publication_evidence().binding_id(),
        )
        .map_err(RefTransactionEffectRefusal::Codec)
    }

    pub(crate) fn from_parts(
        run_commitment: IntentRunCommitment,
        seal: TransactionSealBody,
        publication_binding: [u8; 32],
    ) -> Result<Self, CodecRefusal> {
        let mut bytes = b"frankengit.agent.ref-submission/v1\0".to_vec();
        bytes.extend_from_slice(run_commitment.as_bytes());
        bytes.extend_from_slice(&encode_body(&seal)?);
        bytes.extend_from_slice(&publication_binding);
        bytes.push(0);
        let input_commitment = sha256_digest(&bytes);
        Ok(Self {
            run_commitment,
            seal,
            publication_binding,
            custody_commitment: None,
            input_commitment,
        })
    }

    /// Attach the native adapter's commitment to the exact reviewed commit
    /// bytes and export custody. This narrows an input; it grants no authority.
    pub fn with_custody_commitment(mut self, commitment: [u8; 32]) -> Result<Self, CodecRefusal> {
        let mut bytes = b"frankengit.agent.ref-submission/v1\0".to_vec();
        bytes.extend_from_slice(self.run_commitment.as_bytes());
        bytes.extend_from_slice(&encode_body(&self.seal)?);
        bytes.extend_from_slice(&self.publication_binding);
        bytes.push(1);
        bytes.extend_from_slice(&commitment);
        self.custody_commitment = Some(commitment);
        self.input_commitment = sha256_digest(&bytes);
        Ok(self)
    }

    #[must_use]
    pub const fn custody_commitment(&self) -> Option<[u8; 32]> {
        self.custody_commitment
    }

    /// Ordinary transaction identity, unchanged by agent provenance.
    #[must_use]
    pub const fn tx_id(&self) -> TxId {
        self.seal.tx_id
    }

    /// Complete ordinary seal, including namespace, principal and key digest.
    #[must_use]
    pub const fn seal(&self) -> &TransactionSealBody {
        &self.seal
    }

    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    #[must_use]
    pub const fn publication_binding(&self) -> &[u8; 32] {
        &self.publication_binding
    }

    #[must_use]
    pub const fn input_commitment(&self) -> &[u8; 32] {
        &self.input_commitment
    }

    /// Stable broker identity. A collision fails closed at the broker's
    /// duplicate-effect boundary; the full input commitment is retained too.
    #[must_use]
    pub fn effect_id(&self) -> EffectId {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&self.input_commitment[..16]);
        EffectId::new(u128::from_be_bytes(bytes))
    }

    #[must_use]
    pub fn request(&self, cost: ResourceVector) -> EffectRequest {
        EffectRequest {
            effect_id: self.effect_id(),
            parent_effect_id: None,
            operation: OperationClass::PublishRefTransaction,
            cost,
            input_commitment: self.input_commitment,
        }
    }
}

/// A pre-start refusal or a journal failure with explicit retained ownership.
#[derive(Debug)]
pub enum RefTransactionEffectRefusal {
    Binding,
    DurableJournalRequired,
    AuthorizationLimit,
    Authorization(Box<CurrentAuthorityRevocationCheckedEffectRefusal>),
    FreshAuthorization(Box<crate::CapabilityEffectAuthorizationRefusal>),
    Seal(Box<SealFailure>),
    Codec(CodecRefusal),
    Journal(EffectJournalRefusal),
    Resource(Box<ReserveError>),
    Settlement(LifecycleError),
}

impl fmt::Display for RefTransactionEffectRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ref transaction submission refused: {self:?}")
    }
}
impl core::error::Error for RefTransactionEffectRefusal {}

/// An authorized reservation that has not started ordinary admission.
#[must_use = "abort or start this exact reserved ref transaction"]
#[derive(Debug)]
pub struct ReservedRefTransactionSubmission {
    pub(crate) initial: CurrentAuthorityCapabilityEffectAuthorization,
    pub(crate) request: EffectRequest,
    pub(crate) raw: ReservedSubmission,
}

impl ReservedRefTransactionSubmission {
    #[must_use]
    pub const fn binding(&self) -> &RefTransactionBinding {
        self.raw.binding()
    }

    #[must_use]
    pub const fn initial_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.initial
    }

    /// Cleanup remains allowed after expiry or revocation. This method is
    /// unavailable on a submission that has already started.
    pub fn abort(
        self,
        reason: NoCandidateReason,
    ) -> Result<SettledObligation<RefTransactionSubmission>, EffectJournalRefusal> {
        self.raw.abort(reason)
    }
}

/// Start refusal preserving the still-reserved or already-committed obligation.
#[must_use]
#[derive(Debug)]
pub enum RefTransactionStartRefused {
    BeforeStart {
        reservation: Box<ReservedRefTransactionSubmission>,
        reason: RefTransactionEffectRefusal,
    },
    /// Submission responsibility committed but its journal mirror failed.
    /// The host MUST NOT dispatch on this error; retain and reconcile the debt.
    AfterStart {
        pending: Box<PendingRefTransactionSubmission>,
        reason: EffectJournalRefusal,
    },
}

impl fmt::Display for RefTransactionStartRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeStart { reason, .. } => write!(formatter, "{reason}"),
            Self::AfterStart { reason, .. } => {
                write!(
                    formatter,
                    "submission responsibility needs recovery: {reason}"
                )
            }
        }
    }
}
impl core::error::Error for RefTransactionStartRefused {}

/// Responsibility for an exact submission whose terminal outcome is not settled.
///
/// This is never a successful ref update or permission to retry admission.
/// Its own consequential operation only observes the original ordinary TxId.
/// A live broker can reauthorize the first dispatch for a host that still owns
/// exclusive unsubmitted validation custody; this value alone proves no such
/// custody and cannot authorize transport replay or reopening a journal.
#[must_use = "retain and reconcile the pending canonical submission"]
#[derive(Debug)]
pub struct PendingRefTransactionSubmission {
    pub(crate) run: IntentRun,
    pub(crate) initial: CurrentAuthorityCapabilityEffectAuthorization,
    pub(crate) started: CurrentAuthorityCapabilityEffectAuthorization,
    pub(crate) raw: PendingSubmission,
}

impl PendingRefTransactionSubmission {
    /// Original complete run; observation and retained-custody checks use it
    /// unchanged, including after the run's authority expires.
    #[must_use]
    pub const fn run(&self) -> &IntentRun {
        &self.run
    }

    #[must_use]
    pub const fn binding(&self) -> &RefTransactionBinding {
        self.raw.binding()
    }

    #[must_use]
    pub const fn start_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.started
    }

    /// Observe only. Unknown outcome, cancellation, storage faults, expiry or
    /// later revocation never cause this method to resubmit the request.
    pub async fn reconcile_async<S: AsyncAuthorityStore + ?Sized>(
        self,
        store: &S,
        cx: &S::Context,
        head_key: &HeadKey,
    ) -> Result<RefTransactionResolution, RefTransactionReconciliationRefused> {
        let observation =
            observe_ref_transaction_async(store, cx, head_key, &self.run, self.binding()).await;
        let observation = match observation {
            Ok(Some(observation)) => observation,
            Ok(None) => return Ok(RefTransactionResolution::Pending(self)),
            Err(reason) => {
                return Err(RefTransactionReconciliationRefused::Pending {
                    pending: Box::new(self),
                    reason,
                });
            }
        };
        self.reconcile_observed(observation)
    }

    /// Acknowledge an already authenticated terminal for this exact submission.
    ///
    /// This accepts only the private observation type produced by the authority
    /// readers, including the retained-checkpoint reader. The complete binding
    /// and original run must match before any journal or obligation changes.
    /// A mismatch returns this same pending responsibility; observing another
    /// transaction or another custody binding never authorizes its settlement.
    /// No new capability or admission attempt is created, including after expiry.
    pub fn reconcile_observed(
        self,
        observation: ObservedRefTransaction,
    ) -> Result<RefTransactionResolution, RefTransactionReconciliationRefused> {
        if observation.binding() != self.binding()
            || self.run.commitment().ok() != Some(observation.binding().run_commitment())
        {
            return Err(RefTransactionReconciliationRefused::Pending {
                pending: Box::new(self),
                reason: RefTransactionObservationRefusal::Binding,
            });
        }
        let Self {
            run,
            initial,
            started,
            raw,
        } = self;
        match raw.acknowledge(&observation) {
            Ok(settled) => Ok(RefTransactionResolution::Decided(
                SettledRefTransactionSubmission {
                    initial,
                    started,
                    observation,
                    settled,
                },
            )),
            Err(crate::broker::ref_publication::AcknowledgementFailure::Before {
                pending,
                reason,
            }) => Err(RefTransactionReconciliationRefused::Pending {
                pending: Box::new(Self {
                    run,
                    initial,
                    started,
                    raw: pending,
                }),
                reason: RefTransactionObservationRefusal::Journal(reason),
            }),
            Err(crate::broker::ref_publication::AcknowledgementFailure::After {
                settled,
                reason,
            }) => Err(
                RefTransactionReconciliationRefused::JournalAfterSettlement {
                    settled: Box::new(SettledRefTransactionSubmission {
                        initial,
                        started,
                        observation,
                        settled,
                    }),
                    reason,
                },
            ),
        }
    }
}

/// Authenticated authority observation, never constructible from a caller's
/// asserted `TerminalOutcome`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedRefTransaction {
    binding: RefTransactionBinding,
    terminal: TerminalOutcome,
    commitment: Digest,
}

impl ObservedRefTransaction {
    #[must_use]
    pub const fn binding(&self) -> &RefTransactionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn terminal(&self) -> &TerminalOutcome {
        &self.terminal
    }

    #[must_use]
    pub const fn commitment(&self) -> Digest {
        self.commitment
    }
}

/// Observation failure keeps the original submission undecided locally.
#[derive(Debug)]
pub enum RefTransactionObservationRefusal {
    Binding,
    /// The current head is absent or no longer selects the retained outcome
    /// witness. Recollect within the original request; this proves no absence.
    StaleOutcomeBasis,
    Historical(Box<CurrentAuthorityCapabilityRevocationReadRefusal>),
    Seal(Box<SealFailure>),
    Outcome(Box<fgit_authority::OutcomeFailure>),
    Journal(EffectJournalRefusal),
}

impl fmt::Display for RefTransactionObservationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "canonical submission observation refused: {self:?}"
        )
    }
}
impl core::error::Error for RefTransactionObservationRefusal {}

/// Resolve an original journal-bound TxId after reauthenticating its complete
/// historical run against the actual store and slot. This read is allowed after
/// run expiry; neither a terminal nor an undecided answer grants new authority.
pub async fn observe_ref_transaction_async<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    run: &IntentRun,
    binding: &RefTransactionBinding,
) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal> {
    let seal_present =
        authenticate_observation_binding_async(store, cx, head_key, run, binding).await?;
    let outcome = resolve_outcome_async(
        store,
        cx,
        head_key,
        binding.seal.tenant_id,
        binding.seal.repository_id,
        binding.tx_id(),
    )
    .await
    .map_err(|error| RefTransactionObservationRefusal::Outcome(Box::new(error)))?;
    observation_from_outcome(binding, seal_present, outcome)
}

/// Observe the original terminal through a complete retained outcome witness.
///
/// Historical run and complete-seal authentication are identical to
/// [`observe_ref_transaction_async`]. Authority rechecks the witness against a
/// fresh authenticated head's exact token, repository and outcome root before
/// reconciling the accelerator hint; no decision-history replay is needed here.
///
/// `Ok(None)` means the original transaction is undecided at that exact head.
/// An absent or moved head instead returns
/// [`RefTransactionObservationRefusal::StaleOutcomeBasis`], so a caller can
/// recollect within its original bounded request without inventing absence.
/// The witness grants neither publication nor renewed execution authority.
pub async fn observe_ref_transaction_with_cumulative_async<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    run: &IntentRun,
    binding: &RefTransactionBinding,
    cumulative: &CumulativeOutcomes,
) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal> {
    let seal_present =
        authenticate_observation_binding_async(store, cx, head_key, run, binding).await?;
    let outcome = resolve_outcome_with_cumulative_async(
        store,
        cx,
        head_key,
        cumulative.observed(),
        binding.seal.tenant_id,
        binding.seal.repository_id,
        binding.tx_id(),
        cumulative,
    )
    .await
    .map_err(|error| RefTransactionObservationRefusal::Outcome(Box::new(error)))?
    .ok_or(RefTransactionObservationRefusal::StaleOutcomeBasis)?;
    observation_from_outcome(binding, seal_present, outcome)
}

/// Authenticate the complete original run and validate any existing seal.
/// An absent seal remains legal only if authority also finds no terminal.
async fn authenticate_observation_binding_async<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    run: &IntentRun,
    binding: &RefTransactionBinding,
) -> Result<bool, RefTransactionObservationRefusal> {
    if run.commitment().ok() != Some(binding.run_commitment()) {
        return Err(RefTransactionObservationRefusal::Binding);
    }
    let authority = run
        .authority_read_receipt()
        .filter(|authority| authority.repository_id() == binding.seal.repository_id)
        .ok_or(RefTransactionObservationRefusal::Binding)?;
    let historical =
        crate::descendant_revocation::authenticate_historical_async(store, cx, head_key, authority)
            .await
            .map_err(|error| RefTransactionObservationRefusal::Historical(Box::new(error)))?;
    crate::descendant_revocation::validate_historical_receipt(authority, &historical)
        .map_err(|error| RefTransactionObservationRefusal::Historical(Box::new(error)))?;
    let stored = read_seal_async(
        store,
        cx,
        binding.seal.tenant_id,
        binding.seal.repository_id,
        binding.tx_id(),
    )
    .await
    .map_err(|error| RefTransactionObservationRefusal::Seal(Box::new(error)))?;
    if stored.as_ref().is_some_and(|seal| seal != binding.seal()) {
        return Err(RefTransactionObservationRefusal::Binding);
    }
    Ok(stored.is_some())
}

fn observation_from_outcome(
    binding: &RefTransactionBinding,
    seal_present: bool,
    outcome: OutcomeLookup,
) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal> {
    let OutcomeLookup::Decided(terminal) = outcome else {
        return Ok(None);
    };
    if !seal_present {
        return Err(RefTransactionObservationRefusal::Binding);
    }
    let commitment = outcome_index_root(&[(binding.tx_id(), terminal)])
        .map_err(|error| RefTransactionObservationRefusal::Outcome(Box::new(error)))?;
    Ok(Some(ObservedRefTransaction {
        binding: binding.clone(),
        terminal,
        commitment,
    }))
}

/// Acknowledgement means a terminal decision was observed. Inspect `terminal`
/// to distinguish a committed ref update from an ordinary canonical refusal.
#[derive(Debug)]
pub struct SettledRefTransactionSubmission {
    initial: CurrentAuthorityCapabilityEffectAuthorization,
    started: CurrentAuthorityCapabilityEffectAuthorization,
    observation: ObservedRefTransaction,
    settled: SettledObligation<RefTransactionSubmission>,
}

impl SettledRefTransactionSubmission {
    #[must_use]
    pub const fn observation(&self) -> &ObservedRefTransaction {
        &self.observation
    }

    #[must_use]
    pub const fn initial_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.initial
    }

    #[must_use]
    pub const fn start_authorization(&self) -> CurrentAuthorityCapabilityEffectAuthorization {
        self.started
    }

    #[must_use]
    pub const fn settled(&self) -> &SettledObligation<RefTransactionSubmission> {
        &self.settled
    }
}

#[must_use]
#[derive(Debug)]
pub enum RefTransactionResolution {
    Decided(SettledRefTransactionSubmission),
    Pending(PendingRefTransactionSubmission),
}

#[must_use]
#[derive(Debug)]
pub enum RefTransactionReconciliationRefused {
    Pending {
        pending: Box<PendingRefTransactionSubmission>,
        reason: RefTransactionObservationRefusal,
    },
    /// The resource responsibility settled, but its durable mirror requires
    /// recovery. The authenticated terminal and settlement evidence are retained.
    JournalAfterSettlement {
        settled: Box<SettledRefTransactionSubmission>,
        reason: EffectJournalRefusal,
    },
}

impl CurrentAuthorityRevocationCheckedEffectBroker {
    /// Fresh authority for the first dispatch of exclusively retained custody.
    ///
    /// This is only the authorization half of live pre-dispatch resumption.
    /// The native host must retain the original verified objects and validation
    /// proof in an unforgeable, non-cloneable carrier that never survives an
    /// ordinary admission invocation. No bundle may be read or staged again
    /// under the already-consumed cost. An undecided authority observation alone
    /// is never proof that dispatch did not happen.
    ///
    /// The original live broker, exact prepared head, chain, leaf, input and
    /// charged cost are retained. No new grant, resource transition, journal
    /// event or refreshed run is created. Both bounded authorization histories
    /// advance only after every check succeeds. A refusal leaves `pending`
    /// intact, including its previous authorization. Poisoned journal writers,
    /// cold journal recovery and already-invoked admissions remain observation
    /// only; this method cannot repair or replay them.
    pub fn reauthorize_retained_ref_transaction(
        &mut self,
        pending: &mut PendingRefTransactionSubmission,
        chain: &VerifiedCapabilityChain,
        revocations: &CurrentAuthorityCapabilityRevocationReceipt,
        now: LogicalTime,
    ) -> Result<CurrentAuthorityCapabilityEffectAuthorization, RefTransactionEffectRefusal> {
        if pending.binding().run_commitment() != self.run_commitment()
            || pending.run.commitment().ok() != Some(self.run_commitment())
        {
            return Err(RefTransactionEffectRefusal::Binding);
        }
        let request = self.inner.retained_ref_transaction_request(&pending.raw)?;
        if self.dispatch_authorizations.len()
            >= crate::effect_authorization::MAX_EFFECT_AUTHORIZATIONS
            || self.inner.dispatch_authorizations().len()
                >= crate::effect_authorization::MAX_EFFECT_AUTHORIZATIONS
        {
            return Err(RefTransactionEffectRefusal::AuthorizationLimit);
        }
        let prepared_head = pending
            .run
            .authority_read_receipt()
            .ok_or(RefTransactionEffectRefusal::Binding)?
            .authority_head_id();
        if revocations.current_authority_head_id() != prepared_head
            || now < pending.started.authorization().authorized_at()
        {
            return Err(RefTransactionEffectRefusal::Binding);
        }
        let authorization = CurrentAuthorityCapabilityEffectAuthorization::authorize(
            &self.run,
            chain,
            revocations,
            now,
            &request,
        )
        .map_err(|error| RefTransactionEffectRefusal::FreshAuthorization(Box::new(error)))?;
        if pending.initial.authorization().verified_chain_id()
            != authorization.authorization().verified_chain_id()
            || pending.initial.authorization().capability_id()
                != authorization.authorization().capability_id()
        {
            return Err(RefTransactionEffectRefusal::Binding);
        }
        self.inner
            .record_ref_transaction_start(authorization.authorization());
        self.dispatch_authorizations.push(authorization);
        pending.started = authorization;
        Ok(authorization)
    }

    /// Reserve the new canonical-publication capability against this broker's
    /// complete run and durable journal. A preparation-only or external-integration
    /// capability cannot authorize it.
    pub fn reserve_ref_transaction(
        &mut self,
        binding: &RefTransactionBinding,
        chain: &VerifiedCapabilityChain,
        revocations: &CurrentAuthorityCapabilityRevocationReceipt,
        now: LogicalTime,
        cost: ResourceVector,
    ) -> Result<ReservedRefTransactionSubmission, RefTransactionEffectRefusal> {
        if binding.run_commitment() != self.run_commitment() {
            return Err(RefTransactionEffectRefusal::Binding);
        }
        if self
            .durable_position()
            .map_err(RefTransactionEffectRefusal::Journal)?
            .is_none()
        {
            return Err(RefTransactionEffectRefusal::DurableJournalRequired);
        }
        let request = binding.request(cost);
        let grant = self
            .request_high_value(chain, revocations, now, &request)
            .map_err(|error| RefTransactionEffectRefusal::Authorization(Box::new(error)))?;
        let initial = grant.authorization();
        let raw = self
            .inner
            .reserve_ref_transaction(grant.into_grant(), binding.clone())?;
        Ok(ReservedRefTransactionSubmission {
            initial,
            request,
            raw,
        })
    }

    /// Fresh authorization at irreversible start, preserving actual journal and
    /// resource custody. Refusals before start return the live reservation.
    pub fn start_ref_transaction(
        &mut self,
        reservation: ReservedRefTransactionSubmission,
        chain: &VerifiedCapabilityChain,
        revocations: &CurrentAuthorityCapabilityRevocationReceipt,
        now: LogicalTime,
    ) -> Result<PendingRefTransactionSubmission, RefTransactionStartRefused> {
        let refuse = |reservation, reason| RefTransactionStartRefused::BeforeStart {
            reservation: Box::new(reservation),
            reason,
        };
        if reservation.binding().run_commitment() != self.run_commitment()
            || !self.inner.owns_ref_transaction(&reservation.raw)
        {
            return Err(refuse(reservation, RefTransactionEffectRefusal::Binding));
        }
        if self.dispatch_authorizations.len()
            >= crate::effect_authorization::MAX_EFFECT_AUTHORIZATIONS
        {
            return Err(refuse(
                reservation,
                RefTransactionEffectRefusal::AuthorizationLimit,
            ));
        }
        let started = match CurrentAuthorityCapabilityEffectAuthorization::authorize(
            &self.run,
            chain,
            revocations,
            now,
            &reservation.request,
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                return Err(refuse(
                    reservation,
                    RefTransactionEffectRefusal::FreshAuthorization(Box::new(error)),
                ));
            }
        };
        if reservation.initial.authorization().verified_chain_id()
            != started.authorization().verified_chain_id()
            || reservation.initial.authorization().capability_id()
                != started.authorization().capability_id()
        {
            return Err(refuse(reservation, RefTransactionEffectRefusal::Binding));
        }
        let ReservedRefTransactionSubmission {
            initial,
            request,
            raw,
        } = reservation;
        match raw.start(&request.cost) {
            Ok(raw) => {
                self.inner
                    .record_ref_transaction_start(started.authorization());
                self.dispatch_authorizations.push(started);
                Ok(PendingRefTransactionSubmission {
                    run: self.run.clone(),
                    initial,
                    started,
                    raw,
                })
            }
            Err(StartFailure::Before {
                reservation: raw,
                reason,
            }) => Err(refuse(
                ReservedRefTransactionSubmission {
                    initial,
                    request,
                    raw,
                },
                reason,
            )),
            Err(StartFailure::After {
                pending: raw,
                reason,
            }) => {
                self.inner
                    .record_ref_transaction_start(started.authorization());
                self.dispatch_authorizations.push(started);
                Err(RefTransactionStartRefused::AfterStart {
                    pending: Box::new(PendingRefTransactionSubmission {
                        run: self.run.clone(),
                        initial,
                        started,
                        raw,
                    }),
                    reason,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests;
