//! A bounded, deterministic Wing--Gong style linearizability checker.
//!
//! This checker is deliberately an offline verifier, not an authority-store
//! implementation or benchmark. Its default bound is 16 recorded operations
//! (including invocations without a response) and 250,000 explored search
//! nodes. Callers may choose another bound up to 63 recorded operations, but
//! an over-bound or budget-exhausted history is reported as indeterminate
//! instead of being accepted or silently truncated.

use std::collections::BTreeMap;
use std::fmt;

use crate::history::{History, OperationId, RecordedOperation, normalize_authority_tokens};
use crate::keys::{HeadKey, ImmutableKey};
use crate::tokens::{AuthorityVersionToken, StoreInstanceId};
use crate::vocabulary::{
    AuthenticatedHead, AuthorityOp, AuthorityRefusal, AuthorityResponse, CasOutcome, HeadInit,
    HeadRead, HeadReadReceipt, ImmutableRead, PutOutcome,
};
use fgit_types::HeadGeneration;

/// Stable schema label for newline-delimited checker reports.
pub const NDJSON_SCHEMA: &str = "fgit.authority.lincheck.v1";

/// The maximum number of recorded operations representable by the search mask.
pub const HARD_MAX_COMPLETED_OPERATIONS: usize = 63;

/// History binding for the authority operation vocabulary.
///
/// This alias makes conformance and fault campaigns record the exact
/// `AuthorityOp` and `AuthorityResponse` values exposed by the store, while
/// the checker itself remains reusable for a pure sequential model.
pub type AuthorityHistory = History<AuthorityOp, AuthorityResponse>;

/// A pure sequential model of the authority operation vocabulary.
///
/// `fgit-authority` binds this trait to its published `AuthorityOp` and
/// `AuthorityResponse` types. Keeping the checker generic prevents a second,
/// checker-specific authority vocabulary from becoming a competing contract.
pub trait SequentialSpec {
    /// Model state reached by sequentially applying operations.
    type State: Clone + Eq;
    /// Operation supplied at invocation.
    type Operation;
    /// Response expected from the sequential model.
    type Response: Eq;

    /// Returns the initial state for one independent history check.
    fn initial_state(&self) -> Self::State;

    /// Applies one operation atomically in the sequential specification.
    fn apply(
        &self,
        state: &Self::State,
        operation: &Self::Operation,
    ) -> (Self::State, Self::Response);
}

/// A sequential specification over the real `AuthorityStore` vocabulary.
///
/// This is intentionally only a binding: the authority trait/backend remains
/// the owner of operation semantics, and this module never duplicates it in a
/// second production state machine.
pub trait AuthoritySequentialSpec:
    SequentialSpec<Operation = AuthorityOp, Response = AuthorityResponse>
{
}

impl<Specification> AuthoritySequentialSpec for Specification where
    Specification: SequentialSpec<Operation = AuthorityOp, Response = AuthorityResponse>
{
}

/// Reference sequential specification for the full authority vocabulary.
///
/// This is a checker-only model, not a durable authority backend. It gives
/// every fault or schedule campaign one definition of immutable writes, head
/// issuance, authenticated receipts, and the ordered conditional-head guards.
/// In particular, its tokens use the representatives installed by
/// [`normalize_authority_tokens`], so callers compare authority semantics
/// rather than a backend's opaque token layout.
#[derive(Clone, Debug)]
pub struct AuthorityReferenceSpec {
    instance: StoreInstanceId,
    initial_head: Option<InitialHead>,
}

impl AuthorityReferenceSpec {
    /// Starts from an authority store with no immutable bodies or head slots.
    #[must_use]
    pub const fn new(instance: StoreInstanceId) -> Self {
        Self {
            instance,
            initial_head: None,
        }
    }

    /// Starts from one head that existed before the recorded history.
    ///
    /// This constructor is for a schedule that records only operations after
    /// setup. The seed receives the first normalized authority token, exactly
    /// as an `InitializeHead` operation would; later reads reuse that token
    /// and only a committed replacement mints a successor.
    #[must_use]
    pub const fn with_initial_head(
        instance: StoreInstanceId,
        key: HeadKey,
        generation: HeadGeneration,
        body: Vec<u8>,
    ) -> Self {
        Self {
            instance,
            initial_head: Some(InitialHead {
                key,
                generation,
                body,
            }),
        }
    }
}

#[derive(Clone, Debug)]
struct InitialHead {
    key: HeadKey,
    generation: HeadGeneration,
    body: Vec<u8>,
}

/// State held by [`AuthorityReferenceSpec`] while the checker explores one
/// candidate linearization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityReferenceState {
    immutable: BTreeMap<ImmutableKey, Vec<u8>>,
    heads: BTreeMap<HeadKey, HeadReadReceipt>,
    issued: BTreeMap<AuthorityVersionToken, IssuedVersion>,
    next_issuance: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IssuedVersion {
    key: HeadKey,
    generation: HeadGeneration,
    body: Vec<u8>,
}

impl AuthorityReferenceState {
    fn mint_receipt(
        &mut self,
        key: HeadKey,
        generation: HeadGeneration,
        body: Vec<u8>,
    ) -> HeadReadReceipt {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(b"fgithist");
        bytes[8..].copy_from_slice(&self.next_issuance.to_be_bytes());
        self.next_issuance = self.next_issuance.saturating_add(1);
        let token = AuthorityVersionToken::from_opaque_bytes(bytes);
        self.issued.insert(
            token,
            IssuedVersion {
                key: key.clone(),
                generation,
                body: body.clone(),
            },
        );
        HeadReadReceipt::new(key, token, generation, body)
    }
}

impl SequentialSpec for AuthorityReferenceSpec {
    type State = AuthorityReferenceState;
    type Operation = AuthorityOp;
    type Response = AuthorityResponse;

    fn initial_state(&self) -> Self::State {
        let mut state = AuthorityReferenceState {
            immutable: BTreeMap::new(),
            heads: BTreeMap::new(),
            issued: BTreeMap::new(),
            next_issuance: 0,
        };
        if let Some(head) = &self.initial_head {
            let receipt = state.mint_receipt(head.key.clone(), head.generation, head.body.clone());
            state.heads.insert(head.key.clone(), receipt);
        }
        state
    }

    fn apply(
        &self,
        state: &Self::State,
        operation: &Self::Operation,
    ) -> (Self::State, Self::Response) {
        let mut next = state.clone();
        let response = match operation {
            AuthorityOp::PutIfAbsent { key, body } => match next.immutable.get(key) {
                Some(existing) if existing == body => {
                    AuthorityResponse::PutIfAbsent(PutOutcome::IdenticalRetry)
                }
                Some(_) => AuthorityResponse::PutIfAbsent(PutOutcome::Conflict),
                None => {
                    next.immutable.insert(key.clone(), body.clone());
                    AuthorityResponse::PutIfAbsent(PutOutcome::Created)
                }
            },
            AuthorityOp::ReadImmutable { key } => next.immutable.get(key).map_or_else(
                || AuthorityResponse::ReadImmutable(ImmutableRead::Absent),
                |body| AuthorityResponse::ReadImmutable(ImmutableRead::Present(body.clone())),
            ),
            AuthorityOp::InitializeHead {
                key,
                generation,
                body,
            } => match next.heads.get(key) {
                Some(existing)
                    if existing.generation() == *generation && existing.body() == body =>
                {
                    AuthorityResponse::InitializeHead(HeadInit::IdenticalRetry(existing.clone()))
                }
                Some(_) => AuthorityResponse::InitializeHead(HeadInit::Conflict),
                None => {
                    let receipt = next.mint_receipt(key.clone(), *generation, body.clone());
                    next.heads.insert(key.clone(), receipt.clone());
                    AuthorityResponse::InitializeHead(HeadInit::Created(receipt))
                }
            },
            AuthorityOp::ReadHead { key } => next.heads.get(key).map_or_else(
                || AuthorityResponse::ReadHead(HeadRead::Absent),
                |receipt| AuthorityResponse::ReadHead(HeadRead::Present(receipt.clone())),
            ),
            AuthorityOp::CompareExchangeHead {
                key,
                expected,
                new_generation,
                new_body,
            } => match next.issued.get(expected) {
                None => AuthorityResponse::Refused(AuthorityRefusal::UnknownVersionToken),
                Some(issued) if issued.key != *key => {
                    AuthorityResponse::Refused(AuthorityRefusal::TokenKeyMismatch)
                }
                Some(_) => match next.heads.get(key).cloned() {
                    None => AuthorityResponse::Refused(AuthorityRefusal::HeadAbsent),
                    Some(current) if current.token() != *expected => {
                        AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch)
                    }
                    Some(current) if *new_generation <= current.generation() => {
                        AuthorityResponse::Refused(AuthorityRefusal::NonMonotoneGeneration {
                            current: current.generation(),
                            proposed: *new_generation,
                        })
                    }
                    Some(_) => {
                        let receipt =
                            next.mint_receipt(key.clone(), *new_generation, new_body.clone());
                        next.heads.insert(key.clone(), receipt.clone());
                        AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(receipt))
                    }
                },
            },
            AuthorityOp::AuthenticateHeadReceipt { receipt } => {
                match next.issued.get(&receipt.token()) {
                    None => AuthorityResponse::Refused(AuthorityRefusal::UnknownVersionToken),
                    Some(issued) if issued.key != *receipt.key() => {
                        AuthorityResponse::Refused(AuthorityRefusal::TokenKeyMismatch)
                    }
                    Some(issued) if issued.generation != receipt.generation() => {
                        AuthorityResponse::Refused(AuthorityRefusal::TokenGenerationMismatch)
                    }
                    Some(issued) if issued.body.as_slice() != receipt.body() => {
                        AuthorityResponse::Refused(AuthorityRefusal::TokenBodyMismatch)
                    }
                    Some(_) => AuthorityResponse::AuthenticateHeadReceipt(AuthenticatedHead::new(
                        receipt.clone(),
                        self.instance,
                    )),
                }
            }
        };
        (next, response)
    }
}

/// Explicit resource bounds for one checker invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckLimits {
    /// Maximum recorded operations permitted in the supplied history.
    ///
    /// The historical field name is retained for source compatibility. An
    /// incomplete invocation can still take effect, so it consumes the same
    /// bounded-search capacity as an operation with a recorded response.
    pub max_completed_operations: usize,
    /// Maximum depth-first search nodes explored before returning indeterminate.
    pub max_search_nodes: usize,
}

impl Default for CheckLimits {
    fn default() -> Self {
        Self {
            max_completed_operations: 16,
            max_search_nodes: 250_000,
        }
    }
}

impl CheckLimits {
    /// Validates limits before any checker work starts.
    pub const fn validate(self) -> Result<(), CheckLimitsError> {
        if self.max_completed_operations == 0 {
            return Err(CheckLimitsError::ZeroCompletedOperationBound);
        }
        if self.max_completed_operations > HARD_MAX_COMPLETED_OPERATIONS {
            return Err(CheckLimitsError::CompletedOperationBoundExceedsHardLimit {
                requested: self.max_completed_operations,
                hard_limit: HARD_MAX_COMPLETED_OPERATIONS,
            });
        }
        if self.max_search_nodes == 0 {
            return Err(CheckLimitsError::ZeroSearchNodeBudget);
        }
        Ok(())
    }
}

/// A checker configured with a fixed resource budget.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinearizabilityChecker {
    limits: CheckLimits,
}

impl LinearizabilityChecker {
    /// Creates a checker after validating its declared bounds.
    pub fn new(limits: CheckLimits) -> Result<Self, CheckLimitsError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    /// Returns the configured bounds.
    #[must_use]
    pub const fn limits(self) -> CheckLimits {
        self.limits
    }

    /// Checks a validated history against a sequential specification.
    ///
    /// Operations are explored in `OperationId` order whenever their
    /// response-before-invocation predecessors have already linearized. A
    /// pending invocation is explored deterministically in both legal forms:
    /// it may have taken effect, or it may be absent from the linearization.
    /// This makes both the witness and a predecessor-closed minimal conflict
    /// window stable without treating a lost acknowledgement as a negative.
    #[must_use]
    pub fn check<Spec>(
        &self,
        specification: &Spec,
        history: &History<Spec::Operation, Spec::Response>,
    ) -> CheckReport
    where
        Spec: SequentialSpec,
    {
        let operations = history.operations();
        let pending_operations = operations
            .iter()
            .filter(|operation| operation.response.is_none())
            .map(|operation| operation.id)
            .collect::<Vec<_>>();
        let completed_operations = operations
            .iter()
            .copied()
            .filter_map(completed_from_recorded)
            .collect::<Vec<_>>();

        if operations.len() > self.limits.max_completed_operations {
            return CheckReport {
                completed_operations: completed_operations.len(),
                pending_operations,
                explored_nodes: 0,
                verdict: CheckVerdict::Indeterminate {
                    reason: IndeterminateReason::HistoryTooLarge {
                        completed_operations: completed_operations.len(),
                        pending_operations: operations.len() - completed_operations.len(),
                        allowed_operations: self.limits.max_completed_operations,
                    },
                },
            };
        }

        match run_search(specification, &operations, self.limits.max_search_nodes) {
            SearchOutcome::Linearizable {
                witness,
                explored_nodes,
            } => CheckReport {
                completed_operations: completed_operations.len(),
                pending_operations,
                explored_nodes,
                verdict: CheckVerdict::Linearizable { witness },
            },
            SearchOutcome::NotLinearizable { explored_nodes } => {
                let (conflict, predecessor_closed_minimal) = minimize_conflict_window(
                    specification,
                    &completed_operations,
                    self.limits.max_search_nodes,
                );
                CheckReport {
                    completed_operations: completed_operations.len(),
                    pending_operations,
                    explored_nodes,
                    verdict: CheckVerdict::NotLinearizable {
                        conflict,
                        predecessor_closed_minimal,
                    },
                }
            }
            SearchOutcome::SearchBudgetExhausted { explored_nodes } => CheckReport {
                completed_operations: completed_operations.len(),
                pending_operations,
                explored_nodes,
                verdict: CheckVerdict::Indeterminate {
                    reason: IndeterminateReason::SearchBudgetExhausted {
                        allowed_nodes: self.limits.max_search_nodes,
                    },
                },
            },
        }
    }

    /// Checks the real authority vocabulary without depending on a backend's
    /// private opaque-token byte layout.
    ///
    /// Authority tokens are equality-only handles. The adapter preserves their
    /// observed equality classes while assigning checker-local representatives,
    /// so a sequential specification verifies issuance and predecessor rules
    /// rather than transcribing a particular store implementation.
    #[must_use]
    pub fn check_authority<Spec>(
        &self,
        specification: &Spec,
        history: &AuthorityHistory,
    ) -> CheckReport
    where
        Spec: AuthoritySequentialSpec,
    {
        let normalized = normalize_authority_tokens(history);
        self.check(specification, &normalized)
    }
}

/// A structured checker report that can be rendered as one NDJSON record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckReport {
    /// Number of operations that supplied both an invocation and a response.
    pub completed_operations: usize,
    /// Invocations without a response. Each is explicitly explored as either
    /// effectful or absent; see a successful witness for the effectful subset.
    pub pending_operations: Vec<OperationId>,
    /// Search nodes explored by the primary history evaluation.
    pub explored_nodes: usize,
    /// The resulting proof witness, conflict, or explicit bound result.
    pub verdict: CheckVerdict,
}

impl CheckReport {
    /// Serializes this report as one deterministic NDJSON line.
    ///
    /// The current writer emits only fixed strings and numeric identifiers, so
    /// it needs no provisional serialization dependency. `fgit-codec` may add
    /// a binary history envelope without changing this evidence shape.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let pending = format_operation_ids(&self.pending_operations);
        let common = format!(
            "\"schema\":\"{NDJSON_SCHEMA}\",\"completed_operations\":{},\"pending_operations\":[{pending}],\"explored_nodes\":{}",
            self.completed_operations, self.explored_nodes
        );

        match &self.verdict {
            CheckVerdict::Linearizable { witness } => format!(
                "{{{common},\"verdict\":\"linearizable\",\"witness\":[{}],\"effectful_pending_operations\":[{}]}}\n",
                format_operation_ids(&witness.operation_ids),
                format_operation_ids(&witness.effectful_pending_operations),
            ),
            CheckVerdict::NotLinearizable {
                conflict,
                predecessor_closed_minimal,
            } => format!(
                "{{{common},\"verdict\":\"not_linearizable\",\"conflict_window\":{{\"operation_ids\":[{}],\"first_event_index\":{},\"last_event_index\":{},\"predecessor_closed_minimal\":{predecessor_closed_minimal}}}}}\n",
                format_operation_ids(&conflict.operation_ids),
                conflict.first_event_index,
                conflict.last_event_index,
            ),
            CheckVerdict::Indeterminate { reason } => format!(
                "{{{common},\"verdict\":\"indeterminate\",{}}}\n",
                reason.to_ndjson_fields()
            ),
        }
    }
}

/// A successful sequential order for the operations that took effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearizationWitness {
    /// Completed operations and effectful pending invocations in deterministic
    /// linearization order.
    pub operation_ids: Vec<OperationId>,
    /// The subset of `operation_ids` that lacked an observed response.
    pub effectful_pending_operations: Vec<OperationId>,
}

/// The smallest deterministic predecessor-closed conflict set found by deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictWindow {
    /// Operations that still cannot be linearized together, including every
    /// response-before-invocation predecessor needed to interpret their state.
    pub operation_ids: Vec<OperationId>,
    /// First invocation or response index belonging to the conflict set.
    pub first_event_index: usize,
    /// Last invocation or response index belonging to the conflict set.
    pub last_event_index: usize,
}

/// The non-success classes returned by a check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckVerdict {
    /// The recorded completed operations have a valid sequential order.
    Linearizable {
        /// Deterministic witness order.
        witness: LinearizationWitness,
    },
    /// No valid sequential order exists for the returned conflict window.
    NotLinearizable {
        /// A deterministic, predecessor-closed minimal conflicting window.
        conflict: ConflictWindow,
        /// Whether every allowed predecessor-closed deletion was checked within
        /// the configured search budget.
        predecessor_closed_minimal: bool,
    },
    /// The checker refused to claim a verdict beyond its declared bounds.
    Indeterminate {
        /// Exact declared bound that prevented a yes/no result.
        reason: IndeterminateReason,
    },
}

/// A declared limit prevented the checker from producing a yes/no verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndeterminateReason {
    /// The history contains more recorded operations than the caller allowed.
    HistoryTooLarge {
        /// Number of complete operations observed.
        completed_operations: usize,
        /// Number of incomplete invocations observed.
        pending_operations: usize,
        /// Configured cap.
        allowed_operations: usize,
    },
    /// The bounded search did not finish before the declared node budget.
    SearchBudgetExhausted {
        /// Configured cap.
        allowed_nodes: usize,
    },
}

impl IndeterminateReason {
    fn to_ndjson_fields(&self) -> String {
        match self {
            Self::HistoryTooLarge {
                completed_operations,
                pending_operations,
                allowed_operations,
            } => format!(
                "\"reason\":\"history-too-large\",\"observed_completed_operations\":{completed_operations},\"observed_pending_operations\":{pending_operations},\"allowed_recorded_operations\":{allowed_operations}"
            ),
            Self::SearchBudgetExhausted { allowed_nodes } => {
                format!(
                    "\"reason\":\"search-budget-exhausted\",\"allowed_search_nodes\":{allowed_nodes}"
                )
            }
        }
    }
}

/// Invalid checker limits are rejected before evaluating a history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckLimitsError {
    /// A zero operation cap could never inspect an actual operation.
    ZeroCompletedOperationBound,
    /// The mask representation has a fixed finite maximum.
    CompletedOperationBoundExceedsHardLimit {
        /// Requested cap.
        requested: usize,
        /// Largest supported cap.
        hard_limit: usize,
    },
    /// A zero-node search cannot inspect even an empty history.
    ZeroSearchNodeBudget,
}

impl fmt::Display for CheckLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCompletedOperationBound => {
                formatter.write_str("recorded-operation bound must be greater than zero")
            }
            Self::CompletedOperationBoundExceedsHardLimit {
                requested,
                hard_limit,
            } => write!(
                formatter,
                "recorded-operation bound {requested} exceeds hard limit {hard_limit}"
            ),
            Self::ZeroSearchNodeBudget => {
                formatter.write_str("search-node budget must be greater than zero")
            }
        }
    }
}

impl std::error::Error for CheckLimitsError {}

#[derive(Debug)]
struct CompletedOperation<'history, Operation, Response> {
    id: OperationId,
    invocation_event_index: usize,
    response_event_index: usize,
    operation: &'history Operation,
    response: &'history Response,
}

#[derive(Debug)]
struct SearchOperation<'history, Operation, Response> {
    id: OperationId,
    invocation_event_index: usize,
    response_event_index: Option<usize>,
    operation: &'history Operation,
    response: Option<&'history Response>,
}

impl<Operation, Response> Copy for SearchOperation<'_, Operation, Response> {}

impl<Operation, Response> Clone for SearchOperation<'_, Operation, Response> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Operation, Response> Copy for CompletedOperation<'_, Operation, Response> {}

impl<Operation, Response> Clone for CompletedOperation<'_, Operation, Response> {
    fn clone(&self) -> Self {
        *self
    }
}

const fn completed_from_recorded<Operation, Response>(
    recorded: RecordedOperation<'_, Operation, Response>,
) -> Option<CompletedOperation<'_, Operation, Response>> {
    match (recorded.response_event_index, recorded.response) {
        (Some(response_event_index), Some(response)) => Some(CompletedOperation {
            id: recorded.id,
            invocation_event_index: recorded.invocation_event_index,
            response_event_index,
            operation: recorded.operation,
            response,
        }),
        _ => None,
    }
}

const fn search_from_recorded<Operation, Response>(
    recorded: RecordedOperation<'_, Operation, Response>,
) -> SearchOperation<'_, Operation, Response> {
    SearchOperation {
        id: recorded.id,
        invocation_event_index: recorded.invocation_event_index,
        response_event_index: recorded.response_event_index,
        operation: recorded.operation,
        response: recorded.response,
    }
}

enum SearchOutcome {
    Linearizable {
        witness: LinearizationWitness,
        explored_nodes: usize,
    },
    NotLinearizable {
        explored_nodes: usize,
    },
    SearchBudgetExhausted {
        explored_nodes: usize,
    },
}

fn run_search<Spec>(
    specification: &Spec,
    operations: &[RecordedOperation<'_, Spec::Operation, Spec::Response>],
    max_search_nodes: usize,
) -> SearchOutcome
where
    Spec: SequentialSpec,
{
    let search_operations = operations
        .iter()
        .copied()
        .map(search_from_recorded)
        .collect::<Vec<_>>();
    let mut engine = SearchEngine::new(specification, &search_operations, max_search_nodes);
    let mut witness = Vec::with_capacity(operations.len());
    let mut effectful_pending_operations = Vec::new();
    let state = specification.initial_state();

    match engine.search(state, 0, 0, &mut witness, &mut effectful_pending_operations) {
        SearchStep::Found => SearchOutcome::Linearizable {
            witness: LinearizationWitness {
                operation_ids: witness,
                effectful_pending_operations,
            },
            explored_nodes: engine.explored_nodes,
        },
        SearchStep::NoSolution => SearchOutcome::NotLinearizable {
            explored_nodes: engine.explored_nodes,
        },
        SearchStep::SearchBudgetExhausted => SearchOutcome::SearchBudgetExhausted {
            explored_nodes: engine.explored_nodes,
        },
    }
}

struct SearchEngine<'operations, 'history, 'specification, Spec>
where
    Spec: SequentialSpec,
{
    specification: &'specification Spec,
    operations: &'operations [SearchOperation<'history, Spec::Operation, Spec::Response>],
    predecessors: Vec<u64>,
    full_mask: u64,
    max_search_nodes: usize,
    explored_nodes: usize,
    exhausted_states: BTreeMap<(u64, u64), Vec<Spec::State>>,
}

impl<'operations, 'history, 'specification, Spec>
    SearchEngine<'operations, 'history, 'specification, Spec>
where
    Spec: SequentialSpec,
{
    fn new(
        specification: &'specification Spec,
        operations: &'operations [SearchOperation<'history, Spec::Operation, Spec::Response>],
        max_search_nodes: usize,
    ) -> Self {
        let predecessors = build_predecessors(operations);
        let full_mask = (1_u64 << operations.len()).saturating_sub(1);
        Self {
            specification,
            operations,
            predecessors,
            full_mask,
            max_search_nodes,
            explored_nodes: 0,
            exhausted_states: BTreeMap::new(),
        }
    }

    fn search(
        &mut self,
        state: Spec::State,
        linearized_mask: u64,
        skipped_pending_mask: u64,
        witness: &mut Vec<OperationId>,
        effectful_pending_operations: &mut Vec<OperationId>,
    ) -> SearchStep {
        if linearized_mask | skipped_pending_mask == self.full_mask {
            return SearchStep::Found;
        }

        if self
            .exhausted_states
            .get(&(linearized_mask, skipped_pending_mask))
            .is_some_and(|states| states.iter().any(|known| known == &state))
        {
            return SearchStep::NoSolution;
        }

        if self.explored_nodes >= self.max_search_nodes {
            return SearchStep::SearchBudgetExhausted;
        }
        self.explored_nodes += 1;

        for operation_index in 0..self.operations.len() {
            let bit = 1_u64 << operation_index;
            if (linearized_mask | skipped_pending_mask) & bit != 0
                || self.predecessors[operation_index] & !linearized_mask != 0
            {
                continue;
            }

            let operation = self.operations[operation_index];
            let (next_state, expected_response) =
                self.specification.apply(&state, operation.operation);

            if let Some(response) = operation.response {
                if !expected_response.eq(response) {
                    continue;
                }

                witness.push(operation.id);
                match self.search(
                    next_state,
                    linearized_mask | bit,
                    skipped_pending_mask,
                    witness,
                    effectful_pending_operations,
                ) {
                    SearchStep::Found => return SearchStep::Found,
                    SearchStep::NoSolution => {
                        let _ = witness.pop();
                    }
                    SearchStep::SearchBudgetExhausted => {
                        let _ = witness.pop();
                        return SearchStep::SearchBudgetExhausted;
                    }
                }
            } else {
                witness.push(operation.id);
                effectful_pending_operations.push(operation.id);
                match self.search(
                    next_state,
                    linearized_mask | bit,
                    skipped_pending_mask,
                    witness,
                    effectful_pending_operations,
                ) {
                    SearchStep::Found => return SearchStep::Found,
                    SearchStep::NoSolution => {
                        let _ = effectful_pending_operations.pop();
                        let _ = witness.pop();
                    }
                    SearchStep::SearchBudgetExhausted => {
                        let _ = effectful_pending_operations.pop();
                        let _ = witness.pop();
                        return SearchStep::SearchBudgetExhausted;
                    }
                }

                match self.search(
                    state.clone(),
                    linearized_mask,
                    skipped_pending_mask | bit,
                    witness,
                    effectful_pending_operations,
                ) {
                    SearchStep::Found => return SearchStep::Found,
                    SearchStep::NoSolution => {}
                    SearchStep::SearchBudgetExhausted => return SearchStep::SearchBudgetExhausted,
                }
            }
        }

        self.exhausted_states
            .entry((linearized_mask, skipped_pending_mask))
            .or_default()
            .push(state);
        SearchStep::NoSolution
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchStep {
    Found,
    NoSolution,
    SearchBudgetExhausted,
}

fn build_predecessors<Operation, Response>(
    operations: &[SearchOperation<'_, Operation, Response>],
) -> Vec<u64> {
    operations
        .iter()
        .map(|operation| {
            operations
                .iter()
                .enumerate()
                .filter_map(|(candidate_index, candidate)| {
                    candidate
                        .response_event_index
                        .is_some_and(|response_event_index| {
                            response_event_index < operation.invocation_event_index
                        })
                        .then_some(1_u64 << candidate_index)
                })
                .fold(0_u64, |predecessors, predecessor| {
                    predecessors | predecessor
                })
        })
        .collect()
}

fn minimize_conflict_window<Spec>(
    specification: &Spec,
    completed_operations: &[CompletedOperation<'_, Spec::Operation, Spec::Response>],
    max_search_nodes: usize,
) -> (ConflictWindow, bool)
where
    Spec: SequentialSpec,
{
    let mut active = completed_operations.to_vec();
    let mut candidate_index = 0;
    let mut predecessor_closed_minimal = true;

    while candidate_index < active.len() {
        if active.iter().enumerate().any(|(other_index, other)| {
            other_index != candidate_index
                && active[candidate_index].response_event_index < other.invocation_event_index
        }) {
            candidate_index += 1;
            continue;
        }

        let mut trial = active.clone();
        trial.remove(candidate_index);

        let trial_recorded = trial
            .iter()
            .map(|operation| RecordedOperation {
                id: operation.id,
                client: crate::history::ClientId(0),
                invocation_event_index: operation.invocation_event_index,
                response_event_index: Some(operation.response_event_index),
                operation: operation.operation,
                response: Some(operation.response),
            })
            .collect::<Vec<_>>();

        match run_search(specification, &trial_recorded, max_search_nodes) {
            SearchOutcome::NotLinearizable { .. } => {
                active = trial;
                candidate_index = 0;
            }
            SearchOutcome::Linearizable { .. } => {
                candidate_index += 1;
            }
            SearchOutcome::SearchBudgetExhausted { .. } => {
                predecessor_closed_minimal = false;
                candidate_index += 1;
            }
        }
    }

    (conflict_window(&active), predecessor_closed_minimal)
}

fn conflict_window<Operation, Response>(
    operations: &[CompletedOperation<'_, Operation, Response>],
) -> ConflictWindow {
    let mut first_event_index = usize::MAX;
    let mut last_event_index = 0;
    let operation_ids = operations
        .iter()
        .map(|operation| {
            first_event_index = first_event_index.min(operation.invocation_event_index);
            last_event_index = last_event_index.max(operation.response_event_index);
            operation.id
        })
        .collect();

    ConflictWindow {
        operation_ids,
        first_event_index,
        last_event_index,
    }
}

fn format_operation_ids(operation_ids: &[OperationId]) -> String {
    operation_ids
        .iter()
        .map(|operation_id| operation_id.0.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityStore, MemoryAuthorityStore};

    fn head_key(label: &str) -> HeadKey {
        HeadKey::new(format!("lincheck/{label}").into_bytes())
            .expect("the fixed test head key is valid")
    }

    fn initialized_receipt(response: AuthorityResponse) -> HeadReadReceipt {
        match response {
            AuthorityResponse::InitializeHead(HeadInit::Created(receipt)) => receipt,
            unexpected => panic!("expected created head receipt, got {unexpected:?}"),
        }
    }

    fn committed_receipt(response: AuthorityResponse) -> HeadReadReceipt {
        match response {
            AuthorityResponse::CompareExchangeHead(CasOutcome::Committed(receipt)) => receipt,
            unexpected => panic!("expected committed head receipt, got {unexpected:?}"),
        }
    }

    #[test]
    fn reference_spec_and_store_preserve_overlapping_cas_guard_order() {
        let instance = StoreInstanceId::from_raw(73);
        let store = MemoryAuthorityStore::new(instance);
        let specification = AuthorityReferenceSpec::new(instance);
        let initial = specification.initial_state();
        let primary = head_key("primary");
        let other = head_key("other");

        // An unissued token also names an absent head. The unknown-token guard
        // wins before the store considers the target slot.
        let unknown = AuthorityOp::CompareExchangeHead {
            key: primary.clone(),
            expected: AuthorityVersionToken::from_opaque_bytes([0xA5; 16]),
            new_generation: HeadGeneration::FIRST,
            new_body: b"unknown".to_vec(),
        };
        let (_, modeled_unknown) = specification.apply(&initial, &unknown);
        let stored_unknown = store.execute(&unknown);
        assert_eq!(modeled_unknown, stored_unknown);
        assert_eq!(
            modeled_unknown,
            AuthorityResponse::Refused(AuthorityRefusal::UnknownVersionToken)
        );

        let initialize = AuthorityOp::InitializeHead {
            key: primary.clone(),
            generation: HeadGeneration::FIRST,
            body: b"genesis".to_vec(),
        };
        let (initialized_state, modeled_initialize) = specification.apply(&initial, &initialize);
        let stored_initialize = store.execute(&initialize);
        assert_eq!(modeled_initialize, stored_initialize);
        let first = initialized_receipt(modeled_initialize);

        // The issued token is valid, but belongs to another key. This also
        // targets an absent head and proposes a non-advancing generation; key
        // mismatch must still win before either later guard.
        let wrong_key = AuthorityOp::CompareExchangeHead {
            key: other,
            expected: first.token(),
            new_generation: HeadGeneration::FIRST,
            new_body: b"wrong-key".to_vec(),
        };
        let (_, modeled_wrong_key) = specification.apply(&initialized_state, &wrong_key);
        let stored_wrong_key = store.execute(&wrong_key);
        assert_eq!(modeled_wrong_key, stored_wrong_key);
        assert_eq!(
            modeled_wrong_key,
            AuthorityResponse::Refused(AuthorityRefusal::TokenKeyMismatch)
        );

        let advance = AuthorityOp::CompareExchangeHead {
            key: primary.clone(),
            expected: first.token(),
            new_generation: first
                .generation()
                .next()
                .expect("the genesis generation has a successor"),
            new_body: b"advanced".to_vec(),
        };
        let (advanced_state, modeled_advance) = specification.apply(&initialized_state, &advance);
        let stored_advance = store.execute(&advance);
        assert_eq!(modeled_advance, stored_advance);
        let _second = committed_receipt(modeled_advance);

        // The first token is known and key-correct, but stale. It also offers
        // a non-monotone generation, so predecessor mismatch must win before
        // the monotonicity guard.
        let stale_and_non_monotone = AuthorityOp::CompareExchangeHead {
            key: primary,
            expected: first.token(),
            new_generation: HeadGeneration::FIRST,
            new_body: b"stale".to_vec(),
        };
        let (_, modeled_stale) = specification.apply(&advanced_state, &stale_and_non_monotone);
        let stored_stale = store.execute(&stale_and_non_monotone);
        assert_eq!(modeled_stale, stored_stale);
        assert_eq!(
            modeled_stale,
            AuthorityResponse::CompareExchangeHead(CasOutcome::PredecessorMismatch)
        );
    }
}
