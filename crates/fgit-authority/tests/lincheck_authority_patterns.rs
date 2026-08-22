use fgit_authority::history::{ClientId, History, HistoryEvent, LogicalTime, OperationId};
use fgit_authority::lincheck::{
    CheckLimits, CheckLimitsError, CheckReport, CheckVerdict, HARD_MAX_COMPLETED_OPERATIONS,
    LinearizabilityChecker, SequentialSpec,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct HeadState {
    value: Option<u8>,
    version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthorityOperation {
    PutIfAbsent { value: u8 },
    CompareExchange { expected_version: u64, value: u8 },
    ReadHead,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthorityResponse {
    PutCreated { version: u64 },
    PutAlreadyPresent { version: u64 },
    PutConflict { version: u64 },
    CompareExchangeWon { version: u64 },
    CompareExchangeLost { observed_version: u64 },
    ReadHead { value: Option<u8>, version: u64 },
}

struct AuthoritySequentialSpec;

impl SequentialSpec for AuthoritySequentialSpec {
    type State = HeadState;
    type Operation = AuthorityOperation;
    type Response = AuthorityResponse;

    fn initial_state(&self) -> Self::State {
        HeadState {
            value: Some(0),
            version: 1,
        }
    }

    fn apply(
        &self,
        state: &Self::State,
        operation: &Self::Operation,
    ) -> (Self::State, Self::Response) {
        match operation {
            AuthorityOperation::PutIfAbsent { value } => match state.value {
                None => (
                    HeadState {
                        value: Some(*value),
                        version: state.version + 1,
                    },
                    AuthorityResponse::PutCreated {
                        version: state.version + 1,
                    },
                ),
                Some(existing) if existing == *value => (
                    state.clone(),
                    AuthorityResponse::PutAlreadyPresent {
                        version: state.version,
                    },
                ),
                Some(_) => (
                    state.clone(),
                    AuthorityResponse::PutConflict {
                        version: state.version,
                    },
                ),
            },
            AuthorityOperation::CompareExchange {
                expected_version,
                value,
            } if *expected_version == state.version => (
                HeadState {
                    value: Some(*value),
                    version: state.version + 1,
                },
                AuthorityResponse::CompareExchangeWon {
                    version: state.version + 1,
                },
            ),
            AuthorityOperation::CompareExchange { .. } => (
                state.clone(),
                AuthorityResponse::CompareExchangeLost {
                    observed_version: state.version,
                },
            ),
            AuthorityOperation::ReadHead => (
                state.clone(),
                AuthorityResponse::ReadHead {
                    value: state.value,
                    version: state.version,
                },
            ),
        }
    }
}

fn checker() -> LinearizabilityChecker {
    LinearizabilityChecker::new(CheckLimits {
        max_completed_operations: 16,
        max_search_nodes: 50_000,
    })
    .expect("test checker limits are valid")
}

const fn invocation(
    client: u64,
    timestamp: u64,
    operation_id: u64,
    operation: AuthorityOperation,
) -> HistoryEvent<AuthorityOperation, AuthorityResponse> {
    HistoryEvent::invocation(
        ClientId(client),
        LogicalTime(timestamp),
        OperationId(operation_id),
        operation,
    )
}

const fn response(
    client: u64,
    timestamp: u64,
    operation_id: u64,
    response: AuthorityResponse,
) -> HistoryEvent<AuthorityOperation, AuthorityResponse> {
    HistoryEvent::response(
        ClientId(client),
        LogicalTime(timestamp),
        OperationId(operation_id),
        response,
    )
}

fn history(
    events: Vec<HistoryEvent<AuthorityOperation, AuthorityResponse>>,
) -> History<AuthorityOperation, AuthorityResponse> {
    History::new(events).expect("test histories are structurally valid")
}

fn conflict(report: CheckReport) -> (Vec<OperationId>, usize, usize) {
    match report.verdict {
        CheckVerdict::NotLinearizable {
            conflict,
            predecessor_closed_minimal: true,
        } => (
            conflict.operation_ids,
            conflict.first_event_index,
            conflict.last_event_index,
        ),
        unexpected => panic!("expected a predecessor-closed minimal conflict, got {unexpected:?}"),
    }
}

fn generated_good_history() -> History<AuthorityOperation, AuthorityResponse> {
    let specification = AuthoritySequentialSpec;
    let operations = [
        AuthorityOperation::ReadHead,
        AuthorityOperation::CompareExchange {
            expected_version: 1,
            value: 3,
        },
        AuthorityOperation::PutIfAbsent { value: 3 },
        AuthorityOperation::ReadHead,
    ];
    let mut events = Vec::new();
    let mut state = specification.initial_state();

    for ((client, operation_id), operation) in [
        (1_u64, 1_u64),
        (2_u64, 2_u64),
        (1_u64, 3_u64),
        (2_u64, 4_u64),
    ]
    .into_iter()
    .zip(operations)
    {
        let invocation_time = operation_id * 2 - 1;
        let response_time = invocation_time + 1;
        events.push(invocation(
            client,
            invocation_time,
            operation_id,
            operation.clone(),
        ));
        let (next_state, observed_response) = specification.apply(&state, &operation);
        state = next_state;
        events.push(response(
            client,
            response_time,
            operation_id,
            observed_response,
        ));
    }

    history(events)
}

#[test]
fn generated_history_from_the_sequential_spec_passes() {
    let report = checker().check(&AuthoritySequentialSpec, &generated_good_history());

    assert!(matches!(report.verdict, CheckVerdict::Linearizable { .. }));
    assert_eq!(report.pending_operations, Vec::new());
}

#[test]
fn history_refuses_a_non_monotonic_per_client_clock() {
    let malformed = History::new(vec![
        invocation(1, 1, 10, AuthorityOperation::ReadHead),
        response(
            1,
            1,
            10,
            AuthorityResponse::ReadHead {
                value: Some(0),
                version: 1,
            },
        ),
    ]);

    assert!(matches!(
        malformed,
        Err(fgit_authority::history::HistoryError::NonMonotonicClientTime { .. })
    ));
}

#[test]
fn history_beyond_the_declared_bound_is_indeterminate_not_accepted() {
    let checker = LinearizabilityChecker::new(CheckLimits {
        max_completed_operations: 1,
        max_search_nodes: 100,
    })
    .expect("test checker limits are valid");
    let report = checker.check(&AuthoritySequentialSpec, &generated_good_history());

    assert_eq!(
        report.verdict,
        CheckVerdict::Indeterminate {
            reason: fgit_authority::lincheck::IndeterminateReason::HistoryTooLarge {
                completed_operations: 4,
                pending_operations: 0,
                allowed_operations: 1,
            },
        }
    );
}

#[test]
fn rejects_stale_read_after_a_completed_compare_exchange() {
    let report = checker().check(
        &AuthoritySequentialSpec,
        &history(vec![
            invocation(
                1,
                1,
                10,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 1,
                },
            ),
            response(
                1,
                2,
                10,
                AuthorityResponse::CompareExchangeWon { version: 2 },
            ),
            invocation(2, 1, 20, AuthorityOperation::ReadHead),
            response(
                2,
                2,
                20,
                AuthorityResponse::ReadHead {
                    value: Some(0),
                    version: 1,
                },
            ),
        ]),
    );

    assert_eq!(
        conflict(report),
        (vec![OperationId(10), OperationId(20)], 0, 3)
    );
}

#[test]
fn pending_compare_exchange_can_take_effect_before_a_resolution_read() {
    let report = checker().check(
        &AuthoritySequentialSpec,
        &history(vec![
            invocation(
                1,
                1,
                10,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 1,
                },
            ),
            invocation(2, 1, 20, AuthorityOperation::ReadHead),
            response(
                2,
                2,
                20,
                AuthorityResponse::ReadHead {
                    value: Some(1),
                    version: 2,
                },
            ),
        ]),
    );

    assert_eq!(
        report.verdict,
        CheckVerdict::Linearizable {
            witness: fgit_authority::lincheck::LinearizationWitness {
                operation_ids: vec![OperationId(10), OperationId(20)],
                effectful_pending_operations: vec![OperationId(10)],
            },
        }
    );
}

#[test]
fn pending_compare_exchange_can_be_absent_when_the_resolution_is_unchanged() {
    let report = checker().check(
        &AuthoritySequentialSpec,
        &history(vec![
            invocation(
                1,
                1,
                10,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 1,
                },
            ),
            invocation(2, 1, 20, AuthorityOperation::ReadHead),
            response(
                2,
                2,
                20,
                AuthorityResponse::ReadHead {
                    value: Some(0),
                    version: 1,
                },
            ),
        ]),
    );

    assert_eq!(
        report.verdict,
        CheckVerdict::Linearizable {
            witness: fgit_authority::lincheck::LinearizationWitness {
                operation_ids: vec![OperationId(20)],
                effectful_pending_operations: Vec::new(),
            },
        }
    );
}

#[test]
fn pending_operations_are_part_of_the_history_bound() {
    let checker = LinearizabilityChecker::new(CheckLimits {
        max_completed_operations: 1,
        max_search_nodes: 100,
    })
    .expect("test checker limits are valid");
    let report = checker.check(
        &AuthoritySequentialSpec,
        &history(vec![
            invocation(1, 1, 10, AuthorityOperation::ReadHead),
            invocation(2, 1, 20, AuthorityOperation::ReadHead),
        ]),
    );

    assert_eq!(
        report.verdict,
        CheckVerdict::Indeterminate {
            reason: fgit_authority::lincheck::IndeterminateReason::HistoryTooLarge {
                completed_operations: 0,
                pending_operations: 2,
                allowed_operations: 1,
            },
        }
    );
}

#[test]
fn rejects_lost_update_visible_in_a_later_read() {
    let report = checker().check(
        &AuthoritySequentialSpec,
        &history(vec![
            invocation(
                1,
                1,
                10,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 1,
                },
            ),
            response(
                1,
                2,
                10,
                AuthorityResponse::CompareExchangeWon { version: 2 },
            ),
            invocation(
                2,
                1,
                20,
                AuthorityOperation::CompareExchange {
                    expected_version: 2,
                    value: 2,
                },
            ),
            response(
                2,
                2,
                20,
                AuthorityResponse::CompareExchangeWon { version: 3 },
            ),
            invocation(3, 1, 30, AuthorityOperation::ReadHead),
            response(
                3,
                2,
                30,
                AuthorityResponse::ReadHead {
                    value: Some(1),
                    version: 2,
                },
            ),
        ]),
    );

    assert_eq!(
        conflict(report),
        (
            vec![OperationId(10), OperationId(20), OperationId(30)],
            0,
            5
        )
    );
}

#[test]
fn rejects_aba_acceptance_of_a_restored_body_with_an_old_token() {
    let report = checker().check(
        &AuthoritySequentialSpec,
        &history(vec![
            invocation(
                1,
                1,
                10,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 1,
                },
            ),
            response(
                1,
                2,
                10,
                AuthorityResponse::CompareExchangeWon { version: 2 },
            ),
            invocation(
                1,
                3,
                20,
                AuthorityOperation::CompareExchange {
                    expected_version: 2,
                    value: 0,
                },
            ),
            response(
                1,
                4,
                20,
                AuthorityResponse::CompareExchangeWon { version: 3 },
            ),
            invocation(
                2,
                1,
                30,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 9,
                },
            ),
            response(
                2,
                2,
                30,
                AuthorityResponse::CompareExchangeWon { version: 4 },
            ),
        ]),
    );

    assert_eq!(
        conflict(report),
        (
            vec![OperationId(10), OperationId(20), OperationId(30)],
            0,
            5
        )
    );
}

#[test]
fn rejects_split_brain_double_compare_exchange_success() {
    let report = checker().check(
        &AuthoritySequentialSpec,
        &history(vec![
            invocation(
                1,
                1,
                10,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 1,
                },
            ),
            invocation(
                2,
                1,
                20,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 2,
                },
            ),
            response(
                1,
                2,
                10,
                AuthorityResponse::CompareExchangeWon { version: 2 },
            ),
            response(
                2,
                2,
                20,
                AuthorityResponse::CompareExchangeWon { version: 2 },
            ),
        ]),
    );

    assert_eq!(
        conflict(report),
        (vec![OperationId(10), OperationId(20)], 0, 3)
    );
}

#[test]
fn witness_ndjson_is_deterministic_for_overlapping_reads() {
    let observed_history = history(vec![
        invocation(1, 1, 20, AuthorityOperation::ReadHead),
        invocation(2, 1, 10, AuthorityOperation::ReadHead),
        response(
            1,
            2,
            20,
            AuthorityResponse::ReadHead {
                value: Some(0),
                version: 1,
            },
        ),
        response(
            2,
            2,
            10,
            AuthorityResponse::ReadHead {
                value: Some(0),
                version: 1,
            },
        ),
    ]);

    let first = checker().check(&AuthoritySequentialSpec, &observed_history);
    let second = checker().check(&AuthoritySequentialSpec, &observed_history);

    assert_eq!(first, second);
    assert_eq!(first.to_ndjson(), second.to_ndjson());
    assert!(first.to_ndjson().contains("\"witness\":[10,20]"));
}

#[test]
fn overlapping_compare_exchange_attempts_pass_when_exactly_one_wins() {
    let report = checker().check(
        &AuthoritySequentialSpec,
        &history(vec![
            invocation(
                1,
                1,
                10,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 1,
                },
            ),
            invocation(
                2,
                1,
                20,
                AuthorityOperation::CompareExchange {
                    expected_version: 1,
                    value: 2,
                },
            ),
            response(
                1,
                2,
                10,
                AuthorityResponse::CompareExchangeWon { version: 2 },
            ),
            response(
                2,
                2,
                20,
                AuthorityResponse::CompareExchangeLost {
                    observed_version: 2,
                },
            ),
        ]),
    );

    assert_eq!(
        report.verdict,
        CheckVerdict::Linearizable {
            witness: fgit_authority::lincheck::LinearizationWitness {
                operation_ids: vec![OperationId(10), OperationId(20)],
                effectful_pending_operations: Vec::new(),
            },
        }
    );
}

// ---------------------------------------------------------------------------
// frankengit-9vsd: the checker's own input validation.
//
// `History::validate` is what stops the linearizability checker analysing a
// malformed history and returning a verdict anyway. That matters beyond tidy
// coverage: `scripts/e2e/suites/authority/faults.sh` asserts FG-004C-E2E-003
// ("verdict":"linearizable") and FG-004C-E2E-004 ("verdict":"not_linearizable")
// on this checker's output, so a validator that does not fire produces a false
// green inside the machinery built to detect false greens.
//
// Four of its five refusals had zero assertions anywhere in the workspace.
//
// THE ORDER IS LOAD-BEARING. The per-client clock check runs for EVERY event
// before the kind match, and inside a Response the sequence is
// no-invocation -> client-mismatch -> duplicate-response. So each case below is
// built so that every EARLIER check passes -- monotonic clocks, and an
// invocation present where one is required -- which is what makes the case
// prove its own refusal rather than an earlier one. Each test says which
// earlier checks it had to satisfy.
// ---------------------------------------------------------------------------

/// One operation identity invoked twice.
///
/// Earlier checks satisfied: both events advance client 1's clock strictly
/// (10, 20), so `NonMonotonicClientTime` cannot fire first.
#[test]
fn history_refuses_one_operation_identity_invoked_twice() {
    let malformed = History::new(vec![
        invocation(1, 10, 7, AuthorityOperation::ReadHead),
        invocation(1, 20, 7, AuthorityOperation::ReadHead),
    ]);

    let Err(fgit_authority::history::HistoryError::DuplicateInvocation {
        operation_id,
        first_event_index,
        duplicate_event_index,
    }) = malformed
    else {
        panic!("expected DuplicateInvocation, got {malformed:?}");
    };
    assert_eq!(operation_id, OperationId(7));
    assert_eq!(
        (first_event_index, duplicate_event_index),
        (0, 1),
        "the refusal must locate both invocations, since that is what an \
         operator reads to find the malformed records",
    );
}

/// A response naming an operation that was never invoked.
///
/// Earlier checks satisfied: a single event cannot violate the per-client
/// clock, so this reaches the Response arm directly.
#[test]
fn history_refuses_a_response_with_no_invocation() {
    let malformed = History::new(vec![response(
        1,
        10,
        7,
        AuthorityResponse::ReadHead {
            value: Some(0),
            version: 1,
        },
    )]);

    let Err(fgit_authority::history::HistoryError::ResponseWithoutInvocation {
        operation_id,
        response_event_index,
    }) = malformed
    else {
        panic!("expected ResponseWithoutInvocation, got {malformed:?}");
    };
    assert_eq!(operation_id, OperationId(7));
    assert_eq!(response_event_index, 0);
}

/// A response returned to a different client than the one that invoked.
///
/// Earlier checks satisfied: two DIFFERENT clients each with a strictly
/// advancing clock, so `NonMonotonicClientTime` cannot fire; and the invocation
/// exists, so `ResponseWithoutInvocation` cannot fire. This case is only
/// reachable because both earlier checks pass, which is the ordering the bead
/// asked to be pinned.
#[test]
fn history_refuses_a_response_delivered_to_the_wrong_client() {
    let malformed = History::new(vec![
        invocation(1, 10, 7, AuthorityOperation::ReadHead),
        response(
            2,
            10,
            7,
            AuthorityResponse::ReadHead {
                value: Some(0),
                version: 1,
            },
        ),
    ]);

    let Err(fgit_authority::history::HistoryError::ResponseClientMismatch {
        operation_id,
        invocation_client,
        response_client,
        response_event_index,
    }) = malformed
    else {
        panic!("expected ResponseClientMismatch, got {malformed:?}");
    };
    assert_eq!(operation_id, OperationId(7));
    assert_eq!(
        (invocation_client, response_client),
        (ClientId(1), ClientId(2)),
        "a transposed pair would report the mismatch backwards and survive a \
         variant-only check",
    );
    assert_eq!(response_event_index, 1);
}

/// Two responses for one operation.
///
/// Earlier checks satisfied: client 1's clock advances strictly (10, 20, 30);
/// the invocation exists; and both responses come from the invoking client, so
/// neither `ResponseWithoutInvocation` nor `ResponseClientMismatch` can fire
/// first. This is the deepest case in the ordering.
#[test]
fn history_refuses_two_responses_for_one_operation() {
    let reply = AuthorityResponse::ReadHead {
        value: Some(0),
        version: 1,
    };
    let malformed = History::new(vec![
        invocation(1, 10, 7, AuthorityOperation::ReadHead),
        response(1, 20, 7, reply.clone()),
        response(1, 30, 7, reply),
    ]);

    let Err(fgit_authority::history::HistoryError::DuplicateResponse {
        operation_id,
        first_response_event_index,
        duplicate_event_index,
    }) = malformed
    else {
        panic!("expected DuplicateResponse, got {malformed:?}");
    };
    assert_eq!(operation_id, OperationId(7));
    assert_eq!((first_response_event_index, duplicate_event_index), (1, 2));
}

/// The permitted twin for all five refusals.
///
/// Two clients, interleaved, each with a strictly advancing clock and exactly
/// one response per invocation. Without this the four refusals above are
/// equally satisfied by a `validate` that rejects every history, which would
/// prove nothing about malformedness.
#[test]
fn a_well_formed_interleaved_history_is_accepted() {
    let reply = AuthorityResponse::ReadHead {
        value: Some(0),
        version: 1,
    };
    let accepted = History::new(vec![
        invocation(1, 10, 1, AuthorityOperation::ReadHead),
        invocation(2, 10, 2, AuthorityOperation::ReadHead),
        response(1, 20, 1, reply.clone()),
        response(2, 20, 2, reply),
    ])
    .expect("a well-formed interleaved history is admissible");

    assert_eq!(accepted.events().len(), 4);
    assert_eq!(
        accepted.completed_operation_count(),
        2,
        "both operations completed, so the acceptance is not vacuous on an \
         empty or pending history",
    );
}

/// The checker's own limits refuse degenerate configurations.
///
/// `HARD_MAX_COMPLETED_OPERATIONS` is a REPRESENTATION bound -- "the mask
/// representation has a fixed finite maximum" -- so exceeding it is a
/// correctness ceiling rather than a policy choice, and the permitted twin at
/// exactly the limit is what stops an off-by-one either rejecting a legal
/// history or overflowing the mask.
#[test]
fn check_limits_refuse_degenerate_bounds_and_permit_the_exact_hard_limit() {
    assert!(
        matches!(
            CheckLimits {
                max_completed_operations: 0,
                max_search_nodes: 1,
            }
            .validate(),
            Err(CheckLimitsError::ZeroCompletedOperationBound)
        ),
        "a zero operation cap could never inspect an operation",
    );

    assert!(
        matches!(
            CheckLimits {
                max_completed_operations: 1,
                max_search_nodes: 0,
            }
            .validate(),
            Err(CheckLimitsError::ZeroSearchNodeBudget)
        ),
        "a zero-node search cannot inspect even an empty history",
    );

    let over = CheckLimits {
        max_completed_operations: HARD_MAX_COMPLETED_OPERATIONS + 1,
        max_search_nodes: 1,
    }
    .validate();
    assert!(
        matches!(
            over,
            Err(CheckLimitsError::CompletedOperationBoundExceedsHardLimit {
                requested,
                hard_limit,
            }) if requested == HARD_MAX_COMPLETED_OPERATIONS + 1
                && hard_limit == HARD_MAX_COMPLETED_OPERATIONS
        ),
        "the refusal must report both the request and the ceiling; got {over:?}",
    );

    // The permitted twins, on the exact boundary and at the smallest legal
    // values. The comparison is `>`, so exactly the hard limit is admissible.
    CheckLimits {
        max_completed_operations: HARD_MAX_COMPLETED_OPERATIONS,
        max_search_nodes: 1,
    }
    .validate()
    .expect("exactly HARD_MAX_COMPLETED_OPERATIONS is inside the bound");
    CheckLimits {
        max_completed_operations: 1,
        max_search_nodes: 1,
    }
    .validate()
    .expect("the smallest legal configuration is admissible");
}
