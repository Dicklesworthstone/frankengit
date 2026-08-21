use fgit_authority::history::{ClientId, History, HistoryEvent, LogicalTime, OperationId};
use fgit_authority::lincheck::{
    CheckLimits, CheckReport, CheckVerdict, LinearizabilityChecker, SequentialSpec,
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

fn invocation(
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

fn response(
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
    assert!(report.pending_operations.is_empty());
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
            },
        }
    );
}
