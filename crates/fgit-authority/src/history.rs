//! Canonical, bounded history input for AuthorityStore linearizability checks.
//!
//! The vector order is the observer's total event order. `logical_time` is a
//! strictly increasing, per-client clock; it deliberately does not invent an
//! order between distinct clients. Real-time precedence is therefore inferred
//! only when one response appears before another invocation in this vector.

use std::collections::BTreeMap;
use std::fmt;

/// A stable operation identity, unique within one checked history.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(pub u64);

/// A client identity local to one checked history.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientId(pub u64);

/// A strictly increasing timestamp within one client stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalTime(pub u64);

/// The event payload recorded by a history observer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryEventKind<Operation, Response> {
    /// The client invoked an operation.
    Invocation { operation: Operation },
    /// The client observed an operation response.
    Response { response: Response },
}

/// One invocation or response observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEvent<Operation, Response> {
    /// Client that issued and observed this operation.
    pub client: ClientId,
    /// Logical timestamp in the client's own event stream.
    pub logical_time: LogicalTime,
    /// Identity shared by the invocation and optional response.
    pub operation_id: OperationId,
    /// Whether this event invoked an operation or returned its response.
    pub kind: HistoryEventKind<Operation, Response>,
}

impl<Operation, Response> HistoryEvent<Operation, Response> {
    /// Builds an invocation event.
    #[must_use]
    pub fn invocation(
        client: ClientId,
        logical_time: LogicalTime,
        operation_id: OperationId,
        operation: Operation,
    ) -> Self {
        Self {
            client,
            logical_time,
            operation_id,
            kind: HistoryEventKind::Invocation { operation },
        }
    }

    /// Builds a response event.
    #[must_use]
    pub fn response(
        client: ClientId,
        logical_time: LogicalTime,
        operation_id: OperationId,
        response: Response,
    ) -> Self {
        Self {
            client,
            logical_time,
            operation_id,
            kind: HistoryEventKind::Response { response },
        }
    }
}

/// A validated invocation/response history.
///
/// The event vector is an immutable evidence record. Its index supplies the
/// only cross-client ordering used by the checker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct History<Operation, Response> {
    events: Vec<HistoryEvent<Operation, Response>>,
}

impl<Operation, Response> History<Operation, Response> {
    /// Validates and retains an event sequence.
    pub fn new(events: Vec<HistoryEvent<Operation, Response>>) -> Result<Self, HistoryError> {
        let history = Self { events };
        history.validate()?;
        Ok(history)
    }

    /// Returns the immutable, observer-ordered event sequence.
    #[must_use]
    pub fn events(&self) -> &[HistoryEvent<Operation, Response>] {
        &self.events
    }

    /// Returns every operation in deterministic `OperationId` order.
    ///
    /// An invocation without a response is retained as `response: None`. The
    /// checker may omit such operations, as permitted by linearizability for
    /// incomplete calls; it never invents a response for one.
    #[must_use]
    pub fn operations(&self) -> Vec<RecordedOperation<'_, Operation, Response>> {
        let mut operations = BTreeMap::new();

        for (event_index, event) in self.events.iter().enumerate() {
            match &event.kind {
                HistoryEventKind::Invocation { operation } => {
                    operations.insert(
                        event.operation_id,
                        RecordedOperation {
                            id: event.operation_id,
                            client: event.client,
                            invocation_event_index: event_index,
                            response_event_index: None,
                            operation,
                            response: None,
                        },
                    );
                }
                HistoryEventKind::Response { response } => {
                    if let Some(recorded) = operations.get_mut(&event.operation_id) {
                        recorded.response_event_index = Some(event_index);
                        recorded.response = Some(response);
                    }
                }
            }
        }

        operations.into_values().collect()
    }

    /// Returns the number of completed operations.
    #[must_use]
    pub fn completed_operation_count(&self) -> usize {
        self.operations()
            .iter()
            .filter(|operation| operation.response.is_some())
            .count()
    }

    fn validate(&self) -> Result<(), HistoryError> {
        let mut last_time_by_client = BTreeMap::new();
        let mut operations: BTreeMap<OperationId, OperationLifecycle> = BTreeMap::new();

        for (event_index, event) in self.events.iter().enumerate() {
            if let Some(previous) = last_time_by_client.insert(event.client, event.logical_time)
                && event.logical_time <= previous
            {
                return Err(HistoryError::NonMonotonicClientTime {
                    client: event.client,
                    previous,
                    current: event.logical_time,
                    event_index,
                });
            }

            match &event.kind {
                HistoryEventKind::Invocation { .. } => {
                    if let Some(existing) = operations.get(&event.operation_id) {
                        return Err(HistoryError::DuplicateInvocation {
                            operation_id: event.operation_id,
                            first_event_index: existing.invocation_event_index,
                            duplicate_event_index: event_index,
                        });
                    }

                    operations.insert(
                        event.operation_id,
                        OperationLifecycle {
                            client: event.client,
                            invocation_event_index: event_index,
                            response_event_index: None,
                        },
                    );
                }
                HistoryEventKind::Response { .. } => {
                    let Some(existing) = operations.get_mut(&event.operation_id) else {
                        return Err(HistoryError::ResponseWithoutInvocation {
                            operation_id: event.operation_id,
                            response_event_index: event_index,
                        });
                    };

                    if existing.client != event.client {
                        return Err(HistoryError::ResponseClientMismatch {
                            operation_id: event.operation_id,
                            invocation_client: existing.client,
                            response_client: event.client,
                            response_event_index: event_index,
                        });
                    }

                    if let Some(first_response_event_index) = existing.response_event_index {
                        return Err(HistoryError::DuplicateResponse {
                            operation_id: event.operation_id,
                            first_response_event_index,
                            duplicate_event_index: event_index,
                        });
                    }

                    existing.response_event_index = Some(event_index);
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct OperationLifecycle {
    client: ClientId,
    invocation_event_index: usize,
    response_event_index: Option<usize>,
}

/// A validated operation reconstructed from its invocation and response.
#[derive(Clone, Copy, Debug)]
pub struct RecordedOperation<'history, Operation, Response> {
    /// Stable operation identity.
    pub id: OperationId,
    /// Client that owns the operation.
    pub client: ClientId,
    /// Position of the invocation in [`History::events`].
    pub invocation_event_index: usize,
    /// Position of the response, if the invocation completed.
    pub response_event_index: Option<usize>,
    /// Operation presented to the sequential specification.
    pub operation: &'history Operation,
    /// Response observed in the history, if any.
    pub response: Option<&'history Response>,
}

/// A malformed history cannot be a trustworthy checker input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// A client did not advance its logical clock strictly.
    NonMonotonicClientTime {
        /// Client whose clock regressed or repeated.
        client: ClientId,
        /// Previous timestamp for that client.
        previous: LogicalTime,
        /// Rejected timestamp.
        current: LogicalTime,
        /// Position of the rejected event.
        event_index: usize,
    },
    /// More than one invocation used the same operation identity.
    DuplicateInvocation {
        /// Reused operation identity.
        operation_id: OperationId,
        /// First invocation position.
        first_event_index: usize,
        /// Duplicate invocation position.
        duplicate_event_index: usize,
    },
    /// A response referred to an operation that was never invoked.
    ResponseWithoutInvocation {
        /// Unknown operation identity.
        operation_id: OperationId,
        /// Response position.
        response_event_index: usize,
    },
    /// Invocation and response identities were associated with different clients.
    ResponseClientMismatch {
        /// Operation whose client binding was violated.
        operation_id: OperationId,
        /// Client recorded at invocation.
        invocation_client: ClientId,
        /// Client recorded at response.
        response_client: ClientId,
        /// Response position.
        response_event_index: usize,
    },
    /// More than one response used the same operation identity.
    DuplicateResponse {
        /// Reused operation identity.
        operation_id: OperationId,
        /// First response position.
        first_response_event_index: usize,
        /// Duplicate response position.
        duplicate_event_index: usize,
    },
}

impl fmt::Display for HistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonMonotonicClientTime {
                client,
                previous,
                current,
                event_index,
            } => write!(
                formatter,
                "client {} timestamp at event {event_index} did not advance strictly: {} then {}",
                client.0, previous.0, current.0
            ),
            Self::DuplicateInvocation {
                operation_id,
                first_event_index,
                duplicate_event_index,
            } => write!(
                formatter,
                "operation {} invoked twice at events {first_event_index} and {duplicate_event_index}",
                operation_id.0
            ),
            Self::ResponseWithoutInvocation {
                operation_id,
                response_event_index,
            } => write!(
                formatter,
                "operation {} responded at event {response_event_index} without an invocation",
                operation_id.0
            ),
            Self::ResponseClientMismatch {
                operation_id,
                invocation_client,
                response_client,
                response_event_index,
            } => write!(
                formatter,
                "operation {} was invoked by client {} but responded by client {} at event {response_event_index}",
                operation_id.0, invocation_client.0, response_client.0
            ),
            Self::DuplicateResponse {
                operation_id,
                first_response_event_index,
                duplicate_event_index,
            } => write!(
                formatter,
                "operation {} responded twice at events {first_response_event_index} and {duplicate_event_index}",
                operation_id.0
            ),
        }
    }
}

impl std::error::Error for HistoryError {}
