//! Canonical, bounded history input for `AuthorityStore` linearizability checks.
//!
//! The vector order is the observer's total event order. `logical_time` is a
//! strictly increasing, per-client clock; it deliberately does not invent an
//! order between distinct clients. Real-time precedence is therefore inferred
//! only when one response appears before another invocation in this vector.

use std::collections::BTreeMap;
use std::fmt;

use crate::tokens::{AuthorityVersionToken, VERSION_TOKEN_BYTES};
use crate::vocabulary::{
    AmbiguityReason, AuthenticatedHead, AuthorityOp, AuthorityRefusal, AuthorityResponse,
    CasOutcome, HeadInit, HeadRead, HeadReadReceipt, ImmutableRead, PutOutcome,
};
use fgit_codec::{CanonicalBody, CodecRefusal, Decoder, Encoder};
use fgit_types::{DomainTag, HeadGeneration, SchemaFamily};

use crate::keys::{HeadKey, ImmutableKey, KeyError};
use crate::tokens::StoreInstanceId;

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
    pub const fn invocation(
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
    pub const fn response(
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

/// Replaces authority version tokens with deterministic opaque representatives.
///
/// Version-token bytes are intentionally an implementation detail of the
/// issuing store. A sequential checker must compare token equality and
/// freshness, but must not reproduce a backend's private minting layout. This
/// adapter preserves equality classes in observer-event order and maps each
/// class to a checker-local opaque token. It preserves all event, client, and
/// operation identities, so an already validated history remains valid.
#[must_use]
pub fn normalize_authority_tokens(
    history: &History<AuthorityOp, AuthorityResponse>,
) -> History<AuthorityOp, AuthorityResponse> {
    let mut replacements = BTreeMap::new();
    let mut next_token = 0_u64;
    let events = history
        .events
        .iter()
        .map(|event| HistoryEvent {
            client: event.client,
            logical_time: event.logical_time,
            operation_id: event.operation_id,
            kind: match &event.kind {
                HistoryEventKind::Invocation { operation } => HistoryEventKind::Invocation {
                    operation: normalize_authority_operation(
                        operation,
                        &mut replacements,
                        &mut next_token,
                    ),
                },
                HistoryEventKind::Response { response } => HistoryEventKind::Response {
                    response: normalize_authority_response(
                        response,
                        &mut replacements,
                        &mut next_token,
                    ),
                },
            },
        })
        .collect();

    History { events }
}

fn normalize_authority_operation(
    operation: &AuthorityOp,
    replacements: &mut BTreeMap<AuthorityVersionToken, AuthorityVersionToken>,
    next_token: &mut u64,
) -> AuthorityOp {
    match operation {
        AuthorityOp::PutIfAbsent { key, body } => AuthorityOp::PutIfAbsent {
            key: key.clone(),
            body: body.clone(),
        },
        AuthorityOp::ReadImmutable { key } => AuthorityOp::ReadImmutable { key: key.clone() },
        AuthorityOp::InitializeHead {
            key,
            generation,
            body,
        } => AuthorityOp::InitializeHead {
            key: key.clone(),
            generation: *generation,
            body: body.clone(),
        },
        AuthorityOp::ReadHead { key } => AuthorityOp::ReadHead { key: key.clone() },
        AuthorityOp::CompareExchangeHead {
            key,
            expected,
            new_generation,
            new_body,
        } => AuthorityOp::CompareExchangeHead {
            key: key.clone(),
            expected: normalize_token(*expected, replacements, next_token),
            new_generation: *new_generation,
            new_body: new_body.clone(),
        },
        AuthorityOp::AuthenticateHeadReceipt { receipt } => AuthorityOp::AuthenticateHeadReceipt {
            receipt: normalize_receipt(receipt, replacements, next_token),
        },
    }
}

fn normalize_authority_response(
    response: &AuthorityResponse,
    replacements: &mut BTreeMap<AuthorityVersionToken, AuthorityVersionToken>,
    next_token: &mut u64,
) -> AuthorityResponse {
    match response {
        AuthorityResponse::PutIfAbsent(outcome) => AuthorityResponse::PutIfAbsent(*outcome),
        AuthorityResponse::ReadImmutable(read) => AuthorityResponse::ReadImmutable(read.clone()),
        AuthorityResponse::InitializeHead(init) => AuthorityResponse::InitializeHead(match init {
            HeadInit::Created(receipt) => {
                HeadInit::Created(normalize_receipt(receipt, replacements, next_token))
            }
            HeadInit::IdenticalRetry(receipt) => {
                HeadInit::IdenticalRetry(normalize_receipt(receipt, replacements, next_token))
            }
            HeadInit::Conflict => HeadInit::Conflict,
        }),
        AuthorityResponse::ReadHead(read) => AuthorityResponse::ReadHead(match read {
            HeadRead::Present(receipt) => {
                HeadRead::Present(normalize_receipt(receipt, replacements, next_token))
            }
            HeadRead::Absent => HeadRead::Absent,
        }),
        AuthorityResponse::CompareExchangeHead(outcome) => {
            AuthorityResponse::CompareExchangeHead(match outcome {
                CasOutcome::Committed(receipt) => {
                    CasOutcome::Committed(normalize_receipt(receipt, replacements, next_token))
                }
                CasOutcome::PredecessorMismatch => CasOutcome::PredecessorMismatch,
            })
        }
        AuthorityResponse::AuthenticateHeadReceipt(authenticated) => {
            AuthorityResponse::AuthenticateHeadReceipt(AuthenticatedHead::new(
                normalize_receipt(authenticated.receipt(), replacements, next_token),
                authenticated.authenticated_by(),
            ))
        }
        AuthorityResponse::Refused(refusal) => AuthorityResponse::Refused(*refusal),
        AuthorityResponse::Ambiguous(reason) => AuthorityResponse::Ambiguous(*reason),
    }
}

fn normalize_receipt(
    receipt: &HeadReadReceipt,
    replacements: &mut BTreeMap<AuthorityVersionToken, AuthorityVersionToken>,
    next_token: &mut u64,
) -> HeadReadReceipt {
    HeadReadReceipt::new(
        receipt.key().clone(),
        normalize_token(receipt.token(), replacements, next_token),
        receipt.generation(),
        receipt.body().to_vec(),
    )
}

fn normalize_token(
    token: AuthorityVersionToken,
    replacements: &mut BTreeMap<AuthorityVersionToken, AuthorityVersionToken>,
    next_token: &mut u64,
) -> AuthorityVersionToken {
    *replacements.entry(token).or_insert_with(|| {
        let mut bytes = [0_u8; VERSION_TOKEN_BYTES];
        bytes[..8].copy_from_slice(b"fgithist");
        bytes[8..].copy_from_slice(&next_token.to_be_bytes());
        *next_token = next_token.saturating_add(1);
        AuthorityVersionToken::from_opaque_bytes(bytes)
    })
}

/// Versioned, canonical `fgit-codec` body for one authority history.
///
/// The event sequence is ordered evidence, not a set: the encoding preserves
/// every event index because cross-client real-time precedence is inferred from
/// that order. Decoding reconstructs the same validation boundary as a live
/// recorder, so malformed lifecycle sequences are refused before checking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityHistoryBody {
    history: History<AuthorityOp, AuthorityResponse>,
}

impl AuthorityHistoryBody {
    /// Wraps a previously validated authority history for codec framing.
    #[must_use]
    pub const fn new(history: History<AuthorityOp, AuthorityResponse>) -> Self {
        Self { history }
    }

    /// Returns the validated authority history.
    #[must_use]
    pub const fn history(&self) -> &History<AuthorityOp, AuthorityResponse> {
        &self.history
    }

    /// Consumes the codec body and returns its history.
    #[must_use]
    pub fn into_history(self) -> History<AuthorityOp, AuthorityResponse> {
        self.history
    }
}

impl CanonicalBody for AuthorityHistoryBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/authority-history/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("authority-history");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_sequence(
            "AuthorityHistory.events",
            self.history.events(),
            write_history_event,
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let events = input.read_sequence("AuthorityHistory.events", read_history_event)?;
        let offset = input.offset();
        History::new(events)
            .map(Self::new)
            .map_err(|error| history_validation_refusal(error, offset))
    }
}

fn write_history_event(
    out: &mut Encoder,
    event: &HistoryEvent<AuthorityOp, AuthorityResponse>,
) -> Result<(), CodecRefusal> {
    out.write_scalar(event.client.0);
    out.write_scalar(event.logical_time.0);
    out.write_scalar(event.operation_id.0);
    match &event.kind {
        HistoryEventKind::Invocation { operation } => {
            out.write_scalar(0_u8);
            write_authority_operation(out, operation)
        }
        HistoryEventKind::Response { response } => {
            out.write_scalar(1_u8);
            write_authority_response(out, response)
        }
    }
}

fn read_history_event(
    input: &mut Decoder<'_>,
) -> Result<HistoryEvent<AuthorityOp, AuthorityResponse>, CodecRefusal> {
    let client = ClientId(input.read_scalar("AuthorityHistory.client")?);
    let logical_time = LogicalTime(input.read_scalar("AuthorityHistory.logical_time")?);
    let operation_id = OperationId(input.read_scalar("AuthorityHistory.operation_id")?);
    let offset = input.offset();
    match input.read_scalar("AuthorityHistory.event_kind")? {
        0 => Ok(HistoryEvent::invocation(
            client,
            logical_time,
            operation_id,
            read_authority_operation(input)?,
        )),
        1 => Ok(HistoryEvent::response(
            client,
            logical_time,
            operation_id,
            read_authority_response(input)?,
        )),
        observed => Err(unknown_variant(
            "AuthorityHistory.event_kind",
            observed,
            offset,
        )),
    }
}

fn write_authority_operation(
    out: &mut Encoder,
    operation: &AuthorityOp,
) -> Result<(), CodecRefusal> {
    match operation {
        AuthorityOp::PutIfAbsent { key, body } => {
            out.write_scalar(0_u8);
            write_immutable_key(out, key)?;
            out.write_bytes("AuthorityOp.PutIfAbsent.body", body)
        }
        AuthorityOp::ReadImmutable { key } => {
            out.write_scalar(1_u8);
            write_immutable_key(out, key)
        }
        AuthorityOp::InitializeHead {
            key,
            generation,
            body,
        } => {
            out.write_scalar(2_u8);
            write_head_key(out, key)?;
            write_generation(out, *generation);
            out.write_bytes("AuthorityOp.InitializeHead.body", body)
        }
        AuthorityOp::ReadHead { key } => {
            out.write_scalar(3_u8);
            write_head_key(out, key)
        }
        AuthorityOp::CompareExchangeHead {
            key,
            expected,
            new_generation,
            new_body,
        } => {
            out.write_scalar(4_u8);
            write_head_key(out, key)?;
            write_token(out, *expected);
            write_generation(out, *new_generation);
            out.write_bytes("AuthorityOp.CompareExchangeHead.body", new_body)
        }
        AuthorityOp::AuthenticateHeadReceipt { receipt } => {
            out.write_scalar(5_u8);
            write_receipt(out, receipt)
        }
    }
}

fn read_authority_operation(input: &mut Decoder<'_>) -> Result<AuthorityOp, CodecRefusal> {
    let offset = input.offset();
    match input.read_scalar("AuthorityOp.tag")? {
        0 => Ok(AuthorityOp::PutIfAbsent {
            key: read_immutable_key(input)?,
            body: input.read_bytes("AuthorityOp.PutIfAbsent.body")?.to_vec(),
        }),
        1 => Ok(AuthorityOp::ReadImmutable {
            key: read_immutable_key(input)?,
        }),
        2 => Ok(AuthorityOp::InitializeHead {
            key: read_head_key(input)?,
            generation: read_generation(input)?,
            body: input
                .read_bytes("AuthorityOp.InitializeHead.body")?
                .to_vec(),
        }),
        3 => Ok(AuthorityOp::ReadHead {
            key: read_head_key(input)?,
        }),
        4 => Ok(AuthorityOp::CompareExchangeHead {
            key: read_head_key(input)?,
            expected: read_token(input)?,
            new_generation: read_generation(input)?,
            new_body: input
                .read_bytes("AuthorityOp.CompareExchangeHead.body")?
                .to_vec(),
        }),
        5 => Ok(AuthorityOp::AuthenticateHeadReceipt {
            receipt: read_receipt(input)?,
        }),
        observed => Err(unknown_variant("AuthorityOp.tag", observed, offset)),
    }
}

fn write_authority_response(
    out: &mut Encoder,
    response: &AuthorityResponse,
) -> Result<(), CodecRefusal> {
    match response {
        AuthorityResponse::PutIfAbsent(outcome) => {
            out.write_scalar(0_u8);
            out.write_scalar(put_outcome_tag(*outcome));
            Ok(())
        }
        AuthorityResponse::ReadImmutable(read) => {
            out.write_scalar(1_u8);
            match read {
                ImmutableRead::Present(body) => {
                    out.write_scalar(0_u8);
                    out.write_bytes("AuthorityResponse.ReadImmutable.body", body)
                }
                ImmutableRead::Absent => {
                    out.write_scalar(1_u8);
                    Ok(())
                }
            }
        }
        AuthorityResponse::InitializeHead(init) => {
            out.write_scalar(2_u8);
            match init {
                HeadInit::Created(receipt) => {
                    out.write_scalar(0_u8);
                    write_receipt(out, receipt)
                }
                HeadInit::IdenticalRetry(receipt) => {
                    out.write_scalar(1_u8);
                    write_receipt(out, receipt)
                }
                HeadInit::Conflict => {
                    out.write_scalar(2_u8);
                    Ok(())
                }
            }
        }
        AuthorityResponse::ReadHead(read) => {
            out.write_scalar(3_u8);
            match read {
                HeadRead::Present(receipt) => {
                    out.write_scalar(0_u8);
                    write_receipt(out, receipt)
                }
                HeadRead::Absent => {
                    out.write_scalar(1_u8);
                    Ok(())
                }
            }
        }
        AuthorityResponse::CompareExchangeHead(outcome) => {
            out.write_scalar(4_u8);
            match outcome {
                CasOutcome::Committed(receipt) => {
                    out.write_scalar(0_u8);
                    write_receipt(out, receipt)
                }
                CasOutcome::PredecessorMismatch => {
                    out.write_scalar(1_u8);
                    Ok(())
                }
            }
        }
        AuthorityResponse::AuthenticateHeadReceipt(authenticated) => {
            out.write_scalar(5_u8);
            write_receipt(out, authenticated.receipt())?;
            out.write_scalar(authenticated.authenticated_by().raw());
            Ok(())
        }
        AuthorityResponse::Refused(refusal) => {
            out.write_scalar(6_u8);
            write_refusal(out, *refusal)
        }
        AuthorityResponse::Ambiguous(reason) => {
            out.write_scalar(7_u8);
            out.write_scalar(ambiguity_reason_tag(*reason));
            Ok(())
        }
    }
}

fn read_authority_response(input: &mut Decoder<'_>) -> Result<AuthorityResponse, CodecRefusal> {
    let offset = input.offset();
    match input.read_scalar("AuthorityResponse.tag")? {
        0 => Ok(AuthorityResponse::PutIfAbsent(read_put_outcome(input)?)),
        1 => {
            let nested_offset = input.offset();
            match input.read_scalar("ImmutableRead.tag")? {
                0 => Ok(AuthorityResponse::ReadImmutable(ImmutableRead::Present(
                    input
                        .read_bytes("AuthorityResponse.ReadImmutable.body")?
                        .to_vec(),
                ))),
                1 => Ok(AuthorityResponse::ReadImmutable(ImmutableRead::Absent)),
                observed => Err(unknown_variant(
                    "ImmutableRead.tag",
                    observed,
                    nested_offset,
                )),
            }
        }
        2 => {
            let nested_offset = input.offset();
            match input.read_scalar("HeadInit.tag")? {
                0 => Ok(AuthorityResponse::InitializeHead(HeadInit::Created(
                    read_receipt(input)?,
                ))),
                1 => Ok(AuthorityResponse::InitializeHead(HeadInit::IdenticalRetry(
                    read_receipt(input)?,
                ))),
                2 => Ok(AuthorityResponse::InitializeHead(HeadInit::Conflict)),
                observed => Err(unknown_variant("HeadInit.tag", observed, nested_offset)),
            }
        }
        3 => {
            let nested_offset = input.offset();
            match input.read_scalar("HeadRead.tag")? {
                0 => Ok(AuthorityResponse::ReadHead(HeadRead::Present(
                    read_receipt(input)?,
                ))),
                1 => Ok(AuthorityResponse::ReadHead(HeadRead::Absent)),
                observed => Err(unknown_variant("HeadRead.tag", observed, nested_offset)),
            }
        }
        4 => {
            let nested_offset = input.offset();
            match input.read_scalar("CasOutcome.tag")? {
                0 => Ok(AuthorityResponse::CompareExchangeHead(
                    CasOutcome::Committed(read_receipt(input)?),
                )),
                1 => Ok(AuthorityResponse::CompareExchangeHead(
                    CasOutcome::PredecessorMismatch,
                )),
                observed => Err(unknown_variant("CasOutcome.tag", observed, nested_offset)),
            }
        }
        5 => Ok(AuthorityResponse::AuthenticateHeadReceipt(
            AuthenticatedHead::new(
                read_receipt(input)?,
                StoreInstanceId::from_raw(input.read_scalar("AuthenticatedHead.instance")?),
            ),
        )),
        6 => Ok(AuthorityResponse::Refused(read_refusal(input)?)),
        7 => Ok(AuthorityResponse::Ambiguous(read_ambiguity_reason(input)?)),
        observed => Err(unknown_variant("AuthorityResponse.tag", observed, offset)),
    }
}

fn write_immutable_key(out: &mut Encoder, key: &ImmutableKey) -> Result<(), CodecRefusal> {
    out.write_bytes("ImmutableKey", key.as_bytes())
}

fn read_immutable_key(input: &mut Decoder<'_>) -> Result<ImmutableKey, CodecRefusal> {
    let offset = input.offset();
    ImmutableKey::new(input.read_bytes("ImmutableKey")?)
        .map_err(|error| key_validation_refusal("ImmutableKey", error, offset))
}

fn write_head_key(out: &mut Encoder, key: &HeadKey) -> Result<(), CodecRefusal> {
    out.write_bytes("HeadKey", key.as_bytes())
}

fn read_head_key(input: &mut Decoder<'_>) -> Result<HeadKey, CodecRefusal> {
    let offset = input.offset();
    HeadKey::new(input.read_bytes("HeadKey")?)
        .map_err(|error| key_validation_refusal("HeadKey", error, offset))
}

fn write_generation(out: &mut Encoder, generation: HeadGeneration) {
    out.write_scalar(generation.get());
}

fn read_generation(input: &mut Decoder<'_>) -> Result<HeadGeneration, CodecRefusal> {
    HeadGeneration::try_new(input.read_scalar("HeadGeneration")?).map_err(CodecRefusal::from)
}

fn write_token(out: &mut Encoder, token: AuthorityVersionToken) {
    out.write_raw(&token.to_opaque_bytes());
}

fn read_token(input: &mut Decoder<'_>) -> Result<AuthorityVersionToken, CodecRefusal> {
    let bytes = input.take("AuthorityVersionToken", VERSION_TOKEN_BYTES)?;
    let mut token = [0_u8; VERSION_TOKEN_BYTES];
    token.copy_from_slice(bytes);
    Ok(AuthorityVersionToken::from_opaque_bytes(token))
}

fn write_receipt(out: &mut Encoder, receipt: &HeadReadReceipt) -> Result<(), CodecRefusal> {
    write_head_key(out, receipt.key())?;
    write_token(out, receipt.token());
    write_generation(out, receipt.generation());
    out.write_bytes("HeadReadReceipt.body", receipt.body())
}

fn read_receipt(input: &mut Decoder<'_>) -> Result<HeadReadReceipt, CodecRefusal> {
    Ok(HeadReadReceipt::new(
        read_head_key(input)?,
        read_token(input)?,
        read_generation(input)?,
        input.read_bytes("HeadReadReceipt.body")?.to_vec(),
    ))
}

const fn put_outcome_tag(outcome: PutOutcome) -> u8 {
    match outcome {
        PutOutcome::Created => 0,
        PutOutcome::IdenticalRetry => 1,
        PutOutcome::Conflict => 2,
    }
}

fn read_put_outcome(input: &mut Decoder<'_>) -> Result<PutOutcome, CodecRefusal> {
    let offset = input.offset();
    match input.read_scalar("PutOutcome.tag")? {
        0 => Ok(PutOutcome::Created),
        1 => Ok(PutOutcome::IdenticalRetry),
        2 => Ok(PutOutcome::Conflict),
        observed => Err(unknown_variant("PutOutcome.tag", observed, offset)),
    }
}

fn write_refusal(out: &mut Encoder, refusal: AuthorityRefusal) -> Result<(), CodecRefusal> {
    match refusal {
        AuthorityRefusal::InvalidKey(error) => {
            out.write_scalar(0_u8);
            write_key_error(out, error)
        }
        AuthorityRefusal::BodyTooLarge { len, limit } => {
            out.write_scalar(1_u8);
            write_usize(out, "AuthorityRefusal.BodyTooLarge.len", len)?;
            write_usize(out, "AuthorityRefusal.BodyTooLarge.limit", limit)
        }
        AuthorityRefusal::CapacityExhausted { occupancy, limit } => {
            out.write_scalar(2_u8);
            write_usize(
                out,
                "AuthorityRefusal.CapacityExhausted.occupancy",
                occupancy,
            )?;
            write_usize(out, "AuthorityRefusal.CapacityExhausted.limit", limit)
        }
        AuthorityRefusal::UnknownVersionToken => {
            write_tag_only(out, 3);
            Ok(())
        }
        AuthorityRefusal::TokenKeyMismatch => {
            write_tag_only(out, 4);
            Ok(())
        }
        AuthorityRefusal::TokenGenerationMismatch => {
            write_tag_only(out, 5);
            Ok(())
        }
        AuthorityRefusal::TokenBodyMismatch => {
            write_tag_only(out, 6);
            Ok(())
        }
        AuthorityRefusal::HeadAbsent => {
            write_tag_only(out, 7);
            Ok(())
        }
        AuthorityRefusal::NonMonotoneGeneration { current, proposed } => {
            out.write_scalar(8_u8);
            write_generation(out, current);
            write_generation(out, proposed);
            Ok(())
        }
        AuthorityRefusal::Throttled => {
            write_tag_only(out, 9);
            Ok(())
        }
        AuthorityRefusal::Unavailable => {
            write_tag_only(out, 10);
            Ok(())
        }
    }
}

fn read_refusal(input: &mut Decoder<'_>) -> Result<AuthorityRefusal, CodecRefusal> {
    let offset = input.offset();
    match input.read_scalar("AuthorityRefusal.tag")? {
        0 => Ok(AuthorityRefusal::InvalidKey(read_key_error(input)?)),
        1 => Ok(AuthorityRefusal::BodyTooLarge {
            len: read_usize(input, "AuthorityRefusal.BodyTooLarge.len")?,
            limit: read_usize(input, "AuthorityRefusal.BodyTooLarge.limit")?,
        }),
        2 => Ok(AuthorityRefusal::CapacityExhausted {
            occupancy: read_usize(input, "AuthorityRefusal.CapacityExhausted.occupancy")?,
            limit: read_usize(input, "AuthorityRefusal.CapacityExhausted.limit")?,
        }),
        3 => Ok(AuthorityRefusal::UnknownVersionToken),
        4 => Ok(AuthorityRefusal::TokenKeyMismatch),
        5 => Ok(AuthorityRefusal::TokenGenerationMismatch),
        6 => Ok(AuthorityRefusal::TokenBodyMismatch),
        7 => Ok(AuthorityRefusal::HeadAbsent),
        8 => Ok(AuthorityRefusal::NonMonotoneGeneration {
            current: read_generation(input)?,
            proposed: read_generation(input)?,
        }),
        9 => Ok(AuthorityRefusal::Throttled),
        10 => Ok(AuthorityRefusal::Unavailable),
        observed => Err(unknown_variant("AuthorityRefusal.tag", observed, offset)),
    }
}

fn write_key_error(out: &mut Encoder, error: KeyError) -> Result<(), CodecRefusal> {
    match error {
        KeyError::Empty => {
            write_tag_only(out, 0);
            Ok(())
        }
        KeyError::TooLong { len, limit } => {
            out.write_scalar(1_u8);
            write_usize(out, "KeyError.TooLong.len", len)?;
            write_usize(out, "KeyError.TooLong.limit", limit)
        }
    }
}

fn read_key_error(input: &mut Decoder<'_>) -> Result<KeyError, CodecRefusal> {
    let offset = input.offset();
    match input.read_scalar("KeyError.tag")? {
        0 => Ok(KeyError::Empty),
        1 => Ok(KeyError::TooLong {
            len: read_usize(input, "KeyError.TooLong.len")?,
            limit: read_usize(input, "KeyError.TooLong.limit")?,
        }),
        observed => Err(unknown_variant("KeyError.tag", observed, offset)),
    }
}

fn write_usize(out: &mut Encoder, field: &'static str, value: usize) -> Result<(), CodecRefusal> {
    let value = u64::try_from(value).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::MAX,
        limit: u64::MAX,
    })?;
    out.write_scalar(value);
    Ok(())
}

fn read_usize(input: &mut Decoder<'_>, field: &'static str) -> Result<usize, CodecRefusal> {
    let value = input.read_scalar::<u64>(field)?;
    usize::try_from(value).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: value,
        limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
    })
}

fn write_tag_only(out: &mut Encoder, tag: u8) {
    out.write_scalar(tag);
}

const fn ambiguity_reason_tag(reason: AmbiguityReason) -> u8 {
    match reason {
        AmbiguityReason::NoResponse => 0,
        AmbiguityReason::Timeout => 1,
        AmbiguityReason::Cancelled => 2,
    }
}

fn read_ambiguity_reason(input: &mut Decoder<'_>) -> Result<AmbiguityReason, CodecRefusal> {
    let offset = input.offset();
    match input.read_scalar("AmbiguityReason.tag")? {
        0 => Ok(AmbiguityReason::NoResponse),
        1 => Ok(AmbiguityReason::Timeout),
        2 => Ok(AmbiguityReason::Cancelled),
        observed => Err(unknown_variant("AmbiguityReason.tag", observed, offset)),
    }
}

fn unknown_variant(field: &'static str, observed: u8, offset: u64) -> CodecRefusal {
    CodecRefusal::VariantUnknown {
        field,
        observed: u32::from(observed),
        offset,
    }
}

const fn history_validation_refusal(error: HistoryError, offset: u64) -> CodecRefusal {
    let observed = match error {
        HistoryError::NonMonotonicClientTime { .. } => 0,
        HistoryError::DuplicateInvocation { .. } => 1,
        HistoryError::ResponseWithoutInvocation { .. } => 2,
        HistoryError::ResponseClientMismatch { .. } => 3,
        HistoryError::DuplicateResponse { .. } => 4,
    };
    CodecRefusal::VariantUnknown {
        field: "AuthorityHistory.lifecycle",
        observed,
        offset,
    }
}

const fn key_validation_refusal(field: &'static str, error: KeyError, offset: u64) -> CodecRefusal {
    let observed = match error {
        KeyError::Empty => 0,
        KeyError::TooLong { .. } => 1,
    };
    CodecRefusal::VariantUnknown {
        field,
        observed,
        offset,
    }
}

#[derive(Clone, Copy, Debug)]
struct OperationLifecycle {
    client: ClientId,
    invocation_event_index: usize,
    response_event_index: Option<usize>,
}

/// A validated operation reconstructed from its invocation and response.
#[derive(Debug)]
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

impl<Operation, Response> Copy for RecordedOperation<'_, Operation, Response> {}

impl<Operation, Response> Clone for RecordedOperation<'_, Operation, Response> {
    fn clone(&self) -> Self {
        *self
    }
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
