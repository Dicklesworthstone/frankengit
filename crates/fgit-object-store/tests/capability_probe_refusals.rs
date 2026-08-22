#![forbid(unsafe_code)]
//! The authority capability probe's refusals (`frankengit-3cdx`).
//!
//! `ObjectStoreAuthority::probe` is the gate deciding whether a third-party
//! object store may hold **canonical** repository state. §5.1: only successful
//! conditional replacement of the exact predecessor publishes. The probe's job
//! is to refuse a provider that cannot prove that, and its own comment on the
//! `ContentDerivedVersionToken` arm says so outright — *"an ETag-only provider
//! cannot prove no-ABA authority publication"*.
//!
//! Measured per variant with a both-trees grep (the crate has no suite-like
//! module in `src/`, so a `tests/` scan is sound here — checked, after
//! `fgit-authority`'s `src/suite.rs` made a covered variant look untested):
//!
//! ```text
//! MissingOrMalformedVersionToken   untested     3 sites
//! HistoricalVersionReadUnavailable untested     1 site
//! ReadAfterWriteViolation          untested     1 site
//! Configuration                    untested     the signer path
//! ConditionalWritesUnavailable     in-src only  named by no file under tests/
//! ContentDerivedVersionToken       covered      not claimed
//! Ambiguous                        covered      not claimed
//! ```
//!
//! # One fault at a time, and that is structural rather than asserted
//!
//! [`ProbeProvider`] is a conforming conditional store — the same ABA drill
//! `frankengit-0lyk` established — with a single [`Fault`] switch. Every
//! refusal below is the *same* store with exactly one behaviour changed, so a
//! refusal is attributable to that behaviour. A provider broken in two ways
//! would prove nothing about which guard fired, and writing each faulty store
//! from scratch would make "differs in one behaviour" a claim rather than a
//! fact about the code.
//!
//! [`a_conforming_provider_is_admitted`] is the control and comes first: a
//! probe that rejected every provider would satisfy every refusal here. It was
//! made to pass before any faulty variant was written.
//!
//! # Non-claims
//!
//! Newly covered: `MissingOrMalformedVersionToken`,
//! `HistoricalVersionReadUnavailable`, `ReadAfterWriteViolation`,
//! `Configuration`. Also covered here, and it was **in-src-only** rather than
//! newly discovered: `ConditionalWritesUnavailable`. Already covered elsewhere
//! and **not** claimed: `ContentDerivedVersionToken`, `Ambiguous`. That is five
//! of seven now named from `tests/`, of which four are new.
//!
//! `ProbeProvider` deliberately duplicates the conforming-store shape from
//! `tests/adapter_config_refusals.rs` rather than extending that file, whose
//! subject is `AdapterConfigError`. Two integration binaries cannot share a
//! fixture; the duplication is the accepted cost and is stated rather than
//! hidden.
//!
//! Nothing here modifies `crates/fgit-object-store/src/**`.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use asupersync::runtime::{Runtime, RuntimeBuilder};
use fgit_authority::VERSION_TOKEN_BYTES;
use fgit_object_store::{
    AdapterConfigError, CanonicalHmacSha256Signer, CapabilityProbeFailure, ObjectStoreAuthority,
    ObjectStoreEndpoint, ObjectStoreMethod, ObjectStoreRequest, ObjectStoreResponse,
    ObjectStoreTransport, ObjectStoreTransportError, ProbeRunId, RequestSigner,
    VersionTokenProfile,
};

const VERSION_HEADER: &str = "x-fgit-version-token";

/// The single behaviour that separates a faulty provider from the control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    /// Behaves correctly: the control.
    None,
    /// Never emits the version-token header.
    OmitVersionToken,
    /// Emits a token of the wrong width, so it cannot be decoded.
    TruncatedVersionToken,
    /// Serves different bytes than were written, on the read-after-write.
    StaleReadAfterWrite,
    /// Answers the historical exact-version read with a miss.
    NoHistoricalRead,
    /// Answers the very first conditional create with a non-success status.
    RefuseConditionalWrite,
}

/// A conforming conditional object store with exactly one optional fault.
#[derive(Clone, Debug)]
struct ProbeProvider {
    fault: Fault,
    state: Arc<Mutex<ProviderState>>,
}

#[derive(Debug, Default)]
struct ProviderState {
    live: BTreeMap<String, ([u8; VERSION_TOKEN_BYTES], Vec<u8>)>,
    history: BTreeMap<(String, [u8; VERSION_TOKEN_BYTES]), Vec<u8>>,
    writes: u64,
}

impl ProbeProvider {
    fn new(fault: Fault) -> Self {
        Self {
            fault,
            state: Arc::new(Mutex::new(ProviderState::default())),
        }
    }

    fn answer(&self, request: &ObjectStoreRequest) -> ObjectStoreResponse {
        let (path, query) = match request.url.split_once('?') {
            Some((path, query)) => (path.to_owned(), Some(query.to_owned())),
            None => (request.url.clone(), None),
        };
        let mut guard = self.state.lock().expect("provider state is not poisoned");
        let response = {
            let state = &mut *guard;
            match request.method {
                ObjectStoreMethod::Get => {
                    let historical = query
                        .as_deref()
                        .and_then(|query| query.strip_prefix("fgit-version-token="))
                        .and_then(decode_token);
                    historical.map_or_else(
                        || {
                            state.live.get(&path).map_or_else(
                                || bare(404),
                                |(token, body)| {
                                    // The read-after-write fault serves bytes the
                                    // caller never wrote, with an otherwise valid
                                    // token — so only the body comparison differs.
                                    let served = if self.fault == Fault::StaleReadAfterWrite {
                                        b"stale".to_vec()
                                    } else {
                                        body.clone()
                                    };
                                    self.versioned(200, *token, served)
                                },
                            )
                        },
                        |token| {
                            if self.fault == Fault::NoHistoricalRead {
                                return bare(404);
                            }
                            state.history.get(&(path.clone(), token)).map_or_else(
                                || bare(404),
                                |body| self.versioned(200, token, body.clone()),
                            )
                        },
                    )
                }
                ObjectStoreMethod::Put => {
                    let current = state.live.get(&path).map(|(token, _)| *token);
                    let permitted = match (
                        request.headers.get("if-none-match").map(String::as_str),
                        request.headers.get("if-match").map(String::as_str),
                    ) {
                        (Some("*"), _) => current.is_none(),
                        (_, Some(expected)) => {
                            current.is_some_and(|token| encode_token(token) == expected)
                        }
                        _ => false,
                    };
                    if !permitted {
                        return bare(412);
                    }
                    if self.fault == Fault::RefuseConditionalWrite {
                        return bare(500);
                    }
                    state.writes += 1;
                    let token = mint_token(state.writes);
                    state
                        .history
                        .insert((path.clone(), token), request.body.clone());
                    state.live.insert(path, (token, request.body.clone()));
                    self.versioned(200, token, Vec::new())
                }
            }
        };
        drop(guard);
        response
    }

    /// A response carrying the version-token header, unless the token faults
    /// suppress or corrupt it.
    fn versioned(
        &self,
        status: u16,
        token: [u8; VERSION_TOKEN_BYTES],
        body: Vec<u8>,
    ) -> ObjectStoreResponse {
        let header = match self.fault {
            Fault::OmitVersionToken => None,
            Fault::TruncatedVersionToken => Some(encode_token(token)[..8].to_owned()),
            _ => Some(encode_token(token)),
        };
        let headers: Vec<(String, String)> = header
            .map(|value| vec![(VERSION_HEADER.to_owned(), value)])
            .unwrap_or_default();
        ObjectStoreResponse::new(status, headers, body)
            .expect("the provider emits at most one well-formed header")
    }
}

impl ObjectStoreTransport for ProbeProvider {
    fn send(
        &self,
        _cx: &asupersync::Cx,
        request: ObjectStoreRequest,
    ) -> impl Future<Output = Result<ObjectStoreResponse, ObjectStoreTransportError>> + Send {
        let answer = self.answer(&request);
        async move { Ok(answer) }
    }
}

/// Counter-derived so no two writes share a token even for identical bodies;
/// the probe refuses a provider whose restore token repeats an earlier one.
fn mint_token(writes: u64) -> [u8; VERSION_TOKEN_BYTES] {
    let mut token = [0u8; VERSION_TOKEN_BYTES];
    token[..8].copy_from_slice(&writes.to_be_bytes());
    token
}

fn encode_token(token: [u8; VERSION_TOKEN_BYTES]) -> String {
    use std::fmt::Write as _;
    token.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn decode_token(value: &str) -> Option<[u8; VERSION_TOKEN_BYTES]> {
    if value.len() != VERSION_TOKEN_BYTES * 2 {
        return None;
    }
    let mut token = [0u8; VERSION_TOKEN_BYTES];
    let (pairs, rest) = value.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    for (slot, pair) in token.iter_mut().zip(pairs) {
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(token)
}

fn bare(status: u16) -> ObjectStoreResponse {
    ObjectStoreResponse::new(status, [], Vec::new()).expect("a header-free response is admissible")
}

/// A signer that refuses, so the probe's configuration arm can be reached.
///
/// The signer is the only component the probe treats as a *configuration*
/// fault rather than a provider fault, which is why this is a separate type
/// instead of another `Fault`.
#[derive(Debug)]
struct RefusingSigner;

impl RequestSigner for RefusingSigner {
    fn sign(&self, _request: &mut ObjectStoreRequest) -> Result<(), AdapterConfigError> {
        Err(AdapterConfigError::InvalidSigningCredential)
    }
}

fn runtime() -> (Runtime, asupersync::Cx) {
    let runtime = RuntimeBuilder::new().build().expect("runtime builds");
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    (runtime, cx)
}

fn endpoint() -> ObjectStoreEndpoint {
    ObjectStoreEndpoint::new("https://objects.example.test", "objects", "scratch")
        .expect("the probe endpoint is valid")
}

fn signer() -> CanonicalHmacSha256Signer {
    CanonicalHmacSha256Signer::new("probe-key", b"probe-secret".to_vec())
        .expect("the probe credential is well formed")
}

/// Runs the probe against a provider carrying `fault`.
fn probe(fault: Fault) -> Result<(), CapabilityProbeFailure> {
    let provider = ProbeProvider::new(fault);
    let (runtime, cx) = runtime();
    runtime
        .block_on(ObjectStoreAuthority::<
            ProbeProvider,
            CanonicalHmacSha256Signer,
        >::probe(
            &cx,
            &provider,
            &signer(),
            &endpoint(),
            ProbeRunId::new([11u8; VERSION_TOKEN_BYTES]),
            VersionTokenProfile::Unique,
        ))
        .map(|_| ())
}

/// The refusal from a provider that must be rejected.
fn refusal(fault: Fault, what: &str) -> CapabilityProbeFailure {
    match probe(fault) {
        Ok(()) => panic!("{what} must not be admitted as an authority backend"),
        Err(failure) => failure,
    }
}

// ---------------------------------------------------------------------------
// The control, first
// ---------------------------------------------------------------------------

/// A conforming provider is admitted and yields a receipt.
///
/// This comes first and had to pass before any faulty variant was written. A
/// probe that rejected every provider would satisfy every refusal below, so
/// without this control none of them is attributable.
#[test]
fn a_conforming_provider_is_admitted() {
    probe(Fault::None).expect("a provider satisfying the ABA drill is an admissible authority");
}

// ---------------------------------------------------------------------------
// MissingOrMalformedVersionToken — two axes
// ---------------------------------------------------------------------------

/// Axis 1: no version-token header at all.
///
/// Without a per-write token the store cannot name a specific version, so it
/// cannot prove a conditional replacement replaced the exact predecessor.
#[test]
fn a_provider_that_omits_the_version_token_is_refused() {
    let failure = refusal(
        Fault::OmitVersionToken,
        "a provider that names no version for a write",
    );
    assert_eq!(
        failure,
        CapabilityProbeFailure::MissingOrMalformedVersionToken
    );
}

/// Axis 2: a token of the wrong width.
///
/// Present but undecodable is a different fault from absent, and a probe
/// hitting only one leaves the other unexercised.
#[test]
fn a_provider_that_emits_a_malformed_version_token_is_refused() {
    let failure = refusal(
        Fault::TruncatedVersionToken,
        "a provider whose token cannot be decoded",
    );
    assert_eq!(
        failure,
        CapabilityProbeFailure::MissingOrMalformedVersionToken
    );
}

// ---------------------------------------------------------------------------
// ReadAfterWriteViolation
// ---------------------------------------------------------------------------

/// A store that does not serve what it just accepted cannot hold canonical
/// state: a reader could observe a superseded generation as current.
///
/// The faulty provider still emits a valid, unique token — only the body
/// differs — so this refusal is attributable to the read-after-write property
/// rather than to token handling.
#[test]
fn a_provider_that_serves_stale_bytes_after_a_write_is_refused() {
    let failure = refusal(
        Fault::StaleReadAfterWrite,
        "a provider without read-after-write consistency",
    );
    assert_eq!(failure, CapabilityProbeFailure::ReadAfterWriteViolation);
}

// ---------------------------------------------------------------------------
// HistoricalVersionReadUnavailable
// ---------------------------------------------------------------------------

/// Without an exact historical read, a superseded version cannot be produced on
/// demand — so an authority-head history cannot be audited after the fact.
#[test]
fn a_provider_without_an_exact_historical_read_is_refused() {
    let failure = refusal(
        Fault::NoHistoricalRead,
        "a provider that cannot serve a named earlier version",
    );
    assert_eq!(
        failure,
        CapabilityProbeFailure::HistoricalVersionReadUnavailable
    );
}

// ---------------------------------------------------------------------------
// ConditionalWritesUnavailable — named by no file under tests/ until now
// ---------------------------------------------------------------------------

/// A store that cannot complete a conditional create is refused at the first
/// step of the drill.
///
/// This variant was constructed in `src` and exercised only by the crate's
/// inline module; it is named from `tests/` here for the first time. Recording
/// that distinction rather than claiming it as newly discovered.
#[test]
fn a_provider_that_cannot_complete_a_conditional_write_is_refused() {
    let failure = refusal(
        Fault::RefuseConditionalWrite,
        "a provider that fails the conditional create",
    );
    assert_eq!(
        failure,
        CapabilityProbeFailure::ConditionalWritesUnavailable
    );
}

// ---------------------------------------------------------------------------
// Configuration — a signer fault, not a provider fault
// ---------------------------------------------------------------------------

/// A signer that refuses is a **configuration** failure, not a provider one.
///
/// The distinction is the point: the store may be perfectly conformant and the
/// probe still refuses, because the operator's credential cannot sign. The
/// provider here is the same conforming one the control uses, so the only
/// difference from [`a_conforming_provider_is_admitted`] is the signer.
#[test]
fn a_signer_that_refuses_is_a_configuration_failure() {
    let provider = ProbeProvider::new(Fault::None);
    let (runtime, cx) = runtime();
    let failure = runtime
        .block_on(
            ObjectStoreAuthority::<ProbeProvider, RefusingSigner>::probe(
                &cx,
                &provider,
                &RefusingSigner,
                &endpoint(),
                ProbeRunId::new([12u8; VERSION_TOKEN_BYTES]),
                VersionTokenProfile::Unique,
            ),
        )
        .expect_err("a credential that cannot sign cannot admit a backend");
    assert_eq!(
        failure,
        CapabilityProbeFailure::Configuration,
        "a signing failure is the operator's configuration, not the provider's behaviour"
    );
}

// ---------------------------------------------------------------------------
// Ordering — a provider wrong twice
// ---------------------------------------------------------------------------

/// The conditional create is attempted before the token is read, so a provider
/// that both fails the write and omits the token reports the write.
///
/// The single-fault probes cannot see this: each satisfies the earlier stage by
/// construction and so always reaches its own. (A *deleted* stage is a
/// different mutation class, which only the single-fault probe for that stage
/// detects — the two do not substitute for each other.)
#[test]
fn a_failed_conditional_write_outranks_a_missing_token() {
    let provider = ProbeProvider {
        fault: Fault::RefuseConditionalWrite,
        state: Arc::new(Mutex::new(ProviderState::default())),
    };
    // The write fault short-circuits before any token is emitted, so this
    // provider is wrong in both respects at once.
    let (runtime, cx) = runtime();
    let failure = runtime
        .block_on(ObjectStoreAuthority::<
            ProbeProvider,
            CanonicalHmacSha256Signer,
        >::probe(
            &cx,
            &provider,
            &signer(),
            &endpoint(),
            ProbeRunId::new([13u8; VERSION_TOKEN_BYTES]),
            VersionTokenProfile::Unique,
        ))
        .expect_err("a provider failing the create cannot be admitted");
    assert_eq!(
        failure,
        CapabilityProbeFailure::ConditionalWritesUnavailable,
        "the write status is checked before the response token is read"
    );
}
