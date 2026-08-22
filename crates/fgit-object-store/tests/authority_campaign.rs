//! FG-006b: fault-injection campaign against the object-store authority adapter.
//!
//! WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT.
//!
//! The provider below is an INDEPENDENT conditional object store. It speaks the
//! wire protocol in its own vocabulary — the header names are written out here
//! rather than imported — because a provider that shared constants with the
//! client it serves would be a mirror of the adapter rather than a counterparty
//! to it. A differential instrument must not import the implementation it
//! checks, and the adapter's own `canonical_request` is documented as "exposed
//! for independent provider tests", which is the seam this uses.
//!
//! THE HAZARD THAT CREATES, AND WHY THE FIRST TEST IS A POSITIVE CONTROL. If the
//! adapter ever renames a header, this provider stops conforming and answers
//! `400`/`412` to everything. A campaign whose assertions are mostly "this is
//! refused" would then keep passing while testing a protocol the adapter no
//! longer speaks — green, and measuring nothing. So the happy path is asserted
//! FIRST: a conditional write followed by an exact-key read must SUCCEED. When
//! the vocabulary drifts, that control fails loudly instead of the refusals
//! quietly succeeding.
//!
//! NON-CLAIM, carried deliberately: **no live server is exercised.**
//! `AsupersyncHttpTransport::new` returns `Err(TlsTransportNotAdmitted)`
//! unconditionally, because the closed dependency set has not admitted
//! Asupersync's Rustls closure. That refusal is intentional and is not softened
//! here. Everything below runs the adapter's real signing, conditional-write,
//! ambiguity-classification and admission logic against an in-process
//! counterparty; only the wire is substituted, which is where faults must be
//! injected in any case. This evidence does not establish anything about a
//! network transport, and the acceptance line naming a local test server is not
//! satisfied by it.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use asupersync::runtime::{Runtime, RuntimeBuilder};
use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthorityLimits, CasOutcome, HeadGeneration, HeadInit,
    HeadKey, HeadRead, ImmutableKey, ImmutableRead, StoreInstanceId,
};
use fgit_object_store::{
    CanonicalHmacSha256Signer, ObjectStoreAuthority, ObjectStoreEndpoint, ObjectStoreMethod,
    ObjectStoreRequest, ObjectStoreResponse, ObjectStoreTransport, ObjectStoreTransportError,
    ProbeRunId, VersionTokenProfile,
};

/// The adapter takes its transport by value, so the campaign holds the provider
/// behind an `Arc` and implements the transport trait for that handle. Without
/// this the fault schedule would be unreachable once the adapter owned it, and
/// the campaign could arm nothing.
#[derive(Clone, Debug, Default)]
struct ProviderHandle(Arc<FaultyProvider>);

impl ObjectStoreTransport for ProviderHandle {
    fn send(
        &self,
        cx: &asupersync::Cx,
        request: ObjectStoreRequest,
    ) -> impl Future<Output = Result<ObjectStoreResponse, ObjectStoreTransportError>> + Send {
        self.0.send(cx, request)
    }
}

/// Wire vocabulary, stated independently of the adapter's private constants.
///
/// If these drift from the adapter, `the_happy_path_control_still_works` fails.
/// That is the whole reason it exists.
const HDR_VERSION: &str = "x-fgit-version-token";
const HDR_GENERATION: &str = "x-fgit-head-generation";
const HDR_IF_MATCH: &str = "if-match";
const HDR_IF_NONE_MATCH: &str = "if-none-match";
const TOKEN_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// the fault schedule
// ---------------------------------------------------------------------------

/// One injected fault, applied to the next matching request.
///
/// Each corresponds to a fault the bead names. `Drop` and `Reject` are the
/// authority-critical pair: a dropped mutation MAY have applied and must be
/// reported ambiguous, while a rejected one provably did not reach an effect.
/// An adapter that collapsed them would be safe in one direction and wrong in
/// the other, which is why they are always asserted together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Connection dropped mid-request: the effect may or may not have landed.
    DropMidRequest,
    /// Refused before any effect could occur.
    RejectBeforeEffect,
    /// Deliver the request twice; the second delivery is the duplicate.
    DuplicateDelivery,
    /// Serve a superseded version for the next read, as a stale proxy would.
    StaleProxyRead,
}

#[derive(Debug)]
struct StoredVersion {
    token: [u8; TOKEN_BYTES],
    body: Vec<u8>,
    generation: Option<String>,
}

#[derive(Default, Debug)]
struct ProviderState {
    next_token: u64,
    objects: BTreeMap<String, Vec<StoredVersion>>,
    requests: Vec<ObjectStoreRequest>,
    faults: Vec<Fault>,
    duplicates_delivered: usize,
}

/// An independent conditional object store with an injectable fault schedule.
#[derive(Default, Debug)]
struct FaultyProvider {
    state: Mutex<ProviderState>,
}

impl FaultyProvider {
    fn arm(&self, faults: impl IntoIterator<Item = Fault>) {
        let mut state = self.lock();
        state.faults = faults.into_iter().collect();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ProviderState> {
        self.state.lock().expect("provider state lock")
    }

    fn requests(&self) -> Vec<ObjectStoreRequest> {
        self.lock().requests.clone()
    }

    /// Mutation requests only — the ones an adapter must never replay.
    fn mutations(&self) -> Vec<ObjectStoreRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.method == ObjectStoreMethod::Put)
            .collect()
    }

    fn duplicates_delivered(&self) -> usize {
        self.lock().duplicates_delivered
    }

    /// How many versions the store actually holds for a key suffix.
    ///
    /// This is what separates "the call returned an error" from "no effect
    /// occurred". A lost acknowledgement leaves a version behind; a rejection
    /// does not, and an adapter that reported them identically would be wrong
    /// about the only fact a caller needs.
    fn versions_for(&self, suffix: &str) -> usize {
        // The adapter PERCENT-ENCODES the key into the path, so an immutable
        // key `campaign/clean` is stored at `.../immutable/campaign%2Fclean`.
        // Matching the raw suffix silently found nothing and made the clean
        // path look like it had written zero versions -- which the permitted
        // twin caught immediately, and which a suite of refusal-only assertions
        // would not have.
        self.lock()
            .objects
            .iter()
            .filter(|(url, _)| url.replace("%2F", "/").ends_with(suffix))
            .map(|(_, versions)| versions.len())
            .sum()
    }

    /// Versions written under the probe's own scratch prefix.
    ///
    /// The admission probe leaves its ABA evidence in the store: it writes a
    /// body, deletes-and-restores identical bytes, and checks whether the
    /// provider reissued the earlier token. Those versions are observable, so
    /// "the drill ran" is a measurement rather than an inference.
    fn probe_scratch_versions(&self) -> usize {
        self.lock()
            .objects
            .iter()
            .filter(|(url, _)| url.contains("/scratch/"))
            .map(|(_, versions)| versions.len())
            .sum()
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unhex(value: &str) -> Option<[u8; TOKEN_BYTES]> {
    if value.len() != TOKEN_BYTES * 2 {
        return None;
    }
    let mut out = [0_u8; TOKEN_BYTES];
    for (index, slot) in out.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(value.get(start..start + 2)?, 16).ok()?;
    }
    Some(out)
}

fn version_response(status: u16, version: &StoredVersion) -> ObjectStoreResponse {
    let mut headers = vec![(HDR_VERSION.to_owned(), hex(&version.token))];
    if let Some(generation) = version.generation.clone() {
        headers.push((HDR_GENERATION.to_owned(), generation));
    }
    ObjectStoreResponse::new(status, headers, version.body.clone())
        .expect("provider response is well formed")
}

fn plain(status: u16) -> ObjectStoreResponse {
    ObjectStoreResponse::new(status, [], Vec::new()).expect("provider response is well formed")
}

impl ProviderState {
    /// Apply one request to the store, returning the provider's answer.
    fn apply(&mut self, request: &ObjectStoreRequest) -> ObjectStoreResponse {
        let (url, historical) = match request.url.split_once("?fgit-version-token=") {
            Some((url, token)) => match unhex(token) {
                Some(token) => (url.to_owned(), Some(token)),
                None => return plain(400),
            },
            None => (request.url.clone(), None),
        };

        match request.method {
            ObjectStoreMethod::Get => {
                let stale = self.take_fault(Fault::StaleProxyRead);
                let Some(versions) = self.objects.get(&url) else {
                    return plain(404);
                };
                let chosen = historical.map_or_else(
                    || {
                        if stale && versions.len() >= 2 {
                            // A stale proxy serves a superseded version, not garbage.
                            versions.get(versions.len() - 2)
                        } else {
                            versions.last()
                        }
                    },
                    |token| versions.iter().find(|version| version.token == token),
                );
                chosen.map_or_else(|| plain(404), |version| version_response(200, version))
            }
            ObjectStoreMethod::Put => {
                let if_none = request
                    .headers
                    .get(HDR_IF_NONE_MATCH)
                    .is_some_and(|value| value == "*");
                let if_match = request
                    .headers
                    .get(HDR_IF_MATCH)
                    .and_then(|value| unhex(value));
                let current = self
                    .objects
                    .get(&url)
                    .and_then(|versions| versions.last())
                    .map(|version| version.token);
                let occupied = current.is_some();

                if if_none && occupied {
                    return plain(412);
                }
                if !if_none && if_match.is_none() {
                    // Neither an if-none-match create nor a conditional replace:
                    // an unconditional write is exactly what must never be
                    // accepted, because it cannot be a linearization point.
                    return plain(400);
                }
                if !if_none && current != if_match {
                    return plain(412);
                }

                self.next_token = self.next_token.checked_add(1).expect("token capacity");
                let mut token = [0_u8; TOKEN_BYTES];
                token[8..].copy_from_slice(&self.next_token.to_be_bytes());
                let versions = self.objects.entry(url).or_default();
                versions.push(StoredVersion {
                    token,
                    body: request.body.clone(),
                    generation: request.headers.get(HDR_GENERATION).cloned(),
                });
                version_response(201, versions.last().expect("just pushed"))
            }
        }
    }

    fn take_fault(&mut self, wanted: Fault) -> bool {
        if let Some(index) = self.faults.iter().position(|fault| *fault == wanted) {
            self.faults.remove(index);
            true
        } else {
            false
        }
    }
}

impl ObjectStoreTransport for FaultyProvider {
    fn send(
        &self,
        _cx: &asupersync::Cx,
        request: ObjectStoreRequest,
    ) -> impl Future<Output = Result<ObjectStoreResponse, ObjectStoreTransportError>> + Send {
        let mut state = self.lock();
        state.requests.push(request.clone());

        if state.take_fault(Fault::RejectBeforeEffect) {
            // Provably no effect: the request never reached the store.
            drop(state);
            return std::future::ready(Err(ObjectStoreTransportError::Rejected));
        }

        if state.take_fault(Fault::DropMidRequest) {
            // The effect DOES land; only the answer is lost. That is what makes
            // this ambiguous rather than a refusal, and it is why the adapter
            // must not replay: replaying would apply it twice.
            let _ = state.apply(&request);
            drop(state);
            return std::future::ready(Err(ObjectStoreTransportError::Ambiguous(
                AmbiguityReason::NoResponse,
            )));
        }

        if state.take_fault(Fault::DuplicateDelivery) {
            // A duplicated delivery of a CONDITIONAL write is answered by the
            // store's own condition, not by the adapter: the second apply sees
            // the token it already advanced and refuses.
            let _ = state.apply(&request);
            state.duplicates_delivered += 1;
        }

        let response = state.apply(&request);
        drop(state);
        std::future::ready(Ok(response))
    }
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn endpoint() -> ObjectStoreEndpoint {
    ObjectStoreEndpoint::new(
        "https://objects.example",
        "bucket/fgit",
        "scratch/authority",
    )
    .expect("valid endpoint")
}

fn signer() -> CanonicalHmacSha256Signer {
    CanonicalHmacSha256Signer::new("campaign-key", b"campaign-secret".to_vec())
        .expect("valid signer")
}

fn runtime() -> (Runtime, asupersync::Cx) {
    let runtime = RuntimeBuilder::new().build().expect("runtime builds");
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    (runtime, cx)
}

fn block<T: Future>(runtime: &Runtime, future: T) -> T::Output {
    runtime.block_on(future)
}

/// Admit a provider and return the bound adapter.
///
/// Admission is not a formality here: the receipt has private fields and can
/// only come from a successful probe, so every adapter below has necessarily
/// passed the ABA drill against this provider.
fn admit(
    seed: u8,
) -> (
    Runtime,
    asupersync::Cx,
    ObjectStoreAuthority<ProviderHandle, CanonicalHmacSha256Signer>,
    ProviderHandle,
) {
    let provider = ProviderHandle::default();
    let (runtime, cx) = runtime();
    let receipt = block(
        &runtime,
        ObjectStoreAuthority::<ProviderHandle, CanonicalHmacSha256Signer>::probe(
            &cx,
            &provider,
            &signer(),
            &endpoint(),
            ProbeRunId::new([seed; TOKEN_BYTES]),
            VersionTokenProfile::Unique,
        ),
    )
    .expect("an independent unique-token provider satisfies the authority probe");

    let adapter = ObjectStoreAuthority::new(
        provider.clone(),
        signer(),
        endpoint(),
        receipt,
        StoreInstanceId::from_raw(6006),
        AuthorityLimits::default(),
    )
    .expect("the capability receipt binds this endpoint");
    (runtime, cx, adapter, provider)
}

// ---------------------------------------------------------------------------
// POSITIVE CONTROL — must come first
// ---------------------------------------------------------------------------

/// A clean conditional write and exact-key read succeed end to end.
///
/// This is the control that keeps every refusal assertion in this file honest.
/// The provider states the wire vocabulary independently; if the adapter renames
/// a header, this provider answers 400/412 to everything and every "is refused"
/// assertion below would still pass. This test is what fails instead.
#[test]
fn the_happy_path_control_still_works() {
    let (runtime, cx, adapter, _provider) = admit(1);
    let key = ImmutableKey::new(b"campaign/control".to_vec()).expect("key");

    block(
        &runtime,
        adapter.put_if_absent(&cx, &key, b"control body\n"),
    )
    .expect("a clean conditional create succeeds against a conforming provider");

    let read = block(&runtime, adapter.read_immutable(&cx, &key))
        .expect("the just-written body reads back by exact key");
    assert_eq!(
        read,
        ImmutableRead::Present(b"control body\n".to_vec()),
        "the provider must return the bytes the adapter wrote; a mismatch here means the wire \
         vocabulary has drifted and every refusal assertion in this file is now vacuous"
    );
}

// ---------------------------------------------------------------------------
// lost acknowledgement: ambiguous is not failed, and is never replayed
// ---------------------------------------------------------------------------

/// A dropped mutation response is ambiguous, and the adapter does not replay it.
///
/// The provider APPLIES the write before losing the answer, so a replay would
/// apply it twice. The adapter issuing exactly one mutation is therefore not a
/// stylistic preference; it is what keeps the effect count correct.
#[test]
fn a_lost_acknowledgement_is_never_replayed_and_the_effect_survives() {
    let (runtime, cx, adapter, provider) = admit(2);
    let key = ImmutableKey::new(b"campaign/lost-ack".to_vec()).expect("key");
    provider.0.arm([Fault::DropMidRequest]);

    let before = provider.0.mutations().len();
    let outcome = block(
        &runtime,
        adapter.put_if_absent(&cx, &key, b"lost ack body\n"),
    );
    let after = provider.0.mutations().len();

    assert!(
        outcome.is_err(),
        "a lost acknowledgement must not be reported as a completed write"
    );
    assert_eq!(
        after - before,
        1,
        "the adapter must issue exactly one mutation; replaying a write whose effect may have \
         landed would apply it twice"
    );
    assert_eq!(
        provider.0.versions_for("campaign/lost-ack"),
        1,
        "the effect DID land — that is what makes the no-replay rule load-bearing rather than \
         tidy. If this were 0 the test would be asserting no-retry against a write that never \
         happened, which proves nothing."
    );
}

/// A rejection is distinguishable from a lost acknowledgement, and leaves no effect.
///
/// This is the pairing that makes the test above mean something. `is_err()` on
/// its own is satisfied by an adapter that fails every write; what must hold is
/// that the two failures differ in the fact a caller acts on — whether an effect
/// may exist. Rejected: provably none. Dropped: possibly one, and here exactly
/// one.
#[test]
fn a_rejection_is_not_confused_with_a_lost_acknowledgement() {
    let (runtime, cx, adapter, provider) = admit(3);
    let key = ImmutableKey::new(b"campaign/rejected".to_vec()).expect("key");
    provider.0.arm([Fault::RejectBeforeEffect]);

    let before = provider.0.mutations().len();
    let outcome = block(
        &runtime,
        adapter.put_if_absent(&cx, &key, b"rejected body\n"),
    );
    let after = provider.0.mutations().len();

    assert!(outcome.is_err(), "a rejected write did not complete");
    assert_eq!(
        after - before,
        1,
        "a rejection is not a licence to retry either: the adapter issues one mutation and \
         reports, rather than replaying against a store whose state it has not re-read"
    );
    assert_eq!(
        provider.0.versions_for("campaign/rejected"),
        0,
        "a rejection provably left no effect; if this were nonzero the provider's own fault \
         injection would be lying and every conclusion here would be unsound"
    );
}

/// The permitted twin for both failure tests: with no fault armed, the same
/// call succeeds and lands exactly one version.
///
/// Without this, both tests above are satisfied by an adapter that refuses
/// unconditionally — the same vacuity the whole campaign exists to avoid.
#[test]
fn with_no_fault_armed_the_same_write_succeeds() {
    let (runtime, cx, adapter, provider) = admit(4);
    let key = ImmutableKey::new(b"campaign/clean".to_vec()).expect("key");

    block(&runtime, adapter.put_if_absent(&cx, &key, b"clean body\n"))
        .expect("with no fault armed the identical call completes");
    assert_eq!(
        provider.0.versions_for("campaign/clean"),
        1,
        "exactly one version lands on the clean path"
    );
}

// ---------------------------------------------------------------------------
// the ABA drill, observed rather than assumed
// ---------------------------------------------------------------------------

/// Admission really exercises the ABA drill against this provider.
///
/// The receipt's private fields mean an adapter can only exist if the probe
/// succeeded, so every test above has already passed the drill. But "the probe
/// succeeded" is a claim about a return value; this asserts the drill left its
/// evidence in the store — the probe writes to a scratch key, restores byte
/// identical content, and checks whether the provider reissued the earlier
/// token. A provider that reissued it is refused as content-derived.
///
/// Measured, not inferred: the probe leaves multiple versions under its own
/// scratch prefix, which is what a delete-and-identical-restore sequence looks
/// like from the store's side.
#[test]
fn admission_exercises_the_aba_drill_and_leaves_its_evidence() {
    let (_runtime, _cx, _adapter, provider) = admit(5);
    assert!(
        provider.0.probe_scratch_versions() >= 2,
        "the ABA drill must write and then restore under its scratch prefix; fewer than two \
         versions means admission passed without exercising the delete-and-restore case, and the \
         no-ABA guarantee would be unproven for every adapter this file builds"
    );
}

/// A duplicated delivery cannot produce two effects.
///
/// The store's own condition is what stops it: the second delivery of an
/// `if-none-match: *` create finds the slot occupied and answers `412`. This is
/// a property of the conditional protocol, not of the adapter — which is
/// exactly why it belongs in a provider-side fault test.
///
/// NOTE ON WHAT THE CLIENT SEES, stated as an observation rather than a claim:
/// with the duplicate applied first, the answer the adapter receives is the
/// `412` from the *second* delivery, so a write that genuinely succeeded looks
/// like a conflict. That is not a defect in the adapter — it cannot distinguish
/// them from one response — and it is precisely the case the adapter's
/// documented rule covers: resolve by exact-key read, never by assuming. The
/// assertion below is on the effect count, which is the fact that must hold
/// regardless of what the client concluded.
#[test]
fn a_duplicated_delivery_still_lands_exactly_one_effect() {
    let (runtime, cx, adapter, provider) = admit(6);
    let key = ImmutableKey::new(b"campaign/duplicate".to_vec()).expect("key");
    provider.0.arm([Fault::DuplicateDelivery]);

    let _outcome = block(
        &runtime,
        adapter.put_if_absent(&cx, &key, b"duplicate body\n"),
    );

    assert_eq!(
        provider.0.duplicates_delivered(),
        1,
        "the fault must actually have fired; if it did not, this test asserts nothing about \
         duplication"
    );
    assert_eq!(
        provider.0.versions_for("campaign/duplicate"),
        1,
        "a duplicated conditional create lands exactly one version — the second delivery is \
         refused by the store's own condition, which is what makes at-least-once delivery safe \
         for a conditional write and unsafe for an unconditional one"
    );
}

// ---------------------------------------------------------------------------
// stale-proxy read
// ---------------------------------------------------------------------------

/// A stale proxy serving a superseded head is DETECTABLE, not silently absorbed.
///
/// This is the fault with the worst failure mode in the list: a dropped or
/// rejected request announces itself, but a stale read looks exactly like a
/// successful read of older truth. Nothing in a single response says "this is
/// behind". What must hold is that the adapter reports what it actually
/// observed — token and generation — rather than normalising the answer, so a
/// caller that just committed generation 2 can tell it is being served
/// generation 1.
///
/// Written by observing first: the assertion pins what the adapter genuinely
/// does, rather than what I assumed it should.
#[test]
fn a_stale_proxy_read_is_visible_in_the_receipt() {
    let (runtime, cx, adapter, provider) = admit(7);
    let head = HeadKey::new(b"repo/head".to_vec()).expect("head key");

    let init = block(
        &runtime,
        adapter.initialize_head(&cx, &head, HeadGeneration::FIRST, b"head-v1"),
    )
    .expect("head initialises");
    let first = match init {
        HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt) => receipt,
        HeadInit::Conflict => panic!("a fresh head slot must not conflict"),
    };

    let second_generation = HeadGeneration::try_new(2).expect("generation 2");
    let committed = block(
        &runtime,
        adapter.compare_exchange_head(&cx, &head, first.token(), second_generation, b"head-v2"),
    )
    .expect("the exchange completes");
    let CasOutcome::Committed(committed_receipt) = committed else {
        panic!("the CAS against the current token must commit; got {committed:?}");
    };

    // Now the proxy serves the superseded version.
    provider.0.arm([Fault::StaleProxyRead]);
    let stale = block(&runtime, adapter.read_head(&cx, &head)).expect("the stale read returns");
    let HeadRead::Present(receipt) = stale else {
        panic!("a head that exists must not read as absent under a stale proxy");
    };

    assert_eq!(
        receipt.generation(),
        HeadGeneration::FIRST,
        "the stale read must surface the generation it actually observed; normalising it to the \
         latest would make a lagging proxy indistinguishable from a current one"
    );
    assert_eq!(
        receipt.body(),
        b"head-v1",
        "the observed bytes and the observed generation must agree — a receipt pairing new bytes \
         with an old generation, or the reverse, would let a caller mis-order history"
    );
    // Sanity, against the POST-CAS token rather than the pre-CAS one. My first
    // version compared with `first.token()` and failed: a stale read serves
    // exactly version 1, so of course it carries version 1's token. The
    // meaningful statement is that it is NOT the committed token — that is what
    // makes the read stale rather than current.
    assert_ne!(
        receipt.token(),
        committed_receipt.token(),
        "the staleness must be real: a stale read carries the superseded token, never the \
         committed one. If these were equal the fault would not have fired and every assertion \
         above would be describing an ordinary current read."
    );
    assert_eq!(
        receipt.token(),
        first.token(),
        "and it carries precisely the superseded version's token, so a caller can identify WHICH \
         version it was served rather than only that something was wrong"
    );
}

/// The permitted twin: with no stale fault, the same read observes the commit.
///
/// Without this, the test above is satisfied by an adapter whose reads always
/// lag — the failure mode it exists to detect.
#[test]
fn without_the_stale_fault_the_same_read_observes_the_commit() {
    let (runtime, cx, adapter, _provider) = admit(8);
    let head = HeadKey::new(b"repo/head".to_vec()).expect("head key");

    let init = block(
        &runtime,
        adapter.initialize_head(&cx, &head, HeadGeneration::FIRST, b"head-v1"),
    )
    .expect("head initialises");
    let first = match init {
        HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt) => receipt,
        HeadInit::Conflict => panic!("a fresh head slot must not conflict"),
    };
    block(
        &runtime,
        adapter.compare_exchange_head(
            &cx,
            &head,
            first.token(),
            HeadGeneration::try_new(2).expect("generation 2"),
            b"head-v2",
        ),
    )
    .expect("the exchange completes");

    let HeadRead::Present(receipt) =
        block(&runtime, adapter.read_head(&cx, &head)).expect("the read returns")
    else {
        panic!("a committed head must read as present");
    };
    assert_eq!(
        receipt.generation(),
        HeadGeneration::try_new(2).expect("generation 2"),
        "a clean read observes the committed generation"
    );
    assert_eq!(receipt.body(), b"head-v2");
}
