#![forbid(unsafe_code)]
//! Every refusal the object-store adapter configuration can produce
//! (`frankengit-0lyk`).
//!
//! Measured at this tree before the file was written: `AdapterConfigError` has
//! **seven constructed variants, and neither the crate's own `mod tests` nor
//! any integration test in the workspace mentions the type or any variant of
//! it**. The subject matter is not bookkeeping — the variants' own
//! documentation names the stakes:
//!
//! - `InvalidHeaderValue` — *"a header value could **split** or exceed the
//!   bounded HTTP field"*. The guard rejects CR and LF: this is header
//!   injection.
//! - `DuplicateHeader` — *"two case-insensitive headers would make
//!   conditional/**signing** semantics ambiguous"*.
//! - `InvalidPathComponent` — the guard rejects `..` segments: path traversal
//!   out of the configured namespace.
//! - `ReceiptEndpointMismatch` — *"the adapter was constructed with a receipt
//!   for another endpoint scope"*. This is the capability-confusion guard: a
//!   probe passed against one provider must not authorize an adapter pointed
//!   somewhere else.
//!
//! # Four properties that force the probes into a particular shape
//!
//! **The duplicate rule is case-insensitive by construction.** Names are
//! lowercased *before* the duplicate check, so
//! [`two_headers_differing_only_in_case_collide`] uses `X-Trace` and `x-trace`.
//! A probe using two *identical* names would still pass against an
//! implementation that had lost the normalization, so it would not test the
//! property the documentation claims.
//!
//! **The bounds are `>`, not `>=`.** A 256-byte header name, a 256-byte key id
//! and a 512-byte path component are all *admissible*, and those permitted
//! cases are exactly what a refusal-only corpus cannot see: tightening any of
//! those bounds by one byte would leave every refusal probe here green.
//!
//! **`validate_path_component` is called twice** — once for the namespace and
//! once for the scratch prefix. Both call sites are probed, because a refusal
//! reached only through the namespace says nothing about the second call. The
//! scratch prefix is not decorative: it appears in `probe_url`, so an
//! unvalidated one would steer the capability probe's own key space.
//!
//! **A receipt cannot be fabricated.** `AuthorityCapabilityReceipt` has private
//! fields and no public constructor, so the only way to reach the mismatch
//! guard is to earn a real one. `ConformingProvider` below is a minimal honest
//! conditional store that satisfies the ABA drill; the receipts those tests
//! hold came out of the adapter's real probe.
//!
//! # Non-claims
//!
//! No live network transport is exercised — `AsupersyncHttpTransport::new`
//! refuses unconditionally under the closed dependency set, and this file does
//! not soften that. The provider here is an in-process counterparty used only
//! to mint a genuine receipt.
//!
//! `ObjectStoreRequest::insert_header` applies the same value and duplicate
//! rules as `ObjectStoreResponse::new`, but it is private and the crate feeds
//! it only crate-owned protocol constants. The refusals below therefore reach
//! the response-side call site. That is a stated limit, not a claim that both
//! sites are covered.
//!
//! Nothing here modifies `crates/fgit-object-store/src/**`.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use asupersync::runtime::{Runtime, RuntimeBuilder};
use fgit_authority::{AuthorityLimits, StoreInstanceId, VERSION_TOKEN_BYTES};
use fgit_object_store::{
    AdapterConfigError, AuthorityCapabilityReceipt, CanonicalHmacSha256Signer,
    ObjectStoreAuthority, ObjectStoreEndpoint, ObjectStoreMethod, ObjectStoreRequest,
    ObjectStoreResponse, ObjectStoreTransport, ObjectStoreTransportError, ProbeRunId,
    VersionTokenProfile,
};

/// Mirrors the crate-private header-value bound (`MAX_HEADER_BYTES`).
///
/// Mirrored rather than imported because it is private. If the crate's bound
/// moves, the boundary twins below fail loudly instead of silently testing a
/// number that is no longer the boundary.
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Mirrors the crate-private header-name bound.
const MAX_HEADER_NAME_BYTES: usize = 256;

/// Mirrors the crate-private path-component bound.
const MAX_PATH_COMPONENT_BYTES: usize = 512;

/// Mirrors the crate-private signing key-id bound.
const MAX_KEY_ID_BYTES: usize = 256;

const ORIGIN: &str = "https://objects.example.test";

const VERSION_HEADER: &str = "x-fgit-version-token";

fn endpoint(
    origin: &str,
    namespace: &str,
    scratch: &str,
) -> Result<ObjectStoreEndpoint, AdapterConfigError> {
    ObjectStoreEndpoint::new(origin, namespace, scratch)
}

/// Differs from the canonical endpoint only in its namespace.
fn with_namespace(namespace: &str) -> Result<ObjectStoreEndpoint, AdapterConfigError> {
    endpoint(ORIGIN, namespace, "scratch")
}

/// Differs from the canonical endpoint only in its scratch prefix.
fn with_scratch(scratch: &str) -> Result<ObjectStoreEndpoint, AdapterConfigError> {
    endpoint(ORIGIN, "objects", scratch)
}

fn response(headers: &[(&str, &str)]) -> Result<ObjectStoreResponse, AdapterConfigError> {
    ObjectStoreResponse::new(
        200,
        headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        Vec::new(),
    )
}

/// Every probe's baseline is admissible.
///
/// Without this, any refusal below could be some unrelated field of the fixture
/// failing rather than the field the test is named for.
#[test]
fn the_canonical_endpoint_response_and_signer_are_admitted() {
    endpoint(ORIGIN, "objects", "scratch").expect("the canonical endpoint must be constructible");
    response(&[("x-trace", "abc")]).expect("a single well-formed header must be admissible");
    CanonicalHmacSha256Signer::new("probe-key", b"probe-secret".to_vec())
        .expect("a well-formed signing credential must be admissible");
}

// ---------------------------------------------------------------------------
// InvalidEndpoint — four axes
// ---------------------------------------------------------------------------

#[test]
fn a_non_https_origin_is_refused() {
    let refusal = endpoint("http://objects.example.test", "objects", "scratch")
        .expect_err("a plaintext origin must not configure a production adapter");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidEndpoint),
        "a non-HTTPS origin must refuse as an invalid endpoint, got {refusal:?}"
    );
}

/// The scheme alone is not an origin.
///
/// This is the axis the length condition exists for: `"https://"` satisfies the
/// prefix test and would pass a guard that checked only the prefix.
#[test]
fn a_bare_scheme_with_no_host_is_refused() {
    let refusal = endpoint("https://", "objects", "scratch")
        .expect_err("a scheme with no host identifies nothing");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidEndpoint),
        "a bare scheme must refuse as an invalid endpoint, got {refusal:?}"
    );
}

/// Every character the ambiguity condition rejects, checked individually.
///
/// One condition covers four characters, so a probe using only one leaves three
/// unexercised. `?` and `#` would make the joined URL ambiguous; CR and LF are
/// request splitting.
#[test]
fn each_ambiguous_or_splitting_character_in_the_origin_is_refused() {
    for suffix in ['?', '#', '\r', '\n'] {
        let origin = format!("{ORIGIN}{suffix}");
        let refusal = endpoint(&origin, "objects", "scratch")
            .expect_err(&format!("an origin containing {suffix:?} must be refused"));
        assert!(
            matches!(refusal, AdapterConfigError::InvalidEndpoint),
            "an origin containing {suffix:?} must refuse as an invalid endpoint, got {refusal:?}"
        );
    }
}

#[test]
fn a_trailing_slash_on_the_origin_is_refused() {
    let refusal = endpoint("https://objects.example.test/", "objects", "scratch")
        .expect_err("a trailing slash makes the joined path ambiguous");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidEndpoint),
        "a trailing slash must refuse as an invalid endpoint, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// InvalidPathComponent — six axes, two call sites, one boundary
// ---------------------------------------------------------------------------

/// **The traversal axis.** A namespace containing a `..` segment is refused.
///
/// This is the one whose absence would be a defect rather than a coverage gap:
/// a `..` segment escapes the configured namespace, and every URL the adapter
/// builds is `{origin}/{namespace}/...`.
#[test]
fn a_namespace_containing_a_parent_segment_is_refused() {
    let refusal = with_namespace("objects/../secrets")
        .expect_err("a parent segment escapes the configured namespace");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidPathComponent),
        "a .. segment must refuse as an invalid path component, got {refusal:?}"
    );
}

/// The sibling of the traversal axis: a bare `.` segment is refused too, since
/// it lets two spellings name one location.
#[test]
fn a_namespace_containing_a_current_segment_is_refused() {
    let refusal =
        with_namespace("objects/./here").expect_err("a . segment makes the path non-canonical");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidPathComponent),
        "a . segment must refuse as an invalid path component, got {refusal:?}"
    );
}

#[test]
fn an_empty_namespace_is_refused() {
    let refusal = with_namespace("").expect_err("an empty namespace names nothing");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidPathComponent),
        "got {refusal:?}"
    );
}

#[test]
fn an_empty_segment_inside_the_namespace_is_refused() {
    let refusal =
        with_namespace("objects//here").expect_err("a doubled separator makes an empty segment");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidPathComponent),
        "got {refusal:?}"
    );
}

#[test]
fn a_leading_or_trailing_separator_on_the_namespace_is_refused() {
    for namespace in ["/objects", "objects/"] {
        let refusal = with_namespace(namespace)
            .expect_err(&format!("namespace {namespace:?} must be refused"));
        assert!(
            matches!(refusal, AdapterConfigError::InvalidPathComponent),
            "namespace {namespace:?} must refuse as an invalid path component, got {refusal:?}"
        );
    }
}

#[test]
fn a_byte_outside_the_permitted_path_set_is_refused() {
    let refusal =
        with_namespace("obj ects").expect_err("a space is not in the permitted path byte set");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidPathComponent),
        "got {refusal:?}"
    );
}

/// The **second call site**: the same rule applied to the scratch prefix.
///
/// Probed separately because a refusal reached only through the namespace says
/// nothing about whether the scratch prefix is validated at all — and the
/// scratch prefix steers `probe_url`, the capability probe's own key space.
#[test]
fn the_scratch_prefix_is_validated_too() {
    let refusal = with_scratch("scratch/../secrets")
        .expect_err("the scratch prefix must be validated like the namespace");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidPathComponent),
        "a traversal in the scratch prefix must refuse, got {refusal:?}"
    );
}

/// **The permitted twin at the exact boundary.**
///
/// The guard reads `> 512`, so 512 is legal. This is the case a refusal-only
/// corpus cannot see: changing the comparison to `>=` would leave every
/// refusal above green and break only this test.
#[test]
fn a_path_component_at_exactly_the_bound_is_admitted() {
    let at_bound = "a".repeat(MAX_PATH_COMPONENT_BYTES);
    with_namespace(&at_bound).expect("a namespace at exactly the bound must be admissible");

    let over = "a".repeat(MAX_PATH_COMPONENT_BYTES + 1);
    let refusal = with_namespace(&over).expect_err("one byte past the bound must be refused");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidPathComponent),
        "got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// InvalidHeaderName — three axes
// ---------------------------------------------------------------------------

#[test]
fn an_empty_header_name_is_refused() {
    let refusal = response(&[("", "value")]).expect_err("an empty header name names nothing");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidHeaderName),
        "got {refusal:?}"
    );
}

#[test]
fn a_header_name_outside_the_token_set_is_refused() {
    let refusal = response(&[("x trace", "value")])
        .expect_err("a space is not a token character in a header name");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidHeaderName),
        "got {refusal:?}"
    );
}

/// **The permitted twin at the exact boundary**, paired with one byte past it.
#[test]
fn a_header_name_at_exactly_the_bound_is_admitted() {
    let at_bound = "a".repeat(MAX_HEADER_NAME_BYTES);
    response(&[(at_bound.as_str(), "value")])
        .expect("a header name at exactly the bound must be admissible");

    let over = "a".repeat(MAX_HEADER_NAME_BYTES + 1);
    let refusal =
        response(&[(over.as_str(), "value")]).expect_err("one byte past the bound must refuse");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidHeaderName),
        "got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// InvalidHeaderValue — the splitting axis, and the bound
// ---------------------------------------------------------------------------

/// **Header splitting.** A value carrying CR or LF is refused, each form
/// checked individually.
///
/// This is the axis the variant's documentation is about: a value that could
/// *split* the bounded HTTP field. The third case is the realistic shape — a
/// CRLF followed by a forged header.
#[test]
fn a_header_value_carrying_a_line_break_is_refused() {
    for injected in ["a\rb", "a\nb", "a\r\nx-injected: 1"] {
        let refusal = response(&[("x-trace", injected)])
            .expect_err(&format!("the splitting value {injected:?} must be refused"));
        assert!(
            matches!(refusal, AdapterConfigError::InvalidHeaderValue),
            "a value containing a line break must refuse, got {refusal:?}"
        );
    }
}

/// **The permitted twin at the exact boundary**, paired with one byte past it.
#[test]
fn a_header_value_at_exactly_the_bound_is_admitted() {
    let at_bound = "a".repeat(MAX_HEADER_BYTES);
    response(&[("x-trace", at_bound.as_str())])
        .expect("a header value at exactly the bound must be admissible");

    let over = "a".repeat(MAX_HEADER_BYTES + 1);
    let refusal =
        response(&[("x-trace", over.as_str())]).expect_err("one byte past the bound must refuse");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidHeaderValue),
        "got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// DuplicateHeader — and it must be case-insensitive
// ---------------------------------------------------------------------------

/// Two headers differing **only in case** collide.
///
/// Names are normalized to lowercase *before* the duplicate check, which is
/// what makes the rule case-insensitive and what the variant's documentation
/// claims. A probe using two *identical* names would pass against an
/// implementation that had dropped the normalization, so it would not test the
/// property at all.
#[test]
fn two_headers_differing_only_in_case_collide() {
    let refusal = response(&[("X-Trace", "first"), ("x-trace", "second")])
        .expect_err("case-variant duplicates make signing semantics ambiguous");
    assert!(
        matches!(refusal, AdapterConfigError::DuplicateHeader),
        "case-variant names must collide as duplicates, got {refusal:?}"
    );
}

/// The permitted twin: two genuinely distinct names are admitted, so the
/// collision above is attributable to the names matching after normalization
/// rather than to the constructor rejecting any second header at all.
#[test]
fn two_distinct_headers_are_admitted() {
    let assembled = response(&[("x-trace", "first"), ("x-request-id", "second")])
        .expect("two distinct header names must be admissible");
    assert_eq!(
        assembled.headers.len(),
        2,
        "both distinct headers must survive normalization"
    );
}

// ---------------------------------------------------------------------------
// InvalidSigningCredential — three axes, two boundaries
// ---------------------------------------------------------------------------

#[test]
fn a_key_id_with_a_non_visible_byte_is_refused() {
    for key_id in ["key id", "key\nid", "key\u{7f}id"] {
        let refusal = CanonicalHmacSha256Signer::new(key_id, b"secret".to_vec())
            .expect_err(&format!("the key id {key_id:?} must be refused"));
        assert!(
            matches!(refusal, AdapterConfigError::InvalidSigningCredential),
            "a non-visible byte in the key id must refuse as an invalid credential, got {refusal:?}"
        );
    }
}

#[test]
fn an_empty_signing_key_is_refused() {
    let refusal = CanonicalHmacSha256Signer::new("probe-key", Vec::new())
        .expect_err("an empty secret cannot authenticate anything");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidSigningCredential),
        "got {refusal:?}"
    );
}

/// **The permitted twins at the exact boundaries.**
///
/// The key-id guard reads `> 256`, so 256 is legal; the key guard reads
/// `is_empty`, so a single byte is legal. Both are cases that would go
/// unnoticed if either condition were tightened.
#[test]
fn a_key_id_at_exactly_the_bound_and_a_one_byte_key_are_admitted() {
    let at_bound = "a".repeat(MAX_KEY_ID_BYTES);
    CanonicalHmacSha256Signer::new(at_bound.as_str(), b"secret".to_vec())
        .expect("a key id at exactly the bound must be admissible");
    CanonicalHmacSha256Signer::new("probe-key", b"k".to_vec())
        .expect("a one-byte key is short, but the guard rejects only an empty one");

    let over = "a".repeat(MAX_KEY_ID_BYTES + 1);
    let refusal = CanonicalHmacSha256Signer::new(over.as_str(), b"secret".to_vec())
        .expect_err("one byte past the key-id bound must refuse");
    assert!(
        matches!(refusal, AdapterConfigError::InvalidSigningCredential),
        "got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// ReceiptEndpointMismatch — the capability-scope guard
// ---------------------------------------------------------------------------

/// A minimal honest conditional object store: enough to pass the adapter's
/// authority probe, and nothing more.
///
/// This is deliberately not the fault-injection provider from
/// `authority_campaign.rs`; that one exists to misbehave. This one exists only
/// so a **real** `AuthorityCapabilityReceipt` can be earned, since the type has
/// private fields and the probe is its only constructor.
///
/// It satisfies exactly what `probe` demands: conditional create on
/// `if-none-match: *`, conditional replace on a matching `if-match`, `412` on a
/// stale predecessor, a unique non-content-derived version token per write, and
/// an exact historical read by `?fgit-version-token=`.
/// Cloned into the adapter by value, so the handle is shared rather than moved:
/// the probe borrows it first and the adapter owns it afterwards.
#[derive(Clone, Debug, Default)]
struct ConformingProvider {
    state: Arc<Mutex<ProviderState>>,
}

#[derive(Debug, Default)]
struct ProviderState {
    /// Current token and body per exact key.
    live: BTreeMap<String, ([u8; VERSION_TOKEN_BYTES], Vec<u8>)>,
    /// Every version ever written, so a historical exact read can answer.
    history: BTreeMap<(String, [u8; VERSION_TOKEN_BYTES]), Vec<u8>>,
    /// Monotone write counter. Tokens derive from this rather than from the
    /// body, because a content-derived token is exactly what the probe refuses.
    writes: u64,
}

impl ObjectStoreTransport for ConformingProvider {
    fn send(
        &self,
        _cx: &asupersync::Cx,
        request: ObjectStoreRequest,
    ) -> impl Future<Output = Result<ObjectStoreResponse, ObjectStoreTransportError>> + Send {
        let answer = self.answer(&request);
        async move { Ok(answer) }
    }
}

impl ConformingProvider {
    fn answer(&self, request: &ObjectStoreRequest) -> ObjectStoreResponse {
        let (path, query) = match request.url.split_once('?') {
            Some((path, query)) => (path.to_owned(), Some(query.to_owned())),
            None => (request.url.clone(), None),
        };
        let mut guard = self.state.lock().expect("provider state is not poisoned");
        // The response is built under the lock, then the guard is released
        // explicitly before returning rather than living to end of call.
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
                                |(token, body)| versioned(200, *token, body.clone()),
                            )
                        },
                        |token| {
                            state.history.get(&(path.clone(), token)).map_or_else(
                                || bare(404),
                                |body| versioned(200, token, body.clone()),
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
                    if permitted {
                        state.writes += 1;
                        let token = mint_token(state.writes);
                        state
                            .history
                            .insert((path.clone(), token), request.body.clone());
                        state.live.insert(path, (token, request.body.clone()));
                        versioned(200, token, Vec::new())
                    } else {
                        bare(412)
                    }
                }
            }
        };
        drop(guard);
        response
    }
}

/// Counter-derived, so no two writes share a token even when the bodies match.
/// The probe's ABA drill restores byte-identical content and refuses any
/// provider whose third token repeats either of the first two.
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

fn versioned(status: u16, token: [u8; VERSION_TOKEN_BYTES], body: Vec<u8>) -> ObjectStoreResponse {
    ObjectStoreResponse::new(
        status,
        [(VERSION_HEADER.to_owned(), encode_token(token))],
        body,
    )
    .expect("the provider emits one well-formed version header")
}

fn bare(status: u16) -> ObjectStoreResponse {
    ObjectStoreResponse::new(status, [], Vec::new()).expect("a header-free response is admissible")
}

fn runtime() -> (Runtime, asupersync::Cx) {
    let runtime = RuntimeBuilder::new().build().expect("runtime builds");
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    (runtime, cx)
}

fn probe_signer() -> CanonicalHmacSha256Signer {
    CanonicalHmacSha256Signer::new("scope-key", b"scope-secret".to_vec())
        .expect("the probe credential is well formed")
}

/// A receipt earned against `https://objects.example.test`, namespace
/// `objects`, scratch prefix `scratch` — plus the endpoint it was earned
/// against and the provider that granted it.
fn earned_receipt() -> (
    Runtime,
    ObjectStoreEndpoint,
    AuthorityCapabilityReceipt,
    ConformingProvider,
) {
    let provider = ConformingProvider::default();
    let (runtime, cx) = runtime();
    let scope = endpoint(ORIGIN, "objects", "scratch").expect("the probe endpoint is valid");
    let receipt = runtime
        .block_on(ObjectStoreAuthority::<
            ConformingProvider,
            CanonicalHmacSha256Signer,
        >::probe(
            &cx,
            &provider,
            &probe_signer(),
            &scope,
            ProbeRunId::new([7u8; VERSION_TOKEN_BYTES]),
            VersionTokenProfile::Unique,
        ))
        .expect("a conforming unique-token provider satisfies the authority probe");
    (runtime, scope, receipt, provider)
}

/// The permitted twin, and the control for every mismatch below.
///
/// If this failed, the three refusals would be unattributable — they could be
/// the adapter rejecting any receipt at all rather than rejecting a foreign
/// scope.
#[test]
fn a_receipt_admits_the_endpoint_it_was_earned_against() {
    let (_runtime, scope, receipt, provider) = earned_receipt();
    ObjectStoreAuthority::new(
        provider,
        probe_signer(),
        scope,
        receipt,
        StoreInstanceId::from_raw(6006),
        AuthorityLimits::default(),
    )
    .expect("the receipt binds the endpoint the probe ran against");
}

/// **Capability confusion.** A receipt earned against one scope must not
/// authorize an adapter pointed at another.
///
/// Each case differs from the probed endpoint in exactly **one** field, which
/// is what pins the fingerprint's domain: origin, namespace and scratch prefix
/// must all be inside it. A fingerprint that covered only the origin would
/// refuse the first case and admit the other two — so the three are not
/// redundant with each other.
#[test]
fn a_receipt_from_another_scope_is_refused_on_every_endpoint_field() {
    let foreign = [
        (
            "origin",
            endpoint("https://objects.other.test", "objects", "scratch"),
        ),
        ("namespace", endpoint(ORIGIN, "other-objects", "scratch")),
        ("scratch prefix", endpoint(ORIGIN, "objects", "other")),
    ];

    for (field, candidate) in foreign {
        let (_runtime, _scope, receipt, provider) = earned_receipt();
        let candidate = candidate.expect("each foreign endpoint is itself well formed");
        let refusal = ObjectStoreAuthority::new(
            provider,
            probe_signer(),
            candidate,
            receipt,
            StoreInstanceId::from_raw(6006),
            AuthorityLimits::default(),
        )
        .err()
        .unwrap_or_else(|| {
            panic!("an endpoint differing in its {field} must not accept this receipt")
        });
        assert!(
            matches!(refusal, AdapterConfigError::ReceiptEndpointMismatch),
            "a receipt from another scope must refuse as an endpoint mismatch \
             when the {field} differs, got {refusal:?}"
        );
    }
}
