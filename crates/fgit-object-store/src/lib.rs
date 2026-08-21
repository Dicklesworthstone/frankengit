#![forbid(unsafe_code)]
//! Provider-neutral object-store authority adapter.
//!
//! This crate binds a deliberately small HTTP object-store profile to
//! [`fgit_authority::AsyncAuthorityStore`].  It does **not** treat a normal
//! content ETag as an authority token: a usable provider has a version token
//! that is unique for every write, supports conditional writes against that
//! token, and can retrieve the exact historical version named by it.  The
//! startup probe demonstrates those properties using only exact keys under a
//! caller-provided scratch prefix; no API in this crate lists or deletes.
//!
//! Asupersync's HTTPS client is an explicit typed refusal until its Rustls
//! closure is registry-admitted; no plaintext fallback exists.  A generic
//! transport is exposed for an admitted provider transport and for the scripted
//! test double below; the test double is a wire-script oracle, never a
//! durable-store substitute.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;

use asupersync::cx::Cx;
use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityRefusal, AuthorityVersionToken, CasOutcome, HeadGeneration, HeadInit, HeadKey,
    HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
    VERSION_TOKEN_BYTES,
};
use fgit_crypto::{hmac_sha256, sha256_digest};

const VERSION_HEADER: &str = "x-fgit-version-token";
const GENERATION_HEADER: &str = "x-fgit-head-generation";
const IF_MATCH: &str = "if-match";
const IF_NONE_MATCH: &str = "if-none-match";
const AUTHORIZATION: &str = "authorization";
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// A bounded, exact-key object-store HTTP request.
///
/// The header map deliberately normalizes names to lowercase and rejects a
/// duplicate instead of leaving a signing or conditional-write ambiguity to
/// the HTTP stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreRequest {
    /// HTTP method selected by the adapter.
    pub method: ObjectStoreMethod,
    /// Absolute URL under the configured origin and namespace.
    pub url: String,
    /// Canonically ordered, normalized request headers.
    pub headers: BTreeMap<String, String>,
    /// Complete request body.  Authority bounds are checked before this is sent.
    pub body: Vec<u8>,
}

impl ObjectStoreRequest {
    fn new(method: ObjectStoreMethod, url: String, body: Vec<u8>) -> Self {
        Self {
            method,
            url,
            headers: BTreeMap::new(),
            body,
        }
    }

    fn insert_header(
        &mut self,
        name: impl AsRef<str>,
        value: impl Into<String>,
    ) -> Result<(), AdapterConfigError> {
        let name = normalize_header_name(name.as_ref())?;
        let value = value.into();
        if value.len() > MAX_HEADER_BYTES || value.contains(['\r', '\n']) {
            return Err(AdapterConfigError::InvalidHeaderValue);
        }
        if self.headers.insert(name, value).is_some() {
            return Err(AdapterConfigError::DuplicateHeader);
        }
        Ok(())
    }
}

/// The only HTTP methods needed by the authority profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectStoreMethod {
    /// Retrieve a known object key or a known historical version.
    Get,
    /// Write an immutable body or conditionally replace a head.
    Put,
}

impl ObjectStoreMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
        }
    }
}

/// A normalized HTTP response received from an object-store transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreResponse {
    /// Numeric HTTP response status.
    pub status: u16,
    /// Lowercase, duplicate-free response headers.
    pub headers: BTreeMap<String, String>,
    /// Complete response body, bounded by the transport configuration.
    pub body: Vec<u8>,
}

impl ObjectStoreResponse {
    /// Assemble a scripted response, rejecting ambiguous headers.
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: Vec<u8>,
    ) -> Result<Self, AdapterConfigError> {
        let mut normalized = BTreeMap::new();
        for (name, value) in headers {
            let name = normalize_header_name(&name)?;
            if value.len() > MAX_HEADER_BYTES || value.contains(['\r', '\n']) {
                return Err(AdapterConfigError::InvalidHeaderValue);
            }
            if normalized.insert(name, value).is_some() {
                return Err(AdapterConfigError::DuplicateHeader);
            }
        }
        Ok(Self {
            status,
            headers: normalized,
            body,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// A transport failure classified by whether the request could have changed state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectStoreTransportError {
    /// The request did not reach an object-store effect.
    Rejected,
    /// The request may have reached an object-store effect.
    Ambiguous(AmbiguityReason),
}

/// Owned transport boundary for the provider-neutral adapter.
///
/// Implementations must return [`ObjectStoreTransportError::Ambiguous`] for a
/// mutation whenever they cannot prove that it never reached the endpoint.
/// The adapter never retries a mutation; a caller resolves ambiguity with an
/// exact-key read and the higher-level outcome index.
pub trait ObjectStoreTransport {
    /// Send exactly one signed request under `cx`.
    fn send(
        &self,
        cx: &Cx,
        request: ObjectStoreRequest,
    ) -> impl Future<Output = Result<ObjectStoreResponse, ObjectStoreTransportError>> + Send;
}

/// The future built-in Asupersync HTTPS transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsupersyncHttpTransport;

impl AsupersyncHttpTransport {
    /// Construct an HTTP transport with authority-safe client behavior.
    ///
    /// Automatic retries are disabled even for `PUT`: a conditional mutation
    /// with a lost response must be resolved, not replayed.  Redirects and
    /// proxies are disabled so signing credentials cannot be redirected to a
    /// different endpoint.
    ///
    /// The endpoint profile requires HTTPS.  The current workspace's closed
    /// dependency set has not admitted Asupersync's Rustls feature closure, so
    /// construction refuses instead of silently attempting plaintext traffic.
    /// A later dependency-policy amendment can add the owned Asupersync HTTPS
    /// client here, configured with redirects, retries, cookies, and proxies
    /// disabled.  The provider-neutral adapter itself remains usable with a
    /// transport that satisfies [`ObjectStoreTransport`].
    pub fn new(_max_response_body_bytes: usize) -> Result<Self, TransportSetupRefusal> {
        Err(TransportSetupRefusal::TlsTransportNotAdmitted)
    }
}

/// Why the built-in Asupersync transport cannot be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportSetupRefusal {
    /// The authenticated transport dependency closure is not yet registry-admitted.
    TlsTransportNotAdmitted,
}

impl fmt::Display for TransportSetupRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsTransportNotAdmitted => formatter.write_str(
                "Asupersync TLS transport dependencies are not admitted by this workspace",
            ),
        }
    }
}

impl std::error::Error for TransportSetupRefusal {}

/// Request-authentication boundary.  The adapter never sends an unsigned request.
pub trait RequestSigner {
    /// Add the provider authentication headers to `request`.
    fn sign(&self, request: &mut ObjectStoreRequest) -> Result<(), AdapterConfigError>;
}

/// Deterministic HMAC-SHA-256 signer for the minimal FrankenGit object-store profile.
///
/// This is deliberately not called an AWS signer: the signed canonical request
/// is documented by this crate and can be implemented by any compatible store.
/// A provider with another authentication protocol supplies its own
/// [`RequestSigner`].
pub struct CanonicalHmacSha256Signer {
    key_id: String,
    key: Vec<u8>,
}

impl fmt::Debug for CanonicalHmacSha256Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalHmacSha256Signer")
            .field("key_id", &self.key_id)
            .field("key", &"[redacted]")
            .finish()
    }
}

impl CanonicalHmacSha256Signer {
    /// Construct a signer from a caller-provided credential scope and secret.
    pub fn new(
        key_id: impl Into<String>,
        key: impl Into<Vec<u8>>,
    ) -> Result<Self, AdapterConfigError> {
        let key_id = key_id.into();
        let key = key.into();
        if !is_visible_ascii(&key_id) || key_id.len() > 256 || key.is_empty() {
            return Err(AdapterConfigError::InvalidSigningCredential);
        }
        Ok(Self { key_id, key })
    }

    /// Canonical bytes signed by this profile, exposed for independent provider tests.
    #[must_use]
    pub fn canonical_request(request: &ObjectStoreRequest) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(request.method.as_str().as_bytes());
        output.push(b'\n');
        output.extend_from_slice(request.url.as_bytes());
        output.push(b'\n');
        for (name, value) in &request.headers {
            if name != AUTHORIZATION {
                output.extend_from_slice(name.as_bytes());
                output.push(b':');
                output.extend_from_slice(value.as_bytes());
                output.push(b'\n');
            }
        }
        output.extend_from_slice(hex_encode(&sha256_digest(&request.body)).as_bytes());
        output
    }
}

impl RequestSigner for CanonicalHmacSha256Signer {
    fn sign(&self, request: &mut ObjectStoreRequest) -> Result<(), AdapterConfigError> {
        request.insert_header("x-fgit-key-id", self.key_id.clone())?;
        let canonical = Self::canonical_request(request);
        let tag = hex_encode(&hmac_sha256(&self.key, &canonical));
        request.insert_header(AUTHORIZATION, format!("FGIT-HMAC-SHA256 {tag}"))
    }
}

/// Provider origin, namespace, and probe scratch prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreEndpoint {
    origin: String,
    namespace: String,
    scratch_prefix: String,
}

impl ObjectStoreEndpoint {
    /// Construct an HTTPS-only production endpoint.
    pub fn new(
        origin: impl Into<String>,
        namespace: impl Into<String>,
        scratch_prefix: impl Into<String>,
    ) -> Result<Self, AdapterConfigError> {
        let origin = origin.into();
        if !origin.starts_with("https://")
            || origin.len() <= "https://".len()
            || origin.contains(['?', '#', '\r', '\n'])
            || origin.ends_with('/')
        {
            return Err(AdapterConfigError::InvalidEndpoint);
        }
        let namespace = validate_path_component(namespace.into())?;
        let scratch_prefix = validate_path_component(scratch_prefix.into())?;
        Ok(Self {
            origin,
            namespace,
            scratch_prefix,
        })
    }

    /// A stable fingerprint binding a capability receipt to this endpoint scope.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        sha256_digest(
            format!(
                "fgit-object-store-endpoint-v1\n{}\n{}\n{}",
                self.origin, self.namespace, self.scratch_prefix
            )
            .as_bytes(),
        )
    }

    fn immutable_url(&self, key: &ImmutableKey) -> String {
        self.url("immutable", key.as_bytes())
    }

    fn head_url(&self, key: &HeadKey) -> String {
        self.url("head", key.as_bytes())
    }

    fn historical_head_url(&self, key: &HeadKey, token: AuthorityVersionToken) -> String {
        format!(
            "{}?fgit-version-token={}",
            self.head_url(key),
            hex_encode(&token.to_opaque_bytes())
        )
    }

    fn probe_url(&self, run: ProbeRunId, name: &str) -> String {
        format!(
            "{}/{}/{}/probe/{}/{}",
            self.origin,
            self.namespace,
            self.scratch_prefix,
            hex_encode(&run.0),
            name
        )
    }

    fn url(&self, kind: &str, key: &[u8]) -> String {
        format!(
            "{}/{}/{}/{}",
            self.origin,
            self.namespace,
            kind,
            percent_encode(key)
        )
    }
}

/// A caller-minted non-repeating probe run identifier.
///
/// A deployment obtains these bytes from its capability-scoped entropy source.
/// The adapter cannot synthesize a safe freshness value from authority content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeRunId([u8; VERSION_TOKEN_BYTES]);

impl ProbeRunId {
    /// Wrap one caller-generated probe run identifier.
    #[must_use]
    pub const fn new(bytes: [u8; VERSION_TOKEN_BYTES]) -> Self {
        Self(bytes)
    }
}

/// The authority-relevant kind of provider version token observed by the probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionTokenProfile {
    /// Tokens are opaque, unique per write, and support historical exact reads.
    Unique,
    /// Tokens are provider generation handles with the same authority properties.
    GenerationVerified,
}

/// A successful, endpoint-bound object-store authority capability probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCapabilityReceipt {
    endpoint_fingerprint: [u8; 32],
    profile: VersionTokenProfile,
    probe_run: ProbeRunId,
}

impl AuthorityCapabilityReceipt {
    /// The accepted provider versioning profile.
    #[must_use]
    pub const fn profile(&self) -> VersionTokenProfile {
        self.profile
    }

    /// The scratch run that yielded this receipt, for audit correlation.
    #[must_use]
    pub const fn probe_run(&self) -> ProbeRunId {
        self.probe_run
    }

    /// The endpoint binding recorded by the probe.
    #[must_use]
    pub const fn endpoint_fingerprint(&self) -> [u8; 32] {
        self.endpoint_fingerprint
    }
}

/// A typed reason an endpoint cannot carry canonical authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityProbeFailure {
    /// A conditional write was unavailable or rejected before authority use.
    ConditionalWritesUnavailable,
    /// Restoring identical bytes reused the earlier token, proving content derivation.
    ContentDerivedVersionToken,
    /// The endpoint did not return a well-formed 16-byte unique token.
    MissingOrMalformedVersionToken,
    /// A known historical token could not be read exactly.
    HistoricalVersionReadUnavailable,
    /// The endpoint returned different bytes than the just-written probe body.
    ReadAfterWriteViolation,
    /// A lower-level transport outcome did not prove absence of an effect.
    Ambiguous(AmbiguityReason),
    /// Endpoint configuration or signing failed before the probe call.
    Configuration,
}

impl fmt::Display for CapabilityProbeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ConditionalWritesUnavailable => "conditional writes are unavailable",
            Self::ContentDerivedVersionToken => "version token is content-derived",
            Self::MissingOrMalformedVersionToken => "version token is absent or malformed",
            Self::HistoricalVersionReadUnavailable => {
                "historical exact version reads are unavailable"
            }
            Self::ReadAfterWriteViolation => "known-key read violates read-after-write",
            Self::Ambiguous(reason) => {
                return write!(formatter, "probe result ambiguous: {reason}");
            }
            Self::Configuration => "endpoint configuration or signing failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CapabilityProbeFailure {}

/// Typed construction/signing/endpoint validation refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterConfigError {
    /// Endpoint does not identify one HTTPS origin without URL ambiguity.
    InvalidEndpoint,
    /// Namespace or scratch prefix is not a bounded path sequence.
    InvalidPathComponent,
    /// A header name is not lowercase-visible ASCII after normalization.
    InvalidHeaderName,
    /// A header value could split or exceed the bounded HTTP field.
    InvalidHeaderValue,
    /// Two case-insensitive headers would make conditional/signing semantics ambiguous.
    DuplicateHeader,
    /// Signing key material or identifier was not admissible.
    InvalidSigningCredential,
    /// The adapter was constructed with a receipt for another endpoint scope.
    ReceiptEndpointMismatch,
}

impl fmt::Display for AdapterConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEndpoint => "object-store endpoint must be one unambiguous HTTPS origin",
            Self::InvalidPathComponent => "object-store namespace or scratch prefix is invalid",
            Self::InvalidHeaderName => "object-store header name is invalid",
            Self::InvalidHeaderValue => "object-store header value is invalid",
            Self::DuplicateHeader => "object-store request has duplicate header",
            Self::InvalidSigningCredential => "object-store signing credential is invalid",
            Self::ReceiptEndpointMismatch => "capability receipt belongs to a different endpoint",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AdapterConfigError {}

/// Async object-store implementation of the authority contract.
///
/// Construction consumes a private [`AuthorityCapabilityReceipt`], so a
/// provider is not admitted based on configuration or an ETag claim alone.
/// The adapter has no listing or deletion operation.
pub struct ObjectStoreAuthority<T, S> {
    transport: T,
    signer: S,
    endpoint: ObjectStoreEndpoint,
    instance: StoreInstanceId,
    limits: AuthorityLimits,
    _profile: VersionTokenProfile,
}

impl<T, S> fmt::Debug for ObjectStoreAuthority<T, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStoreAuthority")
            .field("endpoint", &self.endpoint)
            .field("instance", &self.instance)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<T, S> ObjectStoreAuthority<T, S>
where
    T: ObjectStoreTransport,
    S: RequestSigner,
{
    /// Probe an endpoint's authority-relevant conditional-write semantics.
    ///
    /// The probe uses exact scratch keys only: PIA, known-key RAW, two
    /// conditional replacements that restore byte-identical content, a stale
    /// predecessor rejection, and a historical exact-version read.
    pub async fn probe(
        cx: &Cx,
        transport: &T,
        signer: &S,
        endpoint: &ObjectStoreEndpoint,
        run: ProbeRunId,
        profile: VersionTokenProfile,
    ) -> Result<AuthorityCapabilityReceipt, CapabilityProbeFailure> {
        let url = endpoint.probe_url(run, "version-aba");
        let first = send_probe(
            cx,
            transport,
            signer,
            conditional_put(&url, b"first".to_vec(), IF_NONE_MATCH, "*"),
        )
        .await?;
        if !is_success(first.status) {
            return Err(CapabilityProbeFailure::ConditionalWritesUnavailable);
        }
        let token_a =
            response_token(&first).ok_or(CapabilityProbeFailure::MissingOrMalformedVersionToken)?;

        let raw = send_probe(
            cx,
            transport,
            signer,
            ObjectStoreRequest::new(ObjectStoreMethod::Get, url.clone(), Vec::new()),
        )
        .await?;
        if !is_success(raw.status) || raw.body != b"first" || response_token(&raw) != Some(token_a)
        {
            return Err(CapabilityProbeFailure::ReadAfterWriteViolation);
        }

        let second = send_probe(
            cx,
            transport,
            signer,
            conditional_put(
                &url,
                b"second".to_vec(),
                IF_MATCH,
                &hex_encode(&token_a.to_opaque_bytes()),
            ),
        )
        .await?;
        if !is_success(second.status) {
            return Err(CapabilityProbeFailure::ConditionalWritesUnavailable);
        }
        let token_b = response_token(&second)
            .ok_or(CapabilityProbeFailure::MissingOrMalformedVersionToken)?;
        if token_a == token_b {
            return Err(CapabilityProbeFailure::ContentDerivedVersionToken);
        }

        let restored = send_probe(
            cx,
            transport,
            signer,
            conditional_put(
                &url,
                b"first".to_vec(),
                IF_MATCH,
                &hex_encode(&token_b.to_opaque_bytes()),
            ),
        )
        .await?;
        if !is_success(restored.status) {
            return Err(CapabilityProbeFailure::ConditionalWritesUnavailable);
        }
        let token_c = response_token(&restored)
            .ok_or(CapabilityProbeFailure::MissingOrMalformedVersionToken)?;
        if token_c == token_a || token_c == token_b {
            // Admission decision: an ETag-only provider cannot prove no-ABA authority publication.
            return Err(CapabilityProbeFailure::ContentDerivedVersionToken);
        }

        let stale = send_probe(
            cx,
            transport,
            signer,
            conditional_put(
                &url,
                b"stale".to_vec(),
                IF_MATCH,
                &hex_encode(&token_a.to_opaque_bytes()),
            ),
        )
        .await?;
        if stale.status != 412 {
            return Err(CapabilityProbeFailure::ConditionalWritesUnavailable);
        }

        let historical = send_probe(
            cx,
            transport,
            signer,
            ObjectStoreRequest::new(
                ObjectStoreMethod::Get,
                format!(
                    "{url}?fgit-version-token={}",
                    hex_encode(&token_a.to_opaque_bytes())
                ),
                Vec::new(),
            ),
        )
        .await?;
        if !is_success(historical.status)
            || historical.body != b"first"
            || response_token(&historical) != Some(token_a)
        {
            return Err(CapabilityProbeFailure::HistoricalVersionReadUnavailable);
        }

        Ok(AuthorityCapabilityReceipt {
            endpoint_fingerprint: endpoint.fingerprint(),
            profile,
            probe_run: run,
        })
    }

    /// Construct an authority adapter only from a successful endpoint-bound probe.
    pub fn new(
        transport: T,
        signer: S,
        endpoint: ObjectStoreEndpoint,
        receipt: AuthorityCapabilityReceipt,
        instance: StoreInstanceId,
        limits: AuthorityLimits,
    ) -> Result<Self, AdapterConfigError> {
        if receipt.endpoint_fingerprint != endpoint.fingerprint() {
            return Err(AdapterConfigError::ReceiptEndpointMismatch);
        }
        Ok(Self {
            transport,
            signer,
            endpoint,
            instance,
            limits,
            _profile: receipt.profile,
        })
    }

    async fn send(
        &self,
        cx: &Cx,
        mut request: ObjectStoreRequest,
    ) -> Result<ObjectStoreResponse, AuthorityFailure> {
        if let Err(error) = cx.checkpoint() {
            return Err(AuthorityFailure::Ambiguous(checkpoint_ambiguity(&error)));
        }
        self.signer
            .sign(&mut request)
            .map_err(|_| AuthorityFailure::Refused(AuthorityRefusal::Unavailable))?;
        self.transport
            .send(cx, request)
            .await
            .map_err(map_transport_failure)
    }

    fn check_body(&self, body: &[u8]) -> Result<(), AuthorityFailure> {
        if body.len() > self.limits.body_bytes {
            return Err(AuthorityFailure::Refused(AuthorityRefusal::BodyTooLarge {
                len: body.len(),
                limit: self.limits.body_bytes,
            }));
        }
        Ok(())
    }

    async fn read_immutable_inner(
        &self,
        cx: &Cx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        let response = self
            .send(
                cx,
                ObjectStoreRequest::new(
                    ObjectStoreMethod::Get,
                    self.endpoint.immutable_url(key),
                    Vec::new(),
                ),
            )
            .await?;
        match response.status {
            200..=299 => {
                self.check_body(&response.body)?;
                Ok(ImmutableRead::Present(response.body))
            }
            404 => Ok(ImmutableRead::Absent),
            429 => Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled)),
            _ => Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable)),
        }
    }

    async fn read_head_inner(&self, cx: &Cx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        let response = self
            .send(
                cx,
                ObjectStoreRequest::new(
                    ObjectStoreMethod::Get,
                    self.endpoint.head_url(key),
                    Vec::new(),
                ),
            )
            .await?;
        match response.status {
            200..=299 => Ok(HeadRead::Present(
                self.receipt_from_response(key, response)?,
            )),
            404 => Ok(HeadRead::Absent),
            429 => Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled)),
            _ => Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable)),
        }
    }

    async fn read_historical_head(
        &self,
        cx: &Cx,
        key: &HeadKey,
        token: AuthorityVersionToken,
    ) -> Result<HeadReadReceipt, AuthorityFailure> {
        let response = self
            .send(
                cx,
                ObjectStoreRequest::new(
                    ObjectStoreMethod::Get,
                    self.endpoint.historical_head_url(key, token),
                    Vec::new(),
                ),
            )
            .await?;
        match response.status {
            200..=299 => {
                let receipt = self.receipt_from_response(key, response)?;
                if receipt.token() == token {
                    Ok(receipt)
                } else {
                    Err(AuthorityFailure::Refused(
                        AuthorityRefusal::UnknownVersionToken,
                    ))
                }
            }
            404 => Err(AuthorityFailure::Refused(
                AuthorityRefusal::UnknownVersionToken,
            )),
            429 => Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled)),
            _ => Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable)),
        }
    }

    fn receipt_from_response(
        &self,
        key: &HeadKey,
        response: ObjectStoreResponse,
    ) -> Result<HeadReadReceipt, AuthorityFailure> {
        self.check_body(&response.body)?;
        let token = response_token(&response)
            .ok_or(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse))?;
        let generation = response
            .header(GENERATION_HEADER)
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|value| HeadGeneration::try_new(value).ok())
            .ok_or(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse))?;
        Ok(HeadReadReceipt::new(
            key.clone(),
            token,
            generation,
            response.body,
        ))
    }

    async fn put_head(
        &self,
        cx: &Cx,
        key: &HeadKey,
        body: &[u8],
        condition: (&str, String),
        generation: HeadGeneration,
    ) -> Result<ObjectStoreResponse, AuthorityFailure> {
        let mut request = ObjectStoreRequest::new(
            ObjectStoreMethod::Put,
            self.endpoint.head_url(key),
            body.to_vec(),
        );
        request
            .insert_header(condition.0, condition.1)
            .map_err(|_| AuthorityFailure::Refused(AuthorityRefusal::Unavailable))?;
        request
            .insert_header(GENERATION_HEADER, generation.get().to_string())
            .map_err(|_| AuthorityFailure::Refused(AuthorityRefusal::Unavailable))?;
        self.send(cx, request).await
    }
}

impl<T, S> AsyncAuthorityStore for ObjectStoreAuthority<T, S>
where
    T: ObjectStoreTransport + Sync,
    S: RequestSigner + Sync,
{
    type Context = Cx;

    fn instance_id(&self) -> StoreInstanceId {
        self.instance
    }

    fn limits(&self) -> AuthorityLimits {
        self.limits
    }

    async fn put_if_absent(
        &self,
        cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.check_body(body)?;
        let mut request = ObjectStoreRequest::new(
            ObjectStoreMethod::Put,
            self.endpoint.immutable_url(key),
            body.to_vec(),
        );
        request
            .insert_header(IF_NONE_MATCH, "*")
            .map_err(|_| AuthorityFailure::Refused(AuthorityRefusal::Unavailable))?;
        let response = self.send(cx, request).await?;
        match response.status {
            200..=299 => Ok(PutOutcome::Created),
            409 | 412 => match self.read_immutable_inner(cx, key).await? {
                ImmutableRead::Present(found) if found == body => Ok(PutOutcome::IdenticalRetry),
                ImmutableRead::Present(_) => Ok(PutOutcome::Conflict),
                ImmutableRead::Absent => {
                    Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable))
                }
            },
            429 => Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled)),
            _ => Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable)),
        }
    }

    async fn read_immutable(
        &self,
        cx: &Self::Context,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.read_immutable_inner(cx, key).await
    }

    async fn initialize_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.check_body(body)?;
        let response = self
            .put_head(cx, key, body, (IF_NONE_MATCH, "*".to_owned()), generation)
            .await?;
        match response.status {
            200..=299 => Ok(HeadInit::Created(
                self.receipt_from_response(key, response)?,
            )),
            409 | 412 => match self.read_head_inner(cx, key).await? {
                HeadRead::Present(receipt)
                    if receipt.generation() == generation && receipt.body() == body =>
                {
                    Ok(HeadInit::IdenticalRetry(receipt))
                }
                HeadRead::Present(_) | HeadRead::Absent => Ok(HeadInit::Conflict),
            },
            429 => Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled)),
            _ => Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable)),
        }
    }

    async fn read_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
    ) -> Result<HeadRead, AuthorityFailure> {
        self.read_head_inner(cx, key).await
    }

    async fn compare_exchange_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.check_body(new_body)?;
        let expected_receipt = self.read_historical_head(cx, key, expected).await?;
        if new_generation <= expected_receipt.generation() {
            return Err(AuthorityFailure::Refused(
                AuthorityRefusal::NonMonotoneGeneration {
                    current: expected_receipt.generation(),
                    proposed: new_generation,
                },
            ));
        }
        let response = self
            .put_head(
                cx,
                key,
                new_body,
                (IF_MATCH, hex_encode(&expected.to_opaque_bytes())),
                new_generation,
            )
            .await?;
        match response.status {
            200..=299 => Ok(CasOutcome::Committed(
                self.receipt_from_response(key, response)?,
            )),
            409 | 412 => Ok(CasOutcome::PredecessorMismatch),
            429 => Err(AuthorityFailure::Refused(AuthorityRefusal::Throttled)),
            _ => Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable)),
        }
    }

    /// Refuse the atomic composite rather than create the forbidden split window.
    ///
    /// A provider conditional write can replace the head, and immutable objects
    /// can be written with PIA, but those two operations have no common
    /// linearization point in this adapter. Sending either request here could
    /// expose a head whose outcome records are absent, or durable outcomes that
    /// no head ever makes canonical. `Unavailable` is returned before any
    /// transport request, so the refusal proves that no partial publication was
    /// attempted. An object-store profile that supplies an atomic compound
    /// primitive can implement this method without changing the ordinary CAS
    /// profile above.
    async fn publish_head_with_outcomes(
        &self,
        _cx: &Self::Context,
        _key: &HeadKey,
        _expected: AuthorityVersionToken,
        _new_generation: HeadGeneration,
        _new_body: &[u8],
        _outcomes: &[(ImmutableKey, Vec<u8>)],
    ) -> Result<CasOutcome, AuthorityFailure> {
        Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable))
    }

    async fn authenticate_head_receipt(
        &self,
        cx: &Self::Context,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        let found = self
            .read_historical_head(cx, receipt.key(), receipt.token())
            .await?;
        if found.generation() != receipt.generation() {
            return Err(AuthorityFailure::Refused(
                AuthorityRefusal::TokenGenerationMismatch,
            ));
        }
        if found.body() != receipt.body() {
            return Err(AuthorityFailure::Refused(
                AuthorityRefusal::TokenBodyMismatch,
            ));
        }
        Ok(AuthenticatedHead::new(receipt.clone(), self.instance))
    }
}

fn conditional_put(
    url: &str,
    body: Vec<u8>,
    condition_name: &str,
    condition_value: &str,
) -> ObjectStoreRequest {
    let mut request = ObjectStoreRequest::new(ObjectStoreMethod::Put, url.to_owned(), body);
    // Both condition names and their values are crate-owned protocol
    // constants, so install them directly instead of creating a panic-only
    // impossible branch through the public untrusted-header validator.
    request
        .headers
        .insert(condition_name.to_owned(), condition_value.to_owned());
    request
}

async fn send_probe<T, S>(
    cx: &Cx,
    transport: &T,
    signer: &S,
    mut request: ObjectStoreRequest,
) -> Result<ObjectStoreResponse, CapabilityProbeFailure>
where
    T: ObjectStoreTransport,
    S: RequestSigner,
{
    if let Err(error) = cx.checkpoint() {
        return Err(CapabilityProbeFailure::Ambiguous(checkpoint_ambiguity(
            &error,
        )));
    }
    signer
        .sign(&mut request)
        .map_err(|_| CapabilityProbeFailure::Configuration)?;
    transport
        .send(cx, request)
        .await
        .map_err(|failure| match failure {
            ObjectStoreTransportError::Rejected => {
                CapabilityProbeFailure::ConditionalWritesUnavailable
            }
            ObjectStoreTransportError::Ambiguous(reason) => {
                CapabilityProbeFailure::Ambiguous(reason)
            }
        })
}

fn map_transport_failure(failure: ObjectStoreTransportError) -> AuthorityFailure {
    match failure {
        ObjectStoreTransportError::Rejected => {
            AuthorityFailure::Refused(AuthorityRefusal::Unavailable)
        }
        ObjectStoreTransportError::Ambiguous(reason) => AuthorityFailure::Ambiguous(reason),
    }
}

fn checkpoint_ambiguity(error: &asupersync::Error) -> AmbiguityReason {
    if error.is_timeout() {
        AmbiguityReason::Timeout
    } else {
        AmbiguityReason::Cancelled
    }
}

fn response_token(response: &ObjectStoreResponse) -> Option<AuthorityVersionToken> {
    let value = response.header(VERSION_HEADER)?;
    let bytes = hex_decode_fixed::<VERSION_TOKEN_BYTES>(value)?;
    Some(AuthorityVersionToken::from_opaque_bytes(bytes))
}

fn normalize_header_name(name: &str) -> Result<String, AdapterConfigError> {
    if name.is_empty() || name.len() > 256 || !name.bytes().all(is_header_token) {
        return Err(AdapterConfigError::InvalidHeaderName);
    }
    Ok(name.to_ascii_lowercase())
}

const fn is_header_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_path_component(component: String) -> Result<String, AdapterConfigError> {
    if component.is_empty()
        || component.len() > 512
        || component.starts_with('/')
        || component.ends_with('/')
        || component
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(AdapterConfigError::InvalidPathComponent);
    }
    Ok(component)
}

fn is_visible_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(3));
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(percent_hex_digit(byte >> 4));
            output.push(percent_hex_digit(byte & 0x0f));
        }
    }
    output
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'a' + (value - 10)),
    }
}

fn percent_hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'A' + (value - 10)),
    }
}

fn hex_decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.saturating_mul(2) {
        return None;
    }
    let mut output = [0_u8; N];
    let input = value.as_bytes();
    let mut index = 0;
    while index < N {
        output[index] = hex_value(input[index * 2])? << 4 | hex_value(input[index * 2 + 1])?;
        index += 1;
    }
    Some(output)
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use asupersync::runtime::RuntimeBuilder;
    use asupersync::types::CancelKind;
    use fgit_authority::{
        AsyncAuthorityStore, AuthorityFailure, AuthorityRefusal, HeadGeneration, HeadKey,
    };

    use super::*;

    #[derive(Debug)]
    struct ScriptTransport {
        responses: Mutex<VecDeque<Result<ObjectStoreResponse, ObjectStoreTransportError>>>,
        requests: Mutex<Vec<ObjectStoreRequest>>,
    }

    impl ScriptTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<ObjectStoreResponse, ObjectStoreTransportError>>,
        ) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<ObjectStoreRequest> {
            self.requests.lock().expect("request log lock").clone()
        }
    }

    impl ObjectStoreTransport for ScriptTransport {
        async fn send(
            &self,
            _cx: &Cx,
            request: ObjectStoreRequest,
        ) -> Result<ObjectStoreResponse, ObjectStoreTransportError> {
            self.requests
                .lock()
                .expect("request log lock")
                .push(request);
            self.responses
                .lock()
                .expect("response script lock")
                .pop_front()
                .expect("script contains one response per request")
        }
    }

    /// A minimal in-Rust conditional object-store test double.
    ///
    /// This is intentionally confined to tests and implements the wire
    /// capability the adapter needs: exact-key `GET`, PIA, conditional `PUT`,
    /// opaque write-unique tokens, and historical version reads.  It is not a
    /// durable profile, is never exported, and is not used by production code.
    /// `BTreeMap` makes its scripted state and its observable order explicit;
    /// the production adapter owns no in-memory object map.
    #[derive(Default)]
    struct ConditionalStoreTestDouble {
        state: Mutex<ConditionalStoreState>,
    }

    #[derive(Default)]
    struct ConditionalStoreState {
        next_token: u64,
        objects: BTreeMap<String, Vec<ConditionalStoreVersion>>,
        requests: Vec<ObjectStoreRequest>,
    }

    struct ConditionalStoreVersion {
        token: [u8; VERSION_TOKEN_BYTES],
        body: Vec<u8>,
        generation: Option<String>,
    }

    impl ConditionalStoreTestDouble {
        fn requests(&self) -> Vec<ObjectStoreRequest> {
            self.state
                .lock()
                .expect("conditional store lock")
                .requests
                .clone()
        }
    }

    impl ObjectStoreTransport for ConditionalStoreTestDouble {
        async fn send(
            &self,
            _cx: &Cx,
            request: ObjectStoreRequest,
        ) -> Result<ObjectStoreResponse, ObjectStoreTransportError> {
            let mut state = self.state.lock().expect("conditional store lock");
            state.requests.push(request.clone());
            let (url, historical_token) = match request.url.split_once("?fgit-version-token=") {
                Some((url, token)) => match hex_decode_fixed::<VERSION_TOKEN_BYTES>(token) {
                    Some(token) => (url, Some(token)),
                    None => {
                        return Ok(ObjectStoreResponse::new(400, [], Vec::new()).expect("response"));
                    }
                },
                None => (request.url.as_str(), None),
            };
            match request.method {
                ObjectStoreMethod::Get => {
                    let Some(versions) = state.objects.get(url) else {
                        return Ok(ObjectStoreResponse::new(404, [], Vec::new()).expect("response"));
                    };
                    let version = historical_token.map_or_else(
                        || versions.last(),
                        |token| versions.iter().find(|version| version.token == token),
                    );
                    let Some(version) = version else {
                        return Ok(ObjectStoreResponse::new(404, [], Vec::new()).expect("response"));
                    };
                    Ok(test_store_response(200, version))
                }
                ObjectStoreMethod::Put => {
                    let if_none = request
                        .headers
                        .get(IF_NONE_MATCH)
                        .is_some_and(|value| value == "*");
                    let if_match = request
                        .headers
                        .get(IF_MATCH)
                        .and_then(|value| hex_decode_fixed(value));
                    let occupied = state
                        .objects
                        .get(url)
                        .is_some_and(|versions| !versions.is_empty());
                    let current_token = state
                        .objects
                        .get(url)
                        .and_then(|versions| versions.last())
                        .map(|version| version.token);
                    if if_none && occupied {
                        return Ok(ObjectStoreResponse::new(412, [], Vec::new()).expect("response"));
                    }
                    if !if_none {
                        let Some(expected) = if_match else {
                            return Ok(
                                ObjectStoreResponse::new(400, [], Vec::new()).expect("response")
                            );
                        };
                        if current_token != Some(expected) {
                            return Ok(
                                ObjectStoreResponse::new(412, [], Vec::new()).expect("response")
                            );
                        }
                    }
                    state.next_token = state
                        .next_token
                        .checked_add(1)
                        .expect("test token capacity");
                    let mut token = [0_u8; VERSION_TOKEN_BYTES];
                    token[8..].copy_from_slice(&state.next_token.to_be_bytes());
                    let generation = request.headers.get(GENERATION_HEADER).cloned();
                    let versions = state.objects.entry(url.to_owned()).or_default();
                    versions.push(ConditionalStoreVersion {
                        token,
                        body: request.body,
                        generation,
                    });
                    Ok(test_store_response(
                        201,
                        versions.last().expect("just pushed version"),
                    ))
                }
            }
        }
    }

    fn test_store_response(status: u16, version: &ConditionalStoreVersion) -> ObjectStoreResponse {
        let mut headers = vec![(VERSION_HEADER.to_owned(), hex_encode(&version.token))];
        if let Some(generation) = &version.generation {
            headers.push((GENERATION_HEADER.to_owned(), generation.clone()));
        }
        ObjectStoreResponse::new(status, headers, version.body.clone())
            .expect("test-store response")
    }

    fn response(status: u16, token: [u8; VERSION_TOKEN_BYTES], body: &[u8]) -> ObjectStoreResponse {
        ObjectStoreResponse::new(
            status,
            [(VERSION_HEADER.to_owned(), hex_encode(&token))],
            body.to_vec(),
        )
        .expect("script response")
    }

    fn head_response(
        status: u16,
        token: [u8; VERSION_TOKEN_BYTES],
        generation: u64,
        body: &[u8],
    ) -> ObjectStoreResponse {
        ObjectStoreResponse::new(
            status,
            [
                (VERSION_HEADER.to_owned(), hex_encode(&token)),
                (GENERATION_HEADER.to_owned(), generation.to_string()),
            ],
            body.to_vec(),
        )
        .expect("script head response")
    }

    fn endpoint() -> ObjectStoreEndpoint {
        ObjectStoreEndpoint::new(
            "https://objects.example",
            "bucket/fgit",
            "scratch/authority",
        )
        .expect("valid endpoint")
    }

    fn signer() -> CanonicalHmacSha256Signer {
        CanonicalHmacSha256Signer::new("test-key", b"test-secret".to_vec()).expect("valid signer")
    }

    fn test_runtime() -> (asupersync::runtime::Runtime, Cx) {
        let runtime = RuntimeBuilder::new().build().expect("runtime builds");
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        (runtime, cx)
    }

    fn run<T>(runtime: &asupersync::runtime::Runtime, future: T) -> T::Output
    where
        T: Future,
    {
        runtime.block_on(future)
    }

    #[test]
    fn canonical_signing_is_header_order_independent_and_redacts_key() {
        let signer = signer();
        let mut left = ObjectStoreRequest::new(
            ObjectStoreMethod::Put,
            "https://objects.example/a".to_owned(),
            b"body".to_vec(),
        );
        left.insert_header("z-last", "z").expect("header");
        left.insert_header("a-first", "a").expect("header");
        signer.sign(&mut left).expect("sign");

        let mut right = ObjectStoreRequest::new(
            ObjectStoreMethod::Put,
            "https://objects.example/a".to_owned(),
            b"body".to_vec(),
        );
        right.insert_header("a-first", "a").expect("header");
        right.insert_header("z-last", "z").expect("header");
        signer.sign(&mut right).expect("sign");

        assert_eq!(
            left.headers.get(AUTHORIZATION),
            right.headers.get(AUTHORIZATION)
        );
        assert!(!format!("{signer:?}").contains("test-secret"));
    }

    #[test]
    fn endpoint_refuses_ambiguous_paths_and_percent_encodes_authority_keys() {
        assert!(ObjectStoreEndpoint::new("http://objects.example", "bucket", "scratch").is_err());
        assert!(
            ObjectStoreEndpoint::new("https://objects.example", "bucket/../escape", "scratch")
                .is_err()
        );
        let endpoint = endpoint();
        let key = ImmutableKey::new(b"tenant/a?b".to_vec()).expect("valid opaque key");
        assert_eq!(
            endpoint.immutable_url(&key),
            "https://objects.example/bucket/fgit/immutable/tenant%2Fa%3Fb"
        );
    }

    #[test]
    fn builtin_transport_refuses_to_downgrade_when_tls_is_not_admitted() {
        assert!(matches!(
            AsupersyncHttpTransport::new(1024),
            Err(TransportSetupRefusal::TlsTransportNotAdmitted)
        ));
    }

    #[test]
    fn probe_refuses_content_derived_tokens_after_identical_restore() {
        let token_a = [1; VERSION_TOKEN_BYTES];
        let token_b = [2; VERSION_TOKEN_BYTES];
        let transport = ScriptTransport::new([
            Ok(response(201, token_a, b"")),
            Ok(response(200, token_a, b"first")),
            Ok(response(200, token_b, b"")),
            Ok(response(200, token_a, b"")),
        ]);
        let (runtime, cx) = test_runtime();
        let failure = run(
            &runtime,
            ObjectStoreAuthority::<ScriptTransport, CanonicalHmacSha256Signer>::probe(
                &cx,
                &transport,
                &signer(),
                &endpoint(),
                ProbeRunId::new([9; VERSION_TOKEN_BYTES]),
                VersionTokenProfile::Unique,
            ),
        )
        .expect_err("content ETag must be rejected");
        assert_eq!(failure, CapabilityProbeFailure::ContentDerivedVersionToken);
        assert_eq!(transport.requests().len(), 4);
    }

    #[test]
    fn probe_accepts_unique_tokens_only_after_stale_rejection_and_historical_read() {
        let token_a = [1; VERSION_TOKEN_BYTES];
        let token_b = [2; VERSION_TOKEN_BYTES];
        let token_c = [3; VERSION_TOKEN_BYTES];
        let transport = ScriptTransport::new([
            Ok(response(201, token_a, b"")),
            Ok(response(200, token_a, b"first")),
            Ok(response(200, token_b, b"")),
            Ok(response(200, token_c, b"")),
            Ok(response(412, token_c, b"")),
            Ok(response(200, token_a, b"first")),
        ]);
        let endpoint = endpoint();
        let (runtime, cx) = test_runtime();
        let receipt = run(
            &runtime,
            ObjectStoreAuthority::<ScriptTransport, CanonicalHmacSha256Signer>::probe(
                &cx,
                &transport,
                &signer(),
                &endpoint,
                ProbeRunId::new([8; VERSION_TOKEN_BYTES]),
                VersionTokenProfile::GenerationVerified,
            ),
        )
        .expect("unique provider profile is accepted");
        assert_eq!(receipt.profile(), VersionTokenProfile::GenerationVerified);
        let requests = transport.requests();
        assert_eq!(requests.len(), 6);
        assert_eq!(
            requests[4].headers.get(IF_MATCH),
            Some(&hex_encode(&token_a))
        );
        assert!(requests[5].url.contains("fgit-version-token="));
    }

    #[test]
    fn probe_refuses_endpoint_that_accepts_stale_conditional_write() {
        let token_a = [1; VERSION_TOKEN_BYTES];
        let token_b = [2; VERSION_TOKEN_BYTES];
        let token_c = [3; VERSION_TOKEN_BYTES];
        let transport = ScriptTransport::new([
            Ok(response(201, token_a, b"")),
            Ok(response(200, token_a, b"first")),
            Ok(response(200, token_b, b"")),
            Ok(response(200, token_c, b"")),
            Ok(response(200, [4; VERSION_TOKEN_BYTES], b"")),
        ]);
        let (runtime, cx) = test_runtime();
        let failure = run(
            &runtime,
            ObjectStoreAuthority::<ScriptTransport, CanonicalHmacSha256Signer>::probe(
                &cx,
                &transport,
                &signer(),
                &endpoint(),
                ProbeRunId::new([7; VERSION_TOKEN_BYTES]),
                VersionTokenProfile::Unique,
            ),
        )
        .expect_err("stale precondition acceptance is unsafe");
        assert_eq!(
            failure,
            CapabilityProbeFailure::ConditionalWritesUnavailable
        );
    }

    #[test]
    fn cancelled_context_stops_before_probe_transmission() {
        let transport = ScriptTransport::new([]);
        let (runtime, cx) = test_runtime();
        cx.cancel_fast(CancelKind::User);
        let failure = run(
            &runtime,
            ObjectStoreAuthority::<ScriptTransport, CanonicalHmacSha256Signer>::probe(
                &cx,
                &transport,
                &signer(),
                &endpoint(),
                ProbeRunId::new([11; VERSION_TOKEN_BYTES]),
                VersionTokenProfile::Unique,
            ),
        )
        .expect_err("cancelled context cannot start network I/O");
        assert_eq!(
            failure,
            CapabilityProbeFailure::Ambiguous(AmbiguityReason::Cancelled)
        );
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn conditional_store_double_exercises_the_full_authority_adapter_without_listing() {
        let transport = ConditionalStoreTestDouble::default();
        let endpoint = endpoint();
        let (runtime, cx) = test_runtime();
        let capability = run(
            &runtime,
            ObjectStoreAuthority::<ConditionalStoreTestDouble, CanonicalHmacSha256Signer>::probe(
                &cx,
                &transport,
                &signer(),
                &endpoint,
                ProbeRunId::new([4; VERSION_TOKEN_BYTES]),
                VersionTokenProfile::Unique,
            ),
        )
        .expect("test conditional store has the required profile");
        let adapter = ObjectStoreAuthority::new(
            transport,
            signer(),
            endpoint,
            capability,
            StoreInstanceId::from_raw(31),
            AuthorityLimits::default(),
        )
        .expect("capability receipt binds this endpoint");

        let immutable = ImmutableKey::new(b"body/key".to_vec()).expect("key");
        assert_eq!(
            run(
                &runtime,
                adapter.put_if_absent(&cx, &immutable, b"immutable")
            ),
            Ok(PutOutcome::Created)
        );
        assert_eq!(
            run(
                &runtime,
                adapter.put_if_absent(&cx, &immutable, b"immutable")
            ),
            Ok(PutOutcome::IdenticalRetry)
        );
        assert_eq!(
            run(
                &runtime,
                adapter.put_if_absent(&cx, &immutable, b"different")
            ),
            Ok(PutOutcome::Conflict)
        );
        assert_eq!(
            run(&runtime, adapter.read_immutable(&cx, &immutable)),
            Ok(ImmutableRead::Present(b"immutable".to_vec()))
        );

        let head = HeadKey::new(b"repo/head".to_vec()).expect("key");
        let first = match run(
            &runtime,
            adapter.initialize_head(&cx, &head, HeadGeneration::FIRST, b"head-v1"),
        )
        .expect("initial head")
        {
            HeadInit::Created(receipt) => receipt,
            other => panic!("expected head creation, got {other:?}"),
        };
        assert_eq!(
            run(&runtime, adapter.authenticate_head_receipt(&cx, &first)),
            Ok(AuthenticatedHead::new(
                first.clone(),
                StoreInstanceId::from_raw(31)
            ))
        );
        let second = match run(
            &runtime,
            adapter.compare_exchange_head(
                &cx,
                &head,
                first.token(),
                HeadGeneration::try_new(2).expect("generation"),
                b"head-v2",
            ),
        )
        .expect("CAS")
        {
            CasOutcome::Committed(receipt) => receipt,
            other => panic!("expected committed head, got {other:?}"),
        };
        assert_eq!(
            second.generation(),
            HeadGeneration::try_new(2).expect("generation")
        );
        assert_eq!(
            run(&runtime, adapter.authenticate_head_receipt(&cx, &first)),
            Ok(AuthenticatedHead::new(
                first.clone(),
                StoreInstanceId::from_raw(31)
            )),
            "a stale receipt remains authentic even after the head advances"
        );
        assert_eq!(
            run(
                &runtime,
                adapter.compare_exchange_head(
                    &cx,
                    &head,
                    first.token(),
                    HeadGeneration::try_new(3).expect("generation"),
                    b"must-not-publish",
                )
            ),
            Ok(CasOutcome::PredecessorMismatch)
        );

        let outcome = ImmutableKey::new(b"outcome/tx-1".to_vec()).expect("key");
        let requests_before_publish = adapter.transport.requests().len();
        assert_eq!(
            run(
                &runtime,
                adapter.publish_head_with_outcomes(
                    &cx,
                    &head,
                    second.token(),
                    HeadGeneration::try_new(3).expect("generation"),
                    b"head-v3",
                    &[(outcome.clone(), b"terminal-outcome".to_vec())],
                )
            ),
            Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable)),
            "the adapter must refuse instead of synthesizing a non-atomic publication"
        );
        assert_eq!(
            adapter.transport.requests().len(),
            requests_before_publish,
            "the atomic-publication refusal must not transmit a partial head or outcome write"
        );
        assert_eq!(
            run(&runtime, adapter.read_immutable(&cx, &outcome)),
            Ok(ImmutableRead::Absent),
            "no refused outcome object may become durable"
        );
        assert_eq!(
            run(&runtime, adapter.read_head(&cx, &head)),
            Ok(HeadRead::Present(second)),
            "no refused atomic publication may advance the authority head"
        );

        let requests = adapter.transport.requests();
        assert!(
            requests
                .iter()
                .all(|request| !request.url.contains("?list"))
        );
        assert!(
            requests
                .iter()
                .all(|request| request.headers.contains_key(AUTHORIZATION))
        );
    }

    #[test]
    fn cas_never_retries_ambiguous_mutation_and_requires_token_history() {
        let token_a = [1; VERSION_TOKEN_BYTES];
        let transport = ScriptTransport::new([
            Ok(response(201, token_a, b"")),
            Ok(response(200, token_a, b"first")),
            Ok(response(200, [2; VERSION_TOKEN_BYTES], b"")),
            Ok(response(200, [3; VERSION_TOKEN_BYTES], b"")),
            Ok(response(412, [3; VERSION_TOKEN_BYTES], b"")),
            Ok(response(200, token_a, b"first")),
            Ok(head_response(200, token_a, 1, b"old")),
            Err(ObjectStoreTransportError::Ambiguous(
                AmbiguityReason::Timeout,
            )),
        ]);
        let endpoint = endpoint();
        let (runtime, cx) = test_runtime();
        let receipt = run(
            &runtime,
            ObjectStoreAuthority::<ScriptTransport, CanonicalHmacSha256Signer>::probe(
                &cx,
                &transport,
                &signer(),
                &endpoint,
                ProbeRunId::new([6; VERSION_TOKEN_BYTES]),
                VersionTokenProfile::Unique,
            ),
        )
        .expect("probe works");
        let adapter = ObjectStoreAuthority::new(
            transport,
            signer(),
            endpoint,
            receipt,
            StoreInstanceId::from_raw(17),
            AuthorityLimits::default(),
        )
        .expect("adapter construction");
        let key = HeadKey::new(b"repo/head".to_vec()).expect("key");
        let result = run(
            &runtime,
            adapter.compare_exchange_head(
                &cx,
                &key,
                AuthorityVersionToken::from_opaque_bytes(token_a),
                HeadGeneration::try_new(2).expect("generation"),
                b"new",
            ),
        );
        assert_eq!(
            result,
            Err(AuthorityFailure::Ambiguous(AmbiguityReason::Timeout))
        );
        let requests = adapter.transport.requests();
        assert_eq!(
            requests.len(),
            8,
            "one historic read and one mutation; no retry"
        );
        assert_eq!(requests[7].method, ObjectStoreMethod::Put);
    }

    #[test]
    fn receipt_authentication_reads_the_historical_version_and_refuses_tampering() {
        let token_a = [1; VERSION_TOKEN_BYTES];
        let token_b = [2; VERSION_TOKEN_BYTES];
        let token_c = [3; VERSION_TOKEN_BYTES];
        let transport = ScriptTransport::new([
            Ok(response(201, token_a, b"")),
            Ok(response(200, token_a, b"first")),
            Ok(response(200, token_b, b"")),
            Ok(response(200, token_c, b"")),
            Ok(response(412, token_c, b"")),
            Ok(response(200, token_a, b"first")),
            Ok(head_response(200, token_a, 1, b"canonical")),
        ]);
        let endpoint = endpoint();
        let (runtime, cx) = test_runtime();
        let receipt = run(
            &runtime,
            ObjectStoreAuthority::<ScriptTransport, CanonicalHmacSha256Signer>::probe(
                &cx,
                &transport,
                &signer(),
                &endpoint,
                ProbeRunId::new([5; VERSION_TOKEN_BYTES]),
                VersionTokenProfile::Unique,
            ),
        )
        .expect("probe works");
        let adapter = ObjectStoreAuthority::new(
            transport,
            signer(),
            endpoint,
            receipt,
            StoreInstanceId::from_raw(23),
            AuthorityLimits::default(),
        )
        .expect("adapter construction");
        let key = HeadKey::new(b"repo/head".to_vec()).expect("key");
        let forged = HeadReadReceipt::new(
            key,
            AuthorityVersionToken::from_opaque_bytes(token_a),
            HeadGeneration::try_new(1).expect("generation"),
            b"altered".to_vec(),
        );
        let result = run(&runtime, adapter.authenticate_head_receipt(&cx, &forged));
        assert_eq!(
            result,
            Err(AuthorityFailure::Refused(
                AuthorityRefusal::TokenBodyMismatch
            ))
        );
        assert_eq!(adapter.transport.requests().len(), 7);
    }
}
