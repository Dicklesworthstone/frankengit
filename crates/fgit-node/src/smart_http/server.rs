//! Bounded, single-repository HTTP gateway (frankengit-asa3).
//!
//! This is an explicit loopback capability profile, not organization/team IAM.
//! Operators grant principals independent Git, issue, PR and outcome scopes
//! through token credentials (Bearer or Basic token-as-password). TLS
//! terminates outside this listener; forwarded
//! headers never authenticate. Git RPCs stream to native machines; metadata
//! forms have a separate small envelope. Outcome queries never mutate state.

mod browser;
mod credentials;
mod issues;
mod lifetime;
mod outcomes;
mod pulls;
mod source;
mod stock_receive;

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fgit_authority::IdempotencyKey;
use fgit_types::PrincipalId;
use fgit_types::cell::CellState;
use fgit_wire::WireLimits;
use fgit_wire::smart_http::rpc::RpcError;
use fgit_wire::smart_http::{
    HttpError, HttpLimits, HttpVersion, Operation, RequestHead, Service, head, parse_head,
};

use super::NodeSmartHttpRefusal;
use crate::{
    DeadlineTcpStream, GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionDeadline,
    GitDaemonSessionTimeout, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    MAX_CONCURRENT_WRITERS, NodeConfig, NodeRefusal, OneNode, PushQuota, WriterGate,
};
use credentials::{Binding, CredentialFailure, CredentialSource};

// Offer Basic first so ordinary Git credential helpers can negotiate a token
// password. Both schemes authenticate through the SAME digest/grant lookup.
// This profile remains loopback-only; neither scheme replaces external TLS.
const AUTHENTICATION_CHALLENGES: &str = concat!(
    "WWW-Authenticate: Basic realm=\"frankengit\", charset=\"UTF-8\"\r\n",
    "WWW-Authenticate: Bearer realm=\"frankengit\"\r\n",
);

const IO_CHUNK: usize = 16 * 1024;
const MAX_IN_FLIGHT: usize = 16;
const MAX_SESSIONS: usize = 1_000_000;
const FRAMING_ALLOWANCE: u64 = 4 * 1024 * 1024;

#[derive(Clone)]
struct Profile {
    config: NodeConfig,
    route: Vec<u8>,
    credentials: CredentialSource,
    allow_receive: bool,
    allow_issues: bool,
    allow_outcomes: bool,
    allow_pulls: bool,
    allow_source: bool,
    http: HttpLimits,
    maximum_response_bytes: u64,
    timeout: GitDaemonSessionTimeout,
    quota: Arc<PushQuota>,
    outcome_quota: Arc<PushQuota>,
    source_quota: Arc<PushQuota>,
    writers: Arc<WriterGate>,
}

struct PendingSession {
    finished: Arc<AtomicBool>,
    join: Box<dyn FnOnce()>,
}

// A panicking or never-submitted worker still settles its accepted connection.
// The flag is published only after node shutdown and bounded socket cleanup.
struct Completion {
    finished: Arc<AtomicBool>,
    completed: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
    success: bool,
}
impl Drop for Completion {
    fn drop(&mut self) {
        if self.success {
            self.completed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        self.finished.store(true, Ordering::Release);
    }
}

impl OneNode {
    /// Serve authenticated Smart HTTP on a loopback listener, then drain it.
    ///
    /// `credential_digest` is SHA-256 of an operator-provisioned 64-character
    /// lowercase hexadecimal bearer secret. It grants access ONLY to this
    /// repository incarnation and principal. The same token can be supplied as
    /// a Basic password through an ordinary Git credential helper. Basic
    /// usernames are nonempty UTF-8, at most 256 bytes, with no ASCII control
    /// characters; they never select a principal or grant additional scopes.
    /// Receive discovery and RPC are
    /// disabled unless `allow_receive` is explicitly true. Stock Git discovery
    /// selects an attempt-scoped URL carrying a stable retry key; its RPC still
    /// authenticates independently. Explicit `Idempotency-Key` clients retain
    /// their existing route and canonical outcome-recovery contract.
    ///
    /// This local capability profile does not implement organization/team IAM
    /// or TLS. Non-loopback listeners are refused. Forwarded identity headers
    /// never convey authority. HTTP connections are not reused. Native issue,
    /// PR and outcome endpoints remain disabled on this compatible entry point.
    ///
    /// RPC ingress is incremental: fixed-size read buffers feed the native
    /// machines directly. Receive-pack owns its bounded quarantine, not a
    /// second gateway body copy. Pack responses are streamed. At most 16
    /// connections run on the node's Asupersync blocking pool. Every accepted
    /// child is joined before return, including on accept/scheduling failure.
    ///
    /// Acceptance ends at the request limit or an idle window without active
    /// work. Completed requests start a fresh idle window for follow-up fetches.
    /// Refused transport counts never constitute evidence of non-commit.
    pub fn serve_smart_http_bounded(
        &self,
        listener: &TcpListener,
        server_limits: GitDaemonServerLimits,
        credential_digest: [u8; 32],
        principal: PrincipalId,
        allow_receive: bool,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_bounded(
            listener,
            server_limits,
            CredentialSource::Static {
                digest: credential_digest,
                principal,
            },
            allow_receive,
            false,
            false,
            false,
            false,
            idle_timeout,
        )
    }

    /// Validate an operator credential table against this exact node before
    /// reporting listener readiness. This does not cache or activate a table.
    pub fn validate_smart_http_credentials_file(
        &self,
        path: &Path,
    ) -> Result<(), NodeSmartHttpRefusal> {
        self.smart_http_credentials_source(path)
            .validate()
            .map_err(credential_error)
    }

    /// Serve multiple explicitly granted principals on the same bounded node.
    ///
    /// The private regular file starts with
    /// `frankengit-http-credentials-v1 <tenant> <repository> <incarnation>`.
    /// Each following line is `<sha256-of-token> <principal> <scopes>`. Git
    /// scopes are `read` and `receive`; metadata scopes are independent. This
    /// entry point leaves metadata endpoints disabled even if grants exist.
    /// IDs and digests are lowercase hex. At most 256 grants and 64 KiB are
    /// accepted. A header without rows revokes all credentials. `allow_receive`
    /// remains a mandatory ceiling for individually receive-enabled grants.
    ///
    /// The file is re-read for EVERY authentication. Replace it atomically to
    /// rotate tokens, change scopes, or revoke access without restarting.
    /// Missing/malformed/foreign-incarnation files fail closed without cached
    /// grants. Already authenticated requests retain their bounded grant; this
    /// is not instant revocation of in-flight publication or a canonical IAM
    /// service. Receive scope permits push discovery but does not imply fetch.
    pub fn serve_smart_http_with_credentials_file_bounded(
        &self,
        listener: &TcpListener,
        server_limits: GitDaemonServerLimits,
        credentials_file: &Path,
        allow_receive: bool,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_bounded(
            listener,
            server_limits,
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            false,
            false,
            false,
            false,
            idle_timeout,
        )
    }

    /// Explicitly enable the native issue API alongside the Git endpoints.
    ///
    /// GET `{repository-route}/api/v1/issues` lists head-pinned issue state;
    /// GET `.../issues/{number}` pages its exact event/comment history.
    /// POST `.../issues/{number}/{open|edit|close|reopen|comment}` accepts a
    /// bounded URL-encoded form with an explicit expected_version and an
    /// Idempotency-Key header. Replies are JSON. The principal comes only
    /// from this repository-incarnation-bound credential table.
    ///
    /// `issues-read` and `issues-write` are explicit independent grants; neither
    /// Git permission grants either, and issue write does not imply issue read.
    /// Git pushes still require allow_receive. This is repository-wide issue
    /// access, not per-issue ACLs, account administration, or TLS. Outcome and
    /// PR queries remain disabled on this backward-compatible entry point.
    pub fn serve_git_and_issue_http_with_credentials_file_bounded(
        &self,
        listener: &TcpListener,
        server_limits: GitDaemonServerLimits,
        credentials_file: &Path,
        allow_receive: bool,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_bounded(
            listener,
            server_limits,
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            true,
            false,
            false,
            false,
            idle_timeout,
        )
    }

    /// Select independent Git-write, issue, and read-only recovery endpoints.
    ///
    /// Outcome lookup is a bodyless POST to `.../api/v1/outcomes` with the
    /// ORIGINAL Idempotency-Key. A non-atomic receive command is selected by
    /// `.../api/v1/outcomes/receive/{zero-based-wire-index}`. Only an explicit
    /// `outcomes-read` grant permits either query, and only in that grant's
    /// principal namespace. This does not reveal another principal's results.
    ///
    /// Recovery uses a separate per-principal quota and requires no mutation
    /// permission. A read never re-seals or resubmits work, and nonterminal
    /// observations never prove non-commit. Existing entry points do not
    /// enable these endpoints implicitly. All listener/drain bounds still apply.
    /// PR endpoints remain disabled on this backward-compatible entry point.
    pub fn serve_repository_http_with_credentials_file_bounded(
        &self,
        listener: &TcpListener,
        server_limits: GitDaemonServerLimits,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_bounded(
            listener,
            server_limits,
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            allow_issues,
            allow_outcomes,
            false,
            false,
            idle_timeout,
        )
    }

    /// Explicitly enable same-repository native PR metadata alongside selected
    /// existing services. PR list/show use `pulls-read`; open/update/close use
    /// `pulls-write`. Neither grants Git, issue, recovery, review or merge rights.
    ///
    /// Requests carry complete explicit data, native object format, expected
    /// aggregate version and client Idempotency-Key. The node's existing sealed
    /// admission publishes the PR event and outbox obligation together, without
    /// changing any Git ref. Reads use retained snapshots and current hidden-ref
    /// policy. This local operator profile is not per-PR ACLs or hosted IAM.
    pub fn serve_repository_http_with_pull_requests_bounded(
        &self,
        listener: &TcpListener,
        server_limits: GitDaemonServerLimits,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_bounded(
            listener,
            server_limits,
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            allow_issues,
            allow_outcomes,
            true,
            false,
            idle_timeout,
        )
    }

    /// Enable source browsing, search, patch preparation and candidate inspection
    /// for read-scoped credentials. Applying a single-parent candidate additionally
    /// requires `allow_receive` and the token's independent receive grant; it uses
    /// native sealed admission and cannot turn a read grant into write authority.
    /// Current canonical hidden refs apply. Paths never select host files or
    /// arbitrary admitted objects. Reads have their own principal quota; source
    /// publication shares mutation quota. Older entrypoints keep source disabled.
    pub fn serve_repository_http_with_source_bounded(
        &self,
        listener: &TcpListener,
        server_limits: GitDaemonServerLimits,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_bounded(
            listener,
            server_limits,
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            allow_issues,
            allow_outcomes,
            allow_pulls,
            true,
            idle_timeout,
        )
    }

    fn smart_http_credentials_source(&self, path: &Path) -> CredentialSource {
        CredentialSource::File {
            path: path.to_path_buf(),
            binding: Binding {
                tenant: self.tenant_id,
                repository: self.repository_id,
                incarnation: self.repository_incarnation_id(),
            },
        }
    }

    fn serve_smart_http_with_source_bounded(
        &self,
        listener: &TcpListener,
        server_limits: GitDaemonServerLimits,
        credentials: CredentialSource,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        allow_source: bool,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            server_limits.max_in_flight(),
            credentials,
            allow_receive,
            allow_issues,
            allow_outcomes,
            allow_pulls,
            allow_source,
            lifetime::Acceptance::Bounded {
                max_sessions: server_limits.max_sessions(),
                idle_timeout,
            },
        )
    }

    fn serve_smart_http_with_source_lifetime(
        &self,
        listener: &TcpListener,
        max_in_flight: usize,
        credentials: CredentialSource,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        allow_source: bool,
        acceptance: lifetime::Acceptance<'_>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        let address = listener
            .local_addr()
            .map_err(|source| io_error("inspect HTTP listener", source))?;
        if !address.ip().is_loopback() {
            return Err(invalid_configuration(
                "Smart HTTP requires a loopback listener",
            ));
        }
        if self.cell_state() != CellState::Serving {
            return Err(invalid_configuration(
                "bring the HTTP node into service before listening",
            ));
        }
        if !(1..=MAX_IN_FLIGHT).contains(&max_in_flight) || !acceptance.valid() {
            return Err(invalid_configuration(
                "invalid bounded Smart HTTP service limits",
            ));
        }
        credentials.validate().map_err(credential_error)?;
        let maximum_body = u64::try_from(self.git_daemon_receive_limits.pack.max_input_bytes)
            .map_err(|_| invalid_configuration("HTTP input envelope is not representable"))?;
        let maximum_wire = maximum_body
            .checked_add(FRAMING_ALLOWANCE)
            .ok_or_else(|| invalid_configuration("HTTP wire envelope overflow"))?;
        let maximum_response_bytes =
            u64::try_from(self.selected_pack_limits.max_total_expanded_bytes)
                .ok()
                .and_then(|n| n.checked_mul(2))
                .and_then(|n| n.checked_add(FRAMING_ALLOWANCE))
                .ok_or_else(|| invalid_configuration("HTTP response envelope overflow"))?;
        let http = HttpLimits {
            max_body_bytes: maximum_body,
            max_body_wire_bytes: maximum_wire,
            ..HttpLimits::default()
        };
        http.validate()?;
        let profile = Arc::new(Profile {
            config: self
                .service_config
                .clone()
                .with_expected_repository_incarnation(self.repository_incarnation_id()),
            route: self.git_daemon_repository_path().as_bytes().to_vec(),
            credentials,
            allow_receive,
            allow_issues,
            allow_outcomes,
            allow_pulls,
            allow_source,
            http,
            maximum_response_bytes,
            timeout: self.git_daemon_session_timeout,
            quota: Arc::new(PushQuota::default()),
            outcome_quota: Arc::new(PushQuota::default()),
            source_quota: Arc::new(PushQuota::default()),
            writers: Arc::new(WriterGate::new(MAX_CONCURRENT_WRITERS)),
        });
        listener
            .set_nonblocking(true)
            .map_err(|source| io_error("configure HTTP listener", source))?;
        let completed = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let mut pending: Vec<PendingSession> = Vec::new();
        let mut accepted = 0;
        let mut last_activity = Instant::now();
        let mut failure = None;
        loop {
            let mut index = 0;
            while index < pending.len() {
                if pending[index].finished.load(Ordering::Acquire) {
                    (pending.swap_remove(index).join)();
                    last_activity = Instant::now();
                } else {
                    index += 1;
                }
            }
            // Check lifetime control even while all connection slots are full.
            // Stop/error retires acceptance, not the responsibility for any
            // accepted request. The common epilogue joins every child.
            match acceptance.keep_accepting(accepted, pending.len(), last_activity.elapsed()) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    failure = Some(io_error("poll HTTP service stop", error));
                    break;
                }
            }
            if pending.len() >= max_in_flight {
                self.runtime.wait_for(Duration::from_millis(1));
                continue;
            }
            let (stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.runtime.wait_for(Duration::from_millis(1));
                    continue;
                }
                Err(source) => {
                    failure = Some(io_error("accept Smart HTTP connection", source));
                    break;
                }
            };
            accepted += 1;
            last_activity = Instant::now();
            // Queue time counts against ingress: a queued peer does not acquire
            // a new wall-clock allowance when a blocking worker becomes free.
            let deadline =
                GitDaemonSessionDeadline::new(profile.timeout, GitDaemonSessionWorkScaling::FLAT);
            let finished = Arc::new(AtomicBool::new(false));
            let completion = Completion {
                finished: Arc::clone(&finished),
                completed: Arc::clone(&completed),
                refused: Arc::clone(&refused),
                success: false,
            };
            let child_profile = Arc::clone(&profile);
            match self.runtime.submit_blocking(move || {
                let mut completion = completion;
                completion.success = serve_connection(stream, deadline, &child_profile);
            }) {
                Ok(task) => pending.push(PendingSession {
                    finished,
                    join: Box::new(move || {
                        task.wait();
                    }),
                }),
                Err(error) => {
                    failure = Some(io_error(
                        "schedule Smart HTTP connection",
                        io::Error::other(error.to_string()),
                    ));
                    break;
                }
            }
        }
        for child in pending {
            (child.join)();
        }
        let restored = listener
            .set_nonblocking(false)
            .map_err(|source| io_error("restore HTTP listener", source));
        if let Some(error) = failure {
            if let Err(cleanup) = restored {
                return Err(io_error(
                    "HTTP listener cleanup after service failure",
                    io::Error::other(format!("{error}; {cleanup}")),
                ));
            }
            return Err(error);
        }
        restored?;
        let completed_sessions = completed.load(Ordering::Acquire);
        let refused_sessions = refused.load(Ordering::Acquire);
        if completed_sessions.checked_add(refused_sessions) != Some(accepted) {
            return Err(invalid_configuration(
                "HTTP service did not settle every accepted child",
            ));
        }
        Ok(GitDaemonServerReceipt {
            accepted_sessions: accepted,
            completed_sessions,
            refused_sessions,
        })
    }
}

fn credential_error(error: CredentialFailure) -> NodeSmartHttpRefusal {
    io_error("load Smart HTTP credentials", io::Error::other(error))
}
fn invalid_configuration(message: &'static str) -> NodeSmartHttpRefusal {
    io_error(
        "configure Smart HTTP service",
        io::Error::new(io::ErrorKind::InvalidInput, message),
    )
}
const fn io_error(operation: &'static str, source: io::Error) -> NodeSmartHttpRefusal {
    NodeSmartHttpRefusal::Io { operation, source }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Status {
    Success,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    TooLarge,
    HeaderTooLarge,
    MediaType,
    Method,
    Expectation,
    Timeout,
    RateLimited,
    Unavailable,
}
impl Status {
    const fn line(self) -> &'static str {
        match self {
            Self::Success => "200 OK",
            Self::BadRequest => "400 Bad Request",
            Self::Unauthorized => "401 Unauthorized",
            Self::Forbidden => "403 Forbidden",
            Self::NotFound => "404 Not Found",
            Self::Conflict => "409 Conflict",
            Self::TooLarge => "413 Content Too Large",
            Self::HeaderTooLarge => "431 Request Header Fields Too Large",
            Self::MediaType => "415 Unsupported Media Type",
            Self::Method => "405 Method Not Allowed",
            Self::Expectation => "417 Expectation Failed",
            Self::Timeout => "408 Request Timeout",
            Self::RateLimited => "429 Too Many Requests",
            Self::Unavailable => "503 Service Unavailable",
        }
    }
}
impl From<CredentialFailure> for Status {
    fn from(error: CredentialFailure) -> Self {
        match error {
            CredentialFailure::UnknownCredential => Self::Unauthorized,
            _ => Self::Unavailable,
        }
    }
}
impl From<HttpError> for Status {
    fn from(error: HttpError) -> Self {
        match error {
            HttpError::BodyTooLarge | HttpError::WireBudgetExceeded | HttpError::TooManyChunks => {
                Self::TooLarge
            }
            HttpError::HeadTooLarge | HttpError::TooManyHeaders => Self::HeaderTooLarge,
            HttpError::UnsupportedMediaType | HttpError::UnsupportedContentEncoding => {
                Self::MediaType
            }
            HttpError::UnsupportedExpectation => Self::Expectation,
            HttpError::MethodNotAllowed => Self::Method,
            HttpError::InvalidRoute => Self::NotFound,
            _ => Self::BadRequest,
        }
    }
}
impl From<io::Error> for Status {
    fn from(error: io::Error) -> Self {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            Self::Timeout
        } else {
            Self::BadRequest
        }
    }
}
impl From<NodeSmartHttpRefusal> for Status {
    fn from(error: NodeSmartHttpRefusal) -> Self {
        match error {
            NodeSmartHttpRefusal::Http(error) => Self::from(*error),
            NodeSmartHttpRefusal::TrailingRequestBytes { .. } => Self::BadRequest,
            NodeSmartHttpRefusal::UnauthenticatedReceive => Self::Unauthorized,
            NodeSmartHttpRefusal::RepositoryRouteMismatch => Self::NotFound,
            NodeSmartHttpRefusal::Rpc(error) => match *error {
                RpcError::Http(error) => Self::from(error),
                RpcError::Cancelled => Self::Timeout,
                RpcError::Wire(_)
                | RpcError::Receive(_)
                | RpcError::WrongOperation
                | RpcError::IncompleteRequest
                | RpcError::MultipleCommands
                | RpcError::FailedRequest => Self::BadRequest,
                _ => Self::Unavailable,
            },
            NodeSmartHttpRefusal::Io {
                operation: "read smart HTTP body",
                source,
            } => Self::from(source),
            // Admission errors can follow transmission or partial non-atomic
            // publication. Never classify those as proof of a rejected push.
            _ => Self::Unavailable,
        }
    }
}

fn authenticated_session(
    request: &RequestHead<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<LoopbackReceiveSession, Status> {
    let grant = profile
        .credentials
        .authenticate(request.authorization())
        .map_err(Status::from)?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(Status::NotFound);
    }
    if !grant.permits(request.operation.service())
        || (request.operation.service() == Service::ReceivePack && !profile.allow_receive)
    {
        return Err(Status::Forbidden);
    }
    let key = retry_key(raw_head)?;
    let key = if request.operation == Operation::Rpc(Service::ReceivePack) {
        key.ok_or(Status::BadRequest)?
    } else {
        b"smart-http-discovery-no-publication".as_slice()
    };
    let key = IdempotencyKey::new(key.to_vec()).map_err(|_| Status::BadRequest)?;
    Ok(LoopbackReceiveSession::authenticated(grant.principal, key))
}

fn retry_key(raw_head: &[u8]) -> Result<Option<&[u8]>, Status> {
    let text = std::str::from_utf8(raw_head).map_err(|_| Status::BadRequest)?;
    let mut key = None;
    for line in text
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
    {
        let (name, value) = line.split_once(':').ok_or(Status::BadRequest)?;
        if name.eq_ignore_ascii_case("Idempotency-Key") {
            let value = value.trim_matches([' ', '\t']).as_bytes();
            if key.is_some()
                || value.is_empty()
                || value.len() > 128
                || !value.iter().all(u8::is_ascii_graphic)
            {
                return Err(Status::BadRequest);
            }
            key = Some(value);
        }
        if name.eq_ignore_ascii_case("Connection")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("Idempotency-Key"))
        {
            return Err(Status::BadRequest);
        }
    }
    Ok(key)
}

fn append_bounded(target: &mut Vec<u8>, bytes: &[u8], maximum: u64) -> Result<(), Status> {
    let next = target
        .len()
        .checked_add(bytes.len())
        .ok_or(Status::TooLarge)?;
    let maximum = usize::try_from(maximum).unwrap_or(usize::MAX);
    if next > maximum {
        return Err(Status::TooLarge);
    }
    if next > target.capacity() {
        let capacity = next.max(target.capacity().saturating_mul(2)).min(maximum);
        target
            .try_reserve_exact(capacity - target.len())
            .map_err(|_| Status::Unavailable)?;
    }
    target.extend_from_slice(bytes);
    Ok(())
}

fn read_head(reader: &mut impl Read, limits: HttpLimits) -> Result<Vec<u8>, Status> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; IO_CHUNK];
    loop {
        if head::parse(&bytes, limits)?.is_some() {
            return Ok(bytes);
        }
        let count = buffer
            .len()
            .min(limits.max_head_bytes.saturating_sub(bytes.len()));
        if count == 0 {
            return Err(Status::HeaderTooLarge);
        }
        let read = match reader.read(&mut buffer[..count]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            return Err(Status::BadRequest);
        }
        append_bounded(&mut bytes, &buffer[..read], limits.max_head_bytes as u64)?;
    }
}

struct ResponseWriter<'a> {
    inner: DeadlineTcpStream<'a>,
    timeout: GitDaemonSessionTimeout,
    started: bool,
}
impl Write for ResponseWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.started {
            self.inner.restart_deadline(GitDaemonSessionDeadline::new(
                self.timeout,
                GitDaemonSessionWorkScaling::FLAT,
            ));
            self.started = true;
        }
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn write_error(writer: &mut impl Write, version: HttpVersion, status: Status) -> io::Result<()> {
    let version = match version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    let body = if status == Status::Unavailable {
        "repository operation unavailable; a push may already be committed; retry with the same Idempotency-Key\n"
    } else {
        "Smart HTTP request refused\n"
    };
    let extra = match status {
        Status::Unauthorized => AUTHENTICATION_CHALLENGES,
        Status::RateLimited => "Retry-After: 60\r\n",
        Status::Method => "Allow: GET, POST\r\n",
        _ => "",
    };
    write!(
        writer,
        "{version} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{extra}\r\n{body}",
        status.line(),
        body.len()
    )?;
    writer.flush()
}

fn serve_connection(
    mut stream: TcpStream,
    deadline: GitDaemonSessionDeadline,
    profile: &Profile,
) -> bool {
    if stream.set_nonblocking(false).is_err() {
        return false;
    }
    let Ok(mut output) = stream.try_clone() else {
        return false;
    };
    let admission_deadline = deadline.clone();
    let mut reader = DeadlineTcpStream::new(&mut stream, deadline.clone());
    let mut writer = ResponseWriter {
        inner: DeadlineTcpStream::new(&mut output, deadline),
        timeout: profile.timeout,
        started: false,
    };
    let mut version = HttpVersion::Http11;
    let mut native = false;
    let mut native_mutation = false;
    let mut pull_api = false;
    let mut source_api = false;
    let mut api_error = None;
    let mut recovery = false;
    let mut recovery_error = None;
    let served = (|| -> Result<(), Status> {
        let bytes = read_head(&mut reader, profile.http)?;
        let Some(bytes) = stock_receive::adapt(bytes, profile, &mut version, &mut writer)? else {
            return Ok(());
        };
        let envelope = head::parse(&bytes, profile.http)?.ok_or(Status::BadRequest)?;
        version = envelope.version;
        if browser::serve(profile, &envelope, &bytes[envelope.consumed..], &mut writer)? {
            return Ok(());
        }
        recovery = envelope
            .target
            .split('?')
            .next()
            .is_some_and(|path| path.contains("/api/v1/outcomes"));
        if recovery {
            // This read-only child has no mutation intake/Serving transition.
            // It uses its own scoped quota and always closes before returning.
            return outcomes::serve(
                profile,
                &envelope,
                &bytes[..envelope.consumed],
                &bytes[envelope.consumed..],
                &mut writer,
            )
            .map_err(|error| {
                recovery_error = Some(error);
                error.status
            });
        }
        source_api = envelope
            .target
            .split('?')
            .next()
            .is_some_and(|path| path.contains("/api/v1/source"));
        pull_api = envelope
            .target
            .split('?')
            .next()
            .is_some_and(|path| path.contains("/api/v1/pulls"));
        native = source_api
            || pull_api
            || envelope
                .target
                .split('?')
                .next()
                .is_some_and(|path| path.contains("/api/v1/issues"));
        native_mutation = native && envelope.method == "POST" && !source_api;
        let source_request = if source_api {
            Some(source::Request::parse(&envelope).map_err(|error| {
                api_error = Some(error);
                error.status
            })?)
        } else {
            None
        };
        if let Some(request) = &source_request {
            native_mutation = request.is_mutation();
        }
        let pull_request = if source_request.is_none() {
            pulls::Request::parse(&envelope).map_err(|error| {
                api_error = Some(error);
                error.status
            })?
        } else {
            None
        };
        if let Some(request) = &pull_request {
            native_mutation = request.is_mutation();
        }
        let issue_request = if source_request.is_none() && pull_request.is_none() {
            issues::Request::parse(&envelope).map_err(|error| {
                api_error = Some(error);
                error.status
            })?
        } else {
            None
        };
        let git_request =
            if source_request.is_none() && issue_request.is_none() && pull_request.is_none() {
                Some(parse_head(&bytes, profile.http)?.ok_or(Status::BadRequest)?)
            } else {
                None
            };
        let session =
            if let Some(request) = &source_request {
                source::authenticate(request, &envelope, &bytes[..envelope.consumed], profile)
                    .map_err(|error| {
                        api_error = Some(error);
                        error.status
                    })?
            } else if let Some(request) = &pull_request {
                pulls::authenticate(request, &envelope, &bytes[..envelope.consumed], profile)
                    .map_err(|error| {
                        api_error = Some(error);
                        error.status
                    })?
            } else if let Some(request) = &issue_request {
                issues::authenticate(request, &envelope, &bytes[..envelope.consumed], profile)
                    .map_err(|error| {
                        api_error = Some(error);
                        error.status
                    })?
            } else {
                authenticated_session(
                    git_request.as_ref().ok_or(Status::BadRequest)?,
                    &bytes[..envelope.consumed],
                    profile,
                )?
            };
        let mutation = native_mutation
            || git_request
                .as_ref()
                .is_some_and(|request| request.operation == Operation::Rpc(Service::ReceivePack));
        if source_request.is_some() && !mutation {
            let principal = session
                .authenticated_session()
                .ok_or(Status::Unauthorized)?
                .principal_id();
            profile
                .source_quota
                .evaluate(&principal)
                .map_err(|_| Status::RateLimited)?;
        } else if mutation
            || pull_request
                .as_ref()
                .is_some_and(|request| request.accepts_body())
        {
            // Source browsing/search must not consume mutation or recovery quotas.
            let principal = session
                .authenticated_session()
                .ok_or(Status::Unauthorized)?
                .principal_id();
            profile
                .quota
                .evaluate(&principal)
                .map_err(|_| Status::RateLimited)?;
        }
        if envelope.expect_continue && envelope.version == HttpVersion::Http10 {
            return Err(Status::Expectation);
        }
        // Held until this connection's response is complete. A writer that
        // cannot be admitted within its own deadline was admitted to nothing,
        // so it is told to retry later rather than that its outcome is unknown.
        let _writer = if mutation
            || pull_request
                .as_ref()
                .is_some_and(|request| request.accepts_body())
        {
            Some(
                profile
                    .writers
                    .acquire(&admission_deadline)
                    .ok_or(Status::RateLimited)?,
            )
        } else {
            None
        };
        let initial = &bytes[envelope.consumed..];
        let body_not_allowed = pull_request
            .as_ref()
            .is_some_and(|request| !request.accepts_body())
            || issue_request
                .as_ref()
                .is_some_and(|request| !request.is_mutation())
            || git_request
                .as_ref()
                .is_some_and(|request| matches!(request.operation, Operation::Discover(_)));
        if body_not_allowed && !initial.is_empty() {
            return Err(Status::BadRequest);
        }
        let mut node = OneNode::open_existing(profile.config.clone()).map_err(|error| {
            eprintln!("Smart HTTP could not open the repository node: {error}");
            Status::Unavailable
        })?;
        let result = (|| -> Result<(), Status> {
            let authenticated = node
                .runtime()
                .block_on(node.authenticate_authority_head())
                .map_err(|error| {
                    eprintln!("Smart HTTP could not authenticate the authority head: {error}");
                    Status::Unavailable
                })?;
            node.bring_into_service(authenticated.receipt().generation())
                .map_err(|error| {
                    eprintln!("Smart HTTP could not bring the node into service: {error}");
                    Status::Unavailable
                })?;
            if envelope.expect_continue {
                // No interim success before credentials, scopes, incarnation,
                // endpoint envelope policy and node intake have all passed.
                writer.inner.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                writer.inner.flush()?;
            }
            let mut body = io::Cursor::new(initial).chain(&mut reader);
            if let Some(request) = &source_request {
                let reply = source::execute(
                    &node,
                    request,
                    &session,
                    envelope.body,
                    &mut body,
                    profile.http,
                    profile.maximum_response_bytes,
                )
                .map_err(|error| {
                    api_error = Some(error);
                    error.status
                })?;
                reply
                    .send(&mut writer, version)
                    .map_err(|_| Status::Unavailable)?;
            } else if let Some(request) = &pull_request {
                let reply = pulls::execute(
                    &node,
                    request,
                    &session,
                    envelope.body,
                    &mut body,
                    profile.http,
                    profile.maximum_response_bytes,
                )
                .map_err(|error| {
                    api_error = Some(error);
                    error.status
                })?;
                reply
                    .send(&mut writer, version)
                    .map_err(|_| Status::Unavailable)?;
            } else if let Some(request) = &issue_request {
                let reply = issues::execute(
                    &node,
                    request,
                    &session,
                    envelope.body,
                    &mut body,
                    profile.http,
                    profile.maximum_response_bytes,
                )
                .map_err(|error| {
                    api_error = Some(error);
                    error.status
                })?;
                reply
                    .send(&mut writer, version)
                    .map_err(|_| Status::Unavailable)?;
            } else {
                let request = git_request.as_ref().ok_or(Status::BadRequest)?;
                let mut live = || true;
                let git_result = (|| -> Result<(), NodeSmartHttpRefusal> {
                    match request.operation {
                        Operation::Discover(service) => {
                            let discovery = match service {
                                Service::UploadPack => node.smart_http_upload_discovery_in(
                                    request,
                                    WireLimits::default(),
                                )?,
                                Service::ReceivePack => node.smart_http_receive_discovery_in(
                                    request,
                                    &session,
                                    WireLimits::default(),
                                )?,
                            };
                            writer
                                .write_all(discovery.head().as_bytes())
                                .map_err(|source| io_error("write HTTP discovery head", source))?;
                            writer
                                .write_all(discovery.body())
                                .map_err(|source| io_error("write HTTP discovery body", source))?;
                        }
                        Operation::Rpc(Service::UploadPack) => {
                            node.smart_http_upload_stream_in(
                                request,
                                &mut body,
                                WireLimits::default(),
                                profile.http,
                                profile.maximum_response_bytes,
                                &mut live,
                                &mut writer,
                            )?;
                        }
                        Operation::Rpc(Service::ReceivePack) => {
                            let _outcome = node.smart_http_receive_stream_in(
                                request,
                                &session,
                                &mut body,
                                profile.http,
                                fgit_admission::AdmissionLimits::default(),
                                &mut live,
                                &mut writer,
                            )?;
                        }
                    }
                    Ok(())
                })();
                if let Err(NodeSmartHttpRefusal::ReceiveResponse { outcome, .. }) = &git_result {
                    for command in &outcome.commands {
                        eprintln!(
                            "Smart HTTP reply lost after canonical outcome for transaction {}; retry with the original Idempotency-Key",
                            command.tx_id
                        );
                    }
                } else if let Err(error) = &git_result
                    && request.operation == Operation::Rpc(Service::ReceivePack)
                {
                    // The client sees only a status; the operator gets the
                    // typed cause, which separates contention from a fault.
                    eprintln!("Smart HTTP receive ended without a reported outcome: {error}");
                }
                git_result.map_err(Status::from)?;
            }
            writer.flush().map_err(|_| Status::Unavailable)
        })();
        let cleanup = node.shutdown();
        if let Err(error) = cleanup {
            log_cleanup(&error);
            return Err(Status::Unavailable);
        }
        result
    })();
    if let Err(status) = served {
        // Never append a second response after any final response has started.
        // In particular, disconnect/cleanup never proves a mutation rolled back.
        if !writer.started {
            if recovery {
                let error =
                    recovery_error.unwrap_or_else(|| outcomes::ApiError::from_status(status));
                let _ = error.send(&mut writer, version);
            } else if native {
                let error = api_error
                    .unwrap_or_else(|| issues::ApiError::from_status(status, native_mutation));
                if source_api {
                    let _ = error.send_named(&mut writer, version, "source_error");
                } else if pull_api {
                    let _ = error.send_named(&mut writer, version, "pull_request_error");
                } else {
                    let _ = error.send(&mut writer, version);
                }
            } else {
                let _ = write_error(&mut writer, version, status);
            }
        }
    }
    drop(writer);
    drop(reader);
    let _ = output.shutdown(Shutdown::Write);
    let started = Instant::now();
    let mut remaining = 64 * 1024;
    let mut buffer = [0_u8; 1024];
    while remaining > 0 {
        let budget = Duration::from_secs(1).saturating_sub(started.elapsed());
        if budget.is_zero() || stream.set_read_timeout(Some(budget)).is_err() {
            break;
        }
        match stream.read(&mut buffer[..remaining.min(1024)]) {
            Ok(0) | Err(_) => break,
            Ok(count) => remaining -= count,
        }
    }
    served.is_ok()
}

fn log_cleanup(error: &NodeRefusal) {
    eprintln!("Smart HTTP child shutdown failed: {error}");
}

#[cfg(test)]
mod tests {
    use super::super::ingress::BodyInput;
    use super::*;
    use fgit_crypto::sha256_digest;
    use fgit_types::{RepositoryId, TenantId};
    use fgit_wire::smart_http::BodyDecoder;
    use fgit_wire::smart_http::rpc::RpcProgress;
    use std::io::Cursor;

    #[test]
    fn the_writer_gate_admits_to_its_limit_and_times_out_without_a_permit() {
        let gate = WriterGate::new(2);
        let session = |seconds| {
            GitDaemonSessionDeadline::new(
                GitDaemonSessionTimeout::try_new(Duration::from_secs(seconds)).unwrap(),
                crate::GitDaemonSessionWorkScaling::FLAT,
            )
        };
        let live = session(60);
        let first = gate.acquire(&live).expect("first writer");
        let second = gate.acquire(&live).expect("second writer");
        // A third writer whose own deadline passes while it waits was
        // admitted to nothing: no permit, and the count is unchanged.
        let short = session(1);
        let started = Instant::now();
        assert!(gate.acquire(&short).is_none());
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert_eq!(*gate.active.lock().unwrap(), 2);
        // Its permitted twin: a slot released while it waits admits it.
        let waiter = std::thread::scope(|scope| {
            let handle = scope.spawn(|| gate.acquire(&live));
            std::thread::sleep(Duration::from_millis(100));
            drop(first);
            handle.join().unwrap()
        });
        assert!(waiter.is_some());
        assert_eq!(
            *gate.active.lock().unwrap(),
            2,
            "second plus the admitted waiter"
        );
        drop((second, waiter));
        assert_eq!(*gate.active.lock().unwrap(), 0);
    }
    fn profile() -> Profile {
        Profile {
            config: NodeConfig::new(
                "unused".into(),
                TenantId::from_bytes([1; 16]),
                RepositoryId::from_bytes([2; 16]),
            ),
            route: b"/repo.git".to_vec(),
            credentials: CredentialSource::Static {
                digest: sha256_digest(&[b'a'; 64]),
                principal: PrincipalId::from_bytes([3; 16]),
            },
            allow_receive: true,
            allow_issues: false,
            allow_outcomes: false,
            allow_pulls: false,
            allow_source: false,
            http: HttpLimits::default(),
            maximum_response_bytes: 1024,
            timeout: GitDaemonSessionTimeout::DEFAULT,
            quota: Arc::new(PushQuota::default()),
            outcome_quota: Arc::new(PushQuota::default()),
            source_quota: Arc::new(PushQuota::default()),
            writers: Arc::new(WriterGate::new(MAX_CONCURRENT_WRITERS)),
        }
    }
    fn head(extra: &str) -> Vec<u8> {
        format!("POST /repo.git/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\n{extra}\r\n").into_bytes()
    }
    #[test]
    fn bearer_and_explicit_retry_identity_are_both_required() {
        let profile = profile();
        for extra in [
            "".to_owned(),
            "X-Forwarded-User: trusted\r\nIdempotency-Key: k\r\n".to_owned(),
            format!(
                "Authorization: Bearer {}\r\nIdempotency-Key: k\r\n",
                "b".repeat(64)
            ),
        ] {
            let bytes = head(&extra);
            let request = parse_head(&bytes, profile.http).unwrap().unwrap();
            assert_eq!(
                authenticated_session(&request, &bytes, &profile),
                Err(Status::Unauthorized)
            );
        }
        let bytes = head(&format!("Authorization: Bearer {}\r\n", "a".repeat(64)));
        let request = parse_head(&bytes, profile.http).unwrap().unwrap();
        assert_eq!(
            authenticated_session(&request, &bytes, &profile),
            Err(Status::BadRequest)
        );
        let bytes = head(&format!(
            "Authorization: Bearer {}\r\nIdempotency-Key: stable-1\r\n",
            "a".repeat(64)
        ));
        let request = parse_head(&bytes, profile.http).unwrap().unwrap();
        assert!(authenticated_session(&request, &bytes, &profile).is_ok());
        let mut readonly = profile.clone();
        readonly.allow_receive = false;
        assert_eq!(
            authenticated_session(&request, &bytes, &readonly),
            Err(Status::Forbidden)
        );
    }
    // RFC 4648 encoding of the fixture user-pass `git:` + 64 lowercase a's.
    const BASIC: &str = "Basic Z2l0OmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";

    #[test]
    fn basic_and_bearer_bind_the_same_principal_and_explicit_retry_key() {
        let profile = profile();
        let basic = head(&format!(
            "Authorization: {BASIC}\r\nIdempotency-Key: stable-1\r\n"
        ));
        let bearer = head(&format!(
            "Authorization: Bearer {}\r\nIdempotency-Key: stable-1\r\n",
            "a".repeat(64)
        ));
        let basic_request = parse_head(&basic, profile.http).unwrap().unwrap();
        let bearer_request = parse_head(&bearer, profile.http).unwrap().unwrap();
        let selected = authenticated_session(&basic_request, &basic, &profile).unwrap();
        assert_eq!(
            selected,
            authenticated_session(&bearer_request, &bearer, &profile).unwrap()
        );
        assert_eq!(
            selected.authenticated_session().unwrap().principal_id(),
            PrincipalId::from_bytes([3; 16])
        );
        let no_key = head(&format!("Authorization: {BASIC}\r\n"));
        let request = parse_head(&no_key, profile.http).unwrap().unwrap();
        assert_eq!(
            authenticated_session(&request, &no_key, &profile),
            Err(Status::BadRequest)
        );
        let mut readonly = profile.clone();
        readonly.allow_receive = false;
        assert_eq!(
            authenticated_session(&basic_request, &basic, &readonly),
            Err(Status::Forbidden)
        );
        let mut foreign = profile.clone();
        foreign.route = b"/different.git".to_vec();
        assert_eq!(
            authenticated_session(&basic_request, &basic, &foreign),
            Err(Status::NotFound)
        );
    }

    #[test]
    fn credential_helper_discovery_needs_no_publication_key_or_write_permission() {
        let mut profile = profile();
        profile.allow_receive = false;
        let bytes = format!("GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: local\r\nAuthorization: {BASIC}\r\n\r\n").into_bytes();
        let request = parse_head(&bytes, profile.http).unwrap().unwrap();
        let selected = authenticated_session(&request, &bytes, &profile).unwrap();
        assert_eq!(
            selected.authenticated_session().unwrap().principal_id(),
            PrincipalId::from_bytes([3; 16])
        );
        assert_eq!(retry_key(&bytes).unwrap(), None);
    }

    #[test]
    fn only_unauthorized_responses_offer_both_credential_challenges() {
        for (version, prefix) in [
            (HttpVersion::Http10, "HTTP/1.0"),
            (HttpVersion::Http11, "HTTP/1.1"),
        ] {
            for status in [Status::Unauthorized, Status::Forbidden, Status::Unavailable] {
                let mut response = Vec::new();
                write_error(&mut response, version, status).unwrap();
                let response = String::from_utf8(response).unwrap();
                let (headers, body) = response.split_once("\r\n\r\n").unwrap();
                assert!(headers.starts_with(&format!("{prefix} {}", status.line())));
                assert!(headers.contains(&format!("Content-Length: {}\r\n", body.len())));
                assert!(headers.contains("Cache-Control: no-store"));
                assert!(!response.contains(BASIC));
                if status == Status::Unauthorized {
                    assert!(headers.contains(
                        "WWW-Authenticate: Basic realm=\"frankengit\", charset=\"UTF-8\""
                    ));
                    assert!(headers.contains("WWW-Authenticate: Bearer realm=\"frankengit\""));
                    assert_eq!(headers.matches("WWW-Authenticate:").count(), 2);
                    assert!(
                        headers.find("WWW-Authenticate: Basic")
                            < headers.find("WWW-Authenticate: Bearer")
                    );
                } else {
                    assert!(!headers.contains("WWW-Authenticate:"));
                }
                if status == Status::Unavailable {
                    assert!(body.contains("a push may already be committed"));
                }
            }
        }
    }

    #[test]
    fn duplicate_or_hop_by_hop_retry_identity_is_refused() {
        for extra in [
            "Idempotency-Key: a\r\nidempotency-key: b\r\n",
            "Idempotency-Key: a\r\nConnection: Idempotency-Key\r\n",
            "Idempotency-Key: \r\n",
        ] {
            assert_eq!(retry_key(&head(extra)), Err(Status::BadRequest));
        }
        assert_eq!(
            retry_key(&head("Idempotency-Key: a\r\n")).unwrap(),
            Some(b"a".as_slice())
        );
    }
    fn decoded_body(
        reader: &mut impl Read,
        initial: &[u8],
        request: &RequestHead<'_>,
        limits: HttpLimits,
    ) -> Result<u64, Status> {
        let mut decoder = BodyDecoder::new(request.body, limits)?;
        let mut reader = Cursor::new(initial).chain(reader);
        BodyInput::Reader(&mut reader)
            .consume(&mut || true, |bytes, _| {
                let mut consumed = 0;
                while consumed < bytes.len() && !decoder.is_complete() {
                    consumed += decoder.push(&bytes[consumed..])?.consumed;
                }
                Ok(RpcProgress {
                    consumed,
                    body_complete: decoder.is_complete(),
                    decoded_body_bytes: decoder.decoded_bytes(),
                })
            })
            .map_err(Status::from)
    }
    #[test]
    fn bodies_finish_at_framing_without_waiting_for_socket_eof() {
        struct NoMoreReads;
        impl Read for NoMoreReads {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("complete body must not wait for EOF")
            }
        }
        let bytes = head("");
        let request = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(
            decoded_body(&mut NoMoreReads, b"0000", &request, HttpLimits::default()).unwrap(),
            4
        );
        assert_eq!(
            decoded_body(
                &mut NoMoreReads,
                b"0000NEXT",
                &request,
                HttpLimits::default()
            ),
            Err(Status::BadRequest)
        );
        assert_eq!(
            decoded_body(
                &mut Cursor::new(b""),
                b"000",
                &request,
                HttpLimits::default()
            ),
            Err(Status::BadRequest)
        );
    }
    #[test]
    fn chunked_intake_rejects_trailers_and_overflow() {
        let bytes = String::from_utf8(head(""))
            .unwrap()
            .replace("Content-Length: 4", "Transfer-Encoding: chunked");
        let request = parse_head(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let body = b"2\r\n00\r\n2\r\n00\r\n0\r\n\r\n";
        assert_eq!(
            decoded_body(&mut Cursor::new(body), b"", &request, HttpLimits::default()).unwrap(),
            4
        );
        assert_eq!(
            decoded_body(
                &mut Cursor::new(b"0\r\nX: y\r\n\r\n"),
                b"",
                &request,
                HttpLimits::default()
            ),
            Err(Status::BadRequest)
        );
        let limits = HttpLimits {
            max_body_bytes: 3,
            ..HttpLimits::default()
        };
        assert_eq!(
            decoded_body(&mut Cursor::new(body), b"", &request, limits),
            Err(Status::TooLarge)
        );
    }
    #[test]
    fn final_refusal_is_self_delimiting_and_contains_no_request_text() {
        let mut response = Vec::new();
        write_error(&mut response, HttpVersion::Http11, Status::Unauthorized).unwrap();
        let response = String::from_utf8(response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 401"));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(head.contains("WWW-Authenticate: Bearer"));
        assert!(!response.contains(&"a".repeat(64)));
    }
}
