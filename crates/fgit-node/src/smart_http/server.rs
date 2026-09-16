//! Bounded, single-repository Smart HTTP gateway (frankengit-asa3).
//!
//! This is an explicit loopback capability profile, not organization/team IAM.
//! The operator grants one principal repository access through a bearer secret.
//! TLS terminates outside this listener; forwarded headers never authenticate.
//! Every request authenticates before repository opening, 100 Continue, or body
//! retention. Git parsing and canonical publication remain in the node adapters.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fgit_authority::IdempotencyKey;
use fgit_crypto::{sha256_digest, verify_mac};
use fgit_types::PrincipalId;
use fgit_types::cell::CellState;
use fgit_wire::smart_http::{
    BodyDecoder, HttpError, HttpLimits, HttpVersion, Operation, RequestHead, Service, parse_head,
};
use fgit_wire::WireLimits;

use super::NodeSmartHttpRefusal;
use crate::{
    DeadlineTcpStream, GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionDeadline,
    GitDaemonSessionTimeout, GitDaemonSessionWorkScaling, LoopbackReceiveSession, NodeConfig,
    NodeRefusal, OneNode, PushQuota,
};

const IO_CHUNK: usize = 16 * 1024;
const MAX_IN_FLIGHT: usize = 16;
const MAX_SESSIONS: usize = 1_000_000;
const FRAMING_ALLOWANCE: u64 = 4 * 1024 * 1024;

#[derive(Clone)]
struct Profile {
    config: NodeConfig,
    route: Vec<u8>,
    credential_digest: [u8; 32],
    principal: PrincipalId,
    allow_receive: bool,
    http: HttpLimits,
    maximum_response_bytes: u64,
    timeout: GitDaemonSessionTimeout,
    quota: Arc<PushQuota>,
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
    /// repository incarnation and principal. Receive discovery and RPC are
    /// disabled unless `allow_receive` is explicitly true. Every push RPC must
    /// additionally carry a client-chosen `Idempotency-Key` header; retrying it
    /// unchanged resolves an ambiguous response through canonical admission.
    ///
    /// This local capability profile does not implement multi-user IAM or TLS.
    /// Non-loopback listeners are refused. An external TLS gateway must forward
    /// the actual bearer credential: Forwarded/X-Forwarded-* and identity-like
    /// headers never convey authority. HTTP connections are not reused.
    ///
    /// The configured receive input envelope bounds each complete HTTP body;
    /// chunk framing has a separate 4 MiB ceiling above it. Ingress is buffered
    /// under that bound before native quarantine. Pack responses are streamed.
    /// At most 16 connections and their buffers may be in flight, and completed
    /// worker handles are reaped continuously rather than retained per request.
    /// Socket work runs only on this node's Asupersync blocking pool.
    ///
    /// Acceptance stops at `server_limits.max_sessions()` or `idle_timeout`
    /// since the last accepted connection. Every accepted child is joined,
    /// including after an accept/scheduling failure, before this returns. A
    /// refused-session count describes transport completion, NOT non-commit.
    pub fn serve_smart_http_bounded(
        &self,
        listener: &TcpListener,
        server_limits: GitDaemonServerLimits,
        credential_digest: [u8; 32],
        principal: PrincipalId,
        allow_receive: bool,
        idle_timeout: Duration,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        let address = listener.local_addr().map_err(|source| io_error("inspect HTTP listener", source))?;
        if !address.ip().is_loopback() {
            return Err(invalid_configuration("Smart HTTP requires a loopback listener"));
        }
        if self.cell_state() != CellState::Serving {
            return Err(invalid_configuration("bring the HTTP node into service before listening"));
        }
        if !(1..=MAX_SESSIONS).contains(&server_limits.max_sessions())
            || !(1..=MAX_IN_FLIGHT).contains(&server_limits.max_in_flight())
            || idle_timeout.is_zero()
        {
            return Err(invalid_configuration("invalid bounded Smart HTTP service limits"));
        }
        let maximum_body = u64::try_from(self.git_daemon_receive_limits.pack.max_input_bytes)
            .map_err(|_| invalid_configuration("HTTP input envelope is not representable"))?;
        let maximum_wire = maximum_body.checked_add(FRAMING_ALLOWANCE)
            .ok_or_else(|| invalid_configuration("HTTP wire envelope overflow"))?;
        let maximum_response_bytes = u64::try_from(self.selected_pack_limits.max_total_expanded_bytes)
            .ok().and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(FRAMING_ALLOWANCE))
            .ok_or_else(|| invalid_configuration("HTTP response envelope overflow"))?;
        let http = HttpLimits {
            max_body_bytes: maximum_body,
            max_body_wire_bytes: maximum_wire,
            ..HttpLimits::default()
        };
        http.validate()?;
        let profile = Arc::new(Profile {
            config: self.service_config.clone()
                .with_expected_repository_incarnation(self.repository_incarnation_id()),
            route: self.git_daemon_repository_path().as_bytes().to_vec(),
            credential_digest,
            principal,
            allow_receive,
            http,
            maximum_response_bytes,
            timeout: self.git_daemon_session_timeout,
            // Shared across all HTTP connections, unlike each reopened node's
            // local counter. A contained caller never reaches body retention.
            quota: Arc::new(PushQuota::default()),
        });
        listener.set_nonblocking(true).map_err(|source| io_error("configure HTTP listener", source))?;
        let completed = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let mut pending: Vec<PendingSession> = Vec::new();
        let mut accepted = 0;
        let mut last_accept = Instant::now();
        let mut failure = None;
        while accepted < server_limits.max_sessions() && last_accept.elapsed() < idle_timeout {
            let mut index = 0;
            while index < pending.len() {
                if pending[index].finished.load(Ordering::Acquire) {
                    (pending.swap_remove(index).join)();
                } else {
                    index += 1;
                }
            }
            if pending.len() >= server_limits.max_in_flight() {
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
            last_accept = Instant::now();
            // Queue time counts against ingress: a queued peer does not acquire
            // a new wall-clock allowance when a blocking worker becomes free.
            let deadline = GitDaemonSessionDeadline::new(profile.timeout, GitDaemonSessionWorkScaling::FLAT);
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
                    join: Box::new(move || { task.wait(); }),
                }),
                Err(error) => {
                    failure = Some(io_error("schedule Smart HTTP connection", io::Error::other(error.to_string())));
                    break;
                }
            }
        }
        for child in pending {
            (child.join)();
        }
        // Return the listener to blocking mode after the bounded run.
        let restored = listener.set_nonblocking(false)
            .map_err(|source| io_error("restore HTTP listener", source));
        if let Some(error) = failure {
            if let Err(cleanup) = restored {
                return Err(io_error("HTTP listener cleanup after service failure", io::Error::other(format!("{error}; {cleanup}"))));
            }
            return Err(error);
        }
        restored?;
        let completed_sessions = completed.load(Ordering::Acquire);
        let refused_sessions = refused.load(Ordering::Acquire);
        if completed_sessions.checked_add(refused_sessions) != Some(accepted) {
            return Err(invalid_configuration("HTTP service did not settle every accepted child"));
        }
        Ok(GitDaemonServerReceipt {
            accepted_sessions: accepted,
            completed_sessions,
            refused_sessions,
        })
    }
}

fn invalid_configuration(message: &'static str) -> NodeSmartHttpRefusal {
    io_error("configure Smart HTTP service", io::Error::new(io::ErrorKind::InvalidInput, message))
}
fn io_error(operation: &'static str, source: io::Error) -> NodeSmartHttpRefusal {
    NodeSmartHttpRefusal::Io { operation, source }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Status {
    BadRequest, Unauthorized, Forbidden, NotFound, TooLarge, HeaderTooLarge,
    MediaType, Method, Expectation, Timeout, RateLimited, Unavailable,
}
impl Status {
    fn line(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::Unauthorized => "401 Unauthorized",
            Self::Forbidden => "403 Forbidden",
            Self::NotFound => "404 Not Found",
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
impl From<HttpError> for Status {
    fn from(error: HttpError) -> Self {
        match error {
            HttpError::BodyTooLarge | HttpError::WireBudgetExceeded | HttpError::TooManyChunks => Self::TooLarge,
            HttpError::HeadTooLarge | HttpError::TooManyHeaders => Self::HeaderTooLarge,
            HttpError::UnsupportedMediaType | HttpError::UnsupportedContentEncoding => Self::MediaType,
            HttpError::UnsupportedExpectation => Self::Expectation,
            HttpError::MethodNotAllowed => Self::Method,
            HttpError::InvalidRoute => Self::NotFound,
            _ => Self::BadRequest,
        }
    }
}
impl From<io::Error> for Status {
    fn from(error: io::Error) -> Self {
        if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
            Self::Timeout
        } else {
            Self::BadRequest
        }
    }
}

// No Debug on credentials/profile; no client text is echoed in a refusal.
fn authenticated_session(
    request: &RequestHead<'_>,
    raw_head: &[u8],
    profile: &Profile,
) -> Result<LoopbackReceiveSession, Status> {
    let (scheme, token) = request.authorization().and_then(|value| value.split_once(' '))
        .ok_or(Status::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.len() != 64
        || !token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !verify_mac(&profile.credential_digest, &sha256_digest(token.as_bytes()))
    {
        return Err(Status::Unauthorized);
    }
    if request.repository_route.as_bytes() != profile.route {
        return Err(Status::NotFound);
    }
    if request.operation.service() == Service::ReceivePack && !profile.allow_receive {
        return Err(Status::Forbidden);
    }
    let key = retry_key(raw_head)?;
    let key = if request.operation == Operation::Rpc(Service::ReceivePack) {
        key.ok_or(Status::BadRequest)?
    } else {
        // Discovery never seals a transaction; its session identity is unused.
        b"smart-http-discovery-no-publication".as_slice()
    };
    let key = IdempotencyKey::new(key.to_vec()).map_err(|_| Status::BadRequest)?;
    Ok(LoopbackReceiveSession::authenticated(profile.principal, key))
}

fn retry_key(raw_head: &[u8]) -> Result<Option<&[u8]>, Status> {
    let text = std::str::from_utf8(raw_head).map_err(|_| Status::BadRequest)?;
    let mut key = None;
    for line in text.split("\r\n").skip(1).take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(Status::BadRequest)?;
        if name.eq_ignore_ascii_case("Idempotency-Key") {
            let value = value.trim_matches([' ', '\t']).as_bytes();
            if key.is_some() || value.is_empty() || value.len() > 128
                || !value.iter().all(u8::is_ascii_graphic)
            {
                return Err(Status::BadRequest);
            }
            key = Some(value);
        }
        // A hop-by-hop retry identity could be stripped by an intermediary.
        if name.eq_ignore_ascii_case("Connection")
            && value.split(',').any(|part| part.trim().eq_ignore_ascii_case("Idempotency-Key"))
        {
            return Err(Status::BadRequest);
        }
    }
    Ok(key)
}

fn append_bounded(target: &mut Vec<u8>, bytes: &[u8], maximum: u64) -> Result<(), Status> {
    let next = target.len().checked_add(bytes.len()).ok_or(Status::TooLarge)?;
    let maximum = usize::try_from(maximum).unwrap_or(usize::MAX);
    if next > maximum { return Err(Status::TooLarge); }
    if next > target.capacity() {
        let capacity = next.max(target.capacity().saturating_mul(2)).min(maximum);
        target.try_reserve_exact(capacity - target.len()).map_err(|_| Status::Unavailable)?;
    }
    target.extend_from_slice(bytes);
    Ok(())
}

fn read_head(reader: &mut impl Read, limits: HttpLimits) -> Result<Vec<u8>, Status> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; IO_CHUNK];
    loop {
        if parse_head(&bytes, limits)?.is_some() { return Ok(bytes); }
        let count = buffer.len().min(limits.max_head_bytes.saturating_sub(bytes.len()));
        if count == 0 { return Err(Status::HeaderTooLarge); }
        let read = match reader.read(&mut buffer[..count]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 { return Err(Status::BadRequest); }
        append_bounded(&mut bytes, &buffer[..read], limits.max_head_bytes as u64)?;
    }
}

fn read_body(
    reader: &mut impl Read,
    initial: &[u8],
    request: &RequestHead<'_>,
    limits: HttpLimits,
) -> Result<Vec<u8>, Status> {
    let mut decoder = BodyDecoder::new(request.body, limits)?;
    let mut body = Vec::new();
    let mut consume = |offered: &[u8], decoder: &mut BodyDecoder| -> Result<(), Status> {
        let mut cursor = 0;
        while cursor < offered.len() {
            if decoder.is_complete() { return Err(Status::BadRequest); }
            let step = decoder.push(&offered[cursor..])?;
            if step.consumed == 0 { return Err(Status::BadRequest); }
            append_bounded(&mut body, &offered[cursor..cursor + step.consumed], limits.max_body_wire_bytes)?;
            cursor += step.consumed;
        }
        Ok(())
    };
    consume(initial, &mut decoder)?;
    let mut buffer = [0_u8; IO_CHUNK];
    while !decoder.is_complete() {
        let read = match reader.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 { return Err(Status::BadRequest); }
        consume(&buffer[..read], &mut decoder)?;
    }
    decoder.finish()?;
    Ok(body)
}

// First final write begins a separate finite response phase, so completed
// admission does not lose its reply to an already-spent ingress allowance.
struct ResponseWriter<'a> {
    inner: DeadlineTcpStream<'a>,
    timeout: GitDaemonSessionTimeout,
    started: bool,
}
impl Write for ResponseWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.started {
            self.inner.restart_deadline(GitDaemonSessionDeadline::new(self.timeout, GitDaemonSessionWorkScaling::FLAT));
            self.started = true;
        }
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}

fn write_error(writer: &mut impl Write, version: HttpVersion, status: Status) -> io::Result<()> {
    let version = match version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
    let body = if status == Status::Unavailable {
        "repository operation unavailable; a push may already be committed; retry with the same Idempotency-Key\n"
    } else {
        "Smart HTTP request refused\n"
    };
    let extra = match status {
        Status::Unauthorized => "WWW-Authenticate: Bearer realm=\"frankengit\"\r\n",
        Status::RateLimited => "Retry-After: 60\r\n",
        Status::Method => "Allow: GET, POST\r\n",
        _ => "",
    };
    write!(writer, "{version} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{extra}\r\n{body}", status.line(), body.len())?;
    writer.flush()
}

fn serve_connection(mut stream: TcpStream, deadline: GitDaemonSessionDeadline, profile: &Profile) -> bool {
    if stream.set_nonblocking(false).is_err() { return false; }
    let Ok(mut output) = stream.try_clone() else { return false; };
    let mut reader = DeadlineTcpStream::new(&mut stream, deadline.clone());
    let mut writer = ResponseWriter {
        inner: DeadlineTcpStream::new(&mut output, deadline),
        timeout: profile.timeout,
        started: false,
    };
    let mut version = HttpVersion::Http11;
    let served = (|| -> Result<(), Status> {
        let bytes = read_head(&mut reader, profile.http)?;
        let request = parse_head(&bytes, profile.http)?.ok_or(Status::BadRequest)?;
        version = request.http_version;
        let session = authenticated_session(&request, &bytes[..request.consumed], profile)?;
        if request.operation == Operation::Rpc(Service::ReceivePack) {
            profile.quota.evaluate(&profile.principal).map_err(|_| Status::RateLimited)?;
        }
        if request.expect_continue {
            if request.http_version == HttpVersion::Http10 {
                return Err(Status::Expectation);
            }
            // Only authenticated, route-authorized, quota-admitted requests
            // reach this interim response. It is not a final success header.
            writer.inner.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            writer.inner.flush()?;
        }
        let body = read_body(&mut reader, &bytes[request.consumed..], &request, profile.http)?;
        let mut node = OneNode::open_existing(profile.config.clone()).map_err(|_| Status::Unavailable)?;
        let work_deadline = GitDaemonSessionDeadline::new(profile.timeout, GitDaemonSessionWorkScaling::FLAT);
        let result = (|| -> Result<(), NodeSmartHttpRefusal> {
            let authenticated = node.runtime().block_on(node.authenticate_authority_head())
                .map_err(crate::NodeAdmissionViewRefusal::from)?;
            node.bring_into_service(authenticated.receipt().generation())
                .map_err(|error| io_error("bring HTTP child into service", io::Error::other(error.to_string())))?;
            let mut live = || !work_deadline.expired();
            match request.operation {
                Operation::Discover(service) => {
                    let discovery = match service {
                        Service::UploadPack => node.smart_http_upload_discovery_in(&request, WireLimits::default())?,
                        Service::ReceivePack => node.smart_http_receive_discovery_in(&request, &session, WireLimits::default())?,
                    };
                    writer.write_all(discovery.head().as_bytes()).map_err(|source| io_error("write HTTP discovery head", source))?;
                    writer.write_all(discovery.body()).map_err(|source| io_error("write HTTP discovery body", source))?;
                }
                Operation::Rpc(Service::UploadPack) => {
                    node.smart_http_upload_rpc_in(&request, &body, WireLimits::default(), profile.http,
                        profile.maximum_response_bytes, &mut live, &mut writer)?;
                }
                Operation::Rpc(Service::ReceivePack) => {
                    let _outcome = node.smart_http_receive_rpc_in(&request, &session, &body,
                        profile.http, fgit_admission::AdmissionLimits::default(), &mut live, &mut writer)?;
                }
            }
            writer.flush().map_err(|source| io_error("flush HTTP response", source))
        })();
        // Always close the child, even on protocol, publication, or write error.
        let cleanup = node.shutdown();
        if let Err(NodeSmartHttpRefusal::ReceiveResponse { outcome, .. }) = &result {
            for command in &outcome.commands {
                eprintln!("Smart HTTP reply lost after canonical outcome for transaction {}; retry with the original Idempotency-Key", command.tx_id);
            }
        }
        if let Err(error) = cleanup {
            log_cleanup(&error);
            return Err(Status::Unavailable);
        }
        result.map_err(|_| Status::Unavailable)
    })();
    if let Err(status) = served {
        // Never append a second HTTP response after a partially written 200,
        // including a push whose commit succeeded but response delivery failed.
        if !writer.started {
            let _ = write_error(&mut writer, version, status);
        }
    }
    drop(writer);
    drop(reader);
    let _ = output.shutdown(Shutdown::Write);
    // Bound the politeness drain by BOTH bytes and absolute time. A peer that
    // keeps transmitting cannot pin a worker after its response is finished.
    let started = Instant::now();
    let mut remaining = 64 * 1024;
    let mut buffer = [0_u8; 1024];
    while remaining > 0 {
        let budget = Duration::from_secs(1).saturating_sub(started.elapsed());
        if budget.is_zero() || stream.set_read_timeout(Some(budget)).is_err() { break; }
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
    use super::*;
    use std::io::Cursor;
    use fgit_types::{RepositoryId, TenantId};

    fn profile() -> Profile {
        Profile {
            config: NodeConfig::new("unused".into(), TenantId::from_bytes([1; 16]), RepositoryId::from_bytes([2; 16])),
            route: b"/repo.git".to_vec(),
            credential_digest: sha256_digest(&[b'a'; 64]),
            principal: PrincipalId::from_bytes([3; 16]),
            allow_receive: true,
            http: HttpLimits::default(),
            maximum_response_bytes: 1024,
            timeout: GitDaemonSessionTimeout::DEFAULT,
            quota: Arc::new(PushQuota::default()),
        }
    }
    fn head(extra: &str) -> Vec<u8> {
        format!("POST /repo.git/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\n{extra}\r\n").into_bytes()
    }
    #[test]
    fn bearer_and_explicit_retry_identity_are_both_required() {
        let profile = profile();
        for extra in ["".to_owned(), "X-Forwarded-User: trusted\r\nIdempotency-Key: k\r\n".to_owned(),
            format!("Authorization: Bearer {}\r\nIdempotency-Key: k\r\n", "b".repeat(64))] {
            let bytes = head(&extra);
            let request = parse_head(&bytes, profile.http).unwrap().unwrap();
            assert_eq!(authenticated_session(&request, &bytes, &profile), Err(Status::Unauthorized));
        }
        let bytes = head(&format!("Authorization: Bearer {}\r\n", "a".repeat(64)));
        let request = parse_head(&bytes, profile.http).unwrap().unwrap();
        assert_eq!(authenticated_session(&request, &bytes, &profile), Err(Status::BadRequest));
        let bytes = head(&format!("Authorization: Bearer {}\r\nIdempotency-Key: stable-1\r\n", "a".repeat(64)));
        let request = parse_head(&bytes, profile.http).unwrap().unwrap();
        assert!(authenticated_session(&request, &bytes, &profile).is_ok());
        let mut readonly = profile.clone();
        readonly.allow_receive = false;
        assert_eq!(authenticated_session(&request, &bytes, &readonly), Err(Status::Forbidden));
    }
    #[test]
    fn duplicate_or_hop_by_hop_retry_identity_is_refused() {
        for extra in ["Idempotency-Key: a\r\nidempotency-key: b\r\n", "Idempotency-Key: a\r\nConnection: Idempotency-Key\r\n", "Idempotency-Key: \r\n"] {
            assert_eq!(retry_key(&head(extra)), Err(Status::BadRequest));
        }
        assert_eq!(retry_key(&head("Idempotency-Key: a\r\n")).unwrap(), Some(b"a".as_slice()));
    }
    #[test]
    fn bodies_finish_at_framing_without_waiting_for_socket_eof() {
        struct NoMoreReads;
        impl Read for NoMoreReads {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { panic!("complete body must not wait for EOF") }
        }
        let bytes = head("");
        let request = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(read_body(&mut NoMoreReads, b"0000", &request, HttpLimits::default()).unwrap(), b"0000");
        assert_eq!(read_body(&mut NoMoreReads, b"0000NEXT", &request, HttpLimits::default()), Err(Status::BadRequest));
        assert_eq!(read_body(&mut Cursor::new(b""), b"000", &request, HttpLimits::default()), Err(Status::BadRequest));
    }
    #[test]
    fn chunked_intake_preserves_wire_bytes_and_rejects_trailers_and_overflow() {
        let bytes = String::from_utf8(head("")).unwrap().replace("Content-Length: 4", "Transfer-Encoding: chunked");
        let request = parse_head(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
        let body = b"2\r\n00\r\n2\r\n00\r\n0\r\n\r\n";
        assert_eq!(read_body(&mut Cursor::new(body), b"", &request, HttpLimits::default()).unwrap(), body);
        assert_eq!(read_body(&mut Cursor::new(b"0\r\nX: y\r\n\r\n"), b"", &request, HttpLimits::default()), Err(Status::BadRequest));
        let limits = HttpLimits { max_body_bytes: 3, ..HttpLimits::default() };
        assert_eq!(read_body(&mut Cursor::new(body), b"", &request, limits), Err(Status::TooLarge));
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
