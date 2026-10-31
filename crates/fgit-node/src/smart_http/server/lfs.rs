//! Authenticated Git LFS basic transfer over the immutable artifact fabric.
//! Uploading bytes grants custody only: this adapter never publishes a Git ref,
//! artifact alias, retention decision, or second repository authority. The
//! existing permanent-retention profile applies until pointer-aware GC exists.

mod body;
mod protocol;
#[cfg(test)]
mod tests;

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsStore, MAX_OBJECT_BYTES};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactStorageError};
use fgit_types::{RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_wire::smart_http::{BodyFraming, HttpError, HttpVersion, head::Envelope};

use super::credentials::Grant;
use super::issues::quote;
use super::{AUTHENTICATION_CHALLENGES, Profile, Status};
use crate::GitDaemonSessionDeadline;

const ROUTE: &str = "/info/lfs/";
const JSON_MEDIA: &str = "application/vnd.git-lfs+json";
const BINARY_MEDIA: &str = "application/octet-stream";
const MAX_BATCH_VERIFIED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub(super) struct Service {
    store: LfsStore,
}

impl Service {
    pub(super) fn open(
        root: &Path,
        tenant: TenantId,
        repository: RepositoryId,
        incarnation: RepositoryIncarnationId,
    ) -> Result<Self, ArtifactStorageError> {
        Ok(Self {
            store: LfsStore::open(root, tenant, repository, incarnation)?,
        })
    }
}

pub(super) fn is_route(target: &str, repository_route: &[u8]) -> bool {
    target.split('?').next().is_some_and(|path| {
        path.as_bytes()
            .strip_prefix(repository_route)
            .is_some_and(|suffix| suffix == b"/info/lfs" || suffix.starts_with(ROUTE.as_bytes()))
    })
}

#[derive(Clone, Copy, Debug)]
struct Failure {
    status: Status,
    message: &'static str,
}

impl Failure {
    const fn new(status: Status, message: &'static str) -> Self {
        Self { status, message }
    }
    const fn bad(message: &'static str) -> Self {
        Self::new(Status::BadRequest, message)
    }
    const fn unavailable() -> Self {
        Self::new(Status::Unavailable, "lfs_storage_unavailable")
    }
    const fn not_found() -> Self {
        Self::new(Status::NotFound, "lfs_object_not_found")
    }
    fn http(error: HttpError) -> Self {
        Self::new(Status::from(error), "invalid_lfs_http_framing")
    }
    fn io(error: io::Error) -> Self {
        Self::new(Status::from(error), "incomplete_lfs_body")
    }
    fn storage(error: ArtifactStorageError) -> Self {
        match error {
            ArtifactStorageError::NotFound => Self::not_found(),
            ArtifactStorageError::PayloadLimit => {
                Self::new(Status::TooLarge, "lfs_object_size_limit")
            }
            ArtifactStorageError::Cancelled | ArtifactStorageError::Deadline => {
                Self::new(Status::Timeout, "lfs_request_expired")
            }
            ArtifactStorageError::PayloadMismatch => Self::bad("lfs_payload_mismatch"),
            ArtifactStorageError::PublicationUncertain { .. } => Self::new(
                Status::Unavailable,
                "lfs_upload_outcome_unknown_retry_identical_object",
            ),
            ArtifactStorageError::Io { kind, .. }
                if matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) =>
            {
                Self::new(Status::Timeout, "lfs_request_expired")
            }
            ArtifactStorageError::Io { kind, .. }
                if matches!(
                    kind,
                    io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                ) =>
            {
                Self::bad("incomplete_lfs_body")
            }
            _ => Self::unavailable(),
        }
    }
    fn stored(error: ArtifactStorageError) -> Self {
        // A digest/length failure while reading custody is a server fault,
        // whereas the same failure while accepting a PUT rejects its input.
        match error {
            ArtifactStorageError::NotFound => Self::not_found(),
            ArtifactStorageError::Cancelled | ArtifactStorageError::Deadline => {
                Self::new(Status::Timeout, "lfs_request_expired")
            }
            ArtifactStorageError::Io { kind, .. }
                if matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) =>
            {
                Self::new(Status::Timeout, "lfs_request_expired")
            }
            _ => Self::unavailable(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endpoint {
    Batch,
    Object(LfsObject),
    Verify(LfsObject),
}

struct Request<'a> {
    repository_route: &'a str,
    endpoint: Endpoint,
}

impl<'a> Request<'a> {
    fn parse(envelope: &Envelope<'a>) -> Result<Self, Failure> {
        if envelope.target.contains('?') || envelope.git_protocol.is_some() {
            return Err(Failure::bad("invalid_lfs_request"));
        }
        let (repository_route, suffix) = envelope
            .target
            .rsplit_once(ROUTE)
            .ok_or_else(Failure::not_found)?;
        if repository_route.is_empty() {
            return Err(Failure::not_found());
        }
        let endpoint = if suffix == "objects/batch" {
            Endpoint::Batch
        } else {
            let Some(path) = suffix.strip_prefix("objects/") else {
                return Err(Failure::not_found());
            };
            let mut parts = path.split('/');
            let oid = parts.next().ok_or_else(Failure::not_found)?;
            let size = parts.next().ok_or_else(Failure::not_found)?;
            let object = LfsObject::parse(oid, size).map_err(Failure::bad)?;
            let endpoint = match parts.next() {
                None => Endpoint::Object(object),
                Some("verify") => Endpoint::Verify(object),
                _ => return Err(Failure::not_found()),
            };
            if parts.next().is_some() {
                return Err(Failure::not_found());
            }
            endpoint
        };
        if !matches!(
            (endpoint, envelope.method),
            (Endpoint::Batch | Endpoint::Verify(_), "POST") | (Endpoint::Object(_), "GET" | "PUT")
        ) {
            return Err(Failure::new(Status::Method, "lfs_method_not_allowed"));
        }
        if let Endpoint::Object(object) | Endpoint::Verify(object) = endpoint
            && object.size > MAX_OBJECT_BYTES
        {
            return Err(Failure::new(Status::TooLarge, "lfs_object_size_limit"));
        }
        if envelope.method == "GET" {
            if !matches!(
                envelope.body,
                BodyFraming::Empty | BodyFraming::ContentLength(0)
            ) || envelope.expect_continue
            {
                return Err(Failure::bad("lfs_download_body_not_allowed"));
            }
        } else {
            let media = if envelope.method == "PUT" {
                BINARY_MEDIA
            } else {
                JSON_MEDIA
            };
            if !media_type(envelope.content_type, media) {
                return Err(Failure::new(
                    Status::MediaType,
                    "unsupported_lfs_media_type",
                ));
            }
            let maximum = match endpoint {
                Endpoint::Object(object) => {
                    if let BodyFraming::ContentLength(length) = envelope.body {
                        if length != object.size {
                            return Err(Failure::bad("lfs_upload_length_mismatch"));
                        }
                    } else if envelope.body == BodyFraming::Empty && object.size != 0 {
                        return Err(Failure::bad("lfs_upload_body_required"));
                    }
                    object.size
                }
                _ => protocol::MAX_JSON_BYTES as u64,
            };
            if matches!(envelope.body, BodyFraming::ContentLength(length) if length > maximum) {
                return Err(Failure::new(Status::TooLarge, "lfs_request_size_limit"));
            }
        }
        Ok(Self {
            repository_route,
            endpoint,
        })
    }
}

fn media_type(actual: Option<&str>, expected: &str) -> bool {
    let Some(actual) = actual else { return false };
    let mut parts = actual.split(';');
    if !parts
        .next()
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case(expected))
    {
        return false;
    }
    match parts.next() {
        None => true,
        Some(parameter) if expected == JSON_MEDIA => {
            parameter.trim().eq_ignore_ascii_case("charset=utf-8") && parts.next().is_none()
        }
        Some(_) => false,
    }
}

fn authorize(
    profile: &Profile,
    envelope: &Envelope<'_>,
    request: &Request<'_>,
) -> Result<Grant, Failure> {
    let grant = profile
        .credentials
        .authenticate(envelope.authorization())
        .map_err(|error| Failure::new(Status::from(error), "lfs_authentication_required"))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(Failure::not_found());
    }
    if profile.lfs.is_none() {
        return Err(Failure::new(Status::Forbidden, "lfs_service_disabled"));
    }
    let permitted = match request.endpoint {
        Endpoint::Batch => grant.permits_lfs(false) || grant.permits_lfs(true),
        Endpoint::Object(_) => grant.permits_lfs(envelope.method == "PUT"),
        Endpoint::Verify(_) => grant.permits_lfs(true),
    };
    if !permitted {
        return Err(Failure::new(Status::Forbidden, "lfs_scope_not_granted"));
    }
    profile
        .source_quota
        .evaluate(&grant.principal)
        .map_err(|_| Failure::new(Status::RateLimited, "lfs_rate_limited"))?;
    Ok(grant)
}

fn action_origin(profile: &Profile, local: Option<SocketAddr>) -> Result<String, Failure> {
    if let Some(origin) = profile.config.http_trusted_origin() {
        return Ok(origin.as_str().to_owned());
    }
    let local = local
        .filter(|local| local.ip().is_loopback())
        .ok_or_else(Failure::unavailable)?;
    Ok(format!("http://{local}"))
}

fn action(url: &str) -> String {
    // The client authenticates the action with its credential helper. Never
    // echo Authorization, sign a bearer URL, or construct an origin from Host.
    format!("{{\"href\":{}}}", quote(url))
}

fn object_error(object: LfsObject, code: u16, message: &'static str) -> String {
    format!(
        "{{\"oid\":{},\"size\":{},\"error\":{{\"code\":{code},\"message\":{}}}}}",
        quote(&object.oid.to_string()),
        object.size,
        quote(message)
    )
}

fn batch_reply(
    service: &Service,
    request: &protocol::Batch,
    base: &str,
    op: &ArtifactOperation<'_>,
    live: &dyn Fn() -> bool,
) -> Result<Vec<u8>, Failure> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(request.objects.len())
        .map_err(|_| Failure::unavailable())?;
    let mut inspected = 0_u64;
    for object in &request.objects {
        if !live() {
            return Err(Failure::new(Status::Timeout, "lfs_request_expired"));
        }
        if object.size > MAX_OBJECT_BYTES
            || object.size > MAX_BATCH_VERIFIED_BYTES.saturating_sub(inspected)
        {
            entries.push(object_error(*object, 413, "lfs_batch_verification_limit"));
            continue;
        }
        inspected += object.size;
        let present = match service.store.contains(*object, op) {
            Ok(present) => present,
            Err(ArtifactStorageError::Cancelled | ArtifactStorageError::Deadline) => {
                return Err(Failure::new(Status::Timeout, "lfs_request_expired"));
            }
            Err(_) => {
                entries.push(object_error(*object, 503, "lfs_storage_unavailable"));
                continue;
            }
        };
        if request.operation == protocol::Operation::Download && !present {
            entries.push(object_error(*object, 404, "lfs_object_not_found"));
            continue;
        }
        let actions = match request.operation {
            protocol::Operation::Upload if present => String::new(),
            protocol::Operation::Upload => {
                let path = format!("{base}/objects/{}/{}", object.oid, object.size);
                format!(
                    ",\"actions\":{{\"upload\":{},\"verify\":{}}}",
                    action(&path),
                    action(&format!("{path}/verify")),
                )
            }
            protocol::Operation::Download => format!(
                ",\"actions\":{{\"download\":{}}}",
                action(&format!("{base}/objects/{}/{}", object.oid, object.size)),
            ),
        };
        entries.push(format!(
            "{{\"oid\":{},\"size\":{}{actions}}}",
            quote(&object.oid.to_string()),
            object.size,
        ));
    }
    let body = format!(
        "{{\"transfer\":\"basic\",\"hash_algo\":\"sha256\",\"objects\":[{}]}}",
        entries.join(",")
    );
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(Failure::new(Status::TooLarge, "lfs_response_size_limit"));
    }
    Ok(body.into_bytes())
}

fn execute(
    profile: &Profile,
    envelope: &Envelope<'_>,
    prefix: &[u8],
    reader: &mut impl Read,
    writer: &mut impl Write,
    deadline: &GitDaemonSessionDeadline,
    local: Option<SocketAddr>,
) -> Result<(&'static str, Vec<u8>), Failure> {
    let request = Request::parse(envelope)?;
    let grant = authorize(profile, envelope, &request)?;
    let service = profile.lfs.as_ref().ok_or_else(Failure::unavailable)?;
    let live = || !deadline.expired();
    let remaining = deadline.remaining().map_err(Failure::io)?;
    let op = ArtifactOperation::new(
        MAX_OBJECT_BYTES,
        remaining.min(Duration::from_secs(3600)),
        &live,
    )
    .map_err(Failure::storage)?;
    if envelope.method == "GET" && !prefix.is_empty() {
        return Err(Failure::bad("lfs_download_body_not_allowed"));
    }
    // Authentication, endpoint scope and declared framing/size are checked
    // before this interim response permits the peer to send upload bytes.
    if envelope.expect_continue {
        writer
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .and_then(|()| writer.flush())
            .map_err(Failure::io)?;
    }
    match request.endpoint {
        Endpoint::Batch => {
            let input = body::json(envelope.body, profile.http, prefix, reader, &live)?;
            let batch = protocol::Batch::parse(&input).map_err(Failure::bad)?;
            if !grant.permits_lfs(batch.operation == protocol::Operation::Upload) {
                return Err(Failure::new(Status::Forbidden, "lfs_scope_not_granted"));
            }
            let origin = action_origin(profile, local)?;
            let base = format!("{origin}{}/info/lfs", request.repository_route);
            batch_reply(service, &batch, &base, &op, &live).map(|bytes| (JSON_MEDIA, bytes))
        }
        Endpoint::Object(object) if envelope.method == "PUT" => {
            let mut body = body::Framed::new(
                envelope.body,
                profile.http,
                object.size,
                prefix,
                reader,
                &live,
            )?;
            service
                .store
                .put(object, &mut body, &op)
                .map_err(Failure::storage)?;
            Ok((JSON_MEDIA, Vec::new()))
        }
        Endpoint::Object(object) => service
            .store
            .read(object, &op)
            .map(|bytes| (BINARY_MEDIA, bytes))
            .map_err(Failure::stored),
        Endpoint::Verify(object) => {
            let input = body::json(envelope.body, profile.http, prefix, reader, &live)?;
            if protocol::verify(&input).map_err(Failure::bad)? != object {
                return Err(Failure::bad("lfs_verify_object_mismatch"));
            }
            if !service
                .store
                .contains(object, &op)
                .map_err(Failure::stored)?
            {
                return Err(Failure::not_found());
            }
            Ok((JSON_MEDIA, b"{}".to_vec()))
        }
    }
}

/// Own the full LFS response. The outer ResponseWriter suppresses a second
/// response after either an error or interrupted download has started.
pub(super) fn serve(
    profile: &Profile,
    envelope: &Envelope<'_>,
    read_ahead: &[u8],
    reader: &mut impl Read,
    writer: &mut impl Write,
    deadline: &GitDaemonSessionDeadline,
    local: Option<SocketAddr>,
) -> Result<(), Status> {
    match execute(
        profile, envelope, read_ahead, reader, writer, deadline, local,
    ) {
        Ok((media, bytes)) => send(writer, envelope.version, Status::Success, media, &bytes)
            .map_err(|_| Status::Unavailable),
        Err(error) => {
            let body = format!("{{\"message\":{}}}", quote(error.message));
            let _ = send(
                writer,
                envelope.version,
                error.status,
                JSON_MEDIA,
                body.as_bytes(),
            );
            Err(error.status)
        }
    }
}

fn send(
    writer: &mut impl Write,
    version: HttpVersion,
    status: Status,
    media: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let version = match version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    let extra = match status {
        Status::Unauthorized => AUTHENTICATION_CHALLENGES,
        Status::RateLimited => "Retry-After: 60\r\n",
        Status::Method => "Allow: GET, POST, PUT\r\n",
        _ => "",
    };
    write!(
        writer,
        "{version} {}\r\nContent-Type: {media}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{extra}\r\n",
        status.line(),
        bytes.len(),
    )?;
    writer.write_all(bytes)?;
    writer.flush()
}
