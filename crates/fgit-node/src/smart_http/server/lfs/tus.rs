//! Git LFS Tus 1.0 transfer. Batch creates the upload resource; the creation,
//! concatenation, checksum and expiration extensions are not advertised.

use fgit_object_fabric::artifact::storage::lfs::UploadError;
use fgit_types::PrincipalId;

use super::*;

const VERSION: &str = "1.0.0";
const PATCH_MEDIA: &str = "application/offset+octet-stream";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Method {
    Head,
    Patch,
    Options,
}

pub(super) fn is_route(target: &str) -> bool {
    target
        .split('?')
        .next()
        .is_some_and(|path| path.contains("/info/lfs/objects/") && path.ends_with("/tus"))
}

/// A method override must not turn the outer browser guard's read exemption
/// into permission to upload. Invalid/duplicate overrides are conservative;
/// endpoint validation will refuse them before any staging mutation.
pub(super) fn overrides_read_method(envelope: &Envelope<'_>) -> bool {
    is_route(envelope.target)
        && !matches!(
            envelope.method_override(),
            Ok(None | Some("HEAD" | "OPTIONS"))
        )
}

fn method(envelope: &Envelope<'_>) -> Result<Method, Failure> {
    match envelope
        .method_override()
        .map_err(Failure::http)?
        .unwrap_or(envelope.method)
    {
        "HEAD" => Ok(Method::Head),
        "PATCH" => Ok(Method::Patch),
        "OPTIONS" => Ok(Method::Options),
        _ => Err(Failure::new(Status::Method, "lfs_tus_method_not_allowed")),
    }
}

fn offset(envelope: &Envelope<'_>) -> Result<u64, Failure> {
    let raw = envelope
        .upload_offset()
        .map_err(Failure::http)?
        .ok_or_else(|| Failure::bad("lfs_tus_offset_required"))?;
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::bad("invalid_lfs_tus_offset"));
    }
    raw.parse()
        .map_err(|_| Failure::bad("invalid_lfs_tus_offset"))
}

pub(super) fn validate(envelope: &Envelope<'_>, object: LfsObject) -> Result<(), Failure> {
    let method = method(envelope)?;
    // Tus requires OPTIONS to ignore the version field, including a version
    // this server cannot serve. It is the client's capability-discovery path.
    if method != Method::Options
        && envelope.tus_resumable().map_err(Failure::http)? != Some(VERSION)
    {
        return Err(Failure::new(
            Status::Precondition,
            "unsupported_lfs_tus_version",
        ));
    }
    // The object length and identity are fixed by the authenticated Batch
    // request and URL. No request can renegotiate them through an extension.
    for field in [
        envelope.upload_length(),
        envelope.upload_checksum(),
        envelope.upload_concat(),
        envelope.upload_defer_length(),
        envelope.upload_metadata(),
    ] {
        if field.map_err(Failure::http)?.is_some() {
            return Err(Failure::bad("lfs_tus_extension_not_supported"));
        }
    }
    if method == Method::Patch {
        if !media_type(envelope.content_type, PATCH_MEDIA) {
            return Err(Failure::new(
                Status::MediaType,
                "unsupported_lfs_tus_media_type",
            ));
        }
        let offset = offset(envelope)?;
        let remaining = object
            .size
            .checked_sub(offset)
            .ok_or_else(|| Failure::new(Status::Conflict, "lfs_tus_offset_mismatch"))?;
        if matches!(envelope.body, BodyFraming::ContentLength(length) if length > remaining) {
            return Err(Failure::new(Status::TooLarge, "lfs_upload_length_mismatch"));
        }
    } else {
        if envelope.upload_offset().map_err(Failure::http)?.is_some() {
            return Err(Failure::bad("unexpected_lfs_tus_offset"));
        }
        if !matches!(
            envelope.body,
            BodyFraming::Empty | BodyFraming::ContentLength(0)
        ) || envelope.expect_continue
        {
            return Err(Failure::bad("lfs_tus_body_not_allowed"));
        }
    }
    Ok(())
}

pub(super) fn failure(error: UploadError) -> Failure {
    match error {
        UploadError::Busy => Failure::new(Status::Unavailable, "lfs_tus_upload_busy"),
        UploadError::Offset { .. } => Failure::new(Status::Conflict, "lfs_tus_offset_mismatch"),
        UploadError::NotFound => Failure::new(Status::NotFound, "lfs_tus_upload_not_found"),
        UploadError::Quota => Failure::new(Status::RateLimited, "lfs_tus_staging_quota"),
        UploadError::Corrupt => Failure::bad("lfs_tus_session_corrupt"),
        UploadError::Storage(error) => Failure::storage(error),
    }
}

pub(super) fn custody_failure(error: UploadError) -> Failure {
    match error {
        // No request payload is being accepted during status/preflight. A
        // damaged immutable container is a storage fault, not a bad PATCH.
        UploadError::Storage(error) => Failure::stored(error),
        other => failure(other),
    }
}

pub(super) enum Reply {
    Head { offset: u64, size: u64 },
    Patch { offset: u64 },
    Options,
}

pub(super) fn execute(
    profile: &Profile,
    service: &Service,
    object: LfsObject,
    principal: PrincipalId,
    envelope: &Envelope<'_>,
    prefix: &[u8],
    reader: &mut impl Read,
    writer: &mut impl Write,
    op: &ArtifactOperation<'_>,
    live: &dyn Fn() -> bool,
) -> Result<Reply, Failure> {
    validate(envelope, object)?;
    let method = method(envelope)?;
    if method != Method::Patch && !prefix.is_empty() {
        return Err(Failure::bad("lfs_tus_body_not_allowed"));
    }
    if method == Method::Options {
        return Ok(Reply::Options);
    }
    if method == Method::Head {
        let state = service
            .store
            .upload_status(object, principal, op)
            .map_err(custody_failure)?;
        return Ok(Reply::Head {
            offset: state.offset,
            size: object.size,
        });
    }
    let expected = offset(envelope)?;
    service
        .store
        .check_upload_offset(object, principal, expected, op)
        .map_err(custody_failure)?;
    let mut body = body::Framed::new(
        envelope.body,
        profile.http,
        object.size - expected,
        prefix,
        reader,
        live,
    )?;
    // Do not solicit bytes until authentication, scope, framing, version,
    // existing session and the current durable offset have passed. Storage
    // checks the offset again while holding its cross-process session lock.
    if envelope.expect_continue {
        writer
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .and_then(|()| writer.flush())
            .map_err(Failure::io)?;
    }
    let state = service
        .store
        .append_upload(object, principal, expected, &mut body, op)
        .map_err(failure)?;
    Ok(Reply::Patch {
        offset: state.offset,
    })
}

fn head(
    writer: &mut impl Write,
    version: HttpVersion,
    status: Status,
    extra: &str,
) -> io::Result<()> {
    let version = match version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    write!(
        writer,
        "{version} {}\r\nTus-Resumable: {VERSION}\r\nTus-Version: {VERSION}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{extra}\r\n",
        status.line(),
    )
}

pub(super) fn send(writer: &mut impl Write, version: HttpVersion, reply: Reply) -> io::Result<()> {
    match reply {
        Reply::Head { offset, size } => head(
            writer,
            version,
            Status::Success,
            &format!("Upload-Offset: {offset}\r\nUpload-Length: {size}\r\n"),
        )?,
        Reply::Patch { offset } => head(
            writer,
            version,
            Status::NoContent,
            &format!("Upload-Offset: {offset}\r\n"),
        )?,
        Reply::Options => head(
            writer,
            version,
            Status::NoContent,
            &format!("Tus-Max-Size: {MAX_OBJECT_BYTES}\r\nAllow: HEAD, PATCH, OPTIONS\r\n"),
        )?,
    }
    writer.flush()
}

pub(super) fn refuse(
    writer: &mut impl Write,
    envelope: &Envelope<'_>,
    error: Failure,
) -> Result<(), Status> {
    let body = format!("{{\"message\":{}}}", quote(error.message));
    let challenge = match error.status {
        Status::Unauthorized => AUTHENTICATION_CHALLENGES,
        Status::RateLimited => "Retry-After: 60\r\n",
        Status::Method => "Allow: HEAD, PATCH, OPTIONS\r\n",
        _ => "",
    };
    let extra = format!(
        "Content-Type: {JSON_MEDIA}\r\nContent-Length: {}\r\n{challenge}",
        body.len(),
    );
    let is_head =
        method(envelope).is_ok_and(|method| method == Method::Head) || envelope.method == "HEAD";
    let _ = head(writer, envelope.version, error.status, &extra).and_then(|()| {
        if !is_head {
            writer.write_all(body.as_bytes())?;
        }
        writer.flush()
    });
    Err(error.status)
}
