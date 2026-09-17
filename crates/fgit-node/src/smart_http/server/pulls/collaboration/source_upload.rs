//! Source-change envelopes reuse the candidate transport's only HTTP/MIME
//! parsers. Payloads remain borrowed bytes; no effect occurs during parsing.

use std::io::Read;
use fgit_wire::smart_http::{BodyFraming, HttpLimits};
use super::{ApiError, Status, multipart, read_upload_bounded};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::smart_http::server) enum SourceUploadKind { Patch, Bundle }
impl SourceUploadKind {
    pub(in crate::smart_http::server) fn maximum(self) -> usize {
        self.payload_maximum() + multipart::MAX_COMMAND_BYTES + 16 * 1024
    }
    fn payload_maximum(self) -> usize {
        match self {
            Self::Patch => fgit_forge::patch::PatchLimits::default().max_patch_bytes,
            Self::Bundle => multipart::MAX_BUNDLE_BYTES,
        }
    }
    fn name(self) -> &'static str {
        match self { Self::Patch => "patch", Self::Bundle => "bundle" }
    }
    fn media(self, value: &str) -> bool {
        value.eq_ignore_ascii_case("application/octet-stream") || match self {
            Self::Patch => value.eq_ignore_ascii_case("text/x-diff"),
            Self::Bundle => value.eq_ignore_ascii_case("application/x-git-bundle"),
        }
    }
}

fn error(error: multipart::Error) -> ApiError {
    match error {
        multipart::Error::Framing => ApiError::bad("invalid_source_upload"),
        multipart::Error::Limit => ApiError::too_large(),
        multipart::Error::Cancelled => ApiError::from_status(Status::Timeout, false),
    }
}

pub(in crate::smart_http::server) fn source_upload_boundary(value: &str) -> Result<&str, ApiError> {
    multipart::boundary(value).map_err(|_| ApiError::media())
}

pub(in crate::smart_http::server) fn read_source_upload(
    reader: &mut impl Read, framing: BodyFraming, limits: HttpLimits, kind: SourceUploadKind,
) -> Result<Vec<u8>, ApiError> {
    read_upload_bounded(reader, framing, limits, kind.maximum())
}

pub(in crate::smart_http::server) fn source_upload<'a>(
    bytes: &'a [u8], boundary: &str, kind: SourceUploadKind, live: &mut impl FnMut() -> bool,
) -> Result<(&'a [u8], &'a [u8]), ApiError> {
    let (mut command, mut payload) = (None, None);
    multipart::visit_parts(bytes, boundary, kind.maximum(), 2, live, |part| {
        if part.name == "command" && command.is_none() && multipart::command_media(part.media) {
            if part.content.len() > multipart::MAX_COMMAND_BYTES { return Err(multipart::Error::Limit); }
            command = Some(part.content);
        } else if part.name == kind.name() && payload.is_none() && kind.media(part.media) {
            if part.content.len() > kind.payload_maximum() { return Err(multipart::Error::Limit); }
            payload = Some(part.content);
        } else { return Err(multipart::Error::Framing); }
        Ok(())
    }).map_err(error)?;
    let command = command.filter(|bytes| !bytes.is_empty()).ok_or_else(|| ApiError::bad("source_command_required"))?;
    let payload = payload.filter(|bytes| !bytes.is_empty()).ok_or_else(|| ApiError::bad("source_payload_required"))?;
    Ok((command, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn part(name: &str, media: &str, body: &[u8]) -> Vec<u8> {
        let mut bytes = format!("--source\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"ignored\"\r\nContent-Type: {media}\r\n\r\n").into_bytes();
        bytes.extend_from_slice(body); bytes.extend_from_slice(b"\r\n"); bytes
    }
    fn input(name: &str, payload: &[u8], reverse: bool) -> Vec<u8> {
        let command = part("command", "application/x-www-form-urlencoded", b"ref=refs/heads/main");
        let body = part(name, "application/octet-stream", payload);
        let mut bytes = if reverse { [body, command].concat() } else { [command, body].concat() };
        bytes.extend_from_slice(b"--source--\r\n"); bytes
    }
    #[test]
    fn exact_patch_and_bundle_bytes_survive_both_part_orders() {
        for kind in [SourceUploadKind::Patch, SourceUploadKind::Bundle] {
            for reverse in [false, true] {
                let bytes = input(kind.name(), b"\0\xff\r\n--sourceX\n", reverse);
                let (command, payload) = source_upload(&bytes, "source", kind, &mut || true).unwrap();
                assert_eq!(command, b"ref=refs/heads/main");
                assert_eq!(payload, b"\0\xff\r\n--sourceX\n");
            }
        }
    }
    #[test]
    fn_source_uploads_require_one_nonempty_payload_of_the_selected_kind() {
        for bytes in [input("bundle", b"data", false), input("patch", b"", false), input("file_0", b"data", true)] {
            assert!(source_upload(&bytes, "source", SourceUploadKind::Patch, &mut || true).is_err());
        }
        let bytes = input("patch", b"data", false);
        assert!(source_upload(&bytes, "source", SourceUploadKind::Bundle, &mut || true).is_err());
        let mut duplicate = part("command", "application/x-www-form-urlencoded", b"a=b");
        duplicate.extend(part("command", "application/x-www-form-urlencoded", b"c=d"));
        duplicate.extend_from_slice(b"--source--\r\n");
        assert!(source_upload(&duplicate, "source", SourceUploadKind::Patch, &mut || true).is_err());
    }
    #[test]
    fn provisional_parts_cannot_escape_truncation_or_cancellation() {
        let bytes = input("patch", b"raw\xffpatch\n", false);
        for end in 0..bytes.len() - 2 {
            assert!(source_upload(&bytes[..end], "source", SourceUploadKind::Patch, &mut || true).is_err());
        }
        let mut trailing = bytes.clone(); trailing.extend_from_slice(b"NEXT");
        assert!(source_upload(&trailing, "source", SourceUploadKind::Patch, &mut || true).is_err());
        assert!(source_upload(&bytes, "source", SourceUploadKind::Patch, &mut || false).is_err());
    }
}
