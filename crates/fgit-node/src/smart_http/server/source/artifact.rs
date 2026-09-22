//! Read-only prepared artifacts shared by native source transformations.
//! Buffer bounded metadata, but retain and send the native bundle only once.

use super::super::{Status, issues::ApiError};
use fgit_crypto::sha256_digest;
use fgit_wire::smart_http::HttpVersion;
use std::io::{self, Write};

pub(super) const MAX_METADATA: usize = 2 * 1024 * 1024;
const MAX_BUNDLE: usize = 64 * 1024 * 1024;
const MAX_RESPONSE: usize = MAX_METADATA + MAX_BUNDLE + 16 * 1024;

pub(super) fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub(super) fn append(out: &mut String, text: &str) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(text.len())
        .is_none_or(|n| n > MAX_METADATA)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(text.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(text);
    Ok(())
}

pub(super) struct Bundle {
    bytes: Vec<u8>,
    digest: [u8; 32],
}
impl Bundle {
    pub(super) fn new(bytes: Vec<u8>, live: &mut impl FnMut() -> bool) -> Result<Self, ApiError> {
        checkpoint(live)?;
        if bytes.is_empty() {
            return Err(ApiError::unavailable());
        }
        if bytes.len() > MAX_BUNDLE {
            return Err(ApiError::too_large());
        }
        let digest = sha256_digest(&bytes);
        checkpoint(live)?;
        Ok(Self { bytes, digest })
    }
    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }
    pub(super) fn digest_hex(&self) -> String {
        hex(&self.digest)
    }
}

pub(super) struct PreparedReply {
    status: Status,
    content_type: String,
    prefix: String,
    bundle: Option<Bundle>,
    suffix: String,
    length: usize,
}
impl PreparedReply {
    /// The caller constructs and validates operation-specific JSON first.
    /// A conflict or no-change response cannot accidentally carry a candidate.
    pub(super) fn build(
        metadata: String,
        bundle: Option<Bundle>,
        status: Status,
        maximum: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, ApiError> {
        checkpoint(live)?;
        let maximum = maximum.min(MAX_RESPONSE);
        if metadata.len() > MAX_METADATA {
            return Err(ApiError::too_large());
        }
        if !matches!(status, Status::Success | Status::Conflict) {
            return Err(ApiError::unavailable());
        }
        let (content_type, prefix, suffix) = if let Some(bundle) = &bundle {
            if status != Status::Success {
                return Err(ApiError::unavailable());
            }
            let digest = bundle.digest_hex();
            let mut chosen = None;
            for attempt in 0..16 {
                let boundary = format!("fg-source-candidate-{}-{attempt:x}", &digest[..40]);
                let marker = format!("--{boundary}");
                if !contains(metadata.as_bytes(), marker.as_bytes(), live)?
                    && !contains(&bundle.bytes, marker.as_bytes(), live)?
                {
                    chosen = Some(boundary);
                    break;
                }
            }
            let boundary = chosen.ok_or_else(ApiError::too_large)?;
            let prefix = format!(
                concat!(
                    "--{0}\r\nContent-Type: application/json; charset=utf-8\r\n",
                    "Content-Disposition: inline; name=\"metadata\"\r\n\r\n{1}\r\n",
                    "--{0}\r\nContent-Type: application/x-git-bundle\r\n",
                    "Content-Disposition: attachment; name=\"bundle\"; filename=\"candidate.bundle\"\r\n\r\n"
                ),
                boundary, metadata
            );
            (
                format!("multipart/mixed; boundary={boundary}"),
                prefix,
                format!("\r\n--{boundary}--\r\n"),
            )
        } else {
            (
                "application/json; charset=utf-8".into(),
                metadata,
                String::new(),
            )
        };
        let length = prefix
            .len()
            .checked_add(bundle.as_ref().map_or(0, Bundle::len))
            .and_then(|n| n.checked_add(suffix.len()))
            .filter(|n| *n <= maximum)
            .ok_or_else(ApiError::too_large)?;
        checkpoint(live)?;
        Ok(Self {
            status,
            content_type,
            prefix,
            bundle,
            suffix,
            length,
        })
    }

    pub(super) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let version = match version {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
        };
        write!(
            writer,
            "{version} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
            self.status.line(),
            self.content_type,
            self.length
        )?;
        writer.write_all(self.prefix.as_bytes())?;
        if let Some(bundle) = &self.bundle {
            writer.write_all(&bundle.bytes)?;
        }
        writer.write_all(self.suffix.as_bytes())?;
        writer.flush()
    }
}

fn contains(
    bytes: &[u8],
    pattern: &[u8],
    live: &mut impl FnMut() -> bool,
) -> Result<bool, ApiError> {
    // Overlap catches a delimiter crossing a chunk boundary without copying.
    let mut offset = 0_usize;
    while offset < bytes.len() {
        checkpoint(live)?;
        let end = offset
            .saturating_add(64 * 1024 + pattern.len() - 1)
            .min(bytes.len());
        if bytes[offset..end]
            .windows(pattern.len())
            .any(|part| part == pattern)
        {
            return Ok(true);
        }
        offset = offset.saturating_add(64 * 1024);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_artifact_is_exact_framed_and_never_attached_to_conflict() {
        let bytes = b"# v2 git bundle\n\nPACK\0\xff\r\n".to_vec();
        let bundle = Bundle::new(bytes.clone(), &mut || true).unwrap();
        assert_eq!(bundle.digest_hex(), hex(&sha256_digest(&bytes)));
        let reply = PreparedReply::build(
            "{\"state\":\"clean\"}".into(),
            Some(bundle),
            Status::Success,
            MAX_RESPONSE,
            &mut || true,
        )
        .unwrap();
        let mut wire = Vec::new();
        reply.send(&mut wire, HttpVersion::Http11).unwrap();
        let split = wire.windows(4).position(|s| s == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(wire.len() - split, reply.length);
        assert!(wire.windows(bytes.len()).any(|part| part == bytes));
        let bundle = Bundle::new(bytes, &mut || true).unwrap();
        assert!(
            PreparedReply::build(
                "{}".into(),
                Some(bundle),
                Status::Conflict,
                MAX_RESPONSE,
                &mut || true
            )
            .is_err()
        );
    }
    #[test]
    fn bounds_and_cancellation_refuse_before_a_reply_exists() {
        assert!(Bundle::new(vec![], &mut || true).is_err());
        assert!(Bundle::new(vec![1], &mut || false).is_err());
        assert!(PreparedReply::build("{}".into(), None, Status::Success, 1, &mut || true).is_err());
        let mut metadata = String::from("x");
        assert!(append(&mut metadata, &"y".repeat(MAX_METADATA)).is_err());
        assert_eq!(metadata, "x");
        let mut calls = 0;
        assert!(
            PreparedReply::build("{}".into(), None, Status::Success, 2, &mut || {
                calls += 1;
                calls < 2
            })
            .is_err()
        );
    }
    #[test]
    fn delimiter_collision_across_chunks_is_not_missed_and_write_failures_escape() {
        let mut bytes = vec![b'x'; 64 * 1024 - 2];
        bytes.extend_from_slice(b"--candidate");
        assert!(contains(&bytes, b"--candidate", &mut || true).unwrap());
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let reply =
            PreparedReply::build("{}".into(), None, Status::Conflict, 2, &mut || true).unwrap();
        assert!(reply.send(&mut Broken, HttpVersion::Http11).is_err());
    }
}
