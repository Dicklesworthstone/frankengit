//! Resolution-specific part policy over the SAME multipart framing engine as
//! candidate review. Files are borrowed bytes, not filesystem names or paths.
//! The command must consume every named file exactly once before construction.

use super::multipart;
use crate::smart_http::server::issues::ApiError;
use std::collections::BTreeMap;

pub(in crate::smart_http::server::pulls) const MAX_FILES: usize = 128;
pub(in crate::smart_http::server::pulls) const MAX_FILE_BYTES: usize = 1024 * 1024;
pub(in crate::smart_http::server::pulls) const MAX_CONTENT_BYTES: usize = 32 * 1024 * 1024;
pub(in crate::smart_http::server::pulls) const MAX_UPLOAD_BYTES: usize =
    multipart::MAX_COMMAND_BYTES + MAX_CONTENT_BYTES + 129 * (4096 + 80);

pub(in crate::smart_http::server::pulls) type FileParts<'a> = BTreeMap<&'a str, &'a [u8]>;

#[derive(Debug)]
pub(in crate::smart_http::server::pulls) struct Upload<'a> {
    pub command: &'a [u8],
    pub files: FileParts<'a>,
}

pub(in crate::smart_http::server::pulls) fn boundary(content_type: &str) -> Result<&str, ApiError> {
    multipart::boundary(content_type).map_err(|_| ApiError::media())
}

pub(in crate::smart_http::server::pulls) fn file_name(name: &str) -> bool {
    let Some(index) = name.strip_prefix("file_") else {
        return false;
    };
    !index.is_empty()
        && index.len() <= 3
        && !(index.len() > 1 && index.starts_with('0'))
        && index.bytes().all(|byte| byte.is_ascii_digit())
        && index.parse::<usize>().is_ok_and(|index| index < MAX_FILES)
}

pub(in crate::smart_http::server::pulls) fn parse<'a>(
    bytes: &'a [u8],
    boundary: &str,
    live: &mut impl FnMut() -> bool,
) -> Result<Upload<'a>, ApiError> {
    let mut command = None;
    let mut files = BTreeMap::new();
    let mut content_bytes = 0usize;
    multipart::visit_parts(
        bytes,
        boundary,
        MAX_UPLOAD_BYTES,
        MAX_FILES + 1,
        live,
        |part| {
            if part.name == "command" && command.is_none() && multipart::command_media(part.media) {
                if part.content.len() > multipart::MAX_COMMAND_BYTES {
                    return Err(multipart::Error::Limit);
                }
                command = Some(part.content);
            } else if file_name(part.name)
                && part.media.eq_ignore_ascii_case("application/octet-stream")
            {
                if part.content.len() > MAX_FILE_BYTES {
                    return Err(multipart::Error::Limit);
                }
                content_bytes = content_bytes
                    .checked_add(part.content.len())
                    .filter(|size| *size <= MAX_CONTENT_BYTES)
                    .ok_or(multipart::Error::Limit)?;
                if files.insert(part.name, part.content).is_some() {
                    return Err(multipart::Error::Framing);
                }
            } else {
                return Err(multipart::Error::Framing);
            }
            Ok(())
        },
    )
    .map_err(|error| match error {
        multipart::Error::Limit => ApiError::too_large(),
        multipart::Error::Framing => ApiError::bad("invalid_resolution_upload"),
        multipart::Error::Cancelled => {
            ApiError::from_status(crate::smart_http::server::Status::Timeout, false)
        }
    })?;
    Ok(Upload {
        command: command.ok_or_else(|| ApiError::bad("resolution_command_required"))?,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn part(name: &str, content_type: &str, content: &[u8]) -> Vec<u8> {
        let mut bytes = format!("--resolution\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"../../never-open\"\r\nContent-Type: {content_type}\r\n\r\n").into_bytes();
        bytes.extend_from_slice(content);
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
    fn complete(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.extend_from_slice(b"--resolution--\r\n");
        bytes
    }
    #[test]
    fn multiple_binary_files_are_exact_and_part_order_is_not_semantics() {
        let command = part(
            "command",
            "application/x-www-form-urlencoded",
            b"resolution=ff:file:100755:file_1",
        );
        let a = part("file_0", "application/octet-stream", b"");
        let b = part(
            "file_1",
            "application/octet-stream",
            b"\0\xff\r\n--resolutionX\r\n",
        );
        for parts in [
            vec![command.clone(), a.clone(), b.clone()],
            vec![b, a, command],
        ] {
            let bytes = complete(parts.concat());
            let upload = parse(&bytes, "resolution", &mut || true).unwrap();
            assert_eq!(upload.command, b"resolution=ff:file:100755:file_1");
            assert_eq!(upload.files["file_0"], b"");
            assert_eq!(upload.files["file_1"], b"\0\xff\r\n--resolutionX\r\n");
            let offset = upload.files["file_1"].as_ptr() as usize - bytes.as_ptr() as usize;
            assert_eq!(
                &bytes[offset..offset + upload.files["file_1"].len()],
                upload.files["file_1"]
            );
        }
    }
    #[test]
    fn duplicate_unknown_mistyped_and_unbounded_parts_refuse() {
        let command = part("command", "application/x-www-form-urlencoded", b"a=b");
        for name in [
            "bundle",
            "file_",
            "file_00",
            "file_-1",
            "file_128",
            "file_0/../../x",
        ] {
            let bytes = complete(
                [
                    command.clone(),
                    part(name, "application/octet-stream", b"x"),
                ]
                .concat(),
            );
            assert!(parse(&bytes, "resolution", &mut || true).is_err(), "{name}");
        }
        let duplicate = complete(
            [
                command.clone(),
                part("file_0", "application/octet-stream", b"a"),
                part("file_0", "application/octet-stream", b"b"),
            ]
            .concat(),
        );
        assert!(parse(&duplicate, "resolution", &mut || true).is_err());
        let mistyped = complete([command.clone(), part("file_0", "text/plain", b"text")].concat());
        assert!(parse(&mistyped, "resolution", &mut || true).is_err());
        let huge = complete(
            [
                command,
                part(
                    "file_0",
                    "application/octet-stream",
                    &vec![0; MAX_FILE_BYTES + 1],
                ),
            ]
            .concat(),
        );
        assert_eq!(
            parse(&huge, "resolution", &mut || true).unwrap_err().code,
            "resource_limit"
        );
    }
    #[test]
    fn cancelled_and_incomplete_envelopes_have_no_usable_upload() {
        let bytes = complete(
            [
                part("file_0", "application/octet-stream", b"\0\xff"),
                part("command", "application/x-www-form-urlencoded", b"a=b"),
            ]
            .concat(),
        );
        for end in 0..bytes.len() - 2 {
            assert!(parse(&bytes[..end], "resolution", &mut || true).is_err());
        }
        assert_eq!(
            parse(&bytes, "resolution", &mut || false).unwrap_err().code,
            "request_timeout"
        );
        let missing = complete(part("file_0", "application/octet-stream", b"x"));
        assert!(parse(&missing, "resolution", &mut || true).is_err());
        let mut tail = bytes;
        tail.extend_from_slice(b"next request");
        assert!(parse(&tail, "resolution", &mut || true).is_err());
    }
}
