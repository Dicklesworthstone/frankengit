//! A closed, deadline-bound client for the existing loopback HTTP service.
//! Credentials cannot leave the explicitly selected numeric loopback endpoint.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use fgit_verified_read::blob::MAX_VERIFIED_BLOB_FRAME_BYTES;

use super::options::{Options, Url};
use super::{Error, head_token, hex};

const MAX_HEADER_BYTES: usize = 16 * 1024;
// Match the bounded request profile in fgit_wire::smart_http::HttpLimits.
// Hex-encoded byte paths may reach this transport limit before their native
// 4,096-byte path limit; file verification retains the full native limit.
const MAX_TARGET_BYTES: usize = 4096;
const MEDIA_TYPE: &str = "application/vnd.frankengit.verified-blob";

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            Error::new(
                "deadline_exceeded",
                "HTTP proof fetch exceeded the command deadline",
            )
        })
}

pub(super) fn fetch(
    url: &Url,
    token: &str,
    options: &Options,
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    let target = request_target(url, options)?;
    let mut stream = TcpStream::connect_timeout(&url.address, remaining(deadline)?)
        .map_err(|error| Error::new("http_connect", error.to_string()))?;
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: {MEDIA_TYPE}\r\nUser-Agent: FrankenGit/0.0.1\r\nConnection: close\r\n\r\n",
        url.address, token
    );
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|error| Error::new("http_deadline", error.to_string()))?;
    let result = (|| {
        stream
            .write_all(request.as_bytes())
            .map_err(|error| Error::new("http_write", error.to_string()))?;
        read_response(&mut stream, deadline)
    })();
    // Closing the owned stream is the end of this read-only operation. It does
    // not imply anything about a mutation because no transaction was created.
    let _ = stream.shutdown(Shutdown::Both);
    result
}

pub(super) fn request_target(url: &Url, options: &Options) -> Result<String, Error> {
    let target = format!(
        "{}/api/v1/source/verified-blob?ref_hex={}&path_hex={}&expected_head={}",
        url.route,
        hex(options.reference.as_bytes()),
        hex(&options.path),
        head_token(options.head)
    );
    if target.len() > MAX_TARGET_BYTES {
        return Err(Error::new(
            "http_target_limit",
            "encoded proof request target exceeds the 4,096-byte HTTP profile; use a canonical proof file for larger native paths",
        ));
    }
    Ok(target)
}

fn read(stream: &mut TcpStream, bytes: &mut [u8], deadline: Instant) -> Result<usize, Error> {
    stream
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|error| Error::new("http_deadline", error.to_string()))?;
    stream
        .read(bytes)
        .map_err(|error| Error::new("http_read", error.to_string()))
}

fn read_response(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, Error> {
    let mut received = Vec::new();
    let header_end = loop {
        if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            if position + 4 > MAX_HEADER_BYTES {
                return Err(Error::new(
                    "http_framing",
                    "response headers exceed the byte limit",
                ));
            }
            break position + 4;
        }
        if received.len() >= MAX_HEADER_BYTES {
            return Err(Error::new(
                "http_framing",
                "response headers exceed the byte limit",
            ));
        }
        let mut chunk = [0; 1024];
        let length = read(stream, &mut chunk, deadline)?;
        if length == 0 {
            return Err(Error::new("http_framing", "truncated response headers"));
        }
        received.extend_from_slice(&chunk[..length]);
    };
    let length = response_length(&received[..header_end])?;
    let suffix = &received[header_end..];
    if suffix.len() > length {
        return Err(Error::new(
            "http_framing",
            "bytes follow the declared proof envelope",
        ));
    }
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| Error::new("resource_limit", "cannot reserve bounded proof frame"))?;
    body.extend_from_slice(suffix);
    let mut chunk = [0; 64 * 1024];
    while body.len() < length {
        let wanted = (length - body.len()).min(chunk.len());
        let read = read(stream, &mut chunk[..wanted], deadline)?;
        if read == 0 {
            return Err(Error::new("http_framing", "truncated proof envelope"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    if read(stream, &mut chunk[..1], deadline)? != 0 {
        return Err(Error::new(
            "http_framing",
            "bytes follow the declared proof envelope",
        ));
    }
    Ok(body)
}

fn response_length(bytes: &[u8]) -> Result<usize, Error> {
    let invalid = || {
        Error::new(
            "http_framing",
            "unsupported or ambiguous proof response framing",
        )
    };
    if bytes.len() > MAX_HEADER_BYTES
        || !bytes.ends_with(b"\r\n\r\n")
        || !bytes.iter().all(|byte| {
            matches!(byte, b'\r' | b'\n' | b'\t') || byte.is_ascii_graphic() || *byte == b' '
        })
    {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status = lines.next().ok_or_else(invalid)?;
    if status.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid());
    }
    let mut parts = status.splitn(3, ' ');
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(invalid());
    }
    let code = parts.next().ok_or_else(invalid)?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    if code != "200" {
        return Err(Error::new(
            "http_status",
            format!("proof endpoint returned HTTP {code}; no proof or head pin was accepted"),
        ));
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if headers.len() == 64
            || line.len() > 4096
            || line.starts_with([' ', '\t'])
            || line
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(invalid());
        }
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid());
        }
        let name = name.to_ascii_lowercase();
        if headers
            .insert(name, value.trim_matches([' ', '\t']))
            .is_some()
        {
            return Err(invalid());
        }
    }
    if headers.contains_key("transfer-encoding")
        || headers.contains_key("content-encoding")
        || headers.get("content-type").copied() != Some(MEDIA_TYPE)
        || !headers
            .get("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("close"))
    {
        return Err(invalid());
    }
    let length = headers.get("content-length").ok_or_else(invalid)?;
    if length.is_empty()
        || !length.bytes().all(|byte| byte.is_ascii_digit())
        || length.starts_with('0')
    {
        return Err(invalid());
    }
    let length: usize = length.parse().map_err(|_| invalid())?;
    if length > MAX_VERIFIED_BLOB_FRAME_BYTES {
        return Err(Error::new(
            "resource_limit",
            "proof envelope exceeds the protocol limit",
        ));
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(extra: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: {MEDIA_TYPE}\r\nContent-Length: 9\r\nConnection: close\r\n{extra}\r\n").into_bytes()
    }

    #[test]
    fn accepts_exact_framing_and_rejects_transformations_ambiguity_and_redirects() {
        assert_eq!(response_length(&head("")).unwrap(), 9);
        for extra in [
            "Content-Length: 9\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Encoding: gzip\r\n",
            " Content-Length: 8\r\n",
            "Bad Header: x\r\n",
            "Ignored: one\ntwo\r\n",
            "Ignored: one\rtwo\r\n",
        ] {
            assert!(response_length(&head(extra)).is_err(), "{extra}");
        }
        assert_eq!(
            response_length(b"HTTP/1.1 302 Found\r\nLocation: http://other/\r\n\r\n")
                .unwrap_err()
                .kind,
            "http_status"
        );
        for length in ["0", "09", "-1", "18446744073709551616"] {
            let bytes = String::from_utf8(head(""))
                .unwrap()
                .replace("Content-Length: 9", &format!("Content-Length: {length}"));
            assert!(response_length(bytes.as_bytes()).is_err());
        }
    }
}
