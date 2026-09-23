//! One HTTP framing parser for Git and native repository endpoints.
//!
//! This layer validates the envelope, not the endpoint's method, media type,
//! body policy, credentials, or authority. Endpoint adapters must check those
//! before sending 100 Continue or retaining a transaction body.

use std::fmt;

use super::{BodyFraming, HttpError, HttpLimits, HttpVersion, decimal, token_byte, unique};

/// An explicitly selected content coding, independent of HTTP transfer framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentEncoding {
    Identity,
    Gzip,
}

/// Borrowed, syntactically validated HTTP metadata. Credentials are redacted.
pub struct Envelope<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub version: HttpVersion,
    pub body: BodyFraming,
    pub content_encoding: ContentEncoding,
    pub expect_continue: bool,
    pub consumed: usize,
    pub content_type: Option<&'a str>,
    pub git_protocol: Option<&'a str>,
    pub(super) authorization: Option<&'a str>,
}

impl Envelope<'_> {
    #[must_use]
    pub const fn authorization(&self) -> Option<&str> {
        self.authorization
    }
}

impl fmt::Debug for Envelope<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Envelope")
            .field("method", &self.method)
            .field("version", &self.version)
            .field("body", &self.body)
            .field("content_encoding", &self.content_encoding)
            .field("expect_continue", &self.expect_continue)
            .field("consumed", &self.consumed)
            .field("authorization", &self.authorization.map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

/// Parse one bounded header without copying or inspecting trailing body bytes.
/// A completed envelope conveys no authentication or endpoint permission.
pub fn parse(input: &[u8], limits: HttpLimits) -> Result<Option<Envelope<'_>>, HttpError> {
    parse_with(input, limits, |_, _| Ok(())).map(|head| head.map(|(envelope, ())| envelope))
}

// Git keeps its existing route-before-header-error ordering. Both entry points
// then execute exactly the same framing checks; no second HTTP parser drifts.
pub(super) fn parse_with<'a, T>(
    input: &'a [u8],
    limits: HttpLimits,
    select: impl FnOnce(&'a str, &'a str) -> Result<T, HttpError>,
) -> Result<Option<(Envelope<'a>, T)>, HttpError> {
    limits.validate()?;
    let visible = &input[..input.len().min(limits.max_head_bytes)];
    let Some(end) = visible.windows(4).position(|part| part == b"\r\n\r\n") else {
        return if input.len() >= limits.max_head_bytes {
            Err(HttpError::HeadTooLarge)
        } else {
            Ok(None)
        };
    };
    let text = std::str::from_utf8(&input[..end]).map_err(|_| HttpError::InvalidHeader)?;
    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or(HttpError::InvalidRequest)?;
    let mut words = request.split(' ');
    let method = words.next().ok_or(HttpError::InvalidRequest)?;
    let target = words.next().ok_or(HttpError::InvalidRequest)?;
    let version = words.next().ok_or(HttpError::InvalidRequest)?;
    if words.next().is_some()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || method.is_empty()
        || !method.bytes().all(token_byte)
    {
        return Err(HttpError::InvalidRequest);
    }
    if target.len() > limits.max_target_bytes
        || !target.starts_with('/')
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"#\\".contains(&byte))
    {
        return Err(HttpError::InvalidRoute);
    }
    let selected = select(method, target)?;
    let (mut host, mut length, mut transfer, mut media, mut protocol, mut authorization) =
        (None, None, None, None, None, None);
    let (mut encoding, mut expectation, mut connection) = (None, None, None);
    for (index, line) in lines.enumerate() {
        if index >= limits.max_headers {
            return Err(HttpError::TooManyHeaders);
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::InvalidHeader)?;
        if name.is_empty()
            || !name.bytes().all(token_byte)
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (32..=126).contains(&byte))
        {
            return Err(HttpError::InvalidHeader);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            unique(&mut host, value)?;
        } else if name.eq_ignore_ascii_case("content-length") {
            unique(&mut length, value)?;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            unique(&mut transfer, value)?;
        } else if name.eq_ignore_ascii_case("content-type") {
            unique(&mut media, value)?;
        } else if name.eq_ignore_ascii_case("git-protocol") {
            unique(&mut protocol, value)?;
        } else if name.eq_ignore_ascii_case("authorization") {
            unique(&mut authorization, value)?;
        } else if name.eq_ignore_ascii_case("content-encoding") {
            unique(&mut encoding, value)?;
        } else if name.eq_ignore_ascii_case("expect") {
            unique(&mut expectation, value)?;
        } else if name.eq_ignore_ascii_case("connection") {
            unique(&mut connection, value)?;
        } else if name.eq_ignore_ascii_case("trailer") {
            return Err(HttpError::TrailersNotSupported);
        }
    }
    if (version == "HTTP/1.1" && host.is_none())
        || host.is_some_and(|value| {
            value.is_empty()
                || value
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b"/?#@\\,".contains(&b))
        })
    {
        return Err(HttpError::InvalidHost);
    }
    if connection.is_some_and(|value| {
        value.split(',').any(|part| {
            let part = part.trim_matches([' ', '\t']);
            !part.eq_ignore_ascii_case("close") && !part.eq_ignore_ascii_case("keep-alive")
        })
    }) {
        return Err(HttpError::InvalidHeader);
    }
    let content_encoding = match encoding {
        None => ContentEncoding::Identity,
        Some(value) if value.eq_ignore_ascii_case("identity") => ContentEncoding::Identity,
        Some(value) if value.eq_ignore_ascii_case("gzip") => ContentEncoding::Gzip,
        Some(_) => return Err(HttpError::UnsupportedContentEncoding),
    };
    // The live gateway first parses this shared envelope even for Git routes.
    // Permit gzip only at the exact upload RPC route, using the same selector
    // as parse_head. Native APIs, discovery and receive remain identity-only.
    if content_encoding == ContentEncoding::Gzip
        && !matches!(
            super::route(method, target, limits.max_target_bytes),
            Ok((super::Operation::Rpc(super::Service::UploadPack), _))
        )
    {
        return Err(HttpError::UnsupportedContentEncoding);
    }
    if length.is_some() && transfer.is_some() {
        return Err(HttpError::AmbiguousFraming);
    }
    let body = if let Some(value) = length {
        let count = decimal(value)?;
        if count > limits.max_body_bytes {
            return Err(HttpError::BodyTooLarge);
        }
        BodyFraming::ContentLength(count)
    } else if let Some(value) = transfer {
        if version != "HTTP/1.1" || !value.eq_ignore_ascii_case("chunked") {
            return Err(HttpError::AmbiguousFraming);
        }
        BodyFraming::Chunked
    } else {
        BodyFraming::Empty
    };
    let expect_continue = match expectation {
        None => false,
        Some(value) if value.eq_ignore_ascii_case("100-continue") => true,
        Some(_) => return Err(HttpError::UnsupportedExpectation),
    };
    Ok(Some((
        Envelope {
            method,
            target,
            version: if version == "HTTP/1.0" {
                HttpVersion::Http10
            } else {
                HttpVersion::Http11
            },
            body,
            content_encoding,
            expect_continue,
            consumed: end + 4,
            content_type: media,
            git_protocol: protocol,
            authorization,
        },
        selected,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_envelopes_do_not_relax_git_endpoint_policy() {
        let bytes = b"POST /repo.git/api/v1/issues/1/open HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\nAuthorization: Bearer secret\r\n\r\nx=y";
        let head = parse(bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(head.target, "/repo.git/api/v1/issues/1/open");
        assert_eq!(head.body, BodyFraming::ContentLength(3));
        assert_eq!(&bytes[head.consumed..], b"x=y");
        assert_eq!(head.authorization(), Some("Bearer secret"));
        assert!(!format!("{head:?}").contains("secret"));
        assert!(super::super::parse_head(bytes, HttpLimits::default()).is_err());
    }

    #[test]
    fn every_header_fragment_waits_and_binary_body_is_not_header_text() {
        let header = b"GET /repo.git/api/v1/issues HTTP/1.1\r\nHost: local\r\n\r\n";
        for end in 0..header.len() {
            assert!(
                parse(&header[..end], HttpLimits::default())
                    .unwrap()
                    .is_none()
            );
        }
        let mut input = header.to_vec();
        input.extend_from_slice(&[0xff, 0, 0xfe]);
        assert_eq!(
            parse(&input, HttpLimits::default())
                .unwrap()
                .unwrap()
                .consumed,
            header.len()
        );
    }

    #[test]
    fn ambiguous_framing_and_hop_by_hop_credentials_still_fail_closed() {
        for headers in [
            "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
            "Content-Length: 0\r\ncontent-length: 0\r\n",
            "Authorization: a\r\nauthorization: b\r\n",
            "Connection: authorization\r\n",
            "Trailer: anything\r\n",
            "Content-Encoding: gzip\r\n",
            " Host: hidden\r\n",
        ] {
            let input = format!(
                "POST /repo.git/api/v1/issues/1/open HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            assert!(
                parse(input.as_bytes(), HttpLimits::default()).is_err(),
                "{headers}"
            );
        }
    }
}
