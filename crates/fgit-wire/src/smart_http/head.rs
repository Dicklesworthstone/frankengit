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
    /// The request's `Host` authority, syntax-checked; absent only on HTTP/1.0.
    pub host: Option<&'a str>,
    /// The browser-supplied `Origin`, if any. Stock Git never sends one.
    pub origin: Option<&'a str>,
    /// The browser-supplied `Sec-Fetch-Site`, if any.
    pub sec_fetch_site: Option<&'a str>,
    pub(super) authorization: Option<&'a str>,
    range: Result<Option<&'a str>, HttpError>,
    if_range: Result<Option<&'a str>, HttpError>,
    tus_resumable: Result<Option<&'a str>, HttpError>,
    upload_offset: Result<Option<&'a str>, HttpError>,
    upload_length: Result<Option<&'a str>, HttpError>,
    upload_checksum: Result<Option<&'a str>, HttpError>,
    upload_concat: Result<Option<&'a str>, HttpError>,
    upload_defer_length: Result<Option<&'a str>, HttpError>,
    upload_metadata: Result<Option<&'a str>, HttpError>,
    method_override: Result<Option<&'a str>, HttpError>,
}

impl Envelope<'_> {
    #[must_use]
    pub const fn authorization(&self) -> Option<&str> {
        self.authorization
    }

    /// Borrowed Range metadata, with duplicate fields reported to the endpoint.
    /// The envelope does not interpret ranges or change unrelated route behavior.
    pub const fn range(&self) -> Result<Option<&str>, HttpError> {
        self.range
    }

    /// Borrowed If-Range metadata; only an endpoint serving ranges evaluates it.
    pub const fn if_range(&self) -> Result<Option<&str>, HttpError> {
        self.if_range
    }

    /// Borrowed Tus protocol version; the authenticated endpoint selects support.
    pub const fn tus_resumable(&self) -> Result<Option<&str>, HttpError> {
        self.tus_resumable
    }

    /// Borrowed Tus offset; no numeric conversion or upload lookup occurs here.
    pub const fn upload_offset(&self) -> Result<Option<&str>, HttpError> {
        self.upload_offset
    }

    /// Borrowed declared upload length, with duplicate policy deferred.
    pub const fn upload_length(&self) -> Result<Option<&str>, HttpError> {
        self.upload_length
    }

    /// Borrowed optional checksum metadata; its presence grants no extension.
    pub const fn upload_checksum(&self) -> Result<Option<&str>, HttpError> {
        self.upload_checksum
    }

    /// Borrowed optional concatenation metadata; only the endpoint interprets it.
    pub const fn upload_concat(&self) -> Result<Option<&str>, HttpError> {
        self.upload_concat
    }

    /// Borrowed deferred-length metadata, without admitting creation extensions.
    pub const fn upload_defer_length(&self) -> Result<Option<&str>, HttpError> {
        self.upload_defer_length
    }

    /// Borrowed optional creation metadata; never decoded or reflected here.
    pub const fn upload_metadata(&self) -> Result<Option<&str>, HttpError> {
        self.upload_metadata
    }

    /// Borrowed method override. The envelope's actual HTTP method is unchanged.
    pub const fn method_override(&self) -> Result<Option<&str>, HttpError> {
        self.method_override
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
    let (mut origin, mut sec_fetch_site) = (None, None);
    let (mut range, mut if_range) = (Ok(None), Ok(None));
    let (mut tus_resumable, mut upload_offset, mut upload_length) = (Ok(None), Ok(None), Ok(None));
    let (mut upload_checksum, mut upload_concat, mut upload_defer_length) =
        (Ok(None), Ok(None), Ok(None));
    let (mut upload_metadata, mut method_override) = (Ok(None), Ok(None));
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
        } else if name.eq_ignore_ascii_case("origin") {
            unique(&mut origin, value)?;
        } else if name.eq_ignore_ascii_case("sec-fetch-site") {
            unique(&mut sec_fetch_site, value)?;
        } else if name.eq_ignore_ascii_case("range") {
            deferred_unique(&mut range, value);
        } else if name.eq_ignore_ascii_case("if-range") {
            deferred_unique(&mut if_range, value);
        } else if name.eq_ignore_ascii_case("tus-resumable") {
            deferred_unique(&mut tus_resumable, value);
        } else if name.eq_ignore_ascii_case("upload-offset") {
            deferred_unique(&mut upload_offset, value);
        } else if name.eq_ignore_ascii_case("upload-length") {
            deferred_unique(&mut upload_length, value);
        } else if name.eq_ignore_ascii_case("upload-checksum") {
            deferred_unique(&mut upload_checksum, value);
        } else if name.eq_ignore_ascii_case("upload-concat") {
            deferred_unique(&mut upload_concat, value);
        } else if name.eq_ignore_ascii_case("upload-defer-length") {
            deferred_unique(&mut upload_defer_length, value);
        } else if name.eq_ignore_ascii_case("upload-metadata") {
            deferred_unique(&mut upload_metadata, value);
        } else if name.eq_ignore_ascii_case("x-http-method-override") {
            deferred_unique(&mut method_override, value);
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
            host,
            origin,
            sec_fetch_site,
            authorization,
            range,
            if_range,
            tus_resumable,
            upload_offset,
            upload_length,
            upload_checksum,
            upload_concat,
            upload_defer_length,
            upload_metadata,
            method_override,
        },
        selected,
    )))
}

// Range and Tus are endpoint policy, not message framing. Remember ambiguity
// without rejecting requests to endpoints which previously ignored these fields.
fn deferred_unique<'a>(field: &mut Result<Option<&'a str>, HttpError>, value: &'a str) {
    *field = match *field {
        Ok(None) => Ok(Some(value)),
        _ => Err(HttpError::DuplicateHeader),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const TUS_HEADERS: [&str; 8] = [
        "Tus-Resumable",
        "Upload-Offset",
        "Upload-Length",
        "Upload-Checksum",
        "Upload-Concat",
        "Upload-Defer-Length",
        "Upload-Metadata",
        "X-HTTP-Method-Override",
    ];

    fn tus_fields<'a>(head: &'a Envelope<'_>) -> [Result<Option<&'a str>, HttpError>; 8] {
        [
            head.tus_resumable(),
            head.upload_offset(),
            head.upload_length(),
            head.upload_checksum(),
            head.upload_concat(),
            head.upload_defer_length(),
            head.upload_metadata(),
            head.method_override(),
        ]
    }

    #[test]
    fn tus_metadata_is_borrowed_without_reading_body_or_changing_actual_method() {
        let values = [
            "1.0.0",
            "7",
            "13",
            "sha256 private-checksum",
            "partial",
            "1",
            "filename private-metadata",
            "PATCH",
        ];
        let mut input = String::from(
            "POST /repo.git/info/lfs/uploads/id/13 HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer top-secret\r\nContent-Length: 3\r\n",
        );
        for (name, value) in TUS_HEADERS.iter().zip(values) {
            input.push_str(&format!("{}: \t{value}\t \r\n", name.to_ascii_lowercase()));
        }
        input.push_str("\r\n");
        let header_len = input.len();
        let mut bytes = input.into_bytes();
        bytes.extend_from_slice(&[0xff, 0, 0xfe]);
        let head = parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.body, BodyFraming::ContentLength(3));
        assert_eq!(head.consumed, header_len);
        assert_eq!(&bytes[head.consumed..], &[0xff, 0, 0xfe]);
        assert_eq!(head.authorization(), Some("Bearer top-secret"));
        for (actual, expected) in tus_fields(&head).into_iter().zip(values) {
            let actual = actual.unwrap().unwrap();
            assert_eq!(actual, expected);
            // The accessor points into the original request's bounded head,
            // not a reconstructed value or retained copy of the upload body.
            let start = actual.as_ptr() as usize;
            let request_start = bytes.as_ptr() as usize;
            assert!(start >= request_start);
            assert!(start + actual.len() <= request_start + head.consumed);
        }
        let debug = format!("{head:?}");
        for private in ["top-secret", "private-checksum", "private-metadata"] {
            assert!(!debug.contains(private));
        }
    }

    #[test]
    fn tus_duplicates_remain_endpoint_policy_and_do_not_change_git_routes() {
        for (selected, name) in TUS_HEADERS.iter().enumerate() {
            let bytes = format!(
                "GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: local\r\n{name}: first\r\n{}: second\r\n{name}: third\r\n\r\n",
                name.to_ascii_lowercase()
            );
            let head = parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            for (index, field) in tus_fields(&head).into_iter().enumerate() {
                assert_eq!(
                    field,
                    if index == selected {
                        Err(HttpError::DuplicateHeader)
                    } else {
                        Ok(None)
                    }
                );
            }
            assert_eq!(head.range(), Ok(None));
            assert_eq!(head.if_range(), Ok(None));
            let git = super::super::parse_head(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                git.operation,
                super::super::Operation::Discover(super::super::Service::UploadPack)
            );
        }
    }

    #[test]
    fn tus_values_are_deferred_but_framing_and_header_bounds_remain_mandatory() {
        let values = [
            "unknown-version",
            "-1",
            "18446744073709551616",
            "unsupported-algorithm not-base64",
            "final;arbitrary",
            "unsupported",
            "unparsed metadata",
            "unsupported-method",
        ];
        let mut bytes = String::from(
            "GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: local\r\n",
        );
        for (name, value) in TUS_HEADERS.iter().zip(values) {
            bytes.push_str(&format!("{name}: {value}\r\n"));
        }
        bytes.push_str("\r\n");
        let limits = HttpLimits {
            max_headers: TUS_HEADERS.len() + 1,
            ..HttpLimits::default()
        };
        let head = parse(bytes.as_bytes(), limits).unwrap().unwrap();
        assert_eq!(tus_fields(&head), values.map(|value| Ok(Some(value))));
        assert!(super::super::parse_head(bytes.as_bytes(), limits).is_ok());
        assert!(matches!(
            parse(
                bytes.as_bytes(),
                HttpLimits {
                    max_headers: limits.max_headers - 1,
                    ..limits
                }
            ),
            Err(HttpError::TooManyHeaders)
        ));
        for name in TUS_HEADERS {
            let invalid = format!(
                "PATCH /repo.git/info/lfs/uploads/id/13 HTTP/1.1\r\nHost: local\r\n{name}: invalid\u{1f}value\r\n\r\n"
            );
            assert!(matches!(
                parse(invalid.as_bytes(), HttpLimits::default()),
                Err(HttpError::InvalidHeader)
            ));
        }
    }

    #[test]
    fn range_metadata_is_borrowed_and_duplicate_policy_is_deferred_to_the_endpoint() {
        let bytes = b"GET /repo.git/info/lfs/objects/id/10 HTTP/1.1\r\nHost: local\r\nRaNgE: bytes=2-\r\nIF-RANGE: \"strong\"\r\n\r\n";
        let head = parse(bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(head.range(), Ok(Some("bytes=2-")));
        assert_eq!(head.if_range(), Ok(Some("\"strong\"")));
        for (field, value) in [("Range", "bytes=2-"), ("If-Range", "\"strong\"")] {
            let bytes = format!(
                "GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: local\r\n{field}: {value}\r\n{field}: {value}\r\n\r\n"
            );
            let head = parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                if field == "Range" {
                    head.range()
                } else {
                    head.if_range()
                },
                Err(HttpError::DuplicateHeader)
            );
            assert!(super::super::parse_head(bytes.as_bytes(), HttpLimits::default()).is_ok());
        }
        let bytes = b"GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: local\r\nRange: malformed\r\n\r\n";
        assert!(super::super::parse_head(bytes, HttpLimits::default()).is_ok());
    }

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

    /// The browser's own statements about a request's source reach the
    /// cross-site guard verbatim, and a client that sends neither leaves both
    /// absent (frankengit-root-doctrine-x2mv.4.31).
    #[test]
    fn origin_fetch_metadata_and_host_are_captured_for_the_cross_site_guard() {
        let bytes = b"POST /repo.git/api/v1/issues/1/open HTTP/1.1\r\nHost: 127.0.0.1:8123\r\norigin: null\r\nSEC-FETCH-SITE: same-origin\r\n\r\n";
        let head = parse(bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!(head.host, Some("127.0.0.1:8123"));
        assert_eq!(head.origin, Some("null"));
        assert_eq!(head.sec_fetch_site, Some("same-origin"));
        let bytes = b"POST /repo.git/git-upload-pack HTTP/1.1\r\nHost: local\r\n\r\n";
        let head = parse(bytes, HttpLimits::default()).unwrap().unwrap();
        assert_eq!((head.origin, head.sec_fetch_site), (None, None));
    }

    #[test]
    fn ambiguous_framing_and_hop_by_hop_credentials_still_fail_closed() {
        for headers in [
            "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
            "Content-Length: 0\r\ncontent-length: 0\r\n",
            "Authorization: a\r\nauthorization: b\r\n",
            "Origin: http://a\r\norigin: http://b\r\n",
            "Sec-Fetch-Site: same-origin\r\nsec-fetch-site: cross-site\r\n",
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
