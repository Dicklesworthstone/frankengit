//! Bounded HTTP/1.x framing for Git smart discovery and stateless RPC.
//!
//! This module owns neither sockets nor authority. A host adapter must resolve
//! the exact repository route, authenticate and authorize EVERY request before
//! advertising refs or accepting a receive, and finish HTTP decoding before
//! admitting any mutation. Never promote a URL or an Authorization header into
//! a principal. Upload-pack RPC supports bounded gzip content decoding; other
//! endpoints refuse non-identity encodings rather than passing them to Git.
//!
//! The deliberately narrow profile accepts canonical ASCII repository routes,
//! HTTP/1.0 or HTTP/1.1, fixed-length or chunked RPC bodies, and no trailers.
//! HTTP transfer decoding is zero-copy and stops exactly at the request boundary.
//! Failure poisons the decoder: a host must close, not reuse, that connection.

#![forbid(unsafe_code)]

/// Shared bounded HTTP envelopes; endpoint policy remains adapter-owned.
pub mod head;
pub use head::ContentEncoding;
/// Backpressured native pack response streaming and aggregate byte budgets.
pub mod response;
/// Composition with the existing native upload-pack and receive-pack machines.
pub mod rpc;

use std::fmt::{self, Display, Formatter};

/// HTTP resource ceilings, independent of pack expansion and Git wire limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpLimits {
    pub max_head_bytes: usize,
    pub max_headers: usize,
    pub max_target_bytes: usize,
    /// Ceiling on both the transfer-decoded body and, for gzip upload RPCs,
    /// its expanded Git payload. Compression never bypasses the byte limit.
    pub max_body_bytes: u64,
    pub max_body_wire_bytes: u64,
    pub max_chunks: u64,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_head_bytes: 32 * 1024,
            max_headers: 64,
            max_target_bytes: 4096,
            max_body_bytes: 128 * 1024 * 1024,
            max_body_wire_bytes: 132 * 1024 * 1024,
            max_chunks: 65_536,
        }
    }
}

impl HttpLimits {
    pub fn validate(self) -> Result<(), HttpError> {
        if !(16..=256 * 1024).contains(&self.max_head_bytes)
            || self.max_headers == 0
            || self.max_headers > 1024
            || self.max_target_bytes == 0
            || self.max_target_bytes > self.max_head_bytes
            || self.max_body_wire_bytes < self.max_body_bytes
            || self.max_chunks == 0
        {
            return Err(HttpError::InvalidLimits);
        }
        Ok(())
    }
}

/// Refusals never contain client credentials, paths, or reflected header text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpError {
    InvalidLimits,
    HeadTooLarge,
    TooManyHeaders,
    InvalidRequest,
    InvalidHeader,
    DuplicateHeader,
    InvalidHost,
    InvalidRoute,
    MethodNotAllowed,
    UnsupportedVersion,
    UnsupportedMediaType,
    UnsupportedContentEncoding,
    InvalidCompressedBody,
    UnsupportedExpectation,
    AmbiguousFraming,
    LengthRequired,
    BodyNotAllowed,
    BodyTooLarge,
    WireBudgetExceeded,
    TooManyChunks,
    InvalidChunk,
    ChunkLineTooLarge,
    TrailersNotSupported,
    TruncatedBody,
    FailedDecoder,
    ResponseLengthMismatch,
}

impl Display for HttpError {
    fn fmt(&self, out: &mut Formatter<'_>) -> fmt::Result {
        write!(out, "smart HTTP refusal: {self:?}")
    }
}
impl std::error::Error for HttpError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}
impl Service {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }
    #[must_use]
    pub const fn request_media_type(self) -> &'static str {
        match self {
            Self::UploadPack => "application/x-git-upload-pack-request",
            Self::ReceivePack => "application/x-git-receive-pack-request",
        }
    }
    #[must_use]
    pub const fn advertisement_media_type(self) -> &'static str {
        match self {
            Self::UploadPack => "application/x-git-upload-pack-advertisement",
            Self::ReceivePack => "application/x-git-receive-pack-advertisement",
        }
    }
    #[must_use]
    pub const fn result_media_type(self) -> &'static str {
        match self {
            Self::UploadPack => "application/x-git-upload-pack-result",
            Self::ReceivePack => "application/x-git-receive-pack-result",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Discover(Service),
    Rpc(Service),
}
impl Operation {
    #[must_use]
    pub const fn service(self) -> Service {
        match self {
            Self::Discover(service) | Self::Rpc(service) => service,
        }
    }
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Discover(service) => service.advertisement_media_type(),
            Self::Rpc(service) => service.result_media_type(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolVersion {
    V0,
    V1,
    V2,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpVersion {
    Http10,
    Http11,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFraming {
    Empty,
    ContentLength(u64),
    Chunked,
}

/// Borrowed request metadata. The route is an opaque routing key, NOT a path
/// that can be joined onto a filesystem root. Debug output redacts credentials.
pub struct RequestHead<'a> {
    pub operation: Operation,
    pub repository_route: &'a str,
    pub requested_version: ProtocolVersion,
    pub http_version: HttpVersion,
    pub body: BodyFraming,
    pub content_encoding: ContentEncoding,
    pub expect_continue: bool,
    pub consumed: usize,
    authorization: Option<&'a str>,
}
impl RequestHead<'_> {
    /// Raw credential input for the host's authentication boundary only.
    #[must_use]
    pub const fn authorization(&self) -> Option<&str> {
        self.authorization
    }
}
impl fmt::Debug for RequestHead<'_> {
    fn fmt(&self, out: &mut Formatter<'_>) -> fmt::Result {
        out.debug_struct("RequestHead")
            .field("operation", &self.operation)
            .field("repository_route", &self.repository_route)
            .field("requested_version", &self.requested_version)
            .field("http_version", &self.http_version)
            .field("body", &self.body)
            .field("content_encoding", &self.content_encoding)
            .field("expect_continue", &self.expect_continue)
            .field("consumed", &self.consumed)
            .field("authorization", &self.authorization.map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Inspect a bounded accumulated Git HTTP header. `None` means more bytes are
/// needed. Native endpoints share envelope framing, never Git service policy.
pub fn parse_head(input: &[u8], limits: HttpLimits) -> Result<Option<RequestHead<'_>>, HttpError> {
    let Some((envelope, (operation, repository_route))) =
        head::parse_with(input, limits, |method, target| {
            route(method, target, limits.max_target_bytes)
        })?
    else {
        return Ok(None);
    };
    match operation {
        Operation::Discover(_) => {
            if !matches!(
                envelope.body,
                BodyFraming::Empty | BodyFraming::ContentLength(0)
            ) || envelope.expect_continue
            {
                return Err(HttpError::BodyNotAllowed);
            }
        }
        Operation::Rpc(service) => {
            if envelope.body == BodyFraming::Empty {
                return Err(HttpError::LengthRequired);
            }
            if !envelope
                .content_type
                .is_some_and(|value| value.eq_ignore_ascii_case(service.request_media_type()))
            {
                return Err(HttpError::UnsupportedMediaType);
            }
        }
    }
    Ok(Some(RequestHead {
        operation,
        repository_route,
        requested_version: parse_protocol(envelope.git_protocol)?,
        body: envelope.body,
        content_encoding: envelope.content_encoding,
        http_version: envelope.version,
        expect_continue: envelope.expect_continue,
        consumed: envelope.consumed,
        authorization: envelope.authorization,
    }))
}

fn unique<'a>(slot: &mut Option<&'a str>, value: &'a str) -> Result<(), HttpError> {
    if slot.replace(value).is_some() {
        return Err(HttpError::DuplicateHeader);
    }
    Ok(())
}
fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
fn decimal(text: &str) -> Result<u64, HttpError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpError::AmbiguousFraming);
    }
    text.parse().map_err(|_| HttpError::AmbiguousFraming)
}
fn route<'a>(
    method: &str,
    target: &'a str,
    ceiling: usize,
) -> Result<(Operation, &'a str), HttpError> {
    if target.len() > ceiling || !target.starts_with('/') {
        return Err(HttpError::InvalidRoute);
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let (operation, repository) = if let Some(repository) = path.strip_suffix("/info/refs") {
        if method != "GET" {
            return Err(HttpError::MethodNotAllowed);
        }
        let service = match query {
            Some("service=git-upload-pack") => Service::UploadPack,
            Some("service=git-receive-pack") => Service::ReceivePack,
            _ => return Err(HttpError::InvalidRoute),
        };
        (Operation::Discover(service), repository)
    } else {
        if method != "POST" {
            return Err(HttpError::MethodNotAllowed);
        }
        if query.is_some() {
            return Err(HttpError::InvalidRoute);
        }
        if let Some(repository) = path.strip_suffix("/git-upload-pack") {
            (Operation::Rpc(Service::UploadPack), repository)
        } else if let Some(repository) = path.strip_suffix("/git-receive-pack") {
            (Operation::Rpc(Service::ReceivePack), repository)
        } else {
            return Err(HttpError::InvalidRoute);
        }
    };
    if repository.len() < 2
        || repository[1..].split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        })
    {
        return Err(HttpError::InvalidRoute);
    }
    Ok((operation, repository))
}
fn parse_protocol(header: Option<&str>) -> Result<ProtocolVersion, HttpError> {
    let Some(header) = header else {
        return Ok(ProtocolVersion::V0);
    };
    let mut version = None;
    for part in header.split(':') {
        let (key, value) = part
            .split_once('=')
            .map_or((part, None), |(k, v)| (k, Some(v)));
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || value.is_some_and(|v| v.is_empty() || !v.bytes().all(|b| (33..=126).contains(&b)))
        {
            return Err(HttpError::UnsupportedVersion);
        }
        if key == "version" {
            if version.is_some() {
                return Err(HttpError::DuplicateHeader);
            }
            version = Some(match value {
                Some("0") => ProtocolVersion::V0,
                Some("1") => ProtocolVersion::V1,
                Some("2") => ProtocolVersion::V2,
                _ => return Err(HttpError::UnsupportedVersion),
            });
        }
    }
    Ok(version.unwrap_or(ProtocolVersion::V0))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeState {
    Fixed(u64),
    Size,
    Data(u64),
    DataCr,
    DataLf,
    EndCr,
    EndLf,
    Complete,
    Failed,
}

/// One zero-copy step. Feed `input[consumed..]` again until it is empty or
/// `complete` is true. Only `data` belongs to the Git request payload.
#[derive(Debug, Eq, PartialEq)]
pub struct BodyStep<'a> {
    pub consumed: usize,
    pub data: &'a [u8],
    pub complete: bool,
}

/// Incremental body decoder. No body-sized buffers or per-chunk allocations.
#[derive(Debug)]
pub struct BodyDecoder {
    limits: HttpLimits,
    state: DecodeState,
    line: [u8; 1024],
    line_len: usize,
    decoded: u64,
    wire: u64,
    chunks: u64,
}
impl BodyDecoder {
    pub fn new(framing: BodyFraming, limits: HttpLimits) -> Result<Self, HttpError> {
        limits.validate()?;
        let state = match framing {
            BodyFraming::Empty | BodyFraming::ContentLength(0) => DecodeState::Complete,
            BodyFraming::ContentLength(count) => {
                if count > limits.max_body_bytes {
                    return Err(HttpError::BodyTooLarge);
                }
                DecodeState::Fixed(count)
            }
            BodyFraming::Chunked => DecodeState::Size,
        };
        Ok(Self {
            limits,
            state,
            line: [0; 1024],
            line_len: 0,
            decoded: 0,
            wire: 0,
            chunks: 0,
        })
    }
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded
    }
    #[must_use]
    pub const fn wire_bytes(&self) -> u64 {
        self.wire
    }
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, DecodeState::Complete)
    }
    /// Check transport EOF or a host-selected request boundary. A truncated
    /// request permanently poisons the decoder, even if bytes arrive later.
    pub fn finish(&mut self) -> Result<(), HttpError> {
        match self.state {
            DecodeState::Complete => Ok(()),
            DecodeState::Failed => Err(HttpError::FailedDecoder),
            _ => {
                self.state = DecodeState::Failed;
                Err(HttpError::TruncatedBody)
            }
        }
    }
    pub fn push<'a>(&mut self, input: &'a [u8]) -> Result<BodyStep<'a>, HttpError> {
        let result = self.step(input);
        if result.is_err() {
            self.state = DecodeState::Failed;
        }
        result
    }
    fn charge(&mut self, count: u64) -> Result<(), HttpError> {
        let next = self
            .wire
            .checked_add(count)
            .ok_or(HttpError::WireBudgetExceeded)?;
        if next > self.limits.max_body_wire_bytes {
            return Err(HttpError::WireBudgetExceeded);
        }
        self.wire = next;
        Ok(())
    }
    fn step<'a>(&mut self, input: &'a [u8]) -> Result<BodyStep<'a>, HttpError> {
        if self.state == DecodeState::Failed {
            return Err(HttpError::FailedDecoder);
        }
        let mut cursor = 0;
        while cursor < input.len() && self.state != DecodeState::Complete {
            match self.state {
                DecodeState::Fixed(remaining) | DecodeState::Data(remaining) => {
                    let available = input.len() - cursor;
                    let count = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(available);
                    self.charge(count as u64)?;
                    self.decoded = self
                        .decoded
                        .checked_add(count as u64)
                        .ok_or(HttpError::BodyTooLarge)?;
                    if self.decoded > self.limits.max_body_bytes {
                        return Err(HttpError::BodyTooLarge);
                    }
                    let rest = remaining - count as u64;
                    self.state = match self.state {
                        DecodeState::Fixed(_) if rest == 0 => DecodeState::Complete,
                        DecodeState::Fixed(_) => DecodeState::Fixed(rest),
                        _ if rest == 0 => DecodeState::DataCr,
                        _ => DecodeState::Data(rest),
                    };
                    return Ok(BodyStep {
                        consumed: cursor + count,
                        data: &input[cursor..cursor + count],
                        complete: self.is_complete(),
                    });
                }
                DecodeState::Size => {
                    self.charge(1)?;
                    let byte = input[cursor];
                    cursor += 1;
                    if byte == b'\n' {
                        if self.line_len == 0 || self.line[self.line_len - 1] != b'\r' {
                            return Err(HttpError::InvalidChunk);
                        }
                        let size = chunk_size(&self.line[..self.line_len - 1])?;
                        self.line_len = 0;
                        if size == 0 {
                            self.state = DecodeState::EndCr;
                        } else {
                            if size > self.limits.max_body_bytes - self.decoded {
                                return Err(HttpError::BodyTooLarge);
                            }
                            self.chunks =
                                self.chunks.checked_add(1).ok_or(HttpError::TooManyChunks)?;
                            if self.chunks > self.limits.max_chunks {
                                return Err(HttpError::TooManyChunks);
                            }
                            self.state = DecodeState::Data(size);
                        }
                    } else {
                        if self.line_len == self.line.len() {
                            return Err(HttpError::ChunkLineTooLarge);
                        }
                        self.line[self.line_len] = byte;
                        self.line_len += 1;
                    }
                }
                state @ (DecodeState::DataCr
                | DecodeState::DataLf
                | DecodeState::EndCr
                | DecodeState::EndLf) => {
                    self.charge(1)?;
                    let expected = if matches!(state, DecodeState::DataCr | DecodeState::EndCr) {
                        b'\r'
                    } else {
                        b'\n'
                    };
                    if input[cursor] != expected {
                        return Err(if state == DecodeState::EndCr {
                            HttpError::TrailersNotSupported
                        } else {
                            HttpError::InvalidChunk
                        });
                    }
                    cursor += 1;
                    self.state = match state {
                        DecodeState::DataCr => DecodeState::DataLf,
                        DecodeState::DataLf => DecodeState::Size,
                        DecodeState::EndCr => DecodeState::EndLf,
                        _ => DecodeState::Complete,
                    };
                }
                DecodeState::Complete | DecodeState::Failed => break,
            }
        }
        Ok(BodyStep {
            consumed: cursor,
            data: &[],
            complete: self.is_complete(),
        })
    }
}

fn chunk_size(line: &[u8]) -> Result<u64, HttpError> {
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 16 {
        return Err(HttpError::InvalidChunk);
    }
    let mut value = 0_u64;
    for &byte in &line[..digits] {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => byte - b'A' + 10,
        };
        value = value
            .checked_mul(16)
            .and_then(|n| n.checked_add(u64::from(digit)))
            .ok_or(HttpError::InvalidChunk)?;
    }
    let mut cursor = digits;
    while cursor < line.len() {
        skip_ows(line, &mut cursor);
        if line.get(cursor) != Some(&b';') {
            return Err(HttpError::InvalidChunk);
        }
        cursor += 1;
        skip_ows(line, &mut cursor);
        let start = cursor;
        while line.get(cursor).is_some_and(|b| token_byte(*b)) {
            cursor += 1;
        }
        if start == cursor {
            return Err(HttpError::InvalidChunk);
        }
        skip_ows(line, &mut cursor);
        if line.get(cursor) == Some(&b'=') {
            cursor += 1;
            skip_ows(line, &mut cursor);
            if line.get(cursor) == Some(&b'"') {
                cursor += 1;
                loop {
                    match line.get(cursor).copied() {
                        Some(b'"') => {
                            cursor += 1;
                            break;
                        }
                        Some(b'\\') => {
                            cursor += 1;
                            if !line
                                .get(cursor)
                                .is_some_and(|b| *b == b'\t' || (32..=126).contains(b))
                            {
                                return Err(HttpError::InvalidChunk);
                            }
                            cursor += 1;
                        }
                        Some(b'\t' | b' '..=b'!' | b'#'..=b'[' | b']'..=b'~') => cursor += 1,
                        _ => return Err(HttpError::InvalidChunk),
                    }
                }
            } else {
                let start = cursor;
                while line.get(cursor).is_some_and(|b| token_byte(*b)) {
                    cursor += 1;
                }
                if start == cursor {
                    return Err(HttpError::InvalidChunk);
                }
            }
        }
    }
    Ok(value)
}
fn skip_ows(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|b| matches!(b, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

/// Prefix to put before an advertisement produced by the Git wire machine.
/// V2 is already self-identifying and MUST NOT acquire the legacy preamble.
/// `version` is the server's selected version, not untrusted request metadata.
pub fn discovery_prefix(
    service: Service,
    version: ProtocolVersion,
) -> Result<&'static [u8], HttpError> {
    match (service, version) {
        (Service::UploadPack, ProtocolVersion::V2) => Ok(b""),
        (Service::ReceivePack, ProtocolVersion::V2) => Err(HttpError::UnsupportedVersion),
        (Service::UploadPack, _) => Ok(b"001e# service=git-upload-pack\n0000"),
        (Service::ReceivePack, _) => Ok(b"001f# service=git-receive-pack\n0000"),
    }
}

/// A successful response header, using the client's HTTP framing version.
/// The caller must already have authorized the request. A known length
/// includes any discovery prefix. Unknown lengths use chunked output for
/// HTTP/1.1 and connection-close delimiting for HTTP/1.0.
/// Use [`ResponseEncoder`] with the same version and length for the body.
#[must_use]
pub fn success_head(request: &RequestHead<'_>, body_length: Option<u64>) -> String {
    let version = match request.http_version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    let framing = match (request.http_version, body_length) {
        (_, Some(length)) => format!("Content-Length: {length}\r\n"),
        (HttpVersion::Http11, None) => "Transfer-Encoding: chunked\r\n".to_owned(),
        (HttpVersion::Http10, None) => String::new(),
    };
    format!(
        "{version} 200 OK\r\nContent-Type: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nVary: Git-Protocol, Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{framing}\r\n",
        request.operation.media_type()
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncodeState {
    Fixed(u64),
    Chunked,
    CloseDelimited,
    Complete,
    Failed,
}

/// Scatter/gather response output: send prefix, data, then suffix, in order.
/// Pack bytes are borrowed rather than copied into an HTTP-sized allocation.
#[derive(Debug, Eq, PartialEq)]
pub struct ResponseChunk<'a> {
    pub prefix: String,
    pub data: &'a [u8],
    pub suffix: &'static [u8],
}

/// Streaming response framing with an explicit EOF and output budget.
/// A write failure must abort the host operation; never retry the same chunk
/// through this encoder or turn a truncated response into a successful one.
#[derive(Debug)]
pub struct ResponseEncoder {
    state: EncodeState,
    remaining_budget: u64,
}
impl ResponseEncoder {
    pub fn new(
        version: HttpVersion,
        length: Option<u64>,
        max_body_bytes: u64,
    ) -> Result<Self, HttpError> {
        if length.is_some_and(|length| length > max_body_bytes) {
            return Err(HttpError::BodyTooLarge);
        }
        let state = match (version, length) {
            (_, Some(length)) => EncodeState::Fixed(length),
            (HttpVersion::Http11, None) => EncodeState::Chunked,
            (HttpVersion::Http10, None) => EncodeState::CloseDelimited,
        };
        Ok(Self {
            state,
            remaining_budget: max_body_bytes,
        })
    }
    pub fn push<'a>(&mut self, data: &'a [u8]) -> Result<ResponseChunk<'a>, HttpError> {
        let result = self.step(data);
        if result.is_err() {
            self.state = EncodeState::Failed;
        }
        result
    }
    fn step<'a>(&mut self, data: &'a [u8]) -> Result<ResponseChunk<'a>, HttpError> {
        if matches!(self.state, EncodeState::Complete | EncodeState::Failed) {
            return Err(HttpError::ResponseLengthMismatch);
        }
        let count = data.len() as u64;
        if count > self.remaining_budget {
            return Err(HttpError::BodyTooLarge);
        }
        if let EncodeState::Fixed(remaining) = self.state {
            if count > remaining {
                return Err(HttpError::ResponseLengthMismatch);
            }
            self.state = EncodeState::Fixed(remaining - count);
        }
        self.remaining_budget -= count;
        let (prefix, suffix) = if self.state == EncodeState::Chunked && !data.is_empty() {
            (format!("{:x}\r\n", data.len()), b"\r\n".as_slice())
        } else {
            (String::new(), b"".as_slice())
        };
        Ok(ResponseChunk {
            prefix,
            data,
            suffix,
        })
    }
    /// Emit the terminal chunk exactly once, or validate a fixed-length body.
    /// For close-delimited output the caller must close the connection after
    /// all payload writes have completed. This method does not perform I/O.
    pub fn finish(&mut self) -> Result<&'static [u8], HttpError> {
        let terminal: &'static [u8] = match self.state {
            EncodeState::Chunked => b"0\r\n\r\n",
            EncodeState::Fixed(0) | EncodeState::CloseDelimited => b"",
            _ => {
                self.state = EncodeState::Failed;
                return Err(HttpError::ResponseLengthMismatch);
            }
        };
        self.state = EncodeState::Complete;
        Ok(terminal)
    }
}

#[cfg(test)]
#[path = "smart_http_tests.rs"]
mod tests;
