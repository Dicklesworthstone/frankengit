//! A close-delimited HTTP response. The first validated NDJSON record starts
//! the final response; authentication, parse and Initial failures keep their
//! ordinary HTTP status. The server owns socket deadlines and agent byte limits.
use super::{
    ApiError, BodyFraming, GitDaemonSessionDeadline, HttpLimits, LoopbackReceiveSession, OneNode,
    Status, context, parse_form, read_form,
};
use fgit_wire::smart_http::HttpVersion;
use std::io::{self, Read, Write};

struct Response<'a, W> {
    output: &'a mut W,
    version: HttpVersion,
    started: bool,
}

impl<W: Write> Write for Response<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if !self.started {
            let version = match self.version {
                HttpVersion::Http10 => "HTTP/1.0",
                HttpVersion::Http11 => "HTTP/1.1",
            };
            write!(
                self.output,
                "{version} 200 OK\r\nContent-Type: application/x-ndjson\r\nCache-Control: no-store\r\nVary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n"
            )?;
            self.started = true;
        }
        self.output.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

pub(in super::super::super) fn send(
    node: &OneNode,
    session: &LoopbackReceiveSession,
    read_grant: Option<&super::super::HttpReadGrant>,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum: u64,
    deadline: &GitDaemonSessionDeadline,
    writer: &mut impl Write,
    version: HttpVersion,
) -> Result<(), ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let read = super::super::retrieval_read(node, read_grant)?;
    let fields = parse_form(&read_form(reader, framing, http)?, 198)?;
    let mut response = Response {
        output: writer,
        version,
        started: false,
    };
    // A delivered terminal refusal completes the HTTP response. A socket
    // failure leaves the enclosing ResponseWriter to close the connection.
    context::progressive::deliver(
        node,
        &read,
        fields,
        usize::try_from(maximum).unwrap_or(usize::MAX),
        &mut response,
        deadline,
    )?;
    Ok(())
}
