#![forbid(unsafe_code)]
//! Refusals that arise while the public git-daemon adapter reads its greeting.
//!
//! `parse_git_daemon_request` intentionally accepts already-buffered bytes, so
//! it cannot reach the reader-owned failures in `serve_git_daemon_upload_pack`.
//! These probes keep that boundary explicit: the server must reject a bad or
//! oversized length before allocating its frame, and must preserve a reader
//! failure as a typed transport refusal.

use std::convert::Infallible;
use std::io::{self, Cursor, Read};

use fgit_node::{GitDaemonServeError, GitDaemonTransportRefusal, serve_git_daemon_upload_pack};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource,
    UploadPackRepository, WireError, WireLimits,
};

struct EmptyRepository;

impl UploadPackRepository for EmptyRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &[]
    }

    fn contains_want(&self, _oid: AnyGitOid) -> bool {
        false
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        false
    }
}

struct EmptyPayload;

impl PackPayloadSource for EmptyPayload {
    fn next_chunk(&mut self, _maximum_chunk_bytes: usize) -> Result<Option<Vec<u8>>, WireError> {
        Ok(None)
    }
}

fn read_refusal(reader: &mut impl Read) -> GitDaemonTransportRefusal {
    let mut output = Vec::new();
    match serve_git_daemon_upload_pack(
        reader,
        &mut output,
        &EmptyRepository,
        Capabilities::default(),
        WireLimits::default(),
        |_request, _pack_request| -> Result<EmptyPayload, Infallible> { Ok(EmptyPayload) },
    ) {
        Err(GitDaemonServeError::Transport(refusal)) => refusal,
        Err(GitDaemonServeError::Pack(never)) => match never {},
        Ok(_) => panic!("a malformed greeting must not reach the session outcome"),
    }
}

struct RefusingReader;

impl Read for RefusingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("test reader refuses the greeting"))
    }
}

#[test]
fn a_greeting_header_read_error_stays_a_transport_io_refusal() {
    let refusal = read_refusal(&mut RefusingReader);

    match refusal {
        GitDaemonTransportRefusal::Io { operation, source } => {
            assert_eq!(operation, "read git-daemon greeting header");
            assert_eq!(source.kind(), io::ErrorKind::Other);
        }
        other => panic!("header reader error must not be reclassified: {other:?}"),
    }
}

#[test]
fn a_non_hex_greeting_header_is_refused_before_payload_read() {
    let refusal = read_refusal(&mut Cursor::new(b"zzzz"));

    assert!(matches!(
        refusal,
        GitDaemonTransportRefusal::InvalidGreetingLength
    ));
}

#[test]
fn an_oversized_greeting_is_refused_before_frame_allocation() {
    let refusal = read_refusal(&mut Cursor::new(b"ffff"));

    assert!(matches!(
        refusal,
        GitDaemonTransportRefusal::GreetingPacketTooLarge {
            declared: 65_535,
            maximum: 65_520,
        }
    ));
}

#[test]
fn a_reserved_underlength_header_is_a_control_packet_not_an_allocated_frame() {
    let refusal = read_refusal(&mut Cursor::new(b"0003"));

    assert!(matches!(
        refusal,
        GitDaemonTransportRefusal::GreetingControlPacket
    ));
}
