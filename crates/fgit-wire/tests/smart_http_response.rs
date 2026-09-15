#![forbid(unsafe_code)]

use std::cell::Cell;

use fgit_wire::smart_http::rpc::{RpcError, UploadReply, UploadRpc};
use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpLimits, HttpVersion,
    ProtocolVersion, ResponseEncoder, parse_head};
use fgit_wire::{AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource,
    Packet, UploadPackRepository, WireError, WireLimits, encode_packets};

struct Repository { refs: Vec<AdvertisedRef>, format: GitObjectFormat }
impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat { self.format }
    fn advertised_refs(&self) -> &[AdvertisedRef] { &self.refs }
    fn contains_want(&self, oid: AnyGitOid) -> bool { oid == self.refs[0].oid }
    fn is_common(&self, _: AnyGitOid) -> bool { false }
}
fn data(text: impl Into<Vec<u8>>) -> Packet { Packet::Data(text.into()) }
fn wire(packets: &[Packet]) -> Vec<u8> { encode_packets(packets, &WireLimits::default()).unwrap() }
fn reply(format: GitObjectFormat, version: ProtocolVersion, sideband: bool, done: bool) -> UploadReply {
    let limits = WireLimits::default();
    let oid = AnyGitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap();
    let repo = Repository { format, refs: vec![AdvertisedRef::new(oid, b"refs/heads/main", &limits).unwrap()] };
    let (capabilities, packets) = if version == ProtocolVersion::V2 {
        let caps = Capabilities::parse_v2_advertisement(&[data(b"version 2\n"),
            data(b"fetch\n"), Packet::Flush], &limits).unwrap();
        let mut request = vec![data(b"command=fetch\n"), Packet::Delimiter, data(format!("want {oid}\n"))];
        if done { request.push(data(b"done\n")); }
        else { request.push(data(format!("have {}\n", "22".repeat(format.digest_len())))); }
        request.push(Packet::Flush); (caps, request)
    } else {
        let caps = Capabilities::parse_v1(b"side-band-64k", &limits).unwrap();
        let suffix = if sideband { " side-band-64k" } else { "" };
        let mut request = vec![data(format!("want {oid}{suffix}\n")), Packet::Flush];
        if done { request.push(data(b"done\n")); }
        else { request.extend([data(format!("have {}\n", "22".repeat(format.digest_len()))), Packet::Flush]); }
        (caps, request)
    };
    let body = wire(&packets);
    let header = format!("POST /repo.git/git-upload-pack HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\n\r\n", body.len());
    let request = parse_head(header.as_bytes(), HttpLimits::default()).unwrap().unwrap();
    let mut rpc = UploadRpc::new(&request, version, capabilities, &repo, limits, HttpLimits::default()).unwrap();
    rpc.push(&body, &mut || true).unwrap(); rpc.finish(&mut || true).unwrap()
}
fn pack(format: GitObjectFormat) -> Vec<u8> {
    let mut output = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    let checksum = match format {
        GitObjectFormat::Sha1 => fgit_crypto::sha1_digest(&output).to_vec(),
        GitObjectFormat::Sha256 => fgit_crypto::sha256_digest(&output).to_vec(),
    };
    output.extend(checksum); output
}
struct Source<'a> { bytes: Vec<u8>, offset: usize, fragment: usize, calls: &'a Cell<usize> }
impl PackPayloadSource for Source<'_> {
    fn next_chunk(&mut self, maximum: usize) -> Result<Option<Vec<u8>>, WireError> {
        self.calls.set(self.calls.get() + 1);
        if self.offset == self.bytes.len() { return Ok(None); }
        let count = self.fragment.min(maximum).min(self.bytes.len() - self.offset);
        assert!(count > 0);
        let output = self.bytes[self.offset..self.offset + count].to_vec();
        self.offset += count; Ok(Some(output))
    }
}

#[test]
fn stream_preserves_native_pack_bytes_and_exact_legacy_or_v2_framing() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for version in [ProtocolVersion::V0, ProtocolVersion::V1, ProtocolVersion::V2] {
            for sideband in [false, true] {
                let reply = reply(format, version, sideband, true);
                let mut expected = reply.prefix().to_vec(); let bytes = pack(format);
                let multiplexed = sideband || version == ProtocolVersion::V2;
                for chunk in bytes.chunks(7) {
                    if multiplexed {
                        let mut payload = vec![1]; payload.extend_from_slice(chunk);
                        expected.extend(wire(&[Packet::Data(payload)]));
                    } else { expected.extend_from_slice(chunk); }
                }
                if multiplexed { expected.extend_from_slice(b"0000"); }
                let calls = Cell::new(0);
                let mut source = Source { bytes, offset: 0, fragment: 7, calls: &calls };
                let mut stream = reply.into_response(Some(&mut source), WireLimits::default(), expected.len() as u64).unwrap();
                let mut output = Vec::new();
                while let Some(chunk) = stream.next_chunk(&mut || true).unwrap() {
                    assert!(chunk.len() <= WireLimits::default().max_packet_bytes); output.extend(chunk);
                }
                assert_eq!(output, expected); assert_eq!(stream.emitted_bytes(), expected.len() as u64);
                let completed_calls = calls.get();
                assert!(stream.next_chunk(&mut || true).unwrap().is_none());
                assert_eq!(calls.get(), completed_calls);
            }
        }
    }
}

#[test]
fn no_pack_source_is_polled_until_consumer_finishes_the_prefix() {
    let reply = reply(GitObjectFormat::Sha1, ProtocolVersion::V0, true, true);
    let expected_prefix = reply.prefix().to_vec(); let calls = Cell::new(0);
    let mut source = Source { bytes: pack(GitObjectFormat::Sha1), offset: 0, fragment: 7, calls: &calls };
    let mut stream = reply.into_response(Some(&mut source), WireLimits::default(), 4096).unwrap();
    assert_eq!(calls.get(), 0);
    assert_eq!(stream.next_chunk(&mut || true).unwrap().unwrap(), expected_prefix);
    assert_eq!(calls.get(), 0);
    stream.next_chunk(&mut || true).unwrap(); assert_eq!(calls.get(), 1);
    stream.next_chunk(&mut || true).unwrap(); assert_eq!(calls.get(), 2);
}

#[test]
fn negotiation_only_stream_never_accepts_an_unrequested_pack() {
    let calls = Cell::new(0);
    let mut source = Source { bytes: pack(GitObjectFormat::Sha1), offset: 0, fragment: 7, calls: &calls };
    assert!(matches!(reply(GitObjectFormat::Sha1, ProtocolVersion::V0, false, false)
        .into_response(Some(&mut source), WireLimits::default(), 4096), Err(RpcError::UnexpectedPack)));
    assert_eq!(calls.get(), 0);
    let reply = reply(GitObjectFormat::Sha1, ProtocolVersion::V0, false, false);
    let expected = reply.prefix().to_vec();
    let mut stream = reply.into_response(None::<&mut Source<'_>>, WireLimits::default(), expected.len() as u64).unwrap();
    assert_eq!(stream.next_chunk(&mut || true).unwrap().unwrap(), expected);
    assert!(stream.next_chunk(&mut || true).unwrap().is_none());
}

#[test]
fn missing_requested_pack_cannot_be_reported_as_a_complete_response() {
    assert!(matches!(reply(GitObjectFormat::Sha1, ProtocolVersion::V0, false, true)
        .into_response(None::<&mut Source<'_>>, WireLimits::default(), 4096), Err(RpcError::MissingPack)));
    let calls = Cell::new(0);
    let mut empty = Source { bytes: vec![], offset: 0, fragment: 7, calls: &calls };
    let mut stream = reply(GitObjectFormat::Sha1, ProtocolVersion::V2, true, true)
        .into_response(Some(&mut empty), WireLimits::default(), 4096).unwrap();
    stream.next_chunk(&mut || true).unwrap();
    assert!(matches!(stream.next_chunk(&mut || true), Err(RpcError::MissingPack)));
    assert!(matches!(stream.next_chunk(&mut || true), Err(RpcError::FailedRequest)));
}

#[test]
fn aggregate_response_budget_includes_every_sideband_header_and_final_flush() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let reply = reply(format, ProtocolVersion::V2, true, true); let bytes = pack(format);
        let exact = reply.prefix().len() + bytes.len() + bytes.len().div_ceil(7) * 5 + 4;
        let calls = Cell::new(0);
        let mut source = Source { bytes, offset: 0, fragment: 7, calls: &calls };
        let mut stream = reply.into_response(Some(&mut source), WireLimits::default(), (exact - 1) as u64).unwrap();
        let mut observed = Vec::new();
        loop {
            match stream.next_chunk(&mut || true) {
                Ok(Some(chunk)) => observed.extend(chunk),
                Err(RpcError::OutputLimit) => break,
                _ => panic!("under-budget stream must fail before a success trailer"),
            }
        }
        assert!(!observed.ends_with(b"0000"));
        assert_eq!(stream.emitted_bytes(), observed.len() as u64);
        let before = calls.get();
        assert!(matches!(stream.next_chunk(&mut || true), Err(RpcError::FailedRequest)));
        assert_eq!(calls.get(), before);
    }
}

#[test]
fn source_errors_cannot_be_followed_by_a_git_success_trailer() {
    struct Broken;
    impl PackPayloadSource for Broken {
        fn next_chunk(&mut self, _: usize) -> Result<Option<Vec<u8>>, WireError> { Err(WireError::AllocationFailure) }
    }
    let mut source = Broken;
    let mut stream = reply(GitObjectFormat::Sha1, ProtocolVersion::V2, true, true)
        .into_response(Some(&mut source), WireLimits::default(), 4096).unwrap();
    stream.next_chunk(&mut || true).unwrap();
    assert!(matches!(stream.next_chunk(&mut || true), Err(RpcError::Wire(WireError::AllocationFailure))));
    assert!(matches!(stream.next_chunk(&mut || true), Err(RpcError::FailedRequest)));
}

#[test]
fn zero_progress_and_oversized_pack_producers_are_refused() {
    struct Malformed(bool);
    impl PackPayloadSource for Malformed {
        fn next_chunk(&mut self, maximum: usize) -> Result<Option<Vec<u8>>, WireError> {
            Ok(Some(if self.0 { vec![42; maximum + 1] } else { vec![] }))
        }
    }
    for oversize in [false, true] {
        let mut source = Malformed(oversize);
        let mut stream = reply(GitObjectFormat::Sha1, ProtocolVersion::V0, true, true)
            .into_response(Some(&mut source), WireLimits::default(), 1_000_000).unwrap();
        stream.next_chunk(&mut || true).unwrap();
        let error = stream.next_chunk(&mut || true);
        if oversize { assert!(matches!(error, Err(RpcError::Wire(WireError::PackChunkTooLarge { .. })))); }
        else { assert!(matches!(error, Err(RpcError::EmptyPackChunk))); }
        assert!(matches!(stream.next_chunk(&mut || true), Err(RpcError::FailedRequest)));
    }
}

#[test]
fn transport_abort_and_cancellation_release_no_further_pack_bytes() {
    for abort in [false, true] {
        let calls = Cell::new(0);
        let mut source = Source { bytes: pack(GitObjectFormat::Sha1), offset: 0, fragment: 7, calls: &calls };
        let mut stream = reply(GitObjectFormat::Sha1, ProtocolVersion::V0, true, true)
            .into_response(Some(&mut source), WireLimits::default(), 4096).unwrap();
        stream.next_chunk(&mut || true).unwrap();
        if abort { stream.abort(); }
        else { assert!(matches!(stream.next_chunk(&mut || false), Err(RpcError::Cancelled))); }
        assert_eq!(calls.get(), 0);
        assert!(matches!(stream.next_chunk(&mut || true), Err(RpcError::FailedRequest)));
        assert_eq!(calls.get(), 0);
    }
}

#[test]
fn cancellation_during_pack_production_discards_the_unreleased_chunk() {
    struct Cancelling<'a>(&'a Cell<bool>);
    impl PackPayloadSource for Cancelling<'_> {
        fn next_chunk(&mut self, _: usize) -> Result<Option<Vec<u8>>, WireError> {
            self.0.set(true); Ok(Some(b"PACK".to_vec()))
        }
    }
    let cancelled = Cell::new(false); let mut source = Cancelling(&cancelled);
    let mut stream = reply(GitObjectFormat::Sha1, ProtocolVersion::V0, true, true)
        .into_response(Some(&mut source), WireLimits::default(), 4096).unwrap();
    stream.next_chunk(&mut || !cancelled.get()).unwrap(); let before = stream.emitted_bytes();
    assert!(matches!(stream.next_chunk(&mut || !cancelled.get()), Err(RpcError::Cancelled)));
    assert_eq!(stream.emitted_bytes(), before);
    assert!(matches!(stream.next_chunk(&mut || true), Err(RpcError::FailedRequest)));
}

#[test]
fn native_git_stream_round_trips_through_chunked_http_without_buffering_a_pack() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let reply = reply(format, ProtocolVersion::V2, true, true); let prefix = reply.prefix().to_vec();
        let bytes = pack(format); let calls = Cell::new(0);
        let mut source = Source { bytes: bytes.clone(), offset: 0, fragment: 5, calls: &calls };
        let mut stream = reply.into_response(Some(&mut source), WireLimits::default(), 4096).unwrap();
        let mut encoder = ResponseEncoder::new(HttpVersion::Http11, None, 4096).unwrap();
        let mut decoder = BodyDecoder::new(BodyFraming::Chunked, HttpLimits::default()).unwrap();
        let mut decoded = Vec::new();
        while let Some(chunk) = stream.next_chunk(&mut || true).unwrap() {
            let framed = encoder.push(&chunk).unwrap();
            for segment in [framed.prefix.as_bytes(), framed.data, framed.suffix] {
                for byte in segment {
                    let input = [*byte];
                    let step = decoder.push(&input).unwrap();
                    decoded.extend_from_slice(step.data);
                }
            }
        }
        for byte in encoder.finish().unwrap() { decoder.push(&[*byte]).unwrap(); }
        decoder.finish().unwrap();
        let mut expected = prefix;
        for chunk in bytes.chunks(5) {
            let mut payload = vec![1]; payload.extend_from_slice(chunk);
            expected.extend(wire(&[Packet::Data(payload)]));
        }
        expected.extend_from_slice(b"0000");
        assert_eq!(decoded, expected);
    }
}
