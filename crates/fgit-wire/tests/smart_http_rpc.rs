#![forbid(unsafe_code)]

use std::cell::Cell;

use fgit_wire::receive::{QuarantineReceipt, ReceiveContext, ReceiveError, ReceiveLimits,
    ReceiveQuarantineHandoff, ReceiveRequest, SignedPushProfile};
use fgit_wire::smart_http::{HttpLimits, ProtocolVersion, Service, parse_head};
use fgit_wire::smart_http::rpc::{ReceiveRpc, RpcError, UploadRpc, receive_discovery, upload_discovery};
use fgit_wire::{AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet,
    UploadPackRepository, WireLimits, encode_packets};

struct Repository { refs: Vec<AdvertisedRef>, format: GitObjectFormat }
impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        let oid = AnyGitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap();
        Self { refs: vec![AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).unwrap()], format }
    }
    fn oid(&self) -> String { "11".repeat(self.format.digest_len()) }
}
impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat { self.format }
    fn advertised_refs(&self) -> &[AdvertisedRef] { &self.refs }
    fn contains_want(&self, oid: AnyGitOid) -> bool { oid == self.refs[0].oid }
    fn is_common(&self, oid: AnyGitOid) -> bool { self.contains_want(oid) }
}
fn data(text: impl Into<Vec<u8>>) -> Packet { Packet::Data(text.into()) }
fn wire(packets: &[Packet]) -> Vec<u8> { encode_packets(packets, &WireLimits::default()).unwrap() }
fn caps(bytes: &[u8]) -> Capabilities { Capabilities::parse_v1(bytes, &WireLimits::default()).unwrap() }
fn v2_caps() -> Capabilities {
    Capabilities::parse_v2_advertisement(&[data(b"version 2\n"), data(b"ls-refs\n"),
        data(b"fetch\n"), Packet::Flush], &WireLimits::default()).unwrap()
}
fn head(service: Service, size: usize, chunked: bool) -> Vec<u8> {
    let name = match service { Service::UploadPack => "git-upload-pack", Service::ReceivePack => "git-receive-pack" };
    let framing = if chunked { "Transfer-Encoding: chunked".to_owned() } else { format!("Content-Length: {size}") };
    format!("POST /repo.git/{name} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-{name}-request\r\n{framing}\r\n\r\n").into_bytes()
}
fn chunked(body: &[u8], width: usize) -> Vec<u8> {
    let mut output = Vec::new();
    for chunk in body.chunks(width) {
        output.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        output.extend_from_slice(chunk); output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"0\r\n\r\n"); output
}
fn clone_request(repo: &Repository) -> Vec<u8> {
    wire(&[data(format!("want {}\n", repo.oid())), Packet::Flush, data(b"done\n")])
}
fn context(format: GitObjectFormat) -> ReceiveContext {
    let capabilities = format!("delete-refs report-status object-format={}",
        if format == GitObjectFormat::Sha1 { "sha1" } else { "sha256" });
    ReceiveContext::new(format, caps(capabilities.as_bytes()), ReceiveLimits::default(), SignedPushProfile::Refuse).unwrap()
}
fn receive_body(format: GitObjectFormat, delete: bool) -> Vec<u8> {
    let old = if delete { "11" } else { "00" }.repeat(format.digest_len());
    let new = if delete { "00" } else { "11" }.repeat(format.digest_len());
    let algorithm = if format == GitObjectFormat::Sha1 { "sha1" } else { "sha256" };
    let mut body = wire(&[data(format!("{old} {new} refs/tags/http\0report-status delete-refs object-format={algorithm}")), Packet::Flush]);
    if !delete {
        // A real, checksum-bound empty native pack tests structural quarantine.
        // The deliberately non-authoritative handoff below does NOT establish
        // target closure, authenticated principal or canonical publication.
        let mut pack = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
        let checksum = match format {
            GitObjectFormat::Sha1 => fgit_crypto::sha1_digest(&pack).to_vec(),
            GitObjectFormat::Sha256 => fgit_crypto::sha256_digest(&pack).to_vec(),
        };
        pack.extend_from_slice(&checksum); body.extend(pack);
    }
    body
}
#[derive(Default)]
struct StructuralHandoff { calls: usize, receipt: Option<QuarantineReceipt>, reject: bool }
impl ReceiveQuarantineHandoff for StructuralHandoff {
    fn handoff(&mut self, request: &ReceiveRequest, pack: Option<&fgit_pack::QuarantinedPack>, receipt: &QuarantineReceipt) -> Result<(), ReceiveError> {
        self.calls += 1;
        assert_eq!(request.commands.len(), 1);
        assert_eq!(pack.is_none(), receipt.delete_only);
        self.receipt = Some(receipt.clone());
        if self.reject { Err(ReceiveError::Cancelled) } else { Ok(()) }
    }
}

#[test]
fn native_upload_requests_survive_every_transport_fragment_and_both_hashes() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format); let body = clone_request(&repo);
        for version in [ProtocolVersion::V0, ProtocolVersion::V1] {
            for is_chunked in [false, true] {
                let header = head(Service::UploadPack, body.len(), is_chunked);
                let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
                let encoded = if is_chunked { chunked(&body, 7) } else { body.clone() };
                for width in [1, 2, 3, 4, 11, encoded.len()] {
                    let mut rpc = UploadRpc::new(&request, version, caps(b""), &repo,
                        WireLimits::default(), HttpLimits::default()).unwrap();
                    for fragment in encoded.chunks(width) {
                        let progress = rpc.push(fragment, &mut || true).unwrap();
                        assert_eq!(progress.consumed, fragment.len());
                    }
                    let reply = rpc.finish(&mut || true).unwrap();
                    assert_eq!(reply.prefix(), b"0008NAK\n");
                    assert_eq!(reply.pack_request().unwrap().wants, vec![repo.refs[0].oid]);
                }
            }
        }
    }
}

#[test]
fn git_done_does_not_replace_http_chunk_termination() {
    let repo = Repository::new(GitObjectFormat::Sha1); let body = clone_request(&repo);
    let header = head(Service::UploadPack, body.len(), true);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let encoded = chunked(&body, body.len());
    for missing in 1..=5 {
        let mut rpc = UploadRpc::new(&request, ProtocolVersion::V0, caps(b""), &repo,
            WireLimits::default(), HttpLimits::default()).unwrap();
        let progress = rpc.push(&encoded[..encoded.len() - missing], &mut || true).unwrap();
        assert!(!progress.body_complete);
        assert!(rpc.finish(&mut || true).is_err());
    }
}

#[test]
fn upload_pipeline_suffix_is_not_consumed_as_git_data() {
    let repo = Repository::new(GitObjectFormat::Sha1); let body = clone_request(&repo);
    for is_chunked in [false, true] {
        let header = head(Service::UploadPack, body.len(), is_chunked);
        let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
        let mut bytes = if is_chunked { chunked(&body, 3) } else { body.clone() };
        let boundary = bytes.len(); bytes.extend_from_slice(b"GET /other/info/refs HTTP/1.1\r\n");
        let mut rpc = UploadRpc::new(&request, ProtocolVersion::V0, caps(b""), &repo,
            WireLimits::default(), HttpLimits::default()).unwrap();
        let progress = rpc.push(&bytes, &mut || true).unwrap();
        assert_eq!(progress.consumed, boundary); assert!(progress.body_complete);
        assert!(rpc.finish(&mut || true).unwrap().pack_request().is_some());
    }
}

#[test]
fn trailing_git_commands_and_partial_frames_poison_entire_upload() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    for suffix in [&b"0000"[..], &b"0"[..], &b"0009done\n"[..]] {
        let mut body = clone_request(&repo); body.extend_from_slice(suffix);
        let header = head(Service::UploadPack, body.len(), false);
        let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
        let mut rpc = UploadRpc::new(&request, ProtocolVersion::V0, caps(b""), &repo,
            WireLimits::default(), HttpLimits::default()).unwrap();
        assert!(rpc.push(&body, &mut || true).is_err());
        assert!(matches!(rpc.push(b"", &mut || true), Err(RpcError::FailedRequest)));
        assert!(matches!(rpc.finish(&mut || true), Err(RpcError::FailedRequest)));
    }
}

#[test]
fn completed_v2_ls_refs_is_one_http_response_without_ipc_response_end() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let body = wire(&[data(b"command=ls-refs\n"), Packet::Delimiter, Packet::Flush]);
        let header = head(Service::UploadPack, body.len(), false);
        let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
        let mut rpc = UploadRpc::new(&request, ProtocolVersion::V2, v2_caps(), &repo,
            WireLimits::default(), HttpLimits::default()).unwrap();
        for byte in &body { rpc.push(&[*byte], &mut || true).unwrap(); }
        let reply = rpc.finish(&mut || true).unwrap();
        assert!(reply.pack_request().is_none());
        assert_eq!(reply.prefix(), wire(&[data(format!("{} refs/heads/main\n", repo.oid())), Packet::Flush]));
        assert!(!reply.prefix().ends_with(b"0002"));
    }
}

#[test]
fn second_v2_command_in_one_http_body_is_refused() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    let command = wire(&[data(b"command=ls-refs\n"), Packet::Delimiter, Packet::Flush]);
    let mut body = command.clone(); body.extend(command);
    let header = head(Service::UploadPack, body.len(), false);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let mut rpc = UploadRpc::new(&request, ProtocolVersion::V2, v2_caps(), &repo,
        WireLimits::default(), HttpLimits::default()).unwrap();
    assert!(matches!(rpc.push(&body, &mut || true), Err(RpcError::MultipleCommands)));
    assert!(matches!(rpc.finish(&mut || true), Err(RpcError::FailedRequest)));
}

#[test]
fn negotiation_only_http_round_does_not_request_a_pack() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    let body = wire(&[data(format!("want {} multi_ack\n", repo.oid())), Packet::Flush,
        data(format!("have {}\n", "22".repeat(20))), Packet::Flush]);
    let header = head(Service::UploadPack, body.len(), false);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let mut rpc = UploadRpc::new(&request, ProtocolVersion::V0, caps(b"multi_ack"), &repo,
        WireLimits::default(), HttpLimits::default()).unwrap();
    rpc.push(&body, &mut || true).unwrap();
    let reply = rpc.finish(&mut || true).unwrap();
    assert!(reply.pack_request().is_none()); assert_eq!(reply.prefix(), b"0008NAK\n");
}

#[test]
fn upload_cancellation_never_releases_a_completed_pack_request() {
    let repo = Repository::new(GitObjectFormat::Sha1); let body = clone_request(&repo);
    let header = head(Service::UploadPack, body.len(), false);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let mut rpc = UploadRpc::new(&request, ProtocolVersion::V0, caps(b""), &repo,
        WireLimits::default(), HttpLimits::default()).unwrap();
    rpc.push(&body, &mut || true).unwrap();
    assert!(matches!(rpc.finish(&mut || false), Err(RpcError::Cancelled)));
}

#[test]
fn receive_calls_native_quarantine_once_only_after_complete_http_body() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for delete in [false, true] {
            let body = receive_body(format, delete);
            for is_chunked in [false, true] {
                let header = head(Service::ReceivePack, body.len(), is_chunked);
                let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
                let encoded = if is_chunked { chunked(&body, 5) } else { body.clone() };
                let mut rpc = ReceiveRpc::new(&request, ProtocolVersion::V0, context(format), HttpLimits::default()).unwrap();
                let mut handoff = StructuralHandoff::default();
                for fragment in encoded.chunks(3) {
                    rpc.push(fragment, &mut || true).unwrap(); assert_eq!(handoff.calls, 0);
                }
                let complete = rpc.finish_with_handoff(&mut handoff, &mut || true).unwrap();
                assert_eq!(handoff.calls, 1); assert_eq!(complete.quarantine.delete_only, delete);
                assert_eq!(complete.quarantine, handoff.receipt.unwrap());
            }
        }
    }
}

#[test]
fn incomplete_http_receive_never_enters_native_handoff_even_with_valid_pack() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for delete in [false, true] {
            let body = receive_body(format, delete); let encoded = chunked(&body, 9);
            let header = head(Service::ReceivePack, body.len(), true);
            let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
            for missing in 1..=5 {
                let mut rpc = ReceiveRpc::new(&request, ProtocolVersion::V0, context(format), HttpLimits::default()).unwrap();
                rpc.push(&encoded[..encoded.len() - missing], &mut || true).unwrap();
                let mut handoff = StructuralHandoff::default();
                assert!(rpc.finish_with_handoff(&mut handoff, &mut || true).is_err());
                assert_eq!(handoff.calls, 0);
            }
        }
    }
}

#[test]
fn receive_checksum_failure_and_cancellation_leave_handoff_untouched() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for corrupt in [false, true] {
            let mut body = receive_body(format, false);
            if corrupt { *body.last_mut().unwrap() ^= 1; }
            let header = head(Service::ReceivePack, body.len(), false);
            let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
            let mut rpc = ReceiveRpc::new(&request, ProtocolVersion::V0, context(format), HttpLimits::default()).unwrap();
            rpc.push(&body, &mut || true).unwrap();
            let mut handoff = StructuralHandoff::default();
            assert!(rpc.finish_with_handoff(&mut handoff, &mut || corrupt).is_err());
            assert_eq!(handoff.calls, 0);
        }
    }
}

#[test]
fn failed_receive_cannot_be_completed_with_replacement_bytes() {
    let body = receive_body(GitObjectFormat::Sha1, true);
    let header = head(Service::ReceivePack, body.len(), true);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let mut rpc = ReceiveRpc::new(&request, ProtocolVersion::V0, context(GitObjectFormat::Sha1), HttpLimits::default()).unwrap();
    assert!(rpc.push(b"!\r\n", &mut || true).is_err());
    assert!(matches!(rpc.push(&chunked(&body, 5), &mut || true), Err(RpcError::FailedRequest)));
    let mut handoff = StructuralHandoff::default();
    assert!(matches!(rpc.finish_with_handoff(&mut handoff, &mut || true), Err(RpcError::FailedRequest)));
    assert_eq!(handoff.calls, 0);
}

#[test]
fn handoff_refusal_is_not_rewritten_as_success() {
    let body = receive_body(GitObjectFormat::Sha1, true);
    let header = head(Service::ReceivePack, body.len(), false);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let mut rpc = ReceiveRpc::new(&request, ProtocolVersion::V0, context(GitObjectFormat::Sha1), HttpLimits::default()).unwrap();
    rpc.push(&body, &mut || true).unwrap();
    let mut handoff = StructuralHandoff { reject: true, ..StructuralHandoff::default() };
    assert!(matches!(rpc.finish_with_handoff(&mut handoff, &mut || true), Err(RpcError::Receive(ReceiveError::Cancelled))));
    assert_eq!(handoff.calls, 1);
}

#[test]
fn post_handoff_cancellation_does_not_fabricate_non_commit() {
    struct Handoff<'a>(&'a Cell<bool>);
    impl ReceiveQuarantineHandoff for Handoff<'_> {
        fn handoff(&mut self, _: &ReceiveRequest, _: Option<&fgit_pack::QuarantinedPack>, _: &QuarantineReceipt) -> Result<(), ReceiveError> {
            self.0.set(true); Ok(())
        }
    }
    let cancelled = Cell::new(false); let mut handoff = Handoff(&cancelled);
    let body = receive_body(GitObjectFormat::Sha1, true);
    let header = head(Service::ReceivePack, body.len(), false);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let mut rpc = ReceiveRpc::new(&request, ProtocolVersion::V0, context(GitObjectFormat::Sha1), HttpLimits::default()).unwrap();
    rpc.push(&body, &mut || !cancelled.get()).unwrap();
    let receipt = rpc.finish_with_handoff(&mut handoff, &mut || !cancelled.get()).unwrap();
    assert!(cancelled.get()); assert!(receipt.quarantine.delete_only);
}

#[test]
fn discovery_has_exact_service_and_version_preludes_and_shared_limit() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    for version in [ProtocolVersion::V0, ProtocolVersion::V1, ProtocolVersion::V2] {
        let capabilities = if version == ProtocolVersion::V2 { v2_caps() } else { caps(b"multi_ack") };
        let body = upload_discovery(&repo, capabilities.clone(), version, &WireLimits::default()).unwrap();
        if version == ProtocolVersion::V2 { assert!(body.starts_with(b"000eversion 2\n")); }
        else { assert!(body.starts_with(b"001e# service=git-upload-pack\n0000")); }
        if version == ProtocolVersion::V1 { assert!(body.windows(14).any(|part| part == b"000eversion 1\n")); }
        assert!(body.ends_with(b"0000"));
        let tight = WireLimits { max_outbound_bytes: body.len() - 1, ..WireLimits::default() };
        assert!(upload_discovery(&repo, capabilities, version, &tight).is_err());
    }
    let receive = receive_discovery(repo.refs.clone(), &context(repo.format), ProtocolVersion::V0).unwrap();
    assert!(receive.starts_with(b"001f# service=git-receive-pack\n0000"));
    assert!(receive_discovery(repo.refs.clone(), &context(repo.format), ProtocolVersion::V2).is_err());
}

#[test]
fn operation_mismatch_and_fictional_v2_push_are_refused() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    let header = head(Service::UploadPack, 4, false);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    assert!(ReceiveRpc::new(&request, ProtocolVersion::V0, context(repo.format), HttpLimits::default()).is_err());
    let header = head(Service::ReceivePack, 4, false);
    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    assert!(UploadRpc::new(&request, ProtocolVersion::V0, caps(b""), &repo, WireLimits::default(), HttpLimits::default()).is_err());
    assert!(ReceiveRpc::new(&request, ProtocolVersion::V2, context(repo.format), HttpLimits::default()).is_err());
}

#[test]
fn v2_negotiation_and_wait_for_done_never_issue_a_premature_pack() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for common in [false, true] {
            for wait in [false, true] {
                for done in [false, true] {
                    let have = if common { repo.oid() } else { "22".repeat(format.digest_len()) };
                    let mut packets = vec![data(b"command=fetch\n"), Packet::Delimiter,
                        data(format!("want {}\n", repo.oid())), data(format!("have {have}\n"))];
                    if wait { packets.push(data(b"wait-for-done\n")); }
                    if done { packets.push(data(b"done\n")); }
                    packets.push(Packet::Flush); let body = wire(&packets);
                    let header = head(Service::UploadPack, body.len(), false);
                    let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
                    let capabilities = Capabilities::parse_v2_advertisement(&[data(b"version 2\n"),
                        data(b"fetch=wait-for-done\n"), Packet::Flush], &WireLimits::default()).unwrap();
                    let mut rpc = UploadRpc::new(&request, ProtocolVersion::V2, capabilities, &repo,
                        WireLimits::default(), HttpLimits::default()).unwrap();
                    for fragment in body.chunks(3) { rpc.push(fragment, &mut || true).unwrap(); }
                    let reply = rpc.finish(&mut || true).unwrap();
                    let should_pack = done || (common && !wait);
                    assert_eq!(reply.pack_request().is_some(), should_pack);
                    let expected = if done { vec![data(b"packfile\n")] } else {
                        let mut output = vec![data(b"acknowledgments\n"), if common {
                            data(format!("ACK {have}\n"))
                        } else { data(b"NAK\n") }];
                        if should_pack { output.extend([data(b"ready\n"), Packet::Delimiter, data(b"packfile\n")]); }
                        else { output.push(Packet::Flush); }
                        output
                    };
                    assert_eq!(reply.prefix(), wire(&expected));
                }
            }
        }
    }
}

#[test]
fn v2_sideband_all_frames_metadata_without_multiplexing_control_packets() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    for done in [false, true] {
        let mut packets = vec![data(b"command=fetch\n"), Packet::Delimiter,
            data(format!("want {}\n", repo.oid())), data(format!("have {}\n", "22".repeat(20))),
            data(b"sideband-all\n")];
        if done { packets.push(data(b"done\n")); }
        packets.push(Packet::Flush); let body = wire(&packets);
        let header = head(Service::UploadPack, body.len(), false);
        let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
        let capabilities = Capabilities::parse_v2_advertisement(&[data(b"version 2\n"),
            data(b"fetch=sideband-all\n"), Packet::Flush], &WireLimits::default()).unwrap();
        let mut rpc = UploadRpc::new(&request, ProtocolVersion::V2, capabilities, &repo,
            WireLimits::default(), HttpLimits::default()).unwrap();
        rpc.push(&body, &mut || true).unwrap();
        let reply = rpc.finish(&mut || true).unwrap();
        assert_eq!(reply.pack_request().is_some(), done);
        if done {
            assert_eq!(reply.prefix(), wire(&[data(b"\x01packfile\n")]));
            assert!(reply.pack_request().unwrap().options.sideband_all());
        } else {
            assert_eq!(reply.prefix(), wire(&[data(b"\x01acknowledgments\n"), data(b"\x01NAK\n"), Packet::Flush]));
        }
    }
}

#[test]
fn v2_fetch_features_must_be_advertised_before_being_requested() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    for feature in ["wait-for-done", "sideband-all"] {
        let body = wire(&[data(b"command=fetch\n"), Packet::Delimiter,
            data(format!("want {}\n", repo.oid())), data(format!("{feature}\n")), Packet::Flush]);
        let header = head(Service::UploadPack, body.len(), false);
        let request = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
        let mut rpc = UploadRpc::new(&request, ProtocolVersion::V2, v2_caps(), &repo,
            WireLimits::default(), HttpLimits::default()).unwrap();
        assert!(rpc.push(&body, &mut || true).is_err());
        assert!(rpc.finish(&mut || true).is_err());
    }
}
