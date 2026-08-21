#![forbid(unsafe_code)]

use fgit_wire::GitObjectFormat;
use fgit_wire::{
    AckMode, AdvertisedRef, AnyGitOid, Capabilities, LegacyUploadPack, ObjectFilter, Packet,
    PktLineDecoder, SidebandBand, StatelessRpcUploadPack, UploadPackRepository, UploadPackVersion,
    V1Advertisement, V2UploadPack, WireError, WireEvent, WireLimits, encode_packets,
    encode_sideband_64k, parse_filter, parse_sideband, sideband_pack_chunk,
};

const WANT: &str = "1111111111111111111111111111111111111111";
const HAVE: &str = "2222222222222222222222222222222222222222";
const ORACLE_WANT: &str = "ba6bb24deaace591e8936c9e8de324de298cedc6";

#[derive(Clone, Debug)]
struct Repository {
    refs: Vec<AdvertisedRef>,
    common: AnyGitOid,
}

impl Repository {
    fn sha1() -> Self {
        let limits = WireLimits::default();
        let want = AnyGitOid::from_hex(GitObjectFormat::Sha1, WANT).expect("fixture SHA-1 want");
        let common = AnyGitOid::from_hex(GitObjectFormat::Sha1, HAVE).expect("fixture SHA-1 have");
        let refs =
            vec![AdvertisedRef::new(want, b"refs/heads/main", &limits).expect("fixture ref")];
        Self { refs, common }
    }

    fn with_want(want: AnyGitOid) -> Self {
        let limits = WireLimits::default();
        let common = AnyGitOid::from_hex(GitObjectFormat::Sha1, HAVE).expect("fixture SHA-1 have");
        let refs = vec![
            AdvertisedRef::new(want, b"refs/heads/master", &limits).expect("oracle fixture ref"),
        ];
        Self { refs, common }
    }
}

impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.refs.iter().any(|reference| reference.oid == oid)
    }

    fn is_common(&self, oid: AnyGitOid) -> bool {
        oid == self.common
    }
}

fn decode_fixture(bytes: &[u8]) -> Vec<Packet> {
    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("default limits");
    let packets = decoder
        .push(fixture_bytes(bytes))
        .expect("fixture packet grammar");
    decoder.finish().expect("complete fixture");
    packets
}

fn fixture_bytes(bytes: &[u8]) -> &[u8] {
    if bytes.ends_with(b"0000\n") {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    }
}

fn v2_fetch_capabilities() -> Capabilities {
    Capabilities::parse_v2_advertisement(
        &[
            Packet::Data(b"version 2\n".to_vec()),
            Packet::Data(b"agent\n".to_vec()),
            Packet::Data(b"fetch=shallow filter\n".to_vec()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .expect("v2 fixture capabilities")
}

#[test]
fn pkt_line_transcript_round_trips_across_fragment_boundaries() {
    let fixture = fixture_bytes(include_bytes!("fixtures/v1-advertisement.pkt"));
    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("default limits");
    let mut packets = decoder.push(&fixture[..9]).expect("first fragment");
    packets.extend(decoder.push(&fixture[9..]).expect("second fragment"));
    decoder.finish().expect("complete transcript");
    assert_eq!(
        encode_packets(&packets, &WireLimits::default()).expect("encode"),
        fixture
    );
}

#[test]
fn pkt_line_control_markers_preserve_flush_delimiter_and_response_end() {
    let bytes = b"000000010002";
    let packets = decode_fixture(bytes);
    assert_eq!(
        packets,
        vec![Packet::Flush, Packet::Delimiter, Packet::ResponseEnd]
    );
    assert_eq!(
        encode_packets(&packets, &WireLimits::default()).expect("controls encode"),
        bytes
    );
}

#[test]
fn pkt_line_boundary_handoff_leaves_raw_pack_suffix_unbuffered() {
    let input = b"0009done\n0000PACK\x00raw-pack-bytes";
    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("default limits");
    let result = decoder
        .push_until_flush(input)
        .expect("flush boundary accepted");

    assert!(result.found_flush);
    assert_eq!(
        result.packets,
        vec![Packet::Data(b"done\n".to_vec()), Packet::Flush]
    );
    assert_eq!(&input[result.consumed..], b"PACK\x00raw-pack-bytes");
    assert_eq!(decoder.pending_len(), 0);
    decoder
        .finish()
        .expect("no raw pack bytes retained as pkt-line");
}

#[test]
fn pkt_line_boundary_handoff_preserves_a_fragmented_flush_offset() {
    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("default limits");
    let first = decoder
        .push_until_flush(b"000")
        .expect("partial header buffered");
    assert!(!first.found_flush);
    assert_eq!(first.consumed, 3);

    let second_input = b"0PACK";
    let second = decoder
        .push_until_flush(second_input)
        .expect("fragment completes flush");
    assert!(second.found_flush);
    assert_eq!(second.packets, vec![Packet::Flush]);
    assert_eq!(second.consumed, 1);
    assert_eq!(&second_input[second.consumed..], b"PACK");
    assert_eq!(decoder.pending_len(), 0);
}

#[test]
fn v1_advertisement_fixture_parses_and_reemits_exactly() {
    let fixture = fixture_bytes(include_bytes!("fixtures/v1-advertisement.pkt"));
    let packets = decode_fixture(fixture);
    let advertisement =
        V1Advertisement::parse(&packets, GitObjectFormat::Sha1, &WireLimits::default())
            .expect("v1 advertisement");
    assert_eq!(advertisement.refs.len(), 1);
    assert_eq!(advertisement.refs[0].name, b"refs/heads/main");
    assert_eq!(
        encode_packets(
            &advertisement
                .encode(&WireLimits::default())
                .expect("advertisement encode"),
            &WireLimits::default()
        )
        .expect("wire encode"),
        fixture
    );
}

#[test]
fn v1_advertisement_accepts_git_nul_capability_suffix_and_reemits_exactly() {
    let packets = vec![
        Packet::Data(
            format!("{WANT} HEAD\0symref=HEAD:refs/heads/main agent=git/2.54.0-Linux\n")
                .into_bytes(),
        ),
        Packet::Data(format!("{WANT} refs/heads/main\n").into_bytes()),
        Packet::Flush,
    ];
    let advertisement =
        V1Advertisement::parse(&packets, GitObjectFormat::Sha1, &WireLimits::default())
            .expect("Git's NUL-separated first-ref capability suffix is valid");
    assert_eq!(advertisement.refs.len(), 2);
    assert!(advertisement.capabilities.contains(b"symref"));
    assert!(advertisement.capabilities.contains(b"agent"));
    assert_eq!(
        advertisement
            .encode(&WireLimits::default())
            .expect("v1 advertisement re-encodes"),
        packets
    );
}

#[test]
fn v1_version_prelude_is_preserved_with_the_ref_advertisement() {
    let packets = vec![
        Packet::Data(b"version 1\n".to_vec()),
        Packet::Data(format!("{WANT} refs/heads/main\n").into_bytes()),
        Packet::Flush,
    ];
    let advertisement =
        V1Advertisement::parse(&packets, GitObjectFormat::Sha1, &WireLimits::default())
            .expect("v1 prelude");
    assert!(advertisement.version_one_prelude);
    assert_eq!(
        advertisement
            .encode(&WireLimits::default())
            .expect("re-emit v1"),
        packets
    );
}

#[test]
fn v1_fetch_transcript_emits_multi_ack_detailed_and_pack_request() {
    let repository = Repository::sha1();
    let server_capabilities = Capabilities::parse_v1(
        b"multi_ack multi_ack_detailed side-band-64k shallow filter",
        &WireLimits::default(),
    )
    .expect("server caps");
    let mut machine = LegacyUploadPack::new(
        UploadPackVersion::V1,
        server_capabilities,
        WireLimits::default(),
    )
    .expect("legacy state machine");
    let transition = machine
        .push_bytes(
            fixture_bytes(include_bytes!("fixtures/v1-fetch-request.pkt")),
            &repository,
        )
        .expect("hand transcript accepted");
    assert!(transition.output.iter().any(|packet| {
        matches!(packet, Packet::Data(line) if line == b"ACK 2222222222222222222222222222222222222222 common\n")
    }));
    assert!(transition.output.iter().any(|packet| {
        matches!(packet, Packet::Data(line) if line == b"ACK 2222222222222222222222222222222222222222 ready\n")
    }));
    let Some(WireEvent::PackRequested(request)) = transition.events.last() else {
        panic!("complete legacy request must ask for a pack");
    };
    assert_eq!(request.version, UploadPackVersion::V1);
    assert_eq!(request.wants.len(), 1);
    assert_eq!(request.haves.len(), 1);
    assert!(request.options.sideband_64k());
}

#[test]
fn multi_ack_mode_emits_continue_for_each_common_have() {
    let repository = Repository::sha1();
    let caps = Capabilities::parse_v1(b"multi_ack", &WireLimits::default()).expect("caps");
    let mut machine =
        LegacyUploadPack::new(UploadPackVersion::V0, caps, WireLimits::default()).expect("machine");
    machine
        .push_packet(
            &Packet::Data(format!("want {WANT} multi_ack\n").into_bytes()),
            &repository,
        )
        .expect("want");
    machine
        .push_packet(&Packet::Flush, &repository)
        .expect("want flush");
    let transition = machine
        .push_packet(
            &Packet::Data(format!("have {HAVE}\n").into_bytes()),
            &repository,
        )
        .expect("common have");
    assert!(matches!(
        transition.output.as_slice(),
        [Packet::Data(line)] if line == b"ACK 2222222222222222222222222222222222222222 continue\n"
    ));
}

#[test]
fn legacy_terminal_flush_requires_no_done_and_accepts_the_negotiated_twin() {
    let repository = Repository::sha1();
    let limits = WireLimits::default();
    let mut without_no_done = LegacyUploadPack::new(
        UploadPackVersion::V0,
        Capabilities::parse_v1(b"multi_ack", &limits).expect("capabilities"),
        limits.clone(),
    )
    .expect("legacy request machine");
    without_no_done
        .push_packet(
            &Packet::Data(format!("want {WANT} multi_ack").into_bytes()),
            &repository,
        )
        .expect("want without line feed is permitted");
    without_no_done
        .push_packet(&Packet::Flush, &repository)
        .expect("want flush");
    assert_eq!(
        without_no_done.push_packet(&Packet::Flush, &repository),
        Err(WireError::IllegalTransition {
            state: "legacy have phase",
            packet: "flush",
        })
    );

    let mut with_no_done = LegacyUploadPack::new(
        UploadPackVersion::V0,
        Capabilities::parse_v1(b"no-done", &limits).expect("no-done capability"),
        limits,
    )
    .expect("legacy request machine");
    with_no_done
        .push_packet(
            &Packet::Data(format!("want {WANT} no-done").into_bytes()),
            &repository,
        )
        .expect("want with no-done is permitted");
    with_no_done
        .push_packet(&Packet::Flush, &repository)
        .expect("want flush");
    let transition = with_no_done
        .push_packet(&Packet::Flush, &repository)
        .expect("negotiated no-done permits terminal flush");
    assert!(matches!(
        transition.events.as_slice(),
        [WireEvent::PackRequested(_)]
    ));
}

#[test]
fn v2_ls_refs_transcript_filters_advertisement() {
    let repository = Repository::sha1();
    let caps = Capabilities::parse_v1(b"ls-refs", &WireLimits::default()).expect("ls-refs cap");
    let mut machine = V2UploadPack::new(caps, WireLimits::default()).expect("v2 machine");
    let transition = machine
        .push_bytes(
            fixture_bytes(include_bytes!("fixtures/v2-ls-refs.pkt")),
            &repository,
        )
        .expect("ls-refs transcript");
    assert!(transition.output.iter().any(|packet| {
        matches!(packet, Packet::Data(line) if line == b"1111111111111111111111111111111111111111 refs/heads/main\n")
    }));
    assert!(matches!(
        transition.events.as_slice(),
        [WireEvent::LsRefs { .. }]
    ));
}

#[test]
fn pinned_oracle_v2_ls_refs_request_accepts_lf_free_capabilities() {
    let repository = Repository::sha1();
    let caps = Capabilities::parse_v1(b"ls-refs agent object-format", &WireLimits::default())
        .expect("advertised v2 capability names");
    let mut machine = V2UploadPack::new(caps, WireLimits::default()).expect("v2 machine");
    let transition = machine
        .push_bytes(
            fixture_bytes(include_bytes!("fixtures/oracle-v2-ls-refs-request.pkt")),
            &repository,
        )
        .expect("pinned Git 2.54.0 ls-refs transcript");

    assert!(matches!(
        transition.events.as_slice(),
        [WireEvent::LsRefs {
            symrefs: true,
            peel: true,
            unborn: true,
            ..
        }]
    ));
}

#[test]
fn pinned_oracle_v0_no_done_depth_request_accepts_lf_free_deepen_and_two_flushes() {
    let oracle_want =
        AnyGitOid::from_hex(GitObjectFormat::Sha1, ORACLE_WANT).expect("oracle want OID");
    let repository = Repository::with_want(oracle_want);
    let caps = Capabilities::parse_v1(
        b"multi_ack_detailed no-done side-band-64k no-progress ofs-delta deepen-since deepen-not agent shallow",
        &WireLimits::default(),
    )
    .expect("oracle server capabilities");
    let request =
        LegacyUploadPack::new(UploadPackVersion::V0, caps, WireLimits::default()).expect("machine");
    let mut machine = StatelessRpcUploadPack::new(request, WireLimits::default())
        .expect("stateless-RPC envelope");
    let completed = machine
        .push_bytes(
            fixture_bytes(include_bytes!("fixtures/oracle-v0-depth-request.pkt")),
            &repository,
        )
        .expect("pinned Git 2.54.0 depth transcript");
    machine.finish().expect("complete nested pkt-line stream");
    assert_eq!(completed.output.len(), 2);
    assert!(
        completed
            .output
            .iter()
            .all(|packet| matches!(packet, Packet::Data(line) if line == b"NAK\n"))
    );
    let Some(WireEvent::PackRequested(request)) = completed.events.last() else {
        panic!("no-done terminal flush requests a pack");
    };
    assert_eq!(request.deepen, Some(1));

    let mut refusal = LegacyUploadPack::new(
        UploadPackVersion::V0,
        Capabilities::parse_v1(b"shallow", &WireLimits::default()).expect("shallow cap"),
        WireLimits::default(),
    )
    .expect("refusal machine");
    refusal
        .push_packet(
            &Packet::Data(format!("want {ORACLE_WANT}").into_bytes()),
            &repository,
        )
        .expect("LF-free want is permitted");
    assert_eq!(
        refusal.push_packet(&Packet::Data(b"deepen -1".to_vec()), &repository),
        Err(WireError::NegativeDepth)
    );
}

#[test]
fn receive_capability_prefix_accepts_one_git_separator_and_refuses_two() {
    assert!(
        Capabilities::parse_v1(
            b" report-status-v2 side-band-64k object-format=sha1",
            &WireLimits::default(),
        )
        .is_ok()
    );
    assert_eq!(
        Capabilities::parse_v1(b"  report-status-v2", &WireLimits::default()),
        Err(WireError::EmptyCapability)
    );
}

#[test]
fn v2_fetch_transcript_requests_sideband_pack_after_done() {
    let repository = Repository::sha1();
    let caps = v2_fetch_capabilities();
    let mut machine = V2UploadPack::new(caps, WireLimits::default()).expect("v2 machine");
    let transition = machine
        .push_bytes(
            fixture_bytes(include_bytes!("fixtures/v2-fetch.pkt")),
            &repository,
        )
        .expect("fetch transcript");
    assert_eq!(
        transition.output,
        vec![Packet::Data(b"packfile\n".to_vec())],
        "a protocol-v2 fetch without wait-for-done starts its response at packfile"
    );
    let Some(WireEvent::PackRequested(request)) = transition.events.last() else {
        panic!("complete v2 request must ask for a pack");
    };
    assert_eq!(request.version, UploadPackVersion::V2);
    assert_eq!(request.shallows.len(), 1);
    assert_eq!(request.deepen, Some(3));
    assert_eq!(request.filter, Some(ObjectFilter::BlobNone));
}

#[test]
fn malformed_packet_hex_and_oversize_packets_have_typed_refusals() {
    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("limits");
    assert_eq!(
        decoder.push(b"00g0"),
        Err(WireError::InvalidPacketLengthHex {
            offset: 2,
            byte: b'g'
        })
    );
    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("limits");
    assert_eq!(
        decoder.push(b"ffff"),
        Err(WireError::PacketTooLarge {
            declared: 65_535,
            limit: 65_520
        })
    );
    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("limits");
    assert_eq!(decoder.push(b"0003"), Err(WireError::ReservedPacketLength));
}

#[test]
fn unadvertised_want_negative_depth_and_unknown_capability_are_refused() {
    let repository = Repository::sha1();
    let caps = Capabilities::parse_v1(b"shallow", &WireLimits::default()).expect("caps");
    let mut machine =
        LegacyUploadPack::new(UploadPackVersion::V0, caps, WireLimits::default()).expect("machine");
    let unknown_want = Packet::Data(b"want 3333333333333333333333333333333333333333\n".to_vec());
    assert!(matches!(
        machine.push_packet(&unknown_want, &repository),
        Err(WireError::WantNotAdvertised { .. })
    ));
    let known_want = Packet::Data(format!("want {WANT}\n").into_bytes());
    machine
        .push_packet(&known_want, &repository)
        .expect("known want");
    assert_eq!(
        machine.push_packet(&Packet::Data(b"deepen -1\n".to_vec()), &repository),
        Err(WireError::NegativeDepth)
    );

    let caps = Capabilities::parse_v1(b"multi_ack", &WireLimits::default()).expect("caps");
    let mut machine =
        LegacyUploadPack::new(UploadPackVersion::V0, caps, WireLimits::default()).expect("machine");
    let bad_cap = Packet::Data(format!("want {WANT} not-a-git-capability\n").into_bytes());
    assert!(matches!(
        machine.push_packet(&bad_cap, &repository),
        Err(WireError::UnknownCapability { .. })
    ));
}

#[test]
fn v2_capability_phase_refuses_a_capability_not_in_its_advertisement() {
    let repository = Repository::sha1();
    let caps = Capabilities::parse_v1(b"ls-refs", &WireLimits::default()).expect("ls-refs cap");
    let mut machine = V2UploadPack::new(caps, WireLimits::default()).expect("v2 machine");
    machine
        .push_packet(&Packet::Data(b"command=ls-refs\n".to_vec()), &repository)
        .expect("command");
    assert!(matches!(
        machine.push_packet(&Packet::Data(b"unadvertised=value\n".to_vec()), &repository),
        Err(WireError::UnknownCapability { .. })
    ));
}

#[test]
fn advertisement_ref_names_reuse_the_canonical_git_ref_validator() {
    let oid = AnyGitOid::from_hex(GitObjectFormat::Sha1, WANT).expect("fixture oid");
    assert!(AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).is_ok());
    assert_eq!(
        AdvertisedRef::new(oid, b"refs/heads/../escape", &WireLimits::default()),
        Err(WireError::InvalidRefName)
    );
}

#[test]
fn filters_sideband_and_hash_formats_preserve_explicit_domains() {
    assert_eq!(
        parse_filter(
            b"combine:blob:none+tree:2",
            GitObjectFormat::Sha1,
            &WireLimits::default()
        ),
        Ok(ObjectFilter::Combine(vec![
            ObjectFilter::BlobNone,
            ObjectFilter::TreeDepth(2)
        ]))
    );
    let packets = encode_sideband_64k(
        SidebandBand::Progress,
        b"counting objects\n",
        &WireLimits::default(),
    )
    .expect("sideband");
    assert_eq!(
        parse_sideband(&packets[0]).expect("parse sideband").band,
        SidebandBand::Progress
    );
    assert_eq!(
        parse_sideband(&Packet::Data(b"\x03remote error\n".to_vec()))
            .expect("fatal sideband")
            .band,
        SidebandBand::Fatal
    );
    let sha1 = AnyGitOid::from_hex(GitObjectFormat::Sha1, WANT).expect("sha1");
    let sha256 = AnyGitOid::from_hex(
        GitObjectFormat::Sha256,
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("sha256");
    assert_ne!(sha1.algorithm(), sha256.algorithm());
}

#[test]
fn deferred_pack_chunks_are_bounded_before_sideband_emission() {
    let packets = sideband_pack_chunk(b"PACK", &WireLimits::default()).expect("small chunk");
    assert_eq!(
        parse_sideband(&packets[0]).expect("sideband packet").band,
        SidebandBand::PackData
    );

    let oversized = vec![0_u8; fgit_wire::MAX_SIDEBAND_DATA_BYTES + 1];
    assert!(matches!(
        sideband_pack_chunk(&oversized, &WireLimits::default()),
        Err(WireError::PackChunkTooLarge { .. })
    ));
}

#[test]
fn repeated_transcript_transitions_are_deterministic() {
    let repository = Repository::sha1();
    let caps = v2_fetch_capabilities();
    let mut first = V2UploadPack::new(caps.clone(), WireLimits::default()).expect("first");
    let mut second = V2UploadPack::new(caps, WireLimits::default()).expect("second");
    let transcript = fixture_bytes(include_bytes!("fixtures/v2-fetch.pkt"));
    assert_eq!(
        first
            .push_bytes(transcript, &repository)
            .expect("first transition"),
        second
            .push_bytes(transcript, &repository)
            .expect("second transition")
    );
}

#[test]
fn multi_ack_default_is_not_selected_without_client_capability() {
    assert_eq!(AckMode::default(), AckMode::None);
}
