#![forbid(unsafe_code)]

use fgit_wire::GitObjectFormat;
use fgit_wire::{
    encode_packets, encode_sideband_64k, parse_filter, parse_sideband, sideband_pack_chunk,
    AckMode, AdvertisedRef, AnyGitOid, Capabilities, LegacyUploadPack, ObjectFilter, Packet,
    PktLineDecoder, SidebandBand, UploadPackRepository, UploadPackVersion, V1Advertisement,
    V2UploadPack, WireError, WireEvent, WireLimits,
};

const WANT: &str = "1111111111111111111111111111111111111111";
const HAVE: &str = "2222222222222222222222222222222222222222";

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
    assert!(request.sideband_64k);
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
    assert!(transition
        .output
        .iter()
        .any(|packet| matches!(packet, Packet::Delimiter)));
    assert!(transition
        .output
        .iter()
        .any(|packet| matches!(packet, Packet::Data(line) if line == b"packfile\n")));
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
