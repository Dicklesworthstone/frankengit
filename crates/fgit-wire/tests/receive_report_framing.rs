#![forbid(unsafe_code)]

//! Channel 1 transports the entire report pkt-line stream, not bare text.
//! The literal inner success transcript follows Git's report/report_v2 grammar
//! and was separately observed with isolated Git 2.47.3; these Rust tests use
//! only the real parser, formatter, encoder, and decoder, never a Git process.

use fgit_wire::receive::{
    ReceiveCommandStatus, ReceiveContext, ReceiveError, ReceiveEvent, ReceiveLimits,
    ReceivePack, ReceiveRequest, SignedPushProfile, UnpackStatus, report_status,
};
use fgit_wire::{
    Capabilities, GitObjectFormat, Packet, PktLineDecoder, SidebandBand, WireError,
    WireLimits, encode_packets, parse_sideband,
};

const SUCCESS: &[u8] = b"000eunpack ok\n0017ok refs/heads/main\n0000";

fn request(format: GitObjectFormat, capabilities: &str, names: &[&str]) -> ReceiveRequest {
    let limits = ReceiveLimits::default();
    let server = Capabilities::parse_v1(
        b"report-status report-status-v2 side-band-64k atomic delete-refs",
        &limits.wire,
    )
    .expect("server capabilities");
    let context = ReceiveContext::new(format, server, limits, SignedPushProfile::Refuse)
        .expect("receive context");
    let mut parser = ReceivePack::new(context).expect("receive parser");
    let old = "1".repeat(format.digest_len() * 2);
    let new = "0".repeat(format.digest_len() * 2);
    for (index, name) in names.iter().enumerate() {
        let mut line = format!("{old} {new} {name}").into_bytes();
        if index == 0 && !capabilities.is_empty() {
            line.push(0);
            line.extend_from_slice(capabilities.as_bytes());
        }
        parser.push_packet(Packet::Data(line)).expect("delete command");
    }
    let ready = parser.push_packet(Packet::Flush).expect("command flush");
    let Some(ReceiveEvent::RequestReady(request)) = ready.events.first() else {
        panic!("complete command section must expose its actual parsed request");
    };
    (**request).clone()
}

fn demultiplex(packets: &[Packet], limits: &WireLimits) -> Vec<u8> {
    assert_eq!(packets.last(), Some(&Packet::Flush), "outer termination");
    let mut inner = Vec::new();
    for packet in &packets[..packets.len() - 1] {
        let Packet::Data(data) = packet else {
            panic!("no outer flush or v2 delimiter may interrupt channel 1");
        };
        assert!(data.len() + 4 <= limits.max_packet_bytes);
        let frame = parse_sideband(packet).expect("valid sideband frame");
        assert_eq!(frame.band, SidebandBand::PackData);
        inner.extend_from_slice(&frame.data);
    }
    inner
}

fn decode(bytes: &[u8], fragment: usize) -> Vec<Packet> {
    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("decoder");
    let mut packets = Vec::new();
    for chunk in bytes.chunks(fragment) {
        packets.extend(decoder.push(chunk).expect("framed report fragment"));
    }
    decoder.finish().expect("complete inner stream");
    packets
}

#[test]
fn both_report_versions_and_object_formats_emit_the_literal_inner_stream() {
    let limits = ReceiveLimits::default();
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for mode in ["report-status", "report-status-v2"] {
            let request = request(format, &format!("{mode} side-band-64k"), &["refs/heads/main"]);
            let original = request.clone();
            let packets = report_status(&request, UnpackStatus::Ok, &[ReceiveCommandStatus::Ok], &limits)
                .expect("sideband report");
            assert_eq!(demultiplex(&packets, &limits.wire), SUCCESS);
            assert_eq!(packets[packets.len() - 2], Packet::Data(b"\x010000".to_vec()));
            assert_eq!(request, original, "framing must not mutate the semantic request");
            assert_eq!(
                report_status(&request, UnpackStatus::Ok, &[ReceiveCommandStatus::Ok], &limits)
                    .expect("repeated report"),
                packets
            );
        }
    }
}

#[test]
fn non_sideband_output_stays_byte_exact_without_an_extra_outer_flush() {
    let limits = ReceiveLimits::default();
    for mode in ["report-status", "report-status-v2"] {
        let request = request(GitObjectFormat::Sha1, mode, &["refs/heads/main"]);
        let packets = report_status(&request, UnpackStatus::Ok, &[ReceiveCommandStatus::Ok], &limits)
            .expect("plain report");
        assert_eq!(encode_packets(&packets, &limits.wire).expect("encode"), SUCCESS);
        assert_eq!(packets, decode(SUCCESS, 1));
    }
}

#[test]
fn inner_records_survive_both_sideband_and_network_fragmentation() {
    let mut limits = ReceiveLimits::default();
    limits.wire.max_packet_bytes = 24;
    let request = request(
        GitObjectFormat::Sha1,
        "report-status side-band-64k",
        &["refs/heads/main"],
    );
    let packets = report_status(&request, UnpackStatus::Ok, &[ReceiveCommandStatus::Ok], &limits)
        .expect("bounded fragmented report");
    assert_eq!(packets.len(), 5, "the command pkt-line needs two outer frames");
    let encoded = encode_packets(&packets, &limits.wire).expect("outer encoding");
    for fragment in 1..=encoded.len() {
        let outer = decode(&encoded, fragment);
        let inner = demultiplex(&outer, &limits.wire);
        assert_eq!(inner, SUCCESS);
        assert_eq!(decode(&inner, fragment), decode(SUCCESS, 1));
    }
}

#[test]
fn outbound_budget_includes_inner_headers_inner_flush_and_outer_termination() {
    for packet_limit in [24, 65_520] {
        let mut limits = ReceiveLimits::default();
        limits.wire.max_packet_bytes = packet_limit;
        let request = request(
            GitObjectFormat::Sha1,
            "report-status side-band-64k",
            &["refs/heads/main"],
        );
        let packets = report_status(&request, UnpackStatus::Ok, &[ReceiveCommandStatus::Ok], &limits)
            .expect("unconstrained reference");
        let required = encode_packets(&packets, &limits.wire).expect("wire bytes").len();
        assert_eq!(required, if packet_limit == 24 { 65 } else { 60 });
        limits.wire.max_outbound_bytes = required;
        assert_eq!(
            report_status(&request, UnpackStatus::Ok, &[ReceiveCommandStatus::Ok], &limits)
                .expect("exact envelope"),
            packets
        );
        limits.wire.max_outbound_bytes -= 1;
        assert_eq!(
            report_status(&request, UnpackStatus::Ok, &[ReceiveCommandStatus::Ok], &limits),
            Err(ReceiveError::Wire(WireError::OutboundBytesExceeded { limit: required - 1 }))
        );
    }
}

#[test]
fn disabled_report_still_finishes_sideband_without_fabricating_inner_statuses() {
    let mut limits = ReceiveLimits::default();
    let request = request(GitObjectFormat::Sha1, "side-band-64k", &["refs/heads/main"]);
    limits.wire.max_outbound_bytes = 4;
    let packets = report_status(&request, UnpackStatus::Ok, &[], &limits)
        .expect("only multiplexing termination is due");
    assert_eq!(packets, vec![Packet::Flush]);
    assert!(demultiplex(&packets, &limits.wire).is_empty());
    limits.wire.max_outbound_bytes = 3;
    assert_eq!(
        report_status(&request, UnpackStatus::Ok, &[], &limits),
        Err(ReceiveError::Wire(WireError::OutboundBytesExceeded { limit: 3 }))
    );
}

#[test]
fn disabled_report_without_sideband_emits_nothing() {
    let request = request(GitObjectFormat::Sha1, "", &["refs/heads/main"]);
    assert!(report_status(&request, UnpackStatus::Ok, &[], &ReceiveLimits::default())
        .expect("no negotiated response")
        .is_empty());
}

#[test]
fn sideband_preserves_ordered_atomic_and_non_atomic_refusals() {
    let limits = ReceiveLimits::default();
    let statuses = [
        ReceiveCommandStatus::Ok,
        ReceiveCommandStatus::Rejected { message: b"protected branch".to_vec() },
    ];
    for atomic in [false, true] {
        let mode = if atomic { "report-status atomic" } else { "report-status" };
        let plain = request(GitObjectFormat::Sha1, mode, &["refs/heads/a", "refs/heads/b"]);
        let multiplexed = request(
            GitObjectFormat::Sha1,
            &format!("{mode} side-band-64k"),
            &["refs/heads/a", "refs/heads/b"],
        );
        let plain = report_status(&plain, UnpackStatus::Ok, &statuses, &limits).expect("plain");
        let side = report_status(&multiplexed, UnpackStatus::Ok, &statuses, &limits).expect("side");
        let decoded = decode(&demultiplex(&side, &limits.wire), 1);
        assert_eq!(decoded, plain);
        assert_eq!(decoded[1], Packet::Data(if atomic {
            b"ng refs/heads/a atomic push failed\n".to_vec()
        } else {
            b"ok refs/heads/a\n".to_vec()
        }));
        assert_eq!(decoded[2], Packet::Data(if atomic {
            b"ng refs/heads/b atomic push failed\n".to_vec()
        } else {
            b"ng refs/heads/b protected branch\n".to_vec()
        }));
    }
}

#[test]
fn rejected_unpack_is_framed_without_reinterpreting_the_supplied_outcome() {
    let limits = ReceiveLimits::default();
    let request = request(
        GitObjectFormat::Sha1,
        "report-status side-band-64k",
        &["refs/heads/main"],
    );
    let packets = report_status(
        &request,
        UnpackStatus::Rejected { message: b"invalid pack".to_vec() },
        &[ReceiveCommandStatus::Rejected { message: b"unpacker error".to_vec() }],
        &limits,
    ).expect("refusal report");
    assert_eq!(decode(&demultiplex(&packets, &limits.wire), 1), vec![
        Packet::Data(b"unpack invalid pack\n".to_vec()),
        Packet::Data(b"ng refs/heads/main unpacker error\n".to_vec()),
        Packet::Flush,
    ]);
}

#[test]
fn malformed_messages_and_status_count_still_fail_before_a_report_is_returned() {
    let limits = ReceiveLimits::default();
    for capabilities in ["report-status", "report-status side-band-64k"] {
        let request = request(GitObjectFormat::Sha1, capabilities, &["refs/heads/main"]);
        assert_eq!(report_status(&request, UnpackStatus::Ok, &[], &limits),
            Err(ReceiveError::StatusCountMismatch { expected: 1, actual: 0 }));
        assert_eq!(report_status(
            &request,
            UnpackStatus::Ok,
            &[ReceiveCommandStatus::Rejected { message: b"bad\ninjected".to_vec() }],
            &limits,
        ), Err(ReceiveError::InvalidStatusMessage));
    }
}
