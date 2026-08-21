#![forbid(unsafe_code)]

use fgit_wire::receive::{
    ReceiveCommandKind, ReceiveCommandStatus, ReceiveCompletion, ReceiveContext, ReceiveError,
    ReceiveEvent, ReceiveLimits, ReceivePack, ReceivePhase, ReceiveQuarantineHandoff,
    SignedPushProfile, UnpackStatus, advertise_receive_pack, report_status,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, WireError, WireLimits,
    encode_packet,
};

const OLD: &str = "1111111111111111111111111111111111111111";
const NEW: &str = "2222222222222222222222222222222222222222";
const ZERO: &str = "0000000000000000000000000000000000000000";

#[derive(Default)]
struct Handoff {
    calls: usize,
    saw_pack: bool,
    pack_entries: usize,
}

impl ReceiveQuarantineHandoff for Handoff {
    fn handoff(
        &mut self,
        _request: &fgit_wire::receive::ReceiveRequest,
        pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &fgit_wire::receive::QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        self.calls += 1;
        self.saw_pack = pack.is_some();
        self.pack_entries = pack.map_or(0, |value| value.entries().len());
        Ok(())
    }
}

fn capabilities(source: &[u8]) -> Capabilities {
    if source.is_empty() {
        return Capabilities::default();
    }
    Capabilities::parse_v1(source, &WireLimits::default()).expect("fixture capabilities")
}

fn context(server_capabilities: &[u8]) -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        capabilities(server_capabilities),
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("fixture receive context")
}

fn signed_context(nonce: &[u8]) -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        capabilities(b"delete-refs push-cert=nonce-1 report-status"),
        ReceiveLimits::default(),
        SignedPushProfile::ParseV1 {
            expected_nonce: nonce.to_vec(),
        },
    )
    .expect("fixture signed receive context")
}

fn command(old: &str, new: &str, name: &str, capabilities: Option<&str>) -> Packet {
    let mut line = format!("{old} {new} {name}").into_bytes();
    if let Some(capabilities) = capabilities {
        line.push(0);
        line.extend_from_slice(capabilities.as_bytes());
    }
    line.push(b'\n');
    Packet::Data(line)
}

fn empty_sha1_pack() -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    let checksum = fgit_crypto::sha1_digest(&pack);
    pack.extend_from_slice(checksum.as_slice());
    pack
}

fn ready_request(machine: &mut ReceivePack) -> fgit_wire::receive::ReceiveRequest {
    let transition = machine.push_packet(Packet::Flush).expect("command flush");
    let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
        panic!("flush must expose a parsed request");
    };
    (**request).clone()
}

#[test]
fn command_goldens_preserve_create_delete_and_expected_old_semantics() {
    let mut create = ReceivePack::new(context(b"delete-refs report-status")).expect("machine");
    create
        .push_packet(command(
            ZERO,
            NEW,
            "refs/heads/create",
            Some("report-status"),
        ))
        .expect("create command");
    let create_request = ready_request(&mut create);
    assert_eq!(
        create_request.commands[0].kind(),
        ReceiveCommandKind::Create
    );
    assert_eq!(create_request.commands[0].expected_old(), None);
    assert_eq!(create.phase(), ReceivePhase::Pack);

    let mut delete = ReceivePack::new(context(b"delete-refs")).expect("machine");
    delete
        .push_packet(command(OLD, ZERO, "refs/heads/delete", Some("delete-refs")))
        .expect("delete command");
    let delete_request = ready_request(&mut delete);
    assert_eq!(
        delete_request.commands[0].kind(),
        ReceiveCommandKind::Delete
    );
    assert!(delete_request.deletes_only());
    assert_eq!(delete.phase(), ReceivePhase::Ready);

    let mut update = ReceivePack::new(context(b"")).expect("machine");
    update
        .push_packet(command(OLD, NEW, "refs/heads/update", None))
        .expect("update command");
    let update_request = ready_request(&mut update);
    assert_eq!(
        update_request.commands[0].kind(),
        ReceiveCommandKind::Update
    );
    assert_eq!(
        update_request.commands[0].expected_old(),
        Some(AnyGitOid::from_hex(GitObjectFormat::Sha1, OLD).expect("old id"))
    );
}

#[test]
fn packet_and_raw_pack_same_read_are_bounded_then_handed_off_without_retention() {
    let mut machine = ReceivePack::new(context(b"report-status")).expect("machine");
    let command = command(OLD, NEW, "refs/heads/main", Some("report-status"));
    let mut transcript = encode_packet(&command, &WireLimits::default()).expect("command encode");
    transcript.extend_from_slice(b"0000");
    transcript.extend_from_slice(&empty_sha1_pack());
    machine
        .push_bytes(&transcript)
        .expect("same-read transcript");
    assert_eq!(machine.phase(), ReceivePhase::Pack);
    assert_eq!(machine.quarantine_len(), empty_sha1_pack().len());

    let mut handoff = Handoff::default();
    let mut continuing = || true;
    let completion = machine
        .finish_with_handoff(&mut handoff, &mut continuing)
        .expect("validated quarantine handoff");
    assert_eq!(completion.quarantine.object_count, 0);
    assert_eq!(completion.quarantine.delete_only, false);
    assert_eq!(handoff.calls, 1);
    assert!(handoff.saw_pack);
    assert_eq!(handoff.pack_entries, 0);
    assert_eq!(machine.quarantine_len(), 0);
    assert_eq!(machine.phase(), ReceivePhase::Complete);
}

#[test]
fn same_read_push_options_second_flush_then_pack_is_quarantined() {
    let mut machine = ReceivePack::new(context(b"report-status push-options")).expect("machine");
    let command = command(
        OLD,
        NEW,
        "refs/heads/main",
        Some("report-status push-options"),
    );
    let mut transcript = encode_packet(&command, &WireLimits::default()).expect("command encode");
    transcript.extend_from_slice(b"0000");
    transcript.extend_from_slice(
        &encode_packet(
            &Packet::Data(b"review=42\n".to_vec()),
            &WireLimits::default(),
        )
        .expect("push-option encode"),
    );
    transcript.extend_from_slice(b"0000");
    transcript.extend_from_slice(&empty_sha1_pack());

    let transition = machine
        .push_bytes(&transcript)
        .expect("same-read transcript");
    assert_eq!(transition.events.len(), 1);
    assert!(matches!(
        transition.events.first(),
        Some(ReceiveEvent::RequestReady(request)) if request.push_options == vec![b"review=42".to_vec()]
    ));
    assert_eq!(machine.phase(), ReceivePhase::Pack);
    assert_eq!(machine.quarantine_len(), empty_sha1_pack().len());

    let mut handoff = Handoff::default();
    let mut continuing = || true;
    let completion = machine
        .finish_with_handoff(&mut handoff, &mut continuing)
        .expect("validated quarantine handoff");
    assert_eq!(completion.request.push_options, vec![b"review=42".to_vec()]);
    assert!(handoff.saw_pack);
    assert_eq!(machine.quarantine_len(), 0);
}

#[test]
fn invalid_pack_and_cancelled_validation_discard_every_local_byte() {
    let mut malformed = ReceivePack::new(context(b"")).expect("machine");
    malformed
        .push_packet(command(OLD, NEW, "refs/heads/main", None))
        .expect("command");
    let _ = ready_request(&mut malformed);
    malformed.push_bytes(b"not a pack").expect("bounded ingest");
    let mut handoff = Handoff::default();
    let mut continuing = || true;
    assert!(matches!(
        malformed.finish_with_handoff(&mut handoff, &mut continuing),
        Err(ReceiveError::Pack(_))
    ));
    assert_eq!(handoff.calls, 0);
    assert_eq!(malformed.quarantine_len(), 0);
    assert_eq!(malformed.phase(), ReceivePhase::Refused);

    let mut cancelled = ReceivePack::new(context(b"")).expect("machine");
    cancelled
        .push_packet(command(OLD, NEW, "refs/heads/main", None))
        .expect("command");
    let _ = ready_request(&mut cancelled);
    cancelled
        .push_bytes(&empty_sha1_pack())
        .expect("bounded valid pack ingest");
    let mut stopped = || false;
    assert_eq!(
        cancelled.finish_with_handoff(&mut Handoff::default(), &mut stopped),
        Err(ReceiveError::Cancelled)
    );
    assert_eq!(cancelled.quarantine_len(), 0);
    assert_eq!(cancelled.phase(), ReceivePhase::Refused);
}

#[test]
fn atomic_and_non_atomic_report_status_are_deterministic_and_ordered() {
    let mut atomic = ReceivePack::new(context(b"report-status atomic")).expect("machine");
    atomic
        .push_packet(command(
            OLD,
            NEW,
            "refs/heads/a",
            Some("report-status atomic"),
        ))
        .expect("first command");
    atomic
        .push_packet(command(OLD, NEW, "refs/heads/b", None))
        .expect("second command");
    let atomic_request = ready_request(&mut atomic);
    let atomic_report = report_status(
        &atomic_request,
        UnpackStatus::Ok,
        &[
            ReceiveCommandStatus::Ok,
            ReceiveCommandStatus::Rejected {
                message: b"protected branch".to_vec(),
            },
        ],
        &ReceiveLimits::default(),
    )
    .expect("atomic report");
    assert_eq!(
        atomic_report,
        vec![
            Packet::Data(b"unpack ok\n".to_vec()),
            Packet::Data(b"ng refs/heads/a atomic push failed\n".to_vec()),
            Packet::Data(b"ng refs/heads/b atomic push failed\n".to_vec()),
            Packet::Flush,
        ]
    );

    let mut non_atomic = ReceivePack::new(context(b"report-status")).expect("machine");
    non_atomic
        .push_packet(command(OLD, NEW, "refs/heads/a", Some("report-status")))
        .expect("first command");
    non_atomic
        .push_packet(command(OLD, NEW, "refs/heads/b", None))
        .expect("second command");
    let request = ready_request(&mut non_atomic);
    let statuses = [
        ReceiveCommandStatus::Ok,
        ReceiveCommandStatus::Rejected {
            message: b"protected branch".to_vec(),
        },
    ];
    let first = report_status(
        &request,
        UnpackStatus::Ok,
        &statuses,
        &ReceiveLimits::default(),
    )
    .expect("first non-atomic report");
    let second = report_status(
        &request,
        UnpackStatus::Ok,
        &statuses,
        &ReceiveLimits::default(),
    )
    .expect("second non-atomic report");
    assert_eq!(first, second);
    assert_eq!(
        first,
        vec![
            Packet::Data(b"unpack ok\n".to_vec()),
            Packet::Data(b"ok refs/heads/a\n".to_vec()),
            Packet::Data(b"ng refs/heads/b protected branch\n".to_vec()),
            Packet::Flush,
        ]
    );
}

#[test]
fn negotiated_receive_capabilities_drive_push_options_and_sideband_status() {
    let server =
        b"report-status-v2 side-band-64k quiet atomic ofs-delta push-options agent=frankengit/0.1";
    let mut machine = ReceivePack::new(context(server)).expect("machine");
    machine
        .push_packet(command(
            OLD,
            NEW,
            "refs/heads/main",
            Some(
                "report-status-v2 side-band-64k quiet atomic ofs-delta push-options agent=client/1.0",
            ),
        ))
        .expect("capability command");
    let first_flush = machine.push_packet(Packet::Flush).expect("command flush");
    assert_eq!(first_flush.events.len(), 0);
    assert_eq!(machine.phase(), ReceivePhase::PushOptions);
    machine
        .push_packet(Packet::Data(b"review=42\n".to_vec()))
        .expect("push option");
    let second_flush = machine
        .push_packet(Packet::Flush)
        .expect("push-option flush");
    let Some(ReceiveEvent::RequestReady(request)) = second_flush.events.first() else {
        panic!("push-option flush must expose request");
    };
    assert_eq!(request.push_options, vec![b"review=42".to_vec()]);
    assert!(request.has_capability(b"ofs-delta"));
    assert!(request.has_capability(b"quiet"));
    let report = report_status(
        request,
        UnpackStatus::Ok,
        &[ReceiveCommandStatus::Ok],
        &ReceiveLimits::default(),
    )
    .expect("sideband report");
    assert!(matches!(
        report.first(),
        Some(Packet::Data(line)) if line.first() == Some(&1)
    ));
    assert_eq!(report.last(), Some(&Packet::Flush));
}

#[test]
fn signed_push_nonce_profile_parses_and_mismatches_are_typed() {
    let mut machine = ReceivePack::new(signed_context(b"nonce-1")).expect("machine");
    machine
        .push_packet(Packet::Data(b"push-cert\0push-cert delete-refs\n".to_vec()))
        .expect("certificate prelude");
    for line in [
        b"certificate version 0.1\n".as_slice(),
        b"pusher A U Thor <a@example.test> 0 +0000\n",
        b"pushee ssh://example.test/repo\n",
        b"nonce nonce-1\n",
        b"\n",
    ] {
        machine
            .push_packet(Packet::Data(line.to_vec()))
            .expect("certificate header");
    }
    machine
        .push_packet(command(OLD, ZERO, "refs/heads/delete", None))
        .expect("signed delete command");
    for line in [
        b"-----BEGIN PGP SIGNATURE-----\n".as_slice(),
        b"signature-data\n",
        b"-----END PGP SIGNATURE-----\n",
        b"push-cert-end\n",
    ] {
        machine
            .push_packet(Packet::Data(line.to_vec()))
            .expect("certificate signature");
    }
    let request = ready_request(&mut machine);
    let certificate = request.certificate.expect("parsed certificate");
    assert_eq!(certificate.nonce, b"nonce-1");
    assert_eq!(certificate.signature_lines.len(), 3);

    let mut mismatch = ReceivePack::new(signed_context(b"nonce-1")).expect("machine");
    mismatch
        .push_packet(Packet::Data(b"push-cert\0push-cert\n".to_vec()))
        .expect("certificate prelude");
    for line in [
        b"certificate version 0.1\n".as_slice(),
        b"pusher A U Thor <a@example.test> 0 +0000\n",
        b"pushee ssh://example.test/repo\n",
    ] {
        mismatch
            .push_packet(Packet::Data(line.to_vec()))
            .expect("prefix before nonce");
    }
    assert_eq!(
        mismatch.push_packet(Packet::Data(b"nonce wrong\n".to_vec())),
        Err(ReceiveError::CertificateNonceMismatch)
    );
    assert_eq!(mismatch.phase(), ReceivePhase::Refused);
    assert_eq!(mismatch.quarantine_len(), 0);
}

#[test]
fn planted_protocol_negatives_refuse_before_admission_or_unbounded_storage() {
    let mut empty = ReceivePack::new(context(b"")).expect("machine");
    assert_eq!(
        empty.push_packet(Packet::Flush),
        Err(ReceiveError::MissingCommands)
    );
    assert_eq!(empty.phase(), ReceivePhase::Refused);

    let mut invalid_ref = ReceivePack::new(context(b"")).expect("machine");
    assert_eq!(
        invalid_ref.push_packet(command(OLD, NEW, "refs/heads/../escape", None)),
        Err(ReceiveError::Wire(WireError::InvalidRefName))
    );

    let mut repeated_capability_separator =
        ReceivePack::new(context(b"report-status atomic")).expect("machine");
    assert!(matches!(
        repeated_capability_separator.push_packet(Packet::Data(
            format!("{OLD} {NEW} refs/heads/main\0report-status\0atomic\n").into_bytes(),
        )),
        Err(ReceiveError::MalformedCommand { .. })
    ));
    assert_eq!(repeated_capability_separator.phase(), ReceivePhase::Refused);
    assert_eq!(repeated_capability_separator.quarantine_len(), 0);

    let mut delete_without_capability = ReceivePack::new(context(b"")).expect("machine");
    delete_without_capability
        .push_packet(command(OLD, ZERO, "refs/heads/delete", None))
        .expect("syntax before capability check");
    assert_eq!(
        delete_without_capability.push_packet(Packet::Flush),
        Err(ReceiveError::DeleteRefsNotNegotiated)
    );

    let mut limits = ReceiveLimits::default();
    limits.max_quarantine_bytes = 4;
    limits.pack.max_input_bytes = 4;
    let bounded_context = ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::default(),
        limits.clone(),
        SignedPushProfile::Refuse,
    )
    .expect("bounded context");
    let mut bounded = ReceivePack::new(bounded_context).expect("machine");
    bounded
        .push_packet(command(OLD, NEW, "refs/heads/main", None))
        .expect("command");
    let _ = ready_request(&mut bounded);
    assert_eq!(
        bounded.push_bytes(&vec![0_u8; limits.max_quarantine_bytes + 1]),
        Err(ReceiveError::QuarantineBytesExceeded {
            limit: limits.max_quarantine_bytes,
        })
    );
    assert_eq!(bounded.quarantine_len(), 0);
    assert_eq!(bounded.phase(), ReceivePhase::Refused);
}

#[test]
fn empty_repository_advertisement_has_capability_pseudo_ref_and_is_reproducible() {
    let context = context(b"report-status delete-refs");
    let first = advertise_receive_pack(Vec::new(), &context).expect("first advertisement");
    let second = advertise_receive_pack(Vec::new(), &context).expect("second advertisement");
    assert_eq!(first, second);
    assert_eq!(
        first,
        vec![
            Packet::Data(
                b"0000000000000000000000000000000000000000 capabilities^{}\0report-status delete-refs\n"
                    .to_vec(),
            ),
            Packet::Flush,
        ]
    );

    let reference = AdvertisedRef::new(
        AnyGitOid::from_hex(GitObjectFormat::Sha1, OLD).expect("fixture object id"),
        b"refs/heads/main",
        &WireLimits::default(),
    )
    .expect("fixture ref");
    let regular = advertise_receive_pack(vec![reference], &context).expect("regular advertisement");
    assert_eq!(regular.last(), Some(&Packet::Flush));
}

#[test]
fn receive_completion_carries_no_pack_and_delete_only_handoff_has_no_pack() {
    let mut machine = ReceivePack::new(context(b"delete-refs")).expect("machine");
    machine
        .push_packet(command(OLD, ZERO, "refs/heads/delete", Some("delete-refs")))
        .expect("delete command");
    let _ = ready_request(&mut machine);
    let mut handoff = Handoff::default();
    let mut continuing = || true;
    let ReceiveCompletion { quarantine, .. } = machine
        .finish_with_handoff(&mut handoff, &mut continuing)
        .expect("delete-only handoff");
    assert_eq!(quarantine.delete_only, true);
    assert_eq!(quarantine.pack_bytes, 0);
    assert!(!handoff.saw_pack);
    assert_eq!(handoff.calls, 1);
}
