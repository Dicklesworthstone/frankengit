#![forbid(unsafe_code)]

use fgit_wire::{AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack,
    Packet, UploadPackRepository, UploadPackVersion, WireEvent, WireLimits, encode_packets};

struct Repository { refs: Vec<AdvertisedRef>, common: Vec<AnyGitOid>, format: GitObjectFormat }
impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        let oid = |byte: &str| AnyGitOid::from_hex(format, &byte.repeat(format.digest_len())).unwrap();
        Self { refs: vec![AdvertisedRef::new(oid("11"), b"refs/heads/main", &WireLimits::default()).unwrap()],
            common: vec![oid("11"), oid("22")], format }
    }
    fn text(&self, byte: &str) -> String { byte.repeat(self.format.digest_len()) }
}
impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat { self.format }
    fn advertised_refs(&self) -> &[AdvertisedRef] { &self.refs }
    fn contains_want(&self, oid: AnyGitOid) -> bool { self.refs.iter().any(|r| r.oid == oid) }
    fn is_common(&self, oid: AnyGitOid) -> bool { self.common.contains(&oid) }
}
fn data(text: impl Into<Vec<u8>>) -> Packet { Packet::Data(text.into()) }
fn machine(repo: &Repository, caps: &str) -> LegacyUploadPack {
    let limits = WireLimits::default();
    let mut machine = LegacyUploadPack::new(UploadPackVersion::V0,
        Capabilities::parse_v1(b"multi_ack multi_ack_detailed no-done", &limits).unwrap(), limits)
        .unwrap().with_stateless_http_rounds();
    let tail = if caps.is_empty() { String::new() } else { format!(" {caps}") };
    let first = machine.push_packet(&data(format!("want {}{tail}\n", repo.text("11"))), repo).unwrap();
    assert!(first.output.is_empty());
    let flush = machine.push_packet(&Packet::Flush, repo).unwrap();
    assert!(flush.output.is_empty(), "HTTP want flush must not send a premature NAK");
    machine
}
fn has_pack(events: &[WireEvent]) -> bool { events.iter().any(|e| matches!(e, WireEvent::PackRequested(_))) }

#[test]
fn http_clone_done_emits_exactly_one_nak_for_every_ack_mode_and_hash() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for caps in ["", "multi_ack", "multi_ack_detailed", "multi_ack_detailed no-done"] {
            let mut machine = machine(&repo, caps);
            let done = machine.push_packet(&data(b"done\n"), &repo).unwrap();
            assert_eq!(done.output, vec![data(b"NAK\n")]);
            assert!(has_pack(&done.events));
            machine.finish_stateless_http_round().unwrap();
        }
    }
}

#[test]
fn http_unknown_have_batch_finishes_without_pack_even_with_no_done() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for caps in ["", "multi_ack", "multi_ack_detailed no-done"] {
            let mut machine = machine(&repo, caps);
            machine.push_packet(&data(format!("have {}\n", repo.text("33"))), &repo).unwrap();
            let batch = machine.push_packet(&Packet::Flush, &repo).unwrap();
            assert_eq!(batch.output, vec![data(b"NAK\n")]);
            assert!(!has_pack(&batch.events));
            assert!(!machine.is_complete());
            assert!(machine.is_http_negotiation_complete());
            machine.finish_stateless_http_round().unwrap();
            assert!(machine.push_packet(&data(b"done\n"), &repo).is_err());
        }
    }
}

#[test]
fn http_common_have_negotiation_uses_native_ack_modes() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for (caps, suffix) in [("", ""), ("multi_ack", " continue"), ("multi_ack_detailed", " common")] {
            let mut machine = machine(&repo, caps);
            let have = machine.push_packet(&data(format!("have {}\n", repo.text("22"))), &repo).unwrap();
            assert_eq!(have.output, vec![data(format!("ACK {}{suffix}\n", repo.text("22")))]);
            let batch = machine.push_packet(&Packet::Flush, &repo).unwrap();
            assert_eq!(batch.output, if caps.is_empty() { vec![] } else { vec![data(b"NAK\n")] });
            assert!(!has_pack(&batch.events));
        }
    }
}

#[test]
fn http_done_after_common_uses_unqualified_final_ack_not_ready() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    for caps in ["multi_ack", "multi_ack_detailed"] {
        let mut machine = machine(&repo, caps);
        machine.push_packet(&data(format!("have {}\n", repo.text("22"))), &repo).unwrap();
        let done = machine.push_packet(&data(b"done\n"), &repo).unwrap();
        assert_eq!(done.output, vec![data(format!("ACK {}\n", repo.text("22")))]);
        assert!(has_pack(&done.events));
    }
}

#[test]
fn http_single_ack_is_sent_only_once_even_with_multiple_common_haves() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    let mut machine = machine(&repo, "");
    let first = machine.push_packet(&data(format!("have {}\n", repo.text("22"))), &repo).unwrap();
    assert_eq!(first.output.len(), 1);
    let second = machine.push_packet(&data(format!("have {}\n", repo.text("11"))), &repo).unwrap();
    assert!(second.output.is_empty());
    let done = machine.push_packet(&data(b"done\n"), &repo).unwrap();
    assert!(done.output.is_empty());
    assert!(has_pack(&done.events));
}

#[test]
fn http_no_done_requires_proven_readiness_not_merely_a_common_object() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    for common in ["11", "22"] {
        let mut machine = machine(&repo, "multi_ack_detailed no-done");
        machine.push_packet(&data(format!("have {}\n", repo.text(common))), &repo).unwrap();
        let flush = machine.push_packet(&Packet::Flush, &repo).unwrap();
        assert_eq!(has_pack(&flush.events), common == "11");
        assert_eq!(machine.is_complete(), common == "11");
        if common == "11" {
            assert_eq!(flush.output, vec![data(format!("ACK {} ready\n", repo.text("11"))),
                data(b"NAK\n"), data(format!("ACK {}\n", repo.text("11")))]);
        } else { assert_eq!(flush.output, vec![data(b"NAK\n")]); }
    }
}

#[test]
fn http_incomplete_wants_and_haves_are_not_completed_by_eof() {
    let repo = Repository::new(GitObjectFormat::Sha1);
    let mut machine = machine(&repo, "multi_ack");
    assert!(machine.finish_stateless_http_round().is_err());
    machine.push_packet(&data(format!("have {}\n", repo.text("22"))), &repo).unwrap();
    assert!(machine.finish_stateless_http_round().is_err());
    machine.push_packet(&Packet::Flush, &repo).unwrap();
    machine.finish_stateless_http_round().unwrap();
}

#[test]
fn http_packet_fragmentation_does_not_change_negotiation_outputs() {
    let repo = Repository::new(GitObjectFormat::Sha256);
    let caps = Capabilities::parse_v1(b"multi_ack_detailed", &WireLimits::default()).unwrap();
    let request = encode_packets(&[data(format!("want {} multi_ack_detailed\n", repo.text("11"))),
        Packet::Flush, data(format!("have {}\n", repo.text("22"))), data(b"done\n")], &WireLimits::default()).unwrap();
    let expected = vec![data(format!("ACK {} common\n", repo.text("22"))), data(format!("ACK {}\n", repo.text("22")))];
    for width in [1, 2, 3, 4, 7, request.len()] {
        let mut machine = LegacyUploadPack::new(UploadPackVersion::V1, caps.clone(), WireLimits::default())
            .unwrap().with_stateless_http_rounds();
        let mut output = Vec::new(); let mut packs = 0;
        for chunk in request.chunks(width) {
            let transition = machine.push_bytes(chunk, &repo).unwrap();
            output.extend(transition.output);
            packs += transition.events.iter().filter(|e| matches!(e, WireEvent::PackRequested(_))).count();
        }
        machine.finish_stateless_http_round().unwrap();
        assert_eq!(output, expected); assert_eq!(packs, 1);
    }
}
