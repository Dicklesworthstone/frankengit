#![forbid(unsafe_code)]
use fgit_wire::closure::ShallowUpdate;
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, PackRequest, Packet,
    UploadPackRepository, UploadPackVersion, V2UploadPack, WireError, WireEvent, WireLimits,
    encode_packets,
};
use std::cell::Cell;

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    permitted: Vec<AnyGitOid>,
    update: ShallowUpdate,
    refuse: bool,
    calls: Cell<usize>,
}

impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }
    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }
    fn contains_want(&self, id: AnyGitOid) -> bool {
        self.permitted.contains(&id)
    }
    fn is_common(&self, _: AnyGitOid) -> bool {
        false
    }
    fn supports_shallow(&self) -> bool {
        true
    }
    fn shallow_update(&self, _: &PackRequest) -> Result<ShallowUpdate, WireError> {
        self.calls.set(self.calls.get() + 1);
        if self.refuse {
            Err(WireError::PackSourceRefused)
        } else {
            Ok(self.update.clone())
        }
    }
}

fn oid(format: GitObjectFormat, byte: u8) -> AnyGitOid {
    AnyGitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}
fn line(text: impl AsRef<str>) -> Packet {
    Packet::Data(format!("{}\n", text.as_ref()).into_bytes())
}
fn repository(format: GitObjectFormat) -> Repository {
    Repository {
        format,
        refs: vec![
            AdvertisedRef::new(oid(format, 1), b"refs/heads/main", &WireLimits::default()).unwrap(),
        ],
        permitted: (1..=3).map(|byte| oid(format, byte)).collect(),
        update: ShallowUpdate {
            shallow: vec![oid(format, 2)],
            unshallow: vec![oid(format, 1)],
        },
        refuse: false,
        calls: Cell::new(0),
    }
}
fn legacy(version: UploadPackVersion, limits: WireLimits, multi: bool) -> LegacyUploadPack {
    let tokens = if multi {
        b"shallow multi_ack_detailed".as_slice()
    } else {
        b"shallow"
    };
    LegacyUploadPack::new(
        version,
        Capabilities::parse_v1(tokens, &limits).unwrap(),
        limits,
    )
    .unwrap()
    .with_shallow_updates()
}
fn legacy_request(machine: &mut LegacyUploadPack, repository: &Repository, multi: bool) {
    let suffix = if multi { " multi_ack_detailed" } else { "" };
    for packet in [
        line(format!("want {}{suffix}", oid(repository.format, 1))),
        line(format!("shallow {}", oid(repository.format, 1))),
        line("deepen 2"),
    ] {
        assert!(
            machine
                .push_packet(&packet, repository)
                .unwrap()
                .output
                .is_empty()
        );
    }
}
fn v2(limits: WireLimits) -> V2UploadPack {
    let caps = Capabilities::parse_v2_advertisement(
        &[line("version 2"), line("fetch=shallow"), Packet::Flush],
        &limits,
    )
    .unwrap();
    V2UploadPack::new(caps, limits)
        .unwrap()
        .with_shallow_updates()
}
fn v2_request(machine: &mut V2UploadPack, repository: &Repository) {
    for packet in [
        line("command=fetch"),
        Packet::Delimiter,
        line(format!("want {}", oid(repository.format, 1))),
        line(format!("shallow {}", oid(repository.format, 1))),
        line("deepen 2"),
        line("done"),
    ] {
        assert!(
            machine
                .push_packet(&packet, repository)
                .unwrap()
                .output
                .is_empty()
        );
    }
}

#[test]
fn legacy_boundaries_and_flush_precede_have_negotiation_and_final_nak() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for multi in [false, true] {
                let repository = repository(format);
                let mut machine = legacy(version, WireLimits::default(), multi);
                legacy_request(&mut machine, &repository, multi);
                let transition = machine.push_packet(&Packet::Flush, &repository).unwrap();
                assert_eq!(
                    transition.output,
                    vec![
                        line(format!("shallow {}", oid(format, 2))),
                        line(format!("unshallow {}", oid(format, 1))),
                        Packet::Flush
                    ]
                );
                assert!(transition.events.is_empty());
                assert_eq!(repository.calls.get(), 1);
                assert!(!machine.is_complete());
                let transition = machine.push_packet(&line("done"), &repository).unwrap();
                assert_eq!(transition.output, vec![line("NAK")]);
                let [WireEvent::PackRequested(request)] = transition.events.as_slice() else {
                    panic!("pack handoff is required");
                };
                assert_eq!(request.deepen, Some(2));
                assert_eq!(request.shallows, vec![oid(format, 1)]);
                assert!(machine.is_complete());
            }
        }
    }
}

#[test]
fn legacy_empty_boundary_update_still_flushes_before_haves() {
    let mut repository = repository(GitObjectFormat::Sha1);
    repository.update = ShallowUpdate {
        shallow: vec![],
        unshallow: vec![],
    };
    let mut machine = legacy(UploadPackVersion::V0, WireLimits::default(), false);
    legacy_request(&mut machine, &repository, false);
    assert_eq!(
        machine
            .push_packet(&Packet::Flush, &repository)
            .unwrap()
            .output,
        vec![Packet::Flush]
    );
}

#[test]
fn v2_shallow_info_is_delimited_before_the_packfile_header() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        let mut machine = v2(WireLimits::default());
        v2_request(&mut machine, &repository);
        let transition = machine.push_packet(&Packet::Flush, &repository).unwrap();
        assert_eq!(
            transition.output,
            vec![
                line("shallow-info"),
                line(format!("shallow {}", oid(format, 2))),
                line(format!("unshallow {}", oid(format, 1))),
                Packet::Delimiter,
                line("packfile")
            ]
        );
        assert_eq!(repository.calls.get(), 1);
        assert!(
            matches!(transition.events.as_slice(), [WireEvent::PackRequested(request)] if request.deepen == Some(2))
        );
    }
}

#[test]
fn provider_failure_does_not_advance_the_legacy_machine_or_emit_success() {
    let mut repository = repository(GitObjectFormat::Sha1);
    repository.refuse = true;
    let mut machine = legacy(UploadPackVersion::V0, WireLimits::default(), false);
    legacy_request(&mut machine, &repository, false);
    assert_eq!(
        machine.push_packet(&Packet::Flush, &repository),
        Err(WireError::PackSourceRefused)
    );
    repository.refuse = false;
    let result = machine.push_packet(&Packet::Flush, &repository).unwrap();
    assert_eq!(result.output.last(), Some(&Packet::Flush));
    assert!(result.events.is_empty());
}

#[test]
fn foreign_hidden_duplicate_overlapping_or_unrequested_boundaries_are_refused() {
    let format = GitObjectFormat::Sha1;
    for update in [
        ShallowUpdate {
            shallow: vec![oid(format, 9)],
            unshallow: vec![],
        },
        ShallowUpdate {
            shallow: vec![oid(format, 2), oid(format, 2)],
            unshallow: vec![],
        },
        ShallowUpdate {
            shallow: vec![oid(format, 3), oid(format, 2)],
            unshallow: vec![],
        },
        ShallowUpdate {
            shallow: vec![oid(format, 1)],
            unshallow: vec![oid(format, 1)],
        },
        ShallowUpdate {
            shallow: vec![],
            unshallow: vec![oid(format, 2)],
        },
        ShallowUpdate {
            shallow: vec![oid(GitObjectFormat::Sha256, 2)],
            unshallow: vec![],
        },
    ] {
        let mut repository = repository(format);
        repository.update = update;
        let mut legacy = legacy(UploadPackVersion::V1, WireLimits::default(), false);
        legacy_request(&mut legacy, &repository, false);
        assert!(legacy.push_packet(&Packet::Flush, &repository).is_err());
        let mut v2 = v2(WireLimits::default());
        v2_request(&mut v2, &repository);
        assert!(v2.push_packet(&Packet::Flush, &repository).is_err());
    }
}

#[test]
fn response_count_and_byte_limits_are_enforced_before_success() {
    for limits in [
        WireLimits {
            max_shallows: 1,
            ..WireLimits::default()
        },
        WireLimits {
            max_outbound_bytes: 8,
            ..WireLimits::default()
        },
    ] {
        let mut repository = repository(GitObjectFormat::Sha1);
        repository.update.shallow = vec![oid(repository.format, 2), oid(repository.format, 3)];
        let mut machine = v2(limits);
        v2_request(&mut machine, &repository);
        assert!(machine.push_packet(&Packet::Flush, &repository).is_err());
    }
}

#[test]
fn fragmented_legacy_requests_resolve_once_and_keep_boundaries_before_nak() {
    let repository = repository(GitObjectFormat::Sha256);
    let limits = WireLimits::default();
    let packets = [
        line(format!("want {}", oid(repository.format, 1))),
        line(format!("shallow {}", oid(repository.format, 1))),
        line("deepen 2"),
        Packet::Flush,
        line("done"),
    ];
    let bytes = encode_packets(&packets, &limits).unwrap();
    let mut machine = legacy(UploadPackVersion::V0, limits, false);
    let mut output = Vec::new();
    let mut events = Vec::new();
    for byte in bytes {
        let transition = machine.push_bytes(&[byte], &repository).unwrap();
        output.extend(transition.output);
        events.extend(transition.events);
    }
    assert_eq!(repository.calls.get(), 1);
    assert_eq!(
        output,
        vec![
            line(format!("shallow {}", oid(repository.format, 2))),
            line(format!("unshallow {}", oid(repository.format, 1))),
            Packet::Flush,
            line("NAK")
        ]
    );
    assert!(matches!(events.as_slice(), [WireEvent::PackRequested(_)]));
    machine.finish().unwrap();
}

#[test]
fn parser_only_mode_does_not_pretend_to_have_resolved_graph_updates() {
    let repository = repository(GitObjectFormat::Sha1);
    let limits = WireLimits::default();
    let caps = Capabilities::parse_v1(b"shallow", &limits).unwrap();
    let mut machine = LegacyUploadPack::new(UploadPackVersion::V0, caps, limits).unwrap();
    legacy_request(&mut machine, &repository, false);
    assert!(
        machine
            .push_packet(&Packet::Flush, &repository)
            .unwrap()
            .output
            .is_empty()
    );
    assert_eq!(repository.calls.get(), 0);
    assert!(
        matches!(machine.push_packet(&line("done"), &repository).unwrap().events.as_slice(), [WireEvent::PackRequested(request)] if request.deepen == Some(2))
    );
}
