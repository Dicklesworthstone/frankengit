#![forbid(unsafe_code)]
//! Regression for the repeated prefix emitted by Git 2.54.0 during unshallow.
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, UploadPackRepository,
    V2UploadPack, WireError, WireEvent, WireLimits, encode_packets,
};

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
}
impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }
    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }
    fn contains_want(&self, id: AnyGitOid) -> bool {
        self.refs.iter().any(|reference| reference.oid == id)
    }
    fn is_common(&self, _: AnyGitOid) -> bool {
        false
    }
}
fn oid(format: GitObjectFormat, byte: u8) -> AnyGitOid {
    AnyGitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}
fn line(value: impl AsRef<str>) -> Packet {
    Packet::Data(format!("{}\n", value.as_ref()).into_bytes())
}
fn repository(format: GitObjectFormat) -> Repository {
    Repository {
        format,
        refs: [
            ("refs/heads/private", 2),
            ("refs/heads/public", 1),
            ("refs/tags/release", 3),
        ]
        .into_iter()
        .map(|(name, id)| {
            AdvertisedRef::new(oid(format, id), name.as_bytes(), &WireLimits::default()).unwrap()
        })
        .collect(),
    }
}
fn machine(format: GitObjectFormat, limits: WireLimits) -> V2UploadPack {
    let caps = Capabilities::parse_v2_advertisement(
        &[
            line("version 2"),
            line("ls-refs"),
            line(format!("object-format={}", format.as_str())),
            Packet::Flush,
        ],
        &limits,
    )
    .unwrap();
    V2UploadPack::new(caps, limits).unwrap()
}
fn start(machine: &mut V2UploadPack, repository: &Repository) {
    for packet in [
        line("command=ls-refs"),
        line(format!("object-format={}", repository.format.as_str())),
        Packet::Delimiter,
    ] {
        let transition = machine.push_packet(&packet, repository).unwrap();
        assert!(transition.output.is_empty() && transition.events.is_empty());
    }
}
fn expected(repository: &Repository, name: &str) -> Vec<Packet> {
    let reference = repository
        .refs
        .iter()
        .find(|reference| reference.name == name.as_bytes())
        .unwrap();
    vec![line(format!("{} {name}", reference.oid)), Packet::Flush]
}

#[test]
fn pinned_unshallow_prefix_sequence_is_idempotent_at_every_input_fragment_size() {
    let prefixes = [
        "refs/heads/public",
        "refs/refs/heads/public",
        "refs/tags/refs/heads/public",
        "refs/heads/refs/heads/public",
        "refs/remotes/refs/heads/public",
        "refs/remotes/refs/heads/public/HEAD",
        "refs/heads/public",
        "HEAD",
    ];
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        let mut packets = vec![
            line("command=ls-refs"),
            line(format!("object-format={}", format.as_str())),
            Packet::Delimiter,
            line("peel"),
            line("symrefs"),
        ];
        packets.extend(
            prefixes
                .iter()
                .map(|prefix| line(format!("ref-prefix {prefix}"))),
        );
        packets.push(Packet::Flush);
        let bytes = encode_packets(&packets, &WireLimits::default()).unwrap();
        for chunk_size in [1, 2, 3, 7, 31, bytes.len()] {
            let mut machine = machine(format, WireLimits::default());
            let (mut output, mut events) = (Vec::new(), Vec::new());
            for chunk in bytes.chunks(chunk_size) {
                let transition = machine.push_bytes(chunk, &repository).unwrap();
                output.extend(transition.output);
                events.extend(transition.events);
            }
            assert_eq!(
                output,
                expected(&repository, "refs/heads/public"),
                "duplicates neither broaden nor duplicate disclosure"
            );
            let [
                WireEvent::LsRefs {
                    prefixes: observed,
                    symrefs,
                    peel,
                    unborn,
                },
            ] = events.as_slice()
            else {
                panic!("one complete ls-refs event required");
            };
            assert_eq!(
                *observed,
                prefixes
                    .iter()
                    .map(|prefix| prefix.as_bytes().to_vec())
                    .collect::<Vec<_>>()
            );
            assert!(*symrefs && *peel && !*unborn);
        }
    }
}

#[test]
fn duplicate_arguments_still_consume_the_existing_inclusive_request_bound() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        let limits = WireLimits {
            max_ref_prefixes: 2,
            ..WireLimits::default()
        };
        let mut allowed = machine(format, limits.clone());
        start(&mut allowed, &repository);
        for _ in 0..2 {
            allowed
                .push_packet(&line("ref-prefix refs/heads/public"), &repository)
                .unwrap();
        }
        assert_eq!(
            allowed
                .push_packet(&Packet::Flush, &repository)
                .unwrap()
                .output,
            expected(&repository, "refs/heads/public")
        );
        for extra in ["refs/heads/public", "refs/tags/"] {
            let mut refused = machine(format, limits.clone());
            start(&mut refused, &repository);
            for _ in 0..2 {
                refused
                    .push_packet(&line("ref-prefix refs/heads/public"), &repository)
                    .unwrap();
            }
            assert_eq!(
                refused.push_packet(&line(format!("ref-prefix {extra}")), &repository),
                Err(WireError::TooManyObjectIds {
                    field: "ref-prefix",
                    limit: 2
                })
            );
        }
    }
}

#[test]
fn repeated_prefixes_and_their_budget_reset_between_commands() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        let mut machine = machine(
            format,
            WireLimits {
                max_ref_prefixes: 2,
                ..WireLimits::default()
            },
        );
        for prefix in [
            "refs/heads/public",
            "refs/tags/release",
            "refs/heads/public",
        ] {
            start(&mut machine, &repository);
            for _ in 0..2 {
                machine
                    .push_packet(&line(format!("ref-prefix {prefix}")), &repository)
                    .unwrap();
            }
            let transition = machine.push_packet(&Packet::Flush, &repository).unwrap();
            assert_eq!(transition.output, expected(&repository, prefix));
            assert_eq!(transition.events.len(), 1);
        }
    }
}

#[test]
fn repeated_prefixes_do_not_bypass_framing_or_response_limits() {
    let format = GitObjectFormat::Sha1;
    let repository = repository(format);
    let prefix = line("ref-prefix refs/heads/public");
    let bytes = encode_packets(&[prefix.clone(), prefix.clone()], &WireLimits::default()).unwrap();
    let mut permitted = machine(
        format,
        WireLimits {
            max_packets_per_push: 2,
            ..WireLimits::default()
        },
    );
    start(&mut permitted, &repository);
    permitted.push_bytes(&bytes, &repository).unwrap();
    assert_eq!(
        permitted
            .push_packet(&Packet::Flush, &repository)
            .unwrap()
            .output,
        expected(&repository, "refs/heads/public")
    );
    let mut refused = machine(
        format,
        WireLimits {
            max_packets_per_push: 1,
            ..WireLimits::default()
        },
    );
    start(&mut refused, &repository);
    assert_eq!(
        refused.push_bytes(&bytes, &repository),
        Err(WireError::PacketCountExceeded { limit: 1 })
    );
    let mut response_bounded = machine(
        format,
        WireLimits {
            max_outbound_bytes: 4,
            ..WireLimits::default()
        },
    );
    start(&mut response_bounded, &repository);
    for _ in 0..2 {
        response_bounded.push_packet(&prefix, &repository).unwrap();
    }
    assert_eq!(
        response_bounded.push_packet(&Packet::Flush, &repository),
        Err(WireError::OutboundBytesExceeded { limit: 4 })
    );
}

#[test]
fn capabilities_are_unique_within_one_command_but_can_recur_in_the_next() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        let mut machine = machine(format, WireLimits::default());
        let format_line = line(format!("object-format={}", format.as_str()));
        for name in ["refs/heads/public", "refs/tags/release"] {
            machine
                .push_packet(&line("command=ls-refs"), &repository)
                .unwrap();
            machine.push_packet(&format_line, &repository).unwrap();
            assert_eq!(
                machine.push_packet(&format_line, &repository),
                Err(WireError::DuplicateCapability {
                    name: b"object-format".to_vec()
                })
            );
            machine
                .push_packet(&Packet::Delimiter, &repository)
                .unwrap();
            machine
                .push_packet(&line(format!("ref-prefix {name}")), &repository)
                .unwrap();
            let complete = machine.push_packet(&Packet::Flush, &repository).unwrap();
            assert_eq!(complete.output, expected(&repository, name));
            assert_eq!(complete.events.len(), 1);
        }
    }
}
