#![forbid(unsafe_code)]
//! Ordered-set negotiation, including a complete default-sized have set.
//! These are native parser/transcript oracles, not a stock-Git transport lane.

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, PackRequest, Packet,
    Transition, UploadPackRepository, UploadPackVersion, V2UploadPack, WireError, WireEvent,
    WireLimits, encode_packets,
};

fn oid(format: GitObjectFormat, value: usize) -> AnyGitOid {
    let width = format.digest_len() * 2;
    AnyGitOid::from_hex(format, &format!("{value:0width$x}")).unwrap()
}

fn data(line: impl Into<Vec<u8>>) -> Packet {
    Packet::Data(line.into())
}

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    common: Vec<AnyGitOid>,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        Self {
            format,
            refs: (1..=3)
                .map(|value| {
                    AdvertisedRef::new(
                        oid(format, value),
                        format!("refs/heads/{value}").as_bytes(),
                        &WireLimits::default(),
                    )
                    .unwrap()
                })
                .collect(),
            common: Vec::new(),
        }
    }
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

    fn is_common(&self, id: AnyGitOid) -> bool {
        self.common.contains(&id)
    }
}

enum Machine {
    Legacy(LegacyUploadPack),
    V2(V2UploadPack),
}

impl Machine {
    fn new(version: UploadPackVersion, limits: WireLimits, http: bool) -> Self {
        if version == UploadPackVersion::V2 {
            let capabilities = Capabilities::parse_v2_advertisement(
                &[
                    data(b"version 2\n"),
                    data(b"fetch=shallow wait-for-done\n"),
                    Packet::Flush,
                ],
                &limits,
            )
            .unwrap();
            let mut machine = V2UploadPack::new(capabilities, limits).unwrap();
            if http {
                machine = machine.with_stateless_http_rounds();
            }
            Self::V2(machine)
        } else {
            let capabilities =
                Capabilities::parse_v1(b"multi_ack_detailed no-done shallow deepen-not", &limits)
                    .unwrap();
            let mut machine = LegacyUploadPack::new(version, capabilities, limits).unwrap();
            if http {
                machine = machine.with_stateless_http_rounds();
            }
            Self::Legacy(machine)
        }
    }

    fn push(&mut self, packet: &Packet, repository: &Repository) -> Result<Transition, WireError> {
        match self {
            Self::Legacy(machine) => machine.push_packet(packet, repository),
            Self::V2(machine) => machine.push_packet(packet, repository),
        }
    }

    fn begin(&mut self, repository: &Repository) {
        if matches!(self, Self::V2(_)) {
            self.push(&data(b"command=fetch\n"), repository).unwrap();
            self.push(&Packet::Delimiter, repository).unwrap();
        }
    }

    fn transcript(&mut self, bytes: &[u8], repository: &Repository, chunk: usize) -> Transition {
        let mut result = Transition {
            output: Vec::new(),
            events: Vec::new(),
        };
        for part in bytes.chunks(chunk) {
            let transition = match self {
                Self::Legacy(machine) => machine.push_bytes(part, repository),
                Self::V2(machine) => machine.push_bytes(part, repository),
            }
            .expect("complete bounded request fragment");
            result.output.extend(transition.output);
            result.events.extend(transition.events);
        }
        match self {
            Self::Legacy(machine) => machine.finish(),
            Self::V2(machine) => machine.finish(),
        }
        .expect("no truncated packet");
        result
    }
}

fn pack_request(transition: &Transition) -> &PackRequest {
    let requests: Vec<_> = transition
        .events
        .iter()
        .filter_map(|event| match event {
            WireEvent::PackRequested(request) => Some(request),
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 1, "exactly one pack handoff");
    requests[0]
}

#[test]
fn default_sized_have_sets_preserve_exact_wire_and_pack_order_in_every_protocol() {
    let limits = WireLimits {
        max_wants: 3,
        ..WireLimits::default()
    };
    let count = limits.max_haves;
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        // A permutation with a long shared byte prefix, rather than OID order.
        let haves: Vec<_> = (0..count)
            .map(|index| oid(format, (index * 40_503) % count + 1))
            .collect();
        let duplicates = [
            haves[count - 1],
            haves[0],
            haves[count / 2],
            haves[count - 1],
        ];
        let mut repository = Repository::new(format);
        repository.common = vec![haves[0], haves[count / 2], haves[count - 1]];
        for version in [
            UploadPackVersion::V0,
            UploadPackVersion::V1,
            UploadPackVersion::V2,
        ] {
            let mut packets = Vec::new();
            if version == UploadPackVersion::V2 {
                packets.extend([data(b"command=fetch\n"), Packet::Delimiter]);
            }
            for (index, value) in [3, 1, 2, 3, 1].into_iter().enumerate() {
                let capabilities = if index == 0 && version != UploadPackVersion::V2 {
                    " multi_ack_detailed"
                } else {
                    ""
                };
                packets.push(data(format!("want {}{capabilities}\n", oid(format, value))));
            }
            if version != UploadPackVersion::V2 {
                packets.push(Packet::Flush);
            }
            for have in haves.iter().chain(&duplicates) {
                packets.push(data(format!("have {have}\n")));
            }
            if version == UploadPackVersion::V2 {
                packets.push(Packet::Flush);
            } else {
                packets.push(data(b"done\n"));
            }
            let bytes = encode_packets(&packets, &limits).unwrap();
            let mut machine = Machine::new(version, limits.clone(), false);
            let result = machine.transcript(&bytes, &repository, 997);
            let request = pack_request(&result);
            assert_eq!(request.version, version);
            assert_eq!(
                request.wants,
                [oid(format, 3), oid(format, 1), oid(format, 2)]
            );
            assert_eq!(request.haves, haves);
            assert!(request.shallows.is_empty() && request.deepen_not.is_empty());
            let expected = if version == UploadPackVersion::V2 {
                let mut expected = vec![data(b"acknowledgments\n")];
                expected.extend(
                    repository
                        .common
                        .iter()
                        .map(|id| data(format!("ACK {id}\n"))),
                );
                expected.extend([data(b"ready\n"), Packet::Delimiter, data(b"packfile\n")]);
                expected
            } else {
                let mut expected = vec![data(b"NAK\n")];
                expected.extend(
                    repository
                        .common
                        .iter()
                        .chain(&duplicates)
                        .map(|id| data(format!("ACK {id} common\n"))),
                );
                expected.push(data(format!("ACK {} ready\n", duplicates[3])));
                let common_events: Vec<_> = result
                    .events
                    .iter()
                    .filter_map(|event| match event {
                        WireEvent::Common(id) => Some(*id),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    common_events,
                    repository
                        .common
                        .iter()
                        .chain(&duplicates)
                        .copied()
                        .collect::<Vec<_>>()
                );
                expected
            };
            assert_eq!(result.output, expected);
            // Different chunk boundaries and freshly randomized membership
            // tables must produce byte-identical output and ordered events.
            assert_eq!(
                Machine::new(version, limits.clone(), false).transcript(&bytes, &repository, 4_093),
                result
            );
        }
    }
}

#[test]
fn duplicate_limits_remain_per_field_and_a_refused_insert_does_not_poison_membership() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        for version in [
            UploadPackVersion::V0,
            UploadPackVersion::V1,
            UploadPackVersion::V2,
        ] {
            for field in ["want", "have", "shallow", "deepen-not"] {
                let limits = WireLimits {
                    max_wants: 2,
                    max_haves: 2,
                    max_shallows: 2,
                    ..WireLimits::default()
                };
                let mut machine = Machine::new(version, limits, false);
                machine.begin(&repository);
                if field != "want" {
                    machine
                        .push(&data(format!("want {}\n", oid(format, 1))), &repository)
                        .unwrap();
                }
                if field == "have" && version != UploadPackVersion::V2 {
                    machine.push(&Packet::Flush, &repository).unwrap();
                }
                let packet = |value| {
                    let identity = if field == "deepen-not" {
                        format!("refs/heads/{value}")
                    } else {
                        oid(format, value).to_string()
                    };
                    data(format!("{field} {identity}\n"))
                };
                for value in [2, 1, 2, 1] {
                    machine
                        .push(&packet(value), &repository)
                        .expect("two distinct identities");
                }
                for _ in 0..2 {
                    assert_eq!(
                        machine.push(&packet(3), &repository),
                        Err(WireError::TooManyObjectIds { field, limit: 2 })
                    );
                }
                machine
                    .push(&packet(1), &repository)
                    .expect("duplicate remains admissible");
                if field != "have" && version != UploadPackVersion::V2 {
                    machine.push(&Packet::Flush, &repository).unwrap();
                }
                let result = if version == UploadPackVersion::V2 {
                    machine.push(&data(b"done\n"), &repository).unwrap();
                    machine.push(&Packet::Flush, &repository).unwrap()
                } else {
                    machine.push(&data(b"done\n"), &repository).unwrap()
                };
                let request = pack_request(&result);
                let actual = match field {
                    "want" => &request.wants,
                    "have" => &request.haves,
                    "shallow" => &request.shallows,
                    "deepen-not" => &request.deepen_not,
                    _ => unreachable!(),
                };
                assert_eq!(actual, &[oid(format, 2), oid(format, 1)]);
            }
        }
    }
}

#[test]
fn duplicate_wants_still_require_current_repository_permission() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let denied = Repository {
            refs: Vec::new(),
            ..Repository::new(format)
        };
        let wanted = oid(format, 1);
        for version in [
            UploadPackVersion::V0,
            UploadPackVersion::V1,
            UploadPackVersion::V2,
        ] {
            let mut machine = Machine::new(version, WireLimits::default(), false);
            machine.begin(&repository);
            let packet = data(format!("want {wanted}\n"));
            machine.push(&packet, &repository).unwrap();
            let expected = if version == UploadPackVersion::V2 {
                WireError::WantNotReachable { oid: wanted }
            } else {
                WireError::WantNotAdvertised { oid: wanted }
            };
            assert_eq!(machine.push(&packet, &denied), Err(expected));
        }
    }
}

#[test]
fn http_readiness_needs_common_authority_even_when_every_want_is_in_the_have_index() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for version in [
            UploadPackVersion::V0,
            UploadPackVersion::V1,
            UploadPackVersion::V2,
        ] {
            for all_common in [false, true] {
                let mut repository = Repository::new(format);
                repository.common = if all_common {
                    vec![oid(format, 1), oid(format, 2)]
                } else {
                    vec![oid(format, 1)]
                };
                let mut machine = Machine::new(version, WireLimits::default(), true);
                machine.begin(&repository);
                let caps = if version == UploadPackVersion::V2 {
                    ""
                } else {
                    " multi_ack_detailed no-done"
                };
                machine
                    .push(
                        &data(format!("want {}{caps}\n", oid(format, 2))),
                        &repository,
                    )
                    .unwrap();
                machine
                    .push(&data(format!("want {}\n", oid(format, 1))), &repository)
                    .unwrap();
                if version != UploadPackVersion::V2 {
                    machine.push(&Packet::Flush, &repository).unwrap();
                }
                for value in [2, 1, 2] {
                    machine
                        .push(&data(format!("have {}\n", oid(format, value))), &repository)
                        .unwrap();
                }
                let result = machine.push(&Packet::Flush, &repository).unwrap();
                assert_eq!(
                    result
                        .events
                        .iter()
                        .any(|event| matches!(event, WireEvent::PackRequested(_))),
                    all_common
                );
                if all_common {
                    let request = pack_request(&result);
                    assert_eq!(request.haves, [oid(format, 2), oid(format, 1)]);
                }
            }
        }
    }
}
