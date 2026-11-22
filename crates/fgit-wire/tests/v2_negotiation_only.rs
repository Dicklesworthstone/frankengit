#![forbid(unsafe_code)]

// The pinned Git client's negotiate_using_fetch sends wait-for-done plus
// haves without wants. Acknowledgments disclose only this view's common set.
use std::cell::Cell;

use fgit_wire::visibility::{RefVisibility, VisibleUploadPackRepository};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, UploadPackRepository,
    V2UploadPack, WireError, WireEvent, WireLimits, encode_packets,
};

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    common: Vec<AnyGitOid>,
    polls: Cell<usize>,
    stop_at: Cell<usize>,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        let limits = WireLimits::default();
        let tip = oid(format, "11");
        let ancestor = oid(format, "22");
        Self {
            format,
            refs: vec![AdvertisedRef::new(tip, b"refs/heads/main", &limits).unwrap()],
            common: vec![tip, ancestor],
            polls: Cell::new(0),
            stop_at: Cell::new(usize::MAX),
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
        self.common.contains(&id)
    }

    fn is_common(&self, id: AnyGitOid) -> bool {
        self.common.contains(&id)
    }

    fn supports_ref_in_want(&self) -> bool {
        true
    }

    fn negotiation_checkpoint(&self) -> Result<(), WireError> {
        let next = self.polls.get() + 1;
        self.polls.set(next);
        if next >= self.stop_at.get() {
            Err(WireError::PackSourceRefused)
        } else {
            Ok(())
        }
    }
}

fn oid(format: GitObjectFormat, byte: &str) -> AnyGitOid {
    AnyGitOid::from_hex(format, &byte.repeat(format.digest_len())).unwrap()
}

fn data(text: impl Into<Vec<u8>>) -> Packet {
    Packet::Data(text.into())
}

fn capabilities(format: GitObjectFormat, features: &[u8]) -> Capabilities {
    let mut fetch = b"fetch=".to_vec();
    fetch.extend_from_slice(features);
    fetch.push(b'\n');
    Capabilities::parse_v2_advertisement(
        &[
            data(b"version 2\n"),
            data(fetch),
            data(format!("object-format={}\n", format.as_str())),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap()
}

fn machine(format: GitObjectFormat, http: bool, limits: WireLimits) -> V2UploadPack {
    let machine = V2UploadPack::new(
        capabilities(format, b"shallow filter ref-in-want wait-for-done"),
        limits,
    )
    .unwrap();
    if http {
        machine.with_stateless_http_rounds()
    } else {
        machine
    }
}

fn request(format: GitObjectFormat, arguments: &[Vec<u8>]) -> Vec<u8> {
    let mut packets = vec![
        data(b"command=fetch\n"),
        data(format!("object-format={}\n", format.as_str())),
        Packet::Delimiter,
    ];
    packets.extend(arguments.iter().cloned().map(Packet::Data));
    packets.push(Packet::Flush);
    encode_packets(&packets, &WireLimits::default()).unwrap()
}

fn have(id: AnyGitOid) -> Vec<u8> {
    format!("have {id}\n").into_bytes()
}

fn want(id: AnyGitOid) -> Vec<u8> {
    format!("want {id}\n").into_bytes()
}

fn ack(ids: &[AnyGitOid]) -> Vec<Packet> {
    let mut result = vec![data(b"acknowledgments\n")];
    if ids.is_empty() {
        result.push(data(b"NAK\n"));
    } else {
        result.extend(ids.iter().map(|id| data(format!("ACK {id}\n"))));
    }
    result.push(Packet::Flush);
    result
}

#[test]
fn have_only_rounds_ack_exact_visible_ids_once_in_request_order_in_both_hash_domains() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for http in [false, true] {
            let repository = Repository::new(format);
            let tip = oid(format, "11");
            let ancestor = oid(format, "22");
            let input = request(
                format,
                &[
                    have(oid(format, "33")),
                    have(ancestor),
                    b"wait-for-done\n".to_vec(),
                    have(tip),
                    have(ancestor),
                ],
            );
            let mut machine = machine(format, http, WireLimits::default());
            let response = machine.push_bytes(&input, &repository).unwrap();
            assert_eq!(response.output, ack(&[ancestor, tip]));
            assert!(response.events.is_empty(), "negotiation never selects a pack");
            assert!(machine.has_completed_negotiation());
            assert_eq!(machine.is_http_negotiation_complete(), http);
            assert_eq!(machine.is_awaiting_command(), !http);
            machine.finish().unwrap();
        }
    }
}

#[test]
fn empty_and_unknown_only_rounds_return_nak_without_ready_or_pack() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for http in [false, true] {
            for haves in [vec![], vec![have(oid(format, "33"))]] {
                let repository = Repository::new(format);
                let mut arguments = vec![b"wait-for-done\n".to_vec()];
                arguments.extend(haves);
                let mut machine = machine(format, http, WireLimits::default());
                let response = machine
                    .push_bytes(&request(format, &arguments), &repository)
                    .unwrap();
                assert_eq!(response.output, ack(&[]));
                assert!(response.events.is_empty());
                assert!(machine.has_completed_negotiation());
            }
        }
    }
}

#[test]
fn wait_for_done_suppresses_ready_even_when_every_wanted_tip_is_common() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for http in [false, true] {
            let repository = Repository::new(format);
            let tip = oid(format, "11");
            let arguments = [
                b"wait-for-done\n".to_vec(),
                want(tip),
                have(tip),
                b"deepen 1\n".to_vec(),
                b"filter blob:none\n".to_vec(),
            ];
            let mut waiting = machine(format, http, WireLimits::default()).with_shallow_updates();
            let response = waiting
                .push_bytes(&request(format, &arguments), &repository)
                .unwrap();
            assert_eq!(response.output, ack(&[tip]));
            assert!(response.events.is_empty());

            let mut completed = machine(format, http, WireLimits::default());
            let response = completed
                .push_bytes(
                    &request(
                        format,
                        &[
                            b"wait-for-done\n".to_vec(),
                            want(tip),
                            have(tip),
                            b"done\n".to_vec(),
                        ],
                    ),
                    &repository,
                )
                .unwrap();
            assert_eq!(response.output, vec![data(b"packfile\n")]);
            assert!(matches!(response.events.as_slice(), [WireEvent::PackRequested(_)]));
            assert!(!completed.has_completed_negotiation());
        }
    }
}

#[test]
fn persistent_rounds_discard_every_previous_fetch_argument_without_resetting_the_decoder() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let tip = oid(format, "11");
        let first = request(
            format,
            &[
                b"want-ref refs/heads/main\n".to_vec(),
                b"wait-for-done\n".to_vec(),
                have(tip),
                format!("shallow {tip}\n").into_bytes(),
                b"deepen 1\n".to_vec(),
                b"filter blob:none\n".to_vec(),
                b"thin-pack\n".to_vec(),
                b"include-tag\n".to_vec(),
                b"no-progress\n".to_vec(),
                b"ofs-delta\n".to_vec(),
            ],
        );
        let second = request(
            format,
            &[
                b"want-ref refs/heads/main\n".to_vec(),
                b"wait-for-done\n".to_vec(),
                have(oid(format, "33")),
            ],
        );
        let last = request(format, &[want(tip), b"done\n".to_vec()]);
        let mut stream = first;
        stream.extend_from_slice(&second);
        stream.extend_from_slice(&last);
        let baseline = machine(format, false, WireLimits::default())
            .push_bytes(&last, &repository)
            .unwrap();
        let mut expected = ack(&[tip]);
        expected.extend(ack(&[]));
        expected.extend(baseline.output);
        for width in [1, 2, 7, 31, stream.len()] {
            let mut machine = machine(
                format,
                false,
                WireLimits {
                    max_wants: 1,
                    ..WireLimits::default()
                },
            );
            let mut output = Vec::new();
            let mut events = Vec::new();
            for chunk in stream.chunks(width) {
                let response = machine.push_bytes(chunk, &repository).unwrap();
                output.extend(response.output);
                events.extend(response.events);
            }
            machine.finish().unwrap();
            assert_eq!(output, expected);
            assert_eq!(events, baseline.events);
            assert!(machine.has_completed_negotiation());
        }
    }
}

#[test]
fn http_rounds_remain_single_requests_and_connection_rounds_accept_explicit_session_end() {
    let format = GitObjectFormat::Sha1;
    let repository = Repository::new(format);
    let input = request(format, &[b"wait-for-done\n".to_vec(), have(oid(format, "11"))]);
    let mut http = machine(format, true, WireLimits::default());
    http.push_bytes(&input, &repository).unwrap();
    assert!(http.push_bytes(&input, &repository).is_err());

    let mut connection = machine(format, false, WireLimits::default());
    connection.push_bytes(&input, &repository).unwrap();
    let end = connection.push_packet(&Packet::Flush, &repository).unwrap();
    assert!(end.output.is_empty() && end.events.is_empty());
    assert!(connection.has_ended());
    assert!(connection.push_bytes(&input, &repository).is_err());
}

#[test]
fn missing_wants_unadvertised_wait_and_duplicate_controls_stay_typed_refusals() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for http in [false, true] {
            let repository = Repository::new(format);
            for arguments in [
                vec![have(oid(format, "11"))],
                vec![b"done\n".to_vec()],
                vec![b"wait-for-done\n".to_vec(), b"done\n".to_vec()],
            ] {
                let mut machine = machine(format, http, WireLimits::default());
                assert_eq!(
                    machine.push_bytes(&request(format, &arguments), &repository),
                    Err(WireError::MissingWant)
                );
                assert!(!machine.has_completed_negotiation());
            }
            let mut machine = machine(format, http, WireLimits::default());
            assert!(matches!(
                machine.push_bytes(
                    &request(format, &[b"wait-for-done\n".to_vec(), b"wait-for-done\n".to_vec()]),
                    &repository
                ),
                Err(WireError::MalformedRequestLine { .. })
            ));
            let mut unsupported = V2UploadPack::new(
                capabilities(format, b"shallow"),
                WireLimits::default(),
            )
            .unwrap();
            if http {
                unsupported = unsupported.with_stateless_http_rounds();
            }
            assert_eq!(
                unsupported.push_bytes(
                    &request(format, &[b"wait-for-done\n".to_vec()]),
                    &repository
                ),
                Err(WireError::UnknownCapability {
                    capability: b"wait-for-done".to_vec()
                })
            );
        }
    }
}

#[test]
fn have_and_response_limits_are_inclusive_and_refuse_without_completing_the_round() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for http in [false, true] {
            let repository = Repository::new(format);
            let tip = oid(format, "11");
            let input = request(
                format,
                &[b"wait-for-done\n".to_vec(), have(tip), have(tip)],
            );
            let exact = encode_packets(&ack(&[tip]), &WireLimits::default()).unwrap().len();
            let limits = WireLimits {
                max_haves: 1,
                max_outbound_bytes: exact,
                ..WireLimits::default()
            };
            let mut permitted = machine(format, http, limits.clone());
            assert_eq!(permitted.push_bytes(&input, &repository).unwrap().output, ack(&[tip]));
            let mut bounded = machine(format, http, WireLimits {
                max_outbound_bytes: exact - 1,
                ..limits.clone()
            });
            assert_eq!(
                bounded.push_bytes(&input, &repository),
                Err(WireError::OutboundBytesExceeded { limit: exact - 1 })
            );
            assert!(!bounded.has_completed_negotiation());
            let mut bounded = machine(format, http, limits);
            assert_eq!(
                bounded.push_bytes(
                    &request(format, &[b"wait-for-done\n".to_vec(), have(tip), have(oid(format, "22"))]),
                    &repository
                ),
                Err(WireError::TooManyObjectIds { field: "have", limit: 1 })
            );
            assert!(!bounded.has_completed_negotiation());
        }
    }
}

#[test]
fn every_live_checkpoint_in_known_unknown_and_empty_rounds_refuses_without_output() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for http in [false, true] {
            for arguments in [
                vec![b"wait-for-done\n".to_vec()],
                vec![b"wait-for-done\n".to_vec(), have(oid(format, "33"))],
                vec![b"wait-for-done\n".to_vec(), have(oid(format, "11")), have(oid(format, "22"))],
            ] {
                let input = request(format, &arguments);
                let repository = Repository::new(format);
                let mut permitted = machine(format, http, WireLimits::default());
                permitted.push_bytes(&input, &repository).unwrap();
                let polls = repository.polls.get();
                assert!(polls >= 3);
                for stop_at in 1..=polls {
                    let repository = Repository::new(format);
                    repository.stop_at.set(stop_at);
                    let mut stopped = machine(format, http, WireLimits::default());
                    assert_eq!(
                        stopped.push_bytes(&input, &repository),
                        Err(WireError::PackSourceRefused),
                        "checkpoint {stop_at}/{polls}"
                    );
                    assert!(!stopped.has_completed_negotiation());
                }
            }
        }
    }
}

#[test]
fn visibility_wrappers_preserve_the_original_negotiation_cancellation_scope() {
    let format = GitObjectFormat::Sha1;
    let repository = Repository::new(format);
    repository.stop_at.set(1);
    let visible = VisibleUploadPackRepository::new(&repository, &RefVisibility::default());
    let mut machine = machine(format, false, WireLimits::default());
    assert_eq!(
        machine.push_bytes(
            &request(format, &[b"wait-for-done\n".to_vec(), have(oid(format, "11"))]),
            &visible
        ),
        Err(WireError::PackSourceRefused)
    );
    assert_eq!(repository.polls.get(), 1);
}

#[test]
fn acknowledgment_header_respects_the_packet_limit_even_without_any_have() {
    let input = encode_packets(
        &[
            data(b"command=fetch\n"),
            Packet::Delimiter,
            data(b"wait-for-done\n"),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    let header_bytes = b"acknowledgments\n".len() + 4;
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for http in [false, true] {
            let repository = Repository::new(format);
            let mut permitted = machine(
                format,
                http,
                WireLimits {
                    max_packet_bytes: header_bytes,
                    ..WireLimits::default()
                },
            );
            assert_eq!(
                permitted.push_bytes(&input, &repository).unwrap().output,
                ack(&[])
            );
            let mut refused = machine(
                format,
                http,
                WireLimits {
                    max_packet_bytes: header_bytes - 1,
                    ..WireLimits::default()
                },
            );
            assert_eq!(
                refused.push_bytes(&input, &repository),
                Err(WireError::PacketTooLarge {
                    declared: header_bytes,
                    limit: header_bytes - 1
                })
            );
            assert!(!refused.has_completed_negotiation());
        }
    }
}
