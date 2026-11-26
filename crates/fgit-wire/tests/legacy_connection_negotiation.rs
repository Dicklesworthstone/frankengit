#![forbid(unsafe_code)]
//! Stateful v0/v1 fetch negotiation across real have-batch boundaries.
//!
//! The response expectations come from Git 2.54.0's get_common_commits and
//! find_common at 94f057755b7941b321fd11fec1b2e3ca5313a4e0. These constructed
//! SANS-I/O transcripts are not a claim that a stock client or socket ran.

use std::cell::Cell;

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, PackOptions,
    PackRequest, Packet, StatelessRpcUploadPack, Transition, UploadPackRepository,
    UploadPackVersion, WireError, WireEvent, WireLimits, encode_packets,
};

fn oid(format: GitObjectFormat, value: usize) -> AnyGitOid {
    let width = format.digest_len() * 2;
    AnyGitOid::from_hex(format, &format!("{value:0width$x}")).unwrap()
}

fn data(value: impl Into<Vec<u8>>) -> Packet {
    Packet::Data(value.into())
}

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    common: Vec<AnyGitOid>,
    live: Cell<bool>,
    common_reads: Cell<usize>,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        Self {
            format,
            refs: vec![
                AdvertisedRef::new(oid(format, 1), b"refs/heads/main", &WireLimits::default())
                    .unwrap(),
            ],
            common: (1..=3).map(|value| oid(format, value)).collect(),
            live: Cell::new(true),
            common_reads: Cell::new(0),
        }
    }

    fn have(&self, value: usize) -> Packet {
        data(format!("have {}\n", oid(self.format, value)))
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
        self.common_reads.set(self.common_reads.get() + 1);
        self.common.contains(&id)
    }

    fn negotiation_checkpoint(&self) -> Result<(), WireError> {
        if self.live.get() {
            Ok(())
        } else {
            Err(WireError::PackSourceRefused)
        }
    }
}

fn machine(repo: &Repository, version: UploadPackVersion, limits: WireLimits) -> LegacyUploadPack {
    let capabilities = format!(
        "multi_ack multi_ack_detailed no-done shallow object-format={}",
        repo.format.as_str(),
    );
    LegacyUploadPack::new(
        version,
        Capabilities::parse_v1(capabilities.as_bytes(), &limits).unwrap(),
        limits,
    )
    .unwrap()
}

fn start(machine: &mut LegacyUploadPack, repo: &Repository, capabilities: &str) {
    let suffix = if capabilities.is_empty() {
        String::new()
    } else {
        format!(" {capabilities}")
    };
    let want = data(format!("want {}{suffix}\n", repo.refs[0].oid));
    let selected = machine.push_packet(&want, repo).unwrap();
    assert!(selected.output.is_empty() && selected.events.is_empty());
    let boundary = machine.push_packet(&Packet::Flush, repo).unwrap();
    assert!(
        boundary.output.is_empty() && boundary.events.is_empty(),
        "the want boundary is not a have-batch NAK"
    );
}

fn pending(machine: &LegacyUploadPack) {
    assert!(!machine.is_complete());
    assert!(!machine.has_ended());
    assert!(!machine.is_http_negotiation_complete());
}

fn selected_pack(transition: &Transition) -> &PackRequest {
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
fn stock_sized_unknown_have_batches_get_replies_before_done() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for capabilities in ["", "multi_ack", "multi_ack_detailed"] {
                let mut request = machine(&repo, version, WireLimits::default());
                start(&mut request, &repo, capabilities);
                // Git 2.54 starts with 16 haves and pipelines the next window.
                // Each boundary must answer without waiting for the final done.
                for batch in 0..3 {
                    for value in 100 + batch * 16..116 + batch * 16 {
                        let have = request.push_packet(&repo.have(value), &repo).unwrap();
                        assert!(have.output.is_empty() && have.events.is_empty());
                    }
                    let boundary = request.push_packet(&Packet::Flush, &repo).unwrap();
                    assert_eq!(boundary.output, vec![data(b"NAK\n")]);
                    assert!(boundary.events.is_empty());
                    pending(&request);
                }
                let done = request.push_packet(&data(b"done\n"), &repo).unwrap();
                assert_eq!(done.output, vec![data(b"NAK\n")]);
                let selected = selected_pack(&done);
                assert_eq!(selected.version, version);
                assert_eq!(selected.wants, vec![oid(format, 1)]);
                assert_eq!(
                    selected.haves,
                    (100..148)
                        .map(|value| oid(format, value))
                        .collect::<Vec<_>>(),
                );
                assert!(request.is_complete());
            }
        }
    }
}

#[test]
fn plain_ack_is_immediate_once_and_never_repeated_at_done() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let mut request = machine(&repo, version, WireLimits::default());
            start(&mut request, &repo, "");
            let first = request.push_packet(&repo.have(2), &repo).unwrap();
            assert_eq!(
                first.output,
                vec![data(format!("ACK {}\n", oid(format, 2)))]
            );
            assert_eq!(first.events, vec![WireEvent::Common(oid(format, 2))]);
            pending(&request);
            for value in [2, 3, 3] {
                let later = request.push_packet(&repo.have(value), &repo).unwrap();
                assert!(later.output.is_empty());
                assert_eq!(later.events, vec![WireEvent::Common(oid(format, value))]);
                let boundary = request.push_packet(&Packet::Flush, &repo).unwrap();
                assert!(boundary.output.is_empty() && boundary.events.is_empty());
                pending(&request);
            }
            let done = request.push_packet(&data(b"done\n"), &repo).unwrap();
            assert!(done.output.is_empty(), "plain mode already sent its ACK");
            assert_eq!(
                selected_pack(&done).haves,
                vec![oid(format, 2), oid(format, 3)]
            );
        }
    }
}

#[test]
fn multi_ack_rounds_send_nak_and_finish_with_an_unqualified_ack() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for (capabilities, suffix) in
                [("multi_ack", "continue"), ("multi_ack_detailed", "common")]
            {
                let mut request = machine(&repo, version, WireLimits::default());
                start(&mut request, &repo, capabilities);
                for value in [2, 3] {
                    let have = request.push_packet(&repo.have(value), &repo).unwrap();
                    assert_eq!(
                        have.output,
                        vec![data(format!("ACK {} {suffix}\n", oid(format, value)))],
                    );
                    let boundary = request.push_packet(&Packet::Flush, &repo).unwrap();
                    assert_eq!(boundary.output, vec![data(b"NAK\n")]);
                    assert!(boundary.events.is_empty());
                    pending(&request);
                }
                let done = request.push_packet(&data(b"done\n"), &repo).unwrap();
                assert_eq!(done.output, vec![data(format!("ACK {}\n", oid(format, 3)))]);
                assert_eq!(
                    selected_pack(&done).haves,
                    vec![oid(format, 2), oid(format, 3)],
                );
            }
        }
    }
}

#[test]
fn no_done_requires_proven_readiness_instead_of_merely_a_flush_or_common_have() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for capabilities in ["no-done", "multi_ack no-done", "multi_ack_detailed no-done"] {
                let mut request = machine(&repo, version, WireLimits::default());
                start(&mut request, &repo, capabilities);
                for value in [None, Some(100), Some(2)] {
                    if let Some(value) = value {
                        let have = request.push_packet(&repo.have(value), &repo).unwrap();
                        assert!(
                            !have
                                .events
                                .iter()
                                .any(|event| { matches!(event, WireEvent::PackRequested(_)) })
                        );
                    }
                    let boundary = request.push_packet(&Packet::Flush, &repo).unwrap();
                    assert_eq!(
                        boundary.output,
                        if capabilities == "no-done" && value == Some(2) {
                            vec![]
                        } else {
                            vec![data(b"NAK\n")]
                        },
                    );
                    assert!(boundary.events.is_empty());
                    pending(&request);
                }
                let done = request.push_packet(&data(b"done\n"), &repo).unwrap();
                assert_eq!(
                    selected_pack(&done).haves,
                    vec![oid(format, 100), oid(format, 2)],
                );
            }
        }
    }
}

#[test]
fn negotiated_no_done_finishes_only_after_detailed_ready_and_authorized_wants() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for capabilities in [
                "no-done",
                "multi_ack no-done",
                "multi_ack_detailed",
                "multi_ack_detailed no-done",
            ] {
                let mut request = machine(&repo, version, WireLimits::default());
                start(&mut request, &repo, capabilities);
                request.push_packet(&repo.have(1), &repo).unwrap();
                let boundary = request.push_packet(&Packet::Flush, &repo).unwrap();
                let ready = capabilities.starts_with("multi_ack_detailed");
                let early = capabilities == "multi_ack_detailed no-done";
                let mut expected = Vec::new();
                if ready {
                    expected.push(data(format!("ACK {} ready\n", oid(format, 1))));
                }
                if capabilities != "no-done" {
                    expected.push(data(b"NAK\n"));
                }
                if early {
                    expected.push(data(format!("ACK {}\n", oid(format, 1))));
                    assert_eq!(selected_pack(&boundary).haves, vec![oid(format, 1)]);
                    assert!(request.is_complete());
                    assert!(request.push_packet(&data(b"done\n"), &repo).is_err());
                } else {
                    assert!(boundary.events.is_empty());
                    pending(&request);
                    let done = request.push_packet(&data(b"done\n"), &repo).unwrap();
                    assert_eq!(selected_pack(&done).haves, vec![oid(format, 1)]);
                }
                assert_eq!(boundary.output, expected);
            }

            let mut restricted = Repository::new(format);
            restricted.common = vec![oid(format, 2)];
            let mut request = machine(&restricted, version, WireLimits::default());
            start(&mut request, &restricted, "multi_ack_detailed no-done");
            for value in [1, 2] {
                request
                    .push_packet(&restricted.have(value), &restricted)
                    .unwrap();
            }
            let boundary = request.push_packet(&Packet::Flush, &restricted).unwrap();
            assert_eq!(boundary.output, vec![data(b"NAK\n")]);
            assert!(
                boundary.events.is_empty(),
                "a client claim is not common authority"
            );
            pending(&request);

            let mut two_wants = Repository::new(format);
            two_wants.refs.push(
                AdvertisedRef::new(oid(format, 3), b"refs/heads/topic", &WireLimits::default())
                    .unwrap(),
            );
            let mut request = machine(&two_wants, version, WireLimits::default());
            for (value, suffix) in [(1, " multi_ack_detailed no-done"), (3, "")] {
                request
                    .push_packet(
                        &data(format!("want {}{suffix}\n", oid(format, value))),
                        &two_wants,
                    )
                    .unwrap();
            }
            request.push_packet(&Packet::Flush, &two_wants).unwrap();
            request.push_packet(&two_wants.have(1), &two_wants).unwrap();
            let partial = request.push_packet(&Packet::Flush, &two_wants).unwrap();
            assert_eq!(partial.output, vec![data(b"NAK\n")]);
            assert!(
                partial.events.is_empty(),
                "one of two wants is insufficient"
            );
            pending(&request);
            request.push_packet(&two_wants.have(3), &two_wants).unwrap();
            let complete = request.push_packet(&Packet::Flush, &two_wants).unwrap();
            assert_eq!(
                selected_pack(&complete).wants,
                vec![oid(format, 1), oid(format, 3)],
            );
            assert!(request.is_complete());
        }
    }
}

#[test]
fn shallow_controls_keep_no_done_pending_until_explicit_done() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for control in [
                data(format!("shallow {}\n", oid(format, 1))),
                data(b"deepen 1\n"),
                data(b"deepen-since 1\n"),
                data(b"deepen-not refs/heads/main\n"),
            ] {
                let mut request = machine(&repo, version, WireLimits::default());
                request
                    .push_packet(
                        &data(format!(
                            "want {} multi_ack_detailed no-done\n",
                            oid(format, 1),
                        )),
                        &repo,
                    )
                    .unwrap();
                request.push_packet(&control, &repo).unwrap();
                request.push_packet(&Packet::Flush, &repo).unwrap();
                request.push_packet(&repo.have(1), &repo).unwrap();
                let boundary = request.push_packet(&Packet::Flush, &repo).unwrap();
                assert_eq!(boundary.output, vec![data(b"NAK\n")]);
                assert!(boundary.events.is_empty());
                pending(&request);
                let done = request.push_packet(&data(b"done\n"), &repo).unwrap();
                assert_eq!(done.output, vec![data(format!("ACK {}\n", oid(format, 1)))]);
                assert_eq!(selected_pack(&done).haves, vec![oid(format, 1)]);
            }
        }
    }
}

#[test]
fn have_limits_survive_rounds_and_duplicates_do_not_spend_the_budget() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let limits = WireLimits {
                max_haves: 17,
                ..WireLimits::default()
            };
            let mut request = machine(&repo, version, limits);
            start(&mut request, &repo, "");
            for value in 100..116 {
                request.push_packet(&repo.have(value), &repo).unwrap();
            }
            assert_eq!(
                request.push_packet(&Packet::Flush, &repo).unwrap().output,
                vec![data(b"NAK\n")],
            );
            request.push_packet(&repo.have(100), &repo).unwrap();
            request.push_packet(&repo.have(2), &repo).unwrap();
            let reads = repo.common_reads.get();
            assert_eq!(
                request.push_packet(&repo.have(116), &repo),
                Err(WireError::TooManyObjectIds {
                    field: "have",
                    limit: 17
                }),
            );
            assert_eq!(
                repo.common_reads.get(),
                reads,
                "refuse before authority lookup"
            );
            let boundary = request.push_packet(&Packet::Flush, &repo).unwrap();
            assert!(boundary.output.is_empty() && boundary.events.is_empty());
            let done = request.push_packet(&data(b"done\n"), &repo).unwrap();
            let mut expected: Vec<_> = (100..116).map(|value| oid(format, value)).collect();
            expected.push(oid(format, 2));
            assert_eq!(selected_pack(&done).haves, expected);
        }
    }
}

#[test]
fn expired_scope_refuses_before_wants_haves_empty_rounds_or_pack_handoff_change() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let mut request = machine(&repo, version, WireLimits::default());
            repo.live.set(false);
            assert_eq!(
                request.push_packet(&data(format!("want {}\n", oid(format, 1))), &repo),
                Err(WireError::PackSourceRefused),
            );
            repo.live.set(true);
            start(&mut request, &repo, "");
            let mut unchanged = request.clone();
            let reads = repo.common_reads.get();
            repo.live.set(false);
            for packet in [repo.have(2), repo.have(100), Packet::Flush, data(b"done\n")] {
                assert_eq!(
                    request.push_packet(&packet, &repo),
                    Err(WireError::PackSourceRefused),
                );
                pending(&request);
                assert_eq!(repo.common_reads.get(), reads);
            }
            repo.live.set(true);
            // Retry the exact packet after the injected scope refusal. Its
            // result must equal a machine that never saw any refused input.
            for packet in [repo.have(2), Packet::Flush, data(b"done\n")] {
                assert_eq!(
                    request.push_packet(&packet, &repo).unwrap(),
                    unchanged.push_packet(&packet, &repo).unwrap(),
                );
            }
            assert!(request.is_complete());

            let mut early = machine(&repo, version, WireLimits::default());
            start(&mut early, &repo, "multi_ack_detailed no-done");
            early.push_packet(&repo.have(1), &repo).unwrap();
            let mut unchanged = early.clone();
            repo.live.set(false);
            assert_eq!(
                early.push_packet(&Packet::Flush, &repo),
                Err(WireError::PackSourceRefused),
            );
            pending(&early);
            repo.live.set(true);
            let selected = early.push_packet(&Packet::Flush, &repo).unwrap();
            assert_eq!(
                selected,
                unchanged.push_packet(&Packet::Flush, &repo).unwrap(),
            );
            assert_eq!(selected_pack(&selected).haves, vec![oid(format, 1)]);
        }
    }
}

#[test]
fn format_refusal_does_not_install_multi_ack_or_no_done_flags() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let opposite = if format == GitObjectFormat::Sha1 {
            GitObjectFormat::Sha256
        } else {
            GitObjectFormat::Sha1
        };
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let mut request = machine(&repo, version, WireLimits::default());
            assert_eq!(
                request.push_packet(
                    &data(format!(
                        "want {} multi_ack_detailed no-done object-format={}\n",
                        oid(format, 1),
                        opposite.as_str(),
                    )),
                    &repo,
                ),
                Err(WireError::ObjectFormatMismatch {
                    expected: format,
                    observed: opposite
                }),
            );
            start(
                &mut request,
                &repo,
                &format!("object-format={}", format.as_str()),
            );
            let have = request.push_packet(&repo.have(1), &repo).unwrap();
            assert_eq!(have.output, vec![data(format!("ACK {}\n", oid(format, 1)))]);
            let boundary = request.push_packet(&Packet::Flush, &repo).unwrap();
            assert!(boundary.output.is_empty() && boundary.events.is_empty());
            pending(&request);
            let done = request.push_packet(&data(b"done\n"), &repo).unwrap();
            assert!(done.output.is_empty());
            assert_eq!(selected_pack(&done).options, PackOptions::NONE);
        }
    }
}

#[test]
fn fragmented_pipelined_rounds_keep_exact_outputs_and_handoff_order() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for (capabilities, suffix) in [
                ("", ""),
                ("multi_ack", " continue"),
                ("multi_ack_detailed", " common"),
            ] {
                let tail = if capabilities.is_empty() {
                    String::new()
                } else {
                    format!(" {capabilities}")
                };
                let mut packets = vec![
                    data(format!("want {}{tail}\n", oid(format, 1))),
                    Packet::Flush,
                ];
                for batch in 0..2 {
                    packets.extend((100 + batch * 16..116 + batch * 16).map(|v| repo.have(v)));
                    packets.push(Packet::Flush);
                }
                packets.extend([repo.have(2), Packet::Flush, repo.have(3), data(b"done\n")]);
                let limits = WireLimits::default();
                let bytes = encode_packets(&packets, &limits).unwrap();
                let mut expected = vec![
                    data(b"NAK\n"),
                    data(b"NAK\n"),
                    data(format!("ACK {}{suffix}\n", oid(format, 2))),
                ];
                if !capabilities.is_empty() {
                    expected.extend([
                        data(b"NAK\n"),
                        data(format!("ACK {}{suffix}\n", oid(format, 3))),
                        data(format!("ACK {}\n", oid(format, 3))),
                    ]);
                }
                let mut haves: Vec<_> = (100..132).map(|value| oid(format, value)).collect();
                haves.extend([oid(format, 2), oid(format, 3)]);
                for width in [1, 2, 3, 4, 7, 37, bytes.len()] {
                    let mut request = machine(&repo, version, limits.clone());
                    let mut result = Transition {
                        output: Vec::new(),
                        events: Vec::new(),
                    };
                    for chunk in bytes.chunks(width) {
                        let transition = request.push_bytes(chunk, &repo).unwrap();
                        result.output.extend(transition.output);
                        result.events.extend(transition.events);
                    }
                    request.finish().unwrap();
                    assert!(request.is_complete());
                    assert_eq!(result.output, expected);
                    assert_eq!(selected_pack(&result).haves, haves);
                    assert_eq!(
                        result.events[..2],
                        [
                            WireEvent::Common(oid(format, 2)),
                            WireEvent::Common(oid(format, 3))
                        ],
                    );
                }
            }
        }
    }
}

#[test]
fn connection_and_http_round_boundaries_keep_distinct_completion_states() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let mut connection = machine(&repo, version, WireLimits::default());
            start(&mut connection, &repo, "");
            let boundary = connection.push_packet(&Packet::Flush, &repo).unwrap();
            assert_eq!(boundary.output, vec![data(b"NAK\n")]);
            pending(&connection);
            connection.finish().unwrap(); // Complete packets do not imply a complete session.
            assert!(connection.finish_stateless_http_round().is_err());
            assert!(connection.push_packet(&data(b"done\n"), &repo).is_ok());

            let mut http =
                machine(&repo, version, WireLimits::default()).with_stateless_http_rounds();
            start(&mut http, &repo, "");
            assert!(http.finish_stateless_http_round().is_err());
            let boundary = http.push_packet(&Packet::Flush, &repo).unwrap();
            assert_eq!(boundary.output, vec![data(b"NAK\n")]);
            assert!(boundary.events.is_empty());
            assert!(!http.is_complete() && http.is_http_negotiation_complete());
            http.finish_stateless_http_round().unwrap();
            assert!(http.push_packet(&data(b"done\n"), &repo).is_err());
        }
    }
}

#[test]
fn stateless_outer_flush_never_invents_an_inner_have_boundary_or_done() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for value in [1, 100] {
                let limits = WireLimits::default();
                let prefix = vec![
                    data(format!(
                        "want {} multi_ack_detailed no-done\n",
                        oid(format, 1),
                    )),
                    Packet::Flush,
                    repo.have(value),
                ];
                let inner = encode_packets(&prefix, &limits).unwrap();
                let outer = encode_packets(&[data(inner), Packet::Flush], &limits).unwrap();
                let mut incomplete = StatelessRpcUploadPack::new(
                    machine(&repo, version, limits.clone()),
                    limits.clone(),
                )
                .unwrap();
                assert!(
                    incomplete.push_bytes(&outer, &repo).is_err(),
                    "an outer flush is not a missing inner flush, even when no-done is ready"
                );

                let mut complete = prefix;
                complete.push(Packet::Flush);
                let inner = encode_packets(&complete, &limits).unwrap();
                let payload = encode_packets(&[data(inner)], &limits).unwrap();
                let mut framed = StatelessRpcUploadPack::new(
                    machine(&repo, version, limits.clone()),
                    limits.clone(),
                )
                .unwrap();
                let transition = framed.push_bytes(&payload, &repo).unwrap();
                assert!(
                    framed.finish().is_err(),
                    "outer termination is still required"
                );
                let boundary = framed.push_bytes(b"0000", &repo).unwrap();
                assert!(boundary.output.is_empty() && boundary.events.is_empty());
                framed.finish().unwrap();
                if value == 1 {
                    assert_eq!(selected_pack(&transition).haves, vec![oid(format, 1)]);
                } else {
                    assert_eq!(transition.output, vec![data(b"NAK\n")]);
                    assert!(transition.events.is_empty());
                }
                assert!(framed.push_bytes(b"0000", &repo).is_err());
            }
        }
    }
}

#[test]
fn malformed_controls_and_packets_after_done_keep_their_refusals() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let mut request = machine(&repo, version, WireLimits::default());
            start(&mut request, &repo, "");
            for packet in [Packet::Delimiter, Packet::ResponseEnd] {
                assert!(request.push_packet(&packet, &repo).is_err());
                pending(&request);
            }
            selected_pack(&request.push_packet(&data(b"done\n"), &repo).unwrap());
            for packet in [Packet::Flush, repo.have(2), data(b"done\n")] {
                assert!(request.push_packet(&packet, &repo).is_err());
                assert!(request.is_complete());
            }
        }
    }
}
