#![forbid(unsafe_code)]
//! Ordinary v2 fetch rounds must discover a common cut before selecting a pack.
//!
//! Expectations follow Git 2.54.0's send_acks and ok_to_give_up at
//! 94f057755b7941b321fd11fec1b2e3ca5313a4e0. These native SANS-I/O transcripts
//! do not claim a stock-client socket run or a full ancestry readiness oracle.

use std::cell::Cell;

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackOptions, PackRequest, Packet,
    Transition, UploadPackRepository, V2UploadPack, WireError, WireEvent, WireLimits,
    encode_packets,
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
    shallow_reads: Cell<usize>,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        Self {
            format,
            refs: [(1, "refs/heads/main"), (3, "refs/heads/topic")]
                .into_iter()
                .map(|(value, name)| {
                    AdvertisedRef::new(oid(format, value), name.as_bytes(), &WireLimits::default())
                        .unwrap()
                })
                .collect(),
            common: (1..=3).map(|value| oid(format, value)).collect(),
            live: Cell::new(true),
            shallow_reads: Cell::new(0),
        }
    }

    fn want(&self, value: usize) -> Packet {
        data(format!("want {}\n", oid(self.format, value)))
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
        self.common.contains(&id)
    }

    fn negotiation_checkpoint(&self) -> Result<(), WireError> {
        if self.live.get() {
            Ok(())
        } else {
            Err(WireError::PackSourceRefused)
        }
    }

    fn supports_ref_in_want(&self) -> bool {
        true
    }

    fn supports_shallow(&self) -> bool {
        true
    }

    fn shallow_update(
        &self,
        _: &PackRequest,
    ) -> Result<fgit_wire::closure::ShallowUpdate, WireError> {
        self.shallow_reads.set(self.shallow_reads.get() + 1);
        // Negotiation-only output must not invoke the pack's shallow provider.
        Err(WireError::PackSourceRefused)
    }
}

fn machine(repo: &Repository, http: bool) -> V2UploadPack {
    let limits = WireLimits::default();
    let capabilities = Capabilities::parse_v2_advertisement(
        &[
            data(b"version 2\n"),
            data(b"fetch=shallow filter ref-in-want wait-for-done\n"),
            data(format!("object-format={}\n", repo.format.as_str())),
            Packet::Flush,
        ],
        &limits,
    )
    .unwrap();
    let request = V2UploadPack::new(capabilities, limits)
        .unwrap()
        .with_shallow_updates();
    if http {
        request.with_stateless_http_rounds()
    } else {
        request
    }
}

fn request(repo: &Repository, arguments: &[Packet]) -> Vec<Packet> {
    let mut packets = vec![
        data(b"command=fetch\n"),
        data(format!("object-format={}\n", repo.format.as_str())),
        Packet::Delimiter,
    ];
    packets.extend_from_slice(arguments);
    packets.push(Packet::Flush);
    packets
}

fn submit(machine: &mut V2UploadPack, repo: &Repository, arguments: &[Packet]) -> Transition {
    let bytes = encode_packets(&request(repo, arguments), &WireLimits::default()).unwrap();
    machine.push_bytes(&bytes, repo).unwrap()
}

fn acknowledgments(ids: &[AnyGitOid]) -> Vec<Packet> {
    let mut output = vec![data(b"acknowledgments\n")];
    if ids.is_empty() {
        output.push(data(b"NAK\n"));
    } else {
        output.extend(ids.iter().map(|id| data(format!("ACK {id}\n"))));
    }
    output.push(Packet::Flush);
    output
}

fn selected(transition: &Transition) -> &PackRequest {
    let [WireEvent::PackRequested(request)] = transition.events.as_slice() else {
        panic!("exactly one final pack handoff is required");
    };
    request
}

fn assert_round(machine: &V2UploadPack, http: bool) {
    assert!(machine.has_completed_negotiation());
    assert_eq!(machine.is_http_negotiation_complete(), http);
    assert_eq!(machine.is_awaiting_command(), !http);
    assert!(!machine.has_ended());
}

#[test]
fn unknown_sixteen_have_batch_can_find_common_history_in_later_ordinary_rounds() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let mut machine = machine(&repo, false);
        let mut first = vec![repo.want(1)];
        first.extend((100..116).map(|value| repo.have(value)));
        let response = submit(&mut machine, &repo, &first);
        assert_eq!(response.output, acknowledgments(&[]));
        assert!(
            response.events.is_empty(),
            "an unknown first window must not start a full pack"
        );
        assert_round(&machine, false);

        let response = submit(
            &mut machine,
            &repo,
            &[repo.want(1), repo.have(200), repo.have(2), repo.have(2)],
        );
        assert_eq!(response.output, acknowledgments(&[oid(format, 2)]));
        assert!(
            response.events.is_empty(),
            "an unrelated common ID does not prove a cut"
        );
        assert_round(&machine, false);

        let response = submit(
            &mut machine,
            &repo,
            &[repo.want(1), repo.have(2), data(b"done\n")],
        );
        assert_eq!(response.output, vec![data(b"packfile\n")]);
        assert_eq!(selected(&response).wants, vec![oid(format, 1)]);
        assert_eq!(
            selected(&response).haves,
            vec![oid(format, 2)],
            "only this independent final request's haves select the pack",
        );
    }
}

#[test]
fn readiness_requires_every_wanted_tip_to_be_independently_common_on_both_carriers() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for http in [false, true] {
            for haves in [vec![100], vec![2], vec![1], vec![1, 3]] {
                for permit_last in [false, true] {
                    let mut repo = Repository::new(format);
                    if !permit_last {
                        repo.common.retain(|id| *id != oid(format, 3));
                    }
                    let mut machine = machine(&repo, http);
                    let mut arguments = vec![repo.want(1), repo.want(3)];
                    arguments.extend(haves.iter().map(|value| repo.have(*value)));
                    let response = submit(&mut machine, &repo, &arguments);
                    let common: Vec<_> = haves
                        .iter()
                        .map(|value| oid(format, *value))
                        .filter(|id| repo.common.contains(id))
                        .collect();
                    let mut expected = acknowledgments(&common);
                    if haves == vec![1, 3] && permit_last {
                        expected.pop();
                        expected.extend([data(b"ready\n"), Packet::Delimiter, data(b"packfile\n")]);
                        assert_eq!(
                            selected(&response).wants,
                            vec![oid(format, 1), oid(format, 3)]
                        );
                    } else {
                        assert!(response.events.is_empty());
                        assert_round(&machine, http);
                    }
                    assert_eq!(response.output, expected);
                }
            }
        }
    }
}

#[test]
fn initial_clone_and_explicit_done_still_select_the_requested_pack_directly() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for http in [false, true] {
            for (have, done) in [
                (None, false),
                (None, true),
                (Some(100), true),
                (Some(2), true),
            ] {
                let mut machine = machine(&repo, http);
                let mut arguments = vec![repo.want(1)];
                if let Some(value) = have {
                    arguments.push(repo.have(value));
                }
                if done {
                    arguments.push(data(b"done\n"));
                }
                let response = submit(&mut machine, &repo, &arguments);
                assert_eq!(response.output, vec![data(b"packfile\n")]);
                assert_eq!(selected(&response).wants, vec![oid(format, 1)]);
                assert_eq!(
                    selected(&response).haves,
                    have.into_iter()
                        .map(|value| oid(format, value))
                        .collect::<Vec<_>>(),
                );
                assert!(!machine.has_completed_negotiation());
            }
        }
    }
}

fn shallow_controls(repo: &Repository) -> Vec<Vec<Packet>> {
    vec![
        vec![data(format!("shallow {}\n", oid(repo.format, 1)))],
        vec![data(b"deepen 1\n")],
        vec![data(b"deepen-since 1\n")],
        vec![data(b"deepen-not refs/heads/topic\n")],
        vec![
            data(format!("shallow {}\n", oid(repo.format, 1))),
            data(b"deepen 1\n"),
            data(b"deepen-relative\n"),
        ],
    ]
}

#[test]
fn shallow_controls_and_wait_for_done_prevent_premature_pack_work() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for http in [false, true] {
            let mut controls = shallow_controls(&repo);
            controls.push(vec![data(b"wait-for-done\n")]);
            for control in controls {
                let mut machine = machine(&repo, http);
                let mut arguments = vec![repo.want(1), repo.have(1)];
                arguments.extend(control);
                let response = submit(&mut machine, &repo, &arguments);
                assert_eq!(response.output, acknowledgments(&[oid(format, 1)]));
                assert!(response.events.is_empty());
                assert_round(&machine, http);
                assert_eq!(repo.shallow_reads.get(), 0);
            }
        }
    }
}

#[test]
fn ordinary_round_reset_discards_refs_shallows_filter_and_pack_options() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for control in shallow_controls(&repo) {
            let mut machine = machine(&repo, false);
            let mut first = vec![
                data(b"want-ref refs/heads/main\n"),
                repo.have(2),
                data(b"filter blob:none\n"),
                data(b"thin-pack\n"),
                data(b"include-tag\n"),
                data(b"ofs-delta\n"),
                data(b"no-progress\n"),
            ];
            first.extend(control);
            let response = submit(&mut machine, &repo, &first);
            assert_eq!(response.output, acknowledgments(&[oid(format, 2)]));
            assert!(
                response.events.is_empty(),
                "wanted-refs wait until pack selection"
            );

            let response = submit(&mut machine, &repo, &[repo.want(3), repo.have(3)]);
            assert_eq!(
                response.output,
                vec![
                    data(b"acknowledgments\n"),
                    data(format!("ACK {}\n", oid(format, 3))),
                    data(b"ready\n"),
                    Packet::Delimiter,
                    data(b"packfile\n"),
                ],
            );
            let request = selected(&response);
            assert_eq!(request.wants, vec![oid(format, 3)]);
            assert_eq!(request.haves, vec![oid(format, 3)]);
            assert!(request.shallows.is_empty() && request.deepen_not.is_empty());
            assert_eq!(
                (
                    request.deepen,
                    request.deepen_since,
                    request.filter.as_ref()
                ),
                (None, None, None)
            );
            assert_eq!(request.options, PackOptions::SIDE_BAND_64K);
            assert_eq!(repo.shallow_reads.get(), 0);
        }
    }
}

#[test]
fn fragmented_ordinary_rounds_keep_all_acknowledgments_before_the_final_pack() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let mut first = vec![repo.want(1)];
        first.extend((100..116).map(|value| repo.have(value)));
        let mut packets = request(&repo, &first);
        packets.extend(request(&repo, &[repo.want(1), repo.have(2)]));
        packets.extend(request(
            &repo,
            &[repo.want(1), repo.have(2), data(b"done\n")],
        ));
        let bytes = encode_packets(&packets, &WireLimits::default()).unwrap();
        let mut expected = acknowledgments(&[]);
        expected.extend(acknowledgments(&[oid(format, 2)]));
        expected.push(data(b"packfile\n"));
        for width in [1, 2, 7, 31, bytes.len()] {
            let mut machine = machine(&repo, false);
            let mut response = Transition {
                output: Vec::new(),
                events: Vec::new(),
            };
            for chunk in bytes.chunks(width) {
                let part = machine.push_bytes(chunk, &repo).unwrap();
                response.output.extend(part.output);
                response.events.extend(part.events);
            }
            machine.finish().unwrap();
            assert_eq!(response.output, expected);
            assert_eq!(selected(&response).haves, vec![oid(format, 2)]);
        }
    }
}

#[test]
fn expired_round_or_final_handoff_refuses_before_output_and_can_retry_the_exact_flush() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for http in [false, true] {
            for (have, done) in [(100, false), (2, false), (1, false), (2, true)] {
                let mut machine = machine(&repo, http);
                let mut arguments = vec![repo.want(1), repo.have(have)];
                if done {
                    arguments.push(data(b"done\n"));
                }
                let mut packets = request(&repo, &arguments);
                assert_eq!(packets.pop(), Some(Packet::Flush));
                for packet in packets {
                    machine.push_packet(&packet, &repo).unwrap();
                }
                let mut untouched = machine.clone();
                repo.live.set(false);
                assert_eq!(
                    machine.push_packet(&Packet::Flush, &repo),
                    Err(WireError::PackSourceRefused),
                );
                assert!(!machine.is_awaiting_command() && !machine.has_completed_negotiation());
                repo.live.set(true);
                assert_eq!(
                    machine.push_packet(&Packet::Flush, &repo).unwrap(),
                    untouched.push_packet(&Packet::Flush, &repo).unwrap(),
                );
            }
        }
    }
}

#[test]
fn completed_ordinary_rounds_preserve_connection_and_http_eof_boundaries() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let mut connection = machine(&repo, false);
        let response = submit(&mut connection, &repo, &[repo.want(1), repo.have(100)]);
        assert_eq!(response.output, acknowledgments(&[]));
        connection.finish().unwrap();
        assert_round(&connection, false);
        let mut partial = connection.clone();
        partial.push_bytes(b"000", &repo).unwrap();
        assert!(
            partial.finish().is_err(),
            "partial next-command framing still refuses"
        );
        let ended = connection.push_packet(&Packet::Flush, &repo).unwrap();
        assert!(ended.output.is_empty() && ended.events.is_empty());
        assert!(connection.has_ended());

        let mut http = machine(&repo, true);
        let response = submit(&mut http, &repo, &[repo.want(1), repo.have(100)]);
        assert_eq!(response.output, acknowledgments(&[]));
        http.finish().unwrap();
        assert_round(&http, true);
        assert!(http.push_packet(&data(b"command=fetch\n"), &repo).is_err());
    }
}
