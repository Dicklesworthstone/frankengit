#![forbid(unsafe_code)]
//! Git protocol-v2 exact-ref fetch, including the shared HTTP adapter.

use std::cell::Cell;
use std::collections::BTreeSet;

use fgit_wire::closure::ShallowUpdate;
use fgit_wire::smart_http::rpc::{RpcError, UploadRpc};
use fgit_wire::smart_http::{HttpLimits, ProtocolVersion, parse_head};
use fgit_wire::visibility::{RefVisibility, VisibleUploadPackRepository};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackRequest, Packet,
    UploadPackRepository, V2UploadPack, WireError, WireEvent, WireLimits, encode_packets,
};

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    permitted: BTreeSet<AnyGitOid>,
    common: BTreeSet<AnyGitOid>,
    supported: bool,
    checkpoints: Cell<usize>,
    stop_at: Cell<Option<usize>>,
    general_lookups: Cell<usize>,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        Self {
            format,
            // A deterministic view need not already be lexicographically
            // sorted. HEAD and aliases deliberately share one object.
            refs: [
                ("HEAD", 1),
                ("refs/tags/release", 2),
                ("refs/heads/zeta", 3),
                ("refs/heads/main", 1),
                ("refs/heads/alias", 1),
                ("refs/heads/private", 4),
            ]
            .into_iter()
            .map(|(name, value)| {
                AdvertisedRef::new(oid(format, value), name.as_bytes(), &WireLimits::default())
                    .unwrap()
            })
            .collect(),
            permitted: (1..=4).map(|value| oid(format, value)).collect(),
            common: BTreeSet::new(),
            supported: true,
            checkpoints: Cell::new(0),
            stop_at: Cell::new(None),
            general_lookups: Cell::new(0),
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
        self.permitted.contains(&id)
    }
    fn is_common(&self, id: AnyGitOid) -> bool {
        self.common.contains(&id)
    }
    fn supports_ref_in_want(&self) -> bool {
        self.supported
    }
    fn ref_in_want_checkpoint(&self) -> Result<(), WireError> {
        let count = self.checkpoints.get() + 1;
        self.checkpoints.set(count);
        if self.stop_at.get().is_some_and(|limit| count >= limit) {
            Err(WireError::PackSourceRefused)
        } else {
            Ok(())
        }
    }
    fn resolve_ref(&self, _: &[u8]) -> Option<AnyGitOid> {
        self.general_lookups.set(self.general_lookups.get() + 1);
        // Deliberately broader than the authenticated advertisement.
        Some(oid(self.format, 4))
    }
    fn symref_target(&self, name: &[u8]) -> Option<&[u8]> {
        (name == b"HEAD").then_some(b"refs/heads/main")
    }
    fn peeled(&self, id: AnyGitOid) -> Option<AnyGitOid> {
        (id == oid(self.format, 2)).then_some(oid(self.format, 1))
    }
    fn supports_shallow(&self) -> bool {
        true
    }
    fn shallow_update(&self, request: &PackRequest) -> Result<ShallowUpdate, WireError> {
        Ok(ShallowUpdate {
            shallow: if request.deepen.is_some() {
                vec![oid(self.format, 1)]
            } else {
                Vec::new()
            },
            unshallow: Vec::new(),
        })
    }
}

fn oid(format: GitObjectFormat, value: u8) -> AnyGitOid {
    AnyGitOid::from_hex(format, &format!("{value:02x}").repeat(format.digest_len())).unwrap()
}

fn data(text: impl AsRef<[u8]>) -> Packet {
    Packet::Data(text.as_ref().to_vec())
}

fn caps(format: GitObjectFormat, features: &str, limits: &WireLimits) -> Capabilities {
    Capabilities::parse_v2_advertisement(
        &[
            data("version 2\n"),
            data("ls-refs\n"),
            data(format!("fetch={features}\n")),
            data(format!("object-format={}\n", format.as_str())),
            Packet::Flush,
        ],
        limits,
    )
    .unwrap()
}

fn request(format: GitObjectFormat, arguments: &[Packet]) -> Vec<Packet> {
    let mut packets = vec![
        data("command=fetch\n"),
        data(format!("object-format={}\n", format.as_str())),
        Packet::Delimiter,
    ];
    packets.extend_from_slice(arguments);
    packets.push(Packet::Flush);
    packets
}

fn machine(format: GitObjectFormat, limits: WireLimits, stateless: bool) -> V2UploadPack {
    let machine = V2UploadPack::new(caps(format, "ref-in-want shallow filter", &limits), limits)
        .unwrap()
        .with_shallow_updates();
    if stateless {
        machine.with_stateless_http_rounds()
    } else {
        machine
    }
}

fn run(
    repository: &impl UploadPackRepository,
    arguments: &[Packet],
    limits: WireLimits,
    stateless: bool,
) -> Result<(Vec<Packet>, Vec<WireEvent>), WireError> {
    let mut machine = machine(repository.object_format(), limits, stateless);
    let (mut output, mut events) = (Vec::new(), Vec::new());
    for packet in request(repository.object_format(), arguments) {
        let transition = machine.push_packet(&packet, repository)?;
        output.extend(transition.output);
        events.extend(transition.events);
    }
    machine.finish()?;
    Ok((output, events))
}

fn selected(events: &[WireEvent]) -> &PackRequest {
    let [WireEvent::PackRequested(request)] = events else {
        panic!("one exact pack request required: {events:?}");
    };
    request
}

#[test]
fn exact_refs_head_and_unpeeled_tags_share_the_bounded_pack_selection() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let arguments = [
            data("want-ref refs/tags/release\n"),
            data(format!("want {}\n", oid(format, 1))),
            data("want-ref HEAD\n"),
            data("want-ref refs/heads/main\n"),
            data("want-ref refs/heads/zeta\n"),
            data("done\n"),
        ];
        let bytes = encode_packets(&request(format, &arguments), &WireLimits::default()).unwrap();
        for chunk_size in [1, 2, 7, 29, bytes.len()] {
            let repository = Repository::new(format);
            let mut machine = machine(format, WireLimits::default(), false);
            let (mut output, mut events) = (Vec::new(), Vec::new());
            for chunk in bytes.chunks(chunk_size) {
                let transition = machine.push_bytes(chunk, &repository).unwrap();
                output.extend(transition.output);
                events.extend(transition.events);
            }
            machine.finish().unwrap();
            assert_eq!(
                selected(&events).wants,
                [oid(format, 2), oid(format, 1), oid(format, 3)]
            );
            assert_eq!(
                output,
                [
                    data("wanted-refs\n"),
                    data(format!("{} refs/tags/release\n", oid(format, 2))),
                    data(format!("{} HEAD\n", oid(format, 1))),
                    data(format!("{} refs/heads/main\n", oid(format, 1))),
                    data(format!("{} refs/heads/zeta\n", oid(format, 3))),
                    Packet::Delimiter,
                    data("packfile\n"),
                ]
            );
            assert_eq!(repository.general_lookups.get(), 0);
        }
    }
}

#[test]
fn missing_hidden_and_visible_but_unpermitted_refs_have_the_same_refusal() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = Repository::new(format);
        let mut visibility = RefVisibility::default();
        visibility
            .push_rule(b"refs/heads/private", &WireLimits::default())
            .unwrap();
        let hidden = VisibleUploadPackRepository::new(&repository, &visibility);
        assert!(hidden.supports_ref_in_want());
        let arguments = [data("want-ref refs/heads/private\n"), data("done\n")];
        let expected = WireError::UnknownWantedRef {
            name: b"refs/heads/private".to_vec(),
        };
        assert_eq!(
            run(&hidden, &arguments, WireLimits::default(), false),
            Err(expected.clone())
        );
        repository
            .refs
            .retain(|reference| reference.name != b"refs/heads/private");
        assert_eq!(
            run(&repository, &arguments, WireLimits::default(), false),
            Err(expected)
        );
        repository.permitted.remove(&oid(format, 1));
        assert_eq!(
            run(
                &repository,
                &[data("want-ref refs/heads/main\n")],
                WireLimits::default(),
                false
            ),
            Err(WireError::UnknownWantedRef {
                name: b"refs/heads/main".to_vec()
            })
        );
        assert_eq!(repository.general_lookups.get(), 0);
        for name in ["main", "heads/main", "does-not-exist"] {
            assert_eq!(
                run(
                    &repository,
                    &[data(format!("want-ref {name}\n"))],
                    WireLimits::default(),
                    false
                ),
                Err(WireError::UnknownWantedRef {
                    name: name.as_bytes().to_vec()
                })
            );
        }
    }
}

#[test]
fn support_requires_both_the_advertised_capability_and_authenticated_provider() {
    let format = GitObjectFormat::Sha1;
    let mut repository = Repository::new(format);
    repository.supported = false;
    assert_eq!(
        run(
            &repository,
            &[data("want-ref HEAD\n")],
            WireLimits::default(),
            false
        ),
        Err(WireError::PackSourceRefused)
    );
    repository.supported = true;
    let mut machine = V2UploadPack::new(
        caps(format, "filter", &WireLimits::default()),
        WireLimits::default(),
    )
    .unwrap();
    for packet in [data("command=fetch\n"), Packet::Delimiter] {
        machine.push_packet(&packet, &repository).unwrap();
    }
    assert_eq!(
        machine.push_packet(&data("want-ref HEAD\n"), &repository),
        Err(WireError::UnknownCapability {
            capability: b"ref-in-want".to_vec()
        })
    );
}

#[test]
fn ref_selectors_and_explicit_oid_selectors_share_one_count_budget() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let limits = WireLimits {
            max_wants: 1,
            ..WireLimits::default()
        };
        assert!(
            run(
                &repository,
                &[data("want-ref HEAD\n"), data("done\n")],
                limits.clone(),
                false
            )
            .is_ok()
        );
        for pair in [
            [data("want-ref HEAD\n"), data("want-ref refs/heads/main\n")],
            [
                data("want-ref HEAD\n"),
                data(format!("want {}\n", oid(format, 1))),
            ],
            [
                data(format!("want {}\n", oid(format, 1))),
                data("want-ref HEAD\n"),
            ],
        ] {
            assert!(matches!(
                run(&repository, &pair, limits.clone(), false),
                Err(WireError::TooManyObjectIds { limit: 1, .. })
            ));
        }
        assert_eq!(
            run(
                &repository,
                &[data("want-ref HEAD\n"), data("want-ref HEAD\n")],
                limits,
                false
            ),
            Err(WireError::DuplicateWantedRef {
                name: b"HEAD".to_vec()
            })
        );
        let limits = WireLimits {
            max_wants: 2,
            ..WireLimits::default()
        };
        let (_, events) = run(
            &repository,
            &[
                data("want-ref HEAD\n"),
                data(format!("want {}\n", oid(format, 1))),
                data(format!("want {}\n", oid(format, 1))),
                data("done\n"),
            ],
            limits,
            false,
        )
        .unwrap();
        assert_eq!(selected(&events).wants, [oid(format, 1)]);
    }
}

#[test]
fn malformed_names_and_metadata_refuse_before_any_response() {
    let format = GitObjectFormat::Sha1;
    let repository = Repository::new(format);
    for name in [
        b"refs/heads/bad name".as_slice(),
        b"../main",
        b"refs/tags/release^{}",
        b"",
    ] {
        let mut line = b"want-ref ".to_vec();
        line.extend_from_slice(name);
        line.push(b'\n');
        assert_eq!(
            run(&repository, &[data(line)], WireLimits::default(), false),
            Err(WireError::InvalidRefName)
        );
    }
    // Embedded framing controls are rejected before ref-name parsing. Keep
    // that exact precedence and the complete original packet in the refusal.
    for name in [
        b"refs/heads/a\0b".as_slice(),
        b"refs/heads/a\rb",
        b"refs/heads/a\nb",
    ] {
        let mut line = b"want-ref ".to_vec();
        line.extend_from_slice(name);
        line.push(b'\n');
        assert_eq!(
            run(&repository, &[data(&line)], WireLimits::default(), false),
            Err(WireError::MalformedRequestLine { line })
        );
    }
    let limits = WireLimits {
        max_ref_name_bytes: 3,
        ..WireLimits::default()
    };
    assert_eq!(
        run(&repository, &[data("want-ref HEAD\n")], limits, false),
        Err(WireError::RefNameTooLarge { limit: 3 })
    );
    let limits = WireLimits {
        max_advertised_refs: 5,
        ..WireLimits::default()
    };
    assert_eq!(
        run(&repository, &[data("want-ref HEAD\n")], limits, false),
        Err(WireError::TooManyAdvertisedRefs { limit: 5 })
    );
    let mut repository = repository;
    repository.refs.push(repository.refs[0].clone());
    assert_eq!(
        run(
            &repository,
            &[data("want-ref HEAD\n")],
            WireLimits::default(),
            false
        ),
        Err(WireError::UnsortedOrDuplicateAdvertisement)
    );
    repository.refs.pop();
    repository.refs[0].oid = oid(GitObjectFormat::Sha256, 1);
    assert_eq!(
        run(
            &repository,
            &[data("want-ref HEAD\n")],
            WireLimits::default(),
            false
        ),
        Err(WireError::ObjectFormatMismatch {
            expected: format,
            observed: GitObjectFormat::Sha256
        })
    );
}

#[test]
fn opaque_ref_bytes_and_response_byte_limits_have_exact_boundary_twins() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = Repository::new(format);
        let name = b"refs/heads/raw-\xff";
        repository
            .refs
            .push(AdvertisedRef::new(oid(format, 3), name, &WireLimits::default()).unwrap());
        let mut line = b"want-ref ".to_vec();
        line.extend_from_slice(name);
        line.push(b'\n');
        let args = [data(line), data("done\n")];
        let (expected, _) = run(&repository, &args, WireLimits::default(), false).unwrap();
        let bytes = encode_packets(&expected, &WireLimits::default()).unwrap();
        let limits = WireLimits {
            max_outbound_bytes: bytes.len(),
            ..WireLimits::default()
        };
        assert_eq!(
            run(&repository, &args, limits.clone(), false).unwrap().0,
            expected
        );
        assert!(matches!(
            run(
                &repository,
                &args,
                WireLimits {
                    max_outbound_bytes: bytes.len() - 1,
                    ..limits
                },
                false
            ),
            Err(WireError::OutboundBytesExceeded { .. })
        ));
        let row_bytes = format.digest_len() * 2 + name.len() + 6;
        let limits = WireLimits {
            max_packet_bytes: row_bytes,
            ..WireLimits::default()
        };
        assert_eq!(
            run(&repository, &args, limits.clone(), false).unwrap().0,
            expected
        );
        assert!(matches!(
            run(
                &repository,
                &args,
                WireLimits {
                    max_packet_bytes: row_bytes - 1,
                    ..limits
                },
                false
            ),
            Err(WireError::PacketTooLarge { .. })
        ));
        let Packet::Data(row) = &expected[1] else {
            panic!("wanted ref row")
        };
        assert!(row.ends_with(&[name.as_slice(), b"\n"].concat()));
    }
}

#[test]
fn canceled_missing_duplicate_or_complete_queries_never_release_receipts() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for argument in [
            data("want-ref HEAD\n"),
            data("want-ref refs/heads/missing\n"),
        ] {
            let repository = Repository::new(format);
            repository.stop_at.set(Some(1));
            assert_eq!(
                run(&repository, &[argument], WireLimits::default(), false),
                Err(WireError::PackSourceRefused)
            );
        }
        let repository = Repository::new(format);
        let mut machine = machine(format, WireLimits::default(), false);
        for packet in [
            data("command=fetch\n"),
            Packet::Delimiter,
            data("want-ref HEAD\n"),
            data("done\n"),
        ] {
            let transition = machine.push_packet(&packet, &repository).unwrap();
            assert!(transition.output.is_empty() && transition.events.is_empty());
        }
        repository
            .stop_at
            .set(Some(repository.checkpoints.get() + 1));
        assert_eq!(
            machine.push_packet(&Packet::Flush, &repository),
            Err(WireError::PackSourceRefused)
        );
        assert_eq!(
            machine.push_packet(&data("want-ref HEAD\n"), &repository),
            Err(WireError::PackSourceRefused)
        );
    }
}

#[test]
fn replacing_the_snapshot_cannot_mix_resolved_refs_and_pack_objects() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let original = Repository::new(format);
        let mut changed = Repository::new(format);
        changed
            .refs
            .iter_mut()
            .find(|reference| reference.name == b"refs/heads/main")
            .unwrap()
            .oid = oid(format, 3);
        let mut machine = machine(format, WireLimits::default(), false);
        for packet in [
            data("command=fetch\n"),
            Packet::Delimiter,
            data("want-ref refs/heads/main\n"),
            data("done\n"),
        ] {
            machine.push_packet(&packet, &original).unwrap();
        }
        assert_eq!(
            machine.push_packet(&Packet::Flush, &changed),
            Err(WireError::PackSourceRefused)
        );
        changed.refs.clear();
        assert_eq!(
            machine.push_packet(&Packet::Flush, &changed),
            Err(WireError::PackSourceRefused)
        );
    }
}

#[test]
fn acknowledgment_only_rounds_do_not_emit_refs_and_next_round_resolves_its_own_view() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let arguments = [
            data("want-ref refs/heads/main\n"),
            data(format!("have {}\n", oid(format, 9))),
        ];
        let (output, events) = run(&repository, &arguments, WireLimits::default(), true).unwrap();
        assert_eq!(
            output,
            [data("acknowledgments\n"), data("NAK\n"), Packet::Flush]
        );
        assert!(events.is_empty());
        let mut changed = Repository::new(format);
        changed
            .refs
            .iter_mut()
            .find(|reference| reference.name == b"refs/heads/main")
            .unwrap()
            .oid = oid(format, 3);
        let (output, events) = run(
            &changed,
            &[data("want-ref refs/heads/main\n"), data("done\n")],
            WireLimits::default(),
            true,
        )
        .unwrap();
        assert_eq!(selected(&events).wants, [oid(format, 3)]);
        assert_eq!(
            output[1],
            data(format!("{} refs/heads/main\n", oid(format, 3)))
        );
        changed.common.insert(oid(format, 3));
        let (output, events) = run(
            &changed,
            &[
                data("want-ref refs/heads/main\n"),
                data(format!("have {}\n", oid(format, 3))),
            ],
            WireLimits::default(),
            true,
        )
        .unwrap();
        assert_eq!(selected(&events).wants, [oid(format, 3)]);
        assert_eq!(
            output,
            [
                data("acknowledgments\n"),
                data(format!("ACK {}\n", oid(format, 3))),
                data("ready\n"),
                Packet::Delimiter,
                data("wanted-refs\n"),
                data(format!("{} refs/heads/main\n", oid(format, 3))),
                Packet::Delimiter,
                data("packfile\n"),
            ]
        );
    }
}

#[test]
fn shallow_information_precedes_wanted_refs_and_combined_sections_share_the_response_budget() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let arguments = [
            data("want-ref refs/heads/main\n"),
            data("deepen 1\n"),
            data("filter blob:none\n"),
            data("done\n"),
        ];
        let (output, events) = run(&repository, &arguments, WireLimits::default(), false).unwrap();
        assert_eq!(selected(&events).deepen, Some(1));
        assert_eq!(
            output,
            [
                data("shallow-info\n"),
                data(format!("shallow {}\n", oid(format, 1))),
                Packet::Delimiter,
                data("wanted-refs\n"),
                data(format!("{} refs/heads/main\n", oid(format, 1))),
                Packet::Delimiter,
                data("packfile\n"),
            ]
        );
        let total = encode_packets(&output, &WireLimits::default())
            .unwrap()
            .len();
        let limits = WireLimits {
            max_outbound_bytes: total,
            ..WireLimits::default()
        };
        assert!(run(&repository, &arguments, limits.clone(), false).is_ok());
        assert!(matches!(
            run(
                &repository,
                &arguments,
                WireLimits {
                    max_outbound_bytes: total - 1,
                    ..limits
                },
                false
            ),
            Err(WireError::OutboundBytesExceeded { .. })
        ));
    }
}

#[test]
fn smart_http_retains_refs_until_the_complete_body_and_refuses_trailing_or_cancelled_work() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for extra_command in [false, true] {
            let repository = Repository::new(format);
            let limits = WireLimits::default();
            let args = [data("want-ref refs/heads/main\n"), data("done\n")];
            let mut body = encode_packets(&request(format, &args), &limits).unwrap();
            if extra_command {
                body.extend(encode_packets(&request(format, &args), &limits).unwrap());
            }
            let head_text = format!(
                "POST /repo.git/git-upload-pack HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let head = parse_head(head_text.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let mut rpc = UploadRpc::new(
                &head,
                ProtocolVersion::V2,
                caps(format, "ref-in-want", &limits),
                &repository,
                limits,
                HttpLimits::default(),
            )
            .unwrap();
            if extra_command {
                assert!(matches!(
                    rpc.push(&body, &mut || true),
                    Err(RpcError::MultipleCommands)
                ));
                assert!(rpc.finish(&mut || true).is_err());
            } else {
                for byte in body.chunks(1) {
                    rpc.push(byte, &mut || true).unwrap();
                }
                let reply = rpc.finish(&mut || true).unwrap();
                assert_eq!(reply.pack_request().unwrap().wants, [oid(format, 1)]);
                let expected = run(&repository, &args, WireLimits::default(), true)
                    .unwrap()
                    .0;
                assert_eq!(
                    reply.prefix(),
                    encode_packets(&expected, &WireLimits::default()).unwrap()
                );
            }
            let mut rpc = UploadRpc::new(
                &head,
                ProtocolVersion::V2,
                caps(format, "ref-in-want", &WireLimits::default()),
                &repository,
                WireLimits::default(),
                HttpLimits::default(),
            )
            .unwrap();
            assert!(matches!(
                rpc.push(&body, &mut || false),
                Err(RpcError::Cancelled)
            ));
            assert!(rpc.finish(&mut || true).is_err());
        }
    }
}

#[test]
fn wait_for_done_holds_wanted_refs_until_a_pack_producing_http_round() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for done in [false, true] {
            let mut repository = Repository::new(format);
            repository.common.insert(oid(format, 1));
            let limits = WireLimits::default();
            let mut machine =
                V2UploadPack::new(caps(format, "ref-in-want wait-for-done", &limits), limits)
                    .unwrap()
                    .with_stateless_http_rounds();
            let mut args = vec![
                data("want-ref HEAD\n"),
                data(format!("have {}\n", oid(format, 1))),
                data("wait-for-done\n"),
            ];
            if done {
                args.push(data("done\n"));
            }
            let (mut output, mut events) = (Vec::new(), Vec::new());
            for packet in request(format, &args) {
                let transition = machine.push_packet(&packet, &repository).unwrap();
                output.extend(transition.output);
                events.extend(transition.events);
            }
            if done {
                assert_eq!(
                    output,
                    [
                        data("wanted-refs\n"),
                        data(format!("{} HEAD\n", oid(format, 1))),
                        Packet::Delimiter,
                        data("packfile\n")
                    ]
                );
                assert_eq!(selected(&events).wants, [oid(format, 1)]);
            } else {
                assert_eq!(
                    output,
                    [
                        data("acknowledgments\n"),
                        data(format!("ACK {}\n", oid(format, 1))),
                        Packet::Flush
                    ]
                );
                assert!(events.is_empty());
                assert!(machine.is_http_negotiation_complete());
            }
        }
    }
}

#[test]
fn smart_http_sideband_all_frames_every_wanted_ref_row_on_channel_one() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let limits = WireLimits::default();
        let body = encode_packets(
            &request(
                format,
                &[
                    data("want-ref HEAD\n"),
                    data("sideband-all\n"),
                    data("done\n"),
                ],
            ),
            &limits,
        )
        .unwrap();
        let head_text = format!(
            "POST /repo.git/git-upload-pack HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let head = parse_head(head_text.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let mut rpc = UploadRpc::new(
            &head,
            ProtocolVersion::V2,
            caps(format, "ref-in-want sideband-all", &limits),
            &repository,
            limits.clone(),
            HttpLimits::default(),
        )
        .unwrap();
        rpc.push(&body, &mut || true).unwrap();
        let reply = rpc.finish(&mut || true).unwrap();
        let expected = [
            data(b"\x01wanted-refs\n"),
            data(format!("\x01{} HEAD\n", oid(format, 1))),
            Packet::Delimiter,
            data(b"\x01packfile\n"),
        ];
        assert_eq!(reply.prefix(), encode_packets(&expected, &limits).unwrap());
        assert!(reply.pack_request().unwrap().options.sideband_all());
    }
}
