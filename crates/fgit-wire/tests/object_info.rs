#![forbid(unsafe_code)]
//! Native command and HTTP-envelope regressions for Git 2.54 object-info.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use fgit_wire::smart_http::rpc::{RpcError, UploadRpc};
use fgit_wire::smart_http::{HttpLimits, ProtocolVersion, parse_head};
use fgit_wire::visibility::{RefVisibility, VisibleUploadPackRepository};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, UploadPackRepository,
    V2UploadPack, WireError, WireEvent, WireLimits, encode_packets,
};

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    visible: BTreeSet<AnyGitOid>,
    sizes: BTreeMap<AnyGitOid, u64>,
    queried: RefCell<Vec<AnyGitOid>>,
    ticks: Cell<usize>,
    stop_at: Cell<Option<usize>>,
    supported: bool,
    fail_lookup: bool,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        let limits = WireLimits::default();
        Self {
            format,
            refs: vec![
                AdvertisedRef::new(oid(format, 2), b"refs/heads/hidden", &limits).unwrap(),
                AdvertisedRef::new(oid(format, 1), b"refs/heads/main", &limits).unwrap(),
            ],
            visible: [oid(format, 1), oid(format, 3)].into_iter().collect(),
            sizes: [
                (oid(format, 1), 0),
                (oid(format, 2), 77),
                (oid(format, 3), u64::MAX),
            ]
            .into_iter()
            .collect(),
            queried: RefCell::default(),
            ticks: Cell::new(0),
            stop_at: Cell::new(None),
            supported: true,
            fail_lookup: false,
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
    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.visible.contains(&oid)
    }
    fn is_common(&self, _: AnyGitOid) -> bool {
        false
    }
    fn supports_object_info(&self) -> bool {
        self.supported
    }
    fn object_info_checkpoint(&self) -> Result<(), WireError> {
        self.ticks.set(self.ticks.get() + 1);
        if self
            .stop_at
            .get()
            .is_some_and(|limit| self.ticks.get() >= limit)
        {
            Err(WireError::PackSourceRefused)
        } else {
            Ok(())
        }
    }
    fn object_info_size(&self, oid: AnyGitOid) -> Result<Option<u64>, WireError> {
        self.queried.borrow_mut().push(oid);
        if self.fail_lookup {
            Err(WireError::PackSourceRefused)
        } else {
            Ok(self.sizes.get(&oid).copied())
        }
    }
}

fn oid(format: GitObjectFormat, byte: u8) -> AnyGitOid {
    AnyGitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}

fn data(text: impl AsRef<str>) -> Packet {
    Packet::Data(text.as_ref().as_bytes().to_vec())
}

fn caps(format: GitObjectFormat, supported: bool, limits: &WireLimits) -> Capabilities {
    let mut packets = vec![data("version 2\n"), data("ls-refs\n"), data("fetch\n")];
    if supported {
        packets.push(data("object-info\n"));
    }
    packets.push(data(format!("object-format={}\n", format.as_str())));
    packets.push(Packet::Flush);
    Capabilities::parse_v2_advertisement(&packets, limits).unwrap()
}

fn request(format: GitObjectFormat, size: bool, objects: &[AnyGitOid]) -> Vec<Packet> {
    let mut packets = vec![
        data("command=object-info\n"),
        data(format!("object-format={}\n", format.as_str())),
        Packet::Delimiter,
    ];
    if size {
        packets.push(data("size\n"));
    }
    packets.extend(objects.iter().map(|oid| data(format!("oid {oid}\n"))));
    packets.push(Packet::Flush);
    packets
}

fn run(
    repository: &impl UploadPackRepository,
    packets: &[Packet],
    limits: WireLimits,
) -> Result<Vec<Packet>, WireError> {
    let mut machine = V2UploadPack::new(caps(repository.object_format(), true, &limits), limits)?;
    let mut output = Vec::new();
    for packet in packets {
        output.extend(machine.push_packet(packet, repository)?.output);
    }
    Ok(output)
}

#[test]
fn size_rows_preserve_order_duplicates_zero_and_full_u64_without_disclosing_hidden_objects() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let objects = [1, 2, 4, 3, 1].map(|byte| oid(format, byte));
        let packets = request(format, true, &objects);
        let bytes = encode_packets(&packets, &WireLimits::default()).unwrap();
        for chunk in [1, 2, 7, 31, bytes.len()] {
            let repository = Repository::new(format);
            let mut machine = V2UploadPack::new(
                caps(format, true, &WireLimits::default()),
                WireLimits::default(),
            )
            .unwrap();
            let (mut output, mut events) = (Vec::new(), Vec::new());
            for part in bytes.chunks(chunk) {
                let transition = machine.push_bytes(part, &repository).unwrap();
                output.extend(transition.output);
                events.extend(transition.events);
            }
            machine.finish().unwrap();
            assert_eq!(
                output,
                vec![
                    data("size"),
                    data(format!("{} 0", objects[0])),
                    data(format!("{} ", objects[1])),
                    data(format!("{} ", objects[2])),
                    data(format!("{} {}", objects[3], u64::MAX)),
                    data(format!("{} 0", objects[4])),
                    Packet::Flush,
                ]
            );
            assert_eq!(
                events,
                vec![WireEvent::ObjectInfo {
                    object_count: 5,
                    size: true
                }]
            );
            assert_eq!(
                *repository.queried.borrow(),
                vec![objects[0], objects[3], objects[4]]
            );
            assert!(machine.is_awaiting_command());
        }
    }
}

#[test]
fn empty_and_attribute_free_queries_match_pinned_git_and_repeated_size_is_idempotent() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        assert_eq!(
            run(
                &repository,
                &request(format, true, &[]),
                WireLimits::default()
            )
            .unwrap(),
            vec![Packet::Flush]
        );
        let objects = [oid(format, 1), oid(format, 4)];
        assert_eq!(
            run(
                &repository,
                &request(format, false, &objects),
                WireLimits::default()
            )
            .unwrap(),
            vec![
                data(objects[0].to_string()),
                data(objects[1].to_string()),
                Packet::Flush
            ]
        );
        assert!(repository.queried.borrow().is_empty());
        let mut packets = request(format, true, &objects);
        packets.insert(4, data("size"));
        assert_eq!(
            run(&repository, &packets, WireLimits::default()).unwrap(),
            vec![
                data("size"),
                data(format!("{} 0", objects[0])),
                data(format!("{} ", objects[1])),
                Packet::Flush
            ]
        );
    }
}

#[test]
fn completed_queries_can_repeat_then_list_refs_without_leaking_request_state() {
    let format = GitObjectFormat::Sha1;
    let repository = Repository::new(format);
    let limits = WireLimits::default();
    let mut machine = V2UploadPack::new(caps(format, true, &limits), limits).unwrap();
    let objects = [oid(format, 1)];
    for size in [true, false, true] {
        let mut result = Vec::new();
        for packet in request(format, size, &objects) {
            result.extend(machine.push_packet(&packet, &repository).unwrap().output);
        }
        let expected = if size {
            vec![
                data("size"),
                data(format!("{} 0", objects[0])),
                Packet::Flush,
            ]
        } else {
            vec![data(objects[0].to_string()), Packet::Flush]
        };
        assert_eq!(result, expected);
    }
    for packet in [data("command=ls-refs"), Packet::Delimiter] {
        assert!(
            machine
                .push_packet(&packet, &repository)
                .unwrap()
                .output
                .is_empty()
        );
    }
    let reply = machine.push_packet(&Packet::Flush, &repository).unwrap();
    assert!(matches!(
        reply.events.as_slice(),
        [WireEvent::LsRefs { .. }]
    ));
    assert!(
        reply
            .output
            .iter()
            .all(|packet| !matches!(packet, Packet::Data(line) if line == b"size"))
    );
}

#[test]
fn capabilities_provider_and_full_native_object_id_are_required() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = Repository::new(format);
        let limits = WireLimits::default();
        let mut machine = V2UploadPack::new(caps(format, false, &limits), limits.clone()).unwrap();
        assert!(matches!(
            machine.push_packet(&data("command=object-info"), &repository),
            Err(WireError::UnsupportedCommand { .. })
        ));
        repository.supported = false;
        assert_eq!(
            run(&repository, &request(format, true, &[]), limits.clone()),
            Err(WireError::PackSourceRefused)
        );
        repository.supported = true;
        for value in ["oid 01", "oid not-an-oid", "type", "want 01"] {
            let mut packets = request(format, false, &[]);
            packets.insert(3, data(value));
            assert!(
                run(&repository, &packets, limits.clone()).is_err(),
                "{value}"
            );
        }
        assert!(repository.queried.borrow().is_empty());
    }
}

#[test]
fn repeated_oids_consume_the_request_ceiling() {
    let format = GitObjectFormat::Sha1;
    let repository = Repository::new(format);
    let mut limits = WireLimits::default();
    limits.max_wants = 2;
    let objects = [oid(format, 1); 3];
    assert!(
        run(
            &repository,
            &request(format, true, &objects[..2]),
            limits.clone()
        )
        .is_ok()
    );
    assert_eq!(
        run(&repository, &request(format, true, &objects), limits),
        Err(WireError::TooManyObjectIds {
            field: "object-info oid",
            limit: 2
        })
    );
}

#[test]
fn response_bytes_and_individual_packet_sizes_have_exact_boundary_twins() {
    let format = GitObjectFormat::Sha256;
    let repository = Repository::new(format);
    let packets = request(format, true, &[oid(format, 3)]);
    let output = run(&repository, &packets, WireLimits::default()).unwrap();
    let encoded = encode_packets(&output, &WireLimits::default()).unwrap();
    let mut limits = WireLimits::default();
    limits.max_outbound_bytes = encoded.len();
    assert_eq!(run(&repository, &packets, limits.clone()).unwrap(), output);
    limits.max_outbound_bytes -= 1;
    assert!(matches!(
        run(&repository, &packets, limits),
        Err(WireError::OutboundBytesExceeded { .. })
    ));
    let row_bytes = 4 + format.digest_len() * 2 + 1 + u64::MAX.to_string().len();
    let mut limits = WireLimits::default();
    limits.max_packet_bytes = row_bytes;
    assert_eq!(run(&repository, &packets, limits.clone()).unwrap(), output);
    limits.max_packet_bytes -= 1;
    assert!(matches!(
        run(&repository, &packets, limits),
        Err(WireError::PacketTooLarge { .. })
    ));
}

#[test]
fn cancellation_and_lookup_failure_never_release_a_partial_response() {
    let format = GitObjectFormat::Sha1;
    for (size, byte) in [(true, 1), (true, 4), (false, 1)] {
        let repository = Repository::new(format);
        repository.stop_at.set(Some(3));
        let mut machine = V2UploadPack::new(
            caps(format, true, &WireLimits::default()),
            WireLimits::default(),
        )
        .unwrap();
        for packet in request(format, size, &[oid(format, byte); 2]) {
            if packet == Packet::Flush {
                assert_eq!(
                    machine.push_packet(&packet, &repository),
                    Err(WireError::PackSourceRefused)
                );
            } else {
                let transition = machine.push_packet(&packet, &repository).unwrap();
                assert!(transition.output.is_empty() && transition.events.is_empty());
            }
        }
    }
    let mut repository = Repository::new(format);
    repository.fail_lookup = true;
    assert_eq!(
        run(
            &repository,
            &request(format, true, &[oid(format, 1)]),
            WireLimits::default()
        ),
        Err(WireError::PackSourceRefused)
    );
}

#[test]
fn visibility_wrapper_refuses_metadata_lookup_for_a_physically_present_hidden_tip() {
    let format = GitObjectFormat::Sha1;
    let mut repository = Repository::new(format);
    let hidden = oid(format, 2);
    repository.visible.insert(hidden);
    let mut visibility = RefVisibility::default();
    visibility
        .push_rule(b"refs/heads/hidden", &WireLimits::default())
        .unwrap();
    let filtered = VisibleUploadPackRepository::new(&repository, &visibility);
    assert!(filtered.supports_object_info());
    assert_eq!(filtered.object_info_size(hidden).unwrap(), None);
    assert_eq!(
        run(
            &filtered,
            &request(format, true, &[hidden, oid(format, 4), oid(format, 1)]),
            WireLimits::default()
        )
        .unwrap(),
        vec![
            data("size"),
            data(format!("{hidden} ")),
            data(format!("{} ", oid(format, 4))),
            data(format!("{} 0", oid(format, 1))),
            Packet::Flush
        ]
    );
    assert_eq!(*repository.queried.borrow(), vec![oid(format, 1)]);
}

#[test]
fn stateless_http_completes_metadata_only_and_rejects_trailing_commands() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format);
        let limits = WireLimits::default();
        let packets = request(format, true, &[oid(format, 1)]);
        let expected = encode_packets(
            &[
                data("size"),
                data(format!("{} 0", oid(format, 1))),
                Packet::Flush,
            ],
            &limits,
        )
        .unwrap();
        for trailing in [false, true] {
            let mut body = encode_packets(&packets, &limits).unwrap();
            if trailing {
                body.extend(encode_packets(&packets, &limits).unwrap());
            }
            let head = format!(
                "POST /repo.git/git-upload-pack HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let head = parse_head(head.as_bytes(), HttpLimits::default())
                .unwrap()
                .expect("complete HTTP request head");
            let mut rpc = UploadRpc::new(
                &head,
                ProtocolVersion::V2,
                caps(format, true, &limits),
                &repository,
                limits.clone(),
                HttpLimits::default(),
            )
            .unwrap();
            if trailing {
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
                assert_eq!(reply.prefix(), expected);
                assert!(reply.pack_request().is_none());
            }
        }
    }
}
