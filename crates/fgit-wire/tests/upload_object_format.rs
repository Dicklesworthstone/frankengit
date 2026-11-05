#![forbid(unsafe_code)]
//! Explicit upload-pack object-format claims bind to the native repository.
//! Omission retains the existing adapter-selected profile; these tests do not
//! introduce a new implicit-format negotiation policy.

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, PackOptions,
    PackRequest, Packet, Transition, UploadPackRepository, UploadPackVersion, V2UploadPack,
    WireError, WireEvent, WireLimits, encode_packets,
};

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        let oid = AnyGitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap();
        Self {
            format,
            refs: vec![
                AdvertisedRef::new(oid, b"refs/heads/main", &WireLimits::default()).unwrap(),
            ],
        }
    }

    fn want(&self, suffix: &str) -> Packet {
        data(format!(
            "want {}{suffix}\n",
            "11".repeat(self.format.digest_len()),
        ))
    }

    fn capability(&self) -> String {
        format!("object-format={}", self.format.as_str())
    }

    fn opposite(&self) -> GitObjectFormat {
        match self.format {
            GitObjectFormat::Sha1 => GitObjectFormat::Sha256,
            GitObjectFormat::Sha256 => GitObjectFormat::Sha1,
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
        self.refs.iter().any(|reference| reference.oid == oid)
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        false
    }
}

fn data(text: impl Into<Vec<u8>>) -> Packet {
    Packet::Data(text.into())
}

fn legacy(repo: &Repository, version: UploadPackVersion, http: bool) -> LegacyUploadPack {
    let limits = WireLimits::default();
    let caps = Capabilities::parse_v1(
        format!(
            "multi_ack_detailed side-band-64k thin-pack include-tag ofs-delta \
             no-progress no-done deepen-relative {}",
            repo.capability(),
        )
        .as_bytes(),
        &limits,
    )
    .unwrap();
    let machine = LegacyUploadPack::new(version, caps, limits).unwrap();
    if http {
        machine.with_stateless_http_rounds()
    } else {
        machine
    }
}

fn v2(repo: &Repository, http: bool) -> V2UploadPack {
    let limits = WireLimits::default();
    let caps = Capabilities::parse_v1(
        format!("ls-refs fetch {}", repo.capability()).as_bytes(),
        &limits,
    )
    .unwrap();
    let machine = V2UploadPack::new(caps, limits).unwrap();
    if http {
        machine.with_stateless_http_rounds()
    } else {
        machine
    }
}

fn legacy_request(repo: &Repository, capability: Option<&str>) -> Vec<u8> {
    let suffix = capability.map_or_else(String::new, |value| format!(" {value}"));
    encode_packets(
        &[repo.want(&suffix), Packet::Flush, data(b"done\n")],
        &WireLimits::default(),
    )
    .unwrap()
}

fn v2_request(repo: &Repository, command: &str, capabilities: &[&str]) -> Vec<u8> {
    let mut packets = vec![data(format!("command={command}\n"))];
    for capability in capabilities {
        packets.push(data(format!("{capability}\n")));
    }
    packets.push(Packet::Delimiter);
    if command == "fetch" {
        packets.push(repo.want(""));
        packets.push(data(b"done\n"));
    }
    packets.push(Packet::Flush);
    encode_packets(&packets, &WireLimits::default()).unwrap()
}

fn collect(
    bytes: &[u8],
    chunk: usize,
    mut push: impl FnMut(&[u8]) -> Result<Transition, WireError>,
) -> Result<Transition, WireError> {
    let mut result = Transition {
        output: Vec::new(),
        events: Vec::new(),
    };
    for fragment in bytes.chunks(chunk) {
        match push(fragment) {
            Ok(transition) => {
                result.output.extend(transition.output);
                result.events.extend(transition.events);
            }
            Err(error) => {
                assert!(
                    result.output.is_empty() && result.events.is_empty(),
                    "format refusal must precede all output and pack work",
                );
                return Err(error);
            }
        }
    }
    Ok(result)
}

fn selected_pack(result: &Transition) -> &PackRequest {
    match result.events.as_slice() {
        [WireEvent::PackRequested(request)] => request,
        other => panic!("one complete request must select one pack, got {other:?}"),
    }
}

fn assert_v2_result(repo: &Repository, command: &str, result: &Transition) {
    if command == "fetch" {
        assert_eq!(selected_pack(result).wants, vec![repo.refs[0].oid]);
    } else {
        assert!(matches!(
            result.events.as_slice(),
            [WireEvent::LsRefs { .. }]
        ));
        assert_eq!(
            result.output,
            vec![
                data(format!(
                    "{} refs/heads/main\n",
                    "11".repeat(repo.format.digest_len()),
                )),
                Packet::Flush,
            ],
        );
    }
}

#[test]
fn explicit_formats_match_and_opposite_formats_refuse_before_output() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let matching = repo.capability();
        let mismatched = format!("object-format={}", repo.opposite().as_str());
        let error = WireError::ObjectFormatMismatch {
            expected: format,
            observed: repo.opposite(),
        };
        for http in [false, true] {
            for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
                for (capability, accepted) in [(&matching, true), (&mismatched, false)] {
                    let bytes = legacy_request(&repo, Some(capability));
                    for chunk in [1, 3, bytes.len()] {
                        let mut machine = legacy(&repo, version, http);
                        let result =
                            collect(&bytes, chunk, |part| machine.push_bytes(part, &repo));
                        if accepted {
                            let result = result.expect("matching legacy format");
                            assert_eq!(selected_pack(&result).wants, vec![repo.refs[0].oid]);
                            assert_eq!(selected_pack(&result).version, version);
                            assert!(machine.is_complete());
                            machine.finish().unwrap();
                        } else {
                            assert_eq!(result, Err(error.clone()));
                            assert!(!machine.is_complete());
                        }
                    }
                }
            }
            for command in ["ls-refs", "fetch"] {
                for (capability, accepted) in [(&matching, true), (&mismatched, false)] {
                    let bytes = v2_request(&repo, command, &[capability]);
                    for chunk in [1, 3, bytes.len()] {
                        let mut machine = v2(&repo, http);
                        let result =
                            collect(&bytes, chunk, |part| machine.push_bytes(part, &repo));
                        if accepted {
                            assert_v2_result(&repo, command, &result.expect("matching v2 format"));
                            machine.finish().unwrap();
                        } else {
                            assert_eq!(result, Err(error.clone()));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn absent_format_keeps_the_existing_adapter_selected_profile() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for http in [false, true] {
            for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
                let mut machine = legacy(&repo, version, http);
                let result = machine
                    .push_bytes(&legacy_request(&repo, None), &repo)
                    .expect("omission keeps the existing typed profile");
                assert_eq!(selected_pack(&result).wants, vec![repo.refs[0].oid]);
            }
            for command in ["ls-refs", "fetch"] {
                let mut machine = v2(&repo, http);
                let result = machine
                    .push_bytes(&v2_request(&repo, command, &[]), &repo)
                    .expect("omission keeps the existing typed profile");
                assert_v2_result(&repo, command, &result);
            }
        }
    }
}

#[test]
fn missing_empty_and_unknown_explicit_values_are_refused() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for capability in [
            "object-format",
            "object-format=",
            "object-format=sha512",
            "object-format=SHA1",
            "object-format=sha1=sha256",
        ] {
            let error = WireError::MalformedRequestLine {
                line: capability.as_bytes().to_vec(),
            };
            for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
                let bytes = legacy_request(&repo, Some(capability));
                for chunk in [1, bytes.len()] {
                    let mut machine = legacy(&repo, version, false);
                    assert_eq!(
                        collect(&bytes, chunk, |part| machine.push_bytes(part, &repo)),
                        Err(error.clone()),
                    );
                }
            }
            for command in ["ls-refs", "fetch"] {
                let bytes = v2_request(&repo, command, &[capability]);
                for chunk in [1, bytes.len()] {
                    let mut machine = v2(&repo, false);
                    assert_eq!(
                        collect(&bytes, chunk, |part| machine.push_bytes(part, &repo)),
                        Err(error.clone()),
                    );
                }
            }
        }
        let capability = "object-format=sha1 sha256";
        let mut machine = v2(&repo, false);
        assert_eq!(
            machine.push_bytes(&v2_request(&repo, "ls-refs", &[capability]), &repo),
            Err(WireError::MalformedRequestLine {
                line: capability.as_bytes().to_vec(),
            }),
        );
    }
}

#[test]
fn duplicate_formats_remain_refused_without_hiding_the_matching_twin() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let matching = repo.capability();
        let duplicate = format!("{matching} {matching}");
        let error = WireError::DuplicateCapability {
            name: b"object-format".to_vec(),
        };
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let mut machine = legacy(&repo, version, false);
            assert_eq!(
                machine.push_bytes(&legacy_request(&repo, Some(&duplicate)), &repo),
                Err(error.clone()),
            );
            let mut machine = legacy(&repo, version, false);
            let result = machine
                .push_bytes(&legacy_request(&repo, Some(&matching)), &repo)
                .unwrap();
            assert_eq!(selected_pack(&result).wants, vec![repo.refs[0].oid]);
        }
        for command in ["ls-refs", "fetch"] {
            let mut machine = v2(&repo, false);
            assert_eq!(
                machine.push_bytes(&v2_request(&repo, command, &[&matching, &matching]), &repo),
                Err(error.clone()),
            );
            let mut machine = v2(&repo, false);
            let result = machine
                .push_bytes(&v2_request(&repo, command, &[&matching]), &repo)
                .unwrap();
            assert_v2_result(&repo, command, &result);
        }
    }
}

#[test]
fn legacy_format_refusal_installs_no_flags_or_want_state() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let mut machine = legacy(&repo, version, false);
            let suffix = format!(
                " multi_ack_detailed side-band-64k thin-pack include-tag ofs-delta \
                 no-progress no-done deepen-relative object-format={}",
                repo.opposite().as_str(),
            );
            assert_eq!(
                machine.push_packet(&repo.want(&suffix), &repo),
                Err(WireError::ObjectFormatMismatch {
                    expected: format,
                    observed: repo.opposite(),
                }),
            );
            let transition = machine
                .push_packet(&repo.want(&format!(" {}", repo.capability())), &repo)
                .expect("refused packet did not install a capability suffix or want");
            assert!(transition.output.is_empty() && transition.events.is_empty());
            let transition = machine.push_packet(&Packet::Flush, &repo).unwrap();
            assert!(transition.output.is_empty(), "no failed-request ACK mode remains");
            assert_eq!(
                machine.push_packet(&Packet::Flush, &repo),
                Err(WireError::IllegalTransition {
                    state: "legacy have phase",
                    packet: "flush",
                }),
                "no failed-request no-done flag remains",
            );
            let result = machine.push_packet(&data(b"done\n"), &repo).unwrap();
            let request = selected_pack(&result);
            assert_eq!(request.wants, vec![repo.refs[0].oid]);
            assert_eq!(request.options, PackOptions::NONE);
        }
    }
}

#[test]
fn v2_format_refusal_does_not_store_a_capability_or_advance_the_phase() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        for command in ["ls-refs", "fetch"] {
            let mut machine = v2(&repo, false);
            let started = machine
                .push_packet(&data(format!("command={command}\n")), &repo)
                .unwrap();
            assert!(started.output.is_empty() && started.events.is_empty());
            assert_eq!(
                machine.push_packet(
                    &data(format!("object-format={}\n", repo.opposite().as_str())),
                    &repo,
                ),
                Err(WireError::ObjectFormatMismatch {
                    expected: format,
                    observed: repo.opposite(),
                }),
            );
            let accepted = machine
                .push_packet(&data(format!("{}\n", repo.capability())), &repo)
                .expect("format refusal did not store a duplicate or advance to arguments");
            assert!(accepted.output.is_empty() && accepted.events.is_empty());
            machine.push_packet(&Packet::Delimiter, &repo).unwrap();
            if command == "fetch" {
                machine.push_packet(&repo.want(""), &repo).unwrap();
                machine.push_packet(&data(b"done\n"), &repo).unwrap();
            }
            let result = machine.push_packet(&Packet::Flush, &repo).unwrap();
            assert_v2_result(&repo, command, &result);
        }
    }
}

#[test]
fn stateful_v2_commands_keep_their_existing_omitted_format_behavior() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let mut machine = v2(&repo, false);
        let first = machine
            .push_bytes(&v2_request(&repo, "ls-refs", &[&repo.capability()]), &repo)
            .unwrap();
        assert_v2_result(&repo, "ls-refs", &first);
        assert!(machine.is_awaiting_command());
        let second = machine
            .push_bytes(&v2_request(&repo, "fetch", &[]), &repo)
            .expect("next command keeps the same selected native domain");
        assert_v2_result(&repo, "fetch", &second);
    }
}

#[test]
fn a_matching_format_does_not_authorize_an_unadvertised_capability() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repo = Repository::new(format);
        let matching = repo.capability();
        let error = WireError::UnknownCapability {
            capability: b"object-format".to_vec(),
        };
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let mut machine = LegacyUploadPack::new(
                version,
                Capabilities::default(),
                WireLimits::default(),
            )
            .unwrap();
            assert_eq!(
                machine.push_bytes(&legacy_request(&repo, Some(&matching)), &repo),
                Err(error.clone()),
            );
            let mut machine = LegacyUploadPack::new(
                version,
                Capabilities::default(),
                WireLimits::default(),
            )
            .unwrap();
            let result = machine
                .push_bytes(&legacy_request(&repo, None), &repo)
                .expect("no unadvertised capability was requested");
            assert_eq!(selected_pack(&result).wants, vec![repo.refs[0].oid]);
        }
        for command in ["ls-refs", "fetch"] {
            let limits = WireLimits::default();
            let caps = Capabilities::parse_v1(b"ls-refs fetch", &limits).unwrap();
            let mut machine = V2UploadPack::new(caps.clone(), limits.clone()).unwrap();
            assert_eq!(
                machine.push_bytes(&v2_request(&repo, command, &[&matching]), &repo),
                Err(error.clone()),
            );
            let mut machine = V2UploadPack::new(caps, limits).unwrap();
            let result = machine
                .push_bytes(&v2_request(&repo, command, &[]), &repo)
                .expect("no unadvertised capability was requested");
            assert_v2_result(&repo, command, &result);
        }
    }
}
