#![forbid(unsafe_code)]
//! Legacy fetch authorization keeps the scalar membership rule while avoiding
//! a full advertised-ref scan for each want covered by an authorized closure.
//! Counting repository calls checks the work mechanism, not clone throughput.

use std::cell::Cell;
use std::collections::BTreeSet;

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, Packet, Transition,
    UploadPackRepository, UploadPackVersion, WireError, WireEvent, WireLimits,
};

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    permitted: BTreeSet<AnyGitOid>,
    advertisement_reads: Cell<usize>,
    closure_queries: Cell<usize>,
}

impl Repository {
    fn new(format: GitObjectFormat, advertised: &[u64], permitted: &[u64]) -> Self {
        let limits = WireLimits::default();
        Self {
            format,
            refs: advertised
                .iter()
                .map(|value| {
                    AdvertisedRef::new(
                        oid(format, *value),
                        format!("refs/heads/branch-{value:06}").as_bytes(),
                        &limits,
                    )
                    .unwrap()
                })
                .collect(),
            permitted: permitted.iter().map(|value| oid(format, *value)).collect(),
            advertisement_reads: Cell::new(0),
            closure_queries: Cell::new(0),
        }
    }
}

impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        self.advertisement_reads
            .set(self.advertisement_reads.get() + 1);
        &self.refs
    }

    fn contains_want(&self, id: AnyGitOid) -> bool {
        self.closure_queries.set(self.closure_queries.get() + 1);
        self.permitted.contains(&id)
    }

    fn is_common(&self, _id: AnyGitOid) -> bool {
        false
    }
}

fn oid(format: GitObjectFormat, value: u64) -> AnyGitOid {
    let width = format.digest_len() * 2;
    AnyGitOid::from_hex(format, &format!("{value:0width$x}")).unwrap()
}

fn want(id: AnyGitOid, capabilities: &str) -> Packet {
    let suffix = if capabilities.is_empty() {
        String::new()
    } else {
        format!(" {capabilities}")
    };
    Packet::Data(format!("want {id}{suffix}\n").into_bytes())
}

fn machine(
    format: GitObjectFormat,
    version: UploadPackVersion,
    http: bool,
    reachable: bool,
    limits: WireLimits,
) -> LegacyUploadPack {
    let extension = if reachable {
        " allow-reachable-sha1-in-want"
    } else {
        ""
    };
    let capabilities = Capabilities::parse_v1(
        format!("thin-pack object-format={}{}", format.as_str(), extension).as_bytes(),
        &limits,
    )
    .unwrap();
    let machine = LegacyUploadPack::new(version, capabilities, limits).unwrap();
    if http {
        machine.with_stateless_http_rounds()
    } else {
        machine
    }
}

fn empty() -> Transition {
    Transition {
        output: Vec::new(),
        events: Vec::new(),
    }
}

#[test]
fn legacy_wants_match_the_original_linear_authorization_and_refusal_order() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let opposite = match format {
            GitObjectFormat::Sha1 => GitObjectFormat::Sha256,
            GitObjectFormat::Sha256 => GitObjectFormat::Sha1,
        };
        let mismatched_format = format!("object-format={}", opposite.as_str());
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for http in [false, true] {
                for reachable in [false, true] {
                    // 1: advertised only (the low-level adapter fallback).
                    // 2: authorized ancestor only. 3: both. 4 and 5 model
                    // hidden and absent objects: neither grants disclosure.
                    for value in 1..=5 {
                        for (suffix, authorized_result) in [
                            ("", Ok(empty())),
                            ("thin-pack", Ok(empty())),
                            (
                                "unknown",
                                Err(WireError::UnknownCapability {
                                    capability: b"unknown".to_vec(),
                                }),
                            ),
                            (
                                "thin-pack thin-pack",
                                Err(WireError::DuplicateCapability {
                                    name: b"thin-pack".to_vec(),
                                }),
                            ),
                            (
                                mismatched_format.as_str(),
                                Err(WireError::ObjectFormatMismatch {
                                    expected: format,
                                    observed: opposite,
                                }),
                            ),
                        ] {
                            let repository = Repository::new(format, &[1, 3], &[2, 3]);
                            let id = oid(format, value);
                            // This is the original scalar predicate, evaluated
                            // directly over fixture facts, without the optimized
                            // repository callbacks or protocol implementation.
                            let allowed = repository.refs.iter().any(|entry| entry.oid == id)
                                || (reachable && repository.permitted.contains(&id));
                            let expected = if allowed {
                                authorized_result
                            } else {
                                Err(WireError::WantNotAdvertised { oid: id })
                            };
                            let mut machine =
                                machine(format, version, http, reachable, WireLimits::default());
                            assert_eq!(
                                machine.push_packet(&want(id, suffix), &repository),
                                expected,
                                "{format:?} {version:?} http={http} reachable={reachable} \
                                 oid={value} capabilities={suffix:?}",
                            );
                            if !reachable {
                                assert_eq!(repository.closure_queries.get(), 0);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn indexed_reachable_wants_do_not_rescan_large_advertisements_or_reorder_the_pack() {
    let advertised: Vec<_> = (1..=8_192).collect();
    let values: Vec<_> = (7_169..=8_192).rev().collect();
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for http in [false, true] {
                let repository = Repository::new(format, &advertised, &advertised);
                let limits = WireLimits {
                    max_wants: values.len(),
                    ..WireLimits::default()
                };
                let mut machine = machine(format, version, http, true, limits);
                let expected: Vec<_> = values.iter().map(|value| oid(format, *value)).collect();
                for (index, id) in expected.iter().enumerate() {
                    assert_eq!(
                        machine.push_packet(&want(*id, ""), &repository),
                        Ok(empty()),
                    );
                    if index % 8 == 0 {
                        assert_eq!(
                            machine.push_packet(&want(*id, ""), &repository),
                            Ok(empty()),
                        );
                    }
                }
                // A duplicate remains idempotent even at the distinct-want bound.
                assert_eq!(
                    machine.push_packet(&want(expected[0], ""), &repository),
                    Ok(empty()),
                );
                assert_eq!(repository.closure_queries.get(), 1_024 + 128 + 1);
                assert_eq!(
                    repository.advertisement_reads.get(),
                    0,
                    "every successful want used the already-authorized closure",
                );
                assert_eq!(
                    machine.push_packet(&Packet::Flush, &repository),
                    Ok(empty())
                );
                let result = machine
                    .push_packet(&Packet::Data(b"done\n".to_vec()), &repository)
                    .unwrap();
                assert_eq!(result.output, vec![Packet::Data(b"NAK\n".to_vec())]);
                let [WireEvent::PackRequested(request)] = result.events.as_slice() else {
                    panic!("complete negotiation must select one pack: {result:?}");
                };
                assert_eq!(request.version, version);
                assert_eq!(request.wants, expected);
                assert!(request.haves.is_empty());
                assert!(machine.is_complete());
            }
        }
    }
}

#[test]
fn authorization_still_precedes_duplicate_capabilities_and_the_want_limit() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            for http in [false, true] {
                let repository = Repository::new(format, &[1], &[1, 2]);
                for (value, suffix, expected) in [
                    (1, "", Ok(empty())),
                    (
                        2,
                        "",
                        Err(WireError::TooManyObjectIds {
                            field: "want",
                            limit: 1,
                        }),
                    ),
                    (
                        2,
                        "thin-pack",
                        Err(WireError::MalformedRequestLine {
                            line: format!("{} thin-pack", oid(format, 2)).into_bytes(),
                        }),
                    ),
                    (
                        3,
                        "thin-pack",
                        Err(WireError::WantNotAdvertised {
                            oid: oid(format, 3),
                        }),
                    ),
                ] {
                    let limits = WireLimits {
                        max_wants: 1,
                        ..WireLimits::default()
                    };
                    let mut machine = machine(format, version, http, true, limits);
                    assert_eq!(
                        machine.push_packet(&want(oid(format, 1), "thin-pack"), &repository),
                        Ok(empty()),
                    );
                    assert_eq!(
                        machine.push_packet(&want(oid(format, value), suffix), &repository),
                        expected,
                    );
                }
            }
        }
    }
}

#[test]
fn malformed_and_cross_domain_wants_never_query_repository_membership() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let opposite = match format {
            GitObjectFormat::Sha1 => GitObjectFormat::Sha256,
            GitObjectFormat::Sha256 => GitObjectFormat::Sha1,
        };
        for reachable in [false, true] {
            for id in ["not-an-oid".to_owned(), oid(opposite, 1).to_string()] {
                let repository = Repository::new(format, &[1], &[1]);
                let mut machine = machine(
                    format,
                    UploadPackVersion::V0,
                    false,
                    reachable,
                    WireLimits::default(),
                );
                assert_eq!(
                    machine.push_packet(
                        &Packet::Data(format!("want {id} unknown\n").into_bytes()),
                        &repository,
                    ),
                    Err(WireError::InvalidObjectId { algorithm: format }),
                );
                assert_eq!(repository.closure_queries.get(), 0);
                assert_eq!(repository.advertisement_reads.get(), 0);
            }
        }
    }
}
