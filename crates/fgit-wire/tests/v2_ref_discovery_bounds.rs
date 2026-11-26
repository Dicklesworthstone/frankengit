#![forbid(unsafe_code)]
//! Ref discovery must preserve a raw-byte OR query while bounding comparison
//! work and observing the same live request as fetch negotiation.
use std::cell::Cell;

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, Transition,
    UploadPackRepository, V2UploadPack, WireError, WireEvent, WireLimits,
};

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    unborn: Option<Vec<u8>>,
    live_checks: Cell<Option<usize>>,
    checks: Cell<usize>,
}

impl Repository {
    fn new(format: GitObjectFormat, mut names: Vec<Vec<u8>>) -> Self {
        names.sort_unstable();
        names.dedup();
        let oid = AnyGitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap();
        Self {
            format,
            refs: names
                .iter()
                .map(|name| AdvertisedRef::new(oid, name, &WireLimits::default()).unwrap())
                .collect(),
            unborn: None,
            live_checks: Cell::new(None),
            checks: Cell::new(0),
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
    fn is_common(&self, _: AnyGitOid) -> bool {
        false
    }
    fn negotiation_checkpoint(&self) -> Result<(), WireError> {
        self.checks.set(self.checks.get() + 1);
        if let Some(remaining) = self.live_checks.get() {
            if remaining == 0 {
                return Err(WireError::PackSourceRefused);
            }
            self.live_checks.set(Some(remaining - 1));
        }
        Ok(())
    }
    fn unborn_symref_target(&self) -> Option<&[u8]> {
        self.unborn.as_deref()
    }
}

fn data(bytes: impl AsRef<[u8]>) -> Packet {
    let mut bytes = bytes.as_ref().to_vec();
    bytes.push(b'\n');
    Packet::Data(bytes)
}

fn machine(format: GitObjectFormat, limits: WireLimits) -> V2UploadPack {
    let capabilities = Capabilities::parse_v2_advertisement(
        &[
            data(b"version 2"),
            data(b"ls-refs=unborn"),
            data(format!("object-format={}", format.as_str())),
            Packet::Flush,
        ],
        &limits,
    )
    .unwrap();
    V2UploadPack::new(capabilities, limits).unwrap()
}

fn start(machine: &mut V2UploadPack, repository: &Repository, prefixes: &[Vec<u8>]) {
    for packet in [
        data(b"command=ls-refs"),
        data(format!("object-format={}", repository.format.as_str())),
        Packet::Delimiter,
        data(b"unborn"),
    ] {
        assert_eq!(
            machine.push_packet(&packet, repository).unwrap(),
            Transition {
                output: vec![],
                events: vec![],
            }
        );
    }
    for prefix in prefixes {
        let mut line = b"ref-prefix ".to_vec();
        line.extend_from_slice(prefix);
        assert_eq!(
            machine.push_packet(&data(line), repository).unwrap(),
            Transition {
                output: vec![],
                events: vec![],
            }
        );
    }
}

/// Deliberately simple scalar oracle: no sorting, compaction or prefix index.
fn oracle(repository: &Repository, prefixes: &[Vec<u8>]) -> Vec<Packet> {
    let matches =
        |name: &[u8]| prefixes.is_empty() || prefixes.iter().any(|prefix| name.starts_with(prefix));
    let mut output = Vec::new();
    if matches(b"HEAD")
        && let Some(target) = &repository.unborn
    {
        let mut line = b"unborn HEAD symref-target:".to_vec();
        line.extend_from_slice(target);
        output.push(data(line));
    }
    for reference in &repository.refs {
        if matches(&reference.name) {
            let mut line = format!("{} ", reference.oid).into_bytes();
            line.extend_from_slice(&reference.name);
            output.push(data(line));
        }
    }
    output.push(Packet::Flush);
    output
}

fn complete(
    machine: &mut V2UploadPack,
    repository: &Repository,
    prefixes: &[Vec<u8>],
) -> Transition {
    start(machine, repository, prefixes);
    machine.push_packet(&Packet::Flush, repository).unwrap()
}

fn assert_query(transition: &Transition, repository: &Repository, prefixes: &[Vec<u8>]) {
    assert_eq!(transition.output, oracle(repository, prefixes));
    assert_eq!(
        transition.events,
        vec![WireEvent::LsRefs {
            prefixes: prefixes.to_vec(),
            symrefs: false,
            peel: false,
            unborn: true,
        }]
    );
}

#[test]
fn indexed_raw_prefix_queries_equal_the_naive_oracle_in_both_hash_domains() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut names = [
            b"HEAD".as_slice(),
            b"refs/heads/a",
            b"refs/heads/a0",
            b"refs/heads/ab",
            b"refs/heads/main",
            b"refs/heads/nested/topic",
            b"refs/tags/v1",
            b"refs/tags/v10",
            b"refs/tags/v2",
            b"refs/\x80/topic",
            b"refs/\xff/topic",
        ]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
        names.extend((0..512).map(|index| format!("refs/heads/generated-{index:04}").into_bytes()));
        let repository = Repository::new(format, names);
        let mut wire = machine(format, WireLimits::default());
        let mut queries = vec![
            vec![],
            vec![b"refs/heads/a".to_vec(), b"refs/tags/v".to_vec()],
            vec![
                b"refs/heads/ab".to_vec(),
                b"refs/heads/".to_vec(),
                b"refs/heads/a".to_vec(),
                b"refs/heads/ab".to_vec(),
            ],
            vec![b"refs/\xff/".to_vec(), b"refs/\x80".to_vec()],
            vec![b"HEAD".to_vec(), b"refs/".to_vec()],
            vec![b"refs/heads0".to_vec(), b"refs/tags/v3".to_vec()],
        ];
        // The exact default argument bound, reversed and overlapping, retains
        // request order and duplicates even though matching can compact it.
        queries.push(
            (0..512)
                .rev()
                .flat_map(|index| {
                    let name = format!("refs/heads/generated-{index:04}").into_bytes();
                    [name.clone(), name]
                })
                .collect(),
        );
        for prefixes in &queries {
            let first = complete(&mut wire, &repository, prefixes);
            assert_query(&first, &repository, prefixes);
            assert_eq!(complete(&mut wire, &repository, prefixes), first);
        }
    }
}

#[test]
fn absent_prefix_arguments_select_all_but_an_empty_argument_is_still_invalid() {
    let format = GitObjectFormat::Sha1;
    let repository = Repository::new(format, vec![b"refs/heads/main".to_vec()]);
    let mut wire = machine(format, WireLimits::default());
    assert_query(&complete(&mut wire, &repository, &[]), &repository, &[]);
    start(&mut wire, &repository, &[]);
    assert_eq!(
        wire.push_packet(&data(b"ref-prefix "), &repository),
        Err(WireError::RefNameTooLarge {
            limit: WireLimits::default().max_ref_name_bytes
        })
    );
}

#[test]
fn unborn_head_uses_the_same_byte_prefix_query_and_command_reset() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = Repository::new(format, vec![]);
        repository.unborn = Some(b"refs/heads/\xfftrunk".to_vec());
        let mut wire = machine(format, WireLimits::default());
        for prefixes in [
            vec![b"refs/heads/".to_vec()],
            vec![b"HEAD".to_vec(), b"HE".to_vec(), b"HEAD".to_vec()],
            vec![],
            vec![b"HEADe".to_vec()],
        ] {
            assert_query(
                &complete(&mut wire, &repository, &prefixes),
                &repository,
                &prefixes,
            );
        }
    }
}

#[test]
fn every_ref_discovery_checkpoint_refuses_without_a_partial_response() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for prefixes in [vec![], vec![b"not-a-visible-ref".to_vec()]] {
            let repository = Repository::new(
                format,
                (0..8)
                    .map(|index| format!("refs/heads/topic-{index}").into_bytes())
                    .collect(),
            );
            let mut accepted = machine(format, WireLimits::default());
            let expected = complete(&mut accepted, &repository, &prefixes);
            assert_query(&expected, &repository, &prefixes);
            let checkpoints = repository.checks.get();
            assert!(
                checkpoints >= 2 * repository.refs.len() + 2,
                "validation and selection must each remain cancellable, including excluded refs"
            );
            for available in 0..checkpoints {
                repository.checks.set(0);
                repository.live_checks.set(Some(available));
                let mut wire = machine(format, WireLimits::default());
                start(&mut wire, &repository, &prefixes);
                assert_eq!(
                    wire.push_packet(&Packet::Flush, &repository),
                    Err(WireError::PackSourceRefused),
                    "cancellation after {available} live checkpoints"
                );
                assert_eq!(repository.checks.get(), available + 1);
                // A refused response has not reset or changed the request.
                // An independently live twin produces exactly the same bytes.
                repository.live_checks.set(None);
                assert_eq!(
                    wire.push_packet(&Packet::Flush, &repository).unwrap(),
                    expected
                );
            }
        }
    }
}

#[test]
fn ref_discovery_preserves_advertisement_and_output_limits() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(
            format,
            vec![b"refs/heads/a".to_vec(), b"refs/heads/b".to_vec()],
        );
        let prefixes = vec![b"refs/heads/a".to_vec(), b"refs/".to_vec()];
        let mut permitted = machine(format, WireLimits::default());
        let expected = complete(&mut permitted, &repository, &prefixes);
        assert_query(&expected, &repository, &prefixes);
        let mut count_limited = machine(
            format,
            WireLimits {
                max_advertised_refs: 1,
                ..WireLimits::default()
            },
        );
        start(&mut count_limited, &repository, &prefixes);
        assert_eq!(
            count_limited.push_packet(&Packet::Flush, &repository),
            Err(WireError::TooManyAdvertisedRefs { limit: 1 })
        );
        let mut output_limited = machine(
            format,
            WireLimits {
                max_outbound_bytes: 4,
                ..WireLimits::default()
            },
        );
        start(&mut output_limited, &repository, &prefixes);
        assert_eq!(
            output_limited.push_packet(&Packet::Flush, &repository),
            Err(WireError::OutboundBytesExceeded { limit: 4 })
        );
        let mut unsorted = Repository::new(
            format,
            vec![b"refs/heads/a".to_vec(), b"refs/heads/b".to_vec()],
        );
        unsorted.refs.swap(0, 1);
        let mut refused = machine(format, WireLimits::default());
        start(&mut refused, &unsorted, &[b"unmatched".to_vec()]);
        assert_eq!(
            refused.push_packet(&Packet::Flush, &unsorted),
            Err(WireError::UnsortedOrDuplicateAdvertisement),
            "prefix exclusion must not hide invalid repository metadata"
        );
    }
}
