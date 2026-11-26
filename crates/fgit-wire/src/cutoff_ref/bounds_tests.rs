//! Scalar-oracle and live-request controls for advertised-only shallow exclusions.
use std::cell::Cell;

use super::resolve;
use crate::visibility::{RefVisibility, VisibleUploadPackRepository};
use crate::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, Packet, Transition,
    UploadPackRepository, UploadPackVersion, V2UploadPack, WireError, WireEvent, WireLimits,
};

#[derive(Clone)]
struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    sorted: bool,
    remaining: Cell<Option<usize>>,
    checks: Cell<usize>,
}

impl Repository {
    fn new(format: GitObjectFormat, mut refs: Vec<AdvertisedRef>, sorted: bool) -> Self {
        if sorted {
            // Stable ordering keeps duplicate-name error precedence explicit.
            refs.sort_by(|left, right| left.name.cmp(&right.name));
        }
        Self {
            format,
            refs,
            sorted,
            remaining: Cell::new(None),
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
    fn sorted_advertised_refs(&self) -> Option<&[AdvertisedRef]> {
        self.sorted.then_some(self.refs.as_slice())
    }
    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.refs.iter().any(|reference| reference.oid == oid)
    }
    fn is_common(&self, _: AnyGitOid) -> bool {
        false
    }
    fn resolve_ref(&self, _: &[u8]) -> Option<AnyGitOid> {
        panic!("a general-purpose resolver must not authorize deepen-not")
    }
    fn negotiation_checkpoint(&self) -> Result<(), WireError> {
        self.checks.set(self.checks.get() + 1);
        if let Some(remaining) = self.remaining.get() {
            if remaining == 0 {
                return Err(WireError::PackSourceRefused);
            }
            self.remaining.set(Some(remaining - 1));
        }
        Ok(())
    }
}

fn oid(format: GitObjectFormat, byte: u8) -> AnyGitOid {
    AnyGitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}

fn reference(name: impl AsRef<[u8]>, oid: AnyGitOid) -> AdvertisedRef {
    AdvertisedRef::new(oid, name.as_ref(), &WireLimits::default()).unwrap()
}

/// Independent oracle deliberately constructs all full candidate names, then
/// visits the original advertisement in order without using an index or hint.
fn expanded_names(name: &[u8]) -> [Vec<u8>; 6] {
    [
        name.to_vec(),
        [b"refs/".as_slice(), name].concat(),
        [b"refs/tags/".as_slice(), name].concat(),
        [b"refs/heads/".as_slice(), name].concat(),
        [b"refs/remotes/".as_slice(), name].concat(),
        [b"refs/remotes/".as_slice(), name, b"/HEAD"].concat(),
    ]
}

fn oracle(repository: &Repository, name: &[u8]) -> Result<AnyGitOid, WireError> {
    let candidates = expanded_names(name);
    let unknown = || WireError::UnknownDeepenNotRef {
        name: name.to_vec(),
    };
    let mut found = None;
    for reference in &repository.refs {
        if candidates
            .iter()
            .any(|candidate| *candidate == reference.name)
        {
            if found.is_some() {
                return Err(unknown());
            }
            if reference.oid.algorithm() != repository.format {
                return Err(WireError::ObjectFormatMismatch {
                    expected: repository.format,
                    observed: reference.oid.algorithm(),
                });
            }
            found = Some(reference.oid);
        }
    }
    found.ok_or_else(unknown)
}

#[test]
fn all_six_expansions_and_ambiguity_match_an_independent_byte_oracle() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for name in [
            b"topic".as_slice(),
            b"heads/topic",
            b"HEAD",
            b"\x80topic",
            b"\xff/topic",
        ] {
            let candidates = expanded_names(name);
            for mask in 0_u8..64 {
                let mut refs = vec![
                    reference(b"refs/heads/unrelated", oid(format, 1)),
                    reference(b"refs/heads/\x7d-neighbor", oid(format, 1)),
                    reference(b"refs/heads/\xff-neighbor", oid(format, 1)),
                ];
                for (index, candidate) in candidates.iter().enumerate() {
                    if mask & (1 << index) != 0 {
                        // Equal targets do not erase distinct-name ambiguity.
                        refs.push(reference(candidate, oid(format, 2)));
                    }
                }
                refs.reverse();
                for sorted in [false, true] {
                    let repository = Repository::new(format, refs.clone(), sorted);
                    assert_eq!(
                        resolve(&repository, name, &WireLimits::default()),
                        oracle(&repository, name),
                        "format={format:?} sorted={sorted} mask={mask} name={name:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn duplicate_rows_and_hash_errors_keep_advertisement_order_precedence() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let other = if format == GitObjectFormat::Sha1 {
            GitObjectFormat::Sha256
        } else {
            GitObjectFormat::Sha1
        };
        let valid = oid(format, 1);
        let wrong = oid(other, 2);
        let cases = [
            vec![
                reference(b"refs/heads/topic", wrong),
                reference(b"refs/tags/topic", valid),
            ],
            vec![
                reference(b"refs/heads/topic", valid),
                reference(b"refs/tags/topic", wrong),
            ],
            vec![
                reference(b"refs/heads/topic", valid),
                reference(b"refs/heads/topic", wrong),
            ],
            vec![
                reference(b"refs/heads/topic", wrong),
                reference(b"refs/heads/topic", valid),
            ],
            vec![
                reference(b"refs/heads/topic", valid),
                reference(b"refs/heads/unrelated", wrong),
            ],
            vec![reference(b"refs/heads/topic", wrong)],
        ];
        for refs in cases {
            for reverse in [false, true] {
                let mut refs = refs.clone();
                if reverse {
                    refs.reverse();
                }
                for sorted in [false, true] {
                    let repository = Repository::new(format, refs.clone(), sorted);
                    assert_eq!(
                        resolve(&repository, b"topic", &WireLimits::default()),
                        oracle(&repository, b"topic"),
                        "sorted={sorted} reverse={reverse}"
                    );
                }
            }
        }
    }
}

#[test]
fn sorted_lookups_obey_a_logarithmic_checkpoint_work_bound() {
    let format = GitObjectFormat::Sha1;
    let count = 16_384_usize;
    let refs = (0..count)
        .map(|index| reference(format!("refs/heads/topic-{index:05}"), oid(format, 1)))
        .collect();
    let repository = Repository::new(format, refs, true);
    let levels = usize::BITS - count.leading_zeros();
    for name in [b"topic-00000".as_slice(), b"topic-16383", b"not-present"] {
        repository.checks.set(0);
        assert_eq!(
            resolve(&repository, name, &WireLimits::default()),
            oracle(&repository, name)
        );
        assert!(
            repository.checks.get() <= 2 + 6 * (levels as usize + 1),
            "a sorted lookup must not rescan the full advertisement: {} checks",
            repository.checks.get()
        );
    }
    let limits = WireLimits {
        max_advertised_refs: count - 1,
        ..WireLimits::default()
    };
    assert_eq!(
        resolve(&repository, b"topic-00000", &limits),
        Err(WireError::TooManyAdvertisedRefs { limit: count - 1 })
    );
    let mut fallback = repository.clone();
    fallback.sorted = false;
    fallback.checks.set(0);
    resolve(&fallback, b"topic-00000", &WireLimits::default()).unwrap();
    assert_eq!(fallback.checks.get(), count + 2);
}

#[test]
fn every_lookup_checkpoint_can_refuse_matches_misses_and_ambiguity() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for sorted in [false, true] {
            let repository = Repository::new(
                format,
                vec![
                    reference(b"refs/tags/ambiguous", oid(format, 1)),
                    reference(b"refs/heads/stop", oid(format, 2)),
                    reference(b"refs/heads/ambiguous", oid(format, 1)),
                    reference(b"refs/heads/unrelated", oid(format, 3)),
                ],
                sorted,
            );
            for name in [b"stop".as_slice(), b"missing", b"ambiguous"] {
                repository.checks.set(0);
                let expected = oracle(&repository, name);
                assert_eq!(resolve(&repository, name, &WireLimits::default()), expected);
                let checkpoints = repository.checks.get();
                for available in 0..checkpoints {
                    repository.checks.set(0);
                    repository.remaining.set(Some(available));
                    assert_eq!(
                        resolve(&repository, name, &WireLimits::default()),
                        Err(WireError::PackSourceRefused),
                        "sorted={sorted} name={name:?} available={available}"
                    );
                    assert_eq!(repository.checks.get(), available + 1);
                    repository.remaining.set(None);
                    assert_eq!(resolve(&repository, name, &WireLimits::default()), expected);
                }
            }
            let empty = Repository::new(format, vec![], sorted);
            empty.remaining.set(Some(0));
            assert_eq!(
                resolve(&empty, b"missing", &WireLimits::default()),
                Err(WireError::PackSourceRefused)
            );
        }
    }
}

#[test]
fn filtered_sorted_hints_never_restore_hidden_aliases() {
    for sorted in [false, true] {
        let format = GitObjectFormat::Sha256;
        let repository = Repository::new(
            format,
            vec![
                reference(b"refs/tags/topic", oid(format, 1)),
                reference(b"refs/heads/topic", oid(format, 1)),
                reference(b"refs/tags/secret", oid(format, 2)),
            ],
            sorted,
        );
        let mut visibility = RefVisibility::new();
        visibility
            .push_rule(b"refs/tags", &WireLimits::default())
            .unwrap();
        let visible = VisibleUploadPackRepository::new(&repository, &visibility);
        assert_eq!(
            visible.sorted_advertised_refs(),
            Some(visible.advertised_refs())
        );
        assert_eq!(
            resolve(&visible, b"topic", &WireLimits::default()).unwrap(),
            oid(format, 1)
        );
        assert_eq!(
            resolve(&visible, b"secret", &WireLimits::default()),
            Err(WireError::UnknownDeepenNotRef {
                name: b"secret".to_vec()
            })
        );
        repository.remaining.set(Some(0));
        assert_eq!(
            resolve(&visible, b"topic", &WireLimits::default()),
            Err(WireError::PackSourceRefused)
        );
    }
}

enum Machine {
    Legacy(LegacyUploadPack),
    V2(V2UploadPack),
}

fn packet(bytes: impl AsRef<[u8]>) -> Packet {
    let mut line = bytes.as_ref().to_vec();
    line.push(b'\n');
    Packet::Data(line)
}

impl Machine {
    fn new(version: UploadPackVersion, repository: &Repository) -> Self {
        let limits = WireLimits::default();
        let mut machine = if version == UploadPackVersion::V2 {
            let capabilities = Capabilities::parse_v2_advertisement(
                &[
                    packet(b"version 2"),
                    packet(b"fetch=shallow"),
                    Packet::Flush,
                ],
                &limits,
            )
            .unwrap();
            Self::V2(V2UploadPack::new(capabilities, limits).unwrap())
        } else {
            let capabilities = Capabilities::parse_v1(b"shallow deepen-not", &limits).unwrap();
            Self::Legacy(LegacyUploadPack::new(version, capabilities, limits).unwrap())
        };
        if version == UploadPackVersion::V2 {
            machine.push(&packet(b"command=fetch"), repository).unwrap();
            machine.push(&Packet::Delimiter, repository).unwrap();
        }
        machine
            .push(
                &packet(format!("want {}", oid(repository.format, 1))),
                repository,
            )
            .unwrap();
        machine
    }
    fn push(&mut self, packet: &Packet, repository: &Repository) -> Result<Transition, WireError> {
        match self {
            Self::Legacy(machine) => machine.push_packet(packet, repository),
            Self::V2(machine) => machine.push_packet(packet, repository),
        }
    }
    fn complete(&mut self, repository: &Repository) -> Transition {
        if matches!(self, Self::Legacy(_)) {
            self.push(&Packet::Flush, repository).unwrap();
            self.push(&packet(b"done"), repository).unwrap()
        } else {
            self.push(&packet(b"done"), repository).unwrap();
            self.push(&Packet::Flush, repository).unwrap()
        }
    }
}

#[test]
fn cancelled_exclusions_leave_all_protocol_versions_ready_for_an_exact_retry() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for sorted in [false, true] {
            let repository = Repository::new(
                format,
                vec![
                    reference(b"refs/heads/main", oid(format, 1)),
                    reference(b"refs/heads/stop", oid(format, 2)),
                ],
                sorted,
            );
            resolve(&repository, b"stop", &WireLimits::default()).unwrap();
            let checkpoints = repository.checks.get();
            for version in [
                UploadPackVersion::V0,
                UploadPackVersion::V1,
                UploadPackVersion::V2,
            ] {
                for available in 0..checkpoints {
                    let mut machine = Machine::new(version, &repository);
                    repository.checks.set(0);
                    repository.remaining.set(Some(available));
                    assert_eq!(
                        machine.push(&packet(b"deepen-not stop"), &repository),
                        Err(WireError::PackSourceRefused)
                    );
                    assert_eq!(repository.checks.get(), available + 1);
                    repository.remaining.set(None);
                    let accepted = machine
                        .push(&packet(b"deepen-not stop"), &repository)
                        .unwrap();
                    assert!(accepted.output.is_empty() && accepted.events.is_empty());
                    let transition = machine.complete(&repository);
                    let [WireEvent::PackRequested(request)] = transition.events.as_slice() else {
                        panic!("expected a single complete pack request")
                    };
                    assert_eq!(request.deepen_not, vec![oid(format, 2)]);
                }
            }
        }
    }
}
