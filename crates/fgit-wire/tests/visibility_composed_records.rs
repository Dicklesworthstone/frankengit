#![forbid(unsafe_code)]

//! Peeling and symbolic aliases must compose in one disclosure projection.

use std::cell::Cell;

use fgit_wire::visibility::{RefVisibility, VisibleUploadPackRepository};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, UploadPackRepository,
    V1Advertisement, WireLimits,
};

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    aliases: Vec<(&'static [u8], &'static [u8])>,
    later_refs: Option<Vec<AdvertisedRef>>,
    reads: Cell<usize>,
}

fn oid(format: GitObjectFormat, digit: char) -> AnyGitOid {
    AnyGitOid::from_hex(format, &digit.to_string().repeat(format.digest_len() * 2))
        .expect("fixture identity")
}

fn reference(format: GitObjectFormat, digit: char, name: &[u8]) -> AdvertisedRef {
    AdvertisedRef::new(oid(format, digit), name, &WireLimits::default())
        .expect("fixture reference")
}

fn repository(format: GitObjectFormat, shared: bool) -> Repository {
    Repository {
        format,
        refs: vec![
            reference(format, if shared { '3' } else { '1' }, b"refs/heads/main"),
            reference(format, '2', b"refs/private/tag"),
            reference(format, '3', b"refs/private/tag^{}"),
            reference(format, '2', b"refs/tags/alias"),
            reference(format, '3', b"refs/tags/alias^{}"),
        ],
        aliases: vec![(b"refs/tags/alias", b"refs/private/tag")],
        later_refs: None,
        reads: Cell::new(0),
    }
}

impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        let reads = self.reads.get();
        self.reads.set(reads + 1);
        if reads > 0 {
            if let Some(refs) = &self.later_refs {
                return refs;
            }
        }
        &self.refs
    }

    fn contains_want(&self, _oid: AnyGitOid) -> bool {
        true
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        true
    }

    fn symref_target(&self, name: &[u8]) -> Option<&[u8]> {
        self.aliases
            .iter()
            .find(|(alias, _)| *alias == name)
            .map(|(_, target)| *target)
    }
}

fn policy() -> RefVisibility {
    let mut visibility = RefVisibility::new();
    visibility
        .push_rule(b"refs/private", &WireLimits::default())
        .expect("hide private namespace");
    visibility
}

#[test]
fn indirectly_hidden_tag_does_not_leave_a_peeled_record_or_identity() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format, false);
        let view = VisibleUploadPackRepository::new(&repository, &policy());
        assert_eq!(view.advertised_refs(), &repository.refs[..1]);
        assert_eq!(view.resolve_ref(b"refs/tags/alias^{}"), None);
        assert_eq!(view.symref_target(b"refs/tags/alias"), None);
        for digit in ['2', '3'] {
            assert!(repository.contains_want(oid(format, digit)));
            assert!(!view.contains_want(oid(format, digit)));
            assert!(!view.is_common(oid(format, digit)));
        }
        assert!(view.contains_want(oid(format, '1')));
    }
}

#[test]
fn hidden_alias_pair_encodes_identically_to_its_absence() {
    let limits = WireLimits::default();
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format, false);
        let view = VisibleUploadPackRepository::new(&repository, &policy());
        let encode = |refs| {
            V1Advertisement::new(refs, Capabilities::default(), format, &limits)
                .expect("advertisement")
                .encode(&limits)
                .expect("encoded advertisement")
        };
        assert_eq!(
            encode(view.advertised_refs().to_vec()),
            encode(repository.refs[..1].to_vec())
        );
    }
}

#[test]
fn unhiding_the_target_restores_the_alias_and_its_peeled_record() {
    let limits = WireLimits::default();
    let mut visibility = policy();
    visibility
        .push_rule(b"!refs/private/tag", &limits)
        .expect("explicit exception");
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format, false);
        let view = VisibleUploadPackRepository::new(&repository, &visibility);
        assert_eq!(view.advertised_refs(), repository.refs.as_slice());
        assert_eq!(view.symref_target(b"refs/tags/alias"), Some(&b"refs/private/tag"[..]));
        assert!(view.contains_want(oid(format, '3')));
    }
}

#[test]
fn a_public_identity_shared_with_a_hidden_alias_remains_usable() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format, true);
        let view = VisibleUploadPackRepository::new(&repository, &policy());
        assert_eq!(view.advertised_refs(), &repository.refs[..1]);
        assert!(view.contains_want(oid(format, '3')));
        assert!(view.is_common(oid(format, '3')));
        assert!(!view.contains_want(oid(format, '2')));
    }
}

#[test]
fn hiding_propagates_through_multiple_aliases_to_every_peeled_record() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = repository(format, false);
        repository.refs.push(reference(format, '2', b"refs/tags/second"));
        repository.refs.push(reference(format, '3', b"refs/tags/second^{}"));
        repository.aliases.push((b"refs/tags/second", b"refs/tags/alias"));
        let view = VisibleUploadPackRepository::new(&repository, &policy());
        assert_eq!(view.advertised_refs(), &repository.refs[..1]);
        assert_eq!(view.resolve_ref(b"refs/tags/second^{}"), None);
        assert!(!view.contains_want(oid(format, '3')));
    }
}

#[test]
fn analysis_and_emission_use_the_same_single_advertised_snapshot() {
    let format = GitObjectFormat::Sha1;
    let mut repository = repository(format, false);
    repository.later_refs = Some(vec![reference(format, '4', b"refs/tags/injected")]);
    repository.aliases.push((b"refs/tags/injected", b"refs/private/tag"));
    let view = VisibleUploadPackRepository::new(&repository, &policy());
    assert_eq!(repository.reads.get(), 1, "do not reread between projection passes");
    assert_eq!(view.advertised_refs(), &repository.refs[..1]);
    assert_eq!(view.resolve_ref(b"refs/tags/injected"), None);
}
