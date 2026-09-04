#![forbid(unsafe_code)]

//! Symbolic metadata is part of the same disclosure decision as ref tips.

use std::cell::Cell;

use fgit_wire::visibility::{RefVisibility, VisibleUploadPackRepository};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, UploadPackRepository,
    V2UploadPack, WireLimits,
};

fn oid(format: GitObjectFormat, digit: char) -> AnyGitOid {
    let width = match format {
        GitObjectFormat::Sha1 => 40,
        GitObjectFormat::Sha256 => 64,
    };
    AnyGitOid::from_hex(format, &digit.to_string().repeat(width)).expect("fixture object id")
}

struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
    aliases: Vec<(Vec<u8>, Vec<u8>)>,
    unborn: Option<Vec<u8>>,
    lookups: Cell<usize>,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        Self {
            format,
            refs: Vec::new(),
            aliases: Vec::new(),
            unborn: None,
            lookups: Cell::new(0),
        }
    }

    fn reference(&mut self, name: &[u8], digit: char) {
        self.refs.push(
            AdvertisedRef::new(oid(self.format, digit), name, &WireLimits::default())
                .expect("fixture ref"),
        );
    }

    fn alias(&mut self, name: &[u8], target: &[u8]) {
        self.aliases.push((name.to_vec(), target.to_vec()));
    }
}

impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    fn contains_want(&self, _oid: AnyGitOid) -> bool {
        true
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        true
    }

    fn symref_target(&self, name: &[u8]) -> Option<&[u8]> {
        self.lookups.set(self.lookups.get() + 1);
        self.aliases
            .iter()
            .find(|(alias, _)| alias.as_slice() == name)
            .map(|(_, target)| target.as_slice())
    }

    fn unborn_symref_target(&self) -> Option<&[u8]> {
        self.unborn.as_deref()
    }
}

fn policy(rules: &[&[u8]]) -> RefVisibility {
    let mut visibility = RefVisibility::new();
    for rule in rules {
        visibility
            .push_rule(rule, &WireLimits::default())
            .expect("fixture rule");
    }
    visibility
}

fn ls_refs(repository: &impl UploadPackRepository, unborn: bool) -> Vec<Packet> {
    let limits = WireLimits::default();
    let mut machine = V2UploadPack::new(
        Capabilities::parse_v1(b"ls-refs=unborn", &limits).expect("ls-refs capability"),
        limits,
    )
    .expect("v2 machine");
    for packet in [
        Packet::Data(b"command=ls-refs\n".to_vec()),
        Packet::Delimiter,
        Packet::Data(b"symrefs\n".to_vec()),
    ] {
        machine.push_packet(&packet, repository).expect("ls-refs request");
    }
    if unborn {
        machine
            .push_packet(&Packet::Data(b"unborn\n".to_vec()), repository)
            .expect("unborn requested");
    }
    machine
        .push_packet(&Packet::Flush, repository)
        .expect("ls-refs response")
        .output
}

#[test]
fn hidden_head_alias_is_indistinguishable_from_an_absent_alias_on_the_wire() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = Repository::new(format);
        repository.reference(b"HEAD", '2');
        repository.reference(b"refs/heads/main", '1');
        repository.reference(b"refs/hidden/secret", '2');
        repository.alias(b"HEAD", b"refs/hidden/secret");
        let mut absent = Repository::new(format);
        absent.reference(b"refs/heads/main", '1');
        let view = VisibleUploadPackRepository::new(&repository, &policy(&[b"refs/hidden"]));
        assert_eq!(view.advertised_refs(), absent.advertised_refs());
        assert_eq!(view.resolve_ref(b"HEAD"), None);
        assert_eq!(view.symref_target(b"HEAD"), None);
        assert!(!view.contains_want(oid(format, '2')));
        assert!(!view.is_common(oid(format, '2')));
        assert!(view.contains_want(oid(format, '1')));
        assert_eq!(ls_refs(&view, true), ls_refs(&absent, true));
        assert_eq!(view.unborn_symref_target(), None, "hiding is not unbornness");
    }
}

#[test]
fn a_public_tip_sharing_the_hidden_head_oid_remains_disclosable() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = Repository::new(format);
        repository.reference(b"HEAD", '1');
        repository.reference(b"refs/heads/main", '1');
        repository.reference(b"refs/hidden/secret", '1');
        repository.alias(b"HEAD", b"refs/hidden/secret");
        let view = VisibleUploadPackRepository::new(&repository, &policy(&[b"refs/hidden"]));
        assert_eq!(view.advertised_refs(), &repository.refs[1..2]);
        assert_eq!(view.symref_target(b"HEAD"), None);
        assert!(view.contains_want(oid(format, '1')));
        assert!(view.is_common(oid(format, '1')));
    }
}

#[test]
fn permitted_symbolic_metadata_is_preserved_and_read_only_once() {
    let mut repository = Repository::new(GitObjectFormat::Sha1);
    repository.reference(b"HEAD", '1');
    repository.reference(b"refs/heads/main", '1');
    repository.alias(b"HEAD", b"refs/heads/main");
    let view = VisibleUploadPackRepository::new(&repository, &RefVisibility::new());
    assert_eq!(view.advertised_refs(), repository.advertised_refs());
    assert_eq!(view.symref_target(b"HEAD"), Some(b"refs/heads/main".as_slice()));
    let output = ls_refs(&view, false);
    assert!(output.iter().any(|packet| matches!(
        packet,
        Packet::Data(line) if line.ends_with(b" HEAD symref-target:refs/heads/main\n")
    )));
    assert_eq!(repository.lookups.get(), repository.refs.len());
}

#[test]
fn hiding_propagates_through_alias_chains_without_depending_on_ref_order() {
    let mut repository = Repository::new(GitObjectFormat::Sha1);
    repository.reference(b"HEAD", '2');
    repository.reference(b"refs/aliases/current", '2');
    repository.reference(b"refs/heads/main", '1');
    repository.reference(b"refs/hidden/secret", '2');
    repository.alias(b"HEAD", b"refs/aliases/current");
    repository.alias(b"refs/aliases/current", b"refs/hidden/secret");
    let visibility = policy(&[b"refs/hidden"]);
    let view = VisibleUploadPackRepository::new(&repository, &visibility);
    assert_eq!(view.advertised_refs(), &repository.refs[2..3]);
    assert_eq!(view.symref_target(b"HEAD"), None);
    assert_eq!(view.symref_target(b"refs/aliases/current"), None);
    assert!(!view.contains_want(oid(repository.format, '2')));
    repository.refs.reverse();
    let reversed = VisibleUploadPackRepository::new(&repository, &visibility);
    assert_eq!(reversed.advertised_refs(), &repository.refs[1..2]);
}

#[test]
fn a_hidden_member_of_an_alias_cycle_hides_the_cycle_without_recursion() {
    let mut repository = Repository::new(GitObjectFormat::Sha1);
    repository.reference(b"refs/aliases/a", '2');
    repository.reference(b"refs/aliases/b", '2');
    repository.reference(b"refs/heads/main", '1');
    repository.alias(b"refs/aliases/a", b"refs/aliases/b");
    repository.alias(b"refs/aliases/b", b"refs/aliases/a");
    let view = VisibleUploadPackRepository::new(&repository, &policy(&[b"refs/aliases/b"]));
    assert_eq!(view.advertised_refs(), &repository.refs[2..]);
    assert_eq!(repository.lookups.get(), repository.refs.len());
}

#[test]
fn a_hidden_target_is_filtered_even_when_not_itself_advertised() {
    let mut repository = Repository::new(GitObjectFormat::Sha1);
    repository.reference(b"HEAD", '2');
    repository.alias(b"HEAD", b"refs/hidden/secret");
    let view = VisibleUploadPackRepository::new(&repository, &policy(&[b"refs/hidden"]));
    assert!(view.advertised_refs().is_empty());
    assert!(!view.contains_want(oid(repository.format, '2')));
    assert_eq!(view.symref_target(b"HEAD"), None);
}

#[test]
fn visible_unborn_head_is_forwarded_only_when_the_client_requests_it() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = Repository::new(format);
        repository.unborn = Some(b"refs/heads/main".to_vec());
        let view = VisibleUploadPackRepository::new(&repository, &RefVisibility::new());
        assert_eq!(view.unborn_symref_target(), Some(b"refs/heads/main".as_slice()));
        assert_eq!(ls_refs(&view, false), vec![Packet::Flush]);
        assert_eq!(
            ls_refs(&view, true),
            vec![
                Packet::Data(b"unborn HEAD symref-target:refs/heads/main\n".to_vec()),
                Packet::Flush,
            ]
        );
    }
}

#[test]
fn unborn_disclosure_requires_both_head_and_target_to_be_visible() {
    let mut repository = Repository::new(GitObjectFormat::Sha1);
    repository.unborn = Some(b"refs/heads/main".to_vec());
    for rules in [vec![b"HEAD".as_slice()], vec![b"refs/heads/main".as_slice()]] {
        let view = VisibleUploadPackRepository::new(&repository, &policy(&rules));
        assert_eq!(view.unborn_symref_target(), None);
        assert_eq!(ls_refs(&view, true), vec![Packet::Flush]);
    }
    let view = VisibleUploadPackRepository::new(
        &repository,
        &policy(&[b"refs/heads", b"!refs/heads/main"]),
    );
    assert_eq!(view.unborn_symref_target(), Some(b"refs/heads/main".as_slice()));
}
