#![forbid(unsafe_code)]

//! Canonical peeled metadata must participate in the same visibility snapshot.
//! These exercise the production wrapper and wire machines, not a model.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};

use fgit_wire::visibility::{RefVisibility, VisibleUploadPackRepository};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, UploadPackRepository,
    V2UploadPack, WireError, WireLimits,
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
    aliases: BTreeMap<Vec<u8>, Vec<u8>>,
    peeled: HashMap<AnyGitOid, AnyGitOid>,
    denied: HashSet<AnyGitOid>,
    peel_calls: RefCell<HashMap<AnyGitOid, usize>>,
}

impl Repository {
    fn new(format: GitObjectFormat) -> Self {
        let mut repository = Self {
            format,
            refs: Vec::new(),
            aliases: BTreeMap::new(),
            peeled: HashMap::new(),
            denied: HashSet::new(),
            peel_calls: RefCell::new(HashMap::new()),
        };
        repository.add_ref(b"refs/heads/main", '1');
        repository
    }

    fn add_ref(&mut self, name: &[u8], digit: char) {
        self.refs.push(
            AdvertisedRef::new(oid(self.format, digit), name, &WireLimits::default())
                .expect("fixture ref"),
        );
        self.refs.sort_by(|left, right| left.name.cmp(&right.name));
    }

    fn add_tag(&mut self, name: &[u8], explicit_peeled: bool) {
        self.add_ref(name, '2');
        self.peeled
            .insert(oid(self.format, '2'), oid(self.format, '3'));
        if explicit_peeled {
            let mut peeled_name = name.to_vec();
            peeled_name.extend_from_slice(b"^{}");
            self.add_ref(&peeled_name, '3');
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

    fn contains_want(&self, target: AnyGitOid) -> bool {
        !self.denied.contains(&target)
            && (self.refs.iter().any(|reference| reference.oid == target)
                || self.peeled.values().any(|peeled| *peeled == target))
    }

    fn is_common(&self, target: AnyGitOid) -> bool {
        self.contains_want(target)
    }

    fn symref_target(&self, name: &[u8]) -> Option<&[u8]> {
        self.aliases.get(name).map(Vec::as_slice)
    }

    fn peeled(&self, source: AnyGitOid) -> Option<AnyGitOid> {
        *self.peel_calls.borrow_mut().entry(source).or_default() += 1;
        self.peeled.get(&source).copied()
    }
}

fn policy(rules: &[&[u8]]) -> RefVisibility {
    let mut policy = RefVisibility::new();
    for rule in rules {
        policy
            .push_rule(rule, &WireLimits::default())
            .expect("fixture rule");
    }
    policy
}

fn alias_chain(format: GitObjectFormat, length: usize, explicit_peeled: bool) -> Repository {
    let mut repository = Repository::new(format);
    for index in 0..length {
        let name = format!("refs/tags/alias-{index:04}").into_bytes();
        let target = if index + 1 == length {
            b"refs/tags/private".to_vec()
        } else {
            format!("refs/tags/alias-{:04}", index + 1).into_bytes()
        };
        repository.add_tag(&name, explicit_peeled);
        repository.aliases.insert(name, target);
    }
    repository.add_tag(b"refs/tags/private", explicit_peeled);
    repository
}

fn v2_want(repository: &impl UploadPackRepository, target: AnyGitOid) -> Result<(), WireError> {
    let limits = WireLimits::default();
    let capabilities = Capabilities::parse_v1(b"fetch", &limits).expect("fetch capability");
    let mut machine = V2UploadPack::new(capabilities, limits).expect("v2 machine");
    machine.push_packet(&Packet::Data(b"command=fetch\n".to_vec()), repository)?;
    machine.push_packet(&Packet::Delimiter, repository)?;
    machine
        .push_packet(&Packet::Data(format!("want {target}\n").into_bytes()), repository)
        .map(|_| ())
}

#[test]
fn hidden_peeled_wants_use_the_same_v2_refusal_as_absent_objects() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = alias_chain(format, 3, false);
        let absent = Repository::new(format);
        let view = VisibleUploadPackRepository::new(&repository, &policy(&[b"refs/tags/private"]));
        let hidden_error = v2_want(&view, oid(format, '3')).unwrap_err();
        let absent_error = v2_want(&absent, oid(format, '3')).unwrap_err();
        assert!(matches!(hidden_error, WireError::WantNotReachable { .. }));
        assert_eq!(format!("{hidden_error:?}"), format!("{absent_error:?}"));
        v2_want(&view, oid(format, '1')).expect("visible branch remains fetchable");
    }
}

#[test]
fn hidden_peeled_metadata_is_guarded_without_a_separate_advertisement_record() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = alias_chain(format, 0, false);
        let view = VisibleUploadPackRepository::new(&repository, &policy(&[b"refs/tags/private"]));
        assert!(repository.contains_want(oid(format, '3')), "inner-store control");
        assert!(!view.contains_want(oid(format, '3')));
        assert!(!view.is_common(oid(format, '3')));
        assert_eq!(view.peeled(oid(format, '2')), None);
        let permitted = VisibleUploadPackRepository::new(&repository, &RefVisibility::new());
        assert!(permitted.contains_want(oid(format, '3')));
        assert_eq!(permitted.peeled(oid(format, '2')), Some(oid(format, '3')));
    }
}

#[test]
fn visible_tag_retains_its_peeled_target_when_a_hidden_branch_shares_it() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let mut repository = Repository::new(format);
        repository.add_ref(b"refs/heads/private", '3');
        let hidden = policy(&[b"refs/heads/private"]);
        let hidden_only = VisibleUploadPackRepository::new(&repository, &hidden);
        assert!(!hidden_only.contains_want(oid(format, '3')));
        repository.add_tag(b"refs/tags/public", false);
        let view = VisibleUploadPackRepository::new(&repository, &hidden);
        assert_eq!(view.peeled(oid(format, '2')), Some(oid(format, '3')));
        assert!(view.contains_want(oid(format, '3')));
        assert!(view.is_common(oid(format, '3')));
        v2_want(&view, oid(format, '3')).expect("public annotated tag path");
    }
}

#[test]
fn visible_peeled_metadata_never_overrides_an_inner_authorization_refusal() {
    let format = GitObjectFormat::Sha256;
    let mut repository = Repository::new(format);
    repository.add_tag(b"refs/tags/public", false);
    repository.denied.insert(oid(format, '3'));
    let view = VisibleUploadPackRepository::new(&repository, &RefVisibility::new());
    assert_eq!(view.peeled(oid(format, '2')), Some(oid(format, '3')));
    assert!(!view.contains_want(oid(format, '3')));
    assert!(!view.is_common(oid(format, '3')));
    assert!(view.contains_want(oid(format, '1')));
}

#[test]
fn peeled_metadata_is_read_once_per_unique_advertised_object() {
    let format = GitObjectFormat::Sha1;
    let mut repository = alias_chain(format, 3, true);
    repository.add_tag(b"refs/tags/public", false);
    let view = VisibleUploadPackRepository::new(&repository, &policy(&[b"refs/tags/private"]));
    let calls = repository.peel_calls.borrow().clone();
    let unique: HashSet<_> = repository.refs.iter().map(|reference| reference.oid).collect();
    assert_eq!(calls.len(), unique.len());
    assert!(unique.iter().all(|source| calls.get(source) == Some(&1)));
    for _ in 0..3 {
        assert_eq!(view.peeled(oid(format, '2')), Some(oid(format, '3')));
        assert_eq!(view.peeled(oid(format, '1')), None);
    }
    assert_eq!(*repository.peel_calls.borrow(), calls);
}
