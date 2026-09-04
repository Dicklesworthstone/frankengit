#![forbid(unsafe_code)]

//! Regression coverage for exact hide rules on v0/v1 peeled tag records.
//! Both native object formats exercise the real visibility and encoding APIs.

use fgit_wire::visibility::{RefVisibility, VisibleUploadPackRepository, filter_advertised_refs};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, UploadPackRepository,
    V1Advertisement, WireLimits,
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
}

impl Repository {
    fn new(format: GitObjectFormat, shared_peeled_tip: bool) -> Self {
        let limits = WireLimits::default();
        Self {
            format,
            refs: vec![
                AdvertisedRef::new(oid(format, '1'), b"refs/heads/main", &limits)
                    .expect("public branch"),
                AdvertisedRef::new(oid(format, '2'), b"refs/tags/private", &limits)
                    .expect("private tag"),
                AdvertisedRef::new(
                    oid(format, if shared_peeled_tip { '1' } else { '3' }),
                    b"refs/tags/private^{}",
                    &limits,
                )
                .expect("private peeled record"),
            ],
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

    fn contains_want(&self, _oid: AnyGitOid) -> bool {
        true
    }

    fn is_common(&self, _oid: AnyGitOid) -> bool {
        true
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

#[test]
fn exact_hide_removes_tag_and_peeled_record_without_hiding_nearby_names() {
    let visibility = policy(&[b"refs/tags/private"]);
    assert!(visibility.hides(b"refs/tags/private"));
    assert!(visibility.hides(b"refs/tags/private^{}"));
    assert!(!visibility.hides(b"refs/tags/private-public"));
    assert!(!visibility.hides(b"refs/tags/private-public^{}"));
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format, false);
        let expected = vec![repository.refs[0].clone()];
        assert_eq!(filter_advertised_refs(&repository.refs, &visibility), expected);
        let view = VisibleUploadPackRepository::new(&repository, &visibility);
        assert_eq!(view.advertised_refs(), expected.as_slice());
        assert_eq!(view.resolve_ref(b"refs/tags/private^{}"), None);
    }
}

#[test]
fn hidden_peeled_identity_is_not_a_want_or_a_common_object() {
    let visibility = policy(&[b"refs/tags/private"]);
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format, false);
        let view = VisibleUploadPackRepository::new(&repository, &visibility);
        for digit in ['2', '3'] {
            let hidden = oid(format, digit);
            assert!(repository.contains_want(hidden), "permissive-store control");
            assert!(repository.is_common(hidden), "permissive-store control");
            assert!(!view.contains_want(hidden));
            assert!(!view.is_common(hidden));
        }
        assert!(view.contains_want(oid(format, '1')));
        assert!(view.is_common(oid(format, '1')));
    }
}

#[test]
fn a_public_ref_still_authorizes_an_identity_shared_with_a_hidden_peeled_record() {
    let visibility = policy(&[b"refs/tags/private"]);
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format, true);
        let view = VisibleUploadPackRepository::new(&repository, &visibility);
        assert_eq!(view.advertised_refs(), &repository.refs[..1]);
        assert!(view.contains_want(oid(format, '1')));
        assert!(view.is_common(oid(format, '1')));
        assert!(!view.contains_want(oid(format, '2')));
    }
}

#[test]
fn last_matching_rule_unhides_or_rehides_the_entire_tag_pair() {
    let visible = policy(&[b"refs/tags", b"!refs/tags/private"]);
    let hidden = policy(&[b"refs/tags", b"!refs/tags/private", b"refs/tags/private"]);
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format, false);
        assert_eq!(filter_advertised_refs(&repository.refs, &visible), repository.refs);
        assert_eq!(
            filter_advertised_refs(&repository.refs, &hidden),
            repository.refs[..1]
        );
    }
}

#[test]
fn filtered_wire_output_contains_neither_the_private_tag_nor_its_peeled_oid() {
    let visibility = policy(&[b"refs/tags/private"]);
    let limits = WireLimits::default();
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = Repository::new(format, false);
        let output = V1Advertisement::new(
            filter_advertised_refs(&repository.refs, &visibility),
            Capabilities::default(),
            format,
            &limits,
        )
        .expect("filtered advertisement")
        .encode(&limits)
        .expect("encode filtered advertisement");
        let text = output
            .iter()
            .filter_map(|packet| match packet {
                Packet::Data(bytes) => Some(String::from_utf8_lossy(bytes)),
                _ => None,
            })
            .collect::<String>();
        assert!(text.contains("refs/heads/main"), "permitted-output control");
        assert!(!text.contains("refs/tags/private"));
        assert!(!text.contains(&oid(format, '2').to_string()));
        assert!(!text.contains(&oid(format, '3').to_string()));
    }
}
