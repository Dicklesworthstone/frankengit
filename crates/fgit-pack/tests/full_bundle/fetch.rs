use super::*;
use fgit_pack::full_bundle::fetch::BundleRefMapping;

fn name(bytes: &[u8]) -> RefName {
    RefName::try_new(bytes).unwrap()
}
fn mapping(source: &[u8], destination: &[u8], old: Option<ObjectId>) -> BundleRefMapping {
    BundleRefMapping {
        source: name(source),
        destination: name(destination),
        expected_old: old,
    }
}

#[test]
fn selection_is_explicit_destination_sorted_and_order_independent() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = bundle(format);
        let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let target = *input.references()[0].target();
        let mappings = [
            mapping(b"refs/heads/main", b"refs/remotes/upstream/z", Some(target)),
            mapping(b"refs/heads/\xff", b"refs/heads/\xfe", None),
        ];
        let selected = input
            .select_updates(&mappings, Default::default(), &mut || true)
            .unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].destination.as_bytes(), b"refs/heads/\xfe");
        assert_eq!(selected[1].expected_old, Some(target));
        assert_eq!(selected[0].target, target);
        assert_eq!(
            selected,
            input
                .select_updates(
                    &[mappings[1].clone(), mappings[0].clone()],
                    Default::default(),
                    &mut || true
                )
                .unwrap()
        );
        let twins = [
            mapping(b"refs/heads/main", b"refs/remotes/a/main", None),
            mapping(b"refs/heads/main", b"refs/remotes/b/main", None),
        ];
        assert_eq!(
            input
                .select_updates(&twins, Default::default(), &mut || true)
                .unwrap()
                .len(),
            2
        );
    }
}

#[test]
fn duplicate_destinations_unknown_sources_and_non_git_namespaces_refuse() {
    let bytes = bundle(ObjectFormat::Sha1);
    let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
    let valid = mapping(b"refs/heads/main", b"refs/heads/main", None);
    for bad in [
        vec![],
        vec![valid.clone(), valid.clone()],
        vec![mapping(b"refs/heads/missing", b"refs/heads/main", None)],
        vec![mapping(b"refs/heads/main", b"refs/forge/policy", None)],
    ] {
        assert!(
            input
                .select_updates(&bad, Default::default(), &mut || true)
                .is_err()
        );
    }
    assert!(
        input
            .select_updates(&[valid], Default::default(), &mut || true)
            .is_ok()
    );
}

#[test]
fn expected_old_is_nonzero_and_format_bound_before_any_publication() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = bundle(format);
        let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let other = if format == ObjectFormat::Sha1 {
            ObjectFormat::Sha256
        } else {
            ObjectFormat::Sha1
        };
        for old in [
            ObjectId::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap(),
            ObjectId::from_hex(other, &"a".repeat(other.digest_len() * 2)).unwrap(),
        ] {
            assert_eq!(
                input.select_updates(
                    &[mapping(b"refs/heads/main", b"refs/heads/main", Some(old))],
                    Default::default(),
                    &mut || true
                ),
                Err(FullBundleError::FormatMismatch)
            );
        }
    }
}

#[test]
fn selection_checks_count_bytes_and_cancellation() {
    let bytes = bundle(ObjectFormat::Sha1);
    let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
    let mappings = [mapping(
        b"refs/heads/main",
        b"refs/remotes/upstream/main",
        None,
    )];
    assert!(
        input
            .select_updates(
                &mappings,
                FullBundleLimits {
                    max_references: 0,
                    ..Default::default()
                },
                &mut || true
            )
            .is_err()
    );
    assert!(
        input
            .select_updates(
                &mappings,
                FullBundleLimits {
                    max_header_bytes: 1,
                    ..Default::default()
                },
                &mut || true
            )
            .is_err()
    );
    let mut calls = 0;
    assert!(
        input
            .select_updates(&mappings, Default::default(), &mut || {
                calls += 1;
                calls < 3
            })
            .is_err()
    );
    assert!(
        input
            .select_updates(&mappings, Default::default(), &mut || true)
            .is_ok()
    );
}

fn streamed_header(bytes: &[u8]) -> fgit_pack::full_bundle::FullBundleHeader {
    let input = FullBundleInput::parse(bytes, Default::default(), &mut || true).unwrap();
    // Only the semantic header is available, as on a terminal-outcome retry.
    let mut reader = std::io::Cursor::new(&bytes[..input.header_bytes()]);
    let header = fgit_pack::full_bundle::FullBundleHeader::read(
        &mut reader,
        Default::default(),
        &mut || true,
    )
    .unwrap();
    assert_eq!(reader.position() as usize, input.header_bytes());
    header
}

#[test]
fn streamed_header_preserves_exact_byte_names_fanout_and_destination_order() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = bundle(format);
        let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let header = streamed_header(&bytes);
        let target = *input.references()[0].target();
        let mappings = [
            mapping(b"refs/heads/main", b"refs/remotes/upstream/z", Some(target)),
            mapping(b"refs/heads/\xff", b"refs/heads/\xfe", None),
            mapping(b"refs/heads/main", b"refs/tags/copied", None),
        ];
        let expected = vec![
            fgit_pack::full_bundle::fetch::BundleRefUpdate {
                source: name(b"refs/heads/\xff"),
                destination: name(b"refs/heads/\xfe"),
                expected_old: None,
                target,
            },
            fgit_pack::full_bundle::fetch::BundleRefUpdate {
                source: name(b"refs/heads/main"),
                destination: name(b"refs/remotes/upstream/z"),
                expected_old: Some(target),
                target,
            },
            fgit_pack::full_bundle::fetch::BundleRefUpdate {
                source: name(b"refs/heads/main"),
                destination: name(b"refs/tags/copied"),
                expected_old: None,
                target,
            },
        ];
        let limits = FullBundleLimits {
            max_references: mappings.len(),
            max_header_bytes: mappings
                .iter()
                .map(|mapping| {
                    mapping.source.as_bytes().len() + mapping.destination.as_bytes().len()
                })
                .sum(),
            ..Default::default()
        };
        assert_eq!(
            header
                .select_updates(&mappings, limits, &mut || true)
                .unwrap(),
            expected
        );
        assert_eq!(
            input
                .select_updates(&mappings, limits, &mut || true)
                .unwrap(),
            expected
        );
        assert_eq!(
            header
                .select_updates(
                    &[
                        mappings[2].clone(),
                        mappings[0].clone(),
                        mappings[1].clone()
                    ],
                    limits,
                    &mut || true,
                )
                .unwrap(),
            expected
        );
        assert_eq!(header.references(), input.references());
        assert_eq!(header.head(), input.head());
    }
}

#[test]
fn streamed_and_buffered_mapping_refusals_share_exact_limits_and_domains() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = bundle(format);
        let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let header = streamed_header(&bytes);
        let valid = mapping(b"refs/heads/main", b"refs/remotes/upstream/main", None);
        let other = if format == ObjectFormat::Sha1 {
            ObjectFormat::Sha256
        } else {
            ObjectFormat::Sha1
        };
        let zero = ObjectId::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        let foreign = ObjectId::from_hex(other, &"a".repeat(other.digest_len() * 2)).unwrap();
        for mappings in [
            vec![],
            vec![valid.clone(), valid.clone()],
            vec![mapping(b"refs/heads/missing", b"refs/heads/main", None)],
            vec![mapping(b"refs/heads/main", b"refs/internal/policy", None)],
            vec![mapping(b"refs/heads/main", b"refs/heads/main", Some(zero))],
            vec![mapping(
                b"refs/heads/main",
                b"refs/heads/main",
                Some(foreign),
            )],
        ] {
            let buffered = input.select_updates(&mappings, Default::default(), &mut || true);
            assert!(buffered.is_err());
            assert_eq!(
                header.select_updates(&mappings, Default::default(), &mut || true),
                buffered
            );
        }
        for limits in [
            FullBundleLimits {
                max_references: 0,
                ..Default::default()
            },
            FullBundleLimits {
                max_header_bytes: valid.source.as_bytes().len()
                    + valid.destination.as_bytes().len()
                    - 1,
                ..Default::default()
            },
        ] {
            let buffered = input.select_updates(std::slice::from_ref(&valid), limits, &mut || true);
            assert!(buffered.is_err());
            assert_eq!(
                header.select_updates(std::slice::from_ref(&valid), limits, &mut || true),
                buffered
            );
        }
        assert!(
            header
                .select_updates(&[valid], Default::default(), &mut || true)
                .is_ok()
        );
    }
}

#[test]
fn streamed_mapping_cancellation_keeps_buffered_checkpoint_behavior() {
    let bytes = bundle(ObjectFormat::Sha256);
    let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
    let header = streamed_header(&bytes);
    let mappings = [
        mapping(b"refs/heads/main", b"refs/remotes/a/main", None),
        mapping(b"refs/heads/main", b"refs/remotes/b/main", None),
    ];
    for stop in 1..=4 {
        let mut buffered_calls = 0;
        let buffered = input.select_updates(&mappings, Default::default(), &mut || {
            buffered_calls += 1;
            buffered_calls != stop
        });
        let mut streamed_calls = 0;
        let streamed = header.select_updates(&mappings, Default::default(), &mut || {
            streamed_calls += 1;
            streamed_calls != stop
        });
        assert!(buffered.is_err());
        assert_eq!(streamed, buffered);
        assert_eq!(streamed_calls, buffered_calls);
    }
    assert_eq!(
        header.select_updates(&mappings, Default::default(), &mut || true),
        input.select_updates(&mappings, Default::default(), &mut || true)
    );
}
