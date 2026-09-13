#![forbid(unsafe_code)]
use fgit_git_object::ObjectType;
use fgit_pack::full_bundle::{FullBundle, FullBundleError, FullBundleInput, FullBundleLimits};
use fgit_pack::{
    BundleReference, CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId,
    PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter,
};
use fgit_types::RefName;
use std::collections::BTreeMap;

struct Source(BTreeMap<ObjectId, CanonicalPackObject>);
impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}
fn source(format: ObjectFormat) -> (Source, ObjectId, ObjectId) {
    let tree = fgit_crypto::git_object_id(format, ObjectType::Tree, b"");
    let bytes = format!("tree {tree}\nauthor A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\ninitial\n").into_bytes();
    let commit = fgit_crypto::git_object_id(format, ObjectType::Commit, &bytes);
    (
        Source(BTreeMap::from([
            (
                tree,
                CanonicalPackObject::new(tree, ObjectType::Tree, vec![], vec![], 0, 0),
            ),
            (
                commit,
                CanonicalPackObject::new(commit, ObjectType::Commit, bytes, vec![tree], 0, 0),
            ),
        ])),
        commit,
        tree,
    )
}
fn refs(id: ObjectId) -> Vec<BundleReference> {
    [
        b"refs/tags/v1".as_slice(),
        b"refs/heads/main",
        b"refs/heads/\xff",
    ]
    .into_iter()
    .map(|name| BundleReference::new(id, RefName::try_new(name).unwrap()))
    .collect()
}
fn bundle(format: ObjectFormat) -> Vec<u8> {
    let (source, id, _) = source(format);
    let limits = PackLimits::default();
    let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone())
        .plan(&source, &[id], &mut || true)
        .unwrap();
    FullBundle::write(
        &refs(id),
        Some(id),
        &plan,
        &PackWriter::new(limits),
        FullBundleLimits::default(),
        &mut || true,
    )
    .unwrap()
    .into_bytes()
}
#[test]
fn full_native_bundles_round_trip_both_domains_with_head_and_byte_names() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = bundle(format);
        assert_eq!(bytes, bundle(format));
        let input =
            FullBundleInput::parse(&bytes, FullBundleLimits::default(), &mut || true).unwrap();
        assert_eq!(input.format(), format);
        assert_eq!(input.references().len(), 3);
        assert_eq!(input.references()[0].name().as_bytes(), b"refs/heads/main");
        assert_eq!(input.references()[1].name().as_bytes(), b"refs/heads/\xff");
        assert_eq!(input.head(), Some(*input.references()[0].target()));
        input
            .verify_pack_framing(&PackLimits::default(), &mut || true)
            .unwrap();
        let pack = fgit_pack::read_verified_pack(
            input.pack_bytes(),
            format,
            &PackLimits::default(),
            &mut || true,
            &fgit_pack::NativeChecksumVerifier,
        )
        .unwrap();
        assert_eq!(pack.entries().len(), 2);
        if format == ObjectFormat::Sha256 {
            assert!(bytes.starts_with(b"# v3 git bundle\n@object-format=sha256\n"));
        }
    }
}
#[test]
fn accepts_unsorted_third_party_refs_but_not_duplicate_names_or_detached_head() {
    let (_, id, _) = source(ObjectFormat::Sha1);
    let pack = bundle(ObjectFormat::Sha1);
    let pack = FullBundleInput::parse(&pack, Default::default(), &mut || true)
        .unwrap()
        .pack_bytes();
    for prefix in [
        format!("# v2 git bundle\n{id} refs/tags/z\n{id} refs/heads/a\n\n"),
        format!("# v3 git bundle\n{id} refs/tags/z\n{id} refs/heads/a\n\n"),
    ] {
        let bytes = [prefix.as_bytes(), pack].concat();
        let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        assert_eq!(input.references()[0].name().as_bytes(), b"refs/heads/a");
    }
    for header in [
        format!("# v2 git bundle\n{id} refs/heads/a\n{id} refs/heads/a\n\n"),
        format!("# v2 git bundle\n{id} HEAD\n{id} HEAD\n{id} refs/heads/a\n\n"),
        format!("# v2 git bundle\n{id} HEAD\n{id} refs/tags/a\n\n"),
    ] {
        assert!(
            FullBundleInput::parse(
                &[header.as_bytes(), pack].concat(),
                Default::default(),
                &mut || true
            )
            .is_err()
        );
    }
}
#[test]
fn refuses_incremental_filtered_unknown_and_misplaced_capability_bundles() {
    let (_, id, _) = source(ObjectFormat::Sha1);
    for header in [
        format!("# v2 git bundle\n-{id} prerequisite\n{id} refs/heads/a\n\nPACK"),
        format!("# v3 git bundle\n@filter=blob:none\n{id} refs/heads/a\n\nPACK"),
        format!("# v3 git bundle\n@future=yes\n{id} refs/heads/a\n\nPACK"),
        format!("# v2 git bundle\n@object-format=sha1\n{id} refs/heads/a\n\nPACK"),
        format!(
            "# v3 git bundle\n@object-format=sha1\n@object-format=sha1\n{id} refs/heads/a\n\nPACK"
        ),
        format!("# v3 git bundle\n{id} refs/heads/a\n@object-format=sha256\n\nPACK"),
    ] {
        assert!(
            FullBundleInput::parse(header.as_bytes(), Default::default(), &mut || true).is_err(),
            "{header}"
        );
    }
}
#[test]
fn corruption_truncation_and_suffix_bytes_do_not_authenticate() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = bundle(format);
        let offset = FullBundleInput::parse(&bytes, Default::default(), &mut || true)
            .unwrap()
            .header_bytes();
        for truncate in [1, format.digest_len()] {
            let input = FullBundleInput::parse(
                &bytes[..bytes.len() - truncate],
                Default::default(),
                &mut || true,
            )
            .unwrap();
            assert!(
                input
                    .verify_pack_framing(&PackLimits::default(), &mut || true)
                    .is_err()
            );
        }
        let mut corrupt = bytes.clone();
        corrupt[offset + 15] ^= 1;
        let mut suffix = bytes;
        suffix.push(0);
        for altered in [corrupt, suffix] {
            let input = FullBundleInput::parse(&altered, Default::default(), &mut || true).unwrap();
            assert!(
                input
                    .verify_pack_framing(&PackLimits::default(), &mut || true)
                    .is_err()
            );
        }
    }
}
#[test]
fn envelope_and_cancellation_limits_are_enforced() {
    let bytes = bundle(ObjectFormat::Sha1);
    let header = FullBundleInput::parse(&bytes, Default::default(), &mut || true)
        .unwrap()
        .header_bytes();
    for limits in [
        FullBundleLimits {
            max_bundle_bytes: bytes.len() - 1,
            ..Default::default()
        },
        FullBundleLimits {
            max_header_bytes: header - 1,
            ..Default::default()
        },
        FullBundleLimits {
            max_references: 3,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            FullBundleInput::parse(&bytes, limits, &mut || true),
            Err(FullBundleError::Limit(_))
        ));
    }
    let limits = FullBundleLimits {
        max_bundle_bytes: bytes.len(),
        max_header_bytes: header,
        max_references: 4,
    };
    assert!(FullBundleInput::parse(&bytes, limits, &mut || true).is_ok());
    assert!(FullBundleInput::parse(&bytes, limits, &mut || false).is_err());
    let input = FullBundleInput::parse(&bytes, limits, &mut || true).unwrap();
    assert!(
        input
            .verify_pack_framing(&Default::default(), &mut || false)
            .is_err()
    );
}
#[test]
fn writer_refuses_missing_edges_and_unrelated_retained_objects_before_pack_work() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (mut source, id, _) = source(format);
        let extra =
            fgit_crypto::git_object_id(format, ObjectType::Blob, b"private retained history");
        source.0.insert(
            extra,
            CanonicalPackObject::new(
                extra,
                ObjectType::Blob,
                b"private retained history".to_vec(),
                vec![],
                0,
                0,
            ),
        );
        let limits = PackLimits::default();
        let planner = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone());
        let incomplete = planner.plan_selected(&source, &[id], &mut || true).unwrap();
        let extra_plan = planner.plan(&source, &[id, extra], &mut || true).unwrap();
        let writer = PackWriter::new(limits);
        assert!(matches!(
            FullBundle::write(
                &refs(id),
                None,
                &incomplete,
                &writer,
                Default::default(),
                &mut || true
            ),
            Err(FullBundleError::MissingObject(_))
        ));
        assert!(
            matches!(FullBundle::write(&refs(id), None, &extra_plan, &writer,
            Default::default(), &mut || true), Err(FullBundleError::UnreachableObject(oid)) if oid == extra)
        );
    }
}

#[path = "full_bundle/fetch.rs"]
mod fetch;
