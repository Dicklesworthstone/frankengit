//! Verified visible tree names improve packing without widening selection.
use super::*;

#[test]
fn raw_names_group_versions_and_choose_a_stable_minimum_for_shared_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let old = source.put(ObjectType::Blob, b"old issues body".to_vec());
        let new = source.put(ObjectType::Blob, b"new issues body".to_vec());
        let shared = source.put(ObjectType::Blob, b"same body, several names".to_vec());
        let raw_name = b"\xff\xfe.bin";
        let literal_backslash = b"directory\\file";
        let first_tree = source.tree(&[
            (b"100644", b"issues.jsonl", old),
            (b"100644", raw_name, shared),
        ]);
        let first = source.commit(first_tree, &[]);
        let second_tree = source.tree(&[
            (b"100644", literal_backslash, shared),
            (b"100644", b"issues.jsonl", new),
        ]);
        let second = source.commit(second_tree, &[first]);
        let unnamed = source.put(ObjectType::Blob, b"direct unnamed root".to_vec());
        let expected = BTreeMap::from([
            (old, basename_path_hash(b"issues.jsonl")),
            (new, basename_path_hash(b"issues.jsonl")),
            (
                shared,
                basename_path_hash(raw_name).min(basename_path_hash(literal_backslash)),
            ),
        ]);
        for roots in [vec![second, unnamed], vec![unnamed, first, second, first]] {
            source.reads.borrow_mut().clear();
            source.header_reads.borrow_mut().clear();
            let graph =
                project_visible_graph(&source, &source.admitted(), roots, &PackLimits::default())
                    .unwrap();
            assert_eq!(graph.path_hashes, expected);
            assert!(!graph.path_hashes.contains_key(&unnamed));
            assert!(!graph.path_hashes.contains_key(&first));
            assert!(!graph.path_hashes.contains_key(&first_tree));
            assert!(
                graph
                    .path_hashes
                    .keys()
                    .all(|id| graph.objects.contains_key(id))
            );
            for blob in [old, new, shared] {
                assert!(!source.reads.borrow().contains(&blob));
                assert_eq!(
                    source
                        .header_reads
                        .borrow()
                        .iter()
                        .filter(|id| **id == blob)
                        .count(),
                    1,
                    "ordering adds no blob-body reads or repeated envelope reads"
                );
            }
        }
    }
}

#[test]
fn imported_mode_type_bits_exclude_gitlinks_and_preserve_local_name_alignment() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let blob = source.put(ObjectType::Blob, b"local file".to_vec());
        let symlink = source.put(ObjectType::Blob, b"local target".to_vec());
        let subtree = source.tree(&[(b"0100644", b"file", blob)]);
        // These native identities deliberately have no local object or
        // admission. Both unusual spellings still have the gitlink type bits.
        let foreign = git_object_id(format, GitObjectKind::Commit, b"foreign repository");
        let root = source.tree(&[
            (b"0160000", b"foreign-a", foreign),
            (b"0040000", b"directory", subtree),
            (b"0160755", b"foreign-b", foreign),
            (b"0120000", b"symlink", symlink),
        ]);
        let graph =
            project_visible_graph(&source, &source.admitted(), [root], &PackLimits::default())
                .unwrap();
        assert_eq!(
            graph.path_hashes,
            BTreeMap::from([
                (subtree, basename_path_hash(b"directory")),
                (blob, basename_path_hash(b"file")),
                (symlink, basename_path_hash(b"symlink")),
            ])
        );
        assert_eq!(
            graph.closure.objects(),
            &BTreeSet::from([root, subtree, blob, symlink])
        );
        assert!(!source.reads.borrow().contains(&foreign));
        assert!(!source.header_reads.borrow().contains(&foreign));
    }
}

#[test]
fn many_names_retain_one_hint_within_the_existing_unique_object_limit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let blob = source.put(ObjectType::Blob, b"shared under many names".to_vec());
        let names = (0..512)
            .map(|index| format!("alias-{index:03}").into_bytes())
            .collect::<Vec<_>>();
        let entries = names
            .iter()
            .map(|name| (&b"100644"[..], name.as_slice(), blob))
            .collect::<Vec<_>>();
        let tree = source.tree(&entries);
        let limits = PackLimits {
            max_entries: 2,
            ..PackLimits::default()
        };
        let graph = project_visible_graph(&source, &source.admitted(), [tree], &limits).unwrap();
        assert_eq!(graph.path_hashes.len(), 1);
        assert_eq!(
            graph.path_hashes[&blob],
            names
                .iter()
                .map(|name| basename_path_hash(name))
                .min()
                .unwrap()
        );
        assert_eq!(graph.closure.objects().len(), 2);
        expect_code(
            project_visible_graph(
                &source,
                &source.admitted(),
                [tree],
                &PackLimits {
                    max_entries: 1,
                    ..limits
                },
            ),
            RefusalCode::ResourceBudgetExceeded,
        );
    }
}

#[test]
fn cancellation_during_name_hashing_does_not_publish_a_partial_hint() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha256);
    let blob = source.put(ObjectType::Blob, b"body".to_vec());
    let body = tree_bytes(&[(b"100644", b"filename", blob)]);
    let entries = crate::parse_tree(
        &body,
        AcceptanceProfile::GitCompatibleImport,
        &source.parse_limits(),
    )
    .unwrap();
    source.stop_at.set(2);
    let mut hashes = BTreeMap::new();
    let edges = [(blob, ObjectType::Blob)];
    let hinted = tree_path_hints(&source, &entries, &edges);
    assert!(matches!(
        &hinted,
        Err(NodePackMaterializationRefusal::Pack(error))
            if matches!(error.as_ref(), PackWriteError::Pack(PackError::DeadlineExceeded))
    ));
    // Hints are merged only from a complete result.
    if let Ok(hints) = hinted {
        merge_path_hints(&edges, &hints, &mut hashes);
    }
    assert!(hashes.is_empty());
}
