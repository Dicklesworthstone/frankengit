//! Actual imported node state; uploaded candidates stay outside immutable storage.
use super::*;

macro_rules! inspect {
    ($node:expr, $history:expr, $id:expr, $bytes:expr, $options:expr) => {
        $node.runtime().block_on($node.inspect_rebase_bundle_in(
            &$node.request_context(),
            &branch(b"refs/heads/topic"),
            &branch(b"refs/heads/main"),
            $history.source,
            $history.onto,
            $id,
            $bytes,
            &Default::default(),
            None,
            $options,
        ))
    };
}
fn transient(
    node: &OneNode,
    history: &support::History,
    format: GitHashAlgorithm,
) -> (Objects, GitOid, GitOid, GitOid, Vec<u8>) {
    let (base_tree, base_body) = source_tree(node, history.onto);
    let mut objects = Objects(BTreeMap::new());
    let blob = insert(
        &mut objects,
        format,
        GitObjectKind::Blob,
        b"temporary\n".to_vec(),
    );
    let mut tree = base_body.clone();
    tree.extend_from_slice(b"100755 zz-transient\0");
    tree.extend_from_slice(blob.as_bytes());
    let tree = insert(&mut objects, format, GitObjectKind::Tree, tree);
    let first = insert(
        &mut objects,
        format,
        GitObjectKind::Commit,
        commit(tree, history.onto, "add"),
    );
    let last = insert(
        &mut objects,
        format,
        GitObjectKind::Commit,
        commit(base_tree, first, "remove"),
    );
    (objects, first, last, base_tree, base_body)
}
#[test]
fn minimal_and_thick_series_have_identical_complete_reviews_and_frontier_counts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, history) = fixture(&root, format, 2);
        let before = generation(&node);
        let (mut objects, first, last, base_tree, base_body) = transient(&node, &history, format);
        let minimal = pack(&objects, format, history.onto, last);
        let a = inspect!(&node, &history, last, &minimal, &ReviewOptions::default()).unwrap();
        let body_start = base_body.iter().position(|byte| *byte == 0).unwrap() + 1;
        let hex: String = base_body[body_start..body_start + format.digest_len()]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let blob = GitOid::from_hex(format, &hex).unwrap();
        insert(&mut objects, format, GitObjectKind::Tree, base_body);
        insert(
            &mut objects,
            format,
            GitObjectKind::Blob,
            node.read_git_object(blob).unwrap().payload().to_vec(),
        );
        let thick = pack(&objects, format, history.onto, last);
        let b = inspect!(&node, &history, last, &thick, &ReviewOptions::default()).unwrap();
        assert_eq!(a.comparisons, b.comparisons);
        assert_eq!(a.commits.len(), b.commits.len());
        for (left, right) in a.commits.iter().zip(&b.commits) {
            assert_eq!(
                (left.id, left.parent, left.tree, &left.body),
                (right.id, right.parent, right.tree, &right.body)
            );
        }
        assert_eq!(a.bundle.closure_objects, b.bundle.closure_objects);
        assert_eq!(a.bundle.transport_only_objects, 0);
        assert_eq!(b.bundle.transport_only_objects, 0);
        assert_eq!(a.bundle.pack_objects + 2, b.bundle.pack_objects);
        assert_eq!(
            a.commits.iter().map(|c| c.id).collect::<Vec<_>>(),
            [first, last]
        );
        assert_eq!(a.commits[1].tree, base_tree);
        assert_eq!(a.comparisons[0].entries.len(), 1);
        assert_eq!(a.comparisons[0].entries[0].path, b"onto");
        for step in &a.comparisons[1..] {
            assert_eq!(step.entries.len(), 1);
            assert_eq!(step.entries[0].path, b"zz-transient");
        }
        assert!(node.read_git_object(first).is_err());
        assert!(node.read_git_object(last).is_err());
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
#[test]
fn uploaded_selected_source_tree_cannot_lend_its_omitted_source_only_blobs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, history) = fixture(&root, format, 0);
        let before = generation(&node);
        let (tree, body) = source_tree(&node, history.source);
        let mut objects = Objects(BTreeMap::new());
        let id = insert(
            &mut objects,
            format,
            GitObjectKind::Commit,
            commit(tree, history.onto, "source bytes"),
        );
        insert(&mut objects, format, GitObjectKind::Tree, body.clone());
        assert!(
            inspect!(
                &node,
                &history,
                id,
                &pack(&objects, format, history.onto, id),
                &ReviewOptions::default()
            )
            .is_err()
        );
        assert!(node.read_git_object(id).is_err());
        let mut offset = 0;
        while offset < body.len() {
            let end = offset + body[offset..].iter().position(|b| *b == 0).unwrap() + 1;
            let hex: String = body[end..end + format.digest_len()]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let blob = GitOid::from_hex(format, &hex).unwrap();
            insert(
                &mut objects,
                format,
                GitObjectKind::Blob,
                node.read_git_object(blob).unwrap().payload().to_vec(),
            );
            offset = end + format.digest_len();
        }
        let result = inspect!(
            &node,
            &history,
            id,
            &pack(&objects, format, history.onto, id),
            &ReviewOptions::default()
        )
        .unwrap();
        assert_eq!(result.commits.len(), 1);
        assert_eq!(result.commits[0].id, id);
        assert!(node.read_git_object(id).is_err());
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
#[test]
fn per_commit_review_budget_is_shared_and_a_missing_intermediate_never_returns_a_prefix() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, history) = fixture(&root, format, 2);
        let before = generation(&node);
        let (mut objects, first, last, _, _) = transient(&node, &history, format);
        let bundle = pack(&objects, format, history.onto, last);
        let mut options = ReviewOptions::default();
        options.limits.max_changes = 2;
        assert!(inspect!(&node, &history, last, &bundle, &options).is_err());
        options.limits.max_changes = 3;
        assert_eq!(
            inspect!(&node, &history, last, &bundle, &options)
                .unwrap()
                .commits
                .len(),
            2
        );
        objects.0.remove(&first);
        assert!(
            inspect!(
                &node,
                &history,
                last,
                &pack(&objects, format, history.onto, last),
                &options
            )
            .is_err()
        );
        assert!(node.read_git_object(first).is_err());
        assert!(node.read_git_object(last).is_err());
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
