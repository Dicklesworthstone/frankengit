use super::*;
use crate::preparation::{CommitInput, MergeEntry, MergeObjectSource, MergeSourceError};
use fgit_crypto::{GitObjectKind, git_object_id};
use std::cell::Cell;
use std::fmt::Write as _;

// Native object bytes and IDs, not fabricated graph IDs. No blob method may
// run: path history is tree-entry history, including binary/large files.
struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, (CommitInput, Vec<u8>)>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    tree_reads: Cell<usize>,
    checkpoints: Cell<usize>,
    stop_at: Cell<usize>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            commits: BTreeMap::new(),
            trees: BTreeMap::new(),
            tree_reads: Cell::new(0),
            checkpoints: Cell::new(0),
            stop_at: Cell::new(usize::MAX),
        }
    }
    fn entry(&self, name: &[u8], mode: u32, body: &[u8]) -> MergeEntry {
        MergeEntry {
            name: name.to_vec(),
            mode,
            oid: git_object_id(self.format, GitObjectKind::Blob, body),
        }
    }
    fn add_tree(&mut self, mut entries: Vec<MergeEntry>) -> GitOid {
        entries.sort_by_key(|entry| {
            let mut name = entry.name.clone();
            name.push(if entry.mode == 0o040000 { b'/' } else { 0 });
            name
        });
        let mut body = Vec::new();
        for entry in &entries {
            body.extend_from_slice(format!("{:o} ", entry.mode).as_bytes());
            body.extend_from_slice(&entry.name);
            body.push(0);
            body.extend_from_slice(entry.oid.as_bytes());
        }
        let id = git_object_id(self.format, GitObjectKind::Tree, &body);
        self.trees.insert(id, entries);
        id
    }
    fn add_commit(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            let _ = write!(body, "parent {parent}\n");
        }
        let _ = write!(
            body,
            "author Untrusted <a@invalid> 1 +0000\ncommitter Untrusted <a@invalid> 1 +0000\n\n{label}\n"
        );
        let body = body.into_bytes();
        let id = git_object_id(self.format, GitObjectKind::Commit, &body);
        self.commits.insert(
            id,
            (
                CommitInput {
                    tree,
                    parents: parents.to_vec(),
                },
                body,
            ),
        );
        id
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let count = self.checkpoints.get() + 1;
        self.checkpoints.set(count);
        if count >= self.stop_at.get() {
            Err(MergeSourceError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits
            .get(&id)
            .map(|row| row.0.clone())
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.tree_reads.set(self.tree_reads.get() + 1);
        self.trees
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, _id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        panic!("path history must not load blobs or follow links")
    }
}
impl HistorySource for Source {
    fn commit_body(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.commits
            .get(&id)
            .map(|row| row.1.clone())
            .ok_or(MergeSourceError::Unavailable(id))
    }
}
fn options(path: &[u8]) -> PathLogOptions {
    PathLogOptions {
        path: path.to_vec(),
        log: LogOptions::default(),
    }
}
fn ids(page: &HistoryPage) -> Vec<GitOid> {
    page.commits.iter().map(|row| row.id).collect()
}
fn read(source: &Source, tip: GitOid, path: &[u8]) -> HistoryPage {
    path_history(source, source.format, tip, &options(path)).unwrap()
}

#[test]
fn both_formats_filter_before_paging_and_track_mode_deletion_and_recreation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let original = source.add_tree(vec![source.entry(b"file", 0o100644, b"binary\0\xff")]);
        let root = source.add_commit(original, &[], "root");
        let noop = source.add_commit(original, &[root], "metadata only");
        let executable = source.add_tree(vec![source.entry(b"file", 0o100755, b"binary\0\xff")]);
        let mode = source.add_commit(executable, &[noop], "mode only");
        let empty = source.add_tree(vec![]);
        let deletion = source.add_commit(empty, &[mode], "delete");
        assert_eq!(
            ids(&read(&source, deletion, b"file")),
            vec![deletion, mode, root]
        );
        let recreated = source.add_commit(original, &[deletion], "recreate");
        let tip = source.add_commit(original, &[recreated], "another noop");
        let full = read(&source, tip, b"file");
        assert_eq!(full.tip, tip);
        assert_eq!(ids(&full), vec![recreated, deletion, mode, root]);
        let mut query = options(b"file");
        query.log.limit = 2;
        let first = path_history(&source, format, tip, &query).unwrap();
        assert_eq!(first.total_commits, 4);
        assert_eq!(first.next_after, Some(2));
        query.log.after = 2;
        let last = path_history(&source, format, tip, &query).unwrap();
        assert_eq!(ids(&last), vec![mode, root]);
        assert_eq!(last.next_after, None);
        query.log.after = 4;
        assert!(
            path_history(&source, format, tip, &query)
                .unwrap()
                .commits
                .is_empty()
        );
        query.log.after = 5;
        assert_eq!(
            path_history(&source, format, tip, &query),
            Err(HistoryError::LineRange)
        );
        assert_eq!(full.commits[2].parents, vec![noop]); // Never rewrite filtered parents.
    }
}

#[test]
fn merges_compare_every_parent_and_keep_native_id_topological_ties() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let a = source.add_tree(vec![source.entry(b"file", 0o100644, b"a")]);
    let b = source.add_tree(vec![source.entry(b"file", 0o100644, b"b")]);
    let c = source.add_tree(vec![source.entry(b"file", 0o100644, b"c")]);
    let base = source.add_commit(a, &[], "base");
    let left = source.add_commit(b, &[base], "left");
    let right = source.add_commit(c, &[base], "right");
    // Equal to FIRST parent, different from second: still a path change.
    let merge = source.add_commit(b, &[left, right], "merge");
    let result = read(&source, merge, b"file");
    assert_eq!(
        ids(&result),
        vec![merge, left.min(right), left.max(right), base]
    );
    assert_eq!(result.commits[0].parents, vec![left, right]);
    let duplicate = source.add_commit(b, &[merge, merge], "duplicate parents, no change");
    assert_eq!(ids(&read(&source, duplicate, b"file")), ids(&result));
}

#[test]
fn directories_raw_names_and_component_boundaries_are_exact() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let leaf = source.add_tree(vec![source.entry(b"\xff", 0o100644, b"v1")]);
        let root_tree = source.add_tree(vec![MergeEntry {
            name: b"dir".to_vec(),
            mode: 0o040000,
            oid: leaf,
        }]);
        let root = source.add_commit(root_tree, &[], "root");
        let leaf2 = source.add_tree(vec![source.entry(b"\xff", 0o100644, b"v2")]);
        let changed_tree = source.add_tree(vec![MergeEntry {
            name: b"dir".to_vec(),
            mode: 0o040000,
            oid: leaf2,
        }]);
        let changed = source.add_commit(changed_tree, &[root], "nested change");
        assert_eq!(ids(&read(&source, changed, b"dir")), vec![changed, root]);
        assert_eq!(
            ids(&read(&source, changed, b"dir/\xff")),
            vec![changed, root]
        );
        for path in [b"di".as_slice(), b"directory", b"dir/\xff/child"] {
            assert_eq!(read(&source, changed, path).total_commits, 0);
        }
    }
}

#[test]
fn symlinks_gitlinks_and_type_changes_are_opaque_and_never_traversed() {
    let mut source = Source::new(GitHashAlgorithm::Sha256);
    let regular = source.add_tree(vec![source.entry(b"path", 0o100644, b"target")]);
    let root = source.add_commit(regular, &[], "root");
    let link = source.add_tree(vec![source.entry(b"path", 0o120000, b"target")]);
    let symlink = source.add_commit(link, &[root], "link");
    let foreign_commit = git_object_id(
        source.format,
        GitObjectKind::Commit,
        b"foreign repository commit",
    );
    let module = source.add_tree(vec![MergeEntry {
        name: b"path".to_vec(),
        mode: 0o160000,
        oid: foreign_commit,
    }]);
    let gitlink = source.add_commit(module, &[symlink], "submodule");
    assert_eq!(
        ids(&read(&source, gitlink, b"path")),
        vec![gitlink, symlink, root]
    );
    assert_eq!(read(&source, gitlink, b"path/child").total_commits, 0);
}

#[test]
fn a_never_present_path_is_a_complete_empty_result_but_missing_trees_are_not() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let tree = source.add_tree(vec![source.entry(b"file", 0o100644, b"v1")]);
    let root = source.add_commit(tree, &[], "root");
    let page = read(&source, root, b"absent");
    assert_eq!(page.tip, root);
    assert_eq!(page.total_commits, 0);
    assert_eq!(page.next_after, None);
    assert!(page.commits.is_empty());
    source.trees.remove(&tree);
    assert_eq!(
        path_history(&source, source.format, root, &options(b"absent")),
        Err(HistoryError::Source(MergeSourceError::Unavailable(tree)))
    );
}

#[test]
fn identical_root_trees_are_read_once_even_for_nonmatching_commits() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let tree = source.add_tree(vec![source.entry(b"file", 0o100644, b"v1")]);
    let root = source.add_commit(tree, &[], "root");
    let mut tip = root;
    for n in 0..30 {
        tip = source.add_commit(tree, &[tip], &format!("noop {n}"));
    }
    assert_eq!(ids(&read(&source, tip, b"file")), vec![root]);
    assert_eq!(source.tree_reads.get(), 1);
}

#[test]
fn limits_cover_the_entire_graph_and_all_tree_work_not_just_output_matches() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let tree = source.add_tree(vec![
        source.entry(b"a", 0o100644, b"a"),
        source.entry(b"b", 0o100644, b"b"),
    ]);
    let root = source.add_commit(tree, &[], "root");
    let middle = source.add_commit(tree, &[root], "middle");
    let tip = source.add_commit(tree, &[middle], "tip");
    let mut query = options(b"absent");
    query.log.limits.max_commits = 2;
    assert_eq!(
        path_history(&source, source.format, tip, &query),
        Err(HistoryError::Budget("commits"))
    );
    query = options(b"absent");
    query.log.limits.max_edges = 1;
    assert_eq!(
        path_history(&source, source.format, tip, &query),
        Err(HistoryError::Budget("commit edges"))
    );
    query = options(b"absent");
    query.log.limits.max_tree_entries = 1;
    assert_eq!(
        path_history(&source, source.format, tip, &query),
        Err(HistoryError::Budget("tree entries"))
    );
    query = options(b"absent");
    query.log.limits.max_cached_bytes = 1;
    assert_eq!(
        path_history(&source, source.format, tip, &query),
        Err(HistoryError::Budget("path cache"))
    );
    query = options(b"a");
    query.log.limits.max_metadata_bytes = 1;
    assert_eq!(
        path_history(&source, source.format, tip, &query),
        Err(HistoryError::Budget("metadata bytes"))
    );
}

#[test]
fn every_checkpoint_cancels_without_returning_a_partial_page() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let tree = source.add_tree(vec![source.entry(b"a", 0o100644, b"a")]);
    let root = source.add_commit(tree, &[], "root");
    let tip = source.add_commit(tree, &[root], "tip");
    let expected = read(&source, tip, b"a");
    let checkpoints = source.checkpoints.get();
    for stop in 1..=checkpoints {
        source.checkpoints.set(0);
        source.stop_at.set(stop);
        assert_eq!(
            path_history(&source, source.format, tip, &options(b"a")),
            Err(HistoryError::Source(MergeSourceError::Cancelled)),
            "checkpoint {stop}"
        );
    }
    source.checkpoints.set(0);
    source.stop_at.set(usize::MAX);
    assert_eq!(read(&source, tip, b"a"), expected);
}

#[test]
fn malformed_paths_and_cross_format_tips_refuse_before_reading_objects() {
    let source = Source::new(GitHashAlgorithm::Sha1);
    let tip = git_object_id(source.format, GitObjectKind::Commit, b"tip");
    for path in [
        vec![],
        b"/a".to_vec(),
        b"a/".to_vec(),
        b"a//b".to_vec(),
        b"a/../b".to_vec(),
        b"a/./b".to_vec(),
        b"a\0b".to_vec(),
        vec![b'a'; 4097],
        b"a/".repeat(64),
    ] {
        assert_eq!(
            path_history(&source, source.format, tip, &options(&path)),
            Err(HistoryError::InvalidOptions)
        );
    }
    assert_eq!(source.checkpoints.get(), 0);
    let other = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Commit, b"tip");
    assert_eq!(
        path_history(&source, source.format, other, &options(b"a")),
        Err(HistoryError::InvalidObject(other))
    );
    assert_eq!(source.checkpoints.get(), 0);
}

#[test]
fn malformed_tree_entries_missing_ancestors_and_corrupt_records_fail_closed() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let entry = source.entry(b"a", 0o100644, b"a");
    let tree = source.add_tree(vec![entry.clone()]);
    let root = source.add_commit(tree, &[], "root");
    source.trees.get_mut(&tree).unwrap().push(entry.clone());
    assert_eq!(
        path_history(&source, source.format, root, &options(b"a")),
        Err(HistoryError::InvalidTree)
    );
    source.trees.insert(
        tree,
        vec![MergeEntry {
            mode: 0o100600,
            ..entry.clone()
        }],
    );
    assert_eq!(
        path_history(&source, source.format, root, &options(b"a")),
        Err(HistoryError::InvalidTree)
    );
    let other = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, b"a");
    source.trees.insert(
        tree,
        vec![MergeEntry {
            oid: other,
            ..entry.clone()
        }],
    );
    assert_eq!(
        path_history(&source, source.format, root, &options(b"a")),
        Err(HistoryError::InvalidObject(other))
    );
    source.trees.insert(tree, vec![entry]);
    let tip = source.add_commit(tree, &[root], "tip");
    source.commits.get_mut(&root).unwrap().1.push(b'x');
    assert_eq!(
        path_history(&source, source.format, tip, &options(b"a")),
        Err(HistoryError::InvalidObject(root))
    );
    source.commits.remove(&root);
    assert_eq!(
        path_history(&source, source.format, tip, &options(b"a")),
        Err(HistoryError::Source(MergeSourceError::Unavailable(root)))
    );
}
