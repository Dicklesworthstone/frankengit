use super::*;
use std::cell::Cell;
use fgit_crypto::{GitObjectKind, git_object_id};
use crate::preparation::{CommitInput, MergeEntry};

/// Pure planner fixtures, not an authority or durable-store substitute.
#[derive(Default)]
struct Source {
    blobs: BTreeMap<GitOid, Vec<u8>>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    commits: BTreeMap<GitOid, CommitInput>,
    reads: Cell<usize>,
    cancel: Cell<bool>,
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        if self.cancel.get() { Err(MergeSourceError::Cancelled) } else { Ok(()) }
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.reads.set(self.reads.get() + 1);
        self.blobs.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.reads.set(self.reads.get() + 1);
        self.trees.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
}
impl Source {
    fn blob_id(&mut self, format: GitHashAlgorithm, bytes: &[u8]) -> GitOid {
        let id = git_object_id(format, GitObjectKind::Blob, bytes);
        self.blobs.insert(id, bytes.to_vec()); id
    }
    fn tree_id(&mut self, format: GitHashAlgorithm, entries: &[(&[u8], u32, GitOid)]) -> GitOid {
        let mut entries: Vec<_> = entries.iter().map(|(name, mode, oid)| MergeEntry {
            name: name.to_vec(), mode: *mode, oid: *oid,
        }).collect();
        entries.sort_by_key(|entry| {
            let mut key = entry.name.clone(); key.push(if is_tree(entry.mode) { b'/' } else { 0 }); key
        });
        let mut bytes = Vec::new();
        for entry in &entries {
            bytes.extend_from_slice(format!("{:o} ", entry.mode).as_bytes());
            bytes.extend_from_slice(&entry.name); bytes.push(0); bytes.extend_from_slice(entry.oid.as_bytes());
        }
        let id = git_object_id(format, GitObjectKind::Tree, &bytes);
        self.trees.insert(id, entries); id
    }
    fn commit_id(&mut self, format: GitHashAlgorithm, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut bytes = format!("tree {tree}\n");
        for parent in parents { bytes.push_str(&format!("parent {parent}\n")); }
        bytes.push_str(&format!("author Test <t@example.invalid> 1 +0000\ncommitter Test <t@example.invalid> 1 +0000\n\n{label}\n"));
        let id = git_object_id(format, GitObjectKind::Commit, bytes.as_bytes());
        self.commits.insert(id, CommitInput { tree, parents: parents.to_vec() }); id
    }
    fn pair(&mut self, format: GitHashAlgorithm, old: &[u8], new: &[u8]) -> (GitOid, GitOid) {
        let a = self.blob_id(format, old); let b = self.blob_id(format, new);
        let a = self.tree_id(format, &[(b"file", 0o100644, a)]);
        let b = self.tree_id(format, &[(b"file", 0o100644, b)]);
        let a = self.commit_id(format, a, &[], "old");
        let b = self.commit_id(format, b, &[a], "new"); (a, b)
    }
}
fn apply_hunks(old: &[u8], hunks: &[ReviewHunk]) -> Vec<u8> {
    let mut result = Vec::new(); let mut cursor = 0;
    for hunk in hunks {
        assert!(hunk.old.byte_start >= cursor);
        assert_eq!(&old[hunk.old.byte_start..hunk.old.byte_end], hunk.before);
        result.extend_from_slice(&old[cursor..hunk.old.byte_start]);
        result.extend_from_slice(&hunk.after); cursor = hunk.old.byte_end;
    }
    result.extend_from_slice(&old[cursor..]); result
}

#[test]
fn context_hunks_reconstruct_exact_bytes_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for (old, new) in [(b"".as_slice(), b"first\n".as_slice()),
            (b"gone\n", b""), (b"a\r\nb\r\nlast", b"a\r\nchanged\r\nlast\n"),
            (b"\xff\nold", b"\xff\nnew"), (b"a\nb\nc\nd\ne\nf\ng\n", b"A\nb\nc\nd\ne\nf\nG\n")]
        {
            for context in [0, 1, 3, 20] {
                let mut source = Source::default(); let (a, b) = source.pair(format, old, new);
                let options = ReviewOptions { context_lines: context, ..ReviewOptions::default() };
                let report = compare_source(&source, format, a, b, &options).unwrap();
                let ReviewContent::Text { hunks, before_bytes, after_bytes, .. } = &report.entries[0].content else { panic!("text"); };
                assert_eq!((*before_bytes, *after_bytes), (old.len(), new.len()));
                assert_eq!(apply_hunks(old, hunks), new);
                for hunk in hunks {
                    assert_eq!(&new[hunk.new.byte_start..hunk.new.byte_end], hunk.after);
                    assert_eq!(old[..hunk.old.byte_start].iter().filter(|byte| **byte == b'\n').count(), hunk.old.line_start);
                }
                assert_eq!(compare_source(&source, format, a, b, &options).unwrap(), report);
            }
        }
    }
}

#[test]
fn merge_base_excludes_target_only_work_and_direct_comparison_does_not() {
    let format = GitHashAlgorithm::Sha256; let mut source = Source::default();
    let original = source.blob_id(format, b"base\n"); let change = source.blob_id(format, b"change\n");
    let root = source.tree_id(format, &[(b"a", 0o100644, original), (b"b", 0o100644, original)]);
    let base = source.commit_id(format, root, &[], "base");
    let root_a = source.tree_id(format, &[(b"a", 0o100644, change), (b"b", 0o100644, original)]);
    let root_b = source.tree_id(format, &[(b"a", 0o100644, original), (b"b", 0o100644, change)]);
    let a = source.commit_id(format, root_a, &[base], "ours"); let b = source.commit_id(format, root_b, &[base], "theirs");
    let mut options = ReviewOptions::default();
    assert_eq!(compare_source(&source, format, a, b, &options).unwrap().entries.len(), 2);
    options.mode = ComparisonMode::MergeBase;
    let report = compare_source(&source, format, a, b, &options).unwrap();
    assert_eq!(report.compared_before, base); assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].path, b"b");
}

#[test]
fn mode_binary_links_empty_files_and_empty_directories_remain_visible() {
    let f = GitHashAlgorithm::Sha1; let mut source = Source::default();
    let text = source.blob_id(f, b"same\n"); let binary = source.blob_id(f, b"\0payload");
    let empty = source.blob_id(f, b""); let empty_tree = source.tree_id(f, &[]);
    let root = source.tree_id(f, &[(b"mode", 0o100644, text)]); let a = source.commit_id(f, root, &[], "a");
    let root = source.tree_id(f, &[(b"binary", 0o100644, binary), (b"empty", 0o100644, empty),
        (b"empty-dir", 0o040000, empty_tree), (b"link", 0o120000, text),
        (b"mode", 0o100755, text), (b"submodule", 0o160000, a)]);
    let b = source.commit_id(f, root, &[a], "b");
    let report = compare_source(&source, f, a, b, &ReviewOptions::default()).unwrap();
    assert_eq!(report.entries.len(), 6);
    assert!(matches!(report.entries[0].content, ReviewContent::Binary { .. }));
    assert!(matches!(report.entries[1].content, ReviewContent::Text { additions: 0, .. }));
    assert!(matches!(report.entries[2].content, ReviewContent::ObjectOnly));
    assert!(matches!(report.entries[4].content, ReviewContent::Identical));
    assert_eq!(report.entries[4].kind, ChangeKind::ModeChanged);
    assert!(matches!(report.entries[5].content, ReviewContent::ObjectOnly));
}

#[test]
fn type_changes_coalesce_git_order_and_unchanged_subtrees_are_not_read() {
    let f = GitHashAlgorithm::Sha1; let mut source = Source::default(); let blob = source.blob_id(f, b"file\n");
    let nested = source.tree_id(f, &[(b"inside", 0o100644, blob)]);
    let unchanged = source.tree_id(f, &[(b"unread", 0o100644, blob)]);
    let a_tree = source.tree_id(f, &[(b"a", 0o100644, blob), (b"a.b", 0o100644, blob), (b"stable", 0o040000, unchanged)]);
    let b_tree = source.tree_id(f, &[(b"a", 0o040000, nested), (b"a.b", 0o100644, blob), (b"stable", 0o040000, unchanged)]);
    let a = source.commit_id(f, a_tree, &[], "a"); let b = source.commit_id(f, b_tree, &[a], "b");
    source.trees.remove(&unchanged);
    let report = compare_source(&source, f, a, b, &ReviewOptions::default()).unwrap();
    assert_eq!(report.entries.iter().map(|e| e.path.as_slice()).collect::<Vec<_>>(), [b"a".as_slice(), b"a/inside"]);
    assert_eq!(report.entries[0].kind, ChangeKind::TypeChanged);
    let options = ReviewOptions { paths: vec![b"a/inside".to_vec()], ..ReviewOptions::default() };
    assert_eq!(compare_source(&source, f, a, b, &options).unwrap().entries.len(), 1);
    let options = ReviewOptions { paths: vec![b"a/missing".to_vec()], ..ReviewOptions::default() };
    assert!(compare_source(&source, f, a, b, &options).unwrap().entries.is_empty());
}

#[test]
fn failures_are_not_successful_empty_or_partial_reports() {
    let f = GitHashAlgorithm::Sha1; let mut source = Source::default(); let (a, b) = source.pair(f, b"a\nb\n", b"A\nB\n");
    let mut options = ReviewOptions::default(); options.limits.max_blob_bytes = 1;
    assert!(matches!(compare_source(&source, f, a, b, &options), Err(ReviewError::Budget("blob bytes"))));
    options = ReviewOptions::default(); options.limits.max_output_bytes = 1;
    assert!(matches!(compare_source(&source, f, a, b, &options), Err(ReviewError::Budget("output bytes"))));
    options = ReviewOptions::default(); options.limits.max_diff_work = 1;
    assert!(matches!(compare_source(&source, f, a, b, &options), Err(ReviewError::Diff(DiffError::WorkExceeded { .. }))));
    for path in [b"../x".as_slice(), b"/x", b"x//y", b"x/", b"x/./y", b"x\0y"] {
        options = ReviewOptions { paths: vec![path.to_vec()], ..ReviewOptions::default() };
        assert!(matches!(compare_source(&source, f, a, b, &options), Err(ReviewError::InvalidOptions)));
    }
    options = ReviewOptions::default(); source.cancel.set(true);
    assert!(matches!(compare_source(&source, f, a, b, &options), Err(ReviewError::Source(MergeSourceError::Cancelled))));
    source.cancel.set(false); source.blobs.clear();
    assert!(matches!(compare_source(&source, f, a, b, &options), Err(ReviewError::Source(MergeSourceError::Unavailable(_)))));
}

#[test]
fn ambiguous_or_unrelated_histories_never_choose_an_arbitrary_base() {
    let f = GitHashAlgorithm::Sha1; let mut source = Source::default(); let tree = source.tree_id(f, &[]);
    let root = source.commit_id(f, tree, &[], "root"); let other = source.commit_id(f, tree, &[], "unrelated");
    let a = source.commit_id(f, tree, &[root], "a"); let b = source.commit_id(f, tree, &[root], "b");
    let left = source.commit_id(f, tree, &[a, b], "left"); let right = source.commit_id(f, tree, &[b, a], "right");
    let options = ReviewOptions { mode: ComparisonMode::MergeBase, ..ReviewOptions::default() };
    assert!(matches!(compare_source(&source, f, left, right, &options), Err(ReviewError::MultipleMergeBases(_))));
    assert!(matches!(compare_source(&source, f, root, other, &options), Err(ReviewError::NoCommonAncestor)));
    assert!(compare_source(&source, f, root, root, &options).unwrap().entries.is_empty());
}
