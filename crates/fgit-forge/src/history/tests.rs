use super::*;
use crate::preparation::MergeEntry;
use std::cell::Cell;

struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, (CommitInput, Vec<u8>)>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    checkpoints: Cell<usize>,
    stop_at: Cell<usize>,
    blob_reads: Cell<usize>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self { format, commits: BTreeMap::new(), trees: BTreeMap::new(), blobs: BTreeMap::new(),
            checkpoints: Cell::new(0), stop_at: Cell::new(usize::MAX), blob_reads: Cell::new(0) }
    }
    fn add_blob(&mut self, body: &[u8]) -> GitOid {
        let id = git_object_id(self.format, GitObjectKind::Blob, body);
        self.blobs.insert(id, body.to_vec()); id
    }
    fn add_tree(&mut self, mut entries: Vec<MergeEntry>) -> GitOid {
        entries.sort_by_key(|entry| { let mut key = entry.name.clone();
            key.push(if entry.mode == 0o040000 { b'/' } else { 0 }); key });
        let mut body = Vec::new();
        for entry in &entries {
            body.extend(format!("{:o} ", entry.mode).as_bytes()); body.extend(&entry.name);
            body.push(0); body.extend(entry.oid.as_bytes());
        }
        let id = git_object_id(self.format, GitObjectKind::Tree, &body);
        self.trees.insert(id, entries); id
    }
    fn add_commit(&mut self, body: &[u8], parents: &[GitOid], label: &str) -> GitOid {
        let blob = self.add_blob(body);
        let tree = self.add_tree(vec![MergeEntry { name: b"file".to_vec(), mode: 0o100644, oid: blob }]);
        self.commit_tree(tree, parents, label)
    }
    fn commit_tree(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut text = format!("tree {tree}\n");
        for parent in parents { text.push_str(&format!("parent {parent}\n")); }
        text.push_str(&format!("author Untrusted <u@example.invalid> 1 +0000\ncommitter Untrusted <u@example.invalid> 1 +0000\n\n{label}\n"));
        let body = text.into_bytes();
        let id = git_object_id(self.format, GitObjectKind::Commit, &body);
        self.commits.insert(id, (CommitInput { tree, parents: parents.to_vec() }, body)); id
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let count = self.checkpoints.get() + 1; self.checkpoints.set(count);
        if count >= self.stop_at.get() { Err(MergeSourceError::Cancelled) } else { Ok(()) }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits.get(&id).map(|(commit, _)| commit.clone()).ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.trees.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.blob_reads.set(self.blob_reads.get() + 1);
        self.blobs.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
}
impl HistorySource for Source {
    fn commit_body(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.commits.get(&id).map(|(_, body)| body.clone()).ok_or(MergeSourceError::Unavailable(id))
    }
}
fn options() -> BlameOptions {
    BlameOptions { path: b"file".to_vec(), first_line: 0, end_line: None, limits: HistoryLimits::default() }
}
fn diamond(format: GitHashAlgorithm) -> (Source, [GitOid; 4]) {
    let mut source = Source::new(format);
    let base = source.add_commit(b"a\r\nb\nc\nd\n", &[], "base");
    let left = source.add_commit(b"A\r\nb\nc\nd\n", &[base], "left");
    let right = source.add_commit(b"a\r\nb\nC\nd\n", &[base], "right");
    let merge = source.add_commit(b"A\r\nb\nC\nd\nresolved\xff", &[left, right], "merge");
    (source, [base, left, right, merge])
}

#[test]
fn both_formats_attribute_through_both_parents_and_verify_every_original_byte() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, [base, left, right, merge]) = diamond(format);
        let result = blame(&source, format, merge, &options()).unwrap();
        assert_eq!(result.lines.iter().map(|line| line.origin_commit).collect::<Vec<_>>(),
            vec![left, base, right, base, merge]);
        assert_eq!(result.content, b"A\r\nb\nC\nd\nresolved\xff");
        assert_eq!(result.graph_commits, 4);
        for line in &result.lines {
            let original = &source.blobs[&line.origin_blob];
            assert_eq!(&result.content[line.byte_start..line.byte_end],
                &original[line.origin_byte_start..line.origin_byte_end]);
        }
        assert!(result.origins.windows(2).all(|pair| pair[0].id < pair[1].id));
        assert_eq!(blame(&source, format, merge, &options()).unwrap(), result);
    }
}

#[test]
fn history_pages_are_child_before_parent_and_native_id_ties_are_stable() {
    let (source, [base, left, right, merge]) = diamond(GitHashAlgorithm::Sha1);
    let first = commit_history(&source, source.format, merge, LogOptions { limit: 2, ..LogOptions::default() }).unwrap();
    assert_eq!(first.total_commits, 4);
    assert_eq!(first.commits[0].id, merge);
    assert_eq!(first.commits[1].id, left.min(right));
    assert_eq!(first.next_after, Some(2));
    let second = commit_history(&source, source.format, merge, LogOptions { after: 2, limit: 2, ..LogOptions::default() }).unwrap();
    assert_eq!(second.commits.iter().map(|commit| commit.id).collect::<Vec<_>>(), vec![left.max(right), base]);
    assert_eq!(second.next_after, None);
    assert_eq!(first.commits[0].parents, vec![left, right]);
    let empty = commit_history(&source, source.format, merge, LogOptions { after: 4, ..LogOptions::default() }).unwrap();
    assert!(empty.commits.is_empty());
    assert!(commit_history(&source, source.format, merge, LogOptions { after: 5, ..LogOptions::default() }).is_err());
}

#[test]
fn identical_parent_ties_choose_original_parent_order_not_object_id_order() {
    let mut source = Source::new(GitHashAlgorithm::Sha256);
    let base = source.add_commit(b"old\n", &[], "base");
    let a = source.add_commit(b"same\n", &[base], "a");
    let b = source.add_commit(b"same\n", &[base], "b");
    let first = a.max(b); let second = a.min(b);
    let merge = source.add_commit(b"same\n", &[first, second], "merge");
    let result = blame(&source, source.format, merge, &options()).unwrap();
    assert_eq!(result.lines[0].origin_commit, first);
    assert_eq!(result.lines[0].origin_line, 0);
}

#[test]
fn shifted_lines_ranges_empty_files_and_missing_final_newlines_remain_exact() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let base = source.add_commit(b"same\nlast", &[], "base");
    let next = source.add_commit(b"inserted\nsame\nlast", &[base], "next");
    let mut range = options(); range.first_line = 1; range.end_line = Some(3);
    let result = blame(&source, source.format, next, &range).unwrap();
    assert_eq!(result.content, b"same\nlast"); assert_eq!(result.content_byte_start, 9);
    assert_eq!(result.lines.iter().map(|line| (line.line, line.origin_line)).collect::<Vec<_>>(), vec![(1, 0), (2, 1)]);
    assert!(result.lines.iter().all(|line| line.origin_commit == base));
    range.end_line = Some(4); assert_eq!(blame(&source, source.format, next, &range), Err(HistoryError::LineRange));
    let empty = source.add_commit(b"", &[], "empty");
    let result = blame(&source, source.format, empty, &options()).unwrap();
    assert!(result.lines.is_empty() && result.origins.is_empty() && result.content.is_empty());
}

#[test]
fn missing_corrupt_and_binary_sources_never_become_attribution_boundaries() {
    let (mut source, [base, _, _, merge]) = diamond(GitHashAlgorithm::Sha1);
    source.commits.remove(&base);
    assert!(matches!(blame(&source, source.format, merge, &options()), Err(HistoryError::Source(MergeSourceError::Unavailable(id))) if id == base));
    let mut source = Source::new(GitHashAlgorithm::Sha256);
    let tip = source.add_commit(b"text\n", &[], "tip");
    let blob = source.trees[&source.commits[&tip].0.tree][0].oid;
    source.blobs.insert(blob, b"altered\n".to_vec());
    assert_eq!(blame(&source, source.format, tip, &options()), Err(HistoryError::InvalidObject(blob)));
    let binary = source.add_commit(b"nul\0data", &[], "binary");
    assert_eq!(blame(&source, source.format, binary, &options()), Err(HistoryError::BinaryContent));
    source.commits.get_mut(&tip).unwrap().1.push(b'!');
    assert_eq!(commit_history(&source, source.format, tip, LogOptions::default()), Err(HistoryError::InvalidObject(tip)));
}

#[test]
fn every_bound_and_cancellation_stop_without_a_partial_success() {
    let (source, [_, _, _, tip]) = diamond(GitHashAlgorithm::Sha1);
    let mut limited = options(); limited.limits.max_commits = 3;
    assert_eq!(blame(&source, source.format, tip, &limited), Err(HistoryError::Budget("commits")));
    limited = options(); limited.limits.max_lines = 2;
    assert_eq!(blame(&source, source.format, tip, &limited), Err(HistoryError::Budget("line count")));
    limited = options(); limited.limits.max_comparisons = 1;
    assert_eq!(blame(&source, source.format, tip, &limited), Err(HistoryError::Budget("line comparisons")));
    limited = options(); limited.limits.max_cached_bytes = 1;
    assert_eq!(blame(&source, source.format, tip, &limited), Err(HistoryError::Budget("blob cache")));
    for stop in [1, 5, 20, 50] {
        source.checkpoints.set(0); source.stop_at.set(stop);
        assert!(matches!(blame(&source, source.format, tip, &options()), Err(HistoryError::Source(MergeSourceError::Cancelled))));
    }
}

#[test]
fn tree_identity_reuse_skips_content_diffs_and_symlinks_are_not_followed() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let base = source.add_commit(b"kept\n", &[], "base");
    let mut tip = base;
    for n in 0..20 { tip = source.add_commit(b"kept\n", &[tip], &format!("metadata-{n}")); }
    let result = blame(&source, source.format, tip, &options()).unwrap();
    assert_eq!(result.lines[0].origin_commit, base); assert_eq!(result.comparisons, 0);
    assert_eq!(source.blob_reads.get(), 1);
    let link = source.add_blob(b"other");
    let tree = source.add_tree(vec![MergeEntry { name: b"file".to_vec(), mode: 0o120000, oid: link }]);
    let tip = source.commit_tree(tree, &[base], "symlink");
    assert_eq!(blame(&source, source.format, tip, &options()), Err(HistoryError::PathUnavailable));
}

#[test]
fn cyclic_input_is_explicitly_refused_and_raw_nested_names_are_preserved() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let tip = source.add_commit(b"one\n", &[], "root");
    source.commits.get_mut(&tip).unwrap().0.parents.push(tip);
    assert_eq!(commit_history(&source, source.format, tip, LogOptions::default()), Err(HistoryError::CyclicHistory));
    source.commits.get_mut(&tip).unwrap().0.parents.clear();
    let blob = source.add_blob(b"raw\xff\r\n");
    let child = source.add_tree(vec![MergeEntry { name: vec![255], mode: 0o100755, oid: blob }]);
    let root = source.add_tree(vec![MergeEntry { name: b"dir".to_vec(), mode: 0o040000, oid: child }]);
    let raw = source.commit_tree(root, &[], "raw path");
    let mut opts = options(); opts.path = b"dir/\xff".to_vec();
    let result = blame(&source, source.format, raw, &opts).unwrap();
    assert_eq!(result.path, opts.path); assert_eq!(result.content, b"raw\xff\r\n");
    for path in [b"../file".to_vec(), b"dir//file".to_vec(), b"/file".to_vec(), vec![]] {
        opts.path = path; assert_eq!(blame(&source, source.format, raw, &opts), Err(HistoryError::InvalidOptions));
    }
}
