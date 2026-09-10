use super::*;
use super::super::{CommitInput, ConflictKind, MergePreparation, prepare_merge};
use std::cell::Cell;

struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    remaining: Cell<usize>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self { format, commits: BTreeMap::new(), trees: BTreeMap::new(),
            blobs: BTreeMap::new(), remaining: Cell::new(usize::MAX) }
    }
    fn file(&mut self, name: &[u8], bytes: &[u8], mode: u32) -> MergeEntry {
        let oid = git_object_id(self.format, GitObjectKind::Blob, bytes);
        self.blobs.insert(oid, bytes.to_vec());
        MergeEntry { name: name.to_vec(), mode, oid }
    }
    fn store_tree(&mut self, mut entries: Vec<MergeEntry>) -> GitOid {
        entries.sort_by_cached_key(|entry| {
            let mut name = entry.name.clone(); name.push(if entry.mode == 0o040000 { b'/' } else { 0 }); name
        });
        let mut body = Vec::new();
        for entry in &entries {
            body.extend(format!("{:o} ", entry.mode).as_bytes()); body.extend(&entry.name);
            body.push(0); body.extend(entry.oid.as_bytes());
        }
        let oid = git_object_id(self.format, GitObjectKind::Tree, &body);
        self.trees.insert(oid, entries); oid
    }
    fn store_commit(&mut self, tree: GitOid, parents: &[GitOid], message: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents { body.push_str(&format!("parent {parent}\n")); }
        body.push_str(&format!("author T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\n{message}"));
        let oid = git_object_id(self.format, GitObjectKind::Commit, body.as_bytes());
        self.commits.insert(oid, CommitInput { tree, parents: parents.to_vec() }); oid
    }
    fn fork(&mut self, base: Vec<MergeEntry>, ours: Vec<MergeEntry>, theirs: Vec<MergeEntry>) -> ResolutionInputs {
        let tree = self.store_tree(base); let base = self.store_commit(tree, &[], "base");
        let tree = self.store_tree(ours); let target = self.store_commit(tree, &[base], "ours");
        let tree = self.store_tree(theirs); let source = self.store_commit(tree, &[base], "theirs");
        ResolutionInputs { base, target, source }
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let remaining = self.remaining.get().checked_sub(1).ok_or(MergeSourceError::Cancelled)?;
        self.remaining.set(remaining); Ok(())
    }
    fn commit(&self, oid: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits.get(&oid).cloned().ok_or(MergeSourceError::Unavailable(oid))
    }
    fn tree(&self, oid: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.trees.get(&oid).cloned().ok_or(MergeSourceError::Unavailable(oid))
    }
    fn blob(&self, oid: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.blobs.get(&oid).cloned().ok_or(MergeSourceError::Unavailable(oid))
    }
}
fn metadata() -> MergeMetadata {
    MergeMetadata { author: "T <t@x>".into(), committer: "T <t@x>".into(),
        timestamp: 1, message: b"explicitly resolved\n".to_vec() }
}
fn resolution(path: &[u8], choice: ResolutionChoice) -> ConflictResolution {
    ConflictResolution { path: path.to_vec(), choice }
}
fn run(s: &Source, inputs: ResolutionInputs, choices: &[ConflictResolution]) -> Result<ResolvedMerge, ResolutionError> {
    prepare_resolved_merge(s, s.format, inputs, choices, &metadata(), PreparationLimits::default())
}
fn simple(format: GitHashAlgorithm) -> (Source, ResolutionInputs, [MergeEntry; 3]) {
    let mut s = Source::new(format);
    let base = s.file(b"file", b"base\n", 0o100644);
    let ours = s.file(b"file", b"ours\n", 0o100644);
    let theirs = s.file(b"file", b"theirs\n", 0o100644);
    let inputs = s.fork(vec![base.clone()], vec![ours.clone()], vec![theirs.clone()]);
    (s, inputs, [base, ours, theirs])
}

#[test]
fn resolved_nested_content_preserves_clean_merges_modes_raw_bytes_and_siblings() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut s = Source::new(format);
        let keep = s.file(b"keep", b"not copied", 0o100644);
        let b = s.file(b"conflict", b"base\n", 0o100644);
        let o = s.file(b"conflict", b"ours\n", 0o100644);
        let t = s.file(b"conflict", b"theirs\n", 0o100644);
        let ab = s.file(b"auto", b"a\nb\nc\nd\ne\n", 0o100644);
        let ao = s.file(b"auto", b"A\nb\nc\nd\ne\n", 0o100644);
        let at = s.file(b"auto", b"a\nb\nc\nd\nE\n", 0o100644);
        let dir = |oid| MergeEntry { name: b"dir".to_vec(), mode: 0o040000, oid };
        let bt = s.store_tree(vec![ab, b]); let ot = s.store_tree(vec![ao, o]); let tt = s.store_tree(vec![at, t]);
        let inputs = s.fork(vec![dir(bt), keep.clone()], vec![dir(ot), keep.clone()], vec![dir(tt), keep.clone()]);
        let merged_auto = s.file(b"auto", b"A\nb\nc\nd\nE\n", 0o100644);
        let resolved = s.file(b"conflict", b"\xff\0resolved\r\nno final newline", 0o100755);
        let resolved_id = resolved.oid;
        let expected_dir = s.store_tree(vec![merged_auto, resolved]);
        let expected_tree = s.store_tree(vec![dir(expected_dir), keep.clone()]);
        let choices = [resolution(b"dir/conflict", ResolutionChoice::File {
            mode: 0o100755, bytes: b"\xff\0resolved\r\nno final newline".to_vec(),
        })];
        let result = run(&s, inputs, &choices).unwrap();
        assert_eq!(result, run(&s, inputs, &choices).unwrap());
        assert_eq!(result.plan.tree, expected_tree);
        assert_eq!(result.resolutions.len(), 1);
        assert_eq!(result.resolutions[0].conflict.kind, ConflictKind::Content);
        assert_eq!(result.resolutions[0].result.as_ref().unwrap().oid, resolved_id);
        assert!(!result.plan.objects.iter().any(|object| object.id == keep.oid));
        assert_eq!(result.plan.objects.iter().map(|o| o.id).collect::<std::collections::BTreeSet<_>>().len(), result.plan.objects.len());
        for object in &result.plan.objects { assert_eq!(object.id, git_object_id(format, object.kind, &object.body)); }
        let commit = result.plan.objects.iter().find(|o| o.id == result.plan.commit).unwrap();
        assert!(commit.body.starts_with(format!("tree {expected_tree}\nparent {}\nparent {}\n", inputs.target, inputs.source).as_bytes()));
        assert!(matches!(prepare_merge(&s, format, inputs.target, inputs.source, &metadata(), PreparationLimits::default()).unwrap(),
            MergePreparation::Conflicted { .. }), "explicit choices must not change automatic behavior");
    }
}

#[test]
fn explicit_sides_and_deletion_have_exact_native_trees() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut s, inputs, entries) = simple(format);
        for (choice, expected) in [
            (ResolutionChoice::Base, Some(entries[0].clone())),
            (ResolutionChoice::Ours, Some(entries[1].clone())),
            (ResolutionChoice::Theirs, Some(entries[2].clone())),
            (ResolutionChoice::Delete, None),
        ] {
            let tree = s.store_tree(expected.clone().into_iter().collect());
            let result = run(&s, inputs, &[resolution(b"file", choice)]).unwrap();
            assert_eq!(result.plan.tree, tree);
            assert_eq!(result.resolutions[0].result, expected);
        }
    }
}

#[test]
fn missing_side_does_not_mean_delete_and_unresolved_or_extra_choices_fail() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let base = s.file(b"file", b"base", 0o100644);
    let theirs = s.file(b"file", b"theirs", 0o100644);
    let inputs = s.fork(vec![base], vec![], vec![theirs]);
    assert!(matches!(run(&s, inputs, &[]), Err(ResolutionError::Unresolved(conflicts)) if conflicts.len() == 1));
    assert!(matches!(run(&s, inputs, &[resolution(b"file", ResolutionChoice::Ours)]), Err(ResolutionError::MissingSide { .. })));
    assert!(matches!(run(&s, inputs, &[resolution(b"unrelated", ResolutionChoice::Delete)]), Err(ResolutionError::NonConflictPath(_))));
    assert!(run(&s, inputs, &[resolution(b"file", ResolutionChoice::Delete)]).is_ok());
    let (s, inputs, _) = simple(GitHashAlgorithm::Sha256);
    let stale = ResolutionInputs { base: inputs.target, ..inputs };
    assert!(matches!(run(&s, stale, &[resolution(b"file", ResolutionChoice::Theirs)]), Err(ResolutionError::BaseMismatch { .. })));
}

#[test]
fn directory_type_conflicts_can_select_a_whole_side_without_following_links() {
    let mut s = Source::new(GitHashAlgorithm::Sha256);
    let b = s.file(b"item", b"base", 0o100644);
    let o = s.file(b"item", b"ours", 0o120000);
    let child = s.file(b"nested", b"theirs", 0o100644);
    let tree = s.store_tree(vec![child]);
    let t = MergeEntry { name: b"item".to_vec(), mode: 0o040000, oid: tree };
    let inputs = s.fork(vec![b], vec![o.clone()], vec![t.clone()]);
    for (choice, entry) in [(ResolutionChoice::Ours, o), (ResolutionChoice::Theirs, t)] {
        let expected = s.store_tree(vec![entry.clone()]);
        let result = run(&s, inputs, &[resolution(b"item", choice)]).unwrap();
        assert_eq!(result.plan.tree, expected);
        assert_eq!(result.resolutions[0].result, Some(entry));
        assert_eq!(result.resolutions[0].conflict.kind, ConflictKind::TypeChange);
    }
}

#[test]
fn choices_cannot_bypass_path_limits_missing_sources_or_cancellation() {
    let (s, inputs, entries) = simple(GitHashAlgorithm::Sha1);
    for path in [b"".as_slice(), b"/file", b"file/", b"a/../file", b".GIT/config", b"a\0b"] {
        assert!(validate_resolutions(&[resolution(path, ResolutionChoice::Delete)], PreparationLimits::default()).is_err());
    }
    assert!(matches!(validate_resolutions(&[resolution(b"a", ResolutionChoice::Delete), resolution(b"a-", ResolutionChoice::Delete),
        resolution(b"a/b", ResolutionChoice::Delete)], PreparationLimits::default()), Err(ResolutionError::OverlappingPaths)));
    let choices = [resolution(b"file", ResolutionChoice::Theirs)];
    assert!(matches!(run(&s, inputs, &[choices[0].clone(), choices[0].clone()]), Err(ResolutionError::DuplicatePath(_))));
    s.remaining.set(0);
    assert!(matches!(run(&s, inputs, &choices), Err(ResolutionError::Preparation(PreparationError::Source(MergeSourceError::Cancelled)))));
    let (mut s, inputs, _) = simple(GitHashAlgorithm::Sha1);
    s.blobs.remove(&entries[1].oid);
    assert!(matches!(run(&s, inputs, &choices), Err(ResolutionError::Preparation(PreparationError::Source(MergeSourceError::Unavailable(_))))));
}

#[test]
fn discovery_and_reconstruction_share_one_work_budget() {
    let (s, inputs, _) = simple(GitHashAlgorithm::Sha1);
    let choices = [resolution(b"file", ResolutionChoice::Theirs)];
    // One automatic content comparison succeeds, but resolution requires the
    // same comparison again. It must not get an implicit second allowance.
    let limits = PreparationLimits { max_content_merges: 1, ..PreparationLimits::default() };
    assert!(matches!(prepare_resolved_merge(&s, s.format, inputs, &choices, &metadata(), limits),
        Err(ResolutionError::Preparation(PreparationError::Budget("content merges")))));
    assert!(run(&s, inputs, &choices).is_ok());
    let limits = PreparationLimits { max_tree_entries: 3, ..PreparationLimits::default() };
    assert!(matches!(prepare_resolved_merge(&s, s.format, inputs, &choices, &metadata(), limits),
        Err(ResolutionError::Preparation(PreparationError::Budget("tree entries")))));
}

#[test]
fn attribute_conflicts_use_explicit_bytes_and_clean_changes_cannot_be_overridden() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let a = s.file(b".gitattributes", b"* merge=external\n", 0o100644);
    let b = s.file(b"file", b"a\nb\nc\n", 0o100644);
    let o = s.file(b"file", b"A\nb\nc\n", 0o100644);
    let t = s.file(b"file", b"a\nb\nC\n", 0o100644);
    let inputs = s.fork(vec![a.clone(), b], vec![a.clone(), o], vec![a.clone(), t]);
    let result = run(&s, inputs, &[resolution(b"file", ResolutionChoice::File { mode: 0o100644, bytes: b"reviewed bytes".to_vec() })]).unwrap();
    assert_eq!(result.resolutions[0].conflict.kind, ConflictKind::AttributesRequireDriver);
    assert!(matches!(run(&s, inputs, &[resolution(b"file", ResolutionChoice::Theirs), resolution(b".gitattributes", ResolutionChoice::Delete)]),
        Err(ResolutionError::NonConflictPath(_))));
    let empty = s.store_tree(vec![]); let first = s.store_commit(empty, &[], "first"); let next = s.store_commit(empty, &[first], "next");
    assert!(matches!(run(&s, ResolutionInputs { base: first, target: first, source: next }, &[]), Err(ResolutionError::NoConflicts)));
}
