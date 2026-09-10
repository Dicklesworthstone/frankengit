use super::*;
use super::super::ConflictKind;
use std::cell::{Cell, RefCell};

struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    read_commits: RefCell<Vec<GitOid>>,
    live: Cell<bool>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self { format, commits: BTreeMap::new(), trees: BTreeMap::new(), blobs: BTreeMap::new(),
            read_commits: RefCell::new(Vec::new()), live: Cell::new(true) }
    }
    fn file(&mut self, name: &[u8], bytes: &[u8], mode: u32) -> MergeEntry {
        let oid = git_object_id(self.format, GitObjectKind::Blob, bytes);
        self.blobs.insert(oid, bytes.to_vec());
        MergeEntry { name: name.to_vec(), mode, oid }
    }
    fn store_tree(&mut self, mut entries: Vec<MergeEntry>) -> GitOid {
        entries.sort_by_cached_key(|entry| { let mut key = entry.name.clone();
            key.push(if entry.mode == 0o040000 { b'/' } else { 0 }); key });
        let mut bytes = Vec::new();
        for entry in &entries {
            bytes.extend_from_slice(format!("{:o} ", entry.mode).as_bytes());
            bytes.extend_from_slice(&entry.name); bytes.push(0); bytes.extend_from_slice(entry.oid.as_bytes());
        }
        let id = git_object_id(self.format, GitObjectKind::Tree, &bytes);
        self.trees.insert(id, entries); id
    }
    fn store_commit(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut bytes = format!("tree {tree}\n");
        for parent in parents { bytes.push_str(&format!("parent {parent}\n")); }
        bytes.push_str(&format!("author T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\n{label}\n"));
        let id = git_object_id(self.format, GitObjectKind::Commit, bytes.as_bytes());
        self.commits.insert(id, CommitInput { tree, parents: parents.to_vec() }); id
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        if self.live.get() { Ok(()) } else { Err(MergeSourceError::Cancelled) }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.read_commits.borrow_mut().push(id);
        self.commits.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.trees.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.blobs.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
}
fn metadata() -> MergeMetadata {
    MergeMetadata { author: "T <t@x>".into(), committer: "T <t@x>".into(), timestamp: 2,
        message: b"explicit replay\r\nno final newline\xff".to_vec() }
}
fn request(target: GitOid, source_tip: GitOid, selected_commit: GitOid, direction: ReplayDirection) -> ReplayRequest {
    ReplayRequest { target, source_tip, selected_commit, direction, mainline: None }
}
fn clean(source: &Source, request: ReplayRequest) -> PreparedReplay {
    match prepare_replay(source, source.format, request, &metadata(), PreparationLimits::default()).unwrap() {
        ReplayPreparation::Clean(plan) => plan,
        other => panic!("expected clean replay, got {other:?}"),
    }
}

#[test]
fn historical_pick_preserves_target_changes_without_replaying_later_source_commits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut s = Source::new(format);
        let base_file = s.file(b"file", b"one\ntwo\nthree\nfour\nfive\n", 0o100644);
        let keep = s.file(b"keep", b"unchanged\0\xff\r\n", 0o100644);
        let base_tree = s.store_tree(vec![base_file, keep.clone()]);
        let base = s.store_commit(base_tree, &[], "base");
        let incoming = s.file(b"file", b"one\ntwo\nthree\nfour\nFIVE\n", 0o100644);
        let incoming_tree = s.store_tree(vec![incoming, keep.clone()]);
        let picked = s.store_commit(incoming_tree, &[base], "picked");
        let later_file = s.file(b"file", b"LATER\ntwo\nthree\nfour\nFIVE\n", 0o100644);
        let later_tree = s.store_tree(vec![later_file, keep.clone()]);
        let later = s.store_commit(later_tree, &[picked], "not selected");
        let ours = s.file(b"file", b"ONE\ntwo\nthree\nfour\nfive\n", 0o100755);
        let target_tree = s.store_tree(vec![ours, keep.clone()]);
        let target = s.store_commit(target_tree, &[base], "target");
        let expected_file = s.file(b"file", b"ONE\ntwo\nthree\nfour\nFIVE\n", 0o100755);
        let expected_tree = s.store_tree(vec![expected_file.clone(), keep.clone()]);
        let inputs = request(target, later, picked, ReplayDirection::CherryPick);
        let plan = clean(&s, inputs);
        assert_eq!(plan.tree, expected_tree);
        assert_eq!(plan.coordinates.selected_parent, Some(base));
        assert_eq!(plan.coordinates.selected_mainline, Some(1));
        assert_eq!(plan, clean(&s, inputs));
        let commit = plan.objects.iter().find(|object| object.id == plan.commit).unwrap();
        let expected = [format!("tree {expected_tree}\nparent {target}\nauthor T <t@x> 2 +0000\ncommitter T <t@x> 2 +0000\n\n").as_bytes(),
            metadata().message.as_slice()].concat();
        assert_eq!(commit.body, expected);
        assert_eq!(plan.commit, git_object_id(format, GitObjectKind::Commit, &expected));
        assert!(!plan.objects.iter().any(|object| object.id == picked || object.id == later || object.id == keep.oid));
        assert!(plan.objects.iter().any(|object| object.id == expected_file.oid));
        for object in plan.objects { assert_eq!(object.id, git_object_id(format, object.kind, &object.body)); }
    }
}

#[test]
fn revert_uses_inverse_changes_and_preserves_unrelated_target_additions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut s = Source::new(format);
        let old = s.file(b"raw\xff", b"\0old\xff\r\n", 0o100755);
        let deleted = s.file(b"restore", b"", 0o100644);
        let base_tree = s.store_tree(vec![old.clone(), deleted.clone()]);
        let base = s.store_commit(base_tree, &[], "base");
        let modified = s.file(b"raw\xff", b"\0new\xfe", 0o100644);
        let added = s.file(b"remove", b"added", 0o100644);
        let changed_tree = s.store_tree(vec![modified.clone(), added.clone()]);
        let selected = s.store_commit(changed_tree, &[base], "to revert");
        let unrelated = s.file(b"unrelated", b"keep me", 0o100644);
        let target_tree = s.store_tree(vec![modified, added, unrelated.clone()]);
        let target = s.store_commit(target_tree, &[selected], "later target work");
        let expected = s.store_tree(vec![old, deleted, unrelated]);
        let plan = clean(&s, request(target, target, selected, ReplayDirection::Revert));
        assert_eq!(plan.tree, expected);
        assert_eq!(plan.coordinates.selected_parent, Some(base));
        assert_eq!(plan.coordinates.request.direction, ReplayDirection::Revert);
        assert!(!plan.objects.iter().any(|o| o.kind == GitObjectKind::Blob));
    }
}

#[test]
fn root_commits_use_the_real_empty_tree_in_both_directions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut s = Source::new(format);
        let introduced = s.file(b"introduced", b"root content\n", 0o100644);
        let root_tree = s.store_tree(vec![introduced.clone()]);
        let root = s.store_commit(root_tree, &[], "root");
        let keep = s.file(b"keep", b"unrelated root\n", 0o100644);
        let other_tree = s.store_tree(vec![keep.clone()]);
        let other = s.store_commit(other_tree, &[], "unrelated target");
        let expected = s.store_tree(vec![introduced.clone(), keep.clone()]);
        let picked = clean(&s, request(other, root, root, ReplayDirection::CherryPick));
        assert_eq!(picked.tree, expected);
        assert_eq!(picked.coordinates.selected_parent, None);
        assert_eq!(picked.coordinates.selected_mainline, None);
        let later = s.store_commit(expected, &[root], "later addition");
        assert_eq!(clean(&s, request(later, later, root, ReplayDirection::Revert)).tree, other_tree);
        // The source need not contain a separately stored empty tree at all.
        let empty = git_object_id(format, GitObjectKind::Tree, &[]);
        assert!(!s.trees.contains_key(&empty));
        let reverted = clean(&s, request(root, root, root, ReplayDirection::Revert));
        assert_eq!(reverted.tree, empty);
        assert!(reverted.objects.iter().any(|o| o.id == empty && o.kind == GitObjectKind::Tree && o.body.is_empty()));
        let mut bad = request(root, root, root, ReplayDirection::Revert); bad.mainline = Some(1);
        assert!(matches!(prepare_replay(&s, format, bad, &metadata(), PreparationLimits::default()),
            Err(ReplayError::InvalidMainline { parents: 0, .. })));
    }
}

#[test]
fn merge_mainline_is_explicit_and_uses_stored_parent_order() {
    let mut s = Source::new(GitHashAlgorithm::Sha256);
    let a = s.file(b"a", b"A", 0o100644); let b = s.file(b"b", b"B", 0o100644);
    let at = s.store_tree(vec![a.clone()]); let bt = s.store_tree(vec![b.clone()]);
    let both = s.store_tree(vec![a, b]);
    let first = s.store_commit(at, &[], "first"); let second = s.store_commit(bt, &[], "second");
    let merge = s.store_commit(both, &[first, second], "merge");
    let input = request(merge, merge, merge, ReplayDirection::Revert);
    assert!(matches!(prepare_replay(&s, s.format, input, &metadata(), PreparationLimits::default()),
        Err(ReplayError::MainlineRequired { parents: 2 })));
    for (mainline, expected) in [(1, at), (2, bt)] {
        let plan = clean(&s, ReplayRequest { mainline: Some(mainline), ..input });
        assert_eq!(plan.tree, expected);
        assert_eq!(plan.coordinates.selected_mainline, Some(mainline));
    }
    for mainline in [0, 3, u16::MAX] {
        assert!(matches!(prepare_replay(&s, s.format, ReplayRequest { mainline: Some(mainline), ..input },
            &metadata(), PreparationLimits::default()), Err(ReplayError::InvalidMainline { .. })));
    }
}

#[test]
fn content_binary_and_modify_delete_conflicts_return_no_candidate() {
    for (base, ours, applied, kind) in [
        (b"base\n".as_slice(), Some(b"ours\n".as_slice()), b"theirs\n".as_slice(), ConflictKind::Content),
        (b"\0base".as_slice(), Some(b"\0ours".as_slice()), b"\0theirs".as_slice(), ConflictKind::Binary),
        (b"base".as_slice(), None, b"theirs".as_slice(), ConflictKind::ModifyDelete),
    ] {
        let mut s = Source::new(GitHashAlgorithm::Sha1);
        let file = s.file(b"conflict", base, 0o100644); let tree = s.store_tree(vec![file]);
        let root = s.store_commit(tree, &[], "base");
        let target_entries = ours.map(|bytes| s.file(b"conflict", bytes, 0o100644)).into_iter().collect();
        let target_tree = s.store_tree(target_entries); let target = s.store_commit(target_tree, &[root], "ours");
        let theirs = s.file(b"conflict", applied, 0o100644); let their_tree = s.store_tree(vec![theirs]);
        let selected = s.store_commit(their_tree, &[root], "selected");
        let result = prepare_replay(&s, s.format, request(target, selected, selected, ReplayDirection::CherryPick),
            &metadata(), PreparationLimits::default()).unwrap();
        assert!(matches!(result, ReplayPreparation::Conflicted { conflicts, .. }
            if conflicts.len() == 1 && conflicts[0].path == b"conflict" && conflicts[0].kind == kind));
    }
}

#[test]
fn no_net_change_does_not_create_an_empty_commit_or_claim_history_equivalence() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let file = s.file(b"file", b"content", 0o100644); let tree = s.store_tree(vec![file]);
    let root = s.store_commit(tree, &[], "root"); let empty = s.store_commit(tree, &[root], "empty change");
    for direction in [ReplayDirection::CherryPick, ReplayDirection::Revert] {
        assert!(matches!(prepare_replay(&s, s.format, request(root, empty, empty, direction),
            &metadata(), PreparationLimits::default()).unwrap(), ReplayPreparation::NoChange { .. }));
    }
    assert!(matches!(prepare_replay(&s, s.format, request(root, root, root, ReplayDirection::CherryPick),
        &metadata(), PreparationLimits::default()).unwrap(), ReplayPreparation::NoChange { .. }));
}

#[test]
fn unrelated_commit_is_not_read_before_selected_history_establishes_membership() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let tree = s.store_tree(vec![]); let visible = s.store_commit(tree, &[], "visible");
    let other = s.store_commit(tree, &[], "not reachable from source");
    assert!(matches!(prepare_replay(&s, s.format, request(other, visible, other, ReplayDirection::CherryPick),
        &metadata(), PreparationLimits::default()), Err(ReplayError::CommitOutsideSourceHistory)));
    assert_eq!(*s.read_commits.borrow(), vec![visible]);
}

#[test]
fn graph_work_metadata_and_cancellation_are_bounded_before_a_candidate_exists() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let file = s.file(b"file", b"content", 0o100644); let tree = s.store_tree(vec![file]);
    let root = s.store_commit(tree, &[], "root"); let later = s.store_commit(tree, &[root], "later");
    let input = request(root, later, root, ReplayDirection::CherryPick);
    assert!(matches!(prepare_replay(&s, s.format, input, &metadata(),
        PreparationLimits { max_commits: 1, ..PreparationLimits::default() }),
        Err(ReplayError::Preparation(PreparationError::Budget(_)))));
    let mut bad = metadata(); bad.committer.push_str("\nparent injected");
    assert!(matches!(prepare_replay(&s, s.format, input, &bad, PreparationLimits::default()),
        Err(ReplayError::Preparation(PreparationError::InvalidMetadata))));
    s.live.set(false);
    assert!(matches!(prepare_replay(&s, s.format, input, &metadata(), PreparationLimits::default()),
        Err(ReplayError::Preparation(PreparationError::Source(MergeSourceError::Cancelled)))));
    s.live.set(true);
    s.commits.get_mut(&later).unwrap().parents[0] = later;
    assert!(matches!(prepare_replay(&s, s.format, input, &metadata(), PreparationLimits::default()),
        Err(ReplayError::Preparation(PreparationError::Source(MergeSourceError::InvalidObject(_))))));
}
