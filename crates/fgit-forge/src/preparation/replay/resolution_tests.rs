use super::*;
use super::super::ConflictKind;
use super::super::resolution::{ResolutionChoice, ResolutionKind};
use std::cell::{Cell, RefCell};

struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    reads: RefCell<Vec<GitOid>>,
    tree_reads: Cell<usize>,
    stop_after_trees: Cell<Option<usize>>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self { format, commits: BTreeMap::new(), trees: BTreeMap::new(), blobs: BTreeMap::new(),
            reads: RefCell::new(Vec::new()), tree_reads: Cell::new(0), stop_after_trees: Cell::new(None) }
    }
    fn file(&mut self, name: &[u8], bytes: &[u8], mode: u32) -> MergeEntry {
        let oid = git_object_id(self.format, GitObjectKind::Blob, bytes);
        self.blobs.insert(oid, bytes.to_vec()); MergeEntry { name: name.to_vec(), mode, oid }
    }
    fn tree_id(&mut self, mut entries: Vec<MergeEntry>) -> GitOid {
        entries.sort_by_cached_key(|entry| { let mut key = entry.name.clone();
            key.push(if entry.mode == 0o040000 { b'/' } else { 0 }); key });
        let mut body = Vec::new();
        for entry in &entries { body.extend(format!("{:o} ", entry.mode).as_bytes());
            body.extend(&entry.name); body.push(0); body.extend(entry.oid.as_bytes()); }
        let id = git_object_id(self.format, GitObjectKind::Tree, &body);
        self.trees.insert(id, entries); id
    }
    fn commit_id(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents { body.push_str(&format!("parent {parent}\n")); }
        body.push_str(&format!("author T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\n{label}\n"));
        let id = git_object_id(self.format, GitObjectKind::Commit, body.as_bytes());
        self.commits.insert(id, CommitInput { tree, parents: parents.to_vec() }); id
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        if self.stop_after_trees.get().is_some_and(|limit| self.tree_reads.get() >= limit) {
            Err(MergeSourceError::Cancelled)
        } else { Ok(()) }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.reads.borrow_mut().push(id);
        self.commits.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.tree_reads.set(self.tree_reads.get() + 1);
        self.trees.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.blobs.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id))
    }
}
fn metadata() -> MergeMetadata {
    MergeMetadata { author: "T <t@x>".into(), committer: "T <t@x>".into(), timestamp: 2,
        message: b"resolved replay\r\nexact bytes\xff".to_vec() }
}
fn choice(path: &[u8], choice: ResolutionChoice) -> ConflictResolution {
    ConflictResolution { path: path.to_vec(), choice }
}
fn pair(s: &mut Source, b: Vec<MergeEntry>, o: Vec<MergeEntry>, t: Vec<MergeEntry>) -> ReplayRequest {
    let bt = s.tree_id(b); let base = s.commit_id(bt, &[], "base");
    let ot = s.tree_id(o); let target = s.commit_id(ot, &[base], "target");
    let tt = s.tree_id(t); let selected = s.commit_id(tt, &[base], "selected");
    ReplayRequest { direction: ReplayDirection::CherryPick, target, source_tip: selected,
        selected_commit: selected, mainline: None }
}
fn simple(format: GitHashAlgorithm) -> (Source, ReplayRequest) {
    let mut s = Source::new(format);
    let b = s.file(b"file", b"base\n", 0o100644);
    let o = s.file(b"file", b"ours\n", 0o100755);
    let t = s.file(b"file", b"theirs\n", 0o100644);
    let input = pair(&mut s, vec![b], vec![o], vec![t]); (s, input)
}
fn resolved(s: &Source, input: ReplayRequest, choices: &[ConflictResolution]) -> ResolvedReplay {
    prepare_resolved_replay(s, s.format, input, choices, &metadata(), PreparationLimits::default()).unwrap()
}

#[test]
fn replay_resolution_keeps_clean_changes_and_exact_single_parent_bytes_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut s = Source::new(format);
        let b = s.file(b"file", b"base\n", 0o100644);
        let o = s.file(b"file", b"target\n", 0o100755);
        let t = s.file(b"file", b"source\n", 0o100644);
        let dir_b = s.tree_id(vec![b]); let dir_o = s.tree_id(vec![o]); let dir_t = s.tree_id(vec![t]);
        let dir = |oid| MergeEntry { name: b"dir".to_vec(), mode: 0o040000, oid };
        let keep = s.file(b"keep", b"unchanged\0\xff", 0o100644);
        let gone = s.file(b"gone", b"delete only in source", 0o100644);
        let ours = s.file(b"target", b"target addition", 0o100644);
        let theirs = s.file(b"source", b"borrowed source addition", 0o100755);
        let input = pair(&mut s, vec![dir(dir_b), keep.clone(), gone.clone()],
            vec![dir(dir_o), keep.clone(), gone, ours.clone()], vec![dir(dir_t), keep.clone(), theirs.clone()]);
        let bytes = b"manual\0\xff\r\nno final newline";
        let file = s.file(b"file", bytes, 0o100755); let chosen = s.tree_id(vec![file]);
        let expected = s.tree_id(vec![dir(chosen), keep, ours, theirs]);
        let choices = [choice(b"dir/file", ResolutionChoice::File { mode: 0o100755, bytes: bytes.to_vec() })];
        let result = resolved(&s, input, &choices);
        assert_eq!(result, resolved(&s, input, &choices));
        assert_eq!(result.resolutions.len(), 1);
        assert_eq!(result.resolutions[0].conflict.path, b"dir/file");
        let ReplayPreparation::Clean(plan) = result.outcome else { panic!("complete candidate"); };
        assert_eq!(plan.tree, expected);
        let body = [format!("tree {expected}\nparent {}\nauthor T <t@x> 2 +0000\ncommitter T <t@x> 2 +0000\n\n", input.target).as_bytes(),
            metadata().message.as_slice()].concat();
        assert_eq!(plan.commit, git_object_id(format, GitObjectKind::Commit, &body));
        assert_eq!(plan.objects.iter().find(|o| o.id == plan.commit).unwrap().body, body);
        assert!(plan.objects.iter().any(|o| o.kind == GitObjectKind::Blob && o.body == bytes));
    }
}

#[test]
fn ours_can_resolve_to_no_change_while_empty_file_and_deletion_remain_distinct() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut s, input) = simple(format);
        let result = resolved(&s, input, &[choice(b"file", ResolutionChoice::Ours)]);
        assert!(matches!(result.outcome, ReplayPreparation::NoChange { .. }));
        assert_eq!(result.resolutions[0].choice, ResolutionKind::Ours);
        let empty_file = s.file(b"file", b"", 0o100644);
        let empty_file_tree = s.tree_id(vec![empty_file]);
        let empty_tree = s.tree_id(Vec::new());
        let file = resolved(&s, input, &[choice(b"file", ResolutionChoice::File { mode: 0o100644, bytes: Vec::new() })]);
        let deleted = resolved(&s, input, &[choice(b"file", ResolutionChoice::Delete)]);
        assert!(matches!(file.outcome, ReplayPreparation::Clean(ref plan) if plan.tree == empty_file_tree));
        assert!(matches!(deleted.outcome, ReplayPreparation::Clean(ref plan) if plan.tree == empty_tree));
        assert_ne!(empty_file_tree, empty_tree);
        assert!(deleted.resolutions[0].result.is_none());
    }
}

#[test]
fn revert_uses_the_selected_parent_as_theirs_and_requires_explicit_missing_side_deletion() {
    let (mut s, mut input) = simple(GitHashAlgorithm::Sha256);
    input.direction = ReplayDirection::Revert;
    let parent = s.commits[&input.selected_commit].parents[0];
    let expected = s.commits[&parent].tree;
    let result = resolved(&s, input, &[choice(b"file", ResolutionChoice::Theirs)]);
    assert!(matches!(result.outcome, ReplayPreparation::Clean(ref plan) if plan.tree == expected));
    let applied_tree = s.commits[&input.selected_commit].tree;
    assert_eq!(result.resolutions[0].conflict.base.as_ref().unwrap().oid, s.trees[&applied_tree][0].oid);
    let introduced = s.file(b"file", b"introduced", 0o100644);
    let changed = s.file(b"file", b"later edit", 0o100644);
    let mut add = pair(&mut s, vec![], vec![changed], vec![introduced]);
    add.direction = ReplayDirection::Revert;
    assert!(matches!(prepare_resolved_replay(&s, s.format, add,
        &[choice(b"file", ResolutionChoice::Theirs)], &metadata(), PreparationLimits::default()),
        Err(ReplayError::Resolution(error)) if matches!(*error, ResolutionError::MissingSide { side: ResolutionKind::Theirs, .. })));
    let deleted = resolved(&s, add, &[choice(b"file", ResolutionChoice::Delete)]);
    assert!(matches!(deleted.outcome, ReplayPreparation::Clean(ref plan)
        if plan.tree == git_object_id(s.format, GitObjectKind::Tree, &[])));
}

#[test]
fn all_and_only_conflicts_are_required_and_paths_are_validated_before_reads() {
    let (s, input) = simple(GitHashAlgorithm::Sha1);
    assert!(matches!(prepare_resolved_replay(&s, s.format, input, &[], &metadata(), PreparationLimits::default()),
        Err(ReplayError::Resolution(error)) if matches!(*error, ResolutionError::Unresolved(_))));
    assert!(matches!(prepare_resolved_replay(&s, s.format, input, &[choice(b"clean", ResolutionChoice::Ours)],
        &metadata(), PreparationLimits::default()), Err(ReplayError::Resolution(error))
        if matches!(*error, ResolutionError::NonConflictPath(_))));
    for paths in [vec![b"file".as_slice(), b"file"], vec![b"a", b"a-", b"a/b"], vec![b".git/config"], vec![b"../file"]] {
        s.reads.borrow_mut().clear();
        let choices: Vec<_> = paths.iter().map(|p| choice(p, ResolutionChoice::Delete)).collect();
        assert!(prepare_resolved_replay(&s, s.format, input, &choices, &metadata(), PreparationLimits::default()).is_err());
        assert!(s.reads.borrow().is_empty());
    }
    let clean = ReplayRequest { target: s.commits[&input.selected_commit].parents[0], ..input };
    assert!(matches!(prepare_resolved_replay(&s, s.format, clean, &[choice(b"file", ResolutionChoice::Theirs)],
        &metadata(), PreparationLimits::default()), Err(ReplayError::Resolution(error)) if matches!(*error, ResolutionError::NoConflicts)));
}

#[test]
fn discovery_and_reconstruction_share_the_tree_budget_and_cancellation() {
    let (s, input) = simple(GitHashAlgorithm::Sha1);
    let limits = PreparationLimits { max_tree_entries: 3, ..PreparationLimits::default() };
    assert!(matches!(prepare_replay(&s, s.format, input, &metadata(), limits).unwrap(), ReplayPreparation::Conflicted { .. }));
    assert!(matches!(prepare_resolved_replay(&s, s.format, input, &[choice(b"file", ResolutionChoice::Theirs)], &metadata(), limits),
        Err(ReplayError::Resolution(error)) if matches!(*error, ResolutionError::Preparation(PreparationError::Budget("tree entries")))));
    s.tree_reads.set(0); s.stop_after_trees.set(Some(4));
    assert!(matches!(prepare_resolved_replay(&s, s.format, input, &[choice(b"file", ResolutionChoice::Theirs)],
        &metadata(), PreparationLimits::default()), Err(ReplayError::Resolution(error))
        if matches!(*error, ResolutionError::Preparation(PreparationError::Source(MergeSourceError::Cancelled)))));
}

#[test]
fn missing_base_in_root_replay_is_not_an_implicit_delete_and_mainline_is_preserved() {
    let mut s = Source::new(GitHashAlgorithm::Sha256);
    let theirs = s.file(b"file", b"root source", 0o100644);
    let ours = s.file(b"file", b"unrelated root", 0o100644);
    let source_tree = s.tree_id(vec![theirs]); let source = s.commit_id(source_tree, &[], "source root");
    let target_tree = s.tree_id(vec![ours]); let target = s.commit_id(target_tree, &[], "target root");
    let input = ReplayRequest { direction: ReplayDirection::CherryPick, target, source_tip: source, selected_commit: source, mainline: None };
    assert!(matches!(prepare_resolved_replay(&s, s.format, input, &[choice(b"file", ResolutionChoice::Base)],
        &metadata(), PreparationLimits::default()), Err(ReplayError::Resolution(error))
        if matches!(*error, ResolutionError::MissingSide { side: ResolutionKind::Base, .. })));
    let result = resolved(&s, input, &[choice(b"file", ResolutionChoice::Theirs)]);
    assert!(matches!(result.outcome, ReplayPreparation::Clean(ref p) if p.tree == source_tree && p.coordinates.selected_parent.is_none()));
    let merge = s.commit_id(source_tree, &[target, source], "explicit merge");
    let selected = ReplayRequest { source_tip: merge, selected_commit: merge, mainline: None, ..input };
    assert!(matches!(prepare_resolved_replay(&s, s.format, selected, &[choice(b"file", ResolutionChoice::Ours)],
        &metadata(), PreparationLimits::default()), Err(ReplayError::MainlineRequired { parents: 2 })));
    let changed = s.file(b"file", b"new target change", 0o100644);
    let changed_tree = s.tree_id(vec![changed]);
    let newer = s.commit_id(changed_tree, &[target], "newer target");
    let explicit = ReplayRequest { target: newer, mainline: Some(1), ..selected };
    let result = resolved(&s, explicit, &[choice(b"file", ResolutionChoice::Theirs)]);
    assert!(matches!(result.outcome, ReplayPreparation::Clean(ref plan)
        if plan.tree == source_tree && plan.coordinates.selected_parent == Some(target)
            && plan.coordinates.selected_mainline == Some(1)));
}

#[test]
fn resolving_a_directory_conflict_reuses_the_selected_subtree_without_flattening_it() {
    let mut s = Source::new(GitHashAlgorithm::Sha1);
    let old = s.file(b"node", b"old", 0o100644); let ours = s.file(b"node", b"target change", 0o100644);
    let leaf = s.file(b"leaf", b"source subtree", 0o100755); let child = s.tree_id(vec![leaf]);
    let theirs = MergeEntry { name: b"node".to_vec(), mode: 0o040000, oid: child };
    let input = pair(&mut s, vec![old], vec![ours], vec![theirs.clone()]);
    let result = resolved(&s, input, &[choice(b"node", ResolutionChoice::Theirs)]);
    assert_eq!(result.resolutions[0].conflict.kind, ConflictKind::TypeChange);
    assert_eq!(result.resolutions[0].result, Some(theirs));
    assert!(matches!(result.outcome, ReplayPreparation::Clean(ref p) if p.tree == s.commits[&input.selected_commit].tree));
}

#[test]
fn explicit_choices_cannot_authorize_a_commit_outside_the_selected_source_history() {
    let (s, input) = simple(GitHashAlgorithm::Sha1);
    s.reads.borrow_mut().clear();
    let outside = ReplayRequest { selected_commit: input.target, ..input };
    assert!(matches!(prepare_resolved_replay(&s, s.format, outside, &[choice(b"file", ResolutionChoice::Ours)],
        &metadata(), PreparationLimits::default()), Err(ReplayError::CommitOutsideSourceHistory)));
    assert!(!s.reads.borrow().contains(&input.target));
}
