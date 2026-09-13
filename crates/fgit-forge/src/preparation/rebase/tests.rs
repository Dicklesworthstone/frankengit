use super::*;
use std::cell::Cell;

struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, CommitInput>,
    metadata: BTreeMap<GitOid, RebaseCommitMetadata>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    polls: Cell<usize>,
    stop: Cell<usize>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            commits: BTreeMap::new(),
            metadata: BTreeMap::new(),
            trees: BTreeMap::new(),
            blobs: BTreeMap::new(),
            polls: Cell::new(0),
            stop: Cell::new(usize::MAX),
        }
    }
    fn tree(&mut self, bytes: &[u8]) -> GitOid {
        let oid = git_object_id(self.format, GitObjectKind::Blob, bytes);
        self.blobs.insert(oid, bytes.to_vec());
        let mut body = b"100644 file\0".to_vec();
        body.extend_from_slice(oid.as_bytes());
        let tree = git_object_id(self.format, GitObjectKind::Tree, &body);
        self.trees.insert(
            tree,
            vec![MergeEntry {
                name: b"file".to_vec(),
                mode: 0o100644,
                oid,
            }],
        );
        tree
    }
    fn commit(&mut self, bytes: &[u8], parents: &[GitOid], message: &[u8]) -> GitOid {
        let tree = self.tree(bytes);
        let data = RebaseCommitMetadata {
            author: b"Original <original@example.invalid> 17 -0430".to_vec(),
            encoding: Some(b"ISO-8859-1".to_vec()),
            message: message.to_vec(),
        };
        let mut body = format!("tree {tree}\n").into_bytes();
        for parent in parents {
            body.extend_from_slice(format!("parent {parent}\n").as_bytes());
        }
        body.extend_from_slice(b"author ");
        body.extend_from_slice(&data.author);
        body.extend_from_slice(
            b"\ncommitter Old <old@example.invalid> 20 +0000\nencoding ISO-8859-1\n\n",
        );
        body.extend_from_slice(message);
        let id = git_object_id(self.format, GitObjectKind::Commit, &body);
        self.commits.insert(
            id,
            CommitInput {
                tree,
                parents: parents.to_vec(),
            },
        );
        self.metadata.insert(id, data);
        id
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        self.polls.set(self.polls.get() + 1);
        if self.polls.get() >= self.stop.get() {
            Err(MergeSourceError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.trees
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.blobs
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
}
impl RebaseObjectSource for Source {
    fn rebase_metadata(&self, id: GitOid) -> Result<RebaseCommitMetadata, MergeSourceError> {
        self.metadata
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
}
fn committer() -> RebaseCommitter {
    RebaseCommitter {
        identity: "Rebaser <rebaser@example.invalid>".into(),
        timestamp: 100,
    }
}
const BASE: &[u8] = b"a\nb\nc\nd\ne\nf\n";
const ONTO: &[u8] = b"A\nb\nc\nd\ne\nf\n";
fn fixture(format: GitHashAlgorithm) -> (Source, RebaseRequest, Vec<GitOid>) {
    let mut source = Source::new(format);
    let upstream = source.commit(BASE, &[], b"base");
    let onto = source.commit(ONTO, &[upstream], b"onto");
    let first = source.commit(b"a\nb\nc\nd\ne\nF\n", &[upstream], b"first\r\n\xff");
    let second = source.commit(b"a\nb\nC\nd\ne\nF\n", &[first], b"second");
    let third = source.commit(b"a\nb\nC\nd\ne\nFF\n", &[second], b"third\n");
    (
        source,
        RebaseRequest {
            source_tip: third,
            upstream,
            onto,
            empty: EmptyCommitPolicy::Stop,
        },
        vec![first, second, third],
    )
}
fn run(
    source: &Source,
    request: RebaseRequest,
    limits: PreparationLimits,
) -> Result<RebasePreparation, RebaseError> {
    prepare_rebase(source, source.format, request, &committer(), limits)
}
fn clean(source: &Source, request: RebaseRequest) -> PreparedRebase {
    let RebasePreparation::Clean(plan) =
        run(source, request, PreparationLimits::default()).unwrap()
    else {
        panic!("clean rebase expected");
    };
    plan
}

#[test]
fn successive_replays_read_generated_trees_and_blobs_and_preserve_native_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, request, originals) = fixture(format);
        let plan = clean(&source, request);
        assert_eq!(
            plan.steps.iter().map(|s| s.original).collect::<Vec<_>>(),
            originals
        );
        let mut parent = request.onto;
        for step in &plan.steps {
            let object = plan
                .objects
                .iter()
                .find(|o| o.id == step.rewritten)
                .unwrap();
            let prefix = format!("tree {}\nparent {parent}\nauthor ", step.tree).into_bytes();
            assert!(object.body.starts_with(&prefix));
            assert_eq!(git_object_id(format, object.kind, &object.body), object.id);
            let metadata = &source.metadata[&step.original];
            let mut tail = metadata.author.clone();
            tail.extend_from_slice(
                b"\ncommitter Rebaser <rebaser@example.invalid> 100 +0000\nencoding ISO-8859-1\n\n",
            );
            tail.extend_from_slice(&metadata.message);
            assert_eq!(&object.body[prefix.len()..], tail);
            assert_eq!(step.kind, RebaseStepKind::Replayed);
            parent = step.rewritten;
        }
        let blob = git_object_id(format, GitObjectKind::Blob, b"A\nb\nC\nd\ne\nFF\n");
        assert!(
            plan.objects
                .iter()
                .any(|o| o.id == blob && o.body == b"A\nb\nC\nd\ne\nFF\n")
        );
        assert_eq!(parent, plan.commit);
        assert_eq!(plan, clean(&source, request), "identity is reproducible");
    }
}

#[test]
fn one_shared_content_tree_and_output_budget_covers_the_complete_series() {
    let (source, request, _) = fixture(GitHashAlgorithm::Sha1);
    assert!(matches!(
        run(
            &source,
            request,
            PreparationLimits {
                max_content_merges: 1,
                ..PreparationLimits::default()
            }
        ),
        Err(RebaseError::Preparation(PreparationError::Budget(
            "content merges"
        )))
    ));
    let full = clean(&source, request);
    let total: usize = full.objects.iter().map(|o| o.body.len()).sum();
    assert!(matches!(
        run(
            &source,
            request,
            PreparationLimits {
                max_output_bytes: total - 1,
                ..PreparationLimits::default()
            }
        ),
        Err(RebaseError::Preparation(PreparationError::Budget(_)))
    ));
    let RebasePreparation::Clean(exact) = run(
        &source,
        request,
        PreparationLimits {
            max_output_bytes: total,
            ..PreparationLimits::default()
        },
    )
    .unwrap() else {
        panic!();
    };
    assert_eq!(exact, full);
    assert!(matches!(
        run(
            &source,
            request,
            PreparationLimits {
                max_tree_entries: 3,
                ..PreparationLimits::default()
            }
        ),
        Err(RebaseError::Preparation(PreparationError::Budget(
            "tree entries"
        )))
    ));
}

#[test]
fn original_empty_commits_survive_while_newly_empty_changes_require_a_policy() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let upstream = source.commit(BASE, &[], b"base");
        let already = source.commit(ONTO, &[upstream], b"already applied");
        let changed = source.commit(ONTO, &[upstream], b"same patch different metadata");
        let empty = source.commit(ONTO, &[changed], b"");
        let mut request = RebaseRequest {
            source_tip: empty,
            upstream,
            onto: already,
            empty: EmptyCommitPolicy::Stop,
        };
        assert!(
            matches!(run(&source,request,PreparationLimits::default()).unwrap(),
            RebasePreparation::Stopped { original, completed, reason:RebaseStop::BecameEmpty,.. } if original==changed && completed.is_empty())
        );
        request.empty = EmptyCommitPolicy::Drop;
        let plan = clean(&source, request);
        assert_eq!(plan.steps[0].kind, RebaseStepKind::DroppedEmpty);
        assert_eq!(plan.steps[0].rewritten, already);
        assert_eq!(plan.steps[1].kind, RebaseStepKind::PreservedEmpty);
        assert_ne!(plan.commit, already);
        request.empty = EmptyCommitPolicy::Keep;
        let kept = clean(&source, request);
        assert_eq!(kept.steps[0].kind, RebaseStepKind::Replayed);
        assert_eq!(kept.steps[1].kind, RebaseStepKind::PreservedEmpty);
    }
}

#[test]
fn later_conflict_returns_only_a_stop_and_not_a_partially_publishable_plan() {
    let (mut source, mut request, originals) = fixture(GitHashAlgorithm::Sha1);
    request.source_tip = source.commit(
        b"other top\nb\nc\nd\ne\nF\n",
        &[originals[0]],
        b"conflicting second",
    );
    let result = run(&source, request, PreparationLimits::default()).unwrap();
    let RebasePreparation::Stopped {
        original,
        completed,
        reason: RebaseStop::Conflicted(conflicts),
        ..
    } = result
    else {
        panic!();
    };
    assert_eq!(original, request.source_tip);
    assert_eq!(completed.len(), 1);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].path, b"file");
}

#[test]
fn unrelated_upstream_merge_suffix_missing_history_and_cycles_refuse() {
    let (mut source, mut request, originals) = fixture(GitHashAlgorithm::Sha256);
    request.upstream = source.commit(b"unrelated", &[], b"other");
    assert!(matches!(
        run(&source, request, PreparationLimits::default()),
        Err(RebaseError::UpstreamOutsideLinearHistory)
    ));
    request.upstream = source.commits[&originals[0]].parents[0];
    request.source_tip = source.commit(BASE, &[originals[0], request.onto], b"merge");
    assert!(matches!(
        run(&source, request, PreparationLimits::default()),
        Err(RebaseError::MergeCommit { parents: 2, .. })
    ));
    request.source_tip = originals[2];
    source.commits.get_mut(&originals[0]).unwrap().parents = vec![originals[2]];
    assert!(matches!(
        run(&source, request, PreparationLimits::default()),
        Err(RebaseError::CyclicHistory(_))
    ));
    source.commits.remove(&originals[0]);
    assert!(matches!(
        run(&source, request, PreparationLimits::default()),
        Err(RebaseError::Preparation(PreparationError::Source(
            MergeSourceError::Unavailable(_)
        )))
    ));
}

#[test]
fn commit_and_edge_bounds_apply_to_topology_before_merging() {
    let (source, request, _) = fixture(GitHashAlgorithm::Sha1);
    for limits in [
        PreparationLimits {
            max_commits: 2,
            ..PreparationLimits::default()
        },
        PreparationLimits {
            max_edges: 1,
            ..PreparationLimits::default()
        },
    ] {
        assert!(matches!(
            run(&source, request, limits),
            Err(RebaseError::Preparation(PreparationError::Budget(_)))
        ));
    }
}

#[test]
fn every_checkpoint_cancellation_refuses_the_whole_rebase() {
    let (source, request, _) = fixture(GitHashAlgorithm::Sha1);
    clean(&source, request);
    let polls = source.polls.get();
    for stop in 1..=polls {
        source.polls.set(0);
        source.stop.set(stop);
        assert!(matches!(
            run(&source, request, PreparationLimits::default()),
            Err(RebaseError::Preparation(PreparationError::Source(
                MergeSourceError::Cancelled
            )))
        ));
    }
}

#[test]
fn empty_range_and_all_dropped_range_use_onto_without_manufacturing_a_commit() {
    let (source, mut request, _) = fixture(GitHashAlgorithm::Sha256);
    request.source_tip = request.upstream;
    let plan = clean(&source, request);
    assert_eq!(plan.commit, request.onto);
    assert!(plan.steps.is_empty() && plan.objects.is_empty());
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let upstream = source.commit(BASE, &[], b"base");
    let onto = source.commit(ONTO, &[upstream], b"onto");
    let original = source.commit(ONTO, &[upstream], b"same patch");
    let plan = clean(
        &source,
        RebaseRequest {
            source_tip: original,
            upstream,
            onto,
            empty: EmptyCommitPolicy::Drop,
        },
    );
    assert_eq!(plan.commit, onto);
    assert!(plan.objects.is_empty());
    assert_eq!(plan.steps[0].kind, RebaseStepKind::DroppedEmpty);
}

#[test]
fn malformed_original_headers_and_cross_hash_inputs_never_become_commits() {
    let (mut source, request, originals) = fixture(GitHashAlgorithm::Sha1);
    source.metadata.get_mut(&originals[0]).unwrap().author =
        b"Author <a@x> 1 +0000\nparent injected".to_vec();
    assert!(matches!(
        run(&source, request, PreparationLimits::default()),
        Err(RebaseError::InvalidOriginalMetadata(_))
    ));
    let foreign = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Commit, b"foreign");
    assert!(matches!(
        run(
            &source,
            RebaseRequest {
                onto: foreign,
                ..request
            },
            PreparationLimits::default()
        ),
        Err(RebaseError::Preparation(PreparationError::ObjectFormat))
    ));
}
