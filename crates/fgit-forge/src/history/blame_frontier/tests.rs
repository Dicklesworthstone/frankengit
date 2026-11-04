use super::*;
use crate::history::blame;
use crate::preparation::{MergeEntry, MergeObjectSource};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_diff::DiffError;
use std::cell::{Cell, RefCell};
use std::fmt::Write as _;

struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, (CommitInput, Vec<u8>)>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    reads: RefCell<Vec<GitOid>>,
    denied: BTreeSet<GitOid>,
    checkpoints: Cell<usize>,
    stop_at: Cell<usize>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            commits: BTreeMap::new(),
            trees: BTreeMap::new(),
            blobs: BTreeMap::new(),
            reads: RefCell::new(Vec::new()),
            denied: BTreeSet::new(),
            checkpoints: Cell::new(0),
            stop_at: Cell::new(usize::MAX),
        }
    }
    fn add(&mut self, bytes: &[u8], parents: &[GitOid], label: &str) -> GitOid {
        let blob = git_object_id(self.format, GitObjectKind::Blob, bytes);
        self.blobs.entry(blob).or_insert_with(|| bytes.to_vec());
        let mut body = b"100644 file\0".to_vec();
        body.extend_from_slice(blob.as_bytes());
        let tree = git_object_id(self.format, GitObjectKind::Tree, &body);
        self.trees.entry(tree).or_insert_with(|| {
            vec![MergeEntry {
                name: b"file".to_vec(),
                mode: 0o100644,
                oid: blob,
            }]
        });
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        write!(body,
            "author Untrusted <u@example.invalid> 1 +0000\ncommitter Untrusted <u@example.invalid> 1 +0000\n\n{label}\n"
        ).unwrap();
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
    fn guard(&self, id: GitOid) -> Result<(), MergeSourceError> {
        if self.denied.contains(&id) {
            Err(MergeSourceError::OutsideSelection)
        } else {
            Ok(())
        }
    }
    fn blob_of(&self, commit: GitOid) -> GitOid {
        self.trees[&self.commits[&commit].0.tree][0].oid
    }
    fn reset(&self) {
        self.reads.borrow_mut().clear();
        self.checkpoints.set(0);
        self.stop_at.set(usize::MAX);
    }
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let next = self.checkpoints.get() + 1;
        self.checkpoints.set(next);
        if next >= self.stop_at.get() {
            Err(MergeSourceError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.guard(id)?;
        self.reads.borrow_mut().push(id);
        self.commits
            .get(&id)
            .map(|(c, _)| c.clone())
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.guard(id)?;
        self.trees
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.guard(id)?;
        self.blobs
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
}
impl HistorySource for Source {
    fn commit_body(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.guard(id)?;
        self.commits
            .get(&id)
            .map(|(_, b)| b.clone())
            .ok_or(MergeSourceError::Unavailable(id))
    }
}
fn options() -> BlameOptions {
    BlameOptions {
        path: b"file".to_vec(),
        first_line: 0,
        end_line: None,
        limits: Default::default(),
    }
}
fn assert_attribution_equal(mut actual: BlameResult, mut expected: BlameResult) {
    assert_eq!(actual.traversal, BlameTraversal::LineFrontier);
    assert_eq!(expected.traversal, BlameTraversal::FullDag);
    assert!(actual.graph_commits <= expected.graph_commits);
    assert!(actual.comparisons <= expected.comparisons);
    // Traversal breadth, memoization and first-observed algorithm order are
    // execution evidence; every source pin, byte span and origin must match.
    actual.traversal = BlameTraversal::FullDag;
    for report in [&mut actual, &mut expected] {
        report.graph_commits = 0;
        report.comparisons = 0;
        report.algorithms.clear();
    }
    assert_eq!(actual, expected);
}

#[test]
fn a_tip_origin_above_a_real_100000_commit_tail_reads_only_two_commits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let mut parent = source.add(b"old\n", &[], "root");
        for n in 1..100_000 {
            parent = source.add(b"old\n", &[parent], &n.to_string());
        }
        let tip = source.add(b"new\n", &[parent], "new line");
        assert_eq!(source.commits.len(), 100_001);
        let mut opts = options();
        opts.limits.max_commits = 2;
        opts.limits.max_edges = 2;
        let result = blame_frontier(&source, format, tip, &opts).unwrap();
        assert_eq!(*source.reads.borrow(), [tip, parent]);
        assert_eq!(result.graph_commits, 2);
        assert_eq!(result.lines[0].origin_commit, tip);
        assert_eq!(result.content, b"new\n");
        assert_eq!(result.comparisons, 1);
        assert_eq!(result.traversal.as_str(), "line-frontier-v1");
        assert_eq!(BlameTraversal::FullDag.as_str(), "full-dag-v1");
        assert_eq!(
            blame(&source, format, tip, &opts),
            Err(HistoryError::Budget("commits"))
        );
    }
}

#[test]
fn reconvergence_after_an_origin_was_processed_is_not_a_cycle() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let base = source.add(b"A\nB\n", &[], "base");
        // Force the worklist to process left, then base, then right. The right
        // route reaches base only AFTER base already resolved the left route.
        let left = (0..512)
            .find_map(|n| {
                let id = source.add(b"A\nL\n", &[base], &format!("left-{n}"));
                (id < base).then_some(id)
            })
            .unwrap();
        let right = (0..512)
            .find_map(|n| {
                let id = source.add(b"R\nB\n", &[base], &format!("right-{n}"));
                (id > base).then_some(id)
            })
            .unwrap();
        let tip = source.add(b"A\nB\n", &[left, right], "merge");
        let actual = blame_frontier(&source, format, tip, &options()).unwrap();
        assert_eq!(actual.graph_commits, 4);
        assert_eq!(source.reads.borrow().len(), 4, "commit bodies are memoized");
        assert!(actual.lines.iter().all(|line| line.origin_commit == base));
        let expected = blame(&source, format, tip, &options()).unwrap();
        assert_attribution_equal(actual, expected);
    }
}

#[test]
fn stored_parent_precedence_duplicate_headers_and_unneeded_parents_are_preserved() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let base = source.add(b"old\n", &[], "base");
        let a = source.add(b"same\n", &[base], "a");
        let b = source.add(b"same\n", &[base], "b");
        let first = a.max(b);
        let second = a.min(b);
        let tip = source.add(b"same\n", &[first, first, second], "merge");
        let actual = blame_frontier(&source, format, tip, &options()).unwrap();
        assert_eq!(actual.lines[0].origin_commit, first);
        assert!(!source.reads.borrow().contains(&second));
        assert_attribution_equal(actual, blame(&source, format, tip, &options()).unwrap());
        source.denied.insert(second);
        source.reset();
        assert_eq!(
            blame_frontier(&source, format, tip, &options())
                .unwrap()
                .lines[0]
                .origin_commit,
            first
        );
        source.denied.insert(first);
        assert_eq!(
            blame_frontier(&source, format, tip, &options()),
            Err(HistoryError::Source(MergeSourceError::OutsideSelection))
        );
        source.denied.clear();
        let mut opts = options();
        opts.limits.max_edges = 3; // Three tip headers plus first's parent = four.
        assert_eq!(
            blame_frontier(&source, format, tip, &opts),
            Err(HistoryError::Budget("commit edges"))
        );
        opts.limits.max_edges = 4;
        assert!(blame_frontier(&source, format, tip, &opts).is_ok());
    }
}

#[test]
fn bounded_generated_dags_match_the_full_graph_oracle_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for seed in 1_u64..=32 {
            let mut state = seed;
            let mut random = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state >> 32) as usize
            };
            let mut source = Source::new(format);
            let mut commits = vec![source.add(b"a\nb\na\ntail", &[], "root")];
            let mut contents = vec![b"a\nb\na\ntail".to_vec()];
            for n in 1..24 {
                let first = random() % commits.len();
                let mut parents = vec![commits[first]];
                if n % 3 == 0 {
                    parents.push(commits[random() % commits.len()]);
                }
                if n % 7 == 0 {
                    parents.insert(0, parents[0]);
                }
                let mut lines: Vec<Vec<u8>> = contents[first]
                    .split_inclusive(|b| *b == b'\n')
                    .map(<[u8]>::to_vec)
                    .collect();
                match random() % 4 {
                    0 if !lines.is_empty() => {
                        let index = random() % lines.len();
                        lines[index] = format!("change-{n}\n").into_bytes();
                    }
                    1 if !lines.is_empty() => {
                        lines.remove(random() % lines.len());
                    }
                    2 => lines.insert(0, b"repeated\r\n".to_vec()),
                    _ => lines.push(b"raw\xff\n".to_vec()),
                }
                let body = lines.concat();
                let id = source.add(&body, &parents, &format!("{seed}-{n}"));
                contents.push(body);
                commits.push(id);
            }
            for index in [17, 23] {
                let tip = commits[index];
                let mut opts = options();
                let expected = blame(&source, format, tip, &opts).unwrap();
                assert_attribution_equal(
                    blame_frontier(&source, format, tip, &opts).unwrap(),
                    expected.clone(),
                );
                opts.first_line = expected.total_lines / 2;
                opts.end_line = Some(expected.total_lines);
                assert_attribution_equal(
                    blame_frontier(&source, format, tip, &opts).unwrap(),
                    blame(&source, format, tip, &opts).unwrap(),
                );
            }
        }
    }
}

fn alternating(format: GitHashAlgorithm) -> (Source, GitOid) {
    let mut source = Source::new(format);
    let mut tip = source.add(b"stable\none\n", &[], "root");
    for n in 1..20 {
        tip = source.add(
            if n % 2 == 0 {
                b"stable\none\n"
            } else {
                b"stable\ntwo\n"
            },
            &[tip],
            &n.to_string(),
        );
    }
    (source, tip)
}

#[test]
fn ordered_blob_pair_memoization_and_aggregate_diff_work_are_both_enforced() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, tip) = alternating(format);
        let mut opts = options();
        opts.end_line = Some(1);
        opts.limits.max_comparisons = 2;
        let actual = blame_frontier(&source, format, tip, &opts).unwrap();
        assert_eq!(
            actual.comparisons, 2,
            "twenty edges share two ordered pairs"
        );
        let mut oracle = opts.clone();
        oracle.limits.max_comparisons = 128;
        assert_attribution_equal(actual, blame(&source, format, tip, &oracle).unwrap());
        opts.limits.max_comparisons = 1;
        assert_eq!(
            blame_frontier(&source, format, tip, &opts),
            Err(HistoryError::Budget("line comparisons"))
        );
        opts.limits.max_comparisons = 2;
        let limits = DiffLimits {
            max_input_bytes: opts.limits.max_blob_bytes * 2,
            max_units: opts.limits.max_lines * 2,
            max_work: opts.limits.max_diff_work,
            max_trace_cells: 512_000,
        };
        let (_, forward) = diff_with_cancellation_and_work(
            b"stable\none\n",
            b"stable\ntwo\n",
            DiffOptions::myers_lines(limits),
            &|| false,
        )
        .unwrap();
        let (_, reverse) = diff_with_cancellation_and_work(
            b"stable\ntwo\n",
            b"stable\none\n",
            DiffOptions::myers_lines(limits),
            &|| false,
        )
        .unwrap();
        opts.limits.max_diff_work = forward + reverse - 1;
        assert!(matches!(
            blame_frontier(&source, format, tip, &opts),
            Err(HistoryError::Diff(DiffError::WorkExceeded { .. }))
        ));
        opts.limits.max_diff_work += 1;
        assert!(blame_frontier(&source, format, tip, &opts).is_ok());
    }
}

#[test]
fn every_cancellation_checkpoint_refuses_without_partial_attribution_and_retry_matches() {
    let mut source = Source::new(GitHashAlgorithm::Sha256);
    let base = source.add(b"a\nb\nc\n", &[], "base");
    let tip = source.add(b"a\nchanged\nc\n", &[base], "tip");
    let expected = blame_frontier(&source, source.format, tip, &options()).unwrap();
    let checkpoints = source.checkpoints.get();
    for stop in 1..=checkpoints {
        source.reset();
        source.stop_at.set(stop);
        assert_eq!(
            blame_frontier(&source, source.format, tip, &options()),
            Err(HistoryError::Source(MergeSourceError::Cancelled)),
            "checkpoint {stop}"
        );
        assert_eq!(source.checkpoints.get(), stop);
    }
    source.reset();
    assert_eq!(
        blame_frontier(&source, source.format, tip, &options()).unwrap(),
        expected
    );
}

#[test]
fn required_missing_objects_corruption_and_cycles_never_create_origins() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let base = source.add(b"old\n", &[], "base");
        let parent = source.add(b"old\n", &[base], "parent");
        let tip = source.add(b"new\n", &[parent], "tip");
        let removed = source.commits.remove(&base).unwrap();
        assert_eq!(
            blame_frontier(&source, format, tip, &options())
                .unwrap()
                .lines[0]
                .origin_commit,
            tip,
            "an irrelevant grandparent is not read"
        );
        assert_eq!(
            blame_frontier(&source, format, parent, &options()),
            Err(HistoryError::Source(MergeSourceError::Unavailable(base)))
        );
        source.commits.insert(base, removed);
        assert_eq!(
            blame_frontier(&source, format, parent, &options())
                .unwrap()
                .lines[0]
                .origin_commit,
            base
        );
        let tip_blob = source.blob_of(tip);
        source.blobs.insert(tip_blob, b"altered\n".to_vec());
        assert_eq!(
            blame_frontier(&source, format, tip, &options()),
            Err(HistoryError::InvalidObject(tip_blob))
        );
        source.blobs.insert(tip_blob, b"new\n".to_vec());
        assert!(blame_frontier(&source, format, tip, &options()).is_ok());
        // Structural adversarial source: a cycle with different content stops
        // local propagation but must still fail induced-graph validation.
        source.commits.get_mut(&parent).unwrap().0.parents = vec![tip];
        assert_eq!(
            blame_frontier(&source, format, tip, &options()),
            Err(HistoryError::CyclicHistory)
        );
        source.commits.get_mut(&parent).unwrap().0.parents = vec![base];
        assert!(blame_frontier(&source, format, tip, &options()).is_ok());
        source.commits.get_mut(&base).unwrap().0.parents = vec![base];
        assert_eq!(
            blame_frontier(&source, format, parent, &options()),
            Err(HistoryError::CyclicHistory)
        );
        source.commits.get_mut(&base).unwrap().0.parents.clear();
        source.commits.get_mut(&tip).unwrap().1.push(b'!');
        assert_eq!(
            blame_frontier(&source, format, tip, &options()),
            Err(HistoryError::InvalidObject(tip))
        );
        source.commits.get_mut(&tip).unwrap().1.pop();
        assert!(blame_frontier(&source, format, tip, &options()).is_ok());
    }
}

#[test]
fn commit_tree_blob_line_cache_and_metadata_limits_have_permitted_twins() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let base = source.add(b"stable\nzero\n", &[], "base");
    let middle = source.add(b"stable\none\n", &[base], "middle");
    let tip = source.add(b"stable\ntwo\n", &[middle], "tip");
    let mut opts = options();
    opts.end_line = Some(1);
    for (field, low, high) in [
        ("commits", 2, 3),
        ("tree entries", 2, 3),
        ("blob bytes", 11, 12),
        ("line count", 1, 2),
    ] {
        let assign = |limits: &mut super::super::HistoryLimits, n| match field {
            "commits" => limits.max_commits = n,
            "tree entries" => limits.max_tree_entries = n,
            "blob bytes" => limits.max_blob_bytes = n,
            "line count" => limits.max_lines = n,
            _ => unreachable!(),
        };
        let mut limited = opts.clone();
        assign(&mut limited.limits, low);
        assert_eq!(
            blame_frontier(&source, source.format, tip, &limited),
            Err(HistoryError::Budget(field))
        );
        assign(&mut limited.limits, high);
        assert!(
            blame_frontier(&source, source.format, tip, &limited).is_ok(),
            "{field}"
        );
    }
    let mut limited = opts.clone();
    limited.limits.max_cached_bytes = 1;
    assert_eq!(
        blame_frontier(&source, source.format, tip, &limited),
        Err(HistoryError::Budget("commit cache"))
    );
    limited.limits.max_cached_bytes = options().limits.max_cached_bytes;
    assert!(blame_frontier(&source, source.format, tip, &limited).is_ok());
    let body_bytes = source.commits[&base].1.len();
    limited.limits.max_metadata_bytes = body_bytes - 1;
    assert_eq!(
        blame_frontier(&source, source.format, tip, &limited),
        Err(HistoryError::Budget("metadata bytes"))
    );
    limited.limits.max_metadata_bytes = body_bytes;
    assert!(blame_frontier(&source, source.format, tip, &limited).is_ok());
}

#[test]
fn empty_ranges_empty_files_binary_data_and_invalid_options_remain_explicit() {
    let mut source = Source::new(GitHashAlgorithm::Sha256);
    let base = source.add(b"old\n", &[], "base");
    let tip = source.add(b"new\n", &[base], "tip");
    source.denied.insert(base);
    let mut opts = options();
    opts.end_line = Some(0);
    opts.limits.max_commits = 1;
    let result = blame_frontier(&source, source.format, tip, &opts).unwrap();
    assert_eq!(*source.reads.borrow(), [tip]);
    assert!(result.lines.is_empty() && result.origins.is_empty() && result.content.is_empty());
    assert_eq!(result.graph_commits, 1);
    let empty = source.add(b"", &[base], "empty");
    assert!(
        blame_frontier(&source, source.format, empty, &options())
            .unwrap()
            .lines
            .is_empty()
    );
    let binary = source.add(b"binary\0bytes", &[], "binary");
    assert_eq!(
        blame_frontier(&source, source.format, binary, &options()),
        Err(HistoryError::BinaryContent)
    );
    assert!(blame_frontier(&source, source.format, tip, &opts).is_ok());
    for path in [
        b"../file".to_vec(),
        b"/file".to_vec(),
        vec![],
        b"a//b".to_vec(),
    ] {
        opts.path = path;
        assert_eq!(
            blame_frontier(&source, source.format, tip, &opts),
            Err(HistoryError::InvalidOptions)
        );
    }
    opts = options();
    opts.end_line = Some(2);
    assert_eq!(
        blame_frontier(&source, source.format, tip, &opts),
        Err(HistoryError::LineRange)
    );
}
