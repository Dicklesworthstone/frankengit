use super::*;
use crate::history::commit_history;
use crate::preparation::{CommitInput, MergeEntry, MergeObjectSource, MergeSourceError};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt::Write as _;

struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, (CommitInput, Vec<u8>)>,
    reads: RefCell<Vec<GitOid>>,
    checkpoints: Cell<usize>,
    stop_at: Cell<usize>,
}
impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            commits: BTreeMap::new(),
            reads: RefCell::new(Vec::new()),
            checkpoints: Cell::new(0),
            stop_at: Cell::new(usize::MAX),
        }
    }
    fn add(&mut self, parents: &[GitOid], message: &str) -> GitOid {
        let tree = git_object_id(self.format, GitObjectKind::Tree, b"");
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        write!(body,
            "author Untrusted <u@example.invalid> 1 +0000\ncommitter Untrusted <u@example.invalid> 1 +0000\n\n{message}"
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
        self.commits
            .get(&id)
            .map(|(metadata, _)| metadata.clone())
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, _: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        panic!("first-parent history never reads trees")
    }
    fn blob(&self, _: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        panic!("first-parent history never reads blobs")
    }
}
impl HistorySource for Source {
    fn commit_body(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.reads.borrow_mut().push(id);
        self.commits
            .get(&id)
            .map(|(_, body)| body.clone())
            .ok_or(MergeSourceError::Unavailable(id))
    }
}

#[test]
fn recent_pages_succeed_above_the_unchanged_full_graph_ceiling_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let mut chain = vec![source.add(&[], "root")];
        for n in 1..4098 {
            chain.push(source.add(&[*chain.last().unwrap()], &n.to_string()));
        }
        let tip = *chain.last().unwrap();
        let query = LogOptions {
            limit: 3,
            ..LogOptions::default()
        };
        assert_eq!(
            commit_history(&source, format, tip, query),
            Err(HistoryError::Budget("commits"))
        );
        let page = first_parent_history(&source, format, tip, query).unwrap();
        let expected: Vec<_> = chain.iter().rev().take(3).copied().collect();
        assert_eq!(
            page.commits
                .iter()
                .map(|commit| commit.id)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(*source.reads.borrow(), expected);
        assert_eq!(page.visited_commits, 3);
        assert_eq!(page.visited_parent_edges, 3);
        assert_eq!(page.next_after, Some(3));
        assert!(!page.root_reached);
        source.reads.borrow_mut().clear();
        let next =
            first_parent_history(&source, format, tip, LogOptions { after: 3, ..query }).unwrap();
        assert_eq!(next.commits[0].id, chain[chain.len() - 4]);
        assert_eq!(next.visited_commits, 6);
        assert_eq!(source.reads.borrow().len(), 6);
        assert_eq!(
            first_parent_history(&source, format, tip, query).unwrap(),
            page
        );
    }
}

#[test]
fn stored_first_parent_order_is_explicit_and_side_history_is_not_read() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let first = source.add(&[], "first root");
        let side = source.add(&[], "side root");
        let tip = source.add(&[first, side, first], "merge");
        source.commits.remove(&side);
        let page = first_parent_history(&source, format, tip, LogOptions::default()).unwrap();
        assert_eq!(
            page.commits
                .iter()
                .map(|commit| commit.id)
                .collect::<Vec<_>>(),
            [tip, first]
        );
        assert_eq!(page.commits[0].parents, [first, side, first]);
        assert_eq!(page.visited_parent_edges, 3);
        assert!(page.root_reached);
        assert_eq!(page.next_after, None);
        assert_eq!(*source.reads.borrow(), [tip, first]);
    }
}

#[test]
fn prefix_page_edges_and_metadata_share_the_original_limits() {
    let format = GitHashAlgorithm::Sha1;
    let mut source = Source::new(format);
    let root = source.add(&[], "root");
    let tip = source.add(&[root, root], "merge");
    let mut query = LogOptions {
        limit: 1,
        limits: HistoryLimits {
            max_commits: 1,
            ..HistoryLimits::default()
        },
        ..LogOptions::default()
    };
    assert_eq!(
        first_parent_history(&source, format, tip, query)
            .unwrap()
            .next_after,
        Some(1)
    );
    query.after = 1;
    assert_eq!(
        first_parent_history(&source, format, tip, query),
        Err(HistoryError::Budget("commits"))
    );
    query.limits.max_commits = 2;
    let page = first_parent_history(&source, format, tip, query).unwrap();
    assert_eq!(page.commits[0].id, root);
    assert_eq!(page.visited_commits, 2);
    query.limits.max_edges = 1;
    assert_eq!(
        first_parent_history(&source, format, tip, query),
        Err(HistoryError::Budget("commit edges"))
    );
    query.limits.max_edges = 2;
    assert!(first_parent_history(&source, format, tip, query).is_ok());
    let total_bytes = source
        .commits
        .values()
        .map(|(_, body)| body.len())
        .sum::<usize>();
    query.limits.max_metadata_bytes = total_bytes - 1;
    assert_eq!(
        first_parent_history(&source, format, tip, query),
        Err(HistoryError::Budget("metadata bytes"))
    );
    query.limits.max_metadata_bytes = total_bytes;
    assert_eq!(
        first_parent_history(&source, format, tip, query)
            .unwrap()
            .metadata_bytes,
        total_bytes
    );
    query.after = 3;
    query.limits = HistoryLimits::default();
    assert_eq!(
        first_parent_history(&source, format, tip, query),
        Err(HistoryError::LineRange)
    );
}

#[test]
fn missing_corrupt_and_cancelled_visited_history_never_becomes_a_short_success() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let root = source.add(&[], "root");
        let tip = source.add(&[root], "tip");
        let query = LogOptions {
            limit: 1,
            ..LogOptions::default()
        };
        let saved = source.commits.remove(&root).unwrap();
        assert!(first_parent_history(&source, format, tip, query).is_ok());
        assert_eq!(
            first_parent_history(&source, format, tip, LogOptions { after: 1, ..query }),
            Err(HistoryError::Source(MergeSourceError::Unavailable(root)))
        );
        source.commits.insert(root, saved);
        source.commits.get_mut(&tip).unwrap().1.push(b'!');
        assert_eq!(
            first_parent_history(&source, format, tip, LogOptions { after: 1, ..query }),
            Err(HistoryError::InvalidObject(tip))
        );
        source.commits.get_mut(&tip).unwrap().1.pop();
        source.checkpoints.set(0);
        first_parent_history(&source, format, tip, query).unwrap();
        let checkpoints = source.checkpoints.get();
        for stop in 1..=checkpoints {
            source.checkpoints.set(0);
            source.stop_at.set(stop);
            assert_eq!(
                first_parent_history(&source, format, tip, query),
                Err(HistoryError::Source(MergeSourceError::Cancelled))
            );
        }
        source.stop_at.set(usize::MAX);
        assert!(first_parent_history(&source, format, tip, query).is_ok());
    }
}

#[test]
fn malformed_options_domains_and_cyclic_source_metadata_refuse() {
    let mut source = Source::new(GitHashAlgorithm::Sha1);
    let root = source.add(&[], "root");
    assert!(
        matches!(first_parent_history(&source, GitHashAlgorithm::Sha256, root, LogOptions::default()),
        Err(HistoryError::InvalidObject(id)) if id == root)
    );
    for query in [
        LogOptions {
            limit: 0,
            ..LogOptions::default()
        },
        LogOptions {
            limit: 101,
            ..LogOptions::default()
        },
        LogOptions {
            after: usize::MAX,
            ..LogOptions::default()
        },
        LogOptions {
            limits: HistoryLimits {
                max_commits: 4097,
                ..HistoryLimits::default()
            },
            ..LogOptions::default()
        },
    ] {
        assert_eq!(
            first_parent_history(&source, GitHashAlgorithm::Sha1, root, query),
            Err(HistoryError::InvalidOptions)
        );
    }
    source.commits.get_mut(&root).unwrap().0.parents.push(root);
    assert_eq!(
        first_parent_history(
            &source,
            GitHashAlgorithm::Sha1,
            root,
            LogOptions {
                limit: 1,
                ..LogOptions::default()
            }
        ),
        Err(HistoryError::CyclicHistory)
    );
}
