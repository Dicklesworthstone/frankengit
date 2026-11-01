//! Native object fixtures; generated objects are never installed into the
//! original source while testing the prefix planner.
use crate::preparation::{
    CommitInput, MergeEntry, MergeMetadata, MergeObjectSource, MergeSourceError, PlannedMergeObject,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

pub(super) type File<'a> = (&'a [u8], &'a [u8], u32);

#[derive(Clone)]
pub(super) struct Source {
    pub format: GitHashAlgorithm,
    pub objects: BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>,
    pub commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    pub polls: Cell<usize>,
    pub stop: Cell<usize>,
    pub seen: RefCell<Vec<GitOid>>,
    pub cancel_on_commit: Cell<Option<GitOid>>,
}

impl Source {
    pub fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            objects: BTreeMap::new(),
            commits: BTreeMap::new(),
            trees: BTreeMap::new(),
            blobs: BTreeMap::new(),
            polls: Cell::new(0),
            stop: Cell::new(usize::MAX),
            seen: RefCell::new(Vec::new()),
            cancel_on_commit: Cell::new(None),
        }
    }

    pub fn write_tree(&mut self, files: &[File<'_>]) -> GitOid {
        let mut entries = Vec::new();
        let mut directories: BTreeMap<Vec<u8>, Vec<File<'_>>> = BTreeMap::new();
        for &(path, body, mode) in files {
            if let Some(slash) = path.iter().position(|byte| *byte == b'/') {
                directories
                    .entry(path[..slash].to_vec())
                    .or_default()
                    .push((&path[slash + 1..], body, mode));
            } else {
                let oid = git_object_id(self.format, GitObjectKind::Blob, body);
                self.blobs.insert(oid, body.to_vec());
                self.objects
                    .insert(oid, (GitObjectKind::Blob, body.to_vec()));
                entries.push(MergeEntry {
                    name: path.to_vec(),
                    mode,
                    oid,
                });
            }
        }
        for (name, files) in directories {
            let oid = self.write_tree(&files);
            entries.push(MergeEntry {
                name,
                mode: 0o040000,
                oid,
            });
        }
        entries.sort_by_cached_key(|entry| {
            let mut key = entry.name.clone();
            key.push(if entry.mode == 0o040000 { b'/' } else { 0 });
            key
        });
        let mut body = Vec::new();
        for entry in &entries {
            body.extend_from_slice(format!("{:o} ", entry.mode).as_bytes());
            body.extend_from_slice(&entry.name);
            body.push(0);
            body.extend_from_slice(entry.oid.as_bytes());
        }
        let oid = git_object_id(self.format, GitObjectKind::Tree, &body);
        self.trees.insert(oid, entries);
        self.objects.insert(oid, (GitObjectKind::Tree, body));
        oid
    }

    pub fn write_commit(&mut self, files: &[File<'_>], parents: &[GitOid], label: &str) -> GitOid {
        let tree = self.write_tree(files);
        let mut body = format!("tree {tree}\n").into_bytes();
        for parent in parents {
            body.extend_from_slice(format!("parent {parent}\n").as_bytes());
        }
        body.extend_from_slice(b"author Fixture <fixture@example.invalid> 1 +0000\n");
        body.extend_from_slice(b"committer Fixture <fixture@example.invalid> 1 +0000\n\n");
        body.extend_from_slice(label.as_bytes());
        let oid = git_object_id(self.format, GitObjectKind::Commit, &body);
        self.commits.insert(
            oid,
            CommitInput {
                tree,
                parents: parents.to_vec(),
            },
        );
        self.objects.insert(oid, (GitObjectKind::Commit, body));
        oid
    }

    /// Independently decode returned native bytes into a separate source. Used
    /// only for comparing per-request budgets with the cumulative prefix limit.
    pub fn install(&mut self, objects: &[PlannedMergeObject]) {
        for object in objects {
            assert_eq!(
                object.id,
                git_object_id(self.format, object.kind, &object.body)
            );
            match object.kind {
                GitObjectKind::Commit => {
                    let mut lines = object.body.split(|byte| *byte == b'\n');
                    let tree = self.hex(lines.next().unwrap().strip_prefix(b"tree ").unwrap());
                    let parents = lines
                        .take_while(|line| line.starts_with(b"parent "))
                        .map(|line| self.hex(&line[7..]))
                        .collect();
                    self.commits
                        .insert(object.id, CommitInput { tree, parents });
                }
                GitObjectKind::Tree => {
                    let mut body = object.body.as_slice();
                    let mut entries = Vec::new();
                    while !body.is_empty() {
                        let space = body.iter().position(|byte| *byte == b' ').unwrap();
                        let mode =
                            u32::from_str_radix(std::str::from_utf8(&body[..space]).unwrap(), 8)
                                .unwrap();
                        body = &body[space + 1..];
                        let nul = body.iter().position(|byte| *byte == 0).unwrap();
                        let name = body[..nul].to_vec();
                        body = &body[nul + 1..];
                        let size = self.format.digest_len();
                        let hex: String = body[..size]
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect();
                        let oid = GitOid::from_hex(self.format, &hex).unwrap();
                        entries.push(MergeEntry { name, mode, oid });
                        body = &body[size..];
                    }
                    self.trees.insert(object.id, entries);
                }
                GitObjectKind::Blob => {
                    self.blobs.insert(object.id, object.body.clone());
                }
                other => panic!("unexpected planned object kind: {other:?}"),
            }
            self.objects
                .insert(object.id, (object.kind, object.body.clone()));
        }
    }

    fn hex(&self, text: &[u8]) -> GitOid {
        GitOid::from_hex(self.format, std::str::from_utf8(text).unwrap()).unwrap()
    }
}

impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let poll = self.polls.get() + 1;
        self.polls.set(poll);
        if poll >= self.stop.get() {
            Err(MergeSourceError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.seen.borrow_mut().push(id);
        if self.cancel_on_commit.get() == Some(id) {
            self.stop.set(self.polls.get());
            return Err(MergeSourceError::Cancelled);
        }
        self.commits
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }

    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.seen.borrow_mut().push(id);
        self.trees
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }

    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.seen.borrow_mut().push(id);
        self.blobs
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
}

pub(super) fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Queue Author <author@example.invalid>".into(),
        committer: "Queue Committer <committer@example.invalid>".into(),
        timestamp: 73,
        message: b"queued merge\n\xff".to_vec(),
    }
}

pub(super) const BASE: &[u8] = b"one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n";
pub(super) const TARGET: &[u8] = b"ONE\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n";
pub(super) const FIRST: &[u8] = b"one\ntwo\nthree\nfour\nfive\nsix\nSEVEN\neight\nnine\nten\n";
pub(super) const SECOND: &[u8] = b"one\ntwo\nthree\nFOUR\nfive\nsix\nseven\neight\nnine\nten\n";
pub(super) const THIRD: &[u8] = b"one\ntwo\nthree\nfour\nfive\nsix\nSEVEN\neight\nNINE\nten\n";
pub(super) const MERGED_FIRST: &[u8] =
    b"ONE\ntwo\nthree\nfour\nfive\nsix\nSEVEN\neight\nnine\nten\n";
pub(super) const MERGED_SECOND: &[u8] =
    b"ONE\ntwo\nthree\nFOUR\nfive\nsix\nSEVEN\neight\nnine\nten\n";
pub(super) const MERGED_THIRD: &[u8] =
    b"ONE\ntwo\nthree\nFOUR\nfive\nsix\nSEVEN\neight\nNINE\nten\n";

pub(super) fn files(text: &[u8]) -> [File<'_>; 2] {
    [
        (b"src/file", text, 0o100644),
        (b"stable/unchanged", b"borrow this subtree\n", 0o100644),
    ]
}

pub(super) fn fixture(format: GitHashAlgorithm) -> (Source, GitOid, GitOid, [GitOid; 3]) {
    let mut source = Source::new(format);
    let base = source.write_commit(&files(BASE), &[], "base");
    let target = source.write_commit(&files(TARGET), &[base], "target");
    let first = source.write_commit(&files(FIRST), &[base], "first");
    let second = source.write_commit(&files(SECOND), &[base], "second");
    let third = source.write_commit(&files(THIRD), &[first], "stacked third");
    (source, base, target, [first, second, third])
}

pub(super) fn commit_body(
    tree: GitOid,
    target: GitOid,
    incoming: GitOid,
    metadata: &MergeMetadata,
) -> Vec<u8> {
    let mut body = format!(
        "tree {tree}\nparent {target}\nparent {incoming}\nauthor {} {} +0000\ncommitter {} {} +0000\n\n",
        metadata.author, metadata.timestamp, metadata.committer, metadata.timestamp
    )
    .into_bytes();
    body.extend_from_slice(&metadata.message);
    body
}
