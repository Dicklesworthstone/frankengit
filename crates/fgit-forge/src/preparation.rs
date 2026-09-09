//! Bounded native merge preparation, without a storage or publication effect.
//!
//! `PathMergeV1` merges exact paths, recurses through changed directories, and
//! uses the existing line merge for regular-file content. It does not run Git,
//! hooks, attributes, external drivers, rename heuristics, or virtual-base
//! synthesis. Multiple best bases and conflicts never produce a candidate.
//! The node adapter supplies identity-verified, authority-selected objects.

use std::collections::{BTreeMap, BTreeSet};

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_diff::{
    CommitGraph, ContentMergeError, ContentMergeOptions, ContentMergeOutcome, MergeBaseError,
    MergeBaseLimits, MergeBaseResult, MergeCancellation, ParentSet, merge_bases_all,
    merge_content_with_cancellation,
};
use fgit_types::{GitHashAlgorithm, GitOid};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitInput {
    pub tree: GitOid,
    pub parents: Vec<GitOid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeEntry {
    pub name: Vec<u8>,
    pub mode: u32,
    pub oid: GitOid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeSourceError {
    Cancelled,
    BudgetExceeded,
    Unavailable(GitOid),
    InvalidObject(GitOid),
    OutsideSelection,
}

/// Implementations must bound reads before allocation, verify the requested
/// native identity and kind, and refuse objects outside their selected source.
/// The pure planner cannot grant those capabilities to an object adapter.
pub trait MergeObjectSource {
    fn checkpoint(&self) -> Result<(), MergeSourceError>;
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError>;
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError>;
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError>;
}

/// Fixed ceilings for the v1 profile. Callers may narrow, but not exceed them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationLimits {
    pub max_commits: usize,
    pub max_edges: usize,
    pub max_tree_entries: usize,
    pub max_depth: usize,
    pub max_path_bytes: usize,
    pub max_content_merges: usize,
    pub max_text_bytes: usize,
    pub max_conflicts: usize,
    pub max_objects: usize,
    pub max_output_bytes: usize,
}

impl Default for PreparationLimits {
    fn default() -> Self {
        Self {
            max_commits: 4096, max_edges: 16_384, max_tree_entries: 100_000,
            max_depth: 64, max_path_bytes: 4096, max_content_merges: 64,
            max_text_bytes: 1024 * 1024, max_conflicts: 128,
            max_objects: 10_000, max_output_bytes: 32 * 1024 * 1024,
        }
    }
}

impl PreparationLimits {
    pub fn validate(self) -> Result<(), PreparationError> {
        let maximum = Self::default();
        for (value, ceiling) in [
            (self.max_commits, maximum.max_commits), (self.max_edges, maximum.max_edges),
            (self.max_tree_entries, maximum.max_tree_entries), (self.max_depth, maximum.max_depth),
            (self.max_path_bytes, maximum.max_path_bytes),
            (self.max_content_merges, maximum.max_content_merges),
            (self.max_text_bytes, maximum.max_text_bytes), (self.max_conflicts, maximum.max_conflicts),
            (self.max_objects, maximum.max_objects), (self.max_output_bytes, maximum.max_output_bytes),
        ] {
            if value == 0 || value > ceiling { return Err(PreparationError::InvalidLimits); }
        }
        Ok(())
    }
}

/// Explicit identity and time make the candidate reproducible. UTC is the
/// only timezone in v1. Metadata is never read from ambient Git configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeMetadata {
    pub author: String,
    pub committer: String,
    pub timestamp: u64,
    pub message: Vec<u8>,
}

impl MergeMetadata {
    pub fn validate(&self) -> Result<(), PreparationError> {
        for identity in [&self.author, &self.committer] {
            let Some((name, address)) = identity.rsplit_once(" <") else {
                return Err(PreparationError::InvalidMetadata);
            };
            if identity.len() > 1024 || name.trim().is_empty()
                || name.contains(['<', '>']) || !address.ends_with('>')
                || address.len() <= 1 || address[..address.len() - 1].contains(['<', '>'])
                || identity.bytes().any(|byte| byte.is_ascii_control())
            { return Err(PreparationError::InvalidMetadata); }
        }
        if self.timestamp == 0 || self.timestamp > i64::MAX as u64
            || self.message.is_empty() || self.message.len() > 64 * 1024
            || self.message.contains(&0)
        { return Err(PreparationError::InvalidMetadata); }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictKind {
    Content,
    Binary,
    ModifyDelete,
    TypeChange,
    Mode,
    Opaque,
    AttributesRequireDriver,
}

/// Raw Git path bytes and native identities, not lossy path strings or marker
/// files. A conflict result deliberately has no tree, commit or object pack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeConflict {
    pub path: Vec<u8>,
    pub kind: ConflictKind,
    pub base: Option<MergeEntry>,
    pub ours: Option<MergeEntry>,
    pub theirs: Option<MergeEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedMergeObject {
    pub id: GitOid,
    pub kind: GitObjectKind,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMerge {
    pub base: GitOid,
    pub target: GitOid,
    pub source: GitOid,
    pub tree: GitOid,
    pub commit: GitOid,
    /// New objects only, in deterministic native-ID order. Unchanged subtrees
    /// are referenced by identity rather than copied into the artifact.
    pub objects: Vec<PlannedMergeObject>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergePreparation {
    Clean(PreparedMerge),
    Conflicted { base: GitOid, conflicts: Vec<MergeConflict> },
    AlreadyUpToDate { target: GitOid },
}

#[derive(Debug)]
pub enum PreparationError {
    InvalidLimits,
    InvalidMetadata,
    ObjectFormat,
    Source(MergeSourceError),
    Graph(MergeBaseError<GitOid, MergeSourceError>),
    NoCommonAncestor,
    MultipleMergeBases(Vec<GitOid>),
    InvalidTree,
    Budget(&'static str),
    Content { path: Vec<u8>, error: ContentMergeError },
}

impl std::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native merge preparation refused: {self:?}")
    }
}
impl std::error::Error for PreparationError {}
impl From<MergeSourceError> for PreparationError {
    fn from(value: MergeSourceError) -> Self { Self::Source(value) }
}

struct Graph<'a, S> { source: &'a S, format: GitHashAlgorithm }
impl<S: MergeObjectSource> CommitGraph for Graph<'_, S> {
    type CommitId = GitOid;
    type Error = MergeSourceError;
    fn parents_of(&self, id: &GitOid) -> Result<ParentSet<GitOid>, MergeSourceError> {
        self.source.checkpoint()?;
        if id.is_zero() || id.algorithm() != self.format {
            return Err(MergeSourceError::InvalidObject(*id));
        }
        let commit = self.source.commit(*id)?;
        if commit.tree.is_zero() || commit.tree.algorithm() != self.format
            || commit.parents.iter().any(|parent| parent.is_zero() || parent.algorithm() != self.format)
        { return Err(MergeSourceError::InvalidObject(*id)); }
        self.source.checkpoint()?;
        Ok(ParentSet::Complete(commit.parents))
    }
}

struct Cancellation<'a, S>(&'a S);
impl<S: MergeObjectSource> MergeCancellation for Cancellation<'_, S> {
    fn is_cancelled(&self) -> bool { self.0.checkpoint().is_err() }
}

/// Construct a reviewable, explicit two-parent merge. The target is the first
/// parent. A fast-forward-capable merge still creates two parents; an already
/// integrated source returns `AlreadyUpToDate` without inventing a new commit.
/// Multiple best ancestors are refused, never selected by incidental order.
pub fn prepare_merge<S: MergeObjectSource>(
    source: &S, format: GitHashAlgorithm, target: GitOid, incoming: GitOid,
    metadata: &MergeMetadata, limits: PreparationLimits,
) -> Result<MergePreparation, PreparationError> {
    limits.validate()?;
    metadata.validate()?;
    source.checkpoint()?;
    if [target, incoming].iter().any(|id| id.is_zero() || id.algorithm() != format) {
        return Err(PreparationError::ObjectFormat);
    }
    let graph = Graph { source, format };
    let bases = merge_bases_all(&graph, target, incoming, MergeBaseLimits {
        max_commits: limits.max_commits, max_edges: limits.max_edges,
    }).map_err(PreparationError::Graph)?;
    source.checkpoint()?;
    let base = match bases {
        MergeBaseResult::NoCommonAncestor => return Err(PreparationError::NoCommonAncestor),
        MergeBaseResult::Bases(bases) if bases.len() == 1 => bases[0],
        MergeBaseResult::Bases(bases) => return Err(PreparationError::MultipleMergeBases(bases)),
    };
    if base == incoming { return Ok(MergePreparation::AlreadyUpToDate { target }); }
    let base_tree = source.commit(base)?.tree;
    let our_tree = source.commit(target)?.tree;
    let their_tree = source.commit(incoming)?.tree;
    let mut planner = Planner {
        source, format, limits, entries: 0, content_merges: 0, output_bytes: 0,
        objects: BTreeMap::new(), conflicts: Vec::new(),
    };
    let tree = planner.directory(Some(base_tree), our_tree, their_tree, &[], 0, false)?;
    source.checkpoint()?;
    if !planner.conflicts.is_empty() {
        planner.conflicts.sort_by(|left, right| left.path.cmp(&right.path));
        return Ok(MergePreparation::Conflicted { base, conflicts: planner.conflicts });
    }
    let tree = tree.ok_or(PreparationError::InvalidTree)?;
    let mut body = format!(
        "tree {tree}\nparent {target}\nparent {incoming}\nauthor {} {} +0000\ncommitter {} {} +0000\n\n",
        metadata.author, metadata.timestamp, metadata.committer, metadata.timestamp,
    ).into_bytes();
    if body.len().saturating_add(metadata.message.len()) > limits.max_output_bytes {
        return Err(PreparationError::Budget("commit bytes"));
    }
    body.extend_from_slice(&metadata.message);
    let commit = planner.emit(GitObjectKind::Commit, body)?;
    source.checkpoint()?;
    Ok(MergePreparation::Clean(PreparedMerge {
        base, target, source: incoming, tree, commit,
        objects: planner.objects.into_values().collect(),
    }))
}

struct Planner<'a, S> {
    source: &'a S,
    format: GitHashAlgorithm,
    limits: PreparationLimits,
    entries: usize,
    content_merges: usize,
    output_bytes: usize,
    objects: BTreeMap<GitOid, PlannedMergeObject>,
    conflicts: Vec<MergeConflict>,
}

impl<S: MergeObjectSource> Planner<'_, S> {
    fn emit(&mut self, kind: GitObjectKind, body: Vec<u8>) -> Result<GitOid, PreparationError> {
        self.source.checkpoint()?;
        let id = git_object_id(self.format, kind, &body);
        if let Some(existing) = self.objects.get(&id) {
            if existing.kind != kind || existing.body != body { return Err(PreparationError::InvalidTree); }
            return Ok(id);
        }
        if self.objects.len() == self.limits.max_objects { return Err(PreparationError::Budget("objects")); }
        self.output_bytes = self.output_bytes.checked_add(body.len())
            .filter(|bytes| *bytes <= self.limits.max_output_bytes)
            .ok_or(PreparationError::Budget("output bytes"))?;
        self.objects.insert(id, PlannedMergeObject { id, kind, body });
        Ok(id)
    }

    fn entries(&mut self, id: Option<GitOid>) -> Result<BTreeMap<Vec<u8>, MergeEntry>, PreparationError> {
        let Some(id) = id else { return Ok(BTreeMap::new()); };
        self.source.checkpoint()?;
        if id.is_zero() || id.algorithm() != self.format { return Err(PreparationError::ObjectFormat); }
        let entries = self.source.tree(id)?;
        self.entries = self.entries.checked_add(entries.len())
            .filter(|count| *count <= self.limits.max_tree_entries)
            .ok_or(PreparationError::Budget("tree entries"))?;
        let mut map = BTreeMap::new();
        for entry in entries {
            self.source.checkpoint()?;
            if entry.name.is_empty() || entry.name.len() > self.limits.max_path_bytes
                || entry.name.contains(&0) || entry.name.contains(&b'/')
                || entry.name == b"." || entry.name == b".." || entry.name.eq_ignore_ascii_case(b".git")
                || !matches!(entry.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000)
                || entry.oid.is_zero() || entry.oid.algorithm() != self.format
            { return Err(PreparationError::InvalidTree); }
            if map.insert(entry.name.clone(), entry).is_some() { return Err(PreparationError::InvalidTree); }
        }
        Ok(map)
    }

    fn directory(
        &mut self, base: Option<GitOid>, ours: GitOid, theirs: GitOid,
        path: &[u8], depth: usize, inherited_attributes: bool,
    ) -> Result<Option<GitOid>, PreparationError> {
        self.source.checkpoint()?;
        if depth > self.limits.max_depth { return Err(PreparationError::Budget("tree depth")); }
        if ours == theirs || base == Some(theirs) { return Ok(Some(ours)); }
        if base == Some(ours) { return Ok(Some(theirs)); }
        let b = self.entries(base)?;
        let o = self.entries(Some(ours))?;
        let t = self.entries(Some(theirs))?;
        let attributes = inherited_attributes || [&b, &o, &t].iter()
            .any(|tree| tree.contains_key(b".gitattributes".as_slice()));
        let names: BTreeSet<_> = b.keys().chain(o.keys()).chain(t.keys()).cloned().collect();
        let before = self.conflicts.len();
        let mut result = Vec::new();
        for name in names {
            self.source.checkpoint()?;
            let length = path.len().checked_add(usize::from(!path.is_empty()))
                .and_then(|bytes| bytes.checked_add(name.len()))
                .filter(|bytes| *bytes <= self.limits.max_path_bytes)
                .ok_or(PreparationError::Budget("path bytes"))?;
            let mut child = Vec::with_capacity(length);
            child.extend_from_slice(path);
            if !path.is_empty() { child.push(b'/'); }
            child.extend_from_slice(&name);
            let base = b.get(&name);
            let ours = o.get(&name);
            let theirs = t.get(&name);
            if let Some(entry) = self.entry(base, ours, theirs, &child, depth, attributes)? {
                result.push(entry);
            }
        }
        if self.conflicts.len() != before { return Ok(None); }
        // Git compares a directory as if its name ended in '/', a file as if
        // it ended in NUL. Plain lexicographic name sorting is not sufficient.
        result.sort_by_cached_key(|entry| {
            let mut key = entry.name.clone();
            key.push(if entry.mode == 0o040000 { b'/' } else { 0 });
            key
        });
        let mut body = Vec::new();
        for entry in &result {
            self.source.checkpoint()?;
            let prefix = format!("{:o} ", entry.mode);
            let new_len = body.len().checked_add(prefix.len())
                .and_then(|len| len.checked_add(entry.name.len() + 1 + entry.oid.as_bytes().len()))
                .filter(|len| *len <= self.limits.max_output_bytes)
                .ok_or(PreparationError::Budget("tree bytes"))?;
            body.try_reserve(new_len - body.len()).map_err(|_| PreparationError::Budget("tree allocation"))?;
            body.extend_from_slice(prefix.as_bytes());
            body.extend_from_slice(&entry.name);
            body.push(0);
            body.extend_from_slice(entry.oid.as_bytes());
        }
        let id = git_object_id(self.format, GitObjectKind::Tree, &body);
        if Some(id) == base || id == ours || id == theirs { return Ok(Some(id)); }
        self.emit(GitObjectKind::Tree, body).map(Some)
    }

    fn conflict(
        &mut self, path: &[u8], kind: ConflictKind,
        base: Option<&MergeEntry>, ours: Option<&MergeEntry>, theirs: Option<&MergeEntry>,
    ) -> Result<Option<MergeEntry>, PreparationError> {
        if self.conflicts.len() == self.limits.max_conflicts { return Err(PreparationError::Budget("conflicts")); }
        self.conflicts.push(MergeConflict {
            path: path.to_vec(), kind, base: base.cloned(), ours: ours.cloned(), theirs: theirs.cloned(),
        });
        Ok(None)
    }

    fn entry(
        &mut self, base: Option<&MergeEntry>, ours: Option<&MergeEntry>, theirs: Option<&MergeEntry>,
        path: &[u8], depth: usize, attributes: bool,
    ) -> Result<Option<MergeEntry>, PreparationError> {
        if ours == theirs || base == theirs { return Ok(ours.cloned()); }
        if base == ours { return Ok(theirs.cloned()); }
        let (Some(o), Some(t)) = (ours, theirs) else {
            return self.conflict(path, ConflictKind::ModifyDelete, base, ours, theirs);
        };
        if o.mode == 0o040000 && t.mode == 0o040000 && base.is_none_or(|b| b.mode == 0o040000) {
            let merged = self.directory(base.map(|b| b.oid), o.oid, t.oid, path, depth + 1, attributes)?;
            return Ok(merged.map(|oid| MergeEntry { name: o.name.clone(), mode: 0o040000, oid }));
        }
        let regular = |entry: &MergeEntry| matches!(entry.mode, 0o100644 | 0o100755);
        if !regular(o) || !regular(t) || base.is_some_and(|b| !regular(b)) {
            let kind = if o.mode & 0o170000 != t.mode & 0o170000
                || base.is_some_and(|b| b.mode & 0o170000 != o.mode & 0o170000)
            { ConflictKind::TypeChange } else { ConflictKind::Opaque };
            return self.conflict(path, kind, base, ours, theirs);
        }
        let mode = if o.mode == t.mode || base.is_some_and(|b| b.mode == t.mode) { o.mode }
            else if base.is_some_and(|b| b.mode == o.mode) { t.mode }
            else { return self.conflict(path, ConflictKind::Mode, base, ours, theirs); };
        let oid = if o.oid == t.oid || base.is_some_and(|b| b.oid == t.oid) { o.oid }
            else if base.is_some_and(|b| b.oid == o.oid) { t.oid }
            else {
                if attributes { return self.conflict(path, ConflictKind::AttributesRequireDriver, base, ours, theirs); }
                if self.content_merges == self.limits.max_content_merges {
                    return Err(PreparationError::Budget("content merges"));
                }
                self.content_merges += 1;
                let b = match base { Some(b) => self.source.blob(b.oid)?, None => Vec::new() };
                let o_bytes = self.source.blob(o.oid)?;
                let t_bytes = self.source.blob(t.oid)?;
                self.source.checkpoint()?;
                if [&b, &o_bytes, &t_bytes].iter().any(|bytes| bytes.contains(&0)) {
                    return self.conflict(path, ConflictKind::Binary, base, ours, theirs);
                }
                let mut options = ContentMergeOptions::default();
                options.limits.max_input_bytes = self.limits.max_text_bytes;
                options.limits.max_output_bytes = self.limits.max_text_bytes;
                options.limits.max_hunks = 4096;
                options.limits.max_conflicts = self.limits.max_conflicts;
                options.limits.max_work_steps = 1_000_000;
                options.profile.diff_options.limits.max_input_bytes = self.limits.max_text_bytes;
                options.profile.diff_options.limits.max_units = 16_384;
                options.profile.diff_options.limits.max_work = 1_000_000;
                options.profile.diff_options.limits.max_trace_cells = 262_144;
                let merged = merge_content_with_cancellation(&b, &o_bytes, &t_bytes, options, &Cancellation(self.source));
                self.source.checkpoint()?;
                match merged.map_err(|error| PreparationError::Content { path: path.to_vec(), error })?.outcome {
                    ContentMergeOutcome::Clean { bytes } => {
                        if bytes == o_bytes { o.oid } else if bytes == t_bytes { t.oid }
                        else if bytes == b && base.is_some() { base.ok_or(PreparationError::InvalidTree)?.oid }
                        else { self.emit(GitObjectKind::Blob, bytes)? }
                    }
                    ContentMergeOutcome::Conflicted { .. } => {
                        return self.conflict(path, ConflictKind::Content, base, ours, theirs);
                    }
                }
            };
        Ok(Some(MergeEntry { name: o.name.clone(), mode, oid }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Source {
        format: GitHashAlgorithm,
        commits: BTreeMap<GitOid, CommitInput>,
        trees: BTreeMap<GitOid, Vec<MergeEntry>>,
        blobs: BTreeMap<GitOid, Vec<u8>>,
        live: Cell<bool>,
    }
    impl Source {
        fn new(format: GitHashAlgorithm) -> Self {
            Self { format, commits: BTreeMap::new(), trees: BTreeMap::new(), blobs: BTreeMap::new(), live: Cell::new(true) }
        }
        fn file(&mut self, name: &[u8], bytes: &[u8], mode: u32) -> MergeEntry {
            let oid = git_object_id(self.format, GitObjectKind::Blob, bytes);
            self.blobs.insert(oid, bytes.to_vec());
            MergeEntry { name: name.to_vec(), mode, oid }
        }
        fn tree(&mut self, mut entries: Vec<MergeEntry>) -> GitOid {
            entries.sort_by_cached_key(|entry| { let mut key = entry.name.clone(); key.push(if entry.mode == 0o040000 { b'/' } else { 0 }); key });
            let mut body = Vec::new();
            for entry in &entries {
                body.extend(format!("{:o} ", entry.mode).as_bytes()); body.extend(&entry.name);
                body.push(0); body.extend(entry.oid.as_bytes());
            }
            let id = git_object_id(self.format, GitObjectKind::Tree, &body);
            self.trees.insert(id, entries); id
        }
        fn commit(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
            let mut body = format!("tree {tree}\n");
            for parent in parents { body.push_str(&format!("parent {parent}\n")); }
            body.push_str(&format!("author T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\n{label}"));
            let id = git_object_id(self.format, GitObjectKind::Commit, body.as_bytes());
            self.commits.insert(id, CommitInput { tree, parents: parents.to_vec() }); id
        }
    }
    impl MergeObjectSource for Source {
        fn checkpoint(&self) -> Result<(), MergeSourceError> {
            if self.live.get() { Ok(()) } else { Err(MergeSourceError::Cancelled) }
        }
        fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> { self.commits.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id)) }
        fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> { self.trees.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id)) }
        fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> { self.blobs.get(&id).cloned().ok_or(MergeSourceError::Unavailable(id)) }
    }
    fn metadata() -> MergeMetadata {
        MergeMetadata { author: "T <t@x>".into(), committer: "T <t@x>".into(), timestamp: 1, message: b"merge\n".to_vec() }
    }
    fn branch_pair(source: &mut Source, b: Vec<MergeEntry>, o: Vec<MergeEntry>, t: Vec<MergeEntry>) -> (GitOid, GitOid) {
        let bt = source.tree(b); let base = source.commit(bt, &[], "base");
        let ot = source.tree(o); let ours = source.commit(ot, &[base], "ours");
        let tt = source.tree(t); let theirs = source.commit(tt, &[base], "theirs");
        (ours, theirs)
    }

    #[test]
    fn recursive_text_mode_and_unchanged_subtrees_are_deterministic_in_both_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let mut s = Source::new(format);
            let base_file = s.file(b"text", b"one\ntwo\nthree\nfour\nfive\n", 0o100644);
            let our_file = s.file(b"text", b"ONE\ntwo\nthree\nfour\nfive\n", 0o100755);
            let their_file = s.file(b"text", b"one\ntwo\nthree\nfour\nFIVE\n", 0o100644);
            let bt = s.tree(vec![base_file]); let ot = s.tree(vec![our_file]); let tt = s.tree(vec![their_file]);
            let dir = |oid| MergeEntry { name: b"dir".to_vec(), mode: 0o040000, oid };
            let keep = s.file(b"keep", b"do not copy me\n", 0o100644);
            let (ours, theirs) = branch_pair(&mut s, vec![dir(bt), keep.clone()], vec![dir(ot), keep.clone()], vec![dir(tt), keep.clone()]);
            let result = prepare_merge(&s, format, ours, theirs, &metadata(), PreparationLimits::default()).unwrap();
            assert_eq!(result, prepare_merge(&s, format, ours, theirs, &metadata(), PreparationLimits::default()).unwrap());
            let MergePreparation::Clean(plan) = result else { panic!("separate lines must merge"); };
            assert!(plan.objects.iter().any(|o| o.kind == GitObjectKind::Blob && o.body == b"ONE\ntwo\nthree\nfour\nFIVE\n"));
            assert!(!plan.objects.iter().any(|o| o.id == keep.oid));
            let commit = plan.objects.iter().find(|o| o.id == plan.commit).unwrap();
            assert!(String::from_utf8_lossy(&commit.body).starts_with(&format!("tree {}\nparent {ours}\nparent {theirs}\n", plan.tree)));
            assert!(plan.objects.iter().any(|o| o.kind == GitObjectKind::Tree && o.body.starts_with(b"100755 text\0")));
            for object in &plan.objects { assert_eq!(object.id, git_object_id(format, object.kind, &object.body)); }
        }
    }

    #[test]
    fn conflicts_never_return_partial_candidate_objects() {
        for (base, ours, theirs, kind) in [
            (b"base\n".as_slice(), b"ours\n".as_slice(), b"theirs\n".as_slice(), ConflictKind::Content),
            (b"\0base".as_slice(), b"\0ours".as_slice(), b"\0theirs".as_slice(), ConflictKind::Binary),
        ] {
            let mut s = Source::new(GitHashAlgorithm::Sha1);
            let b = s.file(b"file", base, 0o100644); let o = s.file(b"file", ours, 0o100644); let t = s.file(b"file", theirs, 0o100644);
            let (ours, theirs) = branch_pair(&mut s, vec![b], vec![o], vec![t]);
            let result = prepare_merge(&s, s.format, ours, theirs, &metadata(), PreparationLimits::default()).unwrap();
            assert!(matches!(result, MergePreparation::Conflicted { conflicts, .. } if conflicts.len() == 1 && conflicts[0].kind == kind));
        }
    }

    #[test]
    fn deletion_and_opaque_changes_do_not_get_silently_resolved() {
        let mut s = Source::new(GitHashAlgorithm::Sha256);
        let b = s.file(b"file", b"base", 0o120000); let t = s.file(b"file", b"new target", 0o120000);
        let (ours, theirs) = branch_pair(&mut s, vec![b], vec![], vec![t]);
        let result = prepare_merge(&s, s.format, ours, theirs, &metadata(), PreparationLimits::default()).unwrap();
        assert!(matches!(result, MergePreparation::Conflicted { conflicts, .. } if conflicts[0].kind == ConflictKind::ModifyDelete));
    }

    #[test]
    fn attributes_require_an_explicit_driver_instead_of_default_text_resolution() {
        let mut s = Source::new(GitHashAlgorithm::Sha1);
        let attr = s.file(b".gitattributes", b"* merge=custom\n", 0o100644);
        let b = s.file(b"file", b"a\nb\nc\n", 0o100644);
        let o = s.file(b"file", b"A\nb\nc\n", 0o100644);
        let t = s.file(b"file", b"a\nb\nC\n", 0o100644);
        let (ours, theirs) = branch_pair(&mut s, vec![attr.clone(), b], vec![attr.clone(), o], vec![attr, t]);
        let result = prepare_merge(&s, s.format, ours, theirs, &metadata(), PreparationLimits::default()).unwrap();
        assert!(matches!(result, MergePreparation::Conflicted { conflicts, .. } if conflicts[0].kind == ConflictKind::AttributesRequireDriver));
    }

    #[test]
    fn criss_cross_and_no_common_base_are_refused_without_picking_an_arbitrary_base() {
        let mut s = Source::new(GitHashAlgorithm::Sha1);
        let tree = s.tree(vec![]); let root = s.commit(tree, &[], "root");
        let a = s.commit(tree, &[root], "a"); let b = s.commit(tree, &[root], "b");
        let left = s.commit(tree, &[a, b], "left"); let right = s.commit(tree, &[b, a], "right");
        assert!(matches!(prepare_merge(&s, s.format, left, right, &metadata(), PreparationLimits::default()), Err(PreparationError::MultipleMergeBases(_))));
        let other = s.commit(tree, &[], "unrelated");
        assert!(matches!(prepare_merge(&s, s.format, left, other, &metadata(), PreparationLimits::default()), Err(PreparationError::NoCommonAncestor)));
        assert_eq!(prepare_merge(&s, s.format, left, a, &metadata(), PreparationLimits::default()).unwrap(), MergePreparation::AlreadyUpToDate { target: left });
    }

    #[test]
    fn cancellation_limits_and_metadata_injection_refuse() {
        let mut s = Source::new(GitHashAlgorithm::Sha1);
        let tree = s.tree(vec![]); let base = s.commit(tree, &[], "base"); let tip = s.commit(tree, &[base], "tip");
        let mut bad = metadata(); bad.author = "T <t@x>\nparent forged".into();
        assert!(matches!(prepare_merge(&s, s.format, base, tip, &bad, PreparationLimits::default()), Err(PreparationError::InvalidMetadata)));
        let limits = PreparationLimits { max_commits: 1, ..PreparationLimits::default() };
        assert!(matches!(prepare_merge(&s, s.format, base, tip, &metadata(), limits), Err(PreparationError::Graph(MergeBaseError::CommitLimitExceeded { .. }))));
        s.live.set(false);
        assert!(matches!(prepare_merge(&s, s.format, base, tip, &metadata(), PreparationLimits::default()), Err(PreparationError::Source(MergeSourceError::Cancelled))));
    }
}
