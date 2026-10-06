//! Independent root-bundle inspection and the shared pre-publication verifier.
//! This module has no object-fabric writer, seal, ref command or publication.
use super::{check_reference, invalid, pack_error};
use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::initial_commit::InitialCommitError;
use fgit_forge::initial_commit::inspection::{
    InitialCommitInspection, InitialInspectionLimits, InspectedInitialDirectory,
    InspectedInitialFile,
};
use fgit_git_object::{
    AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body, parse_tree,
};
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits};
use fgit_pack::{EntryKind, NativeChecksumVerifier, PackLimits, QuarantinedPack, read_verified_pack};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;
use std::collections::{BTreeMap, BTreeSet};

const MAX_CLOSURE_EDGES: usize = 1_000_000;

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), NodeWorkspaceRefusal> {
    if live() {
        Ok(())
    } else {
        Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None })
    }
}
fn budget(name: &'static str) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::InitialCommit(InitialCommitError::Budget(name))
}

/// Header binding stays separate so original-key recovery can precede decoding.
/// A full envelope rejects prerequisites and the one-record bound excludes HEAD.
pub(super) fn envelope<'a>(
    input: &'a [u8],
    format: GitHashAlgorithm,
    reference: &RefName,
    candidate: GitOid,
    live: &mut impl FnMut() -> bool,
) -> Result<FullBundleInput<'a>, NodeWorkspaceRefusal> {
    check_reference(reference)?;
    if candidate.is_zero() || candidate.algorithm() != format {
        return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
    }
    let envelope = FullBundleInput::parse(
        input,
        FullBundleLimits { max_references: 1, ..FullBundleLimits::default() },
        live,
    ).map_err(pack_error)?;
    if envelope.format() != format {
        return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
    }
    let [advertised] = envelope.references() else {
        return Err(invalid("one initial branch is required"));
    };
    if advertised.name() != reference || advertised.target() != &candidate {
        return Err(invalid("initial bundle differs from independent branch/commit expectations"));
    }
    Ok(envelope)
}

struct Child {
    name: Vec<u8>,
    mode: u32,
    id: GitOid,
}
impl Child {
    const fn kind(&self) -> GitObjectKind {
        if self.mode == 0o40000 { GitObjectKind::Tree } else { GitObjectKind::Blob }
    }
}

/// Constructed only after exact identity, kind and complete reachability checks.
/// Retain one copy of the bounded inflated pack, with indexes into those bytes.
pub(super) struct VerifiedInitial {
    pack: QuarantinedPack,
    objects: BTreeMap<GitOid, (GitObjectKind, usize)>,
    trees: BTreeMap<GitOid, Vec<Child>>,
    root: GitOid,
    commit: GitOid,
    expanded_bytes: usize,
}
impl VerifiedInitial {
    fn body(&self, id: GitOid, kind: GitObjectKind) -> Result<&[u8], NodeWorkspaceRefusal> {
        let &(actual, index) = self.objects.get(&id)
            .ok_or_else(|| invalid("initial bundle dependency missing"))?;
        if actual != kind {
            return Err(invalid("initial bundle dependency has the wrong kind"));
        }
        self.pack.entries().get(index).map(|entry| entry.inflated.as_slice())
            .ok_or_else(|| invalid("initial bundle object index invalid"))
    }
}

pub(super) fn read_pack(
    bytes: &[u8],
    format: GitHashAlgorithm,
    expected_commit: GitOid,
    limits: &PackLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<VerifiedInitial, NodeWorkspaceRefusal> {
    checkpoint(live)?;
    let pack = read_verified_pack(bytes, format, limits, live, &NativeChecksumVerifier)
        .map_err(pack_error)?;
    let parsing = ParseLimits {
        tree_reference_bytes: format.digest_len(),
        max_object_bytes: limits.max_object_bytes,
        ..ParseLimits::default()
    };
    let mut objects = BTreeMap::new();
    let mut trees = BTreeMap::new();
    let mut root = None;
    let mut expanded_bytes = 0usize;
    let mut edges = 0usize;
    for (index, entry) in pack.entries().iter().enumerate() {
        checkpoint(live)?;
        let kind = match entry.header.kind {
            EntryKind::Commit => GitObjectKind::Commit,
            EntryKind::Tree => GitObjectKind::Tree,
            EntryKind::Blob => GitObjectKind::Blob,
            _ => return Err(invalid("initial profile excludes tags and delta entries")),
        };
        let id = git_object_id(format, kind, &entry.inflated);
        checkpoint(live)?;
        if id.is_zero() || objects.insert(id, (kind, index)).is_some() {
            return Err(invalid("initial bundle contains duplicate object identities"));
        }
        expanded_bytes = expanded_bytes.checked_add(entry.inflated.len())
            .filter(|n| *n <= limits.max_total_expanded_bytes)
            .ok_or_else(|| budget("initial expanded bytes"))?;
        match kind {
            GitObjectKind::Commit => {
                if id != expected_commit || root.is_some() {
                    return Err(invalid("initial bundle must contain only its reviewed root commit"));
                }
                let ParsedObject::Commit(commit) = parse_object_body(
                    ObjectType::Commit, &entry.inflated, AcceptanceProfile::StrictCreate, &parsing,
                ).map_err(|_| invalid("invalid initial commit bytes"))? else {
                    return Err(invalid("initial object is not a commit"));
                };
                if commit.parent_references().next().is_some() {
                    return Err(invalid("initial commit has a parent"));
                }
                let tree = commit.tree_reference()
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .and_then(|text| GitOid::from_hex(format, text).ok())
                    .filter(|id| !id.is_zero())
                    .ok_or_else(|| invalid("invalid initial tree reference"))?;
                root = Some(tree);
            }
            GitObjectKind::Tree => {
                let tree_limits = ParseLimits {
                    max_tree_entries: MAX_CLOSURE_EDGES.saturating_sub(edges).max(1),
                    ..parsing.clone()
                };
                let parsed = parse_tree(&entry.inflated, AcceptanceProfile::StrictCreate, &tree_limits)
                    .map_err(|_| invalid("invalid initial tree"))?;
                edges = edges.checked_add(parsed.len()).filter(|n| *n <= MAX_CLOSURE_EDGES)
                    .ok_or_else(|| budget("initial closure edges"))?;
                let mut children = Vec::new();
                children.try_reserve_exact(parsed.len()).map_err(|_| budget("initial tree allocation"))?;
                let mut names = BTreeSet::new();
                for child in parsed {
                    checkpoint(live)?;
                    let mode = match child.mode.as_slice() {
                        b"40000" => 0o40000,
                        b"100644" => 0o100644,
                        b"100755" => 0o100755,
                        _ => return Err(invalid("initial tree contains a non-regular file or gitlink")),
                    };
                    if child.name.contains(&b'/')
                        || fgit_treefs::TreePath::parse_default(&child.name).is_err()
                        || !names.insert(child.name.clone())
                    {
                        return Err(invalid("invalid or duplicate initial tree name"));
                    }
                    let id = GitOid::from_hex(format, &fgit_crypto::lowercase_hex(&child.object_id))
                        .map_err(|_| invalid("invalid initial tree child"))?;
                    children.push(Child { name: child.name.to_vec(), mode, id });
                }
                trees.insert(id, children);
            }
            GitObjectKind::Blob => {}
            GitObjectKind::Tag => return Err(invalid("initial profile excludes tags")),
        }
    }
    let root = root.ok_or_else(|| invalid("initial root commit is missing"))?;
    let verified = VerifiedInitial { pack, objects, trees, root, commit: expected_commit, expanded_bytes };
    let mut reached = BTreeSet::from([expected_commit]);
    let mut frontier = vec![(root, GitObjectKind::Tree)];
    while let Some((id, kind)) = frontier.pop() {
        checkpoint(live)?;
        // Check every edge's required type BEFORE deduplicating traversal.
        // A visited tree cannot later satisfy a regular-file edge to the same ID.
        verified.body(id, kind)?;
        if !reached.insert(id) { continue; }
        if let Some(children) = verified.trees.get(&id) {
            frontier.try_reserve(children.len()).map_err(|_| budget("initial closure allocation"))?;
            for child in children {
                checkpoint(live)?;
                frontier.push((child.id, child.kind()));
            }
        }
    }
    if reached.len() != verified.objects.len() {
        return Err(invalid("initial bundle contains objects outside the reviewed closure"));
    }
    checkpoint(live)?;
    Ok(verified)
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, NodeWorkspaceRefusal> {
    let mut output = Vec::new();
    output.try_reserve_exact(bytes.len()).map_err(|_| budget("initial preview allocation"))?;
    output.extend_from_slice(bytes);
    Ok(output)
}
fn charge(total: &mut usize, amount: usize, limit: usize) -> Result<(), NodeWorkspaceRefusal> {
    *total = total.checked_add(amount).filter(|n| *n <= limit)
        .ok_or_else(|| budget("initial preview bytes"))?;
    Ok(())
}

fn preview(
    verified: &VerifiedInitial,
    input: &[u8],
    pack_bytes: usize,
    limits: InitialInspectionLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<InitialCommitInspection, NodeWorkspaceRefusal> {
    limits.validate().map_err(NodeWorkspaceRefusal::InitialCommit)?;
    checkpoint(live)?;
    let body = verified.body(verified.commit, GitObjectKind::Commit)?;
    if body.len() > limits.max_commit_bytes { return Err(budget("initial commit preview bytes")); }
    let mut output_bytes = 0usize;
    charge(&mut output_bytes, body.len(), limits.max_output_bytes)?;
    let commit_body = copy(body)?;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut entries = 0usize;
    let mut frontier = vec![(Vec::new(), verified.root, 0usize)];
    while let Some((path, tree, depth)) = frontier.pop() {
        checkpoint(live)?;
        directories.try_reserve(1).map_err(|_| budget("initial directory preview allocation"))?;
        directories.push(InspectedInitialDirectory { path: copy(&path)?, tree });
        let children = verified.trees.get(&tree).ok_or_else(|| invalid("initial tree missing"))?;
        entries = entries.checked_add(children.len()).filter(|n| *n <= limits.max_tree_entries)
            .ok_or_else(|| budget("initial preview tree entries"))?;
        // Do not deduplicate by tree ID: every alias is a separate output path.
        for child in children {
            checkpoint(live)?;
            if depth >= limits.max_depth { return Err(budget("initial preview depth")); }
            let length = path.len().checked_add(usize::from(!path.is_empty()))
                .and_then(|n| n.checked_add(child.name.len()))
                .filter(|n| *n <= limits.max_path_bytes)
                .ok_or_else(|| budget("initial preview path bytes"))?;
            charge(&mut output_bytes, length, limits.max_output_bytes)?;
            let mut child_path = Vec::new();
            child_path.try_reserve_exact(length).map_err(|_| budget("initial path allocation"))?;
            child_path.extend_from_slice(&path);
            if !path.is_empty() { child_path.push(b'/'); }
            child_path.extend_from_slice(&child.name);
            fgit_treefs::TreePath::parse_default(&child_path)
                .map_err(|_| invalid("invalid expanded initial path"))?;
            if child.kind() == GitObjectKind::Tree {
                frontier.try_reserve(1).map_err(|_| budget("initial preview frontier"))?;
                frontier.push((child_path, child.id, depth + 1));
            } else {
                if files.len() == limits.max_files { return Err(budget("initial preview files")); }
                let content = verified.body(child.id, GitObjectKind::Blob)?;
                if content.len() > limits.max_file_bytes { return Err(budget("initial preview file bytes")); }
                charge(&mut output_bytes, content.len(), limits.max_output_bytes)?;
                files.try_reserve(1).map_err(|_| budget("initial file preview allocation"))?;
                files.push(InspectedInitialFile {
                    path: child_path, blob: child.id, mode: child.mode, content: copy(content)?,
                });
            }
        }
    }
    checkpoint(live)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    directories.sort_by(|a, b| a.path.cmp(&b.path));
    let bundle_sha256 = sha256_digest(input);
    checkpoint(live)?;
    Ok(InitialCommitInspection {
        object_format: verified.pack.format,
        candidate_commit: verified.commit,
        root_tree: verified.root,
        commit_body, files, directories, bundle_sha256,
        bundle_bytes: input.len(), pack_bytes,
        object_count: verified.objects.len(), expanded_bytes: verified.expanded_bytes,
    })
}

impl OneNode {
    /// Inspect a submitted root commit independently of its producer or patch.
    /// The caller must hold source-read permission. Canonical and caller-supplied
    /// visibility both apply; an optional pin and branch absence are checked at
    /// ONE selected head. No original Git object is borrowed or uploaded object
    /// staged. Complete files, empty directories and exact metadata are returned.
    /// Publication still requires its own grant and expected-absent admission.
    pub async fn inspect_initial_patch_bundle_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_commit: GitOid,
        input: &[u8],
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        limits: InitialInspectionLimits,
    ) -> Result<(RepositoryAuthorityHeadId, InitialCommitInspection), NodeWorkspaceRefusal> {
        limits.validate().map_err(NodeWorkspaceRefusal::InitialCommit)?;
        let mut live = || super::workspace_request_live(request);
        checkpoint(&mut live)?;
        let envelope = envelope(input, self.object_format, reference, expected_commit, &mut live)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if visibility.hides(reference.as_bytes()) { return Err(NodeWorkspaceRefusal::RefUnavailable); }
        let selected = self.materialize_admission_in(request).await
            .map_err(|e| NodeWorkspaceRefusal::Authority(Box::new(e)))?;
        checkpoint(&mut live)?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(invalid("initial inspection snapshot moved"));
        }
        if selected.snapshot().refs.contains_key(reference) {
            return Err(invalid("initial inspection destination branch already exists"));
        }
        let verified = read_pack(
            envelope.pack_bytes(), self.object_format, expected_commit,
            &self.initial_commit_pack_limits(), &mut live,
        )?;
        let report = preview(&verified, input, envelope.pack_bytes().len(), limits, &mut live)?;
        Ok((selected.basis().id(), report))
    }
}

#[cfg(test)]
mod tests;
