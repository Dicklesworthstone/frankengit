//! Exact, bounded repository browsing over verified immutable TreeFS objects.
//! No host paths, worktree, object-ID lookup oracle, or publication effects.

mod ancestor;

use super::{NodeTreeSource, NodeWorkspaceRefusal, workspace_request_live};
use crate::{ClosureSelectionSource, NodeRequestContext, OneNode, VerifiedFabricPackSource};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::{
    AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body, parse_tree,
};
use fgit_treefs::{
    BaseEntry, BaseError, BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant,
    TreeCapability, TreePath, WorkspaceId,
};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{
    ByteCount, GitHashAlgorithm as Format, GitOid as Oid, RefName, RepositoryAuthorityHeadId,
};
use fgit_wire::visibility::RefVisibility;
use std::cell::Cell;

const MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_READ_OBJECTS: u64 = 132;
const MAX_ENTRIES: usize = 100_000;
use fgit_forge::source_browse::{
    SourceBrowseAction, SourceBrowseContent, SourceBrowseError, SourceBrowseQuery,
    SourceBrowseReport, SourceDirectoryEntry, SourceEntryKind,
};

fn error(reason: SourceBrowseError) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::SourceBrowse(Box::new(reason))
}
fn base_error(reason: BaseError) -> NodeWorkspaceRefusal {
    error(SourceBrowseError::Base(Box::new(reason)))
}
fn live(request: &NodeRequestContext) -> Result<(), NodeWorkspaceRefusal> {
    if workspace_request_live(request) {
        Ok(())
    } else {
        Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None })
    }
}

fn oid<A: GitHashAlgorithm>(id: &GitOid<A>, format: Format) -> Result<Oid, NodeWorkspaceRefusal> {
    let hex = id
        .digest_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Oid::from_hex(format, &hex).map_err(|_| NodeWorkspaceRefusal::ObjectFormatMismatch)
}
fn kind<A: GitHashAlgorithm>(
    entry: &BaseEntry<A>,
) -> Result<SourceEntryKind, NodeWorkspaceRefusal> {
    Ok(match entry {
        BaseEntry::File { mode, .. } if mode == b"100644" => SourceEntryKind::File,
        BaseEntry::File { mode, .. } if mode == b"100755" => SourceEntryKind::Executable,
        BaseEntry::File { .. } => return Err(error(SourceBrowseError::UnsupportedFileMode)),
        BaseEntry::Directory { .. } => SourceEntryKind::Directory,
        BaseEntry::Symlink { .. } => SourceEntryKind::Symlink,
        BaseEntry::Submodule { .. } => SourceEntryKind::Gitlink,
    })
}

impl OneNode {
    /// A capability-preserving read for authenticated embeddings. No ambient
    /// capability is minted. Hidden refs and caller visibility are conjunctive;
    /// continuations revalidate the current head and the same immutable commit.
    pub async fn browse_source_in<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        visibility: &RefVisibility,
        capability: &mut TreeCapability,
        now: u64,
        query: &SourceBrowseQuery,
    ) -> Result<SourceBrowseReport, NodeWorkspaceRefusal> {
        let path = query.validate(self.object_format).map_err(error)?;
        if capability.repository_id() != self.repository_id() {
            return Err(NodeWorkspaceRefusal::RepositoryMismatch);
        }
        // Reject an out-of-scope request before even selecting/reading its base.
        if let Some(path) = &path {
            capability
                .authorize_read(path, now)
                .map_err(|e| base_error(e.into()))?;
        }
        self.with_workspace_snapshot_in::<A, _>(
            request,
            reference,
            visibility,
            capability,
            now,
            query.expected_head,
            query.expected_commit,
            MAX_OBJECT_BYTES,
            |base, source, capability, head, metadata_bytes| {
                let params = BrowseParams {
                    request,
                    capability,
                    now,
                    head,
                    query,
                    path: path.as_ref(),
                    budget: ReadBudget::new(metadata_bytes, 1),
                };
                browse_at(base, source, params)
            },
        )
        .await
    }

    /// Explicit local-owner read boundary, not remote authentication or an
    /// agent capability broker. Root grants are derived from this selected
    /// verified tree; no wildcard or fabricated root path is introduced.
    pub async fn browse_source_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        query: &SourceBrowseQuery,
    ) -> Result<SourceBrowseReport, NodeWorkspaceRefusal> {
        match self.object_format {
            Format::Sha1 => {
                self.browse_local_format::<Sha1>(request, reference, query, None)
                    .await
            }
            Format::Sha256 => {
                self.browse_local_format::<Sha256>(request, reference, query, None)
                    .await
            }
        }
    }

    async fn browse_local_format<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        query: &SourceBrowseQuery,
        ancestor: Option<ancestor::Selection>,
    ) -> Result<SourceBrowseReport, NodeWorkspaceRefusal> {
        let path = query.validate(self.object_format).map_err(error)?;
        if let Some(selection) = ancestor {
            selection.validate(self.object_format, query)?;
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        live(request)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| NodeWorkspaceRefusal::Authority(Box::new(e)))?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let tip = *selected
            .snapshot()
            .refs
            .get(reference)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let head = selected.basis().id();
        if query.expected_head.is_some_and(|expected| expected != head) {
            return Err(error(SourceBrowseError::SnapshotMoved));
        }
        if ancestor.is_some_and(|selection| selection.expected_ref_tip != tip) {
            return Err(error(SourceBrowseError::CommitMoved));
        }
        let commit = ancestor.map_or(tip, |selection| selection.commit);
        if query
            .expected_commit
            .is_some_and(|expected| expected != commit)
        {
            return Err(error(SourceBrowseError::CommitMoved));
        }
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest: rcr, .. } => rcr,
            ClosureSelectionSource::EmptyGenesis => {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
        };
        let exhaustion = Cell::new(None);
        let source = NodeTreeSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.fabric,
                object_format: self.object_format,
                maximum_object_bytes: MAX_OBJECT_BYTES
                    .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)),
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected: selected.selected_closure(),
            workspace: WorkspaceId::from_bytes(*self.repository_id().as_bytes()),
        };
        let read = |id: Oid, expected: ObjectType| {
            live(request)?;
            if !selected
                .selected_closure()
                .closure()
                .objects()
                .contains(&id)
            {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
            let body = source.inner.read_object(&id);
            live(request)?;
            let (kind, body) = body.map_err(|e| {
                NodeWorkspaceRefusal::Object(ObjectSourceError::Refused {
                    reason: e.to_string(),
                })
            })?;
            if kind != expected {
                return Err(NodeWorkspaceRefusal::CommitRequired);
            }
            Ok(body)
        };
        // An admitted object elsewhere in the repository is not an ancestor
        // of this ref. Establish that relationship BEFORE any tree/blob read.
        // The receipt retains the verified target body, avoiding a second read.
        let (commit_body, ancestry_bytes) = match ancestor {
            Some(_) => {
                let proof = ancestor::select(&source, request, tip, commit)?;
                let additional = proof.bytes - proof.body.len() as u64;
                (proof.body, additional)
            }
            None => (read(commit, ObjectType::Commit)?, 0),
        };
        let parse = ParseLimits {
            max_object_bytes: source.inner.maximum_object_bytes,
            max_tree_entries: MAX_ENTRIES,
            tree_reference_bytes: self.object_format.digest_len(),
            ..ParseLimits::default()
        };
        let ParsedObject::Commit(parsed) = parse_object_body(
            ObjectType::Commit,
            &commit_body,
            AcceptanceProfile::GitCompatibleImport,
            &parse,
        )
        .map_err(|_| NodeWorkspaceRefusal::CommitRequired)?
        else {
            return Err(NodeWorkspaceRefusal::CommitRequired);
        };
        let tree = parsed
            .tree_reference()
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|s| Oid::from_hex(self.object_format, &s.to_ascii_lowercase()).ok())
            .ok_or(NodeWorkspaceRefusal::CommitRequired)?;
        // Ancestry has a separate 4096-commit work ceiling, but its bytes
        // still consume the SAME 64 MiB allowance as subsequent source reads.
        let mut metadata_bytes = commit_body.len() as u64 + ancestry_bytes;
        let mut metadata_objects = 1;
        let prefixes = if let Some(path) = &path {
            vec![
                TreePath::parse_default(path.components().next().unwrap_or_default())
                    .map_err(|_| error(SourceBrowseError::InvalidRequest("invalid path prefix")))?,
            ]
        } else {
            let root = read(tree, ObjectType::Tree)?;
            metadata_bytes += root.len() as u64;
            metadata_objects += 1;
            let entries = parse_tree(&root, AcceptanceProfile::GitCompatibleImport, &parse)
                .map_err(|e| base_error(e.into()))?;
            if entries.len() > 4096 {
                return Err(error(SourceBrowseError::Budget("root disclosure scopes")));
            }
            entries
                .iter()
                .map(|e| TreePath::parse_default(&e.name).map_err(|e| base_error(e.into())))
                .collect::<Result<Vec<_>, _>>()?
        };
        if prefixes.is_empty() {
            live(request)?;
            return Ok(SourceBrowseReport {
                repository_id: self.repository_id(),
                source_head: head,
                source_rcr: rcr,
                source_commit: commit,
                root_tree: tree,
                object_id: tree,
                path: None,
                content: SourceBrowseContent::Directory {
                    entries: Vec::new(),
                    next_after: None,
                },
            });
        }
        let budget = ByteCount::try_new("source browse reads", MAX_READ_BYTES, MAX_READ_BYTES)
            .map_err(|_| error(SourceBrowseError::Budget("read bytes")))?;
        let mut capability =
            TreeCapability::new(source.workspace, self.repository_id(), prefixes, Vec::new())
                .with_fetch_budget(budget)
                .with_file_budget(MAX_READ_OBJECTS);
        capability
            .charge_fetch(metadata_bytes)
            .map_err(|e| base_error(e.into()))?;
        if metadata_objects == 2 {
            capability
                .charge_fetch(0)
                .map_err(|e| base_error(e.into()))?;
        }
        let base = BaseView::<A>::new(
            self.repository_id(),
            rcr,
            A::parse_hex(&commit.to_string())
                .map_err(|_| NodeWorkspaceRefusal::ObjectFormatMismatch)?,
            A::parse_hex(&tree.to_string())
                .map_err(|_| NodeWorkspaceRefusal::ObjectFormatMismatch)?,
            parse,
            PathPolicy::default(),
        );
        let params = BrowseParams {
            request,
            capability: &mut capability,
            now: 0,
            head,
            query,
            path: path.as_ref(),
            budget: ReadBudget::new(metadata_bytes, metadata_objects),
        };
        browse_at(&base, &source, params)
    }
}

// The commit/root discovery reads and the subsequent traversal share this
// envelope. A small output slice must not authorize an unbounded blob decode.
struct ReadBudget {
    bytes: Cell<u64>,
    objects: Cell<u64>,
}
impl ReadBudget {
    fn new(bytes: u64, objects: u64) -> Self {
        Self {
            bytes: Cell::new(bytes),
            objects: Cell::new(objects),
        }
    }
    fn reserve(&self) -> Result<usize, ObjectSourceError> {
        let remaining = MAX_READ_BYTES
            .checked_sub(self.bytes.get())
            .ok_or_else(|| read_refused("source byte budget"))?;
        if self.objects.get() >= MAX_READ_OBJECTS {
            return Err(read_refused("source object budget"));
        }
        self.objects.set(self.objects.get() + 1);
        Ok(MAX_OBJECT_BYTES.min(usize::try_from(remaining).unwrap_or(usize::MAX)))
    }
    fn charge(&self, bytes: usize) -> Result<(), ObjectSourceError> {
        let total = self
            .bytes
            .get()
            .checked_add(bytes as u64)
            .filter(|total| *total <= MAX_READ_BYTES)
            .ok_or_else(|| read_refused("source byte budget"))?;
        self.bytes.set(total);
        Ok(())
    }
}
fn read_refused(reason: &str) -> ObjectSourceError {
    ObjectSourceError::Refused {
        reason: reason.into(),
    }
}
struct BoundedSource<'a, 'source> {
    inner: &'a NodeTreeSource<'source>,
    request: &'a NodeRequestContext,
    budget: ReadBudget,
}
impl<A: GitHashAlgorithm> ObjectSource<A> for BoundedSource<'_, '_> {
    fn read_object(
        &self,
        id: &GitOid<A>,
        kind: GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        if !workspace_request_live(self.request) {
            return Err(read_refused("source read cancelled"));
        }
        let remaining = self.budget.reserve()?;
        // Tighten the fabric read bound BEFORE decompression/allocation,
        // including the remaining aggregate allowance, not merely each object.
        let bounded = NodeTreeSource {
            inner: VerifiedFabricPackSource {
                maximum_object_bytes: self.inner.inner.maximum_object_bytes.min(remaining),
                ..self.inner.inner
            },
            selected: self.inner.selected,
            workspace: self.inner.workspace,
        };
        let body = bounded.read_object::<A>(id, kind, grant)?;
        if !workspace_request_live(self.request) {
            return Err(read_refused("source read cancelled"));
        }
        self.budget.charge(body.len())?;
        Ok(body)
    }
}

struct BrowseParams<'a> {
    request: &'a NodeRequestContext,
    capability: &'a mut TreeCapability,
    now: u64,
    head: RepositoryAuthorityHeadId,
    query: &'a SourceBrowseQuery,
    path: Option<&'a TreePath>,
    budget: ReadBudget,
}

fn browse_at<A: GitHashAlgorithm>(
    base: &BaseView<A>,
    original: &NodeTreeSource<'_>,
    mut params: BrowseParams<'_>,
) -> Result<SourceBrowseReport, NodeWorkspaceRefusal> {
    live(params.request)?;
    let source = BoundedSource {
        inner: original,
        request: params.request,
        budget: params.budget,
    };
    let result = (|| {
        let entry = match params.path {
            Some(path) => base
                .resolve(&source, params.capability, path, params.now)
                .map_err(base_error)?,
            None => BaseEntry::Directory {
                oid: *base.base_tree_oid(),
            },
        };
        let object_id = oid::<A>(entry.oid(), original.inner.object_format)?;
        let content = match &params.query.action {
            SourceBrowseAction::List { after, limit } => {
                let mut entries = base
                    .list(&source, params.capability, params.path, params.now)
                    .map_err(base_error)?;
                if entries.len() > MAX_ENTRIES {
                    return Err(error(SourceBrowseError::Budget("directory entries")));
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                let mut rows = Vec::with_capacity(usize::from(*limit));
                let mut next_after = None;
                for (name, entry) in entries {
                    live(params.request)?;
                    if after.as_ref().is_some_and(|cursor| name <= *cursor) {
                        continue;
                    }
                    if rows.len() == usize::from(*limit) {
                        next_after = rows
                            .last()
                            .map(|row: &SourceDirectoryEntry| row.name.clone());
                        break;
                    }
                    rows.push(SourceDirectoryEntry {
                        name,
                        oid: oid::<A>(entry.oid(), original.inner.object_format)?,
                        kind: kind(&entry)?,
                    });
                }
                SourceBrowseContent::Directory {
                    entries: rows,
                    next_after,
                }
            }
            SourceBrowseAction::Read { offset, limit } => {
                let entry_kind = kind(&entry)?;
                if !matches!(
                    entry_kind,
                    SourceEntryKind::File | SourceEntryKind::Executable | SourceEntryKind::Symlink
                ) {
                    return Err(error(SourceBrowseError::ExpectedFile));
                }
                let path = params
                    .path
                    .ok_or_else(|| error(SourceBrowseError::ExpectedFile))?;
                let grant = params
                    .capability
                    .authorize_read(path, params.now)
                    .map_err(|e| base_error(e.into()))?;
                let body = base
                    .read_object(&source, entry.oid(), GitObjectKind::Blob, &grant)
                    .map_err(NodeWorkspaceRefusal::Object)?;
                params
                    .capability
                    .charge_fetch(body.len() as u64)
                    .map_err(|e| base_error(e.into()))?;
                let start = usize::try_from(*offset)
                    .ok()
                    .filter(|start| *start <= body.len())
                    .ok_or_else(|| error(SourceBrowseError::RangeOutsideFile))?;
                let end = start.saturating_add(*limit as usize).min(body.len());
                SourceBrowseContent::Blob {
                    kind: entry_kind,
                    bytes: body[start..end].to_vec(),
                    total_bytes: body.len() as u64,
                    offset: *offset,
                    next_offset: (end < body.len()).then_some(end as u64),
                }
            }
        };
        Ok(SourceBrowseReport {
            repository_id: base.repository_id(),
            source_head: params.head,
            source_rcr: base.base_rcr_id(),
            source_commit: oid::<A>(base.base_commit_oid(), original.inner.object_format)?,
            root_tree: oid::<A>(base.base_tree_oid(), original.inner.object_format)?,
            object_id,
            path: params.query.path.clone(),
            content,
        })
    })();
    live(params.request)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_and_traversal_share_the_object_allowance() {
        let budget = ReadBudget::new(91, 2);
        for _ in 2..MAX_READ_OBJECTS {
            assert_eq!(budget.reserve().unwrap(), MAX_OBJECT_BYTES);
            budget.charge(0).unwrap();
        }
        assert!(budget.reserve().is_err());
        assert_eq!(budget.objects.get(), MAX_READ_OBJECTS);
        assert_eq!(budget.bytes.get(), 91);
        assert!(ReadBudget::new(0, u64::MAX).reserve().is_err());
    }
    #[test]
    fn remaining_total_bounds_decode_before_the_next_read() {
        let budget = ReadBudget::new(MAX_READ_BYTES - 7, 1);
        assert_eq!(budget.reserve().unwrap(), 7);
        assert!(budget.charge(8).is_err());
        assert_eq!(budget.bytes.get(), MAX_READ_BYTES - 7);
        budget.charge(7).unwrap();
        assert_eq!(budget.reserve().unwrap(), 0);
        budget.charge(0).unwrap();
        assert!(budget.charge(1).is_err());
        assert!(ReadBudget::new(u64::MAX, 1).reserve().is_err());
        assert_eq!(ReadBudget::new(0, 0).reserve().unwrap(), MAX_OBJECT_BYTES);
    }
}
