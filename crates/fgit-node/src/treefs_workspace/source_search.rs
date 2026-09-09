//! Read-only source search at one authenticated selection. No index, seal,
//! object staging or authority mutation is performed by either entrypoint.

use std::cell::Cell;
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, Sha1, Sha256};
use fgit_forge::source_search::{SearchCompletion, SearchError, SearchLimits, SourceQuery,
    SourceSearchReport, search_source};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body, parse_tree};
use fgit_treefs::{BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant,
    TreeCapability, TreePath, WorkspaceId};
use fgit_types::{ByteCount, GitHashAlgorithm as Format, GitOid, RefName};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_wire::visibility::RefVisibility;
use crate::{ClosureSelectionSource, NodeRequestContext, OneNode, VerifiedFabricPackSource};
use super::{NodeTreeSource, NodeWorkspaceRefusal, workspace_request_live};

const READ_BYTES: usize = 128 * 1024 * 1024;
const READ_OBJECTS: usize = 100_000;
fn search_error(error: SearchError) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::SourceSearch(Box::new(error))
}

impl OneNode {
    /// Capability-scoped API for an already authenticated caller. Visibility
    /// can narrow the canonical ref policy, never widen it. The supplied grant
    /// and query both restrict paths. Source bytes and offsets remain pinned
    /// even if a concurrent writer subsequently advances the selected ref.
    pub async fn search_source_in<A: GitHashAlgorithm>(
        &self, request: &NodeRequestContext, reference: &RefName,
        visibility: &RefVisibility, capability: &mut TreeCapability, now: u64,
        query: &SourceQuery, limits: SearchLimits,
    ) -> Result<SourceSearchReport, NodeWorkspaceRefusal> {
        limits.validate().map_err(search_error)?;
        self.with_workspace_base_in::<A, _>(request, reference, visibility, capability, now,
            |base, original, capability| {
                let source = bounded_source(original, request, limits);
                search_source(base, &source, capability, now, query, limits,
                    &|| !workspace_request_live(request)).map_err(search_error)
            },
        ).await
    }

    /// Explicit trusted-local operator interface with whole-repository read
    /// authority. NOT an authenticated remote endpoint or a capability minting
    /// service. The operator grants this invocation read-only top-level scope
    /// from the SAME verified source tree; query paths only narrow its scan.
    /// SHA-1/SHA-256 dispatch is internal, without dependency changes for CLI.
    pub async fn search_source_local_in(
        &self, request: &NodeRequestContext, reference: &RefName,
        query: &SourceQuery, limits: SearchLimits,
    ) -> Result<SourceSearchReport, NodeWorkspaceRefusal> {
        match self.object_format {
            Format::Sha1 => self.search_local_format::<Sha1>(request, reference, query, limits).await,
            Format::Sha256 => self.search_local_format::<Sha256>(request, reference, query, limits).await,
        }
    }

    async fn search_local_format<A: GitHashAlgorithm>(
        &self, request: &NodeRequestContext, reference: &RefName,
        query: &SourceQuery, limits: SearchLimits,
    ) -> Result<SourceSearchReport, NodeWorkspaceRefusal> {
        limits.validate().map_err(search_error)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let commit = *selected.snapshot().refs.get(reference).ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest: rcr, .. } => rcr,
            ClosureSelectionSource::EmptyGenesis => return Err(NodeWorkspaceRefusal::RefUnavailable),
        };
        let exhaustion = Cell::new(None);
        let inner = VerifiedFabricPackSource {
            fabric: &self.fabric, object_format: self.object_format,
            maximum_object_bytes: usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)
                .min(limits.max_file_bytes),
            database_context: request.authority(), database_exhaustion: &exhaustion,
            session_is_live: None,
        };
        let parse = ParseLimits { tree_reference_bytes: self.object_format.digest_len(),
            max_object_bytes: inner.maximum_object_bytes, max_tree_entries: limits.max_entries,
            ..ParseLimits::default() };
        // Metadata discovery is authorized by the local operator, not by a
        // fabricated wildcard/root path. Neither object existence nor a query
        // parameter supplies authority to a remote caller.
        let read = |id: GitOid, expected: ObjectType| {
            if !workspace_request_live(request) { return Err(search_error(SearchError::Cancelled)); }
            if !selected.selected_closure().closure().objects().contains(&id) {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
            let result = inner.read_object(&id);
            if !workspace_request_live(request) { return Err(search_error(SearchError::Cancelled)); }
            let (kind, body) = result.map_err(|error| NodeWorkspaceRefusal::Object(ObjectSourceError::Refused { reason: format!("source metadata unavailable: {error}") }))?;
            if kind != expected { return Err(NodeWorkspaceRefusal::CommitRequired); }
            Ok(body)
        };
        let commit_body = read(commit, ObjectType::Commit)?;
        let ParsedObject::Commit(parsed) = parse_object_body(ObjectType::Commit, &commit_body,
            AcceptanceProfile::GitCompatibleImport, &parse).map_err(|_| NodeWorkspaceRefusal::CommitRequired)?
            else { return Err(NodeWorkspaceRefusal::CommitRequired); };
        let tree_hex = std::str::from_utf8(parsed.tree_reference().ok_or(NodeWorkspaceRefusal::CommitRequired)?)
            .map_err(|_| NodeWorkspaceRefusal::CommitRequired)?;
        let tree = GitOid::from_hex(self.object_format, &tree_hex.to_ascii_lowercase())
            .map_err(|_| NodeWorkspaceRefusal::CommitRequired)?;
        let tree_body = read(tree, ObjectType::Tree)?;
        let entries = parse_tree(&tree_body, AcceptanceProfile::GitCompatibleImport, &parse)
            .map_err(|_| search_error(SearchError::Budget("invalid root tree")))?;
        let prefixes: Vec<_> = entries.iter().map(|entry| TreePath::parse_default(&entry.name))
            .collect::<Result<_, _>>().map_err(|_| search_error(SearchError::InvalidQuery))?;
        if !workspace_request_live(request) { return Err(search_error(SearchError::Cancelled)); }
        if prefixes.is_empty() {
            return Ok(SourceSearchReport { repository: self.repository_id, source_rcr: rcr,
                source_commit: commit, source_tree: tree, matches: Vec::new(), completion: SearchCompletion::Complete,
                files_selected: 0, files_read: 0, bytes_read: 0, bytes_searched: 0, non_regular_entries: 0 });
        }
        let metadata_bytes = commit_body.len() + tree_body.len();
        let bytes = ByteCount::try_new("source_search_reads", (READ_BYTES - metadata_bytes) as u64, READ_BYTES as u64)
            .map_err(|_| search_error(SearchError::Budget("metadata bytes")))?;
        // This ID never leaves the read-only call or enters session storage.
        // It is a local grant namespace, not a resumable workspace capability.
        let workspace = WorkspaceId::from_bytes(*self.repository_id.as_bytes());
        let mut capability = TreeCapability::new(workspace, self.repository_id, prefixes, Vec::new())
            .with_fetch_budget(bytes).with_file_budget((READ_OBJECTS - 2) as u64);
        let commit_oid = A::parse_hex(&commit.to_string()).map_err(|_| search_error(SearchError::InvalidObjectFormat))?;
        let tree_oid = A::parse_hex(&tree.to_string()).map_err(|_| search_error(SearchError::InvalidObjectFormat))?;
        let base = BaseView::new(self.repository_id, rcr, commit_oid, tree_oid, parse, PathPolicy::default());
        let original = NodeTreeSource { inner, selected: selected.selected_closure(), workspace };
        let source = bounded_source(&original, request, limits);
        let result = search_source(&base, &source, &mut capability, 0, query, limits,
            &|| !workspace_request_live(request)).map_err(search_error);
        if !workspace_request_live(request) { return Err(search_error(SearchError::Cancelled)); }
        result
    }
}

struct SearchSource<'a, 'source> {
    source: &'a NodeTreeSource<'source>,
    request: &'a NodeRequestContext,
    bytes: Cell<usize>,
    objects: Cell<usize>,
    max_bytes: usize,
}
fn bounded_source<'a, 'source>(
    source: &'a NodeTreeSource<'source>, request: &'a NodeRequestContext, limits: SearchLimits,
) -> SearchSource<'a, 'source> {
    SearchSource { source, request, bytes: Cell::new(0), objects: Cell::new(0),
        max_bytes: limits.max_file_bytes }
}
impl<A: GitHashAlgorithm> ObjectSource<A> for SearchSource<'_, '_> {
    fn read_object(&self, id: &fgit_crypto::GitOid<A>, kind: GitObjectKind, grant: &ReadGrant)
        -> Result<Vec<u8>, ObjectSourceError>
    {
        let refused = |reason: &str| ObjectSourceError::Refused { reason: reason.to_owned() };
        if !workspace_request_live(self.request) { return Err(refused("search cancelled")); }
        if self.objects.get() == READ_OBJECTS || self.bytes.get() >= READ_BYTES {
            return Err(refused("search object-read budget exceeded"));
        }
        // Bound the actual fabric read before allocation; a post-read file
        // check alone would still allow an arbitrarily large rejected blob.
        let original = self.source;
        let bounded = NodeTreeSource {
            inner: VerifiedFabricPackSource {
                fabric: original.inner.fabric, object_format: original.inner.object_format,
                maximum_object_bytes: original.inner.maximum_object_bytes.min(self.max_bytes),
                database_context: original.inner.database_context,
                database_exhaustion: original.inner.database_exhaustion,
                session_is_live: original.inner.session_is_live,
            },
            selected: original.selected, workspace: original.workspace,
        };
        let body = bounded.read_object::<A>(id, kind, grant)?;
        if !workspace_request_live(self.request) { return Err(refused("search cancelled")); }
        let total = self.bytes.get().checked_add(body.len()).filter(|n| *n <= READ_BYTES)
            .ok_or_else(|| refused("search object-read byte budget exceeded"))?;
        self.bytes.set(total);
        self.objects.set(self.objects.get()+1);
        Ok(body)
    }
}

#[cfg(test)]
mod tests;
