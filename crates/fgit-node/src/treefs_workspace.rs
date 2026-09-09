//! Authority-selected TreeFS input discovery over the production object fabric.

mod candidate;
mod merge_prepare;
mod native_merge;
mod outbox_delivery;
mod publication;
mod session_state;
mod sessions;
mod source_search;
pub use session_state::WorkspaceSessionRefusal;
pub use sessions::{MergeWorkspaceReceipt, WorkspaceShutdownBlocked};
pub(crate) use sessions::NodeWorkspaceSessions;
#[cfg(target_os = "linux")]
mod trusted_tool;

use crate::{
    AdmissionMaterializationRefusal, AuthoritySelectedClosure, ClosureSelectionSource,
    NodeRequestContext, OneNode, PackContextCheckpoint, VerifiedFabricPackSource,
    checkpoint_pack_context,
};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParsedObject, parse_object_body};
use fgit_runtime::Exhaustion;
use fgit_treefs::{
    BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant, SparseLimits, SparseManifest,
    SparseRefusal, TreeCapability, WorkspaceId,
};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm as ObjectFormat, GitOid as AnyOid, RefName};
use fgit_wire::visibility::RefVisibility;
use std::cell::Cell;

/// An unavailable/hidden ref is intentionally one indistinguishable outcome.
#[derive(Debug)]
pub enum NodeWorkspaceRefusal {
    /// This workspace is currently owned by another edit/publication/recovery.
    WorkspaceBusy,
    /// The node's finite session or export capacity was exceeded.
    WorkspaceCapacity,
    /// The opaque handle is absent, belongs to another node, or was closed.
    WorkspaceHandleUnavailable,
    /// The authenticated principal does not own this local workspace.
    WorkspaceOwnerMismatch,
    /// A mutable session refused an edit or obligation transition.
    WorkspaceSession(WorkspaceSessionRefusal),
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    RefUnavailable,
    RepositoryMismatch,
    ObjectFormatMismatch,
    CommitRequired,
    Object(ObjectSourceError),
    Manifest(SparseRefusal),
    /// An immutable source search failed; this is not a no-match result.
    SourceSearch(Box<fgit_forge::source_search::SearchError>),
    Cancelled {
        exhaustion: Option<Exhaustion>,
    },
    /// The current ref no longer names the commit the edits were based on.
    StaleWorkspaceBase,
    /// A requested file operation is not supported by this export profile.
    UnsupportedWorkspaceEdit,
    /// The edit log exceeds the caller's declared construction envelope.
    WorkspaceEditLimit,
    /// A filtered listing would omit siblings from a rebuilt directory.
    /// No undisclosed path is included in this refusal.
    IncompleteWorkspaceExportScope,
    /// The existing deterministic export engine refused the candidate.
    WorkspaceExport(fgit_treefs::ExportRefusal),
    /// Native merge construction refused its bounded inputs or source.
    MergePreparation(fgit_forge::preparation::PreparationError),
    /// The independently checked generated merge failed native validation.
    MergeValidation(fgit_admission::ProjectionFailure),
    /// Packing a fully validated in-memory merge candidate failed.
    MergePack(Box<fgit_pack::PackWriteError>),
    /// The untrusted candidate differs from its explicit review expectations
    /// or is outside the supported bounded single-parent bundle profile.
    InvalidWorkspaceCandidate(&'static str),
    /// Candidate verification could not read an immutable native object.
    WorkspaceCandidateRead(Box<crate::NodeRefusal>),
    /// The existing receive/admission boundary refused or could not complete.
    /// This preserves infrastructure ambiguity, not an assertion of non-commit.
    WorkspacePublication(Box<crate::NodeReceiveTransportRefusal>),
}
impl std::fmt::Display for NodeWorkspaceRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node workspace refused: {self:?}")
    }
}
impl std::error::Error for NodeWorkspaceRefusal {}

impl OneNode {
    /// Select a visible ref from authenticated current authority and derive its
    /// capability-visible TreeFS manifest using verified admitted objects.
    /// The caller supplies current disclosure policy from its authentication
    /// boundary. Neither policy nor a path capability can unhide a canonical
    /// hidden ref. No caller-computed RCR, commit, tree, or closure is accepted.
    ///
    /// This is a synchronous bounded object-read phase after asynchronous
    /// authority selection, like the node's selected-pack path. It retains
    /// object-fabric limits and checkpoints before/after reads. Returned source
    /// coordinates stay pinned even if a later transaction moves the ref.
    /// Commit discovery consumes the same shared capability fetch quota as
    /// tree and blob reads, before its body is parsed or traversal begins.
    pub async fn sparse_workspace_manifest_in<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        visibility: &RefVisibility,
        capability: &mut TreeCapability,
        now: u64,
        limits: SparseLimits,
    ) -> Result<SparseManifest<A>, NodeWorkspaceRefusal> {
        self.with_workspace_base_in(
            request,
            reference,
            visibility,
            capability,
            now,
            |base, source, capability| {
                SparseManifest::build(base, source, capability, now, limits)
                    .map_err(NodeWorkspaceRefusal::Manifest)
            },
        )
        .await
    }

    /// One shared authority-selection and verified-base boundary for workspace
    /// readers and exporters. The consumer runs synchronously while the exact
    /// selected closure and request-owned database context remain alive.
    async fn with_workspace_base_in<A: GitHashAlgorithm, T>(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        visibility: &RefVisibility,
        capability: &mut TreeCapability,
        now: u64,
        consume: impl FnOnce(
            &BaseView<A>,
            &NodeTreeSource<'_>,
            &mut TreeCapability,
        ) -> Result<T, NodeWorkspaceRefusal>
        + Send,
    ) -> Result<T, NodeWorkspaceRefusal> {
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if capability.repository_id() != self.repository_id() {
            return Err(NodeWorkspaceRefusal::RepositoryMismatch);
        }
        let width = match self.object_format {
            ObjectFormat::Sha1 => 20,
            ObjectFormat::Sha256 => 32,
        };
        if A::DIGEST_LEN != width {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        if visibility.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        capability
            .authorize_root(now)
            .map_err(|e| NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(e)))?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| NodeWorkspaceRefusal::Authority(Box::new(e)))?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let commit = selected
            .snapshot()
            .refs
            .get(reference)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
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
                maximum_object_bytes: usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX),
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected: selected.selected_closure(),
            workspace: capability.workspace_id(),
        };
        let built = (|| {
            let commit_oid = A::parse_hex(&commit.to_string())
                .map_err(|_| NodeWorkspaceRefusal::ObjectFormatMismatch)?;
            let grant = capability
                .authorize_root(now)
                .map_err(|e| NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(e)))?;
            let body = source
                .read_object::<A>(&commit_oid, GitObjectKind::Commit, &grant)
                .map_err(NodeWorkspaceRefusal::Object)?;
            capability
                .charge_fetch(body.len() as u64)
                .map_err(|e| NodeWorkspaceRefusal::Manifest(SparseRefusal::Capability(e)))?;
            let ParsedObject::Commit(parsed) = parse_object_body(
                ObjectType::Commit,
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &source.inner.parse_limits(),
            )
            .map_err(|_| NodeWorkspaceRefusal::CommitRequired)?
            else {
                return Err(NodeWorkspaceRefusal::CommitRequired);
            };
            let tree = parsed
                .tree_reference()
                .ok_or(NodeWorkspaceRefusal::CommitRequired)?;
            let tree =
                std::str::from_utf8(tree).map_err(|_| NodeWorkspaceRefusal::CommitRequired)?;
            let tree = A::parse_hex(tree).map_err(|_| NodeWorkspaceRefusal::CommitRequired)?;
            let base = BaseView::new(
                self.repository_id(),
                rcr,
                commit_oid,
                tree,
                source.inner.parse_limits(),
                PathPolicy::default(),
            );
            consume(&base, &source, capability)
        })();
        if let PackContextCheckpoint::Stopped { budget_exhaustion } =
            checkpoint_pack_context(request.authority())
        {
            return Err(NodeWorkspaceRefusal::Cancelled {
                exhaustion: budget_exhaustion.or(exhaustion.get()),
            });
        }
        built
    }
}

fn workspace_request_live(request: &NodeRequestContext) -> bool {
    !matches!(
        checkpoint_pack_context(request.authority()),
        PackContextCheckpoint::Stopped { .. }
    )
}

// This source is deliberately private. External callers cannot pair an
// arbitrary admitted OID with a grant for a different path: BaseView derives
// all requested identities while traversing the selected commit's tree.
struct NodeTreeSource<'a> {
    inner: VerifiedFabricPackSource<'a>,
    selected: &'a AuthoritySelectedClosure,
    workspace: WorkspaceId,
}
impl NodeTreeSource<'_> {
    fn read_object<A: GitHashAlgorithm>(
        &self,
        oid: &GitOid<A>,
        kind: GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        if grant.workspace_id() != self.workspace {
            return Err(refused("workspace grant mismatch"));
        }
        let hex: String = oid
            .digest_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let id = AnyOid::from_hex(self.inner.object_format, &hex)
            .map_err(|_| refused("object format mismatch"))?;
        if !self.selected.closure().objects().contains(&id) {
            return Err(refused("object is outside the authority-selected closure"));
        }
        let (actual, body) = self
            .inner
            .read_object(&id)
            .map_err(|e| refused(&e.to_string()))?;
        let expected = match kind {
            GitObjectKind::Blob => ObjectType::Blob,
            GitObjectKind::Tree => ObjectType::Tree,
            GitObjectKind::Commit => ObjectType::Commit,
            GitObjectKind::Tag => ObjectType::Tag,
        };
        if actual != expected {
            return Err(refused("object kind mismatch"));
        }
        Ok(body)
    }
}
impl<A: GitHashAlgorithm> ObjectSource<A> for NodeTreeSource<'_> {
    fn read_object(
        &self,
        oid: &GitOid<A>,
        kind: GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.read_object::<A>(oid, kind, grant)
    }
}
fn refused(reason: &str) -> ObjectSourceError {
    ObjectSourceError::Refused {
        reason: reason.to_owned(),
    }
}
