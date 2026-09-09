//! Node-owned, process-local TreeFS sessions with publication recovery.
//!
//! A caller owns an opaque handle, never the mutable session. Its admission
//! future holds one exclusive guard from the pending marker through terminal
//! reconciliation. Drop leaves the marker in this node; subsequent operations
//! must drain the same database worker before the workspace can change.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use asupersync::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use fgit_admission::merge::SealedMerge;
use fgit_admission::merge::native::{
    admit_workspace_sealed_native_merge_async, objects::MergeObjectLimits,
    workspace_seal_attempt_for,
};
use fgit_admission::{AdmissionContext, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::ObjectType;
use fgit_treefs::{EpochSet, ExportLimits, IntentLog, TreeCapability, TreeEditIntent, WorkspaceId};
use fgit_types::{GitHashAlgorithm as Format, GitOid, PrincipalId, RefName, RepositoryCommitId};
use fgit_wire::visibility::RefVisibility;

use super::native_merge::NodeNativeMergeProjection;
use super::session_state::SessionState;
use super::{NodeWorkspaceRefusal, candidate, workspace_request_live};
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};

const MAX_SESSIONS: usize = 16;
const MAX_EXPORT_BYTES: usize = 32 * 1024 * 1024;
const MAX_EXPORT_OBJECTS: usize = 16_384;

/// Immutable observation of a node-owned workspace. Cloning it does not clone
/// the mutable anti-rollback record. The private token also binds the handle
/// to this open session: equal snapshot bytes cannot revive a closed handle.
#[derive(Clone, Debug)]
pub struct MergeWorkspaceReceipt {
    workspace_id: WorkspaceId,
    token: Arc<()>,
    snapshot_digest: [u8; 32],
    epochs: EpochSet,
    tree: GitOid,
    base_commit: GitOid,
    base_rcr: RepositoryCommitId,
}

/// Shutdown could not drain a workspace. The failure retains the complete
/// node, including its database worker and pending lease, for explicit retry.
/// Discarding this owner without recovery is not a successful shutdown.
pub struct WorkspaceShutdownBlocked {
    node: OneNode,
    cause: NodeWorkspaceRefusal,
}

impl WorkspaceShutdownBlocked {
    pub(crate) fn new(node: OneNode, cause: NodeWorkspaceRefusal) -> Self {
        Self { node, cause }
    }
    pub const fn cause(&self) -> &NodeWorkspaceRefusal {
        &self.cause
    }
    pub fn into_parts(self) -> (OneNode, NodeWorkspaceRefusal) {
        (self.node, self.cause)
    }
}

impl std::fmt::Debug for WorkspaceShutdownBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceShutdownBlocked")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

impl MergeWorkspaceReceipt {
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }
    pub const fn epochs(&self) -> EpochSet {
        self.epochs
    }
    pub const fn tree(&self) -> GitOid {
        self.tree
    }
    pub const fn base_commit(&self) -> GitOid {
        self.base_commit
    }
    pub const fn base_rcr(&self) -> RepositoryCommitId {
        self.base_rcr
    }
}

#[derive(Clone)]
enum Session {
    Sha1(Arc<AsyncMutex<SessionState<Sha1>>>),
    Sha256(Arc<AsyncMutex<SessionState<Sha256>>>),
}

#[derive(Clone)]
struct Entry {
    token: Arc<()>,
    principal: PrincipalId,
    reference: RefName,
    visibility: RefVisibility,
    clock_floor: Arc<AtomicU64>,
    session: Session,
}

#[derive(Default)]
struct Slots {
    opening: BTreeSet<WorkspaceId>,
    live: BTreeMap<WorkspaceId, Entry>,
}

#[derive(Default)]
pub(crate) struct NodeWorkspaceSessions {
    slots: Mutex<Slots>,
}

/// An opening slot owns no database publication or workspace lease. Dropping
/// selection releases only this bounded admission slot, never a live session.
struct Opening<'a> {
    owner: &'a NodeWorkspaceSessions,
    workspace_id: WorkspaceId,
}

impl Drop for Opening<'_> {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.owner.slots.lock() {
            slots.opening.remove(&self.workspace_id);
        }
    }
}

impl NodeWorkspaceSessions {
    fn reserve(&self, workspace_id: WorkspaceId) -> Result<Opening<'_>, NodeWorkspaceRefusal> {
        let mut slots = self.slots.lock().map_err(|_| unavailable())?;
        if slots.live.contains_key(&workspace_id) || slots.opening.contains(&workspace_id) {
            return Err(NodeWorkspaceRefusal::WorkspaceBusy);
        }
        if slots.live.len() + slots.opening.len() >= MAX_SESSIONS {
            return Err(NodeWorkspaceRefusal::WorkspaceCapacity);
        }
        slots.opening.insert(workspace_id);
        Ok(Opening {
            owner: self,
            workspace_id,
        })
    }

    fn lookup(
        &self,
        receipt: &MergeWorkspaceReceipt,
        principal: PrincipalId,
    ) -> Result<Entry, NodeWorkspaceRefusal> {
        let slots = self.slots.lock().map_err(|_| unavailable())?;
        let entry = slots
            .live
            .get(&receipt.workspace_id)
            .ok_or_else(unavailable)?;
        if !Arc::ptr_eq(&entry.token, &receipt.token) {
            return Err(unavailable());
        }
        if entry.principal != principal {
            return Err(NodeWorkspaceRefusal::WorkspaceOwnerMismatch);
        }
        Ok(entry.clone())
    }
}

fn unavailable() -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::WorkspaceHandleUnavailable
}
fn state_error(error: super::WorkspaceSessionRefusal) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::WorkspaceSession(error)
}
fn authority_error(error: crate::NodeRefusal) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::WorkspaceCandidateRead(Box::new(error))
}
fn admission_error(error: fgit_admission::AdmissionError) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::WorkspacePublication(Box::new(NodeReceiveTransportRefusal::Admission(
        Box::new(error),
    )))
}
fn principal(session: &LoopbackReceiveSession) -> Result<PrincipalId, NodeWorkspaceRefusal> {
    session
        .authenticated_session()
        .map(|s| s.principal_id())
        .ok_or_else(|| {
            NodeWorkspaceRefusal::WorkspacePublication(Box::new(
                NodeReceiveTransportRefusal::Unauthenticated,
            ))
        })
}

fn take<A: GitHashAlgorithm>(
    entry: &Arc<AsyncMutex<SessionState<A>>>,
    request: &NodeRequestContext,
) -> Result<OwnedMutexGuard<SessionState<A>>, NodeWorkspaceRefusal> {
    if !workspace_request_live(request) {
        return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
    }
    entry.try_lock_owned().map_err(|error| match error {
        asupersync::sync::TryLockError::Locked => NodeWorkspaceRefusal::WorkspaceBusy,
        _ => unavailable(),
    })
}

fn receipt<A: GitHashAlgorithm>(
    state: &SessionState<A>,
    token: &Arc<()>,
) -> Result<MergeWorkspaceReceipt, NodeWorkspaceRefusal> {
    let snapshot = state.snapshot();
    Ok(MergeWorkspaceReceipt {
        workspace_id: snapshot.workspace_id(),
        token: Arc::clone(token),
        snapshot_digest: snapshot.snapshot_digest().map_err(|_| unavailable())?,
        epochs: snapshot.epochs(),
        tree: (*state.tree()).erase(),
        base_commit: (*snapshot.base_commit_oid()).erase(),
        base_rcr: snapshot.base_rcr_id(),
    })
}

impl OneNode {
    /// Open one bounded process-local mutable workspace from an authenticated
    /// current branch. The node retains its capability, overlay and lease.
    /// Up to sixteen sessions may be open; each admits at most 32 MiB of edits
    /// and 16,384 objects. No session journal durability is claimed (epoch 0).
    pub async fn open_merge_workspace_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        reference: &RefName,
        visibility: &RefVisibility,
        mut capability: TreeCapability,
        now: u64,
        limits: ExportLimits,
    ) -> Result<MergeWorkspaceReceipt, NodeWorkspaceRefusal> {
        let owner = principal(session)?;
        let now = now.max(self.runtime.now().as_nanos());
        if limits.max_objects == 0
            || limits.max_objects > MAX_EXPORT_OBJECTS
            || limits.max_total_bytes == 0
            || limits.max_total_bytes > MAX_EXPORT_BYTES
            || limits.max_tree_entries == 0
            || limits.max_tree_entries > MAX_EXPORT_OBJECTS
        {
            return Err(NodeWorkspaceRefusal::WorkspaceCapacity);
        }
        let id = capability.workspace_id();
        let opening = self.workspaces.reserve(id)?;
        // Selection finishes before constructing a lease, so a dropped await
        // cannot leave a newly reserved workspace outside node ownership.
        let token = Arc::new(());
        let (session, observed) = match self.object_format {
            Format::Sha1 => {
                let base = self
                    .with_workspace_base_in::<Sha1, _>(
                        request,
                        reference,
                        visibility,
                        &mut capability,
                        now,
                        |base, _, _| Ok(base.clone()),
                    )
                    .await?;
                let state = SessionState::new(base, capability, limits).map_err(state_error)?;
                let observed = receipt(&state, &token)?;
                (Session::Sha1(Arc::new(AsyncMutex::new(state))), observed)
            }
            Format::Sha256 => {
                let base = self
                    .with_workspace_base_in::<Sha256, _>(
                        request,
                        reference,
                        visibility,
                        &mut capability,
                        now,
                        |base, _, _| Ok(base.clone()),
                    )
                    .await?;
                let state = SessionState::new(base, capability, limits).map_err(state_error)?;
                let observed = receipt(&state, &token)?;
                (Session::Sha256(Arc::new(AsyncMutex::new(state))), observed)
            }
        };
        self.workspaces
            .slots
            .lock()
            .map_err(|_| unavailable())?
            .live
            .insert(
                id,
                Entry {
                    token,
                    principal: owner,
                    reference: reference.clone(),
                    visibility: visibility.clone(),
                    clock_floor: Arc::new(AtomicU64::new(now)),
                    session,
                },
            );
        drop(opening);
        Ok(observed)
    }

    /// Append ordinary file intents and export the same evaluated overlay that
    /// the session adopts. The expected receipt must still name this snapshot.
    pub async fn edit_merge_workspace_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        expected: &MergeWorkspaceReceipt,
        append: &IntentLog,
        now: u64,
    ) -> Result<MergeWorkspaceReceipt, NodeWorkspaceRefusal> {
        let entry = self.workspaces.lookup(expected, principal(session)?)?;
        match &entry.session {
            Session::Sha1(state) => {
                self.edit_workspace(request, &entry, state, expected, append, now)
                    .await
            }
            Session::Sha256(state) => {
                self.edit_workspace(request, &entry, state, expected, append, now)
                    .await
            }
        }
    }

    async fn edit_workspace<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        entry: &Entry,
        owner: &Arc<AsyncMutex<SessionState<A>>>,
        expected: &MergeWorkspaceReceipt,
        append: &IntentLog,
        now: u64,
    ) -> Result<MergeWorkspaceReceipt, NodeWorkspaceRefusal> {
        let mut state = take(owner, request)?;
        self.recover_workspace(request, &mut state).await?;
        let now = now.max(self.runtime.now().as_nanos());
        let now = now.max(entry.clock_floor.fetch_max(now, Ordering::Relaxed));
        if state.is_closed() {
            return Err(state_error(super::WorkspaceSessionRefusal::Closed));
        }
        if state.is_retired() {
            return Err(state_error(super::WorkspaceSessionRefusal::Retired));
        }
        if state
            .snapshot()
            .snapshot_digest()
            .map_err(|_| unavailable())?
            != expected.snapshot_digest
        {
            return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
        }
        let limits = state.limits();
        candidate::validate_log(append, state.capability(), now, limits)?;
        if state
            .log()
            .len()
            .checked_add(append.len())
            .is_none_or(|n| n > limits.max_objects)
        {
            return Err(NodeWorkspaceRefusal::WorkspaceEditLimit);
        }
        let mut bytes = 0usize;
        for intent in state.log().intents().iter().chain(append.intents()) {
            if let TreeEditIntent::Write { content, .. } = intent {
                bytes = bytes
                    .checked_add(content.len())
                    .filter(|n| *n <= limits.max_total_bytes)
                    .ok_or(NodeWorkspaceRefusal::WorkspaceEditLimit)?;
            }
        }
        let mut log = state.log().clone();
        for intent in append.intents() {
            log.push(intent.clone());
        }
        let base = state.base().clone();
        let expected_commit = (*base.base_commit_oid()).erase();
        let (export, overlay) = self
            .with_workspace_base_in(
                request,
                &entry.reference,
                &entry.visibility,
                state.capability_mut(),
                now,
                |current: &fgit_treefs::BaseView<A>, source, cap| {
                    if current.base_commit_oid() != base.base_commit_oid() {
                        return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
                    }
                    candidate::export_owned_from_base(
                        &base,
                        source,
                        cap,
                        &log,
                        expected_commit,
                        now,
                        limits,
                        &|| !workspace_request_live(request),
                    )
                },
            )
            .await?;
        for object in export.plan.objects() {
            if !workspace_request_live(request) {
                return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
            }
            let kind = match object.kind() {
                GitObjectKind::Blob => ObjectType::Blob,
                GitObjectKind::Tree => ObjectType::Tree,
                GitObjectKind::Commit => ObjectType::Commit,
                GitObjectKind::Tag => ObjectType::Tag,
            };
            self.put_git_object(kind, object.body().to_vec())
                .map_err(authority_error)?;
        }
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        state
            .adopt(log, overlay, export.plan)
            .map_err(state_error)?;
        receipt(&state, &entry.token)
    }

    /// Admit an explicitly workspace-bound original merge package. The new
    /// scoped precondition is opt-in; callers derive its supplied evidence
    /// using workspace_seal_attempt_for. Old seal profiles remain unchanged.
    pub async fn admit_workspace_merge_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        expected: &MergeWorkspaceReceipt,
        sealed: &SealedMerge<'_>,
        limits: AdmissionLimits,
        object_limits: MergeObjectLimits,
    ) -> Result<TerminalOutcome, NodeWorkspaceRefusal> {
        let authenticated = session.authenticated_session().ok_or_else(|| {
            NodeWorkspaceRefusal::WorkspacePublication(Box::new(
                NodeReceiveTransportRefusal::Unauthenticated,
            ))
        })?;
        let entry = self
            .workspaces
            .lookup(expected, authenticated.principal_id())?;
        self.push_quota
            .evaluate(&authenticated.principal_id())
            .map_err(|e| NodeWorkspaceRefusal::WorkspacePublication(Box::new(e.into())))?;
        self.receive_publication_admitted()
            .map_err(|e| NodeWorkspaceRefusal::WorkspacePublication(Box::new(e)))?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        match &entry.session {
            Session::Sha1(state) => {
                self.admit_workspace(
                    request,
                    &entry,
                    state,
                    expected,
                    sealed,
                    &context,
                    limits,
                    object_limits,
                )
                .await
            }
            Session::Sha256(state) => {
                self.admit_workspace(
                    request,
                    &entry,
                    state,
                    expected,
                    sealed,
                    &context,
                    limits,
                    object_limits,
                )
                .await
            }
        }
    }

    async fn admit_workspace<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        entry: &Entry,
        owner: &Arc<AsyncMutex<SessionState<A>>>,
        expected: &MergeWorkspaceReceipt,
        sealed: &SealedMerge<'_>,
        context: &AdmissionContext,
        limits: AdmissionLimits,
        object_limits: MergeObjectLimits,
    ) -> Result<TerminalOutcome, NodeWorkspaceRefusal> {
        let mut state = take(owner, request)?;
        self.recover_workspace(request, &mut state).await?;
        let observed = state
            .snapshot()
            .snapshot_digest()
            .map_err(|_| unavailable())?;
        let actual_epoch = state.snapshot().epochs().visible();
        let held = SealedMerge {
            package: sealed.package,
            attempt: sealed.attempt,
            closure: sealed.closure,
            evidence: sealed.evidence,
            workspace_epoch_now: actual_epoch,
        };
        let attempt = workspace_seal_attempt_for(context, &held, expected.snapshot_digest)
            .map_err(admission_error)?;
        let (tx_id, _) = attempt.derive().map_err(|e| admission_error(e.into()))?;
        // Terminal retry precedes current workspace/ref checks, including when
        // this workspace's own earlier merge has retired its edit lease.
        if state.is_retired() {
            if let OutcomeLookup::Decided(outcome) = self
                .resolve_outcome_in(request, tx_id)
                .await
                .map_err(authority_error)?
            {
                return Ok(outcome);
            }
            return Err(state_error(super::WorkspaceSessionRefusal::Retired));
        }
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self
                .durable_admission_projection(context)
                .map_err(admission_error)?,
            object_limits,
            workspace: Some((
                observed,
                (*state.tree()).erase(),
                (*state.base().base_commit_oid()).erase(),
            )),
            workspace_capability: Some(state.capability().clone()),
            workspace_clock_floor: entry.clock_floor.load(Ordering::Relaxed),
        };
        state.begin_publication(attempt).map_err(state_error)?;
        let outcome = admit_workspace_sealed_native_merge_async(
            &self.authority,
            request.authority(),
            context,
            &held,
            expected.snapshot_digest,
            limits,
            &projection,
        )
        .await;
        match outcome {
            Ok(outcome) => {
                state
                    .reconcile_publication(tx_id, Some(&outcome))
                    .map_err(state_error)?;
                Ok(outcome)
            }
            Err(error) => {
                // Preserve pending across any ambiguous/cancelled result.
                // Recovery is explicit under a later live finite context.
                Err(admission_error(error))
            }
        }
    }

    async fn recover_workspace<A: GitHashAlgorithm>(
        &self,
        request: &NodeRequestContext,
        state: &mut SessionState<A>,
    ) -> Result<(), NodeWorkspaceRefusal> {
        if let Some(pending) = state.pending() {
            let tx_id = pending.tx_id;
            // This SAME store's operation gate drains abandoned queued SQL
            // before returning an authenticated outcome. The session guard
            // also proves the original admission future cannot still resume.
            let lookup = self
                .resolve_outcome_in(request, tx_id)
                .await
                .map_err(authority_error)?;
            let outcome = match &lookup {
                OutcomeLookup::Decided(outcome) => Some(outcome),
                OutcomeLookup::Undecided => None,
            };
            state
                .reconcile_publication(tx_id, outcome)
                .map_err(state_error)?;
        }
        Ok(())
    }

    /// Drain any abandoned publication before settling/removing this session.
    /// A busy or unresolved session stays owned by the node on refusal.
    pub async fn close_merge_workspace_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        expected: &MergeWorkspaceReceipt,
    ) -> Result<(), NodeWorkspaceRefusal> {
        let entry = self.workspaces.lookup(expected, principal(session)?)?;
        self.close_workspace_entry(request, &entry).await?;
        let mut slots = self.workspaces.slots.lock().map_err(|_| unavailable())?;
        if slots
            .live
            .get(&expected.workspace_id)
            .is_some_and(|e| Arc::ptr_eq(&e.token, &entry.token))
        {
            slots.live.remove(&expected.workspace_id);
        }
        Ok(())
    }

    async fn close_workspace_entry(
        &self,
        request: &NodeRequestContext,
        entry: &Entry,
    ) -> Result<(), NodeWorkspaceRefusal> {
        match &entry.session {
            Session::Sha1(owner) => {
                let mut state = take(owner, request)?;
                self.recover_workspace(request, &mut state).await?;
                state.close().map_err(state_error)?;
            }
            Session::Sha256(owner) => {
                let mut state = take(owner, request)?;
                self.recover_workspace(request, &mut state).await?;
                state.close().map_err(state_error)?;
            }
        }
        Ok(())
    }

    pub(crate) async fn drain_merge_workspaces_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<(), NodeWorkspaceRefusal> {
        let entries: Vec<_> = self
            .workspaces
            .slots
            .lock()
            .map_err(|_| unavailable())?
            .live
            .iter()
            .map(|(id, entry)| (*id, entry.clone()))
            .collect();
        for (id, entry) in &entries {
            self.close_workspace_entry(request, entry).await?;
            self.workspaces
                .slots
                .lock()
                .map_err(|_| unavailable())?
                .live
                .remove(id);
        }
        Ok(())
    }
}
