//! Self-owned thread preferences and a durable, watermarked exact-source sqlmodel inbox.
use super::{issues::snapshots, native_merge::NodeNativeMergeProjection};
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use asupersync::sync::{LockError, Mutex as AsyncMutex, OwnedMutexGuard};
use fgit_admission::merge::native::{notifications, objects::MergeObjectLimits};
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_crypto::{DigestHasher, Sha256Hasher, lowercase_hex};
use fgit_forge::event::notification::{
    NotificationCommand, NotificationMode, NotificationTarget, NotificationTargetKind,
};
use fgit_forge::{AggregateVersion, IssueNumber};
pub use fgit_projection::inbox::InboxSyncOutcome;
use fgit_projection::inbox::{
    InboxError, InboxKind, InboxPage, InboxQuery, InboxReason, InboxRefusal, InboxRow,
    InboxSession, InboxSnapshot, InboxSnapshotBinding,
};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{PrincipalId, RefusalCode, RepositoryAuthorityHeadId, TxId};
use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationThreadState {
    Open,
    Closed,
    Merged,
}
#[derive(Clone, Debug)]
pub struct NotificationThreadView {
    pub target: NotificationTarget,
    pub thread_version: AggregateVersion,
    pub title: String,
    pub state: NotificationThreadState,
    pub preference_version: Option<AggregateVersion>,
    pub mode: NotificationMode,
    pub read_through: Option<AggregateVersion>,
    pub latest_other_version: Option<AggregateVersion>,
    pub reasons: Vec<InboxReason>,
    pub unread: bool,
}
impl NotificationThreadView {
    fn from_source(thread: notifications::NotificationThread, principal: PrincipalId) -> Self {
        let mode = thread
            .preference
            .as_ref()
            .map_or(NotificationMode::Participating, |p| p.mode);
        let mut reasons = Vec::new();
        if thread.subject.opened_by() == principal {
            reasons.push(InboxReason::Author);
        }
        if thread.participated {
            reasons.push(InboxReason::Participant);
        }
        if thread.subject.assigned_to(principal) {
            reasons.push(InboxReason::Assignee);
        }
        if mode == NotificationMode::Subscribed {
            reasons.push(InboxReason::Subscribed);
        }
        let read_through = thread.preference.as_ref().and_then(|p| p.read_through);
        Self {
            target: thread.subject.target(),
            thread_version: thread.subject.version(),
            title: thread.subject.title().to_owned(),
            state: if thread.subject.is_merged() {
                NotificationThreadState::Merged
            } else if thread.subject.is_closed() {
                NotificationThreadState::Closed
            } else {
                NotificationThreadState::Open
            },
            preference_version: thread.preference.as_ref().map(|p| p.version),
            mode,
            read_through,
            latest_other_version: thread.latest_other_version,
            reasons,
            unread: thread.latest_other_version.map_or(0, AggregateVersion::get)
                > read_through.map_or(0, AggregateVersion::get),
        }
    }
    fn row(&self) -> InboxRow {
        InboxRow {
            thread_number: self.target.number(),
            thread_version: self.thread_version.get(),
            preference_version: self.preference_version.map(AggregateVersion::get),
            read_through: self.read_through.map(AggregateVersion::get),
            latest_other_version: self.latest_other_version.map(AggregateVersion::get),
            reasons: self.reasons.clone(),
            muted: self.mode == NotificationMode::Muted,
        }
    }
}
#[derive(Clone, Debug)]
pub struct NotificationInboxPage {
    pub kind: NotificationTargetKind,
    pub binding: InboxSnapshotBinding,
    pub threads: Vec<NotificationThreadView>,
    pub next_after: Option<u64>,
    pub sync_outcome: Option<InboxSyncOutcome>,
}

const fn inbox_kind_for(kind: NotificationTargetKind) -> InboxKind {
    match kind {
        NotificationTargetKind::Issue => InboxKind::Issue,
        NotificationTargetKind::Discussion => InboxKind::Discussion,
        NotificationTargetKind::PullRequest => InboxKind::PullRequest,
    }
}

// Holders and queued requests own the mutex. The registry only makes a live
// mutex discoverable by another node handle opening the same projection.
pub(super) struct ProjectionPath(Arc<Path>);

type FileGate = AsyncMutex<ProjectionPath>;
static PROJECTION_GATES: Mutex<BTreeMap<Arc<Path>, Weak<FileGate>>> = Mutex::new(BTreeMap::new());

impl Drop for ProjectionPath {
    fn drop(&mut self) {
        let mut gates = PROJECTION_GATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A new reader may already have replaced our expired weak reference.
        // Only retire an expired entry while holding the lookup lock.
        if gates
            .get(&self.0)
            .is_some_and(|gate| gate.strong_count() == 0)
        {
            gates.remove(&self.0);
        }
    }
}

pub(super) fn projection_file_gate(path: &Path) -> Arc<FileGate> {
    let mut gates = PROJECTION_GATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(gate) = gates.get(path).and_then(Weak::upgrade) {
        return gate;
    }
    let path = Arc::<Path>::from(path);
    let gate = Arc::new(AsyncMutex::new(ProjectionPath(Arc::clone(&path))));
    gates.insert(path, Arc::downgrade(&gate));
    gate
}

#[cfg(test)]
pub(super) fn projection_gate_count_under(root: &Path) -> usize {
    let root = root.canonicalize().unwrap();
    PROJECTION_GATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .keys()
        .filter(|path| path.starts_with(&root))
        .count()
}

fn prepare_projection_path(path: &Path) -> Result<PathBuf, NotificationReadRefusal> {
    let parent = path
        .parent()
        .ok_or(NotificationReadRefusal::InvalidProjection)?;
    let file = path
        .file_name()
        .ok_or(NotificationReadRefusal::InvalidProjection)?;
    std::fs::create_dir_all(parent).map_err(|_| NotificationReadRefusal::InvalidProjection)?;
    // Different configured storage roots can resolve to the same directory.
    // The projection itself can be absent on first use or during a rebuild.
    let directory = parent
        .canonicalize()
        .map_err(|_| NotificationReadRefusal::InvalidProjection)?;
    Ok(directory.join(file))
}

async fn lock_projection_file(
    path: &Path,
    request: &NodeRequestContext,
    native: &asupersync::Cx,
) -> Result<OwnedMutexGuard<ProjectionPath>, NotificationReadRefusal> {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let lock = OwnedMutexGuard::lock(projection_file_gate(path), native);
    let mut lock = std::pin::pin!(lock);
    let mut cancel = std::pin::pin!(request.authority().wait_for_local_cancel_request());
    let result = poll_fn(|task| {
        // A parked mutex waiter otherwise wakes only when the holder unlocks.
        if cancel.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(LockError::Cancelled));
        }
        lock.as_mut().poll(task)
    })
    .await;
    result.map_err(|error| match error {
        LockError::Cancelled => NotificationReadRefusal::projection(InboxError::Storage(
            fgit_projection::ProjectionError::Interrupted("inbox_acquire_projection_gate"),
        )),
        _ => NotificationReadRefusal::InvalidProjection,
    })
}

fn has_valid_sqlite_header_or_empty(path: &Path) -> bool {
    const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
    let Ok(mut file) = std::fs::File::open(path) else {
        return !path.exists();
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    if metadata.len() == 0 {
        return true;
    }
    if metadata.len() < SQLITE_HEADER.len() as u64 {
        return false;
    }
    let mut header = [0_u8; SQLITE_HEADER.len()];
    std::io::Read::read_exact(&mut file, &mut header).is_ok() && &header == SQLITE_HEADER
}

fn remove_projection_files(path: &Path) {
    let base = path.as_os_str();
    let _ = std::fs::remove_file(path);
    for suffix in [
        "-wal", "-shm", "-journal", ".wal", ".shm", ".journal", ".lock",
    ] {
        let mut sidecar = base.to_os_string();
        sidecar.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(sidecar));
    }
    if let (Some(parent), Some(stem)) = (path.parent(), path.file_name())
        && let Ok(entries) = std::fs::read_dir(parent)
    {
        let prefix = stem.as_encoded_bytes();
        for entry in entries.flatten() {
            if entry.file_name().as_encoded_bytes().starts_with(prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

fn is_recoverable_projection_error(error: &InboxError) -> bool {
    match error {
        InboxError::Storage(
            fgit_projection::ProjectionError::Cancelled { .. }
            | fgit_projection::ProjectionError::Panicked { .. }
            | fgit_projection::ProjectionError::Interrupted(_)
            | fgit_projection::ProjectionError::OutOfRange { .. },
        )
        | InboxError::Refusal(
            InboxRefusal::InvalidField(_)
            | InboxRefusal::RowLimit { .. }
            | InboxRefusal::PageLimit { .. }
            | InboxRefusal::DuplicateThread(_),
        ) => false,
        InboxError::Storage(_)
        | InboxError::Refusal(_)
        | InboxError::CommitUncertain { .. }
        | InboxError::RollbackFailed { .. } => true,
    }
}

fn is_recoverable_projection_refusal(refusal: &NotificationReadRefusal) -> bool {
    match refusal {
        NotificationReadRefusal::Projection(error) => is_recoverable_projection_error(error),
        NotificationReadRefusal::ProjectionCleanup { cause, cleanup } => {
            is_recoverable_projection_refusal(cause) || is_recoverable_projection_error(cleanup)
        }
        _ => false,
    }
}

async fn run_inbox_projection_once(
    cx: &asupersync::Cx,
    projection_path: &Path,
    snapshot: InboxSnapshot,
    query: InboxQuery,
) -> Result<(InboxSyncOutcome, InboxPage), NotificationReadRefusal> {
    if !has_valid_sqlite_header_or_empty(projection_path) {
        remove_projection_files(projection_path);
    }
    let expected = snapshot.binding;
    let mut projection =
        InboxSession::open_file(projection_path).map_err(NotificationReadRefusal::projection)?;
    let result = async {
        let outcome = projection
            .sync_snapshot(cx, snapshot)
            .await
            .map_err(NotificationReadRefusal::projection)?;
        let page = projection
            .read_page(cx, &expected, query)
            .await
            .map_err(NotificationReadRefusal::projection)?;
        Ok((outcome, page))
    }
    .await;
    let close = projection.close(cx).await;
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(NotificationReadRefusal::projection(error)),
        (Err(cause), Err(cleanup)) => Err(NotificationReadRefusal::ProjectionCleanup {
            cause: Box::new(cause),
            cleanup: Box::new(cleanup),
        }),
    }
}
impl OneNode {
    /// Publish only the authenticated principal's own preferences, using the
    /// ordinary immutable seal, exact version and authority-head CAS.
    pub async fn admit_notification_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &NotificationCommand,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let error = |source| NodeReceiveTransportRefusal::Admission(Box::new(source));
        let (_, attempt) = notifications::proposal(&context, command).map_err(error)?;
        let tx = attempt
            .derive()
            .map_err(|_| {
                error(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        if let OutcomeLookup::Decided(terminal) = self
            .resolve_outcome_checkpointed_in(request, tx)
            .await
            .map_err(|source| error(source.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|source| error(source.into()))?;
            return Ok((tx, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self
                .durable_admission_projection(&context)
                .map_err(error)?
                .with_authentication(authenticated.authentication()),
            object_limits: MergeObjectLimits::default(),
            staging: None,
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = Box::pin(notifications::admit_notification_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        ))
        .await
        .map_err(error)?;
        Ok((tx, terminal))
    }
    async fn notification_source_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        kind: NotificationTargetKind,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<
        (InboxSnapshotBinding, BTreeMap<u64, NotificationThreadView>),
        NotificationReadRefusal,
    > {
        let principal = session
            .authenticated_session()
            .ok_or(NotificationReadRefusal::Unauthenticated)?
            .principal_id();
        admits_read(self.cell_state(), ReadMode::Current).map_err(NotificationReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|source| NotificationReadRefusal::Selection(Box::new(source)))?;
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            expected_head,
            &|| !super::workspace_request_live(request),
        )
        .await?;
        let source = notifications::read_source_for_kind_at(
            &self.authority,
            request.authority(),
            &selected,
            principal,
            kind,
            &|| !super::workspace_request_live(request),
        )
        .await
        .map_err(|source| NotificationReadRefusal::Admission(Box::new(source)))?;
        if source.principal != principal || source.kind != kind {
            return Err(NotificationReadRefusal::InvalidProjection);
        }
        let binding = InboxSnapshotBinding {
            kind: inbox_kind_for(kind),
            tenant: self.tenant_id,
            repository: self.repository_id,
            incarnation: self.repository_incarnation_id,
            authority_head: source.source_head,
            authority_head_generation: source.source_generation,
            forge_position_root: source.forge_root,
            outbox_root: source.outbox_root,
            principal,
        };
        let mut threads = BTreeMap::new();
        for thread in source.threads {
            // A retained inbox snapshot never revives permission to see a PR.
            // Filter all current and historical refs with CURRENT policy before installing
            // the derived projection or disclosing title, activity or reasons.
            if !thread
                .subject
                .permits_disclosure(|reference| !current.hidden_refs.hides(reference.as_bytes()))
            {
                continue;
            }
            let view = NotificationThreadView::from_source(thread, principal);
            if view.target.kind() != kind || threads.insert(view.target.number(), view).is_some() {
                return Err(NotificationReadRefusal::InvalidProjection);
            }
        }
        Ok((binding, threads))
    }
    /// Legacy issue-only wrapper. Discussion reads select their own namespace
    /// explicitly and require their own current disclosure grants in adapters.
    pub async fn read_notification_inbox_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
        unread_only: bool,
        include_muted: bool,
    ) -> Result<NotificationInboxPage, NotificationReadRefusal> {
        self.read_notification_inbox_for_kind_in(
            request,
            session,
            NotificationTargetKind::Issue,
            after,
            limit,
            expected_head,
            unread_only,
            include_muted,
        )
        .await
    }
    /// Deterministic filesystem path for the disposable, watermarked per-recipient
    /// inbox projection under `<storage-root>/projections/inbox/`.
    #[must_use]
    pub fn notification_inbox_projection_path(
        &self,
        principal: PrincipalId,
        kind: NotificationTargetKind,
    ) -> PathBuf {
        let inbox_kind = inbox_kind_for(kind);
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"frankengit/node/notification-inbox-projection-file/v1\0");
        hasher.update(self.tenant_id.as_bytes());
        hasher.update(self.repository_id.as_bytes());
        hasher.update(self.repository_incarnation_id.as_bytes());
        hasher.update(principal.as_bytes());
        hasher.update(inbox_kind.name().as_bytes());
        let key_hex = lowercase_hex(&hasher.finish());
        self.storage_root
            .join("projections")
            .join("inbox")
            .join(format!("inbox-{key_hex}.sqlite"))
    }
    /// Remote adapters first check the selected kind's disclosure and service grants.
    /// The session supplies the recipient; page tokens only request retained
    /// ancestors in the current configuration, policy and retention epoch.
    pub async fn read_notification_inbox_for_kind_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        kind: NotificationTargetKind,
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
        unread_only: bool,
        include_muted: bool,
    ) -> Result<NotificationInboxPage, NotificationReadRefusal> {
        if limit == 0 || limit > 100 {
            return Err(NotificationReadRefusal::InvalidLimit);
        }
        if after != 0 && expected_head.is_none() {
            return Err(NotificationReadRefusal::SnapshotRequired);
        }
        let (binding, mut threads) = self
            .notification_source_in(request, session, kind, expected_head)
            .await?;
        let rows: Vec<InboxRow> = threads
            .values()
            .filter(|t| !t.reasons.is_empty() || t.mode == NotificationMode::Muted)
            .map(NotificationThreadView::row)
            .collect();
        let cx = request
            .authority()
            .attached_native_cx()
            .ok_or(NotificationReadRefusal::MissingRuntime)?;
        let query = InboxQuery {
            after_thread: (after != 0).then_some(after),
            limit: NonZeroU16::new(limit).ok_or(NotificationReadRefusal::InvalidLimit)?,
            unread_only,
            include_muted,
        };
        let projection_path = prepare_projection_path(
            &self.notification_inbox_projection_path(binding.principal, kind),
        )?;
        let _file_lease = lock_projection_file(&projection_path, request, &cx).await?;
        let snapshot = InboxSnapshot { binding, rows };
        let (sync_outcome, page) =
            match run_inbox_projection_once(&cx, &projection_path, snapshot.clone(), query).await {
                Ok(ok) => ok,
                Err(first_error)
                    if super::workspace_request_live(request)
                        && !cx.is_cancel_requested()
                        && is_recoverable_projection_refusal(&first_error) =>
                {
                    remove_projection_files(&projection_path);
                    run_inbox_projection_once(&cx, &projection_path, snapshot, query).await?
                }
                Err(error) => return Err(error),
            };
        let mut result = Vec::with_capacity(page.rows.len());
        for row in page.rows {
            let view = threads
                .remove(&row.thread_number)
                .ok_or(NotificationReadRefusal::InvalidProjection)?;
            // Display fields come only from this exact verified source.
            if view.row() != row {
                return Err(NotificationReadRefusal::InvalidProjection);
            }
            result.push(view);
        }
        Ok(NotificationInboxPage {
            kind,
            binding: page.binding,
            threads: result,
            next_after: page.next_thread,
            sync_outcome: Some(sync_outcome),
        })
    }
    /// Exact issue lookup, retained for existing callers.
    pub async fn read_notification_thread_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        number: IssueNumber,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<NotificationInboxPage, NotificationReadRefusal> {
        self.read_notification_target_in(
            request,
            session,
            NotificationTarget::Issue(number),
            expected_head,
        )
        .await
    }
    /// Exact target lookup includes implicit automatic preferences so a reader
    /// can subscribe to a thread not currently relevant to their inbox.
    pub async fn read_notification_target_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        target: NotificationTarget,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<NotificationInboxPage, NotificationReadRefusal> {
        let kind = target.kind();
        let (binding, mut threads) = self
            .notification_source_in(request, session, kind, expected_head)
            .await?;
        Ok(NotificationInboxPage {
            kind,
            binding,
            threads: threads.remove(&target.number()).into_iter().collect(),
            next_after: None,
            sync_outcome: None,
        })
    }
}
#[derive(Debug)]
pub enum NotificationReadRefusal {
    Unauthenticated,
    InvalidLimit,
    SnapshotRequired,
    SnapshotMoved,
    MissingRuntime,
    InvalidProjection,
    Cell(CellRefusal),
    Selection(Box<super::events::ForgeEventReadRefusal>),
    Admission(Box<AdmissionError>),
    Projection(Box<InboxError>),
    ProjectionCleanup {
        cause: Box<Self>,
        cleanup: Box<InboxError>,
    },
}
impl NotificationReadRefusal {
    fn projection(error: InboxError) -> Self {
        Self::Projection(Box::new(error))
    }
}
impl From<snapshots::SnapshotReadRefusal> for NotificationReadRefusal {
    fn from(error: snapshots::SnapshotReadRefusal) -> Self {
        match error {
            snapshots::SnapshotReadRefusal::Unavailable => Self::SnapshotMoved,
            snapshots::SnapshotReadRefusal::Admission(error) => Self::Admission(error),
        }
    }
}
impl std::fmt::Display for NotificationReadRefusal {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "native notification read refused: {self:?}")
    }
}
impl std::error::Error for NotificationReadRefusal {}
