//! Self-owned thread preferences and a disposable, exact-source sqlmodel inbox.
use super::{issues::snapshots, native_merge::NodeNativeMergeProjection};
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use fgit_admission::merge::native::{notifications, objects::MergeObjectLimits};
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::event::notification::{
    NotificationCommand, NotificationMode, NotificationTarget, NotificationTargetKind,
};
use fgit_forge::{AggregateVersion, IssueNumber};
use fgit_projection::inbox::{
    InboxError, InboxKind, InboxQuery, InboxReason, InboxRow, InboxSession, InboxSnapshot,
    InboxSnapshotBinding,
};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{PrincipalId, RefusalCode, RepositoryAuthorityHeadId, TxId};
use std::collections::BTreeMap;
use std::num::NonZeroU16;

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
            kind: match kind {
                NotificationTargetKind::Issue => InboxKind::Issue,
                NotificationTargetKind::Discussion => InboxKind::Discussion,
                NotificationTargetKind::PullRequest => InboxKind::PullRequest,
            },
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
            // Filter both refs with CURRENT canonical policy before installing
            // the derived projection or disclosing title, activity or reasons.
            if thread
                .subject
                .pull_request_refs()
                .is_some_and(|(source, target)| {
                    current.hidden_refs.hides(source.as_bytes())
                        || current.hidden_refs.hides(target.as_bytes())
                })
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
        let rows = threads
            .values()
            .filter(|t| !t.reasons.is_empty() || t.mode == NotificationMode::Muted)
            .map(NotificationThreadView::row)
            .collect();
        let cx = request
            .authority()
            .attached_native_cx()
            .ok_or(NotificationReadRefusal::MissingRuntime)?;
        let mut projection =
            InboxSession::open_memory().map_err(NotificationReadRefusal::projection)?;
        let result = async {
            projection
                .install_snapshot(&cx, InboxSnapshot { binding, rows })
                .await
                .map_err(NotificationReadRefusal::projection)?;
            let page = projection
                .read_page(
                    &cx,
                    &binding,
                    InboxQuery {
                        after_thread: (after != 0).then_some(after),
                        limit: NonZeroU16::new(limit)
                            .ok_or(NotificationReadRefusal::InvalidLimit)?,
                        unread_only,
                        include_muted,
                    },
                )
                .await
                .map_err(NotificationReadRefusal::projection)?;
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
            })
        }
        .await;
        let close = projection.close(&cx).await;
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
