//! Request-owned, exact-source issue and discussion notification inboxes.
//!
//! Canonical thread histories and recipient-owned preferences remain outside
//! this crate. The host authenticates the recipient, reads one verified source
//! snapshot, derives the rows, and installs them here. SQLite is a disposable
//! read model: its complete marker binds the exact head, forge/outbox roots and
//! recipient, never a made-up sequence over delivery-sorted outbox entries.
//!
//! Installation publishes the typed SQLModel rows and complete marker in one
//! transaction. A page checks that marker and its rows in one transaction and
//! requires the host's selected, authenticated source binding. Completeness
//! means all rows at that selected head, not that the head remains latest.
//! The host checks current disclosure grants and any retained-snapshot policy;
//! an older head is never an authorization cache. Hosts hydrate display fields
//! from the same canonical source, matching issue number and version, and await
//! [`InboxSession::close`] on every completed request path.

use std::num::NonZeroU16;

use asupersync::Cx;
use fgit_types::{
    Digest, PrincipalId, RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId, TenantId,
};
use sqlmodel_core::{Connection, Model, TransactionOps};
use sqlmodel_frankensqlite::FrankenConnection;

use crate::session::{ProjectionError, flatten};

mod model;
mod store;
#[cfg(test)]
mod tests;

use model::{StoredInbox, StoredThread};

/// Maximum complete thread rows accepted from one bounded canonical source.
pub const MAX_INBOX_ROWS: usize = 16_384;
/// Maximum page size, matching the native forge HTTP profile.
pub const MAX_INBOX_PAGE_SIZE: u16 = 100;

/// A complete inbox covers one explicit thread namespace. Numbers are local to
/// that namespace; an issue, discussion and PR may have the same number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxKind {
    Issue,
    Discussion,
    PullRequest,
}
impl InboxKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Discussion => "discussion",
            Self::PullRequest => "pull_request",
        }
    }
}

/// Complete source and recipient identity. This is an observation supplied by
/// the authorized host, not a capability minted by the projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxSnapshotBinding {
    pub kind: InboxKind,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub authority_head: RepositoryAuthorityHeadId,
    pub authority_head_generation: u64,
    pub forge_position_root: Digest,
    pub outbox_root: Digest,
    pub principal: PrincipalId,
}

/// Independent reasons why the authenticated recipient follows this thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum InboxReason {
    Author,
    Participant,
    Assignee,
    Subscribed,
}

impl InboxReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Author => "author",
            Self::Participant => "participant",
            Self::Assignee => "assignee",
            Self::Subscribed => "subscribed",
        }
    }

    const fn bit(self) -> i64 {
        match self {
            Self::Author => 1,
            Self::Participant => 2,
            Self::Assignee => 4,
            Self::Subscribed => 8,
        }
    }
}

/// One thread, with the observed activity prefix and preference version kept
/// separately. Issues/discussions use their one aggregate version; PRs use the
/// canonical reader's chronological activity ordinal across independent
/// lifecycle, conversation and reviewer streams. Preferences create no activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxRow {
    pub thread_number: u64,
    pub thread_version: u64,
    pub preference_version: Option<u64>,
    pub read_through: Option<u64>,
    pub latest_other_version: Option<u64>,
    pub reasons: Vec<InboxReason>,
    pub muted: bool,
}

impl InboxRow {
    /// A recipient's own activity does not produce an unread notification.
    /// Clearing the read cursor makes previously seen activity unread again.
    #[must_use]
    pub fn unread(&self) -> bool {
        self.latest_other_version.unwrap_or(0) > self.read_through.unwrap_or(0)
    }

    fn normalize(&mut self) -> Result<(), InboxError> {
        checked_positive("thread_number", self.thread_number)?;
        checked_positive("thread_version", self.thread_version)?;
        if let Some(version) = self.preference_version {
            checked_positive("preference_version", version)?;
        }
        for (field, version) in [
            ("read_through", self.read_through),
            ("latest_other_version", self.latest_other_version),
        ] {
            if let Some(version) = version {
                checked_positive(field, version)?;
                if version > self.thread_version {
                    return Err(InboxRefusal::InvalidField(field).into());
                }
            }
        }
        self.reasons.sort_unstable();
        if self.reasons.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(InboxRefusal::InvalidField("duplicate_reason").into());
        }
        if self.reasons.is_empty() && !self.muted {
            return Err(InboxRefusal::InvalidField("unrelated_thread").into());
        }
        if self.muted && self.reasons.contains(&InboxReason::Subscribed) {
            return Err(InboxRefusal::InvalidField("muted_subscription").into());
        }
        if self.preference_version.is_none()
            && (self.read_through.is_some()
                || self.muted
                || self.reasons.contains(&InboxReason::Subscribed))
        {
            return Err(InboxRefusal::InvalidField("preference_version").into());
        }
        Ok(())
    }
}

/// A complete bounded generation, derived from one verified canonical source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxSnapshot {
    pub binding: InboxSnapshotBinding,
    pub rows: Vec<InboxRow>,
}

/// An issue-number cursor is stable within this exact source; it is not an
/// event sequence, freshness receipt, principal selector or capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxQuery {
    pub after_thread: Option<u64>,
    pub limit: NonZeroU16,
    pub unread_only: bool,
    pub include_muted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxPage {
    pub binding: InboxSnapshotBinding,
    pub rows: Vec<InboxRow>,
    /// Last returned issue when a further matching row exists.
    pub next_thread: Option<u64>,
}

/// Refusals carry field names and bounds, never another recipient's rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboxRefusal {
    InvalidField(&'static str),
    RowLimit { observed: usize, maximum: usize },
    PageLimit { observed: u16, maximum: u16 },
    DuplicateThread(u64),
    SourceMismatch,
    SnapshotConflict,
    SnapshotMissing,
    IncompleteSnapshot,
    CorruptRow,
}

impl std::fmt::Display for InboxRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField(field) => write!(out, "invalid inbox field: {field}"),
            Self::RowLimit { observed, maximum } => {
                write!(out, "inbox has {observed} rows; maximum is {maximum}")
            }
            Self::PageLimit { observed, maximum } => {
                write!(out, "inbox page size {observed} exceeds {maximum}")
            }
            Self::DuplicateThread(issue) => write!(out, "duplicate inbox thread {issue}"),
            Self::SourceMismatch => out.write_str("inbox source or recipient does not match"),
            Self::SnapshotConflict => {
                out.write_str("inbox source was already installed with different rows")
            }
            Self::SnapshotMissing => out.write_str("inbox snapshot is not installed"),
            Self::IncompleteSnapshot => out.write_str("inbox snapshot is incomplete"),
            Self::CorruptRow => out.write_str("inbox row violates its stored model"),
        }
    }
}

impl std::error::Error for InboxRefusal {}

/// Cleanup and commit uncertainty remain distinct from a failed operation.
#[derive(Debug)]
pub enum InboxError {
    Storage(ProjectionError),
    Refusal(InboxRefusal),
    CommitUncertain {
        failure: Box<ProjectionError>,
    },
    RollbackFailed {
        cause: Option<Box<Self>>,
        failure: Box<ProjectionError>,
    },
}

impl std::fmt::Display for InboxError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(out, "inbox storage: {error}"),
            Self::Refusal(error) => std::fmt::Display::fmt(error, out),
            Self::CommitUncertain { failure } => {
                write!(out, "inbox commit was not acknowledged: {failure}")
            }
            Self::RollbackFailed { cause, failure } => {
                write!(out, "inbox rollback failed: {failure}")?;
                if let Some(cause) = cause {
                    write!(out, "; operation: {cause}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for InboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Refusal(error) => Some(error),
            Self::CommitUncertain { failure } | Self::RollbackFailed { failure, .. } => {
                Some(failure.as_ref())
            }
        }
    }
}

impl From<ProjectionError> for InboxError {
    fn from(value: ProjectionError) -> Self {
        Self::Storage(value)
    }
}

impl From<InboxRefusal> for InboxError {
    fn from(value: InboxRefusal) -> Self {
        Self::Refusal(value)
    }
}

/// One owned SQLite connection and an exact source generation. No public raw
/// connection accessor permits a consumer to bypass the typed model boundary.
pub struct InboxSession<C: Connection = FrankenConnection> {
    connection: C,
    installed: Option<InboxSnapshotBinding>,
}

impl InboxSession<FrankenConnection> {
    pub fn open_memory() -> Result<Self, InboxError> {
        FrankenConnection::open_memory()
            .map(Self::new)
            .map_err(|error| ProjectionError::Sql(error).into())
    }
}

impl<C: Connection> InboxSession<C> {
    #[must_use]
    pub const fn new(connection: C) -> Self {
        Self {
            connection,
            installed: None,
        }
    }

    /// Install all rows and completeness metadata atomically. Identical replay
    /// is permitted; changed rows cannot reuse the same source generation.
    pub async fn install_snapshot(
        &mut self,
        cx: &Cx,
        mut snapshot: InboxSnapshot,
    ) -> Result<(), InboxError> {
        if snapshot.rows.len() > MAX_INBOX_ROWS {
            return Err(InboxRefusal::RowLimit {
                observed: snapshot.rows.len(),
                maximum: MAX_INBOX_ROWS,
            }
            .into());
        }
        if self
            .installed
            .is_some_and(|binding| binding != snapshot.binding)
        {
            return Err(InboxRefusal::SourceMismatch.into());
        }
        checked_counter(
            "authority_head_generation",
            snapshot.binding.authority_head_generation,
        )?;
        for row in &mut snapshot.rows {
            row.normalize()?;
        }
        snapshot.rows.sort_unstable_by_key(|row| row.thread_number);
        if let Some(pair) = snapshot
            .rows
            .windows(2)
            .find(|pair| pair[0].thread_number == pair[1].thread_number)
        {
            return Err(InboxRefusal::DuplicateThread(pair[0].thread_number).into());
        }
        let marker = StoredInbox::from_snapshot(&snapshot)?;
        let tx = flatten(self.connection.begin(cx).await, "inbox_begin_install")?;
        macro_rules! checked {
            ($result:expr) => {{
                match $result {
                    Ok(value) => value,
                    Err(error) => return Err(rollback(tx, cx, Some(error.into())).await),
                }
            }};
        }
        for statement in [
            store::create::<StoredInbox>(),
            store::create::<StoredThread>(),
        ] {
            checked!(flatten(
                tx.execute(cx, &statement, &[]).await,
                "inbox_install_model"
            ));
        }
        let held = checked!(flatten(
            tx.query_one(cx, &store::select_marker(), &[]).await,
            "inbox_read_install_marker"
        ));
        if let Some(held) = held {
            let held = checked!(StoredInbox::from_row(&held).map_err(ProjectionError::Sql));
            if !held.matches(&snapshot.binding) {
                return Err(rollback(tx, cx, Some(InboxRefusal::SourceMismatch.into())).await);
            }
            let stored = checked!(flatten(
                tx.query(cx, &store::all_threads(), &[]).await,
                "inbox_check_identical_replay"
            ));
            let observed = checked!(
                stored
                    .iter()
                    .map(StoredThread::from_row)
                    .collect::<sqlmodel_core::Result<Vec<_>>>()
                    .map_err(ProjectionError::Sql)
            );
            let offered = checked!(
                snapshot
                    .rows
                    .iter()
                    .map(StoredThread::from_input)
                    .collect::<Result<Vec<_>, _>>()
            );
            if held != marker || observed != offered {
                return Err(rollback(tx, cx, Some(InboxRefusal::SnapshotConflict.into())).await);
            }
            if let Err(failure) = flatten(tx.rollback(cx).await, "inbox_finish_identical_replay") {
                return Err(InboxError::RollbackFailed {
                    cause: None,
                    failure: Box::new(failure),
                });
            }
            self.installed = Some(snapshot.binding);
            return Ok(());
        }
        for statement in [
            store::delete::<StoredThread>(),
            store::delete::<StoredInbox>(),
        ] {
            checked!(flatten(
                tx.execute(cx, &statement, &[]).await,
                "inbox_replace_generation"
            ));
        }
        for row in &snapshot.rows {
            let row = checked!(StoredThread::from_input(row));
            let (statement, parameters) = store::insert(&row);
            checked!(flatten(
                tx.execute(cx, &statement, &parameters).await,
                "inbox_insert_thread"
            ));
        }
        let (statement, parameters) = store::insert(&marker);
        checked!(flatten(
            tx.execute(cx, &statement, &parameters).await,
            "inbox_install_complete"
        ));
        match flatten(tx.commit(cx).await, "inbox_commit_install") {
            Ok(()) => {
                self.installed = Some(snapshot.binding);
                Ok(())
            }
            Err(failure) => Err(InboxError::CommitUncertain {
                failure: Box::new(failure),
            }),
        }
    }

    /// Read a bounded page and its exact complete marker in one transaction.
    /// The host must independently authorize disclosure for this request and
    /// authenticate `expected` as the selected source. A retained page token
    /// alone proves neither current access nor permission to read old state.
    pub async fn read_page(
        &self,
        cx: &Cx,
        expected: &InboxSnapshotBinding,
        query: InboxQuery,
    ) -> Result<InboxPage, InboxError> {
        match self.installed {
            None => return Err(InboxRefusal::SnapshotMissing.into()),
            Some(binding) if &binding != expected => {
                return Err(InboxRefusal::SourceMismatch.into());
            }
            Some(_) => {}
        }
        if query.limit.get() > MAX_INBOX_PAGE_SIZE {
            return Err(InboxRefusal::PageLimit {
                observed: query.limit.get(),
                maximum: MAX_INBOX_PAGE_SIZE,
            }
            .into());
        }
        checked_counter("after_thread", query.after_thread.unwrap_or(0))?;
        let tx = flatten(self.connection.begin(cx).await, "inbox_begin_read")?;
        macro_rules! checked {
            ($result:expr) => {{
                match $result {
                    Ok(value) => value,
                    Err(error) => return Err(rollback(tx, cx, Some(error.into())).await),
                }
            }};
        }
        let marker = checked!(flatten(
            tx.query_one(cx, &store::select_marker(), &[]).await,
            "inbox_read_complete"
        ));
        let marker = checked!(marker.ok_or(InboxRefusal::SnapshotMissing));
        let marker = checked!(StoredInbox::from_row(&marker).map_err(ProjectionError::Sql));
        if !marker.matches(expected) {
            return Err(rollback(tx, cx, Some(InboxRefusal::SourceMismatch.into())).await);
        }
        let count = checked!(flatten(
            tx.query_one(cx, &store::count::<StoredThread>(), &[]).await,
            "inbox_check_row_count"
        ));
        let count = checked!(model::read_count(count.as_ref()));
        if marker.complete != 1
            || count != marker.row_count
            || !(0..=MAX_INBOX_ROWS as i64).contains(&count)
        {
            return Err(rollback(tx, cx, Some(InboxRefusal::IncompleteSnapshot.into())).await);
        }
        let (statement, parameters) = store::page(query);
        let stored = checked!(flatten(
            tx.query(cx, &statement, &parameters).await,
            "inbox_read_threads"
        ));
        if stored.len() > usize::from(query.limit.get()) + 1 {
            return Err(rollback(tx, cx, Some(InboxRefusal::CorruptRow.into())).await);
        }
        let mut rows = Vec::with_capacity(stored.len());
        let mut last = query.after_thread.unwrap_or(0);
        for row in &stored {
            let row = checked!(StoredThread::from_row(row).map_err(ProjectionError::Sql));
            let row = checked!(row.into_output());
            if row.thread_number <= last
                || (!query.include_muted && row.muted)
                || (query.unread_only && !row.unread())
            {
                return Err(rollback(tx, cx, Some(InboxRefusal::CorruptRow.into())).await);
            }
            last = row.thread_number;
            rows.push(row);
        }
        let has_more = rows.len() > usize::from(query.limit.get());
        if has_more {
            rows.pop();
        }
        let next_thread = if has_more {
            rows.last().map(|row| row.thread_number)
        } else {
            None
        };
        // A read transaction is explicitly rolled back: it has no writes to
        // publish. Even a failed finalizer prevents returning the page.
        if let Err(failure) = flatten(tx.rollback(cx).await, "inbox_finish_read") {
            return Err(InboxError::RollbackFailed {
                cause: None,
                failure: Box::new(failure),
            });
        }
        Ok(InboxPage {
            binding: *expected,
            rows,
            next_thread,
        })
    }

    /// Await the driver's explicit worker shutdown. Failure is preserved;
    /// dropping this session is not evidence that its worker drained.
    pub async fn close(self, cx: &Cx) -> Result<(), InboxError> {
        self.connection
            .close(cx)
            .await
            .map_err(|error| ProjectionError::Sql(error).into())
    }
}

async fn rollback<T: TransactionOps>(tx: T, cx: &Cx, cause: Option<InboxError>) -> InboxError {
    match flatten(tx.rollback(cx).await, "inbox_rollback") {
        Ok(()) => cause.unwrap_or_else(|| InboxRefusal::IncompleteSnapshot.into()),
        Err(failure) => InboxError::RollbackFailed {
            cause: cause.map(Box::new),
            failure: Box::new(failure),
        },
    }
}

fn checked_counter(field: &'static str, value: u64) -> Result<i64, InboxError> {
    i64::try_from(value).map_err(|_| {
        ProjectionError::OutOfRange {
            field,
            value,
            maximum: i64::MAX as u64,
        }
        .into()
    })
}

fn checked_positive(field: &'static str, value: u64) -> Result<i64, InboxError> {
    if value == 0 {
        return Err(InboxRefusal::InvalidField(field).into());
    }
    checked_counter(field, value)
}
