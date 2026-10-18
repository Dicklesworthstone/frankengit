#![forbid(unsafe_code)]
//! Bounded, resumable integrity inventories over authenticated native membership.
//!
//! A cursor selects a suffix, not evidence about an earlier page. Even the last
//! resumed page cannot certify the whole repository. This interface does not
//! enumerate physical residue, repair objects, verify graph connectivity, or
//! change authority. Its caller must authorize trusted-local whole-repository
//! inspection, including hidden references and admitted historical objects.

use std::fmt;
use std::ops::Bound::{Excluded, Unbounded};
use std::time::{Duration, Instant};

use super::{GraphAuditRefusal, checkpoint, revalidate_head};
use crate::{NodeRefusal, NodeRequestContext, OneNode};
use fgit_object_fabric::ObjectKind;
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{
    Digest, GitOid, HeadGeneration, RepositoryAuthorityHeadId, RepositoryId,
    RepositoryIncarnationId,
};

const MAX_SELECTED_OBJECTS: usize = 1_000_000;
const MAX_PAGE_OBJECTS: usize = 100_000;
const MAX_FINDINGS: usize = 1_000;
const MAX_PAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// An untrusted continuation hint. The node checks the exact head and membership
/// before using it; it never accepts prior-page counts or health claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrubCursor {
    head: RepositoryAuthorityHeadId,
    after: GitOid,
}
impl ScrubCursor {
    #[must_use]
    pub const fn new(head: RepositoryAuthorityHeadId, after: GitOid) -> Self {
        Self { head, after }
    }
    #[must_use]
    pub const fn head(self) -> RepositoryAuthorityHeadId {
        self.head
    }
    #[must_use]
    pub const fn after(self) -> GitOid {
        self.after
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ScrubQuery {
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_generation: Option<HeadGeneration>,
    pub cursor: Option<ScrubCursor>,
    pub max_selected_objects: usize,
    pub max_page_objects: usize,
    pub max_findings: usize,
    /// Accounted, verified payload bytes in this page, not physical I/O. One
    /// additional node-bounded object may be read to detect a page boundary.
    pub max_payload_bytes: u64,
    /// Cooperative timeout; a blocking filesystem call is not interruptible.
    pub timeout: Duration,
}
impl Default for ScrubQuery {
    fn default() -> Self {
        Self {
            expected_head: None,
            expected_generation: None,
            cursor: None,
            max_selected_objects: MAX_SELECTED_OBJECTS,
            max_page_objects: 1_000,
            max_findings: 100,
            max_payload_bytes: 64 * 1024 * 1024,
            timeout: Duration::from_secs(300),
        }
    }
}
impl ScrubQuery {
    fn validate(self) -> Result<(), ScrubRefusal> {
        if self.max_selected_objects == 0 || self.max_selected_objects > MAX_SELECTED_OBJECTS {
            return Err(ScrubRefusal::InvalidLimit("max-selected-objects"));
        }
        if self.max_page_objects == 0
            || self.max_page_objects > MAX_PAGE_OBJECTS
            || self.max_page_objects > self.max_selected_objects
        {
            return Err(ScrubRefusal::InvalidLimit("max-page-objects"));
        }
        if self.max_findings == 0 || self.max_findings > MAX_FINDINGS || self.max_findings > self.max_page_objects {
            return Err(ScrubRefusal::InvalidLimit("max-findings"));
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > MAX_PAGE_BYTES {
            return Err(ScrubRefusal::InvalidLimit("max-bytes"));
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(3600) {
            return Err(ScrubRefusal::Audit(GraphAuditRefusal::InvalidTimeout));
        }
        if let (Some(head), Some(cursor)) = (self.expected_head, self.cursor)
            && head != cursor.head
        {
            return Err(ScrubRefusal::CursorHeadMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ScrubRefusal {
    InvalidLimit(&'static str),
    SelectionLimit { selected: usize, maximum: usize },
    CursorHeadMismatch,
    CursorNotSelected,
    ReferenceOutsideClosure(GitOid),
    ObjectFormat(GitOid),
    /// The next object cannot fit even on an otherwise empty page. Increase the
    /// page budget; do not classify a policy/resource ceiling as corruption.
    ObjectExceedsPage { oid: GitOid, payload_bytes: u64, maximum: u64 },
    Allocation,
    Audit(GraphAuditRefusal),
}
impl fmt::Display for ScrubRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => write!(out, "invalid_scrub_limit: {field}"),
            Self::SelectionLimit { selected, maximum } => {
                write!(out, "scrub_selection_limit: {selected} exceeds {maximum}")
            }
            Self::CursorHeadMismatch => out.write_str("scrub_cursor_head_mismatch"),
            Self::CursorNotSelected => out.write_str("scrub_cursor_not_in_selected_closure"),
            Self::ReferenceOutsideClosure(oid) => write!(out, "reference_outside_selected_closure: {oid}"),
            Self::ObjectFormat(oid) => write!(out, "object_format_mismatch: {oid}"),
            Self::ObjectExceedsPage { oid, payload_bytes, maximum } => {
                write!(out, "scrub_object_exceeds_page: {oid}: {payload_bytes} exceeds {maximum}")
            }
            Self::Allocation => out.write_str("scrub_finding_allocation_failed"),
            Self::Audit(cause) => fmt::Display::fmt(cause, out),
        }
    }
}
impl std::error::Error for ScrubRefusal {}
impl From<GraphAuditRefusal> for ScrubRefusal {
    fn from(cause: GraphAuditRefusal) -> Self {
        Self::Audit(cause)
    }
}

/// Unverifiable is deliberately not synonymous with corrupt: a filesystem
/// permission error or a configured per-object ceiling is also a read refusal.
#[derive(Debug)]
pub enum ScrubFindingCause {
    ObjectRead(Box<NodeRefusal>),
    NonGitObject,
}
impl fmt::Display for ScrubFindingCause {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectRead(cause) => fmt::Display::fmt(cause, out),
            Self::NonGitObject => out.write_str("selected object has no native Git kind"),
        }
    }
}
#[derive(Debug)]
pub struct ScrubFinding {
    pub oid: GitOid,
    pub cause: ScrubFindingCause,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrubStop {
    SelectionExhausted,
    ObjectLimit,
    FindingLimit,
    PayloadLimit,
}

/// Private counters prevent callers constructing an apparent successful audit.
/// This remains an observation of bytes read, not a physical-corruption lock.
#[derive(Debug)]
pub struct SelectedObjectScrub {
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    head: RepositoryAuthorityHeadId,
    generation: HeadGeneration,
    closure_root: Digest,
    selected_objects: usize,
    start_after: Option<GitOid>,
    checked_objects: usize,
    verified_objects: usize,
    read_attempts: usize,
    payload_bytes: u64,
    findings: Vec<ScrubFinding>,
    next: Option<ScrubCursor>,
    stop: ScrubStop,
}
impl SelectedObjectScrub {
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId { self.repository }
    #[must_use]
    pub const fn repository_incarnation_id(&self) -> RepositoryIncarnationId { self.incarnation }
    #[must_use]
    pub const fn head(&self) -> RepositoryAuthorityHeadId { self.head }
    #[must_use]
    pub const fn generation(&self) -> HeadGeneration { self.generation }
    #[must_use]
    pub const fn closure_root(&self) -> Digest { self.closure_root }
    #[must_use]
    pub const fn selected_objects(&self) -> usize { self.selected_objects }
    #[must_use]
    pub const fn start_after(&self) -> Option<GitOid> { self.start_after }
    #[must_use]
    pub const fn checked_objects(&self) -> usize { self.checked_objects }
    #[must_use]
    pub const fn verified_objects(&self) -> usize { self.verified_objects }
    #[must_use]
    pub const fn read_attempts(&self) -> usize { self.read_attempts }
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 { self.payload_bytes }
    #[must_use]
    pub fn findings(&self) -> &[ScrubFinding] { &self.findings }
    #[must_use]
    pub const fn next_cursor(&self) -> Option<ScrubCursor> { self.next }
    #[must_use]
    pub const fn stop(&self) -> ScrubStop { self.stop }
    #[must_use]
    pub fn entire_selection_checked(&self) -> bool {
        self.start_after.is_none() && self.next.is_none()
    }
    #[must_use]
    pub fn entire_selection_verified(&self) -> bool {
        self.entire_selection_checked() && self.findings.is_empty()
    }
}

impl OneNode {
    /// Inspect a sorted page of selected Git objects using real fabric reads.
    /// All work, including final exact-head revalidation, belongs to `request`.
    /// Individual read failures become bounded findings; authority failures,
    /// cancellation and deadlines never become a partial-success receipt.
    pub async fn scrub_selected_objects_local_in(
        &self,
        request: &NodeRequestContext,
        query: ScrubQuery,
    ) -> Result<SelectedObjectScrub, ScrubRefusal> {
        query.validate()?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(GraphAuditRefusal::Cell)?;
        let started = Instant::now();
        checkpoint(request, started, query.timeout)?;
        let selected = self.materialize_admission_in(request).await;
        checkpoint(request, started, query.timeout)?;
        let selected = selected.map_err(|error| GraphAuditRefusal::Materialization(Box::new(error)))?;
        let head = selected.basis().id();
        let generation = selected.basis().generation();
        if let Some(expected) = query.expected_generation
            && expected != generation
        {
            return Err(GraphAuditRefusal::ExpectedGeneration {
                expected: expected.get(), observed: generation.get(),
            }.into());
        }
        if query.expected_head.is_some_and(|expected| expected != head) {
            return Err(GraphAuditRefusal::ExpectedHead.into());
        }
        if query.cursor.is_some_and(|cursor| cursor.head != head) {
            return Err(ScrubRefusal::CursorHeadMismatch);
        }
        let objects = selected.selected_closure().closure().objects();
        if objects.len() > query.max_selected_objects {
            return Err(ScrubRefusal::SelectionLimit {
                selected: objects.len(), maximum: query.max_selected_objects,
            });
        }
        let start_after = query.cursor.map(|cursor| cursor.after);
        if start_after.is_some_and(|oid| !objects.contains(&oid)) {
            return Err(ScrubRefusal::CursorNotSelected);
        }
        for oid in selected.snapshot().refs.values() {
            checkpoint(request, started, query.timeout)?;
            if !objects.contains(oid) {
                return Err(ScrubRefusal::ReferenceOutsideClosure(*oid));
            }
        }
        // Seek directly in the canonical BTreeSet instead of rescanning the
        // entire prefix on every page. No directory listing or derived index.
        let mut remaining = objects
            .range((start_after.map_or(Unbounded, Excluded), Unbounded))
            .copied()
            .peekable();
        let mut report = SelectedObjectScrub {
            repository: self.repository_id(),
            incarnation: self.repository_incarnation_id(),
            head, generation,
            closure_root: selected.selected_closure().root(),
            selected_objects: objects.len(),
            start_after,
            checked_objects: 0,
            verified_objects: 0,
            read_attempts: 0,
            payload_bytes: 0,
            findings: Vec::new(),
            next: None,
            stop: ScrubStop::SelectionExhausted,
        };
        let mut last = start_after;
        while let Some(&oid) = remaining.peek() {
            checkpoint(request, started, query.timeout)?;
            if report.checked_objects == query.max_page_objects {
                report.stop = ScrubStop::ObjectLimit;
                break;
            }
            if report.findings.len() == query.max_findings {
                report.stop = ScrubStop::FindingLimit;
                break;
            }
            if oid.algorithm() != self.object_format || oid.is_zero() {
                return Err(ScrubRefusal::ObjectFormat(oid));
            }
            let read = self.read_git_object(oid);
            report.read_attempts += 1;
            checkpoint(request, started, query.timeout)?;
            let finding = match read {
                Err(cause) => Some(ScrubFindingCause::ObjectRead(Box::new(cause))),
                Ok(object) => {
                    let size = object.payload().len() as u64;
                    if size > query.max_payload_bytes && report.checked_objects > 0 {
                        report.stop = ScrubStop::PayloadLimit;
                        break;
                    }
                    if size > query.max_payload_bytes {
                        return Err(ScrubRefusal::ObjectExceedsPage {
                            oid, payload_bytes: size, maximum: query.max_payload_bytes,
                        });
                    }
                    if size > query.max_payload_bytes - report.payload_bytes {
                        report.stop = ScrubStop::PayloadLimit;
                        break;
                    }
                    // Charge even a verified envelope with a non-Git kind.
                    report.payload_bytes += size;
                    if object.envelope().object_kind() == ObjectKind::Internal {
                        Some(ScrubFindingCause::NonGitObject)
                    } else {
                        report.verified_objects += 1;
                        None
                    }
                }
            };
            if let Some(cause) = finding {
                report.findings.try_reserve(1).map_err(|_| ScrubRefusal::Allocation)?;
                report.findings.push(ScrubFinding { oid, cause });
            }
            report.checked_objects += 1;
            last = Some(oid);
            remaining.next();
        }
        if remaining.peek().is_some() {
            // All stopping limits are positive. The only possible zero-progress
            // payload case returned ObjectExceedsPage above, never a loop cursor.
            report.next = Some(ScrubCursor::new(head, last.ok_or(ScrubRefusal::InvalidLimit("no progress"))?));
        }
        checkpoint(request, started, query.timeout)?;
        let current = self.authenticate_authority_head_in(request).await;
        checkpoint(request, started, query.timeout)?;
        let current = current.map_err(|cause| GraphAuditRefusal::Authority(Box::new(cause)))?;
        revalidate_head(selected.authenticated(), &current)?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
