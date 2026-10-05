//! Disclosure projection shared by HTTP and MCP. Neither cursors nor event
//! bytes confer permission. Callers supply independently authenticated grants.

use super::{ForgeEventCursor, ForgeEventPage, ForgeEventReadRefusal, feed, workspace_request_live};
use crate::{NodeRequestContext, OneNode};
use fgit_codec::encode_body;
use fgit_forge::event::ForgeEventPayload;
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent};
use fgit_types::{
    GitHashAlgorithm, PolicyEpoch, RepositoryAuthorityHeadId, RepositoryId,
    RepositoryIncarnationId, TenantId, TxId,
};

const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_PAGE_FRAME_BYTES: usize = 512 * 1024;
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;

/// One already-authorized canonical event. Private fields prevent fabrication
/// of a decoded event or unvalidated JSON fragment through this read surface.
#[derive(Clone, Debug)]
pub struct ScopedForgeEvent {
    cursor: (u64, u32),
    tx_id: TxId,
    policy_epoch: PolicyEpoch,
    aggregate: AggregateId,
    version: AggregateVersion,
    kind: u32,
    frame_hex: String,
}
impl ScopedForgeEvent {
    #[must_use]
    pub const fn cursor(&self) -> (u64, u32) { self.cursor }
    #[must_use]
    pub const fn tx_id(&self) -> TxId { self.tx_id }
    #[must_use]
    pub const fn policy_epoch(&self) -> PolicyEpoch { self.policy_epoch }
    #[must_use]
    pub const fn aggregate(&self) -> AggregateId { self.aggregate }
    #[must_use]
    pub const fn version(&self) -> AggregateVersion { self.version }
    #[must_use]
    pub const fn kind(&self) -> u32 { self.kind }
    #[must_use]
    pub fn frame_hex(&self) -> &str { &self.frame_hex }
}

/// A filtered page of one authenticated history, not a complete forge export.
/// Position gaps and the resume watermark reveal repository activity, but no
/// omitted event's kind, aggregate, actor, transaction, version or payload.
#[derive(Clone, Debug)]
pub struct ScopedForgeEventPage {
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    format: GitHashAlgorithm,
    source_head: RepositoryAuthorityHeadId,
    issues_read: bool,
    pulls_read: bool,
    events: Vec<ScopedForgeEvent>,
    next_after: Option<(u64, u32)>,
    resume_after: Option<(u64, u32)>,
}
impl ScopedForgeEventPage {
    #[must_use]
    pub const fn source_head(&self) -> RepositoryAuthorityHeadId { self.source_head }
    #[must_use]
    pub fn events(&self) -> &[ScopedForgeEvent] { &self.events }
    #[must_use]
    pub const fn next_after(&self) -> Option<(u64, u32)> { self.next_after }
    #[must_use]
    pub const fn resume_after(&self) -> Option<(u64, u32)> { self.resume_after }
    #[must_use]
    pub const fn issues_read(&self) -> bool { self.issues_read }
    #[must_use]
    pub const fn pulls_read(&self) -> bool { self.pulls_read }

    /// Bounded HTTP representation. MCP constructs its own Value tree directly
    /// from these same authorized fields; its hostile-input parser is not used
    /// to decode large trusted result frames or given larger request limits.
    pub fn to_json(&self) -> Result<String, ForgeEventReadRefusal> {
        let id = self.source_head.as_internal_object_id();
        let token = format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes())?);
        let mut out = format!(
            "{{\"type\":\"forge_event_page\",\"schema_version\":1,\"tenant_id\":\"{}\",\"repository_id\":\"{}\",\"repository_incarnation\":\"{}\",\"object_format\":\"{}\",\"source_head\":\"{}\",\"snapshot_token\":\"{}\",\"read_only\":true,\"disclosure_profile\":\"issues-pulls-v1\",\"issues_read\":{},\"pulls_read\":{},\"omits_other_event_families\":true,\"cursor_discloses_repository_activity\":true,\"events\":[",
            self.tenant, self.repository, self.incarnation, self.format.as_str(),
            self.source_head, token, self.issues_read, self.pulls_read,
        );
        for (index, event) in self.events.iter().enumerate() {
            let row = format!(
                "{}{{\"cursor\":\"{}:{}\",\"repository_sequence\":\"{}\",\"event_index\":\"{}\",\"tx_id\":\"{}\",\"policy_epoch\":\"{}\",\"aggregate\":\"{}\",\"aggregate_version\":\"{}\",\"kind\":{},\"event_frame_hex\":\"{}\"}}",
                if index == 0 { "" } else { "," }, event.cursor.0, event.cursor.1,
                event.cursor.0, event.cursor.1, event.tx_id, event.policy_epoch.get(),
                event.aggregate, event.version.get(), event.kind, event.frame_hex,
            );
            append(&mut out, &row)?;
        }
        append(&mut out, &format!(
            "],\"next_after\":{},\"resume_after\":{},\"has_more\":{},\"complete\":{}}}",
            cursor_json(self.next_after), cursor_json(self.resume_after),
            self.next_after.is_some(), self.next_after.is_none(),
        ))?;
        Ok(out)
    }
}

impl ForgeEventReadRefusal {
    /// Public refusals never disclose storage paths, hidden event coordinates,
    /// codec diagnostics or the details of a failed authority read.
    #[must_use]
    pub const fn public_code(&self) -> &'static str {
        match self {
            Self::InvalidLimit => "invalid_event_limit",
            Self::InvalidCursor => "invalid_event_cursor",
            Self::SnapshotMoved => "snapshot_moved",
            Self::NoReadScope => "events_not_granted",
            Self::ResponseLimit => "event_response_limit",
            Self::Cancelled => "event_read_cancelled",
            Self::InvalidPage | Self::Cell(_) | Self::Authority(_) | Self::Admission(_)
                | Self::Boundary(_) | Self::RepositoryBindingMismatch =>
                "event_read_unavailable",
        }
    }
}

impl OneNode {
    /// Parse the shared HTTP/MCP cursor without opening a node. `0` starts at
    /// the beginning; all other inputs are exact nonzero-sequence:u32-index.
    /// Decimal strings avoid lossy JSON number conversion for u64 positions.
    pub fn parse_forge_event_feed_cursor(
        text: &str,
    ) -> Result<Option<(u64, u32)>, ForgeEventReadRefusal> {
        if text == "0" { return Ok(None); }
        if text.len() > 31 { return Err(ForgeEventReadRefusal::InvalidCursor); }
        let (sequence, index) = text.split_once(':').ok_or(ForgeEventReadRefusal::InvalidCursor)?;
        let decimal = |value: &str| -> Result<u64, ForgeEventReadRefusal> {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err(ForgeEventReadRefusal::InvalidCursor);
            }
            value.parse().map_err(|_| ForgeEventReadRefusal::InvalidCursor)
        };
        let sequence = decimal(sequence)?;
        let index = u32::try_from(decimal(index)?).map_err(|_| ForgeEventReadRefusal::InvalidCursor)?;
        if sequence == 0 { return Err(ForgeEventReadRefusal::InvalidCursor); }
        Ok(Some((sequence, index)))
    }

    /// Read the granted issue/PR event families from ONE authenticated history.
    /// Grants MUST come from the caller's independent authentication boundary,
    /// never request fields. Source/receive/write grants do not imply either.
    /// `limit` bounds canonical events examined, not the number disclosed: an
    /// empty page can have `next_after`. Persist `resume_after` even at EOF.
    /// This reuses the existing bounded history replay; no O(limit) indexed
    /// lookup, long-poll, delivery acknowledgement or publication is claimed.
    pub async fn read_scoped_forge_events_in(
        &self,
        request: &NodeRequestContext,
        after: Option<(u64, u32)>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
        issues_read: bool,
        pulls_read: bool,
    ) -> Result<ScopedForgeEventPage, ForgeEventReadRefusal> {
        if !issues_read && !pulls_read { return Err(ForgeEventReadRefusal::NoReadScope); }
        if !(1..=100).contains(&limit) { return Err(ForgeEventReadRefusal::InvalidLimit); }
        let cursor = after.map(|(sequence, index)| ForgeEventCursor::new(sequence, index)
            .map_err(|_| ForgeEventReadRefusal::InvalidCursor)).transpose()?;
        let selected = self.event_read_basis_in(request, expected_head).await?;
        // Events and hidden-ref policy share ONE authenticated head, without
        // reconstructing source objects, refs, outbox or outcome projections.
        // A separate policy head read would introduce a disclosure TOCTOU race.
        let page = feed::read_page_at(
            &self.authority, request.authority(), &selected.basis, cursor, limit,
            &|| !workspace_request_live(request),
        ).await.map_err(|error| ForgeEventReadRefusal::Admission(Box::new(error)))?;
        let mut result = ScopedForgeEventPage {
            tenant: self.tenant_id,
            repository: self.repository_id,
            incarnation: self.repository_incarnation_id(),
            format: self.object_format,
            source_head: page.source_head,
            issues_read,
            pulls_read,
            events: Vec::new(),
            next_after: None,
            resume_after: after,
        };
        project(&mut result, page, after, limit,
            &|reference| selected.hidden_refs.hides(reference),
            &|| !workspace_request_live(request))?;
        Ok(result)
    }
}

fn permitted(
    event: &ForgeEvent,
    issues: bool,
    pulls: bool,
    hidden: &dyn Fn(&[u8]) -> bool,
) -> bool {
    use ForgeEventPayload as Payload;
    match (&event.payload, event.aggregate) {
        (Payload::IssueChangedNative(_), AggregateId::Issue(_)) => issues,
        (Payload::PullRequestChangedNative(change), AggregateId::PullRequest(_)) => {
            pulls && !hidden(change.data.source_ref.as_bytes())
                && !hidden(change.data.target_ref.as_bytes())
        }
        (Payload::MergeCommittedNative(merge), AggregateId::PullRequest(_)) => {
            pulls && !hidden(merge.source_ref.as_bytes()) && !hidden(merge.target_ref.as_bytes())
        }
        // Legacy events without full native coordinates cannot establish
        // current hidden-ref disclosure. Reviews have independent credentials.
        // These and protection/workflow/queue/future families are not implied.
        _ => false,
    }
}
fn stopped(cancelled: &dyn Fn() -> bool) -> Result<(), ForgeEventReadRefusal> {
    if cancelled() { Err(ForgeEventReadRefusal::Cancelled) } else { Ok(()) }
}
fn position(cursor: ForgeEventCursor) -> (u64, u32) {
    (cursor.repository_sequence, cursor.event_index)
}
fn project(
    result: &mut ScopedForgeEventPage,
    page: ForgeEventPage,
    after: Option<(u64, u32)>,
    limit: u16,
    hidden: &dyn Fn(&[u8]) -> bool,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), ForgeEventReadRefusal> {
    stopped(cancelled)?;
    if !(1..=100).contains(&limit) || page.events.len() > usize::from(limit)
        || page.source_head != result.source_head
        || page.events.windows(2).any(|p| p[0].cursor >= p[1].cursor)
        || page.events.iter().any(|e| e.cursor.repository_sequence == 0
            || after.is_some_and(|a| position(e.cursor) <= a))
        || page.next_after.is_some_and(|next| page.events.last().map(|e| e.cursor) != Some(next))
    {
        return Err(ForgeEventReadRefusal::InvalidPage);
    }
    let mut more = page.next_after.is_some();
    let mut bytes = 0usize;
    for envelope in page.events {
        stopped(cancelled)?;
        if permitted(&envelope.event, result.issues_read, result.pulls_read, hidden) {
            // Never encode, identify, format or return an unauthorized event.
            let frame = encode_body(&envelope.event).map_err(|_| ForgeEventReadRefusal::InvalidPage)?;
            if !charge_frame(&mut bytes, frame.len())? {
                // Do not advance past this event: it belongs to the next page.
                more = true;
                break;
            }
            result.events.try_reserve(1).map_err(|_| ForgeEventReadRefusal::ResponseLimit)?;
            result.events.push(ScopedForgeEvent {
                cursor: position(envelope.cursor), tx_id: envelope.tx_id,
                policy_epoch: envelope.policy_epoch, aggregate: envelope.event.aggregate,
                version: envelope.event.version, kind: envelope.event.payload.kind(),
                frame_hex: hex(&frame)?,
            });
        }
        result.resume_after = Some(position(envelope.cursor));
    }
    result.next_after = if more { result.resume_after } else { None };
    if more && result.next_after == after { return Err(ForgeEventReadRefusal::InvalidPage); }
    stopped(cancelled)
}
fn charge_frame(total: &mut usize, next: usize) -> Result<bool, ForgeEventReadRefusal> {
    if next > MAX_FRAME_BYTES { return Err(ForgeEventReadRefusal::ResponseLimit); }
    let updated = total.checked_add(next).ok_or(ForgeEventReadRefusal::ResponseLimit)?;
    if updated > MAX_PAGE_FRAME_BYTES { return Ok(false); }
    *total = updated;
    Ok(true)
}
fn hex(bytes: &[u8]) -> Result<String, ForgeEventReadRefusal> {
    let mut out = String::new();
    out.try_reserve(bytes.len().checked_mul(2).ok_or(ForgeEventReadRefusal::ResponseLimit)?)
        .map_err(|_| ForgeEventReadRefusal::ResponseLimit)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(out)
}
fn cursor_json(cursor: Option<(u64, u32)>) -> String {
    cursor.map_or_else(|| "null".into(), |(sequence, index)| format!("\"{sequence}:{index}\""))
}
fn append(out: &mut String, bytes: &str) -> Result<(), ForgeEventReadRefusal> {
    if out.len().checked_add(bytes.len()).is_none_or(|n| n > MAX_JSON_BYTES) {
        return Err(ForgeEventReadRefusal::ResponseLimit);
    }
    out.try_reserve(bytes.len()).map_err(|_| ForgeEventReadRefusal::ResponseLimit)?;
    out.push_str(bytes);
    Ok(())
}

#[cfg(test)]
mod tests;
