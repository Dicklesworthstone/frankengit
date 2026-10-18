#![forbid(unsafe_code)]
//! A complete native scrub is a chain of internally obtained pages, not a claim
//! reconstructed from caller-supplied cursors or counts. Only the terminal
//! record, emitted after exact-head revalidation and shutdown, certifies scope.

use std::io::Write;
use std::time::Instant;

use fgit_types::{Digest, RepositoryAuthorityHeadId, RepositoryIncarnationId};
use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub pages: usize,
    pub payload_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self { pages: 10_000, payload_bytes: 16 * 1024 * MIB }
    }
}

#[derive(Debug)]
struct Summary {
    head: RepositoryAuthorityHeadId,
    generation: HeadGeneration,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    closure: Digest,
    selected: usize,
    pages: usize,
    checked: usize,
    verified: usize,
    attempts: usize,
    bytes: u64,
    findings: usize,
}
impl Summary {
    fn from_page(page: &SelectedObjectScrub) -> Self {
        Self {
            head: page.head(), generation: page.generation(),
            repository: page.repository_id(), incarnation: page.repository_incarnation_id(),
            closure: page.closure_root(), selected: page.selected_objects(),
            pages: 0, checked: 0, verified: 0, attempts: 0, bytes: 0, findings: 0,
        }
    }
    fn accept(&mut self, page: &SelectedObjectScrub, requested: ScrubQuery) -> Result<(), String> {
        if self.head != page.head() || self.generation != page.generation()
            || self.repository != page.repository_id() || self.incarnation != page.repository_incarnation_id()
            || self.closure != page.closure_root() || self.selected != page.selected_objects()
            || requested.cursor.map(ScrubCursor::after) != page.start_after()
        {
            return Err("scrub sweep source or continuation changed".into());
        }
        if page.checked_objects() > requested.max_page_objects
            || page.findings().len() > requested.max_findings
            || page.payload_bytes() > requested.max_payload_bytes
            || page.checked_objects() != page.verified_objects().checked_add(page.findings().len())
                .ok_or("scrub sweep accounting overflow")?
        {
            return Err("scrub sweep page accounting invalid".into());
        }
        if let Some(next) = page.next_cursor() {
            if page.checked_objects() == 0 || next.head() != self.head
                || page.start_after().is_some_and(|after| next.after() <= after)
            {
                return Err("scrub sweep continuation made no progress".into());
            }
        }
        self.pages = self.pages.checked_add(1).ok_or("scrub sweep page count overflow")?;
        self.checked = self.checked.checked_add(page.checked_objects()).ok_or("scrub sweep count overflow")?;
        self.verified = self.verified.checked_add(page.verified_objects()).ok_or("scrub sweep count overflow")?;
        self.attempts = self.attempts.checked_add(page.read_attempts()).ok_or("scrub sweep count overflow")?;
        self.bytes = self.bytes.checked_add(page.payload_bytes()).ok_or("scrub sweep byte count overflow")?;
        self.findings = self.findings.checked_add(page.findings().len()).ok_or("scrub sweep finding count overflow")?;
        if self.checked > self.selected || (page.next_cursor().is_none() && self.checked != self.selected) {
            return Err("scrub sweep did not cover exactly the selected closure".into());
        }
        Ok(())
    }
    fn receipt(&self, options: &Options) -> String {
        format!(concat!(
            "{{\"type\":\"repository_scrub_sweep\",\"schema_version\":1,",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation_id\":{},",
            "\"object_format\":{},\"authority_generation\":{},\"snapshot_token\":{},",
            "\"selected_closure_root\":{},\"selected_objects\":{},\"pages\":{},",
            "\"objects_checked\":{},\"objects_verified\":{},\"object_read_attempts\":{},",
            "\"payload_bytes_accounted\":{},\"finding_count\":{},",
            "\"complete\":true,\"all_selected_object_bytes_verified\":{},",
            "\"scope\":\"authority_selected_native_object_bytes\",\"head_revalidated\":true,",
            "\"object_graph_verified\":false,\"physical_orphans_scanned\":false,",
            "\"objects_repaired\":false,\"repository_changed\":false,\"node_closed\":true}}"
        ), quote(&options.tenant.to_string()), quote(&self.repository.to_string()),
            quote(&self.incarnation.to_string()), quote(options.format.as_str()), self.generation.get(),
            quote(&head_token(self.head)), quote(&self.closure.to_string()), self.selected, self.pages,
            self.checked, self.verified, self.attempts, self.bytes, self.findings, self.findings == 0)
    }
}

fn remaining_timeout(options: &Options, started: Instant) -> Result<Duration, String> {
    options.query.timeout.checked_sub(started.elapsed()).filter(|left| !left.is_zero())
        .ok_or_else(|| "scrub sweep deadline exceeded; no complete receipt".into())
}

fn drive(
    options: &Options,
    output: &mut impl Write,
    started: Instant,
    mut fetch: impl FnMut(ScrubQuery) -> Result<SelectedObjectScrub, String>,
) -> Result<Summary, String> {
    let limits = options.sweep.ok_or("missing scrub sweep limits")?;
    if options.query.cursor.is_some() {
        return Err("a complete scrub sweep must start at the beginning".into());
    }
    let mut query = options.query;
    let mut summary: Option<Summary> = None;
    loop {
        query.timeout = remaining_timeout(options, started)?;
        let (pages, bytes) = summary.as_ref().map_or((0, 0), |state| (state.pages, state.bytes));
        if pages >= limits.pages {
            return Err("scrub sweep max-pages exceeded; no complete receipt".into());
        }
        let remaining = limits.payload_bytes.checked_sub(bytes).filter(|bytes| *bytes > 0)
            .ok_or("scrub sweep max-sweep-bytes exhausted; no complete receipt")?;
        query.max_payload_bytes = options.query.max_payload_bytes.min(remaining);
        let page = fetch(query)?;
        remaining_timeout(options, started)?;
        let state = summary.get_or_insert_with(|| Summary::from_page(&page));
        state.accept(&page, query)?;
        query.expected_head = Some(state.head);
        query.expected_generation = Some(state.generation);
        query.cursor = page.next_cursor();
        // These bounded records are observations, not successful closed-node
        // receipts. A later failed page, sink, fence or shutdown cannot turn
        // the last clean page into a successful whole-repository certificate.
        writeln!(output, "{}", render_page(options, &page, false))
            .and_then(|()| output.flush())
            .map_err(|error| format!("scrub sweep progress output failed: {error}"))?;
        remaining_timeout(options, started)?;
        if query.cursor.is_none() {
            return summary.ok_or_else(|| "scrub sweep produced no summary".into());
        }
    }
}

fn finish(
    output: &mut impl Write,
    options: &Options,
    result: Result<Summary, String>,
    cleanup: Option<String>,
) -> Result<u8, String> {
    let summary = match (result, cleanup) {
        (Ok(summary), None) => summary,
        (result, cleanup) => return Err(format!(
            "no complete scrub sweep receipt; audit: {}; shutdown: {}",
            result.err().unwrap_or_else(|| "completed".into()),
            cleanup.unwrap_or_else(|| "completed".into()))),
    };
    let code = if summary.findings == 0 { 0 } else { 3 };
    writeln!(output, "{}", summary.receipt(options)).and_then(|()| output.flush())
        .map_err(|error| format!("scrub sweep receipt output incomplete: {error}"))?;
    Ok(code)
}

pub(super) fn run(options: Options) -> Result<u8, String> {
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format).with_max_object_bytes(options.object_bytes),
    ).map_err(|error| format!("cannot open scrub node: {error}"))?;
    let mut output = std::io::stdout().lock();
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let started = Instant::now();
        let request = fgit_cli::command_request_context(&node);
        let initial = node.runtime().block_on(node.authenticate_authority_head_in(&request))
            .map_err(|error| error.to_string())?;
        let summary = drive(&options, &mut output, started, |query| {
            node.runtime().block_on(node.scrub_selected_objects_local_in(&request, query))
                .map_err(|error| error.to_string())
        })?;
        let current = node.runtime().block_on(node.authenticate_authority_head_in(&request))
            .map_err(|error| error.to_string())?;
        if initial.receipt().token() != current.receipt().token()
            || initial.receipt().body() != current.receipt().body()
        {
            return Err("scrub sweep authority changed; no complete receipt".into());
        }
        remaining_timeout(&options, started)?;
        Ok(summary)
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(&mut output, &options, result, cleanup)
}

#[cfg(test)]
mod tests;
