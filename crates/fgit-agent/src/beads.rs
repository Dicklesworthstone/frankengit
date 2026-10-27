//! Concrete Beads JSON and native single-owner claim boundary.
//!
//! Beads remains the task authority. A host invokes the pinned `br` commands
//! through [`BeadsTransport`]; this module never opens its database or edits its
//! export. One claim uses `br update --claim --if-unchanged` with the complete
//! prepared envelope as actor identity and retains history in `agent_context`.
//! A successful process exit is insufficient: both the database and flushed
//! export must return the exact stored history before ownership is confirmed.
//!
//! This is deliberately **not** a [`crate::TaskProjectionStore`]. Beads 0.7.6
//! compares a wall-clock `updated_at` inside its transaction, but does not promise
//! a unique monotone revision token. Native claim predicates independently fence
//! concurrent owners; they do not provide generic exact-generation replacement.
//! Consequently the receipt below proves native task ownership and retained
//! history, not an activatable [`crate::PersistedTaskClaim`]. Release, transfer,
//! and automatic lease renewal remain unsupported. The existing full run,
//! pulse, plan, and claim checks still precede every attempted native mutation.

use core::fmt;

use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_schema::json::{self, Object, Value};
use fgit_types::RepositoryId;

use crate::{
    AgentChangePlan, AgentControlPulse, AuthorityBoundTaskClaimApplication,
    AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt, IntentRun, LogicalTime,
    TaskClaimReceipt, TaskPhase, TaskProjectionAssignment, TaskProjectionMutationEnvelope,
    WorkTaskId,
};

/// Native profile whose process and schema contracts this adapter implements.
pub const BEADS_PROFILE: &str = "beads-rust-0.7.6-native-claim-v1";
/// Bound applies before parsing either a single record or readiness response.
pub const MAX_BEADS_JSON_BYTES: usize = 1024 * 1024;
/// The metadata and preserved user context must fit one bounded CLI argument.
pub const MAX_BEADS_METADATA_BYTES: usize = 32 * 1024;
/// The readiness query needs the exact candidate; it never claims completeness.
pub const MAX_BEADS_READY_ROWS: usize = 4096;
/// Reserved key inside Beads' existing open-schema `agent_context` object.
pub const BEADS_HISTORY_KEY: &str = "frankengit_task_v1";

const JSON_LIMITS: json::Limits = json::Limits {
    input: MAX_BEADS_JSON_BYTES,
    depth: 16,
    nodes: 65_536,
    items: MAX_BEADS_READY_ROWS,
    string: MAX_BEADS_JSON_BYTES,
};

/// A typed pre-effect or decoding refusal. Backend text is never executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeadsRefusal {
    /// The exact external task name is invalid or another task was returned.
    TaskIdentity,
    /// JSON framing, duplicate keys, bounds, or required fields were invalid.
    Document(&'static str),
    /// This adapter admits initial native claims only on open unassigned rows.
    NotOpenUnassigned,
    /// Existing reserved history cannot be overwritten or silently renewed.
    ExistingHistory,
    /// The exact candidate was absent from the authoritative readiness result.
    NotReady,
    /// A complete authenticated authority/read/run/control binding disagreed.
    ControlBinding,
    /// The request's adapter identity does not name this concrete profile.
    AdapterIdentity,
    /// A canonical framing bound could not be represented.
    Framing,
    /// The native implementation does not promise generic replacement semantics.
    UnsupportedTransition,
    /// The prepared run or native lease expired before dispatch.
    Expired,
    /// Read-only or definitely pre-mutation host failure.
    Transport(BeadsTransportRefusal),
}

impl fmt::Display for BeadsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Beads task operation refused: {self:?}")
    }
}
impl core::error::Error for BeadsRefusal {}

/// Fixed identity committed by all claims using this implementation profile.
#[must_use]
pub fn beads_adapter_identity() -> [u8; 32] {
    hash(&[
        b"frankengit.agent.beads-adapter/v1\0",
        BEADS_PROFILE.as_bytes(),
    ])
}

/// Complete bounded result of an exact `br show ID --json` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeadsTaskRecord {
    document: Value,
    id: String,
    title: String,
    status: String,
    assignee: Option<String>,
    updated_at: String,
    history: Option<BeadsTaskClaimHistory>,
}

impl BeadsTaskRecord {
    /// Parses the real one-element Beads show array, refusing ID aliases,
    /// duplicate keys, missing fields, malformed history, and oversized input.
    pub fn parse_show_json(id: &str, bytes: &[u8]) -> Result<Self, BeadsRefusal> {
        validate_id(id)?;
        let Value::Array(mut rows) = parse(bytes)? else {
            return Err(BeadsRefusal::Document("expected_show_array"));
        };
        if rows.len() != 1 {
            return Err(BeadsRefusal::Document("expected_one_show_record"));
        }
        let document = rows.remove(0);
        let fields = object(&document)?;
        if text(fields, "id")? != id {
            return Err(BeadsRefusal::TaskIdentity);
        }
        let title = text(fields, "title")?.to_owned();
        let status = text(fields, "status")?.to_owned();
        let updated_at = text(fields, "updated_at")?.to_owned();
        // The token is opaque to this adapter, but cannot be an empty argument,
        // option, embedded control sequence, or unbounded value. br owns RFC3339.
        if updated_at.is_empty()
            || updated_at.len() > 64
            || !updated_at.bytes().all(|b| b.is_ascii_graphic())
            || updated_at.starts_with('-')
        {
            return Err(BeadsRefusal::Document("invalid_updated_at"));
        }
        let assignee = optional_text(fields, "assignee")?
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
        let context = context_object(fields)?;
        let history = context
            .get(BEADS_HISTORY_KEY)
            .map(BeadsTaskClaimHistory::parse)
            .transpose()?;
        if let Some(history) = &history
            && history.beads_id() != id
        {
            return Err(BeadsRefusal::Document("history_task_mismatch"));
        }
        Ok(Self {
            document,
            id: id.to_owned(),
            title,
            status,
            assignee,
            updated_at,
            history,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
    #[must_use]
    pub fn assignee(&self) -> Option<&str> {
        self.assignee.as_deref()
    }
    #[must_use]
    pub fn updated_at(&self) -> &str {
        &self.updated_at
    }
    #[must_use]
    pub const fn history(&self) -> Option<&BeadsTaskClaimHistory> {
        self.history.as_ref()
    }

    /// Canonical JSON of the task record, still untrusted task-system data.
    pub fn document_json(&self, maximum: usize) -> Result<String, BeadsRefusal> {
        self.document
            .encode(maximum)
            .map_err(BeadsRefusal::Document)
    }

    /// Projects an initial unassigned task under an independently authenticated
    /// repository read. No task text grants any run or capability authority.
    pub fn unclaimed_snapshot(
        &self,
        authority: &AuthorityReadReceipt,
        observed_at: LogicalTime,
    ) -> Result<AuthorityBoundTaskProjectionSnapshot, BeadsRefusal> {
        if self.status != "open" || self.assignee.is_some() {
            return Err(BeadsRefusal::NotOpenUnassigned);
        }
        if self.history.is_some() {
            return Err(BeadsRefusal::ExistingHistory);
        }
        let generation = self.generation(authority.repository_id())?;
        let task_id = task_id(authority.repository_id(), &self.id);
        AuthorityBoundTaskProjectionSnapshot::observed(
            authority,
            task_id,
            generation,
            TaskPhase::Open,
            TaskProjectionAssignment::Unassigned,
            observed_at,
        )
        .map_err(|_| BeadsRefusal::ControlBinding)
    }

    fn generation(&self, repository_id: RepositoryId) -> Result<[u8; 32], BeadsRefusal> {
        let body = self.document_json(MAX_BEADS_JSON_BYTES)?;
        Ok(hash(&[
            b"frankengit.agent.beads-observation/v1\0",
            repository_id.as_bytes(),
            body.as_bytes(),
        ]))
    }
}

/// Complete history stored inside the authoritative task row. Its identities
/// are evidence, not authority. Parsing this object never creates a capability,
/// authenticated read, active lease, or persisted claim receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeadsTaskClaimHistory {
    document: Value,
    beads_id: String,
    actor: String,
    envelope_id: [u8; 32],
    run_commitment: [u8; 32],
    authority_read_receipt_id: [u8; 32],
    previous_generation: [u8; 32],
    claimed_generation: [u8; 32],
    claimed_at: LogicalTime,
    expires_at: LogicalTime,
}

impl BeadsTaskClaimHistory {
    fn parse(value: &Value) -> Result<Self, BeadsRefusal> {
        let fields = object(value)?;
        const FIELDS: &[&str] = &[
            "profile",
            "beads_id",
            "repository_id",
            "task_id",
            "actor",
            "envelope_id",
            "authority_read_receipt_id",
            "before_snapshot_id",
            "after_snapshot_id",
            "previous_generation",
            "claimed_generation",
            "transition_id",
            "inner_transition_id",
            "evidence_root",
            "run_id",
            "run_commitment",
            "plan_id",
            "claimed_at",
            "expires_at",
            "reserved_surfaces",
            "before_updated_at",
            "before_record_root",
            "adapter_identity",
        ];
        if fields.len() != FIELDS.len() || fields.keys().any(|key| !FIELDS.contains(&key.as_str()))
        {
            return Err(BeadsRefusal::Document("unsupported_history_fields"));
        }
        if text(fields, "profile")? != BEADS_PROFILE {
            return Err(BeadsRefusal::Document("unsupported_history_profile"));
        }
        let beads_id = text(fields, "beads_id")?.to_owned();
        validate_id(&beads_id)?;
        hex_field::<16>(fields, "repository_id")?;
        for field in [
            "task_id",
            "before_snapshot_id",
            "after_snapshot_id",
            "transition_id",
            "inner_transition_id",
            "plan_id",
            "before_record_root",
        ] {
            nonzero(hex_field::<32>(fields, field)?)?;
        }
        if hex_field::<32>(fields, "adapter_identity")? != beads_adapter_identity() {
            return Err(BeadsRefusal::AdapterIdentity);
        }
        let run_id = text(fields, "run_id")?;
        if run_id.is_empty()
            || (run_id.len() > 1 && run_id.starts_with('0'))
            || !run_id.bytes().all(|b| b.is_ascii_digit())
            || run_id.parse::<u128>().is_err()
        {
            return Err(BeadsRefusal::Document("invalid_run_id"));
        }
        validate_digest(
            fields
                .get("evidence_root")
                .ok_or(BeadsRefusal::Document("missing_evidence"))?,
        )?;
        let before_updated_at = text(fields, "before_updated_at")?;
        if before_updated_at.is_empty() || before_updated_at.len() > 64 {
            return Err(BeadsRefusal::Document("invalid_before_updated_at"));
        }
        let Value::Array(surfaces) = fields
            .get("reserved_surfaces")
            .ok_or(BeadsRefusal::Document("missing_surfaces"))?
        else {
            return Err(BeadsRefusal::Document("invalid_surfaces"));
        };
        if surfaces.is_empty() || surfaces.len() > crate::MAX_PLAN_ENTRIES {
            return Err(BeadsRefusal::Document("surface_limit"));
        }
        let mut prior: Option<String> = None;
        for surface in surfaces {
            let surface = object(surface)?;
            if surface.len() != 2 || !surface.contains_key("selector") {
                return Err(BeadsRefusal::Document("invalid_surface"));
            }
            match text(surface, "kind")? {
                "repository_path" | "ref" | "forge_entity" | "schema_or_registry"
                | "evidence_target" | "external_effect" | "workspace" => {}
                _ => return Err(BeadsRefusal::Document("unknown_surface_kind")),
            }
            validate_digest(&surface["selector"])?;
            let canonical = Value::Object(surface.clone())
                .encode(MAX_BEADS_METADATA_BYTES)
                .map_err(BeadsRefusal::Document)?;
            if prior.as_ref().is_some_and(|value| value >= &canonical) {
                return Err(BeadsRefusal::Document("duplicate_or_unordered_surface"));
            }
            prior = Some(canonical);
        }
        let envelope_id = nonzero(hex_field::<32>(fields, "envelope_id")?)?;
        let actor = text(fields, "actor")?.to_owned();
        if actor != actor_for(envelope_id) {
            return Err(BeadsRefusal::Document("actor_envelope_mismatch"));
        }
        let previous_generation = nonzero(hex_field::<32>(fields, "previous_generation")?)?;
        let claimed_generation = nonzero(hex_field::<32>(fields, "claimed_generation")?)?;
        let claimed_at = LogicalTime::new(number(fields, "claimed_at")?);
        let expires_at = LogicalTime::new(number(fields, "expires_at")?);
        if claimed_generation == previous_generation || expires_at <= claimed_at {
            return Err(BeadsRefusal::Document("invalid_lease"));
        }
        value
            .encode(MAX_BEADS_METADATA_BYTES)
            .map_err(BeadsRefusal::Document)?;
        Ok(Self {
            document: value.clone(),
            beads_id,
            actor,
            envelope_id,
            run_commitment: nonzero(hex_field::<32>(fields, "run_commitment")?)?,
            authority_read_receipt_id: nonzero(hex_field::<32>(
                fields,
                "authority_read_receipt_id",
            )?)?,
            previous_generation,
            claimed_generation,
            claimed_at,
            expires_at,
        })
    }

    #[must_use]
    pub fn beads_id(&self) -> &str {
        &self.beads_id
    }
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }
    #[must_use]
    pub const fn envelope_id(&self) -> &[u8; 32] {
        &self.envelope_id
    }
    #[must_use]
    pub const fn run_commitment(&self) -> &[u8; 32] {
        &self.run_commitment
    }
    #[must_use]
    pub const fn authority_read_receipt_id(&self) -> &[u8; 32] {
        &self.authority_read_receipt_id
    }
    #[must_use]
    pub const fn previous_generation(&self) -> &[u8; 32] {
        &self.previous_generation
    }
    #[must_use]
    pub const fn claimed_generation(&self) -> &[u8; 32] {
        &self.claimed_generation
    }
    #[must_use]
    pub const fn claimed_at(&self) -> LogicalTime {
        self.claimed_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> LogicalTime {
        self.expires_at
    }
    pub fn document_json(&self, maximum: usize) -> Result<String, BeadsRefusal> {
        self.document
            .encode(maximum)
            .map_err(BeadsRefusal::Document)
    }
}

/// A native claim prepared from the ordinary exact control-plane objects.
/// This value has no public unchecked constructor and exposes no activatable
/// claim. Retain it across an ambiguous response; do not prepare another claim.
#[derive(Debug, Eq, PartialEq)]
pub struct BeadsClaimRequest {
    before: BeadsTaskRecord,
    envelope: TaskProjectionMutationEnvelope,
    history: BeadsTaskClaimHistory,
    context_json: String,
    attempted: bool,
    writer_quiescent: bool,
    run_expires_at: LogicalTime,
}

impl BeadsClaimRequest {
    pub fn prepare(
        record: &BeadsTaskRecord,
        application: &AuthorityBoundTaskClaimApplication,
        pulse: &AgentControlPulse,
        plan: &AgentChangePlan,
        run: &IntentRun,
    ) -> Result<Self, BeadsRefusal> {
        // The ordinary admission gate runs before creating any native command.
        // Its in-memory receipt is intentionally not released to the caller.
        TaskClaimReceipt::admit(pulse, plan, run, application.projection().clone())
            .map_err(|_| BeadsRefusal::ControlBinding)?;
        let envelope = TaskProjectionMutationEnvelope::from_claim(application)
            .map_err(|_| BeadsRefusal::ControlBinding)?;
        if envelope.adapter_identity() != beads_adapter_identity() {
            return Err(BeadsRefusal::AdapterIdentity);
        }
        let expected_before = record.unclaimed_snapshot(
            application.before_snapshot().authority_read_receipt(),
            application.before_snapshot().observed_at(),
        )?;
        if &expected_before != application.before_snapshot() {
            return Err(BeadsRefusal::ControlBinding);
        }
        let lease = envelope
            .after_snapshot()
            .lease()
            .ok_or(BeadsRefusal::UnsupportedTransition)?;
        if lease.run_commitment() != run.commitment().map_err(|_| BeadsRefusal::ControlBinding)?
            || lease.assignee() != run.run_id()
            || !run.is_open_at(lease.claimed_at())
            || lease.expires_at() > run.expiry()
        {
            return Err(BeadsRefusal::ControlBinding);
        }
        let history = history_for(record, &envelope)?;
        let mut context = context_object(object(&record.document)?)?;
        if context
            .insert(BEADS_HISTORY_KEY.to_owned(), history.document.clone())
            .is_some()
        {
            return Err(BeadsRefusal::ExistingHistory);
        }
        let context_json = Value::Object(context)
            .encode(MAX_BEADS_METADATA_BYTES)
            .map_err(BeadsRefusal::Document)?;
        Ok(Self {
            before: record.clone(),
            envelope,
            history,
            context_json,
            attempted: false,
            writer_quiescent: true,
            run_expires_at: run.expiry(),
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.before.id()
    }
    #[must_use]
    pub fn actor(&self) -> &str {
        self.history.actor()
    }
    #[must_use]
    pub fn updated_at(&self) -> &str {
        self.before.updated_at()
    }
    #[must_use]
    pub fn agent_context_json(&self) -> &str {
        &self.context_json
    }
    #[must_use]
    pub const fn envelope(&self) -> &TaskProjectionMutationEnvelope {
        &self.envelope
    }
    #[must_use]
    pub const fn history(&self) -> &BeadsTaskClaimHistory {
        &self.history
    }

    /// Arguments only: hosts use an explicit pinned executable, fixed workspace
    /// and database, cleared environment, deadlines, output bounds, and joined
    /// child ownership. No shell, `--force`, implicit actor, or batch update.
    #[must_use]
    pub fn update_arguments(&self) -> Vec<String> {
        [
            "update",
            self.id(),
            "--claim",
            "--actor",
            self.actor(),
            "--if-unchanged",
            self.updated_at(),
            "--agent-context",
            self.agent_context_json(),
            "--json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
}

/// Selects the live database or collaborative JSONL export through `br show`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeadsReadSource {
    Database,
    Export,
}

/// Bounded host failure without untrusted process output embedded as authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeadsTransportRefusal {
    Unavailable,
    Cancelled,
    TimeLimit,
    OutputLimit,
    Policy,
    Unsupported,
    ProcessFailed,
}

/// A process disposition does not by itself establish a durable task mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeadsWriteOutcome {
    /// Child and readers joined; process returned success.
    Completed,
    /// No mutation process started, or an authoritative refusal proves no write.
    NotStarted(BeadsTransportRefusal),
    /// Mutation may have happened; non-quiescence forbids follow-up I/O here.
    Uncertain {
        quiescent: bool,
        reason: BeadsTransportRefusal,
    },
}

/// Concrete process/storage boundary. The host must use the fixed profile's
/// commands and exact workspace, disable automatic import/export, bound bytes
/// before buffering, check cancellation, and join children and output readers.
/// `flush` invokes `br sync --flush-only`; it never writes JSONL itself.
pub trait BeadsTransport {
    /// Current instant in the exact logical clock domain of the prepared run.
    fn observed_at(&mut self) -> LogicalTime;
    fn show(&mut self, id: &str, source: BeadsReadSource)
    -> Result<Vec<u8>, BeadsTransportRefusal>;
    fn ready_unassigned(&mut self) -> Result<Vec<u8>, BeadsTransportRefusal>;
    fn claim(&mut self, request: &BeadsClaimRequest) -> BeadsWriteOutcome;
    fn flush(&mut self) -> BeadsWriteOutcome;
}

/// Exact native task ownership observed in both the database and export.
/// No conversion to `PersistedTaskClaim` or `TaskClaimReceipt` is supplied.
#[derive(Debug, Eq, PartialEq)]
pub struct BeadsClaimConfirmation {
    request: BeadsClaimRequest,
    database: BeadsTaskRecord,
    export: BeadsTaskRecord,
}
impl BeadsClaimConfirmation {
    #[must_use]
    pub const fn request(&self) -> &BeadsClaimRequest {
        &self.request
    }
    #[must_use]
    pub const fn database(&self) -> &BeadsTaskRecord {
        &self.database
    }
    #[must_use]
    pub const fn export(&self) -> &BeadsTaskRecord {
        &self.export
    }
}

/// Boundary at which an unresolved claim must be inspected, never blindly retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeadsReconciliationStage {
    Claim,
    Flush,
    DatabaseRead,
    ExportRead,
    Confirmation,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BeadsClaimOutcome {
    /// Native ownership and identical complete history are retained in both views.
    Confirmed(BeadsClaimConfirmation),
    /// Before mutation, another complete record or no-ready result was observed.
    Conflict {
        request: BeadsClaimRequest,
        observed: BeadsTaskRecord,
    },
    /// Backend proved no mutation occurred; the original request is retained.
    NotApplied {
        request: BeadsClaimRequest,
        reason: BeadsTransportRefusal,
    },
    /// Mutation might have happened. The exact request is retained for read-only
    /// reconciliation; cancellation and a missing successor never prove abort.
    NeedsReconciliation {
        request: BeadsClaimRequest,
        stage: BeadsReconciliationStage,
        reason: BeadsRefusal,
    },
}

/// Fresh read and readiness check, at most one native claim, flush, then exact
/// confirmation from both durable views. No ambiguous result triggers a retry.
pub fn execute_beads_claim<T: BeadsTransport>(
    transport: &mut T,
    mut request: BeadsClaimRequest,
) -> Result<BeadsClaimOutcome, BeadsRefusal> {
    if request.attempted {
        return Err(BeadsRefusal::UnsupportedTransition);
    }
    validate_dispatch_time(&request, transport.observed_at())?;
    let current = read(transport, request.id(), BeadsReadSource::Database)?;
    if matches_owner(&current, &request) {
        // Exact historical success can still need a collaborative export flush.
        request.attempted = true;
        return Ok(flush_and_confirm(transport, request));
    }
    if current != request.before {
        return Ok(BeadsClaimOutcome::Conflict {
            request,
            observed: current,
        });
    }
    let ready = transport
        .ready_unassigned()
        .map_err(BeadsRefusal::Transport)?;
    if !ready_contains(request.id(), &ready)? {
        return Err(BeadsRefusal::NotReady);
    }
    validate_dispatch_time(&request, transport.observed_at())?;
    request.attempted = true;
    match transport.claim(&request) {
        BeadsWriteOutcome::NotStarted(reason) => {
            Ok(BeadsClaimOutcome::NotApplied { request, reason })
        }
        BeadsWriteOutcome::Uncertain {
            quiescent: false,
            reason,
        } => {
            request.writer_quiescent = false;
            Ok(debt(
                request,
                BeadsReconciliationStage::Claim,
                BeadsRefusal::Transport(reason),
            ))
        }
        BeadsWriteOutcome::Completed
        | BeadsWriteOutcome::Uncertain {
            quiescent: true, ..
        } => Ok(flush_and_confirm(transport, request)),
    }
}

/// Probes an attempted claim without issuing any mutation or flush. A fresh
/// process can also inspect retained history through [`BeadsTaskRecord`].
/// The caller must establish that any earlier writer is quiescent before this
/// read-only probe; otherwise even a matching view cannot settle ongoing work.
pub fn reconcile_beads_claim<T: BeadsTransport>(
    transport: &mut T,
    request: BeadsClaimRequest,
) -> BeadsClaimOutcome {
    if !request.attempted || !request.writer_quiescent {
        return debt(
            request,
            BeadsReconciliationStage::Claim,
            BeadsRefusal::Transport(BeadsTransportRefusal::ProcessFailed),
        );
    }
    confirm(transport, request)
}

fn validate_dispatch_time(
    request: &BeadsClaimRequest,
    at: LogicalTime,
) -> Result<(), BeadsRefusal> {
    if at < request.history.claimed_at() {
        return Err(BeadsRefusal::ControlBinding);
    }
    if at >= request.run_expires_at || at >= request.history.expires_at() {
        return Err(BeadsRefusal::Expired);
    }
    Ok(())
}

fn flush_and_confirm<T: BeadsTransport>(
    transport: &mut T,
    mut request: BeadsClaimRequest,
) -> BeadsClaimOutcome {
    match transport.flush() {
        BeadsWriteOutcome::Completed => confirm(transport, request),
        BeadsWriteOutcome::Uncertain {
            quiescent: false,
            reason,
        } => {
            request.writer_quiescent = false;
            debt(
                request,
                BeadsReconciliationStage::Flush,
                BeadsRefusal::Transport(reason),
            )
        }
        BeadsWriteOutcome::NotStarted(reason)
        | BeadsWriteOutcome::Uncertain {
            quiescent: true,
            reason,
        } => debt(
            request,
            BeadsReconciliationStage::Flush,
            BeadsRefusal::Transport(reason),
        ),
    }
}

fn confirm<T: BeadsTransport>(transport: &mut T, request: BeadsClaimRequest) -> BeadsClaimOutcome {
    let database = match read(transport, request.id(), BeadsReadSource::Database) {
        Ok(record) => record,
        Err(reason) => return debt(request, BeadsReconciliationStage::DatabaseRead, reason),
    };
    let export = match read(transport, request.id(), BeadsReadSource::Export) {
        Ok(record) => record,
        Err(reason) => return debt(request, BeadsReconciliationStage::ExportRead, reason),
    };
    if !matches_owner(&database, &request)
        || !matches_owner(&export, &request)
        || database.updated_at() != export.updated_at()
    {
        return debt(
            request,
            BeadsReconciliationStage::Confirmation,
            BeadsRefusal::Document("successor_not_confirmed"),
        );
    }
    BeadsClaimOutcome::Confirmed(BeadsClaimConfirmation {
        request,
        database,
        export,
    })
}

fn matches_owner(record: &BeadsTaskRecord, request: &BeadsClaimRequest) -> bool {
    record.history() == Some(request.history())
        && record.status() == "in_progress"
        && record.assignee() == Some(request.actor())
}

const fn debt(
    request: BeadsClaimRequest,
    stage: BeadsReconciliationStage,
    reason: BeadsRefusal,
) -> BeadsClaimOutcome {
    BeadsClaimOutcome::NeedsReconciliation {
        request,
        stage,
        reason,
    }
}

fn read<T: BeadsTransport>(
    transport: &mut T,
    id: &str,
    source: BeadsReadSource,
) -> Result<BeadsTaskRecord, BeadsRefusal> {
    let bytes = transport
        .show(id, source)
        .map_err(BeadsRefusal::Transport)?;
    BeadsTaskRecord::parse_show_json(id, &bytes)
}

fn ready_contains(id: &str, bytes: &[u8]) -> Result<bool, BeadsRefusal> {
    let Value::Array(rows) = parse(bytes)? else {
        return Err(BeadsRefusal::Document("expected_ready_array"));
    };
    if rows.len() > MAX_BEADS_READY_ROWS {
        return Err(BeadsRefusal::Document("ready_row_limit"));
    }
    let mut found = false;
    let mut ids = std::collections::BTreeSet::new();
    for row in rows {
        let fields = object(&row)?;
        let row_id = text(fields, "id")?;
        validate_id(row_id)?;
        if !ids.insert(row_id.to_owned()) {
            return Err(BeadsRefusal::Document("duplicate_ready_task"));
        }
        if row_id == id {
            if text(fields, "status")? != "open"
                || optional_text(fields, "assignee")?.is_some_and(|a| !a.trim().is_empty())
            {
                return Err(BeadsRefusal::Document("assigned_ready_task"));
            }
            found = true;
        }
    }
    Ok(found)
}

fn history_for(
    record: &BeadsTaskRecord,
    envelope: &TaskProjectionMutationEnvelope,
) -> Result<BeadsTaskClaimHistory, BeadsRefusal> {
    let lease = envelope
        .after_snapshot()
        .lease()
        .ok_or(BeadsRefusal::UnsupportedTransition)?;
    let surfaces = lease
        .reserved_surfaces()
        .iter()
        .map(|surface| {
            use crate::PlanSurfaceKind;
            let kind = match surface.kind() {
                PlanSurfaceKind::RepositoryPath => "repository_path",
                PlanSurfaceKind::Ref => "ref",
                PlanSurfaceKind::ForgeEntity => "forge_entity",
                PlanSurfaceKind::SchemaOrRegistry => "schema_or_registry",
                PlanSurfaceKind::EvidenceTarget => "evidence_target",
                PlanSurfaceKind::ExternalEffect => "external_effect",
                PlanSurfaceKind::Workspace => "workspace",
            };
            json::object([
                ("kind", json::text(kind)),
                ("selector", digest_value(surface.selector())),
            ])
        })
        .collect::<Vec<_>>();
    // Persisted order is canonical JSON order, independent of enum layout.
    let mut encoded = surfaces
        .into_iter()
        .map(|surface| {
            let encoded = surface
                .encode(MAX_BEADS_METADATA_BYTES)
                .map_err(BeadsRefusal::Document)?;
            Ok((encoded, surface))
        })
        .collect::<Result<Vec<_>, BeadsRefusal>>()?;
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    let value = json::object([
        ("profile", json::text(BEADS_PROFILE)),
        ("beads_id", json::text(record.id())),
        (
            "repository_id",
            json::text(hex(envelope.repository_id().as_bytes())),
        ),
        ("task_id", json::text(hex(envelope.task_id().as_bytes()))),
        (
            "actor",
            json::text(actor_for(*envelope.envelope_id().as_bytes())),
        ),
        (
            "envelope_id",
            json::text(hex(envelope.envelope_id().as_bytes())),
        ),
        (
            "authority_read_receipt_id",
            json::text(hex(envelope.basis_authority_read_receipt_id().as_bytes())),
        ),
        (
            "before_snapshot_id",
            json::text(hex(envelope.before_snapshot_id().as_bytes())),
        ),
        (
            "after_snapshot_id",
            json::text(hex(envelope.after_snapshot_id().as_bytes())),
        ),
        (
            "previous_generation",
            json::text(hex(&envelope.previous_generation())),
        ),
        (
            "claimed_generation",
            json::text(hex(&envelope.resulting_generation())),
        ),
        (
            "transition_id",
            json::text(hex(envelope.transition_id().as_bytes())),
        ),
        (
            "inner_transition_id",
            json::text(hex(&envelope.inner_transition_id())),
        ),
        ("evidence_root", digest_value(envelope.evidence_root())),
        ("run_id", json::text(lease.assignee().value().to_string())),
        (
            "run_commitment",
            json::text(hex(lease.run_commitment().as_bytes())),
        ),
        ("plan_id", json::text(hex(lease.plan_id().as_bytes()))),
        ("claimed_at", json::number(lease.claimed_at().value())),
        ("expires_at", json::number(lease.expires_at().value())),
        (
            "reserved_surfaces",
            Value::Array(encoded.into_iter().map(|(_, value)| value).collect()),
        ),
        ("before_updated_at", json::text(record.updated_at())),
        (
            "before_record_root",
            json::text(hex(&record.generation(envelope.repository_id())?)),
        ),
        (
            "adapter_identity",
            json::text(hex(&beads_adapter_identity())),
        ),
    ]);
    BeadsTaskClaimHistory::parse(&value)
}

fn digest_value(digest: fgit_types::Digest) -> Value {
    json::object([
        (
            "algorithm",
            json::number(u64::from(digest.algorithm().code_point())),
        ),
        ("bytes", json::text(hex(digest.bytes().as_bytes()))),
    ])
}
fn validate_digest(value: &Value) -> Result<(), BeadsRefusal> {
    let fields = object(value)?;
    let algorithm = number(fields, "algorithm")?;
    let bytes = text(fields, "bytes")?;
    if fields.len() != 2
        || algorithm == 0
        || algorithm > u64::from(u16::MAX)
        || bytes.is_empty()
        || bytes.len() > 128
        || bytes.len() % 2 != 0
        || !bytes
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BeadsRefusal::Document("invalid_digest"));
    }
    Ok(())
}
fn task_id(repository: RepositoryId, id: &str) -> WorkTaskId {
    WorkTaskId::from_bytes(hash(&[
        b"frankengit.agent.beads-task/v1\0",
        repository.as_bytes(),
        id.as_bytes(),
    ]))
}
fn actor_for(envelope: [u8; 32]) -> String {
    format!("fgit-{}", hex(&envelope))
}
fn validate_id(id: &str) -> Result<(), BeadsRefusal> {
    if id.is_empty()
        || id.len() > 256
        || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(BeadsRefusal::TaskIdentity);
    }
    Ok(())
}
fn parse(bytes: &[u8]) -> Result<Value, BeadsRefusal> {
    json::parse_with(bytes, JSON_LIMITS).map_err(BeadsRefusal::Document)
}
fn object(value: &Value) -> Result<&Object, BeadsRefusal> {
    value
        .object()
        .ok_or(BeadsRefusal::Document("expected_object"))
}
fn text<'a>(fields: &'a Object, key: &str) -> Result<&'a str, BeadsRefusal> {
    fields
        .get(key)
        .and_then(Value::text)
        .ok_or(BeadsRefusal::Document("missing_or_invalid_string"))
}
fn optional_text<'a>(fields: &'a Object, key: &str) -> Result<Option<&'a str>, BeadsRefusal> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(BeadsRefusal::Document("invalid_optional_string")),
    }
}
fn number(fields: &Object, key: &str) -> Result<u64, BeadsRefusal> {
    fields
        .get(key)
        .and_then(Value::unsigned)
        .ok_or(BeadsRefusal::Document("missing_or_invalid_integer"))
}
fn context_object(fields: &Object) -> Result<Object, BeadsRefusal> {
    match optional_text(fields, "agent_context")? {
        None => Ok(Object::new()),
        Some(value) => {
            if value.len() > MAX_BEADS_METADATA_BYTES {
                return Err(BeadsRefusal::Document("context_limit"));
            }
            let parsed = parse(value.as_bytes())?;
            Ok(object(&parsed)?.clone())
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(CHARS[usize::from(byte >> 4)]));
        out.push(char::from(CHARS[usize::from(byte & 15)]));
    }
    out
}
fn hex_field<const N: usize>(fields: &Object, key: &str) -> Result<[u8; N], BeadsRefusal> {
    let value = text(fields, key)?.as_bytes();
    if value.len() != N * 2 {
        return Err(BeadsRefusal::Document("identity_width"));
    }
    let mut bytes = [0; N];
    for (target, pair) in bytes.iter_mut().zip(value.as_chunks::<2>().0) {
        let digit = |b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(BeadsRefusal::Document("noncanonical_identity")),
        };
        *target = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(bytes)
}
fn nonzero<const N: usize>(bytes: [u8; N]) -> Result<[u8; N], BeadsRefusal> {
    if bytes.iter().all(|b| *b == 0) {
        return Err(BeadsRefusal::Document("zero_identity"));
    }
    Ok(bytes)
}
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finish()
}
