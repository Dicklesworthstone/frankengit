//! Owned, restartable, explicitly at-least-once HTTP dispatch (FG-046).
//! Local observations suppress this worker's retries; they never settle an RCR,
//! change canonical delivery identities, or manufacture strong idempotency.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fgit_codec::CanonicalOutboxStateEntry;
use fgit_crypto::sha256_digest;
use fgit_forge::webhook::{SsrfPolicy, WebhookId, WebhookRegistration, WebhookRetrySchedule};
use fgit_node::webhook::{WebhookDeliveryDestination, WebhookStore};
use fgit_node::{NodeConfig, OneNode, TerminationSignals};
use fgit_types::{AsciiSlug, Digest, GitHashAlgorithm, HeadGeneration, RepositoryAuthorityHeadId,
    RepositoryId, RepositoryIncarnationId, TenantId};

use crate::publication_support::quote;
use super::subscription::require_subscription;
mod journal;
use journal::{Journal, Plan, State, hex};

const USAGE: &str = "usage: fg webhook dispatch <storage-root> <tenant-id> <repository-id> --trusted-local
  --id <registered-id> --destination <canonical-destination> --at-least-once
  [--object-format sha1|sha256] [--max-deliveries <1..1000>]
  [--max-scan-entries <1..16384>] [--attempt-timeout-secs <1..60>]
  [--continuous --stop-file <path> [--poll-millis <100..60000>]]
  [--permissive-for-tests]

Default: one sweep, at most 16 due attempts, 16384 retained entries, 5 s/attempt.
A complete outbox snapshot is selected on every sweep; no append-ordered key
cursor is assumed. The private local journal is locked and synced BEFORE each
send. Restarted in-flight attempts remain unknown and consume the next ordinal.
A retry can duplicate an effect. Local HTTP acceptance NEVER settles canonical
outbox state. No fan-out, HTTPS, journal compaction or exactly-once guarantee.
Continuous mode drains on SIGTERM/SIGINT or a regular stop file. Blocking DNS
and filesystem calls cannot be preempted. All directories must be operator-owned.
Exit 0: no pending/failed selected work; 1: pending/backoff/bound; 2: refusal or
rejection; 3: unresolved transport outcome. See docs/WEBHOOK_DISPATCHER.md.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    id: WebhookId,
    destination: AsciiSlug,
    max_deliveries: usize,
    max_scan: usize,
    timeout: Duration,
    continuous: bool,
    stop_file: Option<PathBuf>,
    poll: Duration,
    permissive: bool,
}
impl Options {
    fn policy(&self) -> SsrfPolicy {
        if self.permissive { SsrfPolicy::PERMISSIVE_FOR_TESTS } else { SsrfPolicy::STRICT }
    }
}

fn number(value: &str, min: u64, max: u64) -> Result<u64, String> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    { return Err("dispatch requires canonical decimal integers".into()); }
    value.parse::<u64>().ok().filter(|n| (min..=max).contains(n))
        .ok_or_else(|| format!("dispatch integer must be in {min}..={max}"))
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4 || args.len() > 26 || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[0].is_empty() || args[0].len() > 4096
    { return Err(USAGE.into()); }
    let (storage, tenant, repository, mut index) = super::parse_base(args)?;
    let mut fields = BTreeMap::new();
    while index < args.len() {
        let flag = args[index].as_str();
        let switch = matches!(flag, "--at-least-once" | "--continuous" | "--permissive-for-tests");
        if !switch && !matches!(flag, "--id" | "--destination" | "--object-format" |
            "--max-deliveries" | "--max-scan-entries" | "--attempt-timeout-secs" | "--stop-file" | "--poll-millis")
        { return Err(format!("unknown dispatch option {flag}")); }
        index += 1;
        let value = if switch { "" } else {
            let value = args.get(index).ok_or_else(|| format!("missing dispatch option value: {flag}"))?;
            if value.is_empty() || value.starts_with("--") { return Err(format!("missing dispatch option value: {flag}")); }
            index += 1;
            value.as_str()
        };
        if fields.insert(flag, value).is_some() { return Err(format!("duplicate dispatch option {flag}")); }
    }
    if !fields.contains_key("--at-least-once") {
        return Err("dispatch requires explicit --at-least-once; a retry can duplicate an effect".into());
    }
    let id = WebhookId(number(fields.get("--id").ok_or("missing --id")?, 0, u64::MAX)?);
    let destination = AsciiSlug::try_new("dispatch destination",
        fields.get("--destination").ok_or("missing --destination")?.as_bytes()).map_err(|e| e.to_string())?;
    let format = match fields.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("dispatch object format must be sha1 or sha256".into()),
    };
    let continuous = fields.contains_key("--continuous");
    let stop_file = fields.get("--stop-file").map(|value| PathBuf::from(*value));
    if continuous != stop_file.is_some() || (!continuous && fields.contains_key("--poll-millis")) {
        return Err("--continuous and --stop-file must be supplied together; polling is continuous-only".into());
    }
    let bounded = |name, fallback, min, max| number(fields.get(name).copied().unwrap_or(fallback), min, max);
    Ok(Options { storage, tenant, repository, format, id, destination,
        max_deliveries: bounded("--max-deliveries", "16", 1, 1000)? as usize,
        max_scan: bounded("--max-scan-entries", "16384", 1, 16384)? as usize,
        timeout: Duration::from_secs(bounded("--attempt-timeout-secs", "5", 1, 60)?),
        continuous, stop_file, poll: Duration::from_millis(bounded("--poll-millis", "1000", 100, 60000)?),
        permissive: fields.contains_key("--permissive-for-tests"),
    })
}

fn stop_file(path: Option<&Path>) -> Result<bool, String> {
    let Some(path) = path else { return Ok(false); };
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err("dispatch stop file must be regular, not a link or special file".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot inspect dispatch stop file: {e}")),
    }
}
fn now_millis() -> Result<u64, String> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "dispatch clock precedes epoch")?.as_millis()).map_err(|_| "dispatch clock overflow".into())
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    let mut output = std::io::stdout().lock();
    if args == ["--help"] {
        writeln!(output, "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    let signals = TerminationSignals::install().map_err(|e| format!("cannot own dispatch shutdown: {e}"))?;
    execute(&options, &|| Ok(signals.requested() || stop_file(options.stop_file.as_deref())?), &now_millis, &mut output)
}

fn with_node<T>(options: &Options, operation: impl FnOnce(&OneNode) -> Result<T, String>) -> Result<T, String> {
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)).map_err(|e| e.to_string())?;
    let result = node.bring_into_service(HeadGeneration::FIRST).map_err(|e| e.to_string())
        .and_then(|_| operation(&node));
    let cleanup = node.shutdown().map(|_| ());
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (result, cleanup) => Err(format!("dispatch source read/shutdown incomplete; previous attempts retain their journal status; read={:?}; shutdown={:?}",
            result.err(), cleanup.err())),
    }
}
struct Snapshot {
    incarnation: RepositoryIncarnationId,
    head: RepositoryAuthorityHeadId,
    entries: Vec<CanonicalOutboxStateEntry>,
}
fn snapshot(options: &Options) -> Result<Snapshot, String> {
    with_node(options, |node| {
        let request = fgit_cli::command_request_context(node);
        let page = node.runtime().block_on(node.read_forge_outbox_snapshot_in(&request, options.max_scan, None))
            .map_err(|e| e.to_string())?;
        Ok(Snapshot { incarnation: node.repository_incarnation_id(), head: page.source_head, entries: page.entries })
    })
}
fn registration(options: &Options) -> Result<(WebhookStore, WebhookRegistration), String> {
    let store = WebhookStore::open(options.storage.join("webhooks"))?;
    let registration = store.get(options.id).ok_or("dispatch webhook registration is missing")?;
    if !registration.active { return Err("dispatch webhook registration is inactive".into()); }
    let validated = options.policy().validate_url(registration.url.raw()).map_err(|e| e.to_string())?;
    if validated.scheme() != "http" { return Err("dispatch HTTPS is not supported; no TLS downgrade is permitted".into()); }
    let schedule = registration.retry_schedule;
    if !(2..=16).contains(&schedule.max_attempts)
        || schedule.initial_delay > Duration::from_secs(86400)
        || schedule.max_delay > Duration::from_secs(86400)
        || schedule.initial_delay > schedule.max_delay
    { return Err("dispatch retry schedule is outside the bounded 2..16 attempts/one-day delay profile".into()); }
    Ok((store, registration))
}

fn scope(options: &Options, incarnation: RepositoryIncarnationId, registration: &WebhookRegistration) -> [u8; 32] {
    let mut bytes = b"frankengit/local-webhook-scope/v1\0".to_vec();
    // Length framing avoids namespace/endpoint concatenation ambiguity. Secret
    // rotation and subscription narrowing do not reset durable attempt identity.
    for part in [options.tenant.to_string(), options.repository.to_string(), incarnation.to_string(),
        options.format.as_str().to_owned(), options.id.0.to_string(), options.destination.as_str().to_owned(),
        registration.url.raw().to_owned(), registration.retry_schedule.max_attempts.to_string(),
        registration.retry_schedule.initial_delay.as_nanos().to_string(), registration.retry_schedule.max_delay.as_nanos().to_string()]
    {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    sha256_digest(&bytes)
}
fn journal_path(options: &Options) -> PathBuf {
    // Endpoint/incarnation changes MUST hit the same slot and fail its header,
    // never quietly create a fresh attempt counter for an old delivery key.
    options.storage.join("webhooks").join(format!("dispatch-{}-{}.journal", options.id.0,
        hex(&sha256_digest(options.destination.as_bytes()))))
}
fn payload_hash(root: Digest) -> [u8; 32] {
    let mut input = root.algorithm().code_point().to_be_bytes().to_vec();
    input.extend_from_slice(root.bytes().as_bytes());
    sha256_digest(&input)
}
fn retry_at(schedule: WebhookRetrySchedule, key: AsciiSlug, attempt: u32, now: u64) -> Result<u64, String> {
    let digest = sha256_digest(key.as_bytes());
    let mut seed = [0; 8];
    seed.copy_from_slice(&digest[..8]);
    let delay = schedule.delay_for_attempt(attempt + 1, u64::from_le_bytes(seed));
    now.checked_add(u64::try_from(delay.as_millis()).map_err(|_| "dispatch retry delay overflow")?)
        .ok_or_else(|| "dispatch retry timestamp overflow".into())
}

#[derive(Default, Debug)]
struct Summary {
    considered: usize,
    attempts: usize,
    accepted: usize,
    rejected: usize,
    unknown: usize,
    pending: usize,
    filtered: usize,
    claimed: usize,
    stopped: bool,
}
impl Summary {
    fn exit_code(&self) -> u8 {
        if self.unknown > 0 { 3 } else if self.rejected > 0 { 2 }
        else if self.pending > 0 || self.stopped { 1 } else { 0 }
    }
    fn count_plan(&mut self, plan: Plan) {
        match plan {
            Plan::Settled { state: State::Accepted, .. } => self.accepted += 1,
            Plan::Settled { outcome_unknown, .. } | Plan::Exhausted { outcome_unknown } => {
                if outcome_unknown { self.unknown += 1; } else { self.rejected += 1; }
            }
            Plan::Due { outcome_unknown, .. } | Plan::Sleeping { outcome_unknown, .. } => {
                self.pending += 1;
                if outcome_unknown { self.unknown += 1; }
            }
        }
    }
}

fn emit(output: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(output, "{text}").and_then(|()| output.flush())
        .map_err(|e| format!("dispatch output failed; synced observations remain in the journal and a receiver may have accepted: {e}"))
}

fn execute(
    options: &Options,
    stop_signal: &impl Fn() -> Result<bool, String>,
    clock: &impl Fn() -> Result<u64, String>,
    output: &mut impl Write,
) -> Result<u8, String> {
    // Cancellation is a request, not a level-triggered pause. Removing a stop
    // file (or recovering from its I/O error) cannot resume an admitted drain.
    let stop_latched = Cell::new(false);
    let stopped = || {
        if stop_latched.get() { return Ok(true); }
        match stop_signal() {
            Ok(false) => Ok(false),
            result => { stop_latched.set(true); result }
        }
    };
    if stopped()? {
        emit(output, "{\"type\":\"webhook_dispatch_stopped\",\"schema_version\":1,\"attempts\":0,\"stopped\":true,\"drained\":true,\"canonical_settled\":false}")?;
        return Ok(1);
    }
    let (_, registration) = registration(options)?;
    let mut page = snapshot(options)?;
    let binding = scope(options, page.incarnation, &registration);
    let original_incarnation = page.incarnation;
    let max_attempts = registration.retry_schedule.max_attempts;
    // Keep only non-secret identity material across sweeps. A long-running
    // controller must not retain an obsolete signing secret after rotation.
    drop(registration);
    let mut journal = Journal::open(&journal_path(options), binding, max_attempts)?;
    loop {
        if page.incarnation != original_incarnation {
            return Err("dispatch repository incarnation changed; original journal retained".into());
        }
        let summary = sweep(options, &page, binding, &mut journal, &stopped, clock, output)?;
        emit(output, &format!(
            "{{\"type\":\"webhook_dispatch_sweep\",\"schema_version\":1,\"mode\":\"fenced-at-least-once\",\"source_head\":{},\"retained_entries\":{},\"considered\":{},\"attempts\":{},\"accepted\":{},\"rejected\":{},\"unknown\":{},\"pending\":{},\"filtered\":{},\"claimed_elsewhere\":{},\"stopped\":{},\"canonical_settled\":false}}",
            quote(&page.head.to_string()), page.entries.len(), summary.considered, summary.attempts, summary.accepted,
            summary.rejected, summary.unknown, summary.pending, summary.filtered, summary.claimed, summary.stopped))?;
        if !options.continuous || summary.stopped { return Ok(summary.exit_code()); }
        let mut remaining = options.poll;
        while !remaining.is_zero() {
            if stopped()? {
                emit(output, "{\"type\":\"webhook_dispatch_stopped\",\"schema_version\":1,\"stopped\":true,\"drained\":true,\"canonical_settled\":false}")?;
                return Ok(summary.exit_code().max(1));
            }
            let interval = remaining.min(Duration::from_millis(100));
            std::thread::sleep(interval);
            remaining = remaining.saturating_sub(interval);
        }
        if stopped()? {
            emit(output, "{\"type\":\"webhook_dispatch_stopped\",\"schema_version\":1,\"stopped\":true,\"drained\":true,\"canonical_settled\":false}")?;
            return Ok(summary.exit_code().max(1));
        }
        page = snapshot(options)?;
    }
}

fn sweep(
    options: &Options,
    page: &Snapshot,
    binding: [u8; 32],
    journal: &mut Journal,
    stopped: &impl Fn() -> Result<bool, String>,
    clock: &impl Fn() -> Result<u64, String>,
    output: &mut impl Write,
) -> Result<Summary, String> {
    let mut summary = Summary::default();
    let mut candidates: Vec<_> = page.entries.iter().filter(|entry|
        entry.destination() == options.destination && entry.effect_class() == AsciiSlug::from_static("forge-event")).collect();
    // Retried, due work precedes new work. Never persist a delivery-key cursor:
    // newly admitted keys can sort before every previously observed key.
    candidates.sort_by_key(|entry| (journal.due_at(entry.delivery_key()) == 0,
        journal.due_at(entry.delivery_key()), entry.delivery_key()));
    for entry in candidates {
        if stopped()? { summary.stopped = true; break; }
        summary.considered += 1;
        let key = entry.delivery_key();
        let payload = payload_hash(entry.payload_root());
        let plan = journal.plan(key, payload, clock()?)?;
        let Plan::Due { attempt, .. } = plan else { summary.count_plan(plan); continue; };
        if summary.attempts >= options.max_deliveries { summary.count_plan(plan); continue; }
        let selected = with_node(options, |node| {
            if node.repository_incarnation_id() != page.incarnation {
                return Err("dispatch repository incarnation changed during selection".into());
            }
            let request = fgit_cli::command_request_context(node);
            node.runtime().block_on(node.select_forge_delivery_in(&request, key, options.destination, None))
                .map_err(|e| e.to_string())
        })?;
        if selected.entry().payload_root() != entry.payload_root() {
            return Err("dispatch canonical payload changed; original key cannot be reused".into());
        }
        if !selected.is_unclaimed() {
            summary.claimed += 1;
            // Another owner does not resolve OUR previous ambiguous send.
            summary.unknown += usize::from(plan.outcome_unknown());
            continue;
        }
        let request = selected.as_request();
        let (store, registration) = registration(options)?;
        if scope(options, page.incarnation, &registration) != binding {
            return Err("dispatch endpoint or retry policy changed; original journal retained".into());
        }
        if require_subscription(&registration.filter, &request.events.events).is_err() {
            summary.filtered += 1;
            // Narrowing a subscription prevents new dispatch, but cannot
            // turn a retained unknown outcome into an apparent success.
            summary.unknown += usize::from(plan.outcome_unknown());
            continue;
        }
        if stopped()? { summary.stopped = true; break; }
        let schedule = registration.retry_schedule;
        let mut destination = WebhookDeliveryDestination::new(options.destination, registration, options.policy(), store.dead_letters());
        destination.timeout = options.timeout;
        let now = clock()?;
        let ordinal = journal.reserve(key, payload, now, retry_at(schedule, key, attempt, now)?)?;
        summary.attempts += 1;
        // The durable reservation and closed repository runtime precede every
        // call, even if cancellation fires immediately after the reservation.
        let checkpoint = || match stopped() {
            Ok(false) => Ok(()),
            _ => Err(fgit_types::RefusalCode::CancellationInProgress),
        };
        let response = destination.deliver_request_with_checkpoint(&request, ordinal, &checkpoint);
        let (state, observation_source, evidence) = match response {
            Ok(("Accepted" | "DuplicateSuppressed", bytes)) => (State::Accepted, "transport-verdict", bytes),
            Ok(("PermanentRejection", bytes)) => (State::Rejected, "transport-verdict", bytes),
            Ok(("TransientFailure", bytes)) => (State::Retryable, "transport-verdict", bytes),
            Ok((_, bytes)) => (State::Unknown, "transport-verdict", bytes),
            // Preserve a digest of the actual adapter refusal, not a made-up
            // receiver response. An adapter error is not proof of non-delivery.
            Err(detail) => (State::Unknown, "adapter-refusal", detail.into_bytes()),
        };
        let completed = clock()?;
        journal.observe(key, state, completed, retry_at(schedule, key, ordinal, completed)?, &evidence)?;
        let next = journal.plan(key, payload, completed)?;
        summary.count_plan(next);
        let unknown = next.outcome_unknown();
        emit(output, &format!(
            "{{\"type\":\"webhook_dispatch_observation\",\"schema_version\":1,\"mode\":\"fenced-at-least-once\",\"delivery_id\":{},\"destination\":{},\"payload_root\":{},\"source_head\":{},\"attempt\":{},\"state\":{},\"observation_source\":{},\"evidence_sha256\":{},\"retry_may_duplicate\":{},\"outcome_unknown\":{},\"journal_synced\":true,\"node_closed\":true,\"canonical_settled\":false}}",
            quote(key.as_str()), quote(options.destination.as_str()), quote(&entry.payload_root().to_string()),
            quote(&selected.source_head().to_string()), ordinal, quote(state.name()), quote(observation_source), quote(&hex(&sha256_digest(&evidence))), ordinal > 1, unknown))?;
    }
    // A signal can arrive during the final attempt, even with no next entry
    // to trigger the loop's stop checkpoint. Report that drain explicitly.
    summary.stopped |= stopped()?;
    Ok(summary)
}

#[cfg(all(test, unix))]
mod tests;
