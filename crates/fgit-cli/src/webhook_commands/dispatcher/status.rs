//! Read-only local dispatch diagnostics, including while a worker is running.
//! This path cannot reserve attempts, sync journals, send HTTP or settle outbox
//! state. A complete observed prefix is not necessarily a durable observation.

use super::{AsciiSlug, BTreeMap, Duration, GitHashAlgorithm, Options,
    RepositoryIncarnationId, WebhookId, hex, journal, journal_path, now_millis,
    number, quote, registration_snapshot, scope, with_node};
use std::io::Write;

const MAX_OUTPUT: usize = 256 * 1024;
const USAGE: &str = "usage: fg webhook dispatch-status <storage-root> <tenant-id> <repository-id> --trusted-local
  --id <registered-id> --destination <canonical-destination>
  [--object-format sha1|sha256] [--limit <1..100>]
  [--after <delivery-id> --expected-tail <64-lowercase-hex>]

Inspect a bounded local journal prefix without acquiring the dispatch fence or
contacting a receiver. No --at-least-once flag is accepted: this is not a send.
Missing journals are distinct from empty history; missing one half of an existing
journal/fence pair, torn tails and corrupt checkpoints refuse. Local counts do
not describe the canonical pending outbox. A live owner's complete append may
still be unsynced: durability_verified is always false. Continuations require
the prior journal_tail_sha256 and refuse when append or compaction changes it.
Configuration mismatch/unavailability remains visible without hiding retained
failures. Exit 0 means the status read completed, not that deliveries succeeded.";

struct Query {
    options: Options,
    after: Option<AsciiSlug>,
    limit: usize,
    expected_tail: Option<[u8; 32]>,
}

fn parse(args: &[String]) -> Result<Query, String> {
    if args.len() < 4 || args.len() > 18 || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[0].is_empty() || args[0].len() > 4096
    { return Err(USAGE.into()); }
    let (storage, tenant, repository, mut index) = super::super::parse_base(args)?;
    let mut fields = BTreeMap::new();
    while index < args.len() {
        let flag = args[index].as_str();
        if !matches!(flag, "--id" | "--destination" | "--object-format" | "--limit" | "--after" | "--expected-tail") {
            return Err(format!("unknown read-only dispatch status option {flag}"));
        }
        let value = args.get(index + 1).filter(|v| !v.is_empty() && !v.starts_with("--"))
            .ok_or_else(|| format!("missing dispatch status value for {flag}"))?;
        if fields.insert(flag, value.as_str()).is_some() { return Err(format!("duplicate dispatch status option {flag}")); }
        index += 2;
    }
    let id = WebhookId(number(fields.get("--id").ok_or("missing --id")?, 0, u64::MAX)?);
    let destination = AsciiSlug::try_new("dispatch destination",
        fields.get("--destination").ok_or("missing --destination")?.as_bytes()).map_err(|e| e.to_string())?;
    let format = match fields.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("status object format must be sha1 or sha256".into()),
    };
    let after = fields.get("--after").map(|value|
        AsciiSlug::try_new("dispatch status cursor", value.as_bytes()).map_err(|e| e.to_string())).transpose()?;
    let expected_tail = fields.get("--expected-tail").map(|value| journal::unhex(value)).transpose()?;
    if after.is_some() && expected_tail.is_none() {
        return Err("dispatch status continuation requires the original --expected-tail".into());
    }
    Ok(Query { options: Options { storage, tenant, repository, format, id, destination,
        max_deliveries: 16, max_scan: 16384, timeout: Duration::from_secs(5),
        continuous: false, stop_file: None, poll: Duration::from_secs(1), permissive: false },
        after, limit: number(fields.get("--limit").copied().unwrap_or("20"), 1, 100)? as usize,
        expected_tail })
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    let mut output = std::io::stdout().lock();
    if args == ["--help"] {
        writeln!(output, "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    execute(args, &now_millis, &mut output)
}

pub(super) fn execute(args: &[String], clock: &impl Fn() -> Result<u64, String>,
    output: &mut impl Write) -> Result<u8, String>
{
    let query = parse(args)?;
    // Authentication of the existing repository binding and node shutdown
    // precede status output. No canonical outbox scan or send is performed.
    let incarnation = with_node(&query.options, |node| Ok(node.repository_incarnation_id()))?;
    // Configuration is diagnostic here, not permission to send. Keep retained
    // unknown outcomes inspectable when a registration was disabled or removed,
    // its URL/schedule changed, or the local configuration cannot be loaded.
    // In particular, do not create a missing webhooks directory for a read.
    let configured = if query.options.storage.join("webhooks").is_dir() {
        registration_snapshot(&query.options).ok().map(|(_, registration)|
            (scope(&query.options, incarnation, &registration), registration.active, registration.retry_schedule.max_attempts))
    } else { None };
    let inspection = journal::inspect(&journal_path(&query.options), query.after, query.limit, query.expected_tail)?;
    let body = render(&query, incarnation, configured, clock().ok(), &inspection)?;
    writeln!(output, "{body}").and_then(|()| output.flush())
        .map_err(|e| format!("dispatch status output incomplete; this command attempted no delivery: {e}"))?;
    Ok(0)
}

fn optional(value: Option<String>) -> String { value.unwrap_or_else(|| "null".into()) }
fn digest(value: Option<[u8; 32]>) -> String { optional(value.map(|v| quote(&hex(&v)))) }
fn decimal_string(value: Option<u64>) -> String { optional(value.map(|v| quote(&v.to_string()))) }
fn boolean(value: Option<bool>) -> String { optional(value.map(|v| v.to_string())) }

fn render(query: &Query, incarnation: RepositoryIncarnationId,
    configured: Option<([u8; 32], bool, u32)>, clock: Option<u64>, page: &journal::Inspection) -> Result<String, String>
{
    let options = &query.options;
    let counts = &page.counts;
    let current_scope = configured.map(|value| value.0);
    let same_scope = page.scope.zip(current_scope).map(|(stored, current)| stored == current);
    let mut out = format!(
        "{{\"type\":\"webhook_dispatch_status\",\"schema_version\":1,\"observation_profile\":\"local-journal-prefix-v2\",\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},\"webhook_id\":\"{}\",\"destination\":{},\"journal_present\":{},\"observed_bytes\":{},\"journal_scope_sha256\":{},\"configured_scope_sha256\":{},\"scope_matches_current\":{},\"configuration_available\":{},\"registration_active\":{},\"configured_attempt_limit\":{},\"journal_attempt_limit\":{},\"journal_tail_sha256\":{},\"clock_floor_millis\":{},\"wall_clock_millis\":{},\"clock_behind_floor\":{},\"counts\":{{\"recorded_deliveries\":{},\"in_flight\":{},\"accepted\":{},\"rejected\":{},\"retryable\":{},\"unknown\":{},\"unresolved\":{},\"exhausted\":{}}},\"after\":{},\"limit\":{},\"entries\":[",
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(&incarnation.to_string()),
        quote(options.format.as_str()), options.id.0, quote(options.destination.as_str()), page.present, page.bytes,
        digest(page.scope), digest(current_scope), boolean(same_scope), configured.is_some(),
        boolean(configured.map(|value| value.1)), optional(configured.map(|value| value.2.to_string())),
        optional(page.max_attempts.map(|value| value.to_string())), digest(page.tail), decimal_string(page.clock_floor),
        decimal_string(clock), boolean(clock.zip(page.clock_floor).map(|(now, floor)| now < floor)),
        counts.total, counts.in_flight, counts.accepted, counts.rejected, counts.retryable, counts.unknown,
        counts.unresolved, counts.exhausted, optional(query.after.map(|value| quote(value.as_str()))), query.limit);
    for (index, row) in page.rows.iter().enumerate() {
        let text = format!(
            "{}{{\"delivery_id\":{},\"payload_binding_sha256\":{},\"attempt\":{},\"observed_at_millis\":\"{}\",\"next_at_millis\":\"{}\",\"state\":{},\"uncertainty_retained\":{},\"outcome_unknown\":{},\"exhausted\":{},\"evidence_sha256\":{}}}",
            if index == 0 { "" } else { "," }, quote(row.key.as_str()), quote(&hex(&row.payload)), row.attempt,
            row.observed_at, row.next_at, quote(row.state.name()), row.uncertain, row.outcome_unknown,
            row.exhausted, quote(&hex(&row.evidence)));
        append(&mut out, &text)?;
    }
    append(&mut out, &format!(
        "],\"next_after\":{},\"has_more\":{},\"read_only\":true,\"journal_modified\":false,\"transport_attempted\":false,\"durability_verified\":false,\"canonical_settled\":false,\"node_closed\":true}}",
        optional(page.next_after.map(|value| quote(value.as_str()))), page.next_after.is_some()))?;
    Ok(out)
}

fn append(out: &mut String, value: &str) -> Result<(), String> {
    if out.len().checked_add(value.len()).is_none_or(|size| size > MAX_OUTPUT) {
        return Err("dispatch status response exceeds 256 KiB".into());
    }
    out.try_reserve(value.len()).map_err(|_| "dispatch status output allocation refused")?;
    out.push_str(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        ["missing", "11111111111111111111111111111111", "22222222222222222222222222222222",
            "--trusted-local", "--id", "7", "--destination", "forge-events"].map(str::to_owned).to_vec()
    }
    #[test]
    fn read_only_status_rejects_effect_flags_bad_numbers_and_unpinned_continuations() {
        assert!(parse(&args()).is_ok());
        for extra in [vec!["--at-least-once"], vec!["--continuous"], vec!["--permissive-for-tests"],
            vec!["--attempt", "2"], vec!["--id", "8"], vec!["--limit", "0"], vec!["--limit", "101"],
            vec!["--limit", "01"], vec!["--after", "some-key"], vec!["--expected-tail", "bad"],
            vec!["--object-format", "sha512"]]
        {
            let mut a = args(); a.extend(extra.iter().map(|v| (*v).to_owned()));
            assert!(parse(&a).is_err(), "{extra:?}");
        }
        let mut a = args();
        a.extend(["--after".into(), "some-key".into(), "--expected-tail".into(), "ab".repeat(32), "--limit".into(), "100".into()]);
        let parsed = parse(&a).unwrap();
        assert_eq!(parsed.limit, 100);
        assert_eq!(parsed.expected_tail, Some([0xab; 32]));
    }

    #[test]
    fn absent_journal_is_not_reported_as_a_completed_canonical_queue() {
        let query = parse(&args()).unwrap();
        let out = render(&query, RepositoryIncarnationId::from_bytes([3; 16]), None, None, &journal::Inspection::default()).unwrap();
        for text in ["\"journal_present\":false", "\"scope_matches_current\":null", "\"configuration_available\":false",
            "\"durability_verified\":false", "\"transport_attempted\":false", "\"canonical_settled\":false"]
        { assert!(out.contains(text), "{text}"); }
        assert!(out.len() < MAX_OUTPUT);
    }

    #[test]
    fn status_output_budget_refuses_instead_of_truncating_json() {
        let mut output = "x".repeat(MAX_OUTPUT - 1);
        append(&mut output, "x").unwrap();
        let old = output.clone();
        assert!(append(&mut output, "x").is_err());
        assert_eq!(output, old);
    }
}
