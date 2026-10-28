//! Versioned diagnostic JSON. SHA-256 binds the complete JSON payload before
//! adding receipt_sha256, including predicate, incarnation, observed authority,
//! full native identity domains, limits, publication domain and every probe.
use super::{
    BisectionTermination, GitHashAlgorithm, IssueState, PROFILE, Predicate, PullState, Report,
    RepositoryAuthorityHeadId, fold,
};
use fgit_forge::bisection::{BisectionRefusal, PredicateOutcome};
use std::fmt::Write;

#[must_use]
pub fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "head:alg:{}:codec:{}.{}:{}",
        id.algorithm().code_point(),
        id.codec_version().major(),
        id.codec_version().minor(),
        hex(id.digest().as_bytes())
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if ch < '\u{20}' => {
                write!(out, "\\u{:04x}", ch as u32).unwrap();
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}
const fn state(state: PullState) -> &'static str {
    match state {
        PullState::Open => "open",
        PullState::Closed => "closed",
        PullState::Merged => "merged",
    }
}
fn predicate(value: &Predicate) -> String {
    match value {
        Predicate::RefEquals { name, target } => format!(
            "{{\"kind\":\"ref_equals\",\"ref_hex\":{},\"oid\":{}}}",
            quote(&hex(name.as_bytes())),
            quote(&target.to_string())
        ),
        Predicate::RefAbsent { name } => format!(
            "{{\"kind\":\"ref_absent\",\"ref_hex\":{}}}",
            quote(&hex(name.as_bytes()))
        ),
        Predicate::PolicyAtLeast(epoch) => format!(
            "{{\"kind\":\"policy_at_least\",\"epoch\":\"{}\"}}",
            epoch.get()
        ),
        Predicate::IssueState { number, state } => format!(
            "{{\"kind\":\"issue_state\",\"number\":\"{}\",\"state\":\"{}\"}}",
            number.get(),
            if *state == IssueState::Open {
                "open"
            } else {
                "closed"
            }
        ),
        Predicate::PullRequestState {
            number,
            state: value,
        } => format!(
            "{{\"kind\":\"pull_request_state\",\"number\":\"{}\",\"state\":\"{}\"}}",
            number.get(),
            state(*value)
        ),
    }
}
pub(super) fn positions_digest(points: &[fold::Point]) -> String {
    let mut bytes = b"fgit-bisection-published-domain-v1\0".to_vec();
    bytes.extend_from_slice(&(points.len() as u64).to_be_bytes());
    for point in points {
        bytes.extend_from_slice(&point.sequence.get().to_be_bytes());
        let mut id = fgit_codec::Encoder::new();
        id.write_internal_object_id(point.head.as_internal_object_id())
            .expect("typed head ID");
        bytes.extend_from_slice(id.as_bytes());
    }
    hex(&fgit_crypto::sha256_digest(&bytes))
}
const fn refusal(error: &BisectionRefusal) -> &'static str {
    match error {
        BisectionRefusal::BudgetExhausted { .. } => "probe_budget_exhausted",
        BisectionRefusal::Cancelled { .. } => "request_stopped",
        BisectionRefusal::MissingPosition { .. } => "missing_position",
        BisectionRefusal::CorruptSnapshot { .. } => "corrupt_snapshot",
        BisectionRefusal::RevokedDisclosure { .. } => "revoked_disclosure",
        BisectionRefusal::NonMonotoneDetected { .. } => "non_monotone",
        BisectionRefusal::InvalidRange { .. } | BisectionRefusal::AmbiguousRange { .. } => {
            "invalid_range"
        }
        BisectionRefusal::PredicateEvaluationFailed { .. } => "predicate_failed",
        BisectionRefusal::SnapshotRefusal(_) => "snapshot_refused",
    }
}
pub(super) fn render(report: &Report) -> String {
    let search = &report.search;
    let status = if !report.complete() {
        "refused"
    } else if report.matched() {
        "matched"
    } else {
        "not_found"
    };
    let shape = if matches!(report.query.predicate, Predicate::PolicyAtLeast(_)) {
        "verified_non_decreasing_policy_epoch"
    } else {
        "exhaustive_published_states"
    };
    let error = match &search.termination {
        BisectionTermination::Refused { reason } => format!(
            "{{\"code\":{},\"detail\":{}}}",
            quote(refusal(reason)),
            quote(&reason.to_string())
        ),
        _ => "null".into(),
    };
    let mut payload = format!(
        "{{\"type\":\"forge_bisection\",\"schema_version\":1,\"profile\":{profile},\"authorization\":\"trusted_local_whole_repository\",\"tenant_id\":{tenant},\"repository_id\":{repository},\"repository_incarnation_id\":{incarnation},\"object_format\":{format},\"source_head\":{head},\"source_generation\":\"{generation}\",\"current_policy_epoch\":\"{epoch}\",\"predicate\":{predicate},\"requested_start\":\"{start}\",\"requested_end\":{requested_end},\"end\":\"{end}\",\"expected_head\":{expected},\"max_probes\":{limit},\"history_batches\":{batches},\"history_events\":{events},\"published_positions\":{positions},\"positions_sha256\":{domain},\"strategy\":{strategy},\"status\":{status},\"complete\":{complete},\"first_match\":{found},\"error\":{error},\"steps_taken\":{steps},\"probes\":[",
        profile = quote(PROFILE),
        tenant = quote(&report.tenant.to_string()),
        repository = quote(&report.repository.to_string()),
        incarnation = quote(&report.incarnation.to_string()),
        format = quote(if report.format == GitHashAlgorithm::Sha1 {
            "sha1"
        } else {
            "sha256"
        }),
        head = quote(&head_token(report.source_head)),
        generation = report.source_generation,
        epoch = report.current_policy_epoch.get(),
        predicate = predicate(&report.query.predicate),
        start = report.query.start.get(),
        requested_end = report
            .query
            .end
            .map_or("null".into(), |end| quote(&end.get().to_string())),
        end = search.range.end().get(),
        expected = report
            .query
            .expected_head
            .map_or("null".into(), |head| quote(&head_token(head))),
        limit = report.query.max_probes,
        batches = report.history_batches,
        events = report.history_events,
        positions = report.published_positions,
        domain = quote(&report.positions_digest),
        strategy = quote(shape),
        status = quote(status),
        complete = report.complete(),
        found = search
            .transition_found
            .map_or("null".into(), |at| quote(&at.get().to_string())),
        steps = search.steps_taken
    );
    for (i, probe) in search.probes.iter().enumerate() {
        if i != 0 {
            payload.push(',');
        }
        let outcome = match &probe.outcome {
            Ok(PredicateOutcome::Satisfied) => "true".into(),
            Ok(PredicateOutcome::Unsatisfied) => "false".into(),
            Err(error) => quote(error),
        };
        write!(payload, "{{\"sequence\":\"{}\",\"head\":{},\"policy_epoch\":\"{}\",\"replayed_batches\":{},\"outcome\":{}}}", probe.sequence.get(), quote(&head_token(probe.head_id)), probe.policy_epoch.get(), probe.replayed_batches, outcome).unwrap();
    }
    payload.push_str("]}");
    let digest = hex(&fgit_crypto::sha256_digest(payload.as_bytes()));
    payload.pop();
    write!(payload, ",\"receipt_sha256\":\"{digest}\"}}").unwrap();
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_quotes_preserve_controls_and_unicode_without_interpreting_them() {
        assert_eq!(quote("a\"\\\n\t\0é"), "\"a\\\"\\\\\\u000a\\u0009\\u0000é\"");
    }
}
