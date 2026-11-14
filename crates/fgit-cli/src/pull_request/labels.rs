//! Exact-version PR label replacement through the independent canonical stream.
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use fgit_admission::merge::native::pull_request::PullRequestView;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::pull_request_labels::{MAX_LABELS, PullRequestLabelsCommand, validate_labels};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, RepositoryAuthorityHeadId, RepositoryId, TenantId, TxId};

use super::options::{decimal, head_token, parse_head};
use crate::publication_support::{describe, quote, write_terminal_receipt};

const USAGE: &str = "\
usage: fg pr labels <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local [--expected-head <snapshot-token>] [--object-format sha1|sha256]
usage: fg pr set-labels <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local --principal <id> --idempotency-key <key>
  --expected-version <labels_version; 0 if never set>
  (--label <literal-text> [--label <literal-text> ...] | --clear-labels)
  [--object-format sha1|sha256]

Replace the complete label set of an existing visible native PR. Labels have
their own exact version; this does not change the PR lifecycle version, refs,
review subject, or approval freshness. Open, closed and merged PRs can be labeled.
Supply at most 32 distinct nonblank labels, each at most 64 UTF-8 bytes without
control characters. Input order is canonicalized; spelling and spaces are kept.
An unset label stream reads as labels_version 0 and an empty set. Clearing an
existing set advances its label version; it does not make the stream unset.
Retry an uncertain write with the identical principal, key, PR number, expected
label version and complete label set. Never refresh its version or change its
key while reconciling an unknown outcome. No latest-state read invents a receipt.
Exit 0: complete read or committed replacement; 3: canonical refusal;
4: PR absent or hidden; 2: input/infrastructure/cleanup/output failure.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    number: PullRequestNumber,
    operation: Operation,
}

#[derive(Debug)]
enum Operation {
    Read { expected_head: Option<RepositoryAuthorityHeadId> },
    Set { principal: PrincipalId, key: Vec<u8>, command: PullRequestLabelsCommand },
}

fn parse(args: &[String]) -> Result<Options, String> {
    if !(6..=96).contains(&args.len()) || args.iter().any(|arg| arg.len() > 4096)
        || args.iter().map(String::len).sum::<usize>() > 24 * 1024 {
        return Err(USAGE.into());
    }
    let writing = match args[0].as_str() {
        "labels" => false,
        "set-labels" => true,
        _ => return Err(USAGE.into()),
    };
    if args[1].is_empty() { return Err("storage root is required".into()); }
    let number = PullRequestNumber::try_new(decimal(&args[4])?).ok_or("a positive PR number is required")?;
    let mut flags = BTreeMap::new();
    let mut labels = Vec::new();
    let (mut trusted, mut clear) = (false, false);
    let mut cursor = 5;
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".into()); }
            trusted = true;
            continue;
        }
        if writing && flag == "--clear-labels" {
            if clear { return Err("duplicate --clear-labels".into()); }
            clear = true;
            continue;
        }
        if flag != "--object-format" && !(if writing {
            matches!(flag, "--principal" | "--idempotency-key" | "--expected-version" | "--label")
        } else { flag == "--expected-head" }) {
            return Err(format!("unknown or inapplicable PR labels option: {flag}"));
        }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if flag == "--label" {
            if labels.len() == MAX_LABELS { return Err("too many PR labels".into()); }
            labels.push(value.clone());
        } else if flags.insert(flag, value.as_str()).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !trusted { return Err("PR label access requires --trusted-local".into()); }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("--object-format must be sha1 or sha256".into()),
    };
    let required = |flag: &str| flags.get(flag).copied().ok_or_else(|| format!("missing {flag}"));
    let operation = if writing {
        if clear != labels.is_empty() {
            return Err("supply labels or --clear-labels, never both or neither".into());
        }
        labels.sort();
        validate_labels(&labels).map_err(|_| "invalid or duplicate PR labels")?;
        let version = decimal(required("--expected-version")?)?;
        let expected_version = if version == 0 { ExpectedVersion::NewStream } else {
            let version = AggregateVersion::try_new(version).ok_or("invalid label version")?;
            version.next().map_err(|_| "label version exhausted")?;
            ExpectedVersion::Exactly(version)
        };
        let principal = PrincipalId::from_hex(required("--principal")?).map_err(|_| "invalid principal ID")?;
        let key = required("--idempotency-key")?.as_bytes().to_vec();
        IdempotencyKey::new(key.clone()).map_err(|_| "invalid bounded idempotency key")?;
        let command = PullRequestLabelsCommand { number, expected_version, labels };
        command.proposed_event(principal).map_err(|_| "invalid PR labels command")?;
        Operation::Set { principal, key, command }
    } else {
        Operation::Read { expected_head: flags.get("--expected-head").map(|value| parse_head(value)).transpose()? }
    };
    Ok(Options {
        storage: args[1].clone().into(),
        tenant: TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?,
        repository: RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?,
        format, number, operation,
    })
}

pub(super) fn run(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args.len() == 2 && args[1] == "--help" {
        return super::write_read_report(out, USAGE).map(|()| 0);
    }
    let options = parse(args)?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)).map_err(|error| format!("cannot open PR labels node: {error}"))?;
    let incarnation = node.repository_incarnation_id().to_string();
    let operation = (|| -> Result<Completed, String> {
        let authority = node.runtime().block_on(node.authenticate_authority_head()).map_err(|error| error.to_string())?;
        // Both observations and publications require a successfully activated node.
        // A failed authority/service transition must never fall through to the
        // durable write path, even if a later admission check would also refuse.
        node.bring_into_service(authority.receipt().generation())
            .map_err(|error| error.to_string())?;
        let context = fgit_cli::command_request_context(&node);
        match &options.operation {
            Operation::Read { expected_head } => {
                let page = node.runtime().block_on(node.read_pull_requests_in(&context, &Default::default(), options.number.get()-1, 1, *expected_head))
                    .map_err(|error| error.to_string())?;
                if expected_head.is_some_and(|head| head != page.source_head)
                    || page.pull_requests.len() > 1 || page.pull_requests.iter().any(|row| row.number < options.number) {
                    return Err("invalid pinned PR label read".into());
                }
                let row = page.pull_requests.first().filter(|row| row.number == options.number && row.data.is_some());
                let report = read_report(&options, &incarnation, page.source_head, row)?;
                Ok(Completed::Read(report, if row.is_some() { 0 } else { 4 }))
            }
            Operation::Set { principal, key, command } => {
                let session = LoopbackReceiveSession::authenticated(*principal, IdempotencyKey::new(key.clone()).map_err(|_| "invalid key")?);
                node.runtime().block_on(node.admit_pull_request_labels_durable_in(&context, &session, command, Default::default()))
                    .map(Completed::Set).map_err(|error| error.to_string())
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match operation {
        Ok(Completed::Set((tx, terminal))) => {
            let report = mutation_report(&options, &incarnation, tx, &terminal, cleanup.as_deref())?;
            if let Err(error) = write_terminal_receipt(out, &report, tx, &terminal) {
                return Err(with_cleanup(error, cleanup.as_deref()));
            }
            if let Some(error) = cleanup { return Err(format!("{}; PR labels node shutdown failed: {error}", describe(tx, &terminal))); }
            Ok(if matches!(terminal.outcome, DecisionOutcome::Committed { .. }) { 0 } else { 3 })
        }
        Ok(Completed::Read(report, exit)) => {
            if let Some(error) = cleanup { return Err(format!("PR labels node shutdown failed: {error}")); }
            super::write_read_report(out, &report)?;
            Ok(exit)
        }
        Err(error) => {
            let error = with_cleanup(error, cleanup.as_deref());
            Err(if matches!(options.operation, Operation::Set { .. }) {
                format!("no terminal PR label outcome returned: {error}; this does not prove non-commit. Retry the identical principal, key, PR number, expected label version and complete label set; do not refresh expectations or replace the key")
            } else { format!("PR labels read failed: {error}; no complete result returned") })
        }
    }
}

enum Completed { Set((TxId, TerminalOutcome)), Read(String, u8) }
fn with_cleanup(error: String, cleanup: Option<&str>) -> String {
    cleanup.map_or_else(|| error.clone(), |cleanup| format!("{error}; node shutdown also failed: {cleanup}"))
}
pub(super) fn labels_json(labels: &[String]) -> String {
    format!("[{}]", labels.iter().map(|label| quote(label)).collect::<Vec<_>>().join(","))
}
fn read_report(options: &Options, incarnation: &str, head: RepositoryAuthorityHeadId, row: Option<&PullRequestView>) -> Result<String, String> {
    if let Some(row) = row {
        if row.number != options.number || row.data.is_none() { return Err("invalid PR labels subject".into()); }
        validate_labels(&row.labels).map_err(|_| "invalid PR label set")?;
        if row.labels_version.is_some() != row.labels_actor.is_some()
            || (row.labels_version.is_none() && !row.labels.is_empty()) { return Err("invalid PR label stream".into()); }
    }
    Ok(format!(concat!(
        "{{\"type\":\"pull_request_labels\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"repository_incarnation\":{},\"object_format\":{},\"number\":{},\"found\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"pull_request_version\":{},\"labels_version\":{},\"labels_actor\":{},\"labels\":{},\"complete\":true,\"read_only\":true,\"transaction_created\":false,\"node_closed\":true}}"),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(incarnation), quote(options.format.as_str()),
        quote(&options.number.get().to_string()), row.is_some(), quote(&head.to_string()), quote(&head_token(head)),
        row.map_or_else(|| "null".into(), |row| quote(&row.event.version.get().to_string())),
        row.map_or_else(|| "null".into(), |row| quote(&row.labels_version.map_or(0, |version| version.get()).to_string())),
        row.and_then(|row| row.labels_actor).map_or_else(|| "null".into(), |actor| quote(&actor.to_string())),
        row.map_or_else(|| "null".into(), |row| labels_json(&row.labels)),
    ))
}
fn mutation_report(options: &Options, incarnation: &str, tx: TxId, terminal: &TerminalOutcome, cleanup: Option<&str>) -> Result<String, String> {
    let Operation::Set { principal, command, .. } = &options.operation else { return Err("invalid label result operation".into()); };
    let (outcome, committed, rcr, code, refusal) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => ("committed", true, quote(&repository_commit_id.to_string()), "null".into(), "null".into()),
        DecisionOutcome::Refused { code, refusal_record_id } => ("refused", false, "null".into(), quote(&format!("{code:?}")), quote(&refusal_record_id.to_string())),
    };
    let expected = match command.expected_version { ExpectedVersion::NewStream => 0, ExpectedVersion::Exactly(version) => version.get() };
    Ok(format!(concat!(
        "{{\"type\":\"pull_request_labels_publication\",\"schema_version\":1,\"action\":\"set-labels\",\"tenant_id\":{},\"repository_id\":{},",
        "\"repository_incarnation\":{},\"object_format\":{},\"principal_id\":{},\"number\":{},\"expected_version\":{},\"labels\":{},\"labels_version\":{},",
        "\"tx_id\":{},\"decision_sequence\":{},\"outcome\":{},\"command_committed\":{},\"repository_commit_id\":{},\"refusal_code\":{},\"refusal_record_id\":{},",
        "\"refs_changed\":false,\"pull_request_version_changed\":false,\"historical_outcome\":true,\"outcome_unknown\":false,\"read_only\":false,\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}"),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(incarnation), quote(options.format.as_str()), quote(&principal.to_string()),
        quote(&command.number.get().to_string()), quote(&expected.to_string()), labels_json(&command.labels),
        if committed { quote(&(expected + 1).to_string()) } else { "null".into() },
        quote(&tx.to_string()), quote(&terminal.decision_sequence.get().to_string()),
        quote(outcome), committed, rcr, code, refusal, cleanup.is_none(), cleanup.map_or_else(|| "null".into(), quote),
    ))
}
