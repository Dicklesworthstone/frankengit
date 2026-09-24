//! Trusted-local configuration of mandatory, canonical required-review policy.
use crate::publication_support::{describe, quote, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::protection::{
    MAX_BRANCH_REVIEWERS, MAX_POLICY_ADMINISTRATORS, MAX_PROTECTED_BRANCHES, ProtectedBranch,
    ProtectionCommand, ReviewProtection,
};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RepositoryId, TenantId, TxId,
};
use std::{collections::BTreeMap, io::Write, path::PathBuf};

const USAGE: &str = "usage: fg protection show <storage-root> <tenant-id> <repository-id> --trusted-local [--object-format sha1|sha256]\n\
usage: fg protection set <storage-root> <tenant-id> <repository-id> --trusted-local\n\
  --principal <id> --idempotency-key <key> --expected-version <0-for-first-install> --expected-epoch <current-epoch>\n\
  --admin <id> [--admin <id> ...]\n\
  (--require-reviewer <refs/heads/branch>:<id> [...] | --clear)\n\
  [--object-format sha1|sha256]\n\
Set replaces the COMPLETE policy. Every listed reviewer is mandatory for that branch.\n\
--clear disables branch protection but retains explicit administrators and immutable history.\n\
Current administrators authorize replacement; the new list does not authorize itself.\n\
All embedded-node ref publications enforce installed rules. No per-mutation opt-in is needed.\n\
First installation requires a trusted repository operator; this is not remote authentication.";

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    operation: Operation,
}
enum Operation {
    Show,
    Set {
        principal: PrincipalId,
        key: IdempotencyKey,
        command: ProtectionCommand,
    },
}
fn number(s: &str) -> Result<u64, String> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("expected a canonical unsigned integer".into());
    }
    s.parse().map_err(|_| "integer overflow".into())
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5
        || args.len() > 4352
        || args.iter().any(|s| s.len() > 4096)
        || args.iter().map(String::len).sum::<usize>() > 256 * 1024
    {
        return Err(USAGE.into());
    }
    let set = match args[0].as_str() {
        "set" => true,
        "show" => false,
        _ => return Err(USAGE.into()),
    };
    if args[1].is_empty() {
        return Err("storage root is required".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let mut singleton = BTreeMap::new();
    let (mut trusted, mut clear) = (false, false);
    let mut admins = Vec::new();
    let mut branches = BTreeMap::<RefName, Vec<PrincipalId>>::new();
    let mut i = 4;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".into());
            }
            trusted = true;
            continue;
        }
        if flag == "--clear" {
            if !set || clear {
                return Err("--clear is permitted once for set".into());
            }
            clear = true;
            continue;
        }
        if flag != "--object-format"
            && (!set
                || !matches!(
                    flag,
                    "--principal"
                        | "--idempotency-key"
                        | "--expected-version"
                        | "--expected-epoch"
                        | "--admin"
                        | "--require-reviewer"
                ))
        {
            return Err(format!(
                "unknown or inapplicable protection option {flag:?}"
            ));
        }
        let value = args
            .get(i)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        i += 1;
        match flag {
            "--admin" => {
                if admins.len() == MAX_POLICY_ADMINISTRATORS {
                    return Err("too many administrators".into());
                }
                admins.push(PrincipalId::from_hex(value).map_err(|_| "invalid administrator ID")?);
            }
            "--require-reviewer" => {
                let (name, id) = value
                    .rsplit_once(':')
                    .ok_or("reviewer must be full-branch:principal-id")?;
                let name =
                    RefName::try_new(name.as_bytes()).map_err(|_| "invalid branch reference")?;
                if !name.as_bytes().starts_with(b"refs/heads/") {
                    return Err("only full branch names may be protected".into());
                }
                let id = PrincipalId::from_hex(id).map_err(|_| "invalid reviewer ID")?;
                if !branches.contains_key(&name) && branches.len() == MAX_PROTECTED_BRANCHES {
                    return Err("too many protected branches".into());
                }
                let reviewers = branches.entry(name).or_default();
                if reviewers.len() == MAX_BRANCH_REVIEWERS {
                    return Err("too many branch reviewers".into());
                }
                reviewers.push(id);
            }
            _ => {
                if singleton.insert(flag, value.as_str()).is_some() {
                    return Err(format!("duplicate {flag}"));
                }
            }
        }
    }
    if !trusted {
        return Err("--trusted-local is required".into());
    }
    let format = match singleton.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let operation = if set {
        let get = |flag: &str| {
            singleton
                .get(flag)
                .copied()
                .ok_or_else(|| format!("{flag} is required"))
        };
        let principal =
            PrincipalId::from_hex(get("--principal")?).map_err(|_| "invalid principal ID")?;
        let key = IdempotencyKey::new(get("--idempotency-key")?.as_bytes().to_vec())
            .map_err(|_| "invalid retry key")?;
        let version = number(get("--expected-version")?)?;
        let expected_version = match AggregateVersion::try_new(version) {
            Some(v) => {
                v.next().map_err(|_| "policy version exhausted")?;
                ExpectedVersion::Exactly(v)
            }
            None => ExpectedVersion::NewStream,
        };
        let expected_epoch = PolicyEpoch::try_new(number(get("--expected-epoch")?)?)
            .map_err(|_| "policy epoch must be positive")?;
        if clear == !branches.is_empty() {
            return Err("supply reviewers OR explicit --clear, never both/neither".into());
        }
        admins.sort();
        let branches = branches
            .into_iter()
            .map(|(name, mut reviewers)| {
                reviewers.sort();
                ProtectedBranch { name, reviewers }
            })
            .collect();
        let command = ProtectionCommand {
            expected_version,
            expected_epoch,
            protection: ReviewProtection {
                administrators: admins,
                branches,
            },
        };
        command
            .proposed_event(principal)
            .map_err(|_| "invalid policy, duplicate identities, or exhausted epoch")?;
        Operation::Set {
            principal,
            key,
            command,
        }
    } else {
        Operation::Show
    };
    Ok(Options {
        storage: args[1].clone().into(),
        tenant,
        repository,
        format,
        operation,
    })
}
fn policy_json(policy: &ReviewProtection) -> String {
    let ids = |ids: &[PrincipalId]| {
        ids.iter()
            .map(|id| quote(&id.to_string()))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "{{\"administrators\":[{}],\"branches\":[{}]}}",
        ids(&policy.administrators),
        policy
            .branches
            .iter()
            .map(|branch| {
                let raw = branch.name.as_bytes();
                let name = std::str::from_utf8(raw)
                    .map(quote)
                    .unwrap_or_else(|_| "null".to_owned());
                let hex = raw
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                format!(
                    "{{\"ref\":{},\"ref_hex\":{},\"required_reviewers\":[{}]}}",
                    name,
                    quote(&hex),
                    ids(&branch.reviewers)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn publication_json(
    tx: TxId,
    terminal: &TerminalOutcome,
    command: &ProtectionCommand,
    cleanup: Option<&str>,
) -> String {
    let (outcome, committed, record, refusal, code) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            true,
            quote(&repository_commit_id.to_string()),
            "null".to_owned(),
            "null".to_owned(),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            false,
            "null".to_owned(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
        ),
    };
    let version = match command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    };
    // Historical refusal/commit receipts describe that exact decision. They
    // never claim the proposed policy is the repository's latest policy now.
    let epoch = if committed {
        command
            .expected_epoch
            .next()
            .ok()
            .map(|e| e.get().to_string())
            .unwrap_or_else(|| "null".into())
    } else {
        "null".into()
    };
    format!(
        concat!(
            "{{\"type\":\"review_protection_publication\",\"schema_version\":1,\"tx_id\":{},",
            "\"decision_sequence\":{},\"outcome\":{},\"committed\":{},\"repository_commit_id\":{},",
            "\"refusal_record_id\":{},\"refusal_code\":{},\"expected_version\":{},\"expected_epoch\":{},",
            "\"committed_policy_epoch\":{},\"proposed_policy\":{},\"refs_changed\":false,\"delivery_acknowledged\":null,",
            "\"node_closed\":{},\"cleanup_error\":{}}}"
        ),
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        quote(outcome),
        committed,
        record,
        refusal,
        code,
        version,
        command.expected_epoch.get(),
        epoch,
        policy_json(&command.protection),
        cleanup.is_none(),
        cleanup.map(quote).unwrap_or_else(|| "null".into())
    )
}
pub fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"]
        || (args.len() == 2 && matches!(args[0].as_str(), "show" | "set") && args[1] == "--help")
    {
        return writeln!(std::io::stdout().lock(), "{USAGE}")
            .map(|()| 0)
            .map_err(|e| e.to_string());
    }
    let options = parse(args)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage, options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| e.to_string())?;
    let service = node
        .bring_into_service(HeadGeneration::FIRST)
        .map_err(|e| e.to_string());
    let request = node.request_context();
    enum ResultValue {
        Show(String),
        Set(TxId, TerminalOutcome),
    }
    let result: Result<ResultValue, String> = match &options.operation {
        Operation::Show => service.and_then(|()| node.runtime().block_on(node.read_review_protection_in(&request)).map_err(|e| e.to_string())).map(|state| {
            let policy = state.protection().map(policy_json).unwrap_or_else(|| "null".into());
            ResultValue::Show(format!("{{\"type\":\"review_protection\",\"schema_version\":1,\"source_head\":{},\"policy_epoch\":{},\"version\":{},\"installed\":{},\"policy\":{},\"node_closed\":true}}",
                quote(&state.source_head.to_string()), state.policy_epoch.get(), state.version().map_or(0, AggregateVersion::get), state.event.is_some(), policy))
        }),
        Operation::Set { principal, key, command } => {
            let session = LoopbackReceiveSession::authenticated(*principal, key.clone());
            node.runtime().block_on(node.admit_review_protection_durable_in(&request, &session, command, Default::default()))
                .map(|(tx,t)| ResultValue::Set(tx,t)).map_err(|e| format!("{e}; no terminal result returned, not proof of non-commit. Retry the identical command/key, or use fg outcome. Service intake: {service:?}"))
        }
    };
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    match result {
        Ok(ResultValue::Show(report)) => {
            if let Some(error) = cleanup {
                return Err(format!("policy read shutdown failed: {error}"));
            }
            let mut out = std::io::stdout().lock();
            writeln!(out, "{report}")
                .and_then(|()| out.flush())
                .map_err(|e| e.to_string())?;
            Ok(0)
        }
        Ok(ResultValue::Set(tx, terminal)) => {
            let committed = matches!(terminal.outcome, DecisionOutcome::Committed { .. });
            let Operation::Set { command, .. } = &options.operation else {
                return Err("policy result mismatch".into());
            };
            let report = publication_json(tx, &terminal, command, cleanup.as_deref());
            write_terminal_receipt(&mut std::io::stdout().lock(), &report, tx, &terminal)
                .map_err(|e| format!("{e}; cleanup: {cleanup:?}"))?;
            if let Some(error) = cleanup {
                return Err(format!(
                    "{}; shutdown failed: {error}",
                    describe(tx, &terminal)
                ));
            }
            Ok(if committed { 0 } else { 3 })
        }
        Err(error) => Err(format!("{error}; shutdown error: {cleanup:?}")),
    }
}

#[cfg(test)]
mod tests;
