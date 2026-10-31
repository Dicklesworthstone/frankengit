//! Trusted-local configuration of mandatory, canonical required-review policy.
use crate::publication_support::{describe, quote, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::protection::{
    MAX_BRANCH_REQUIRED_CHECKS, MAX_BRANCH_REVIEWERS, MAX_POLICY_ADMINISTRATORS,
    MAX_PROTECTED_BRANCHES, MAX_REF_POLICY_FRAME_BYTES, MAX_REF_POLICY_SOURCE_BYTES,
    ProtectedBranch, ProtectionCommand, RequiredWorkflowCheck, ReviewProtection,
    compile_ref_policy, decode_ref_policy,
};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RepositoryId, TenantId, TxId,
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
};

const USAGE: &str = "usage: fg protection show <storage-root> <tenant-id> <repository-id> --trusted-local [--object-format sha1|sha256]\n\
usage: fg protection set <storage-root> <tenant-id> <repository-id> --trusted-local\n\
  --principal <id> --idempotency-key <key> --expected-version <0-for-first-install> --expected-epoch <current-epoch>\n\
  --admin <id> [--admin <id> ...]\n\
  [--require-reviewer <refs/heads/branch>:<id> ...]\n\
  [--require-approvals <refs/heads/branch>:<count> ...]\n\
  [--require-merge-queue <refs/heads/branch> ...]\n\
  [--require-check <target-ref>:<source-ref>:<publisher-id>:<graph-sha256>:<job> ...]\n\
  [--policy-source <UTF-8-policy-file> | --policy-frame <canonical-policy-frame>]\n\
  [--clear]\n\
  [--object-format sha1|sha256]\n\
Set replaces the COMPLETE policy, including its optional DSL component. Omission removes that component.\n\
--policy-source compiles bounded ref-fact and actor.id rules; --policy-frame installs the same canonical bytes.\n\
The DSL may constrain reference names, creation/deletion and the request's actor.id; other actor attributes, ancestry, time and evidence facts refuse.\n\
Listed reviewers are eligible approvers; the default requires all.\n\
--require-approvals selects N approvals from that branch's eligible reviewers (1 through their count).\n\
A check-only or queue-only branch has zero required approvals. Opener and submitter cannot contribute votes.\n\
--require-merge-queue requires an authenticated canonical queue landing targeting that branch.\n\
Direct ref writes and ordinary PR merges cannot satisfy this requirement; existing reviews and checks still apply.\n\
Every check requires the latest trusted publisher result for the exact NEW commit.\n\
Its source ref must still name that commit; the workflow graph and UTF-8 job name must match exactly.\n\
--clear disables branch and DSL protection but retains explicit administrators and immutable history.\n\
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
        || args.len() > 8576
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
    let mut branches =
        BTreeMap::<RefName, (Vec<PrincipalId>, Vec<RequiredWorkflowCheck>, bool)>::new();
    let mut quorums = BTreeMap::<RefName, u16>::new();
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
                        | "--require-approvals"
                        | "--require-merge-queue"
                        | "--require-check"
                        | "--policy-source"
                        | "--policy-frame"
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
                let reviewers = &mut branches.entry(name).or_default().0;
                if reviewers.len() == MAX_BRANCH_REVIEWERS {
                    return Err("too many branch reviewers".into());
                }
                reviewers.push(id);
            }
            "--require-approvals" => {
                let (name, count) = value
                    .rsplit_once(':')
                    .ok_or("approval count must be full-branch:count")?;
                let name =
                    RefName::try_new(name.as_bytes()).map_err(|_| "invalid quorum branch")?;
                if !name.as_bytes().starts_with(b"refs/heads/") {
                    return Err("only full branch names may be protected".into());
                }
                let count = u16::try_from(number(count)?).map_err(|_| "invalid approval count")?;
                if usize::from(count) > MAX_BRANCH_REVIEWERS {
                    return Err("approval count exceeds the reviewer limit".into());
                }
                if quorums.insert(name, count).is_some() {
                    return Err("duplicate branch approval count".into());
                }
                if quorums.len() > MAX_PROTECTED_BRANCHES {
                    return Err("too many branch approval counts".into());
                }
            }
            "--require-merge-queue" => {
                let name = RefName::try_new(value.as_bytes())
                    .map_err(|_| "invalid queue-protected branch reference")?;
                if !name.as_bytes().starts_with(b"refs/heads/") {
                    return Err("only full branch names may be protected".into());
                }
                if !branches.contains_key(&name) && branches.len() == MAX_PROTECTED_BRANCHES {
                    return Err("too many protected branches".into());
                }
                let required = &mut branches.entry(name).or_default().2;
                if *required {
                    return Err("duplicate branch merge queue requirement".into());
                }
                *required = true;
            }
            "--require-check" => {
                let parts: Vec<_> = value.splitn(5, ':').collect();
                if parts.len() != 5 {
                    return Err(
                        "check must be target-ref:source-ref:publisher-id:graph-sha256:job".into(),
                    );
                }
                let name =
                    RefName::try_new(parts[0].as_bytes()).map_err(|_| "invalid target branch")?;
                let source_ref = RefName::try_new(parts[1].as_bytes())
                    .map_err(|_| "invalid check source branch")?;
                let publisher =
                    PrincipalId::from_hex(parts[2]).map_err(|_| "invalid check publisher")?;
                let graph_root = graph_bytes(parts[3])?;
                let check = RequiredWorkflowCheck {
                    source_ref,
                    publisher,
                    graph_root,
                    job: parts[4].to_owned(),
                };
                check.validate().map_err(|_| "invalid required check")?;
                if !branches.contains_key(&name) && branches.len() == MAX_PROTECTED_BRANCHES {
                    return Err("too many protected branches".into());
                }
                let checks = &mut branches.entry(name).or_default().1;
                if checks.len() == MAX_BRANCH_REQUIRED_CHECKS {
                    return Err("too many required branch checks".into());
                }
                checks.push(check);
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
        let ref_policy = match (
            singleton.get("--policy-source"),
            singleton.get("--policy-frame"),
        ) {
            (Some(_), Some(_)) => return Err("choose --policy-source or --policy-frame".into()),
            (Some(path), None) => {
                let bytes = policy_file(path, MAX_REF_POLICY_SOURCE_BYTES)?;
                let source =
                    std::str::from_utf8(&bytes).map_err(|_| "policy source must be UTF-8")?;
                Some(
                    compile_ref_policy(source)
                        .map_err(|error| format!("invalid ref policy: {error}"))?,
                )
            }
            (None, Some(path)) => {
                let bytes = policy_file(path, MAX_REF_POLICY_FRAME_BYTES)?;
                Some(
                    decode_ref_policy(&bytes)
                        .map_err(|error| format!("invalid policy frame: {error}"))?,
                )
            }
            (None, None) => None,
        };
        if clear == (!branches.is_empty() || ref_policy.is_some()) {
            return Err(
                "supply review/check/queue/DSL requirements OR explicit --clear, never both/neither"
                    .into(),
            );
        }
        if quorums.keys().any(|name| !branches.contains_key(name)) {
            return Err("approval count requires a protection rule for the same branch".into());
        }
        admins.sort();
        let branches = branches
            .into_iter()
            .map(
                |(name, (mut reviewers, mut required_checks, require_merge_queue))| {
                    reviewers.sort();
                    required_checks.sort();
                    ProtectedBranch {
                        require_merge_queue,
                        required_approvals: quorums
                            .get(&name)
                            .copied()
                            .unwrap_or(reviewers.len() as u16),
                        required_checks,
                        name,
                        reviewers,
                    }
                },
            )
            .collect();
        let command = ProtectionCommand {
            expected_version,
            expected_epoch,
            protection: ReviewProtection {
                administrators: admins,
                branches,
                ref_policy,
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
fn policy_file(path: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect policy file: {error}"))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(format!(
            "policy file must be a regular file of at most {maximum} bytes"
        ));
    }
    let file =
        std::fs::File::open(path).map_err(|error| format!("cannot open policy file: {error}"))?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read policy file: {error}"))?;
    if bytes.len() > maximum {
        return Err("policy file exceeded its byte limit while reading".into());
    }
    Ok(bytes)
}
fn graph_bytes(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("graph root must be exactly 64 lowercase hexadecimal digits".into());
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid graph root")?;
    }
    Ok(bytes)
}
fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn policy_json(policy: &ReviewProtection) -> Result<String, String> {
    policy.validate().map_err(|error| error.to_string())?;
    let ref_policy = match &policy.ref_policy {
        Some(snapshot) => format!(
            "{{\"snapshot_id\":{},\"profile\":{},\"mode\":\"enforce\",\"frame_hex\":{}}}",
            quote(&snapshot.id().to_string()),
            quote(
                fgit_forge::event::protection::ref_policy_profile_name(snapshot)
                    .map_err(|error| error.to_string())?
            ),
            quote(&bytes_hex(
                &snapshot.encode().map_err(|error| error.to_string())?
            )),
        ),
        None => "null".into(),
    };
    let ids = |ids: &[PrincipalId]| {
        ids.iter()
            .map(|id| quote(&id.to_string()))
            .collect::<Vec<_>>()
            .join(",")
    };
    Ok(format!(
        "{{\"administrators\":[{}],\"branches\":[{}],\"ref_policy\":{}}}",
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
                    "{{\"ref\":{},\"ref_hex\":{},\"required_reviewers\":[{}],\"required_approvals\":{},\"require_merge_queue\":{},\"required_checks\":[{}]}}",
                    name,
                    quote(&hex),
                    ids(&branch.reviewers),
                    branch.required_approvals,
                    branch.require_merge_queue,
                    branch.required_checks.iter().map(|check| format!(
                        "{{\"source_ref_hex\":{},\"publisher\":{},\"graph_root\":{},\"job\":{}}}",
                        quote(&bytes_hex(check.source_ref.as_bytes())), quote(&check.publisher.to_string()),
                        quote(&bytes_hex(&check.graph_root)), quote(&check.job)
                    )).collect::<Vec<_>>().join(",")
                )
            })
            .collect::<Vec<_>>()
            .join(","),
        ref_policy,
    ))
}
fn publication_json(
    tx: TxId,
    terminal: &TerminalOutcome,
    command: &ProtectionCommand,
    cleanup: Option<&str>,
) -> Result<String, String> {
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
    Ok(format!(
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
        policy_json(&command.protection)?,
        cleanup.is_none(),
        cleanup.map(quote).unwrap_or_else(|| "null".into())
    ))
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
    let request = fgit_cli::command_request_context(&node);
    enum ResultValue {
        Show(String),
        Set(TxId, TerminalOutcome),
    }
    let result: Result<ResultValue, String> = match &options.operation {
        Operation::Show => service.and_then(|()| node.runtime().block_on(node.read_review_protection_in(&request)).map_err(|e| e.to_string())).and_then(|state| {
            let policy = state.protection().map(policy_json).transpose()?.unwrap_or_else(|| "null".into());
            Ok(ResultValue::Show(format!("{{\"type\":\"review_protection\",\"schema_version\":1,\"source_head\":{},\"policy_epoch\":{},\"version\":{},\"installed\":{},\"policy\":{},\"node_closed\":true}}",
                quote(&state.source_head.to_string()), state.policy_epoch.get(), state.version().map_or(0, AggregateVersion::get), state.event.is_some(), policy)))
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
            let report =
                publication_json(tx, &terminal, command, cleanup.as_deref()).map_err(|error| {
                    format!(
                        "transaction {tx} has terminal {:?}; receipt rendering failed: {error}",
                        terminal.outcome
                    )
                })?;
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
