#![forbid(unsafe_code)]
//! Bounded explicit multi-branch requests. Parsing performs no repository I/O.
use super::options::{KeyInput, Operation, Options, unhex};
use fgit_authority::{ExpectedOld, MAX_IDEMPOTENCY_KEY_BYTES, ProposedNew, RefCommand};
use fgit_node::OneNode;
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5
        || args.len() > 4 * OneNode::MAX_BRANCH_TRANSACTION_COMMANDS + 16
        || args.iter().any(|value| value.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 1024 * 1024
        || args[0] != "transaction"
        || args[1].is_empty()
        || args[1].len() > 4096
    {
        return Err("branch transaction arguments exceed the bounded profile".into());
    }
    let mut flags = BTreeMap::new();
    let mut operations = Vec::new();
    let mut index = 4;
    while let Some(flag) = args.get(index) {
        index += 1;
        let arity = match flag.as_str() {
            "--create" | "--create-hex" | "--delete" | "--delete-hex" => 2,
            "--update" | "--update-hex" => 3,
            _ => 0,
        };
        if arity != 0 {
            if operations.len() == OneNode::MAX_BRANCH_TRANSACTION_COMMANDS {
                return Err(format!(
                    "branch transaction supports at most {} commands",
                    OneNode::MAX_BRANCH_TRANSACTION_COMMANDS
                ));
            }
            let end = index
                .checked_add(arity)
                .ok_or("transaction argument overflow")?;
            let values = args
                .get(index..end)
                .ok_or_else(|| format!("missing operands for {flag}"))?;
            if values
                .iter()
                .any(|value| value.is_empty() || value.starts_with("--"))
            {
                return Err(format!("missing operands for {flag}"));
            }
            operations.push((flag.as_str(), values));
            index = end;
            continue;
        }
        let value = match flag.as_str() {
            "--trusted-local" | "--key-stdin" => "",
            "--principal" | "--idempotency-key" | "--object-format" => {
                let value = args
                    .get(index)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                index += 1;
                value.as_str()
            }
            _ => return Err(format!("unsupported branch transaction option {flag}")),
        };
        if flags.insert(flag.as_str(), value).is_some() {
            return Err(format!("duplicate branch transaction option {flag}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err("branch transaction requires explicit --trusted-local".into());
    }
    if operations.is_empty() {
        return Err("branch transaction requires at least one command".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let principal =
        PrincipalId::from_hex(flags.get("--principal").ok_or("--principal is required")?)
            .map_err(|_| "invalid principal ID")?;
    let key = match (
        flags.get("--idempotency-key"),
        flags.contains_key("--key-stdin"),
    ) {
        (Some(value), false) if !value.is_empty() && value.len() <= MAX_IDEMPOTENCY_KEY_BYTES => {
            KeyInput::Bytes(value.as_bytes().to_vec())
        }
        (None, true) => KeyInput::Stdin,
        _ => return Err("supply exactly one bounded key or --key-stdin".into()),
    };
    let oid = |value: &str| -> Result<GitOid, String> {
        let oid = GitOid::from_hex(format, value).map_err(|_| "invalid native object ID")?;
        if oid.is_zero() || oid.to_string() != value {
            return Err("transaction tips must be nonzero canonical lowercase native OIDs".into());
        }
        Ok(oid)
    };
    let mut names = BTreeSet::new();
    let mut commands = Vec::with_capacity(operations.len());
    for (action, values) in operations {
        let bytes = if action.ends_with("-hex") {
            unhex(&values[0], 4096)?
        } else {
            values[0].as_bytes().to_vec()
        };
        if bytes.len() > 4096 || !bytes.starts_with(b"refs/heads/") {
            return Err("transaction requires bounded full refs/heads/ names".into());
        }
        let name = RefName::try_new(&bytes).map_err(|_| "invalid branch reference")?;
        if !names.insert(name.clone()) {
            return Err("duplicate branch target in transaction".into());
        }
        let (expected_old, proposed_new) = if action.starts_with("--create") {
            (ExpectedOld::Absent, ProposedNew::Update(oid(&values[1])?))
        } else if action.starts_with("--delete") {
            (ExpectedOld::Exactly(oid(&values[1])?), ProposedNew::Delete)
        } else {
            (
                ExpectedOld::Exactly(oid(&values[1])?),
                ProposedNew::Update(oid(&values[2])?),
            )
        };
        commands.push(RefCommand {
            name,
            expected_old,
            proposed_new,
            force: false,
        });
    }
    Ok(Options {
        storage: args[1].clone().into(),
        tenant: TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?,
        repository: RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?,
        format,
        operation: Operation::Mutate {
            action: "transaction".into(),
            principal,
            key,
            commands,
        },
    })
}

#[cfg(test)]
mod tests;
