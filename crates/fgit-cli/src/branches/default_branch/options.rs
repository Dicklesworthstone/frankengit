use std::{collections::BTreeMap, path::PathBuf};

use fgit_admission::default_branch::DefaultBranchCommand;
use fgit_authority::MAX_IDEMPOTENCY_KEY_BYTES;
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};

use super::super::options::{KeyInput, unhex};

pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub format: GitHashAlgorithm,
    pub operation: Operation,
}

pub(super) enum Operation {
    Read,
    Set {
        principal: PrincipalId,
        key: KeyInput,
        command: DefaultBranchCommand,
    },
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 24
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(super::USAGE.into());
    }
    let mutate = match args[0].as_str() {
        "default" => false,
        "set-default" => true,
        _ => return Err(super::USAGE.into()),
    };
    if args[1].is_empty() || args[1].len() > 4096 {
        return Err("invalid default-branch storage path".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new();
    let mut at = 4;
    while let Some(flag) = args.get(at) {
        at += 1;
        let flag = flag.as_str();
        let permitted = matches!(flag, "--trusted-local" | "--object-format")
            || (mutate
                && matches!(
                    flag,
                    "--principal"
                        | "--idempotency-key"
                        | "--key-stdin"
                        | "--expected-default"
                        | "--expected-default-hex"
                        | "--expect-no-default"
                        | "--ref"
                        | "--ref-hex"
                        | "--expected-tip"
                ));
        if !permitted {
            return Err(format!("inapplicable default-branch option {flag:?}"));
        }
        let value = if matches!(
            flag,
            "--trusted-local" | "--key-stdin" | "--expect-no-default"
        ) {
            ""
        } else {
            let value = args
                .get(at)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            at += 1;
            value.as_str()
        };
        if flags.insert(flag, value).is_some() {
            return Err(format!("duplicate default-branch option {flag}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err("--trusted-local is required; a principal ID is not a credential".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let operation = if mutate {
        let principal = PrincipalId::from_hex(required(&flags, "--principal")?)
            .map_err(|_| "invalid principal ID")?;
        let key = match (
            flags.get("--idempotency-key"),
            flags.contains_key("--key-stdin"),
        ) {
            (Some(key), false) if !key.is_empty() && key.len() <= MAX_IDEMPOTENCY_KEY_BYTES => {
                KeyInput::Bytes(key.as_bytes().to_vec())
            }
            (None, true) => KeyInput::Stdin,
            _ => return Err("supply exactly one bounded key or --key-stdin".into()),
        };
        let expected_head = if flags.contains_key("--expect-no-default") {
            if flags.contains_key("--expected-default")
                || flags.contains_key("--expected-default-hex")
            {
                return Err("absent and named default-branch expectations conflict".into());
            }
            None
        } else {
            Some(reference(
                &flags,
                "--expected-default",
                "--expected-default-hex",
            )?)
        };
        let target = reference(&flags, "--ref", "--ref-hex")?;
        let expected_target_tip = GitOid::from_hex(format, required(&flags, "--expected-tip")?)
            .map_err(|_| "invalid expected target tip for the selected object format")?;
        if expected_target_tip.is_zero() {
            return Err("the expected target tip must be nonzero".into());
        }
        Operation::Set {
            principal,
            key,
            command: DefaultBranchCommand {
                expected_head,
                target,
                expected_target_tip,
            },
        }
    } else {
        Operation::Read
    };
    Ok(Options {
        storage: args[1].clone().into(),
        tenant,
        repository,
        format,
        operation,
    })
}

fn required<'a>(flags: &BTreeMap<&str, &'a str>, flag: &str) -> Result<&'a str, String> {
    flags
        .get(flag)
        .copied()
        .ok_or_else(|| format!("{flag} is required"))
}

fn reference(flags: &BTreeMap<&str, &str>, plain: &str, encoded: &str) -> Result<RefName, String> {
    let bytes = match (flags.get(plain), flags.get(encoded)) {
        (Some(value), None) if value.len() <= 4096 => value.as_bytes().to_vec(),
        (None, Some(value)) => unhex(value, 4096)?,
        _ => return Err(format!("supply exactly one of {plain} or {encoded}")),
    };
    if !bytes.starts_with(b"refs/heads/") {
        return Err("a full branch reference under refs/heads/ is required".into());
    }
    RefName::try_new(&bytes).map_err(|_| "invalid branch reference bytes".into())
}
