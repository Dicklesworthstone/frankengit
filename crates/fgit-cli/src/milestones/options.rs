//! Parse the complete bounded command before opening a node or body file.
use crate::issues::options::{decimal, parse_head};
use fgit_authority::IdempotencyKey;
use fgit_forge::event::milestone::{MilestoneAction, MilestoneCommand, MilestoneEdit};
use fgit_forge::{AggregateVersion, ExpectedVersion, MilestoneNumber};
use fgit_types::{
    GitHashAlgorithm, PrincipalId, RepositoryAuthorityHeadId, RepositoryId, TenantId,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub format: GitHashAlgorithm,
    pub operation: Operation,
}

pub(super) enum Operation {
    Mutate(Mutation),
    Read(ReadOptions),
}

pub(super) struct Mutation {
    pub principal: PrincipalId,
    pub key: Vec<u8>,
    pub command: MilestoneCommand,
    pub body_file: Option<PathBuf>,
}

pub(super) struct ReadOptions {
    pub number: Option<MilestoneNumber>,
    pub after: u64,
    pub limit: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4 {
        return Err(super::USAGE.to_owned());
    }
    if args.len() > 64
        || args.iter().any(|arg| arg.len() > super::MAX_BODY_BYTES)
        || args
            .iter()
            .try_fold(0usize, |n, arg| n.checked_add(arg.len()))
            .is_none_or(|n| n > 128 * 1024)
    {
        return Err("milestone arguments exceed the bounded local profile".into());
    }
    let action = args[0].as_str();
    let mutate = matches!(action, "open" | "edit" | "close" | "reopen");
    if !mutate && !matches!(action, "list" | "show") {
        return Err(super::USAGE.to_owned());
    }
    if args[1].is_empty() || args[1].len() > 4096 {
        return Err("storage root must contain 1..4096 bytes".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let number = if action == "list" {
        None
    } else {
        Some(
            MilestoneNumber::try_new(decimal(
                args.get(4).ok_or("a milestone number is required")?,
            )?)
            .ok_or("milestone number must be positive")?,
        )
    };
    let mut cursor = if action == "list" { 4 } else { 5 };
    let mut trusted = false;
    let mut clear_due = false;
    let mut flags = BTreeMap::new();
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".into());
            }
            trusted = true;
            continue;
        }
        if flag == "--clear-due-at" {
            if action != "edit" || clear_due {
                return Err("--clear-due-at is only accepted once for edit".into());
            }
            clear_due = true;
            continue;
        }
        let allowed = flag == "--object-format"
            || (mutate
                && matches!(
                    flag,
                    "--principal" | "--idempotency-key" | "--expected-version"
                ))
            || (matches!(action, "open" | "edit")
                && matches!(flag, "--title" | "--body" | "--body-file" | "--due-at"))
            || (!mutate && matches!(flag, "--limit" | "--expected-head"))
            || (action == "list" && flag == "--after")
            || (action == "show" && flag == "--after-version");
        if !allowed {
            return Err(format!("unknown or inapplicable milestone option {flag}"));
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if flags.insert(flag, value.as_str()).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !trusted {
        return Err(
            "--trusted-local is required for this repository-local operator interface".into(),
        );
    }
    if clear_due && flags.contains_key("--due-at") {
        return Err("--due-at and --clear-due-at cannot be combined".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("--object-format must be sha1 or sha256".into()),
    };
    let operation = if mutate {
        let principal = PrincipalId::from_hex(required(&flags, "--principal")?)
            .map_err(|_| "invalid principal ID")?;
        let key = required(&flags, "--idempotency-key")?.as_bytes().to_vec();
        IdempotencyKey::new(key.clone()).map_err(|_| "invalid bounded idempotency key")?;
        let version = decimal(required(&flags, "--expected-version")?)?;
        let expected_version = if version == 0 {
            ExpectedVersion::NewStream
        } else {
            let version = AggregateVersion::try_new(version).ok_or("invalid version")?;
            version
                .next()
                .map_err(|_| "milestone version is exhausted")?;
            ExpectedVersion::Exactly(version)
        };
        let body_file = flags
            .get("--body-file")
            .map(|path| {
                if path.is_empty() || path.len() > 4096 {
                    Err("body-file must name a bounded nonempty path")
                } else {
                    Ok(PathBuf::from(path))
                }
            })
            .transpose()?;
        if body_file.is_some() && flags.contains_key("--body") {
            return Err("supply only one of --body and --body-file".into());
        }
        let body = flags.get("--body").map(|body| (*body).to_owned());
        let supplied_body = body.is_some() || body_file.is_some();
        if action == "open" && !supplied_body {
            return Err(
                "--body or --body-file is required; an empty opening body is explicit".into(),
            );
        }
        let title = flags.get("--title").map(|title| (*title).to_owned());
        let due_at = flags.get("--due-at").map(|due| decimal(due)).transpose()?;
        let action = match action {
            "open" => MilestoneAction::Open {
                title: title.ok_or("--title is required")?,
                body: body.unwrap_or_default(),
                due_at,
            },
            "edit" => MilestoneAction::Edit(MilestoneEdit {
                title,
                body: supplied_body.then(|| body.unwrap_or_default()),
                due_at: if clear_due {
                    Some(None)
                } else {
                    due_at.map(Some)
                },
            }),
            "close" => MilestoneAction::Close,
            "reopen" => MilestoneAction::Reopen,
            _ => unreachable!("mutation whitelist"),
        };
        let command = MilestoneCommand {
            number: number.ok_or("missing milestone number")?,
            expected_version,
            action,
        };
        // The actual file bytes replace this syntax-only probe before node IO.
        let mut probe = command.clone();
        if body_file.is_some() {
            *body_slot(&mut probe)? = "file body".into();
        }
        probe
            .proposed_event(principal)
            .map_err(|_| "invalid milestone metadata or action/version combination")?;
        Operation::Mutate(Mutation {
            principal,
            key,
            command,
            body_file,
        })
    } else {
        let after = flags
            .get(if action == "list" {
                "--after"
            } else {
                "--after-version"
            })
            .map(|value| decimal(value))
            .transpose()?
            .unwrap_or(0);
        let limit = flags
            .get("--limit")
            .map(|value| decimal(value))
            .transpose()?
            .unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err("--limit must be 1..100".into());
        }
        let expected_head = flags
            .get("--expected-head")
            .map(|head| parse_head(head))
            .transpose()?;
        if after != 0 && expected_head.is_none() {
            return Err(
                "continuation requires --expected-head from the first page's snapshot_token".into(),
            );
        }
        Operation::Read(ReadOptions {
            number,
            after,
            limit: limit as u16,
            expected_head,
        })
    };
    Ok(Options {
        storage: args[1].clone().into(),
        tenant,
        repository,
        format,
        operation,
    })
}

pub(super) fn body_slot(command: &mut MilestoneCommand) -> Result<&mut String, String> {
    match &mut command.action {
        MilestoneAction::Open { body, .. } => Ok(body),
        MilestoneAction::Edit(MilestoneEdit {
            body: Some(body), ..
        }) => Ok(body),
        _ => Err("body file is inapplicable to this milestone action".into()),
    }
}

fn required<'a>(flags: &BTreeMap<&str, &'a str>, flag: &str) -> Result<&'a str, String> {
    flags
        .get(flag)
        .copied()
        .ok_or_else(|| format!("{flag} is required"))
}

pub(super) const fn expected_version(command: &MilestoneCommand) -> u64 {
    match command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    }
}
