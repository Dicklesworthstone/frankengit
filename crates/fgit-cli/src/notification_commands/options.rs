//! Complete bounded parsing before repository I/O. No command selects a recipient.
use crate::issues::options::{decimal, parse_head};
use fgit_authority::IdempotencyKey;
use fgit_forge::event::notification::{
    NotificationAction, NotificationCommand, NotificationMode, NotificationTarget,
    NotificationTargetKind,
};
use fgit_forge::{AggregateVersion, DiscussionNumber, ExpectedVersion, IssueNumber};
use fgit_types::{
    GitHashAlgorithm, PrincipalId, RepositoryAuthorityHeadId, RepositoryId,
    RepositoryIncarnationId, TenantId,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub format: GitHashAlgorithm,
    pub principal: PrincipalId,
    pub incarnation: Option<RepositoryIncarnationId>,
    pub kind: NotificationTargetKind,
    pub operation: Operation,
}
pub(super) enum Operation {
    Read(ReadOptions),
    Mutate(Mutation),
}
pub(super) struct Mutation {
    pub key: Vec<u8>,
    pub command: NotificationCommand,
}
pub(super) struct ReadOptions {
    pub target: Option<NotificationTarget>,
    pub after: u64,
    pub limit: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub unread_only: bool,
    pub include_muted: bool,
}
pub(super) fn action_name(action: NotificationAction) -> &'static str {
    match action {
        NotificationAction::SetMode(NotificationMode::Subscribed) => "subscribe",
        NotificationAction::SetMode(NotificationMode::Muted) => "mute",
        NotificationAction::SetMode(NotificationMode::Participating) => "automatic",
        NotificationAction::SetReadThrough(Some(_)) => "read",
        NotificationAction::SetReadThrough(None) => "unread",
    }
}
pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4 || args.len() > 34 {
        return Err(super::USAGE.into());
    }
    if args.iter().any(|a| a.len() > 4096)
        || args
            .iter()
            .try_fold(0usize, |n, a| n.checked_add(a.len()))
            .is_none_or(|n| n > 16 * 1024)
        || args[1].is_empty()
    {
        return Err("inbox arguments exceed the bounded local profile".into());
    }
    let operation = args[0].as_str();
    let mutate = matches!(
        operation,
        "subscribe" | "mute" | "automatic" | "read" | "unread"
    );
    if !mutate && !matches!(operation, "list" | "show") {
        return Err(super::USAGE.into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let number = if operation == "list" {
        None
    } else {
        Some(decimal(args.get(4).ok_or("thread number required")?)?)
    };
    let mut at = if operation == "list" { 4 } else { 5 };
    let mut flags = BTreeMap::new();
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        let boolean = flag == "--trusted-local"
            || (operation == "list" && matches!(flag, "--unread-only" | "--include-muted"));
        let allowed = boolean
            || matches!(
                flag,
                "--principal" | "--object-format" | "--expected-incarnation" | "--kind"
            )
            || (mutate && matches!(flag, "--expected-version" | "--idempotency-key"))
            || (!mutate && flag == "--expected-head")
            || (operation == "list" && matches!(flag, "--after" | "--limit"))
            || (operation == "read" && flag == "--read-through");
        if !allowed {
            return Err(format!("unknown or inapplicable inbox option {flag}"));
        }
        let value = if boolean {
            ""
        } else {
            let value = args
                .get(at)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            at += 1;
            value.as_str()
        };
        if flags.insert(flag, value).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err("--trusted-local is required".into());
    }
    let required = |name| {
        flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("{name} is required"))
    };
    let principal =
        PrincipalId::from_hex(required("--principal")?).map_err(|_| "invalid principal ID")?;
    let incarnation = flags
        .get("--expected-incarnation")
        .map(|s| RepositoryIncarnationId::from_hex(s).map_err(|_| "invalid incarnation ID"))
        .transpose()?;
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("--object-format must be sha1 or sha256".into()),
    };
    let kind = match flags.get("--kind").copied().unwrap_or("issue") {
        "issue" => NotificationTargetKind::Issue,
        "discussion" => NotificationTargetKind::Discussion,
        _ => return Err("--kind must be issue or discussion".into()),
    };
    let target = number
        .map(|number| match kind {
            NotificationTargetKind::Issue => IssueNumber::try_new(number)
                .map(NotificationTarget::Issue)
                .ok_or("issue number must be positive"),
            NotificationTargetKind::Discussion => DiscussionNumber::try_new(number)
                .map(NotificationTarget::Discussion)
                .ok_or("discussion number must be positive"),
        })
        .transpose()?;
    let operation = if mutate {
        let before = decimal(required("--expected-version")?)?;
        let expected_version = if before == 0 {
            ExpectedVersion::NewStream
        } else {
            let before = AggregateVersion::try_new(before).ok_or("invalid preference version")?;
            before
                .next()
                .map_err(|_| "preference version is exhausted")?;
            ExpectedVersion::Exactly(before)
        };
        let key = required("--idempotency-key")?.as_bytes().to_vec();
        IdempotencyKey::new(key.clone()).map_err(|_| "invalid bounded idempotency key")?;
        let action = match operation {
            "subscribe" => NotificationAction::SetMode(NotificationMode::Subscribed),
            "mute" => NotificationAction::SetMode(NotificationMode::Muted),
            "automatic" => NotificationAction::SetMode(NotificationMode::Participating),
            "read" => NotificationAction::SetReadThrough(Some(
                AggregateVersion::try_new(decimal(required("--read-through")?)?)
                    .ok_or("--read-through must be a positive observed thread version")?,
            )),
            "unread" => NotificationAction::SetReadThrough(None),
            _ => return Err(super::USAGE.into()),
        };
        let command = NotificationCommand {
            target: target.ok_or("thread number required")?,
            expected_version,
            action,
        };
        command
            .proposed_event(principal)
            .map_err(|_| "invalid notification command")?;
        Operation::Mutate(Mutation { key, command })
    } else {
        let after = flags
            .get("--after")
            .map(|s| decimal(s))
            .transpose()?
            .unwrap_or(0);
        let limit = flags
            .get("--limit")
            .map(|s| decimal(s))
            .transpose()?
            .unwrap_or(20);
        if !(1..=100).contains(&limit) {
            return Err("--limit must be 1..100".into());
        }
        let expected_head = flags
            .get("--expected-head")
            .map(|s| parse_head(s))
            .transpose()?;
        if after != 0 && expected_head.is_none() {
            return Err("nonzero --after requires --expected-head".into());
        }
        Operation::Read(ReadOptions {
            target,
            after,
            limit: limit as u16,
            expected_head,
            unread_only: flags.contains_key("--unread-only"),
            include_muted: flags.contains_key("--include-muted"),
        })
    };
    Ok(Options {
        storage: args[1].clone().into(),
        tenant,
        repository,
        format,
        principal,
        incarnation,
        kind,
        operation,
    })
}
