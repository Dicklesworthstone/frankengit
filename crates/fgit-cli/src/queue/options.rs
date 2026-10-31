//! Bounded, exact-predecessor queue commands parsed before repository IO.
use fgit_authority::IdempotencyKey;
use fgit_forge::event::queue::MAX_QUEUE_ENTRIES;
use fgit_forge::merge_queue::{DequeueReason, QueueCommand, QueueCommandAction};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid, PrincipalId,
    RefName, RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug)]
pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: Option<RepositoryIncarnationId>,
    pub format: GitHashAlgorithm,
    pub operation: Operation,
}

#[derive(Debug)]
pub(super) enum Operation {
    Show {
        number: QueueNumber,
        expected_head: Option<RepositoryAuthorityHeadId>,
    },
    List {
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    },
    Mutate {
        principal: PrincipalId,
        key: IdempotencyKey,
        command: QueueCommand,
    },
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5
        || args.len() > MAX_QUEUE_ENTRIES * 2 + 40
        || args
            .iter()
            .any(|arg| arg.len() > 4096 || arg.contains('\0'))
        || args
            .iter()
            .try_fold(0usize, |sum, arg| sum.checked_add(arg.len()))
            .is_none_or(|sum| sum > 128 * 1024)
    {
        return Err(super::USAGE.to_owned());
    }
    let action = args[0].as_str();
    if !matches!(action, "show" | "list" | "enqueue" | "dequeue" | "reorder") {
        return Err(super::USAGE.to_owned());
    }
    if args[1].is_empty() {
        return Err("storage root is required".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let number = if action == "list" {
        None
    } else {
        Some(QueueNumber::try_new(decimal(&args[4])?).ok_or("queue number must be positive")?)
    };
    let mut cursor = if action == "list" { 4 } else { 5 };
    let mut flags = BTreeMap::new();
    let mut trusted = false;
    let mut order = Vec::new();
    let mut seen_entries = BTreeSet::new();
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
        let allowed = matches!(flag, "--object-format" | "--expected-incarnation")
            || match action {
                "show" => flag == "--expected-head",
                "list" => matches!(flag, "--expected-head" | "--after" | "--limit"),
                _ => {
                    matches!(
                        flag,
                        "--principal" | "--idempotency-key" | "--expected-version" | "--target-ref"
                    ) || match action {
                        "enqueue" => matches!(
                            flag,
                            "--pull-request"
                                | "--source-ref"
                                | "--expected-source-tip"
                                | "--expected-target-tip"
                                | "--expected-pull-version"
                                | "--priority"
                        ),
                        "dequeue" => matches!(flag, "--pull-request" | "--reason"),
                        "reorder" => flag == "--entry",
                        _ => false,
                    }
                }
            };
        if !allowed {
            return Err(format!("unknown or inapplicable queue option {flag:?}"));
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if flag == "--entry" {
            if order.len() == MAX_QUEUE_ENTRIES {
                return Err("queue order exceeds 1024 entries".into());
            }
            let entry = pull_number(value)?;
            if !seen_entries.insert(entry) {
                return Err("queue order contains a duplicate pull request".into());
            }
            order.push(entry);
        } else if flags.insert(flag, value.as_str()).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !trusted {
        return Err("--trusted-local is required".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("--object-format must be sha1 or sha256".into()),
    };
    let incarnation = flags
        .get("--expected-incarnation")
        .map(|value| RepositoryIncarnationId::from_hex(value))
        .transpose()
        .map_err(|_| "invalid repository incarnation ID")?;
    let operation = if matches!(action, "show" | "list") {
        let expected_head = flags
            .get("--expected-head")
            .map(|value| parse_head(value))
            .transpose()?;
        if action == "show" {
            Operation::Show {
                number: number.ok_or("queue number is required")?,
                expected_head,
            }
        } else {
            let after = decimal(flags.get("--after").copied().unwrap_or("0"))?;
            let limit = decimal(flags.get("--limit").copied().unwrap_or("100"))?;
            if !(1..=100).contains(&limit) {
                return Err("queue page limit must be 1..100".into());
            }
            if after != 0 && expected_head.is_none() {
                return Err(
                    "queue continuation requires --expected-head from snapshot_token".into(),
                );
            }
            Operation::List {
                after,
                limit: u16::try_from(limit).map_err(|_| "invalid page limit")?,
                expected_head,
            }
        }
    } else {
        if incarnation.is_none() {
            return Err("queue writes require --expected-incarnation".into());
        }
        let principal = PrincipalId::from_hex(required(&flags, "--principal")?)
            .map_err(|_| "invalid principal ID")?;
        let key = IdempotencyKey::new(required(&flags, "--idempotency-key")?.as_bytes().to_vec())
            .map_err(|_| "invalid bounded idempotency key")?;
        let raw_version = decimal(required(&flags, "--expected-version")?)?;
        let expected_version = if raw_version == 0 {
            if action != "enqueue" {
                return Err("only first enqueue may use queue version 0".into());
            }
            ExpectedVersion::NewStream
        } else {
            let version = AggregateVersion::try_new(raw_version).ok_or("invalid queue version")?;
            version.next().map_err(|_| "queue version is exhausted")?;
            ExpectedVersion::Exactly(version)
        };
        let target_ref = branch(required(&flags, "--target-ref")?)?;
        let command_action = match action {
            "enqueue" => {
                let source_ref = branch(required(&flags, "--source-ref")?)?;
                if source_ref == target_ref {
                    return Err("queue source and target branches must differ".into());
                }
                QueueCommandAction::Enqueue {
                    pull_request: pull_number(required(&flags, "--pull-request")?)?,
                    source_ref,
                    head_tip: oid(required(&flags, "--expected-source-tip")?, format)?,
                    expected_target_tip: oid(required(&flags, "--expected-target-tip")?, format)?,
                    expected_pull_request_version: AggregateVersion::try_new(decimal(required(
                        &flags,
                        "--expected-pull-version",
                    )?)?)
                    .ok_or("expected PR version must be positive")?,
                    priority: u32::try_from(decimal(
                        flags.get("--priority").copied().unwrap_or("0"),
                    )?)
                    .map_err(|_| "queue priority exceeds u32")?,
                }
            }
            "dequeue" => QueueCommandAction::Dequeue {
                pull_request: pull_number(required(&flags, "--pull-request")?)?,
                reason: match required(&flags, "--reason")? {
                    "withdrawn" => DequeueReason::Withdrawn,
                    "conflict" => DequeueReason::Conflict,
                    "check-failed" => DequeueReason::CheckFailed,
                    "base-moved" => DequeueReason::BaseMoved,
                    "evicted" => DequeueReason::Evicted,
                    "admin-override" => DequeueReason::AdminOverride,
                    _ => return Err("invalid queue dequeue reason".into()),
                },
            },
            "reorder" => {
                if order.is_empty() {
                    return Err("reorder requires the complete nonempty --entry order".into());
                }
                QueueCommandAction::Reorder { order }
            }
            _ => return Err(super::USAGE.into()),
        };
        let command = QueueCommand {
            number: number.ok_or("queue number is required")?,
            target_ref,
            expected_version,
            action: command_action,
        };
        command
            .proposed_event(principal, format)
            .map_err(|_| "invalid canonical queue command")?;
        Operation::Mutate {
            principal,
            key,
            command,
        }
    };
    Ok(Options {
        storage: args[1].clone().into(),
        tenant,
        repository,
        incarnation,
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

fn branch(value: &str) -> Result<RefName, String> {
    let name = RefName::try_new(value.as_bytes()).map_err(|_| "invalid full branch reference")?;
    if !name.as_bytes().starts_with(b"refs/heads/") {
        return Err("queue branches must use full refs/heads/ names".into());
    }
    Ok(name)
}

fn pull_number(value: &str) -> Result<PullRequestNumber, String> {
    PullRequestNumber::try_new(decimal(value)?).ok_or_else(|| "PR number must be positive".into())
}

fn oid(value: &str, format: GitHashAlgorithm) -> Result<GitOid, String> {
    let id = GitOid::from_hex(format, value)
        .map_err(|_| "invalid native object ID for repository format")?;
    if id.is_zero() {
        return Err("queue tips must be nonzero native object IDs".into());
    }
    Ok(id)
}

pub(super) fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("expected a canonical unsigned decimal integer".into());
    }
    value.parse().map_err(|_| "decimal integer overflow".into())
}

pub(super) const fn version(expected: ExpectedVersion) -> u64 {
    match expected {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    }
}

pub(super) fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_head(value: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let value = value.strip_prefix("head:").unwrap_or(value);
    let (algorithm, digest) = value
        .strip_prefix("alg:")
        .and_then(|value| value.split_once(':'))
        .ok_or("expected the exact algorithm-qualified snapshot_token")?;
    let algorithm = DigestAlgorithmId::try_new(
        u16::try_from(decimal(algorithm)?).map_err(|_| "head algorithm overflow")?,
    )
    .map_err(|_| "invalid head algorithm")?;
    if digest.is_empty()
        || digest.len() > 128
        || digest.len() % 2 != 0
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("head digest must be bounded nonempty lowercase hexadecimal".into());
    }
    let bytes = digest
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let nibble = |byte: u8| {
                if byte.is_ascii_digit() {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect::<Vec<_>>();
    Ok(RepositoryAuthorityHeadId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&bytes).map_err(|_| "invalid head digest width")?,
    ))
}
