//! Parse complete versioned commands without opening the node or input files.
use std::collections::BTreeMap;
use std::path::PathBuf;
use fgit_authority::IdempotencyKey;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueEdit, MAX_BODY_BYTES, MAX_LABELS};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, PrincipalId, RepositoryAuthorityHeadId, RepositoryId, TenantId};

#[derive(Debug)]
pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub format: GitHashAlgorithm,
    pub operation: Operation,
}
#[derive(Debug)]
pub(super) enum Operation { Mutate(Mutation), Read(ReadOptions) }
#[derive(Debug)]
pub(super) struct Mutation {
    pub principal: PrincipalId,
    pub key: Vec<u8>,
    pub command: IssueCommand,
    pub body_file: Option<PathBuf>,
}
#[derive(Debug)]
pub(super) struct ReadOptions {
    pub number: Option<IssueNumber>,
    pub after: u64,
    pub limit: u16,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}

pub(super) fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 4 { return Err(super::USAGE.to_owned()); }
    if arguments.len() > 96 || arguments.iter().any(|arg| arg.len() > MAX_BODY_BYTES)
        || arguments.iter().try_fold(0usize, |n, arg| n.checked_add(arg.len())).is_none_or(|n| n > 128 * 1024)
    { return Err("issue arguments exceed the bounded local profile".to_owned()); }
    let action = arguments[0].as_str();
    let mutate = matches!(action, "open" | "edit" | "close" | "reopen" | "comment");
    if !mutate && !matches!(action, "list" | "show") { return Err(super::USAGE.to_owned()); }
    if arguments[1].is_empty() || arguments[1].len() > 4096 { return Err("storage root must contain 1..4096 bytes".to_owned()); }
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|_| "invalid repository ID")?;
    let number = if action == "list" { None } else {
        Some(IssueNumber::try_new(decimal(arguments.get(4).ok_or("an issue number is required")?)?)
            .ok_or("issue number must be positive")?)
    };
    let mut cursor = if action == "list" { 4 } else { 5 };
    let mut flags = BTreeMap::new();
    let (mut trusted, mut clear_labels) = (false, false);
    let mut labels = Vec::<String>::new();
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str(); cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".to_owned()); }
            trusted = true; continue;
        }
        if flag == "--clear-labels" {
            if action != "edit" || clear_labels { return Err("--clear-labels is permitted once, only for edit".to_owned()); }
            clear_labels = true; continue;
        }
        let allowed = flag == "--object-format" || if mutate {
            matches!(flag, "--principal" | "--idempotency-key" | "--expected-version")
                || (matches!(action, "open" | "edit") && matches!(flag, "--title" | "--label"))
                || (matches!(action, "open" | "edit" | "comment") && matches!(flag, "--body" | "--body-file"))
        } else {
            matches!(flag, "--expected-head" | "--limit")
                || (action == "list" && flag == "--after")
                || (action == "show" && flag == "--after-version")
        };
        if !allowed { return Err(format!("unknown or inapplicable issue option {flag:?}")); }
        let value = arguments.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?; cursor += 1;
        if flag == "--label" {
            if labels.len() == MAX_LABELS { return Err("at most 32 issue labels may be supplied".to_owned()); }
            labels.push(value.clone());
        } else if flags.insert(flag, value.as_str()).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !trusted { return Err("--trusted-local is required for this repository-local operator interface".to_owned()); }
    if clear_labels && !labels.is_empty() { return Err("--clear-labels and --label cannot be combined".to_owned()); }
    labels.sort();
    if labels.windows(2).any(|pair| pair[0] == pair[1]) { return Err("duplicate issue label".to_owned()); }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("--object-format must be sha1 or sha256".to_owned()),
    };
    let operation = if mutate {
        let principal = PrincipalId::from_hex(required(&flags, "--principal")?).map_err(|_| "invalid principal ID")?;
        let key = required(&flags, "--idempotency-key")?.as_bytes().to_vec();
        IdempotencyKey::new(key.clone()).map_err(|_| "invalid bounded idempotency key")?;
        let version = decimal(required(&flags, "--expected-version")?)?;
        if (action == "open") != (version == 0) { return Err("open requires version 0; all other changes require a positive exact version".to_owned()); }
        let expected_version = if version == 0 { ExpectedVersion::NewStream } else {
            let version = AggregateVersion::try_new(version).ok_or("invalid version")?;
            version.next().map_err(|_| "issue version is exhausted")?;
            ExpectedVersion::Exactly(version)
        };
        let body_file = flags.get("--body-file").map(|path| {
            if path.is_empty() || path.len() > 4096 { Err("body-file must name a bounded nonempty path".to_owned()) }
            else { Ok(PathBuf::from(path)) }
        }).transpose()?;
        if body_file.is_some() && flags.contains_key("--body") { return Err("supply only one of --body and --body-file".to_owned()); }
        let body = flags.get("--body").map(|value| (*value).to_owned());
        let supplied_body = body.is_some() || body_file.is_some();
        if matches!(action, "open" | "comment") && !supplied_body {
            return Err("--body or --body-file is required; an empty opening body is explicit".to_owned());
        }
        let title = flags.get("--title").map(|value| (*value).to_owned());
        let action = match action {
            "open" => IssueAction::Open { title: title.ok_or("--title is required")?, body: body.unwrap_or_default(), labels },
            "edit" => IssueAction::Edit(IssueEdit { title, body: if supplied_body { Some(body.unwrap_or_default()) } else { None },
                labels: if clear_labels || !labels.is_empty() { Some(labels) } else { None } }),
            "comment" => IssueAction::Comment { body: body.unwrap_or_default() },
            "close" => IssueAction::Close,
            "reopen" => IssueAction::Reopen,
            _ => unreachable!("action whitelist"),
        };
        let command = IssueCommand { number: number.ok_or("missing issue number")?, expected_version, action };
        // Only the syntax probe gets a placeholder. Actual file bytes replace
        // the command's body and are validated before any node is opened.
        let mut probe = command.clone();
        if body_file.is_some() { *body_slot(&mut probe)? = "file-body-probe".to_owned(); }
        probe.proposed_event(principal).map_err(|_| "invalid issue title, body, labels, or action/version combination")?;
        Operation::Mutate(Mutation { principal, key, command, body_file })
    } else {
        let after = flags.get(if action == "list" { "--after" } else { "--after-version" })
            .map(|value| decimal(value)).transpose()?.unwrap_or(0);
        let limit = flags.get("--limit").map(|value| decimal(value)).transpose()?.unwrap_or(50);
        if !(1..=100).contains(&limit) { return Err("--limit must be 1..100".to_owned()); }
        let expected_head = flags.get("--expected-head").map(|value| parse_head(value)).transpose()?;
        if after != 0 && expected_head.is_none() { return Err("continuation requires --expected-head from the first page's snapshot_token".to_owned()); }
        Operation::Read(ReadOptions { number, after, limit: u16::try_from(limit).map_err(|_| "invalid page limit")?, expected_head })
    };
    Ok(Options { storage: arguments[1].clone().into(), tenant, repository, format, operation })
}

pub(super) fn body_slot(command: &mut IssueCommand) -> Result<&mut String, String> {
    match &mut command.action {
        IssueAction::Open { body, .. } | IssueAction::Comment { body } => Ok(body),
        IssueAction::Edit(IssueEdit { body: Some(body), .. }) => Ok(body),
        _ => Err("body file is inapplicable to this issue action".to_owned()),
    }
}
fn required<'a>(flags: &BTreeMap<&str, &'a str>, name: &str) -> Result<&'a str, String> {
    flags.get(name).copied().ok_or_else(|| format!("{name} is required"))
}
pub(super) fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return Err("expected a canonical unsigned decimal integer".to_owned());
    }
    text.parse().map_err(|_| "decimal integer overflow".to_owned())
}
pub(super) fn expected_version(command: &IssueCommand) -> u64 {
    match command.expected_version { ExpectedVersion::NewStream => 0, ExpectedVersion::Exactly(version) => version.get() }
}
pub(super) fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    let bytes = id.digest().as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!("alg:{}:{bytes}", id.algorithm().code_point())
}
pub(super) fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let text = text.strip_prefix("head:").unwrap_or(text);
    let (algorithm, digest) = text.strip_prefix("alg:").and_then(|text| text.split_once(':'))
        .ok_or("expected the exact algorithm-qualified snapshot_token")?;
    let algorithm = DigestAlgorithmId::try_new(u16::try_from(decimal(algorithm)?).map_err(|_| "head algorithm overflow")?)
        .map_err(|_| "invalid head algorithm")?;
    if digest.is_empty() || digest.len() > 128 || digest.len() % 2 != 0
        || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err("head digest must be bounded nonempty lowercase hexadecimal".to_owned()); }
    let bytes = digest.as_bytes().chunks_exact(2).map(|pair| {
        let n = |b: u8| if b.is_ascii_digit() { b - b'0' } else { b - b'a' + 10 };
        (n(pair[0]) << 4) | n(pair[1])
    }).collect::<Vec<_>>();
    let digest = DigestBytes::try_new(&bytes).map_err(|_| "invalid head digest width")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}
