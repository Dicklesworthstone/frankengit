//! Bounded, operation-specific command parsing. No repository or body-file I/O.

use std::collections::BTreeMap;
use std::path::PathBuf;
use fgit_authority::IdempotencyKey;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData, MAX_BODY_BYTES};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, PrincipalId, RefName,
    RepositoryAuthorityHeadId, RepositoryId, TenantId};
use crate::publication_support::parse_oid;

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
    pub command: PullRequestCommand,
    pub body_file: Option<PathBuf>,
}
#[derive(Debug)]
pub(super) struct ReadOptions {
    pub selection: Selection,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Selection { List { after: u64, limit: u16 }, Show(PullRequestNumber) }
impl ReadOptions {
    pub fn after(&self) -> u64 {
        match self.selection { Selection::List { after, .. } => after, Selection::Show(number) => number.get() - 1 }
    }
    pub fn limit(&self) -> u16 {
        match self.selection { Selection::List { limit, .. } => limit, Selection::Show(_) => 1 }
    }
}

pub(super) fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 4 { return Err(super::USAGE.to_owned()); }
    if arguments.len() > 48 || arguments.iter().any(|arg| arg.len() > MAX_BODY_BYTES)
        || arguments.iter().map(String::len).sum::<usize>() > 128 * 1024
    { return Err("PR arguments exceed the bounded local profile".to_owned()); }
    let action = arguments[0].as_str();
    let mutation = matches!(action, "open" | "update" | "close");
    if !mutation && !matches!(action, "list" | "show") { return Err(super::USAGE.to_owned()); }
    if arguments[1].is_empty() || arguments[1].len() > 4096 {
        return Err("storage root must contain 1..4096 bytes".to_owned());
    }
    let tenant = TenantId::from_hex(&arguments[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[3]).map_err(|_| "invalid repository ID")?;
    let number = if action != "list" {
        let text = arguments.get(4).ok_or("a PR number is required")?;
        Some(PullRequestNumber::try_new(decimal(text)?).ok_or("PR number must be positive")?)
    } else { None };
    let mut flags = BTreeMap::new();
    let mut trusted = false;
    let mut cursor = if action == "list" { 4 } else { 5 };
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str(); cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".to_owned()); }
            trusted = true; continue;
        }
        let allowed = flag == "--object-format" || if mutation {
            matches!(flag, "--principal" | "--idempotency-key" | "--source-ref" | "--source-ref-hex"
                | "--target-ref" | "--target-ref-hex" | "--expected-source" | "--expected-target"
                | "--expected-version" | "--title" | "--body" | "--body-file")
        } else { flag == "--expected-head" || (action == "list" && matches!(flag, "--after" | "--limit")) };
        if !allowed { return Err(format!("unknown or inapplicable PR option {flag:?}")); }
        let value = arguments.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if flags.insert(flag, value.as_str()).is_some() { return Err(format!("duplicate {flag}")); }
    }
    if !trusted {
        return Err("--trusted-local is required: an authorized local operator owns access to this repository".to_owned());
    }
    let requested_format = flags.get("--object-format").map(|value| match *value {
        "sha1" => Ok(GitHashAlgorithm::Sha1), "sha256" => Ok(GitHashAlgorithm::Sha256),
        _ => Err("--object-format must be sha1 or sha256".to_owned()),
    }).transpose()?;
    let (operation, format) = if mutation {
        let principal = PrincipalId::from_hex(required(&flags, "--principal")?).map_err(|_| "invalid principal ID")?;
        let key = required(&flags, "--idempotency-key")?.as_bytes();
        IdempotencyKey::new(key.to_vec()).map_err(|_| "invalid bounded idempotency key")?;
        let source_tip = parse_oid(required(&flags, "--expected-source")?)?;
        let target_tip = parse_oid(required(&flags, "--expected-target")?)?;
        let format = source_tip.algorithm();
        if target_tip.algorithm() != format || requested_format.is_some_and(|declared| declared != format) {
            return Err("PR tips and explicit repository object format must agree".to_owned());
        }
        let version = decimal(required(&flags, "--expected-version")?)?;
        if (action == "open") != (version == 0) {
            return Err("open requires version 0; update and close require a positive exact version".to_owned());
        }
        let expected_version = if version == 0 { ExpectedVersion::NewStream } else {
            let previous = AggregateVersion::try_new(version).ok_or("invalid aggregate version")?;
            previous.next().map_err(|_| "aggregate version is exhausted")?;
            ExpectedVersion::Exactly(previous)
        };
        let (body, body_file) = match (flags.get("--body"), flags.get("--body-file")) {
            (Some(body), None) => ((*body).to_owned(), None),
            (None, Some(path)) if !path.is_empty() && path.len() <= 4096 =>
                (String::new(), Some(PathBuf::from(*path))),
            _ => return Err("supply exactly one of --body or a nonempty --body-file (empty --body is permitted)".to_owned()),
        };
        let command = PullRequestCommand {
            number: number.ok_or("missing PR number")?, expected_version,
            action: match action { "open" => PullRequestAction::Open, "update" => PullRequestAction::Update, _ => PullRequestAction::Close },
            data: PullRequestData {
                source_ref: reference(&flags, "--source-ref", "--source-ref-hex")?,
                target_ref: reference(&flags, "--target-ref", "--target-ref-hex")?,
                source_tip, target_tip, title: required(&flags, "--title")?.to_owned(), body,
            },
        };
        command.proposed_event(principal, format).map_err(|_| "invalid PR coordinates, text or command shape")?;
        (Operation::Mutate(Mutation { principal, key: key.to_vec(), command, body_file }), format)
    } else {
        let expected_head = flags.get("--expected-head").map(|text| parse_head(text)).transpose()?;
        let selection = if action == "list" {
            let after = flags.get("--after").map(|text| decimal(text)).transpose()?.unwrap_or(0);
            let limit = flags.get("--limit").map(|text| decimal(text)).transpose()?.unwrap_or(50);
            if !(1..=100).contains(&limit) { return Err("--limit must be 1..100".to_owned()); }
            if after > 0 && expected_head.is_none() {
                return Err("list continuation requires --expected-head from the first page's snapshot_token".to_owned());
            }
            Selection::List { after, limit: u16::try_from(limit).map_err(|_| "invalid page size")? }
        } else { Selection::Show(number.ok_or("missing PR number")?) };
        (Operation::Read(ReadOptions { selection, expected_head }), requested_format.unwrap_or(GitHashAlgorithm::Sha1))
    };
    Ok(Options { storage: arguments[1].clone().into(), tenant, repository, format, operation })
}

fn required<'a>(flags: &BTreeMap<&str, &'a str>, flag: &str) -> Result<&'a str, String> {
    flags.get(flag).copied().ok_or_else(|| format!("{flag} is required"))
}
fn reference(flags: &BTreeMap<&str, &str>, plain: &str, encoded: &str) -> Result<RefName, String> {
    let bytes = match (flags.get(plain), flags.get(encoded)) {
        (Some(value), None) if value.len() <= 4096 => value.as_bytes().to_vec(),
        (None, Some(value)) => unhex(value, 4096)?,
        _ => return Err(format!("supply exactly one of {plain} or {encoded}")),
    };
    RefName::try_new(&bytes).map_err(|_| "invalid branch reference bytes".to_owned())
}
pub(super) fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    { return Err("expected a canonical unsigned decimal integer".to_owned()); }
    text.parse().map_err(|_| "decimal integer overflow".to_owned())
}
fn unhex(text: &str, limit: usize) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() > limit * 2 || text.len() % 2 != 0
        || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    { return Err("expected bounded nonempty lowercase hexadecimal bytes".to_owned()); }
    text.as_bytes().chunks_exact(2).map(|pair| {
        let nibble = |byte: u8| if byte.is_ascii_digit() { byte - b'0' } else { byte - b'a' + 10 };
        Ok((nibble(pair[0]) << 4) | nibble(pair[1]))
    }).collect()
}

/// Same algorithm-qualified head spelling as `fg at`; the pinned domain and
/// canonical codec version are implicit in this specifically typed option.
pub(super) fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
pub(super) fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (algorithm, digest) = text.strip_prefix("alg:").and_then(|value| value.split_once(':'))
        .ok_or("--expected-head requires the exact algorithm-qualified snapshot_token")?;
    let algorithm = u16::try_from(decimal(algorithm)?).map_err(|_| "head algorithm overflow")?;
    let algorithm = DigestAlgorithmId::try_new(algorithm).map_err(|_| "invalid head algorithm")?;
    let digest = DigestBytes::try_new(&unhex(digest, 64)?).map_err(|_| "invalid head digest width")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}
pub(super) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes { text.push(char::from(HEX[usize::from(byte >> 4)])); text.push(char::from(HEX[usize::from(byte & 15)])); }
    text
}
