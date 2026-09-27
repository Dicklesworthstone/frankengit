//! Closed fast-forward grammar. No file reads, inferred tips, or merge artifacts.
use std::collections::BTreeMap;
use std::path::PathBuf;

use fgit_authority::IdempotencyKey;
use fgit_forge::event::NativeMerge;
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};

use crate::publication_support::parse_oid;
use crate::pull_request::options::decimal;

#[derive(Debug)]
pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub format: GitHashAlgorithm,
    pub principal: PrincipalId,
    pub key: IdempotencyKey,
    pub number: PullRequestNumber,
    pub version: AggregateVersion,
    pub source_ref: RefName,
    pub source: GitOid,
    pub target_ref: RefName,
    pub target: GitOid,
}

pub(super) fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 4 {
        return Err(super::USAGE.to_owned());
    }
    if arguments.len() > 32
        || arguments.iter().any(|value| value.len() > 8192 || value.contains('\0'))
        || arguments.iter().map(String::len).sum::<usize>() > 64 * 1024
    {
        return Err("fast-forward arguments exceed the bounded local profile".to_owned());
    }
    if arguments[0].is_empty() || arguments[0].len() > 4096 {
        return Err("storage root must contain 1..4096 bytes".to_owned());
    }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let number = PullRequestNumber::try_new(decimal(&arguments[3])?)
        .ok_or("PR number must be positive")?;
    let mut flags = BTreeMap::new();
    let mut trusted = false;
    let mut cursor = 4;
    while cursor < arguments.len() {
        let supplied = arguments[cursor].as_str();
        cursor += 1;
        let flag = match supplied {
            "--source-tip" => "--expected-source",
            "--target-tip" => "--expected-target",
            value => value,
        };
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".to_owned()); }
            trusted = true;
            continue;
        }
        if !matches!(flag,
            "--principal" | "--idempotency-key" | "--expected-version" |
            "--source-ref" | "--source-ref-hex" | "--target-ref" | "--target-ref-hex" |
            "--expected-source" | "--expected-target" | "--object-format")
        {
            return Err(format!("unknown or inapplicable fast-forward option {supplied:?}"));
        }
        let value = arguments.get(cursor).ok_or_else(|| format!("missing value for {supplied}"))?;
        cursor += 1;
        if flags.insert(flag, value.as_str()).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !trusted {
        return Err("--trusted-local is required: an authorized local operator owns access to this repository".to_owned());
    }
    let principal = PrincipalId::from_hex(required(&flags, "--principal")?)
        .map_err(|_| "invalid principal ID")?;
    let key = IdempotencyKey::new(required(&flags, "--idempotency-key")?.as_bytes().to_vec())
        .map_err(|_| "invalid bounded idempotency key")?;
    let version = AggregateVersion::try_new(decimal(required(&flags, "--expected-version")?)?)
        .ok_or("fast-forward requires a positive exact PR version")?;
    version.next().map_err(|_| "aggregate version is exhausted")?;
    let source = parse_oid(required(&flags, "--expected-source")?)?;
    let target = parse_oid(required(&flags, "--expected-target")?)?;
    let format = source.algorithm();
    if target.algorithm() != format || flags.get("--object-format").is_some_and(|value| *value != format.as_str()) {
        return Err("fast-forward tips and explicit repository object format must agree".to_owned());
    }
    let source_ref = reference(&flags, "--source-ref", "--source-ref-hex")?;
    let target_ref = reference(&flags, "--target-ref", "--target-ref-hex")?;
    // This checks representable coordinates only. Native admission, NOT the
    // command parser, proves ancestry and checks current PR/policy state.
    NativeMerge {
        source_ref: source_ref.clone(), source_tip: source,
        base_tip: target, target_ref: target_ref.clone(),
        target_tip_before: target, merge_commit: source,
    }.validate().map_err(|_| "invalid fast-forward branch/tip coordinates")?;
    Ok(Options {
        storage: arguments[0].clone().into(), tenant, repository, format,
        principal, key, number, version, source_ref, source, target_ref, target,
    })
}
fn required<'a>(flags: &BTreeMap<&str, &'a str>, name: &str) -> Result<&'a str, String> {
    flags.get(name).copied().ok_or_else(|| format!("{name} is required"))
}
fn reference(flags: &BTreeMap<&str, &str>, plain: &str, encoded: &str) -> Result<RefName, String> {
    let bytes = match (flags.get(plain), flags.get(encoded)) {
        (Some(value), None) if value.len() <= 4096 => value.as_bytes().to_vec(),
        (None, Some(value)) if !value.is_empty() && value.len() <= 8192 && value.len().is_multiple_of(2)
            && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            value.as_bytes().as_chunks::<2>().0.iter()
                .map(|pair| nibble(pair[0]) * 16 + nibble(pair[1])).collect()
        }
        _ => return Err(format!("supply exactly one bounded {plain} or lowercase {encoded}")),
    };
    RefName::try_new(&bytes).map_err(|_| "invalid branch reference bytes".to_owned())
}
