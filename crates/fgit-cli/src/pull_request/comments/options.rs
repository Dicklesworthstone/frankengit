//! Exact discussion versions and bounded literal comment input.
use std::collections::BTreeMap;
use std::path::PathBuf;

use fgit_authority::IdempotencyKey;
use fgit_forge::event::pull_request_comment::{MAX_COMMENT_BYTES, PullRequestCommentCommand};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{
    GitHashAlgorithm, PrincipalId, RepositoryAuthorityHeadId, RepositoryId, TenantId,
};

use super::super::options::{decimal, parse_head};

#[derive(Debug)]
pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub format: GitHashAlgorithm,
    pub number: PullRequestNumber,
    pub operation: Operation,
}

#[derive(Debug)]
pub(super) enum Operation {
    Append {
        principal: PrincipalId,
        key: Vec<u8>,
        command: PullRequestCommentCommand,
        body_file: Option<PathBuf>,
    },
    Read {
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    },
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 6 || args.len() > 22 {
        return Err(super::USAGE.into());
    }
    let append = match args[0].as_str() {
        "comment" => true,
        "comments" => false,
        _ => return Err(super::USAGE.into()),
    };
    if args.iter().any(|arg| arg.len() > MAX_COMMENT_BYTES)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
        || args[1].is_empty()
        || args[1].len() > 4096
    {
        return Err("comment arguments exceed the bounded local profile".into());
    }
    let number =
        PullRequestNumber::try_new(decimal(&args[4])?).ok_or("a positive PR number is required")?;
    let mut flags = BTreeMap::new();
    let mut trusted = false;
    let mut cursor = 5;
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
        let allowed = flag == "--object-format"
            || if append {
                matches!(
                    flag,
                    "--principal"
                        | "--idempotency-key"
                        | "--expected-version"
                        | "--body"
                        | "--body-file"
                )
            } else {
                matches!(flag, "--after" | "--limit" | "--expected-head")
            };
        if !allowed {
            return Err(format!("unknown or inapplicable comment option: {flag}"));
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
        return Err("comment access requires --trusted-local".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("--object-format must be sha1 or sha256".into()),
    };
    let required = |flag: &str| {
        flags
            .get(flag)
            .copied()
            .ok_or_else(|| format!("missing {flag}"))
    };
    let operation = if append {
        let principal =
            PrincipalId::from_hex(required("--principal")?).map_err(|_| "invalid principal ID")?;
        let key = required("--idempotency-key")?.as_bytes().to_vec();
        IdempotencyKey::new(key.clone()).map_err(|_| "invalid bounded idempotency key")?;
        let version = decimal(required("--expected-version")?)?;
        let expected_version = if version == 0 {
            ExpectedVersion::NewStream
        } else {
            let version = AggregateVersion::try_new(version).ok_or("invalid discussion version")?;
            version.next().map_err(|_| "discussion version exhausted")?;
            ExpectedVersion::Exactly(version)
        };
        let (body, body_file) = match (flags.get("--body"), flags.get("--body-file")) {
            (Some(body), None) => {
                validate_body(body)?;
                ((*body).to_owned(), None)
            }
            (None, Some(path)) if !path.is_empty() && path.len() <= 4096 => {
                (String::new(), Some(PathBuf::from(path)))
            }
            _ => return Err("supply exactly one of --body or --body-file".into()),
        };
        Operation::Append {
            principal,
            key,
            command: PullRequestCommentCommand {
                number,
                expected_version,
                body,
            },
            body_file,
        }
    } else {
        let after = decimal(flags.get("--after").copied().unwrap_or("0"))?;
        let limit = decimal(flags.get("--limit").copied().unwrap_or("20"))?;
        if !(1..=100).contains(&limit) {
            return Err("comment page limit must be 1..100".into());
        }
        let expected_head = flags
            .get("--expected-head")
            .map(|text| parse_head(text))
            .transpose()?;
        if after > 0 && expected_head.is_none() {
            return Err("comment continuation requires --expected-head".into());
        }
        Operation::Read {
            after,
            limit: u16::try_from(limit).map_err(|_| "invalid limit")?,
            expected_head,
        }
    };
    Ok(Options {
        storage: args[1].clone().into(),
        tenant: TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?,
        repository: RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?,
        format,
        number,
        operation,
    })
}

pub(super) fn validate_body(body: &str) -> Result<(), String> {
    if body.len() > MAX_COMMENT_BYTES || body.contains('\0') || body.trim().is_empty() {
        return Err(
            "comment must contain nonblank UTF-8 text without NUL, at most 65536 bytes".into(),
        );
    }
    Ok(())
}
