use crate::publication_support::parse_oid;
use fgit_forge::{patch::PatchLimits, preparation::MergeMetadata};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};
use std::{collections::BTreeMap, path::PathBuf};

pub(super) enum Key {
    Bytes(Vec<u8>),
    Stdin,
}
pub(super) enum Operation {
    Prepare {
        input: PathBuf,
        output: PathBuf,
        metadata: MergeMetadata,
        message_file: Option<PathBuf>,
        limits: PatchLimits,
    },
    Apply {
        input: PathBuf,
        principal: PrincipalId,
        key: Key,
        candidate: GitOid,
    },
}
pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub reference: RefName,
    pub format: GitHashAlgorithm,
    pub operation: Operation,
}
fn path(text: &str) -> Result<PathBuf, String> {
    if text.is_empty() || text.len() > 4096 || text.contains('\0') {
        return Err("local path must be nonempty and bounded".into());
    }
    Ok(text.into())
}
fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("expected canonical unsigned decimal".into());
    }
    text.parse().map_err(|_| "integer overflow".into())
}
pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() > 44
        || args.iter().any(|s| s.len() > 64 * 1024)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err("initial commit arguments exceed the bounded profile".into());
    }
    let prepare = match args.first().map(String::as_str) {
        Some("prepare-initial") => true,
        Some("apply-initial") => false,
        _ => return Err(super::USAGE.into()),
    };
    let start = if prepare { 7 } else { 6 };
    if args.len() < start {
        return Err(super::USAGE.into());
    }
    let storage = path(&args[1])?;
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new();
    let mut cursor = start;
    while cursor < args.len() {
        let name = args[cursor].as_str();
        cursor += 1;
        let switch =
            matches!(name, "--trusted-local" | "--ref-hex") || (!prepare && name == "--key-stdin");
        let allowed = if prepare {
            matches!(
                name,
                "--profile"
                    | "--object-format"
                    | "--author"
                    | "--committer"
                    | "--timestamp"
                    | "--message"
                    | "--message-file"
                    | "--max-files"
                    | "--max-hunks"
                    | "--max-input-bytes"
                    | "--max-output-bytes"
            )
        } else {
            matches!(
                name,
                "--principal" | "--idempotency-key" | "--expected-commit"
            )
        };
        if !switch && !allowed {
            return Err(format!("unknown initial commit option {name:?}"));
        }
        let value = if switch {
            ""
        } else {
            let value = args
                .get(cursor)
                .ok_or_else(|| format!("missing value for {name}"))?;
            cursor += 1;
            value.as_str()
        };
        if flags.insert(name, value).is_some() {
            return Err(format!("duplicate {name}"));
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
    let raw = if flags.contains_key("--ref-hex") {
        let text = &args[4];
        if text.is_empty()
            || text.len() > 8192
            || !text.len().is_multiple_of(2)
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("reference must be bounded lowercase hex".into());
        }
        let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| 16 * digit(p[0]) + digit(p[1]))
            .collect::<Vec<_>>()
    } else {
        args[4].as_bytes().to_vec()
    };
    if raw.len() > 4096 || !raw.starts_with(b"refs/heads/") {
        return Err("bounded full branch reference required".into());
    }
    let reference = RefName::try_new(&raw).map_err(|_| "invalid branch reference")?;
    let (format, operation) = if prepare {
        if required("--profile")? != "exact-v1" {
            return Err("explicit --profile exact-v1 is required".into());
        }
        let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
            "sha1" => GitHashAlgorithm::Sha1,
            "sha256" => GitHashAlgorithm::Sha256,
            _ => return Err("object format must be sha1 or sha256".into()),
        };
        let (message, message_file) = match (flags.get("--message"), flags.get("--message-file")) {
            (Some(message), None) => (message.as_bytes().to_vec(), None),
            (None, Some(file)) => (Vec::new(), Some(path(file)?)),
            _ => return Err("exactly one message or message-file is required".into()),
        };
        let author = required("--author")?.to_owned();
        let timestamp = decimal(required("--timestamp")?)?;
        let metadata = MergeMetadata {
            committer: flags
                .get("--committer")
                .map_or_else(|| author.clone(), |s| (*s).to_owned()),
            author,
            timestamp,
            message,
        };
        if message_file.is_none() {
            metadata.validate().map_err(|e| e.to_string())?;
        }
        let mut limits = PatchLimits::default();
        for (flag, field) in [
            ("--max-files", &mut limits.max_files),
            ("--max-hunks", &mut limits.max_hunks),
            ("--max-input-bytes", &mut limits.max_patch_bytes),
            ("--max-output-bytes", &mut limits.max_output_bytes),
        ] {
            if let Some(value) = flags.get(flag) {
                *field =
                    usize::try_from(decimal(value)?).map_err(|_| "limit exceeds target width")?;
            }
        }
        limits.validate().map_err(|e| e.to_string())?;
        let output = path(&args[6])?;
        if output.file_name().is_none() {
            return Err("output must name a new file".into());
        }
        (
            format,
            Operation::Prepare {
                input: path(&args[5])?,
                output,
                metadata,
                message_file,
                limits,
            },
        )
    } else {
        let principal =
            PrincipalId::from_hex(required("--principal")?).map_err(|_| "invalid principal")?;
        let candidate = parse_oid(required("--expected-commit")?)?;
        let key = match (
            flags.get("--idempotency-key"),
            flags.contains_key("--key-stdin"),
        ) {
            (Some(value), false)
                if !value.is_empty()
                    && value.len() <= fgit_authority::MAX_IDEMPOTENCY_KEY_BYTES =>
            {
                Key::Bytes(value.as_bytes().to_vec())
            }
            (None, true) => Key::Stdin,
            _ => return Err("exactly one nonempty bounded key or --key-stdin is required".into()),
        };
        (
            candidate.algorithm(),
            Operation::Apply {
                input: path(&args[5])?,
                principal,
                key,
                candidate,
            },
        )
    };
    Ok(Options {
        storage,
        tenant,
        repository,
        reference,
        format,
        operation,
    })
}
