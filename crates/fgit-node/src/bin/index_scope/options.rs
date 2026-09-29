//! Closed operator commands. Parse everything before opening repository state.
use fgit_crypto::{IdentityDomain, internal_algorithm_id, internal_domain_tag};
use fgit_forge::source_search::SearchLimits;
use fgit_graph::lexical::scoped::LexicalScope;
use fgit_graph::lexical::{LexicalChannel, LexicalQuery, LexicalQueryLimits, LexicalReadLimits};
use fgit_graph::{GenerationActivation, GraphGenerationId};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestBytes, GitHashAlgorithm, GitOid, HeadGeneration,
    InternalObjectId, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId,
};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::PathBuf;

pub const USAGE: &str = "fg-index-scope build|search|recover ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 FULL_REF --trusted-local --prefix PATH [--prefix PATH | --prefix-hex HEX ...]\n\
Build: --candidate-file NEW_PRIVATE_FILE [--predecessor-token TOKEN] [--max-file-bytes N --max-source-bytes N --max-files N --max-entries N --max-depth N]\n\
Search: --term WORD [--term WORD | --term-hex HEX ...] [--channel content|path] [--filter-prefix PATH | --filter-prefix-hex HEX ...] [--limit N --max-work N --max-payload-bytes N]\n\
Search continuation: --after ID --expected-head TOKEN --expected-commit HEX --index-token TOKEN --index-number N\n\
Search/recover floor: --minimum-index-token TOKEN --minimum-index-number N\n\
Build/search pins: --expected-head TOKEN --expected-commit HEX\n\
Recover: --candidate TOKEN. Tokens use alg:2:<64 lowercase hex>.\n\
All counts are canonical decimal integers. Scope is explicit coverage, not whole-repository search. No scan fallback or automatic retry.";

pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
pub fn failure(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
fn text(value: &OsStr) -> io::Result<&str> {
    value.to_str().ok_or_else(|| {
        invalid("Only filesystem paths may be non-UTF-8; use hex for repository bytes.")
    })
}
pub fn decimal(value: &str) -> io::Result<u64> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid("Expected a canonical decimal u64."));
    }
    value.parse().map_err(|_| invalid("Decimal u64 overflow."))
}
pub fn unhex(value: &str, maximum: usize) -> io::Result<Vec<u8>> {
    if value.len() > maximum * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("Expected bounded lowercase hex bytes."));
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| digit(p[0]) * 16 + digit(p[1]))
        .collect())
}
pub fn identity(value: &str, domain: IdentityDomain) -> io::Result<InternalObjectId> {
    let algorithm = internal_algorithm_id(domain);
    // Closed operator token profile, not a fabricated conversion between domains.
    if algorithm.code_point() != 2 {
        return Err(invalid("Unsupported operator token algorithm."));
    }
    let digest = unhex(
        value
            .strip_prefix("alg:2:")
            .ok_or_else(|| invalid("Expected alg:2: token."))?,
        32,
    )?;
    if digest.len() != 32 || digest.iter().all(|b| *b == 0) {
        return Err(invalid("Invalid token digest."));
    }
    Ok(InternalObjectId::new(
        algorithm,
        internal_domain_tag(domain),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&digest).map_err(failure)?,
    ))
}
pub fn generation(value: &str) -> io::Result<GraphGenerationId> {
    GraphGenerationId::from_internal_object_id(identity(value, IdentityDomain::Generation)?)
        .map_err(failure)
}
fn native(value: &str, format: GitHashAlgorithm) -> io::Result<GitOid> {
    let bytes = unhex(value, format.digest_len())?;
    if bytes.len() != format.digest_len() || bytes.iter().all(|b| *b == 0) {
        return Err(invalid("Invalid native commit ID."));
    }
    GitOid::from_hex(format, value).map_err(failure)
}

#[derive(Debug)]
pub enum Command {
    Build {
        predecessor: Option<GraphGenerationId>,
        record: PathBuf,
        limits: SearchLimits,
    },
    Search {
        query: LexicalQuery,
        generation: Option<GenerationActivation>,
        minimum: Option<GenerationActivation>,
        after: Option<u64>,
        limits: LexicalQueryLimits,
        reads: LexicalReadLimits,
    },
    Recover {
        candidate: GraphGenerationId,
        minimum: Option<GenerationActivation>,
    },
}
#[derive(Debug)]
pub struct Options {
    pub root: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub format: GitHashAlgorithm,
    pub reference: RefName,
    pub scope: LexicalScope,
    pub head: Option<RepositoryAuthorityHeadId>,
    pub commit: Option<GitOid>,
    pub command: Command,
}
type Scalars = BTreeMap<String, OsString>;
fn take(map: &mut Scalars, key: &str) -> io::Result<Option<String>> {
    map.remove(key)
        .map(|v| text(&v).map(str::to_owned))
        .transpose()
}
fn number(map: &mut Scalars, key: &str, default: u64, maximum: u64) -> io::Result<u64> {
    let n = take(map, key)?.map_or(Ok(default), |v| decimal(&v))?;
    if n == 0 || n > maximum {
        return Err(invalid(format!("Out-of-range {key}.")));
    }
    Ok(n)
}
fn checkpoint(map: &mut Scalars, prefix: &str) -> io::Result<Option<GenerationActivation>> {
    match (
        take(map, &format!("--{prefix}-token"))?,
        take(map, &format!("--{prefix}-number"))?,
    ) {
        (None, None) => Ok(None),
        (Some(id), Some(n)) => Ok(Some(GenerationActivation {
            generation_id: generation(&id)?,
            authority_generation: HeadGeneration::try_new(decimal(&n)?).map_err(failure)?,
        })),
        _ => Err(invalid("Index token and number must be supplied together.")),
    }
}
pub fn parse(args: &[OsString]) -> io::Result<Options> {
    if args.len() < 9
        || args.len() > 700
        || args.iter().any(|a| a.len() > 8192)
        || args.iter().map(|a| a.len()).sum::<usize>() > 256 * 1024
    {
        return Err(invalid(USAGE));
    }
    let op = text(&args[0])?;
    if !matches!(op, "build" | "search" | "recover") {
        return Err(invalid(USAGE));
    }
    let id = |at: usize| -> io::Result<[u8; 16]> {
        unhex(text(&args[at])?, 16)?
            .try_into()
            .map_err(|_| invalid("Expected a 16-byte namespace ID."))
    };
    let format = match text(&args[4])? {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err(invalid("Expected sha1 or sha256.")),
    };
    let reference = RefName::try_new(text(&args[5])?.as_bytes()).map_err(failure)?;
    if !reference.as_bytes().starts_with(b"refs/") || reference.as_bytes().len() > 1024 {
        return Err(invalid("Expected a bounded full reference."));
    }
    let mut trusted = false;
    let (mut prefixes, mut terms, mut filters) = (Vec::new(), Vec::new(), Vec::new());
    let mut scalars = Scalars::new();
    let mut at = 6;
    while at < args.len() {
        let name = text(&args[at])?;
        at += 1;
        if name == "--trusted-local" {
            if trusted {
                return Err(invalid("Duplicate --trusted-local."));
            }
            trusted = true;
            continue;
        }
        let value = args
            .get(at)
            .ok_or_else(|| invalid("Missing option value."))?;
        at += 1;
        match name {
            "--prefix" | "--prefix-hex" => prefixes.push(if name.ends_with("-hex") {
                unhex(text(value)?, 4096)?
            } else {
                text(value)?.as_bytes().to_vec()
            }),
            "--term" | "--term-hex" if op == "search" => terms.push(if name.ends_with("-hex") {
                unhex(text(value)?, 128)?
            } else {
                text(value)?.as_bytes().to_vec()
            }),
            "--filter-prefix" | "--filter-prefix-hex" if op == "search" => {
                filters.push(if name.ends_with("-hex") {
                    unhex(text(value)?, 4096)?
                } else {
                    text(value)?.as_bytes().to_vec()
                })
            }
            _ => {
                if !name.starts_with("--")
                    || scalars.insert(name.to_owned(), value.clone()).is_some()
                {
                    return Err(invalid("Unknown argument or duplicate scalar option."));
                }
            }
        }
    }
    if !trusted {
        return Err(invalid(
            "This command requires explicit --trusted-local authority.",
        ));
    }
    let scope = LexicalScope::new(&prefixes).map_err(failure)?;
    let (head, commit) = if op == "recover" {
        (None, None)
    } else {
        (
            take(&mut scalars, "--expected-head")?
                .map(|v| {
                    RepositoryAuthorityHeadId::from_internal_object_id(identity(
                        &v,
                        IdentityDomain::RepositoryAuthorityHead,
                    )?)
                    .map_err(failure)
                })
                .transpose()?,
            take(&mut scalars, "--expected-commit")?
                .map(|v| native(&v, format))
                .transpose()?,
        )
    };
    let command = match op {
        "build" => {
            let predecessor = take(&mut scalars, "--predecessor-token")?
                .map(|v| generation(&v))
                .transpose()?;
            let record = scalars
                .remove("--candidate-file")
                .map(PathBuf::from)
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or_else(|| {
                    invalid("Build requires --candidate-file in an existing private directory.")
                })?;
            let mut limits = SearchLimits::default();
            limits.max_file_bytes = number(
                &mut scalars,
                "--max-file-bytes",
                limits.max_file_bytes as u64,
                limits.max_file_bytes as u64,
            )? as usize;
            limits.max_total_bytes = number(
                &mut scalars,
                "--max-source-bytes",
                limits.max_total_bytes as u64,
                limits.max_total_bytes as u64,
            )? as usize;
            limits.max_files = number(
                &mut scalars,
                "--max-files",
                limits.max_files as u64,
                limits.max_files as u64,
            )? as usize;
            limits.max_entries = number(
                &mut scalars,
                "--max-entries",
                limits.max_entries as u64,
                limits.max_entries as u64,
            )? as usize;
            limits.max_depth = number(
                &mut scalars,
                "--max-depth",
                limits.max_depth as u64,
                limits.max_depth as u64,
            )? as usize;
            limits.validate().map_err(failure)?;
            Command::Build {
                predecessor,
                record,
                limits,
            }
        }
        "search" => {
            let channel = match take(&mut scalars, "--channel")?
                .as_deref()
                .unwrap_or("content")
            {
                "content" => LexicalChannel::Content,
                "path" => LexicalChannel::Path,
                _ => return Err(invalid("Expected content or path channel.")),
            };
            let query = LexicalQuery::new(channel, &terms, &filters).map_err(failure)?;
            let generation = checkpoint(&mut scalars, "index")?;
            let minimum = checkpoint(&mut scalars, "minimum-index")?;
            let after = take(&mut scalars, "--after")?
                .map(|v| decimal(&v))
                .transpose()?;
            if after.is_some() && (head.is_none() || commit.is_none() || generation.is_none()) {
                return Err(invalid(
                    "Continuation needs exact source head, commit and index token/number.",
                ));
            }
            let limits = LexicalQueryLimits {
                max_results: number(&mut scalars, "--limit", 100, 4096)? as usize,
                max_work: number(
                    &mut scalars,
                    "--max-work",
                    16 * 1024 * 1024,
                    16 * 1024 * 1024,
                )?,
            };
            let reads = LexicalReadLimits {
                max_payload_bytes: number(
                    &mut scalars,
                    "--max-payload-bytes",
                    32 * 1024 * 1024,
                    32 * 1024 * 1024,
                )? as usize,
                ..Default::default()
            };
            limits.validate().map_err(failure)?;
            Command::Search {
                query,
                generation,
                minimum,
                after,
                limits,
                reads,
            }
        }
        "recover" => Command::Recover {
            candidate: generation(
                &take(&mut scalars, "--candidate")?
                    .ok_or_else(|| invalid("Recovery needs the original --candidate token."))?,
            )?,
            minimum: checkpoint(&mut scalars, "minimum-index")?,
        },
        _ => return Err(invalid(USAGE)),
    };
    if !scalars.is_empty() {
        return Err(invalid(
            "Unknown or inapplicable option for this operation.",
        ));
    }
    Ok(Options {
        root: PathBuf::from(&args[1]),
        tenant: TenantId::from_bytes(id(2)?),
        repository: RepositoryId::from_bytes(id(3)?),
        format,
        reference,
        scope,
        head,
        commit,
        command,
    })
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
