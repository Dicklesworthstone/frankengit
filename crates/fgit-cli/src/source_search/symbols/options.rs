use super::*;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use std::collections::BTreeMap;

#[derive(Debug)]
pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub reference: RefName,
    pub format: GitHashAlgorithm,
    pub query: SymbolQuery,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_commit: Option<GitOid>,
    pub limits: SearchLimits,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4 || args.len() > 320
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err(USAGE.into());
    }
    if args[0].is_empty() { return Err("storage root must be nonempty".into()); }
    let tenant = TenantId::from_hex(&args[1]).map_err(|error| error.to_string())?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|error| error.to_string())?;
    let reference = RefName::try_new(args[3].as_bytes()).map_err(|error| error.to_string())?;
    if !reference.as_bytes().starts_with(b"refs/") {
        return Err("a full refs/ reference is required".into());
    }
    let mut trusted = false;
    let mut flags = BTreeMap::new();
    let mut paths = Vec::new();
    let mut kinds = Vec::new();
    let mut cursor = 4;
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".into()); }
            trusted = true;
            continue;
        }
        if !matches!(flag,
            "--name" | "--match" | "--kind" | "--path" | "--path-hex"
            | "--object-format" | "--expected-head" | "--expected-commit"
            | "--max-matches" | "--max-work" | "--max-bytes" | "--max-file-bytes" | "--max-files")
        {
            return Err(format!("unknown symbol search option {flag}"));
        }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--kind" => {
                if kinds.len() == 8 { return Err("at most eight kind filters are supported".into()); }
                kinds.push(match value.as_str() {
                    "function" => SymbolKind::Function,
                    "struct" => SymbolKind::Struct,
                    "enum" => SymbolKind::Enum,
                    "trait" => SymbolKind::Trait,
                    "type" => SymbolKind::Type,
                    "module" => SymbolKind::Module,
                    "union" => SymbolKind::Union,
                    "macro" => SymbolKind::Macro,
                    _ => return Err(format!("unsupported symbol kind {value}")),
                });
            }
            "--path" | "--path-hex" => {
                if paths.len() == 128 { return Err("at most 128 path prefixes are supported".into()); }
                paths.push(if flag == "--path" {
                    value.as_bytes().to_vec()
                } else {
                    super::super::unhex(value, 4096)?
                });
            }
            _ => {
                if flags.insert(flag, value.as_str()).is_some() {
                    return Err(format!("duplicate {flag}"));
                }
            }
        }
    }
    if !trusted { return Err("--trusted-local is required for whole-repository symbol reads".into()); }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let mode = match flags.get("--match").copied().unwrap_or("exact") {
        "exact" => SymbolMatchMode::Exact,
        "prefix" => SymbolMatchMode::Prefix,
        _ => return Err("match mode must be exact or prefix".into()),
    };
    let work = flags.get("--max-work").map(|text| positive_u64(text))
        .transpose()?.unwrap_or(MAX_SYMBOL_WORK);
    let query = SymbolQuery::new(
        flags.get("--name").ok_or("--name is required")?.as_bytes(),
        mode, &kinds, &paths, work,
    ).map_err(|error| error.to_string())?;
    let expected_head = flags.get("--expected-head").map(|text| parse_head(text)).transpose()?;
    let expected_commit = flags.get("--expected-commit")
        .map(|text| GitOid::from_hex(format, text).map_err(|error| error.to_string())).transpose()?;
    if expected_commit.is_some_and(|id| id.is_zero()) {
        return Err("expected commit must be nonzero".into());
    }
    let defaults = SearchLimits::default();
    let bound = |name: &str, default| -> Result<usize, String> {
        Ok(flags.get(name).map(|text| super::super::decimal(text)).transpose()?.unwrap_or(default))
    };
    let limits = SearchLimits {
        max_matches: bound("--max-matches", defaults.max_matches)?,
        max_total_bytes: bound("--max-bytes", defaults.max_total_bytes)?,
        max_file_bytes: bound("--max-file-bytes", defaults.max_file_bytes)?,
        max_files: bound("--max-files", defaults.max_files)?,
        ..defaults
    };
    limits.validate().map_err(|error| error.to_string())?;
    Ok(Options {
        storage: args[0].clone().into(), tenant, repository, reference, format, query,
        expected_head, expected_commit, limits,
    })
}

pub(super) fn positive_u64(text: &str) -> Result<u64, String> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("expected a positive canonical decimal integer".into());
    }
    text.parse().map_err(|_| "decimal overflow".into())
}

// Same algorithm-qualified snapshot token as fg tree/show and lexical search.
fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (algorithm, digest) = parse_id(text)?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}

pub(super) fn parse_id(text: &str) -> Result<(DigestAlgorithmId, DigestBytes), String> {
    let (algorithm, digest) = text.strip_prefix("alg:")
        .and_then(|text| text.split_once(':'))
        .ok_or("expected an algorithm-qualified token: alg:<number>:<lowercase-hex>")?;
    let algorithm = u16::try_from(positive_u64(algorithm)?).map_err(|_| "algorithm overflow")?;
    let algorithm = DigestAlgorithmId::try_new(algorithm).map_err(|_| "invalid algorithm")?;
    if !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("token digest must be lowercase hexadecimal".into());
    }
    let digest = DigestBytes::try_new(&super::super::unhex(digest, 64)?)
        .map_err(|_| "invalid digest width")?;
    Ok((algorithm, digest))
}
