use super::*;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{CANONICAL_CODEC_VERSION, GenerationId};
use std::collections::BTreeMap;

#[derive(Debug)]
pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub reference: RefName,
    pub format: GitHashAlgorithm,
    pub query: LexicalQuery,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_commit: Option<GitOid>,
    pub generation: Option<GenerationActivation>,
    pub minimum: Option<GenerationActivation>,
    pub after: Option<u64>,
    pub limits: LexicalQueryLimits,
    pub read_limits: LexicalReadLimits,
}
impl Options {
    pub fn request(&self) -> RevalidatedIndexRequest<'_> {
        RevalidatedIndexRequest {
            reference: &self.reference,
            expected_head: self.expected_head,
            expected_commit: self.expected_commit,
            generation: self.generation.as_ref(),
            minimum: self.minimum.as_ref(),
            query: &self.query,
            after: self.after,
            query_limits: self.limits,
            read_limits: self.read_limits,
        }
    }
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4 || args.len() > 360
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err(USAGE.into());
    }
    if args[0].is_empty() {
        return Err("storage root must be nonempty".into());
    }
    let tenant = TenantId::from_hex(&args[1]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|e| e.to_string())?;
    let reference = RefName::try_new(args[3].as_bytes()).map_err(|e| e.to_string())?;
    if !reference.as_bytes().starts_with(b"refs/") {
        return Err("a full refs/ reference is required".into());
    }
    let mut trusted = false;
    let mut flags = BTreeMap::new();
    let mut terms = Vec::new();
    let mut paths = Vec::new();
    let mut cursor = 4;
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
        if !matches!(flag,
            "--term" | "--path" | "--path-hex" | "--channel" | "--object-format"
            | "--expected-head" | "--expected-commit" | "--generation"
            | "--generation-number" | "--minimum-generation" | "--minimum-number"
            | "--after" | "--max-results" | "--max-work" | "--max-index-bytes")
        {
            return Err(format!("unknown indexed search option {flag}"));
        }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--term" => {
                if terms.len() == 32 {
                    return Err("at most 32 complete terms are supported".into());
                }
                terms.push(value.as_bytes().to_vec());
            }
            "--path" | "--path-hex" => {
                if paths.len() == 128 {
                    return Err("at most 128 path prefixes are supported".into());
                }
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
    if !trusted {
        return Err("--trusted-local is required for whole-repository indexed reads".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let channel = match flags.get("--channel").copied().unwrap_or("content") {
        "content" => LexicalChannel::Content,
        "path" => LexicalChannel::Path,
        _ => return Err("channel must be content or path".into()),
    };
    let query = LexicalQuery::new(channel, &terms, &paths).map_err(|e| e.to_string())?;
    let expected_head = flags.get("--expected-head").map(|text| {
        let (algorithm, digest) = parse_id(text)?;
        Ok::<_, String>(RepositoryAuthorityHeadId::from_digest(
            algorithm, CANONICAL_CODEC_VERSION, digest,
        ))
    }).transpose()?;
    let expected_commit = flags.get("--expected-commit")
        .map(|text| GitOid::from_hex(format, text).map_err(|e| e.to_string()))
        .transpose()?;
    if expected_commit.is_some_and(|commit| commit.is_zero()) {
        return Err("expected commit must be nonzero".into());
    }
    let generation = activation(&flags, "--generation", "--generation-number")?;
    let minimum = activation(&flags, "--minimum-generation", "--minimum-number")?;
    let after = flags.get("--after").map(|text| decimal(text)).transpose()?;
    if after.is_some() && (expected_head.is_none() || expected_commit.is_none() || generation.is_none()) {
        return Err("--after requires --expected-head, --expected-commit, --generation and --generation-number".into());
    }
    let defaults = LexicalQueryLimits::default();
    let limits = LexicalQueryLimits {
        max_results: flags.get("--max-results")
            .map(|text| super::super::decimal(text)).transpose()?.unwrap_or(defaults.max_results),
        max_work: flags.get("--max-work").map(|text| decimal(text)).transpose()?.unwrap_or(defaults.max_work),
    };
    limits.validate().map_err(|e| e.to_string())?;
    let mut read_limits = LexicalReadLimits::default();
    if let Some(text) = flags.get("--max-index-bytes") {
        let limit = super::super::decimal(text)?;
        if limit > read_limits.max_payload_bytes {
            return Err("index byte limit exceeds the bounded profile".into());
        }
        read_limits.max_payload_bytes = limit;
    }
    Ok(Options {
        storage: args[0].clone().into(), tenant, repository, reference, format, query,
        expected_head, expected_commit, generation, minimum, after, limits, read_limits,
    })
}

fn activation(
    flags: &BTreeMap<&str, &str>, token: &str, number: &str,
) -> Result<Option<GenerationActivation>, String> {
    match (flags.get(token), flags.get(number)) {
        (None, None) => Ok(None),
        (Some(text), Some(number)) => {
            let (algorithm, digest) = parse_id(text)?;
            Ok(Some(GenerationActivation {
                generation_id: GenerationId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest),
                authority_generation: fgit_types::HeadGeneration::try_new(decimal(number)?)
                    .map_err(|e| e.to_string())?,
            }))
        }
        _ => Err(format!("{token} and {number} must be supplied together")),
    }
}

// Same algorithm-qualified snapshot-token spelling as fg tree/show. The kind
// is selected by the option, never inferred from an unqualified hex digest.
fn parse_id(text: &str) -> Result<(DigestAlgorithmId, DigestBytes), String> {
    let (algorithm, digest) = text.strip_prefix("alg:")
        .and_then(|text| text.split_once(':'))
        .ok_or("expected an algorithm-qualified token: alg:<number>:<lowercase-hex>")?;
    let algorithm = u16::try_from(decimal(algorithm)?).map_err(|_| "algorithm overflow")?;
    let algorithm = DigestAlgorithmId::try_new(algorithm).map_err(|_| "invalid algorithm")?;
    if !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("token digest must be lowercase hexadecimal".into());
    }
    let digest = DigestBytes::try_new(&super::super::unhex(digest, 64)?)
        .map_err(|_| "invalid digest width")?;
    Ok((algorithm, digest))
}

pub(super) fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected a positive canonical decimal integer".into());
    }
    text.parse().map_err(|_| "decimal overflow".into())
}
