use super::{ContextLimits, InitialLimits, InitialQuery, MAX_OUTPUT_BYTES, USAGE};
use fgit_forge::source_symbols::SymbolMatchMode;
use fgit_node::source_retrieval::SymbolPolicy;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, PrincipalId, RefName, RepositoryAuthorityHeadId,
    RepositoryId, TenantId,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub reference: RefName,
    pub format: GitHashAlgorithm,
    pub sponsor: PrincipalId,
    pub query: InitialQuery,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub retrieval_limits: InitialLimits,
    pub context_limits: ContextLimits,
    pub expires_after: Duration,
    pub max_output_bytes: usize,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 370
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err(USAGE.into());
    }
    if args[0].is_empty() {
        return Err("storage root must be nonempty".into());
    }
    let tenant = TenantId::from_hex(&args[1]).map_err(|error| error.to_string())?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|error| error.to_string())?;
    let reference = RefName::try_new(args[3].as_bytes()).map_err(|error| error.to_string())?;
    if !reference.as_bytes().starts_with(b"refs/") {
        return Err("a full refs/ reference is required".into());
    }
    let mut flags = BTreeMap::new();
    let mut terms = Vec::new();
    let mut prefixes = Vec::new();
    let mut trusted = false;
    let mut at = 4;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".into());
            }
            trusted = true;
            continue;
        }
        if !matches!(
            flag,
            "--sponsor"
                | "--term"
                | "--path"
                | "--path-hex"
                | "--object-format"
                | "--expected-head"
                | "--expires-after-secs"
                | "--max-results"
                | "--max-work"
                | "--max-index-bytes"
                | "--max-files"
                | "--radius-bytes"
                | "--max-source-bytes"
                | "--max-excerpt-bytes"
                | "--max-output-bytes"
                | "--symbol"
                | "--symbol-match"
                | "--symbol-policy"
        ) {
            return Err(format!("unknown agent context option {flag}"));
        }
        let value = args
            .get(at)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        match flag {
            "--term" => {
                if terms.len() == 32 {
                    return Err("at most 32 lexical terms are supported".into());
                }
                terms.push(value.as_bytes().to_vec());
            }
            "--path" | "--path-hex" => {
                if prefixes.len() == 128 {
                    return Err("at most 128 path prefixes are supported".into());
                }
                prefixes.push(if flag == "--path" {
                    value.as_bytes().to_vec()
                } else {
                    unhex(value, 4096)?
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
        return Err(
            "--trusted-local is required: the operator authorizes repository source reads".into(),
        );
    }
    let sponsor = PrincipalId::from_hex(
        flags
            .get("--sponsor")
            .ok_or("--sponsor is required as an explicit operator assertion")?,
    )
    .map_err(|error| error.to_string())?;
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let mut query = InitialQuery::new(&terms, &prefixes).map_err(|error| error.to_string())?;
    if let Some(name) = flags.get("--symbol") {
        let mode = match flags.get("--symbol-match").copied().unwrap_or("exact") {
            "exact" => SymbolMatchMode::Exact,
            "prefix" => SymbolMatchMode::Prefix,
            _ => return Err("symbol match must be exact or prefix".into()),
        };
        let policy = match flags.get("--symbol-policy").copied().unwrap_or("required") {
            "required" => SymbolPolicy::Required,
            "optional" => SymbolPolicy::Optional,
            _ => return Err("symbol policy must be required or optional".into()),
        };
        query = query
            .with_symbols(name.as_bytes(), mode, &[], policy)
            .map_err(|error| error.to_string())?;
    } else if flags.contains_key("--symbol-match") || flags.contains_key("--symbol-policy") {
        return Err("symbol options require --symbol".into());
    }
    let retrieval = InitialLimits::default();
    let retrieval_limits = InitialLimits {
        max_results_per_channel: value(
            &flags,
            "--max-results",
            retrieval.max_results_per_channel,
            1,
            1024,
        )?,
        max_work: flags
            .get("--max-work")
            .map(|value| decimal(value))
            .transpose()?
            .unwrap_or(retrieval.max_work),
        max_payload_bytes: value(
            &flags,
            "--max-index-bytes",
            retrieval.max_payload_bytes,
            1,
            retrieval.max_payload_bytes,
        )?,
        ..retrieval
    };
    retrieval_limits
        .validate(&query)
        .map_err(|error| error.to_string())?;
    let defaults = ContextLimits::default();
    let context_limits = ContextLimits {
        max_files: value(&flags, "--max-files", defaults.max_files, 1, 32)?,
        radius_bytes: value(&flags, "--radius-bytes", defaults.radius_bytes, 0, 4096)?,
        max_source_bytes: value(
            &flags,
            "--max-source-bytes",
            defaults.max_source_bytes,
            1,
            64 * 1024 * 1024,
        )?,
        max_excerpt_bytes: value(
            &flags,
            "--max-excerpt-bytes",
            defaults.max_excerpt_bytes,
            1,
            1024 * 1024,
        )?,
    };
    context_limits
        .validate()
        .map_err(|error| error.to_string())?;
    Ok(Options {
        storage: args[0].clone().into(),
        tenant,
        repository,
        reference,
        format,
        sponsor,
        query,
        expected_head: flags
            .get("--expected-head")
            .map(|value| head(value))
            .transpose()?,
        retrieval_limits,
        context_limits,
        expires_after: Duration::from_secs(
            value(&flags, "--expires-after-secs", 30, 1, 300)? as u64
        ),
        max_output_bytes: value(
            &flags,
            "--max-output-bytes",
            MAX_OUTPUT_BYTES,
            1,
            MAX_OUTPUT_BYTES,
        )?,
    })
}

fn decimal(value: &str) -> Result<u64, String> {
    fgit_schema::json::decimal(value).map_err(str::to_owned)
}
fn value(
    flags: &BTreeMap<&str, &str>,
    flag: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, String> {
    let result = flags
        .get(flag)
        .map(|value| decimal(value))
        .transpose()?
        .unwrap_or(default as u64);
    let result = usize::try_from(result).map_err(|_| format!("{flag} exceeds platform width"))?;
    if !(minimum..=maximum).contains(&result) {
        return Err(format!("{flag} must be in {minimum}..={maximum}"));
    }
    Ok(result)
}
fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() > maximum * 2
        || !value.len().is_multiple_of(2)
        || !value.is_ascii()
    {
        return Err("hexadecimal bytes must be nonempty, even-length and bounded".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&value[at..at + 2], 16)
                .map_err(|_| "invalid hexadecimal byte".into())
        })
        .collect()
}
fn head(value: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let mut pieces = value.split(':');
    if pieces.next() != Some("alg") {
        return Err("head must be alg:<algorithm>:<digest>".into());
    }
    let algorithm = pieces.next().ok_or("head algorithm missing")?;
    let algorithm = u16::try_from(decimal(algorithm)?).map_err(|_| "invalid head algorithm")?;
    let algorithm = DigestAlgorithmId::try_new(algorithm).map_err(|error| error.to_string())?;
    let bytes = unhex(pieces.next().ok_or("head digest missing")?, 64)?;
    if pieces.next().is_some() {
        return Err("head has trailing fields".into());
    }
    let digest = DigestBytes::try_new(&bytes).map_err(|error| error.to_string())?;
    Ok(RepositoryAuthorityHeadId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        digest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "/absent-agent-context".into(),
            "31".repeat(16),
            "32".repeat(16),
            "refs/heads/main".into(),
            "--trusted-local".into(),
            "--sponsor".into(),
            "33".repeat(16),
            "--term".into(),
            "needle".into(),
        ];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        args
    }
    #[test]
    fn bounded_operator_input_and_permitted_twins() {
        let good = parse(&args(&[])).unwrap();
        assert_eq!(good.expires_after, Duration::from_secs(30));
        assert_eq!(good.query.content().terms(), &[b"needle".to_vec()]);
        for extra in [
            vec!["--trusted-local"],
            vec!["--sponsor", "ff"],
            vec!["--max-files", "0"],
            vec!["--max-files", "33"],
            vec!["--max-files", "01"],
            vec!["--max-output-bytes", "16777217"],
            vec!["--expires-after-secs", "301"],
            vec!["--expires-after-secs", "0"],
            vec!["--symbol-match", "prefix"],
            vec!["--run-id", "1"],
            vec!["--grant", "publish"],
            vec!["--expected-head", "not-a-head"],
        ] {
            assert!(parse(&args(&extra)).is_err(), "{extra:?}");
        }
        let narrowed = parse(&args(&[
            "--max-files",
            "1",
            "--radius-bytes",
            "0",
            "--expires-after-secs",
            "1",
            "--symbol",
            "Thing",
            "--symbol-policy",
            "optional",
        ]))
        .unwrap();
        assert_eq!(narrowed.context_limits.radius_bytes, 0);
        assert!(narrowed.query.symbols().is_some());
        let mut missing_trust = args(&[]);
        missing_trust.retain(|arg| arg != "--trusted-local");
        assert!(parse(&missing_trust).is_err());
        let mut missing_sponsor = args(&[]);
        missing_sponsor.drain(5..7);
        assert!(parse(&missing_sponsor).is_err());
    }
}
