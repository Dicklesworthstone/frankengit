use fgit_forge::source_browse::{MAX_SOURCE_PAGE_BYTES, SourceBrowseAction, SourceBrowseQuery};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, RefName,
    RepositoryAuthorityHeadId, RepositoryId, TenantId};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Debug)]
pub(super) struct Options {
    pub storage: PathBuf, pub tenant: TenantId, pub repository: RepositoryId,
    pub reference: RefName, pub format: GitHashAlgorithm, pub query: SourceBrowseQuery,
}
pub(super) fn parse(args: &[String], file: bool) -> Result<Options, String> {
    if args.len() < 3 || args.len() > 24 || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768 { return Err(super::USAGE.into()); }
    if args[0].is_empty() { return Err("storage root must be nonempty".into()); }
    let tenant = TenantId::from_hex(&args[1]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|e| e.to_string())?;
    let mut flags = BTreeMap::new();
    let mut trusted = false;
    let mut cursor = 3;
    while cursor < args.len() {
        let flag = args[cursor].as_str(); cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".into()); } trusted = true; continue;
        }
        let allowed = matches!(flag, "--ref" | "--ref-hex" | "--path" | "--path-hex" | "--object-format" | "--expected-head" | "--expected-commit")
            || if file { matches!(flag, "--offset" | "--max-bytes") } else { matches!(flag, "--after-hex" | "--limit") };
        if !allowed { return Err(format!("unknown source read option {flag}")); }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?; cursor += 1;
        if flags.insert(flag, value.as_str()).is_some() { return Err(format!("duplicate {flag}")); }
    }
    if !trusted { return Err("--trusted-local is required for local-owner source disclosure".into()); }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256, _ => return Err("object format must be sha1 or sha256".into()),
    };
    let bytes = raw_pair(&flags, "--ref", "--ref-hex")?.ok_or("a full reference is required")?;
    if !bytes.starts_with(b"refs/") { return Err("a full refs/ reference is required".into()); }
    let reference = RefName::try_new(&bytes).map_err(|_| "invalid reference bytes")?;
    let path = raw_pair(&flags, "--path", "--path-hex")?;
    let expected_head = flags.get("--expected-head").map(|value| parse_head(value)).transpose()?;
    let expected_commit = flags.get("--expected-commit").map(|value| GitOid::from_hex(format, value).map_err(|e| e.to_string())).transpose()?;
    let action = if file {
        let offset = flags.get("--offset").map(|value| decimal(value)).transpose()?.unwrap_or(0);
        let limit = flags.get("--max-bytes").map(|value| decimal(value)).transpose()?.unwrap_or(65536);
        if limit == 0 || limit > u64::from(MAX_SOURCE_PAGE_BYTES) { return Err("byte limit must be 1..1048576".into()); }
        SourceBrowseAction::Read { offset, limit: u32::try_from(limit).map_err(|_| "byte limit overflow")? }
    } else {
        let limit = flags.get("--limit").map(|value| decimal(value)).transpose()?.unwrap_or(100);
        if !(1..=1000).contains(&limit) { return Err("directory page limit must be 1..1000".into()); }
        let after = flags.get("--after-hex").map(|value| unhex(value, 4096)).transpose()?;
        SourceBrowseAction::List { after, limit: u16::try_from(limit).map_err(|_| "page limit overflow")? }
    };
    let query = SourceBrowseQuery { path, expected_head, expected_commit, action };
    query.validate(format).map_err(|error| error.to_string())?;
    Ok(Options { storage: args[0].clone().into(), tenant, repository, reference, format, query })
}
fn raw_pair(flags: &BTreeMap<&str, &str>, plain: &str, encoded: &str) -> Result<Option<Vec<u8>>, String> {
    match (flags.get(plain), flags.get(encoded)) {
        (None, None) => Ok(None),
        (Some(value), None) if !value.is_empty() && value.len() <= 4096 => Ok(Some(value.as_bytes().to_vec())),
        (None, Some(value)) => unhex(value, 4096).map(Some),
        _ => Err(format!("supply at most one bounded nonempty {plain} or {encoded}")),
    }
}
fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return Err("expected canonical unsigned decimal".into());
    }
    text.parse().map_err(|_| "decimal overflow".into())
}
fn unhex(text: &str, limit: usize) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() % 2 != 0 || text.len() > 2*limit
        || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("expected bounded nonempty lowercase hex".into());
    }
    let nibble = |byte: u8| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|pair| 16*nibble(pair[0]) + nibble(pair[1])).collect())
}
fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (algorithm, digest) = text.strip_prefix("alg:").and_then(|text| text.split_once(':'))
        .ok_or("expected exact algorithm-qualified snapshot_token")?;
    let algorithm = u16::try_from(decimal(algorithm)?).map_err(|_| "head algorithm overflow")?;
    let algorithm = DigestAlgorithmId::try_new(algorithm).map_err(|_| "invalid head algorithm")?;
    let digest = DigestBytes::try_new(&unhex(digest, 64)?).map_err(|_| "invalid head digest width")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}
