use std::{collections::BTreeMap, path::PathBuf};
use fgit_crypto::GitObjectKind;
use fgit_forge::tags::{TagCommand, TagMetadata, validate_tag_name};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId, CANONICAL_CODEC_VERSION};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};

#[derive(Debug)]
pub(super) enum Key { Bytes(Vec<u8>), Stdin }
#[derive(Debug)]
pub(super) enum Operation {
    Mutate { command: TagCommand, principal: PrincipalId, key: Key, message_file: Option<PathBuf> },
    List { after: Option<RefName>, limit: u16, head: Option<RepositoryAuthorityHeadId> },
    Show { reference: RefName, head: Option<RepositoryAuthorityHeadId> },
}
#[derive(Debug)]
pub(super) struct Options {
    pub storage: PathBuf, pub tenant: TenantId, pub repository: RepositoryId,
    pub format: GitHashAlgorithm, pub action: String, pub operation: Operation,
}
pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5 || args.len() > 40 || args.iter().any(|v| v.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768 { return Err(super::USAGE.into()); }
    let action = args[0].as_str();
    if !matches!(action, "create" | "annotate" | "delete" | "list" | "show") || args[1].is_empty() { return Err(super::USAGE.into()); }
    let mut flags = BTreeMap::new(); let mut cursor = 4;
    while cursor < args.len() {
        let flag = args[cursor].as_str(); cursor += 1;
        let common = matches!(flag, "--trusted-local" | "--object-format");
        let allowed = common || match action {
            "list" => matches!(flag, "--after" | "--after-hex" | "--limit" | "--expected-head"),
            "show" => matches!(flag, "--ref" | "--ref-hex" | "--expected-head"),
            _ => matches!(flag, "--ref" | "--ref-hex" | "--principal" | "--idempotency-key" | "--key-stdin")
                || (matches!(action, "create" | "annotate") && flag == "--target")
                || (action == "delete" && flag == "--expected-tip")
                || (action == "annotate" && matches!(flag, "--target-kind" | "--tagger" | "--timestamp" | "--message-file")),
        };
        if !allowed { return Err(format!("unsupported tag option {flag}")); }
        let value = if matches!(flag, "--trusted-local" | "--key-stdin") { "" }
            else { let value = args.get(cursor).ok_or_else(|| format!("missing {flag} value"))?; cursor += 1; value.as_str() };
        if flags.insert(flag, value).is_some() { return Err(format!("duplicate {flag}")); }
    }
    if !flags.contains_key("--trusted-local") { return Err("--trusted-local is required".into()); }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256, _ => return Err("object format must be sha1 or sha256".into()),
    };
    let head = flags.get("--expected-head").map(|v| parse_head(v)).transpose()?;
    let operation = match action {
        "list" => {
            let after = if flags.contains_key("--after") || flags.contains_key("--after-hex") { Some(reference(&flags, "--after", "--after-hex")?) } else { None };
            if after.is_some() && head.is_none() { return Err("tag continuation requires --expected-head".into()); }
            let limit = flags.get("--limit").map(|v| decimal(v)).transpose()?.unwrap_or(50);
            if !(1..=100).contains(&limit) { return Err("tag page limit must be 1..100".into()); }
            Operation::List { after, limit: limit as u16, head }
        }
        "show" => Operation::Show { reference: reference(&flags, "--ref", "--ref-hex")?, head },
        _ => {
            let name = reference(&flags, "--ref", "--ref-hex")?;
            let principal = PrincipalId::from_hex(required(&flags, "--principal")?).map_err(|_| "invalid principal ID")?;
            let key = match (flags.get("--idempotency-key"), flags.contains_key("--key-stdin")) {
                (Some(value), false) if !value.is_empty() && value.len() <= 256 => Key::Bytes(value.as_bytes().to_vec()),
                (None, true) => Key::Stdin,
                _ => return Err("supply exactly one 1..256-byte key or --key-stdin".into()),
            };
            let target_flag = if action == "delete" { "--expected-tip" } else { "--target" };
            let target = GitOid::from_hex(format, required(&flags, target_flag)?).map_err(|_| "invalid target object ID for selected format")?;
            if target.is_zero() { return Err("zero target is not an object ID".into()); }
            let mut message_file = None;
            let command = match action {
                "create" => TagCommand::Lightweight { name, target },
                "delete" => TagCommand::Delete { name, expected: target },
                _ => {
                    let target_kind = match required(&flags, "--target-kind")? {
                        "commit" => GitObjectKind::Commit, "tree" => GitObjectKind::Tree,
                        "blob" => GitObjectKind::Blob, "tag" => GitObjectKind::Tag, _ => return Err("target kind must be commit, tree, blob, or tag".into()),
                    };
                    let path = required(&flags, "--message-file")?;
                    if path.is_empty() { return Err("message path must be nonempty".into()); }
                    message_file = Some(path.into());
                    TagCommand::Annotated { name, target, target_kind, metadata: TagMetadata {
                        tagger: required(&flags, "--tagger")?.into(), timestamp: decimal(required(&flags, "--timestamp")?)?, message: Vec::new(),
                    } }
                }
            };
            command.prepare(format).map_err(|e| e.to_string())?;
            Operation::Mutate { command, principal, key, message_file }
        }
    };
    Ok(Options { storage: args[1].clone().into(), tenant: TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?,
        repository: RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?, format, action: action.into(), operation })
}
fn required<'a>(flags: &BTreeMap<&str, &'a str>, flag: &str) -> Result<&'a str, String> {
    flags.get(flag).copied().ok_or_else(|| format!("{flag} is required"))
}
fn reference(flags: &BTreeMap<&str, &str>, plain: &str, encoded: &str) -> Result<RefName, String> {
    let bytes = match (flags.get(plain), flags.get(encoded)) {
        (Some(value), None) => value.as_bytes().to_vec(), (None, Some(value)) => unhex(value, 4096)?,
        _ => return Err(format!("supply exactly one of {plain} or {encoded}")),
    };
    let reference = RefName::try_new(&bytes).map_err(|_| "invalid tag reference")?;
    validate_tag_name(&reference).map_err(|e| e.to_string())?; Ok(reference)
}
pub(super) fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len()%2 != 0 || value.len()/2 > maximum || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("invalid bounded lowercase hexadecimal bytes".into()); }
    value.as_bytes().chunks_exact(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).map_err(|_| "invalid hex")?,16).map_err(|_| "invalid hex".into())).collect()
}
fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) { return Err("unsigned decimal integer required".into()); }
    value.parse().map_err(|_| "integer overflow".into())
}
pub(super) fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id(); format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn parse_head(value: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (algorithm,digest) = value.strip_prefix("alg:").and_then(|v| v.split_once(':')).ok_or("invalid snapshot token")?;
    let algorithm = u16::try_from(decimal(algorithm)?).map_err(|_| "head algorithm overflow")?;
    let algorithm = DigestAlgorithmId::try_new(algorithm).map_err(|_| "invalid head algorithm")?;
    let digest = DigestBytes::try_new(&unhex(digest,64)?).map_err(|_| "invalid head digest")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest))
}
