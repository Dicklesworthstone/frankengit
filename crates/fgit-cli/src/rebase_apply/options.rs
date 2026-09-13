use super::USAGE;
use crate::commit_replay::unhex;
use crate::publication_support::parse_oid;
use fgit_authority::MAX_IDEMPOTENCY_KEY_BYTES;
use fgit_types::{GitOid, PrincipalId, RefName, RepositoryId, TenantId};
use std::{collections::BTreeMap, path::PathBuf};

pub(super) struct Options {
    pub storage: PathBuf, pub tenant: TenantId, pub repository: RepositoryId,
    pub principal: PrincipalId, pub reference: RefName, pub bundle: PathBuf,
    pub source: GitOid, pub onto: GitOid, pub candidate: GitOid, pub key: KeyInput,
}
pub(super) enum KeyInput { Bytes(Vec<u8>), Stdin }

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5 { return Err(USAGE.into()); }
    if args.len() > 32 || args.iter().any(|text| text.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768 {
        return Err("rebase apply arguments exceed the bounded profile".into());
    }
    if [args[0].as_str(), args[4].as_str()].iter().any(|path| path.is_empty() || path.len() > 4096) {
        return Err("storage and bundle paths must be nonempty and bounded".into());
    }
    let tenant = TenantId::from_hex(&args[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new();
    let mut at = 5;
    while at < args.len() {
        let flag = args[at].as_str(); at += 1;
        let switch = matches!(flag, "--trusted-local" | "--allow-rewrite" | "--source-ref-hex" | "--key-stdin");
        if !switch && !matches!(flag, "--principal" | "--expected-source" | "--expected-onto"
            | "--expected-commit" | "--idempotency-key") {
            return Err("unknown rebase apply option".into());
        }
        let value = if switch { "" } else {
            let value = args.get(at).ok_or_else(|| format!("missing value for {flag}"))?;
            at += 1; value.as_str()
        };
        if flags.insert(flag, value).is_some() { return Err(format!("duplicate {flag}")); }
    }
    if !flags.contains_key("--trusted-local") { return Err("--trusted-local is required; a key is not a credential".into()); }
    if !flags.contains_key("--allow-rewrite") { return Err("--allow-rewrite is required to publish a rebase".into()); }
    let required = |flag: &str| flags.get(flag).copied().ok_or_else(|| format!("{flag} is required"));
    let principal = PrincipalId::from_hex(required("--principal")?).map_err(|_| "invalid principal ID")?;
    let source = parse_oid(required("--expected-source")?)?;
    let onto = parse_oid(required("--expected-onto")?)?;
    let candidate = parse_oid(required("--expected-commit")?)?;
    if source.algorithm() != onto.algorithm() || source.algorithm() != candidate.algorithm() {
        return Err("all rebase commit IDs must use the same native hash domain".into());
    }
    let bytes = if flags.contains_key("--source-ref-hex") { unhex(&args[3], 4096)? }
        else if args[3].len() <= 4096 { args[3].as_bytes().to_vec() }
        else { return Err("source reference exceeds its byte limit".into()); };
    if !bytes.starts_with(b"refs/heads/") { return Err("source must be a full refs/heads/ reference".into()); }
    let reference = RefName::try_new(&bytes).map_err(|_| "invalid source reference bytes")?;
    let key = match (flags.get("--idempotency-key"), flags.contains_key("--key-stdin")) {
        (Some(text), false) if !text.is_empty() && text.len() <= MAX_IDEMPOTENCY_KEY_BYTES => KeyInput::Bytes(text.as_bytes().to_vec()),
        (None, true) => KeyInput::Stdin,
        _ => return Err("supply exactly one bounded nonempty --idempotency-key or --key-stdin".into()),
    };
    Ok(Options { storage: args[0].clone().into(), tenant, repository, principal, reference,
        bundle: args[4].clone().into(), source, onto, candidate, key })
}
