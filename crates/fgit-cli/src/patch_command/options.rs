use std::{collections::BTreeMap, path::PathBuf};
use fgit_forge::{patch::PatchLimits, preparation::MergeMetadata};
use fgit_types::{GitOid, PrincipalId, RefName, RepositoryId, TenantId};
use crate::publication_support::parse_oid;

pub(super) enum Key { Bytes(Vec<u8>), Stdin }
pub(super) enum Operation {
    Prepare { patch: PathBuf, output: PathBuf, workspace_id: [u8; 16], metadata: MergeMetadata,
        message_file: Option<PathBuf>, limits: PatchLimits },
    Apply { bundle: PathBuf, principal: PrincipalId, key: Key, candidate: GitOid },
}
pub(super) struct Options {
    pub storage: PathBuf, pub tenant: TenantId, pub repository: RepositoryId,
    pub reference: RefName, pub base: GitOid, pub operation: Operation,
}
pub(super) fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn unhex(text: &str, max: usize) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() > max * 2 || text.len() % 2 != 0
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("expected bounded lowercase hex".into());
    }
    let digit = |b| if b <= b'9' { b-b'0' } else { b-b'a'+10 };
    Ok(text.as_bytes().chunks_exact(2).map(|pair| digit(pair[0]) * 16 + digit(pair[1])).collect())
}
fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len()>1 && text.starts_with('0')) {
        return Err("expected canonical unsigned decimal".into());
    }
    text.parse().map_err(|_| "integer overflow".into())
}
fn path(text: &str) -> Result<PathBuf, String> {
    if text.is_empty() || text.len()>4096 || text.contains('\0') { return Err("local path must be nonempty and bounded".into()); }
    Ok(text.into())
}
pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len()>48 || args.iter().any(|s| s.len()>64*1024)
        || args.iter().map(String::len).sum::<usize>()>128*1024 { return Err("patch arguments exceed the bounded profile".into()); }
    let prepare = match args.first().map(String::as_str) { Some("prepare")=>true, Some("apply")=>false, _=>return Err(super::USAGE.into()) };
    let start = if prepare {7} else {6}; if args.len()<start { return Err(super::USAGE.into()); }
    let storage=path(&args[1])?; let tenant=TenantId::from_hex(&args[2]).map_err(|_|"invalid tenant ID")?;
    let repository=RepositoryId::from_hex(&args[3]).map_err(|_|"invalid repository ID")?;
    let mut flags=BTreeMap::new(); let mut at=start;
    while at<args.len() {
        let name=args[at].as_str(); at+=1;
        let switch=matches!(name,"--trusted-local"|"--ref-hex") || (!prepare && name=="--key-stdin");
        let allowed=matches!(name,"--expected-base") || if prepare {
            matches!(name,"--profile"|"--workspace-id"|"--author"|"--committer"|"--timestamp"|"--message"|"--message-file"
                |"--max-files"|"--max-hunks"|"--max-input-bytes"|"--max-output-bytes")
        } else { matches!(name,"--principal"|"--idempotency-key"|"--expected-commit") };
        if !switch && !allowed {return Err(format!("unknown patch option {name:?}"));}
        let value=if switch {""} else {let value=args.get(at).ok_or_else(||format!("missing value for {name}"))?; at+=1; value.as_str()};
        if flags.insert(name,value).is_some() {return Err(format!("duplicate {name}"));}
    }
    if !flags.contains_key("--trusted-local") {return Err("--trusted-local is required".into());}
    let required=|name| flags.get(name).copied().ok_or_else(||format!("{name} is required"));
    let bytes=if flags.contains_key("--ref-hex") {unhex(&args[4],4096)?} else {args[4].as_bytes().to_vec()};
    if bytes.len()>4096 || !bytes.starts_with(b"refs/heads/") {return Err("bounded full branch reference required".into());}
    let reference=RefName::try_new(&bytes).map_err(|_|"invalid branch reference")?;
    let base=parse_oid(required("--expected-base")?)?;
    let operation=if prepare {
        if required("--profile")? != "exact-v1" {return Err("explicit --profile exact-v1 is required".into());}
        let workspace_id=unhex(required("--workspace-id")?,16)?.try_into().map_err(|_|"workspace ID must contain 16 bytes")?;
        let (message,message_file)=match (flags.get("--message"),flags.get("--message-file")) {
            (Some(message),None)=>(message.as_bytes().to_vec(),None),
            (None,Some(file))=>(Vec::new(),Some(path(file)?)),
            _=>return Err("exactly one --message or --message-file is required".into()),
        };
        let author=required("--author")?.to_owned();
        let metadata=MergeMetadata {committer:flags.get("--committer").map_or_else(||author.clone(),|s|(*s).to_owned()),
            author,timestamp:decimal(required("--timestamp")?)?,message};
        if message_file.is_none() {metadata.validate().map_err(|error|error.to_string())?;}
        let mut limits=PatchLimits::default();
        for (name,field) in [("--max-files",&mut limits.max_files),("--max-hunks",&mut limits.max_hunks),
            ("--max-input-bytes",&mut limits.max_patch_bytes),("--max-output-bytes",&mut limits.max_output_bytes)] {
            if let Some(value)=flags.get(name) {*field=usize::try_from(decimal(value)?).map_err(|_|"limit exceeds target width")?;}
        }
        limits.validate().map_err(|error|error.to_string())?;
        let output=path(&args[6])?; if output.file_name().is_none() {return Err("output must name a new regular file".into());}
        Operation::Prepare {patch:path(&args[5])?,output,workspace_id,metadata,message_file,limits}
    } else {
        let principal=PrincipalId::from_hex(required("--principal")?).map_err(|_|"invalid principal ID")?;
        let key=match (flags.get("--idempotency-key"),flags.contains_key("--key-stdin")) {
            (Some(text),false) if !text.is_empty() && text.len()<=fgit_authority::MAX_IDEMPOTENCY_KEY_BYTES=>Key::Bytes(text.as_bytes().to_vec()),
            (None,true)=>Key::Stdin,
            _=>return Err("exactly one nonempty bounded key or --key-stdin is required".into()),
        };
        let candidate=parse_oid(required("--expected-commit")?)?;
        if candidate==base || candidate.algorithm()!=base.algorithm() {return Err("base and reviewed commit must be distinct IDs in the same native hash domain".into());}
        Operation::Apply {bundle:path(&args[5])?,principal,key,candidate}
    };
    Ok(Options {storage,tenant,repository,reference,base,operation})
}
