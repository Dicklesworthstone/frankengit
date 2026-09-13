//! Repository-owned named-review requirements, through canonical node APIs.
use crate::publication_support::{describe, quote, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_forge::event::protection::{BranchReviewRule, ProtectionCommand, RepositoryProtectionPolicy,
    MAX_BRANCH_REVIEWERS, MAX_PROTECTED_BRANCHES, MAX_PROTECTION_ADMINISTRATORS};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode, RepositoryProtectionView};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RepositoryId, TenantId, TxId};
use std::{collections::BTreeMap, io::Write, path::PathBuf};

const USAGE: &str = "\
usage: fg protection show <storage-root> <tenant-id> <repository-id> --trusted-local
  [--object-format sha1|sha256]
usage: fg protection set <storage-root> <tenant-id> <repository-id> --trusted-local
  --principal <id> --idempotency-key <key> --expected-version <version>
  --expected-policy-epoch <epoch> --administrator <id> [--administrator <id> ...]
  (--rule <refs/heads/branch> <reviewer-id[,reviewer-id...]> ... | --clear-rules)
  [--object-format sha1|sha256]

Set replaces the complete policy and administrator set. Omitted rules are NOT preserved.
Bootstrap uses version 0; later changes require the exact shown version and policy epoch.
Every listed reviewer must approve the exact native PR candidate at the current epoch.
Protected branches reject direct writes, including administrator/force/import/workspace writes.
This trusted-local administrative profile is not remote authentication or arbitrary policy DSL.
Exit 0: committed/read; 3: canonical refusal; 2: input/infrastructure/cleanup/output failure.";

#[derive(Debug)]
struct Options {
    storage: PathBuf, tenant: TenantId, repository: RepositoryId, format: GitHashAlgorithm,
    change: Option<Change>,
}
#[derive(Debug)]
struct Change { principal: PrincipalId, key: Vec<u8>, command: ProtectionCommand }
fn number(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len()>1 && text.starts_with('0')) {
        return Err("expected a canonical unsigned decimal integer".into());
    }
    text.parse().map_err(|_| "decimal overflow".into())
}
fn principal(text: &str) -> Result<PrincipalId, String> {
    PrincipalId::from_hex(text).map_err(|_| "invalid principal identity".into())
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len()<4 || !matches!(args[0].as_str(), "show"|"set") { return Err(USAGE.into()); }
    if args.len()>450 || args.iter().any(|s| s.len()>8192)
        || args.iter().try_fold(0usize,|n,s| n.checked_add(s.len())).is_none_or(|n| n>512*1024)
    { return Err("protection arguments exceed the bounded profile".into()); }
    if args[1].is_empty() || args[1].len()>4096 { return Err("invalid bounded storage path".into()); }
    let tenant=TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository=RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let set=args[0]=="set";
    let (mut trusted, mut clear, mut cursor)=(false,false,4);
    let mut flags=BTreeMap::new(); let mut administrators=Vec::new(); let mut branches=Vec::new();
    while cursor<args.len() {
        let flag=args[cursor].as_str(); cursor+=1;
        if flag=="--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".into()); }
            trusted=true; continue;
        }
        if flag=="--clear-rules" {
            if !set || clear { return Err("--clear-rules is permitted once, only for set".into()); }
            clear=true; continue;
        }
        if flag!="--object-format" && (!set || !matches!(flag,"--principal"|"--idempotency-key"|
            "--expected-version"|"--expected-policy-epoch"|"--administrator"|"--rule"))
        { return Err(format!("unknown or inapplicable protection option {flag:?}")); }
        let value=args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?; cursor+=1;
        match flag {
            "--administrator" => {
                if administrators.len()==MAX_PROTECTION_ADMINISTRATORS { return Err("too many administrators".into()); }
                administrators.push(principal(value)?);
            }
            "--rule" => {
                if branches.len()==MAX_PROTECTED_BRANCHES { return Err("too many protected branches".into()); }
                let target=RefName::try_new(value.as_bytes()).map_err(|_| "invalid protected branch name")?;
                let names=args.get(cursor).ok_or("each --rule requires a separate comma-delimited reviewer list")?; cursor+=1;
                let mut reviewers=Vec::new();
                for name in names.split(',') {
                    if reviewers.len()==MAX_BRANCH_REVIEWERS { return Err("too many required reviewers".into()); }
                    reviewers.push(principal(name)?);
                }
                reviewers.sort();
                branches.push(BranchReviewRule { target, reviewers });
            }
            _ => { if flags.insert(flag,value.as_str()).is_some() { return Err(format!("duplicate {flag}")); } }
        }
    }
    if !trusted { return Err("--trusted-local is required".into()); }
    let format=match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1"=>GitHashAlgorithm::Sha1,"sha256"=>GitHashAlgorithm::Sha256,
        _=>return Err("--object-format must be sha1 or sha256".into()),
    };
    let change=if set {
        if clear==!branches.is_empty() { return Err("supply --rule entries OR explicit --clear-rules".into()); }
        let required=|name:&str| flags.get(name).copied().ok_or_else(|| format!("{name} is required"));
        let principal=principal(required("--principal")?)?;
        let key=required("--idempotency-key")?.as_bytes().to_vec();
        IdempotencyKey::new(key.clone()).map_err(|_| "invalid bounded idempotency key")?;
        let version=number(required("--expected-version")?)?;
        let expected_version=if version==0 { ExpectedVersion::NewStream }
            else { ExpectedVersion::Exactly(AggregateVersion::try_new(version).ok_or("invalid version")?) };
        let expected_policy_epoch=PolicyEpoch::try_new(number(required("--expected-policy-epoch")?)?)
            .map_err(|_| "invalid policy epoch")?;
        administrators.sort(); branches.sort_by(|a,b| a.target.cmp(&b.target));
        let command=ProtectionCommand { expected_version, expected_policy_epoch,
            policy: RepositoryProtectionPolicy { administrators, branches } };
        command.proposed_event(principal).map_err(|_| "invalid, duplicate, empty, exhausted or out-of-scope protection policy")?;
        Some(Change { principal, key, command })
    } else { None };
    Ok(Options { storage:args[1].clone().into(),tenant,repository,format,change })
}
fn version(command: &ProtectionCommand) -> u64 {
    match command.expected_version { ExpectedVersion::NewStream=>0,ExpectedVersion::Exactly(n)=>n.get() }
}
fn principals(values:&[PrincipalId]) -> String {
    format!("[{}]",values.iter().map(|id| quote(&id.to_string())).collect::<Vec<_>>().join(","))
}
fn policy_json(policy:&RepositoryProtectionPolicy) -> String {
    let branches=policy.branches.iter().map(|rule| format!("{{\"target\":{},\"reviewers\":{}}}",
        quote(&String::from_utf8_lossy(rule.target.as_bytes())),principals(&rule.reviewers))).collect::<Vec<_>>().join(",");
    format!("{{\"administrators\":{},\"branches\":[{branches}]}}",principals(&policy.administrators))
}
fn read_json(options:&Options,view:&RepositoryProtectionView) -> Result<String,String> {
    let (configured,version,policy)=match &view.selected {
        None=>(false,0,"null".into()),
        Some(selected)=>{
            if selected.source_head!=view.source_head || selected.event.activated_epoch().map_err(|_| "invalid activated epoch")?>view.policy_epoch {
                return Err("protection response is not bound to the selected head and epoch".into());
            }
            selected.event.validate().map_err(|_| "invalid canonical policy response")?;
            (true,selected.version.get(),policy_json(&selected.event.policy))
        }
    };
    Ok(format!(concat!("{{\"type\":\"repository_protection\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"object_format\":{},\"source_head\":{},\"policy_epoch\":{},\"configured\":{},\"version\":{},\"policy\":{},\"node_closed\":true}}"),
        quote(&options.tenant.to_string()),quote(&options.repository.to_string()),quote(options.format.as_str()),
        quote(&view.source_head.to_string()),view.policy_epoch.get(),configured,version,policy))
}
fn finish(output:&mut impl Write,change:&Change,tx:TxId,terminal:&TerminalOutcome,cleanup:Option<&str>) -> Result<u8,String> {
    let (status,rcr,refusal,code,exit)=match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } =>("committed",quote(&repository_commit_id.to_string()),"null".into(),"null".into(),0),
        DecisionOutcome::Refused { code,refusal_record_id } =>("refused","null".into(),quote(&refusal_record_id.to_string()),quote(&format!("{code:?}")),3),
    };
    let json=format!(concat!("{{\"type\":\"repository_protection_publication\",\"schema_version\":1,\"outcome\":{},\"tx_id\":{},",
        "\"decision_sequence\":{},\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},",
        "\"expected_version\":{},\"expected_policy_epoch\":{},\"principal_id\":{},\"proposed_policy\":{},",
        "\"refs_changed\":false,\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}"),
        quote(status),quote(&tx.to_string()),terminal.decision_sequence.get(),rcr,refusal,code,version(&change.command),
        change.command.expected_policy_epoch.get(),quote(&change.principal.to_string()),policy_json(&change.command.policy),
        cleanup.is_none(),cleanup.map_or_else(||"null".into(),quote));
    write_terminal_receipt(output,&json,tx,terminal).map_err(|error| format!("{error}; cleanup: {cleanup:?}"))?;
    if let Some(error)=cleanup { return Err(format!("{}; node shutdown failed: {error}",describe(tx,terminal))); }
    Ok(exit)
}
fn emit(output:&mut impl Write,text:&str) -> Result<(),String> {
    writeln!(output,"{text}").and_then(|()|output.flush()).map_err(|error|format!("protection output failed: {error}"))
}
pub(super) fn run(args:&[String]) -> Result<u8,String> {
    if args==["--help"] || (args.len()==2 && matches!(args[0].as_str(),"set"|"show") && args[1]=="--help") {
        emit(&mut std::io::stdout().lock(),USAGE)?;return Ok(0);
    }
    let options=parse(args)?;
    let mut node=OneNode::open_existing(NodeConfig::new(options.storage.clone(),options.tenant,options.repository)
        .with_object_format(options.format)).map_err(|error|format!("cannot open protection node: {error}"))?;
    let result=(|| {
        let intake=node.bring_into_service(HeadGeneration::FIRST).map_err(|error|error.to_string());
        let request=node.request_context();
        if let Some(change)=&options.change {
            let session=LoopbackReceiveSession::authenticated(change.principal,
                IdempotencyKey::new(change.key.clone()).map_err(|_|"invalid retry key")?);
            let result=node.runtime().block_on(node.admit_repository_protection_durable_in(&request,&session,&change.command,Default::default()))
                .map_err(|error|format!("{error}; service intake: {intake:?}"))?;
            Ok(Completion::Mutation(result))
        } else {
            intake?;
            let view=node.runtime().block_on(node.read_repository_protection_in(&request,None)).map_err(|error|error.to_string())?;
            Ok(Completion::Read(read_json(&options,&view)?))
        }
    })();
    let cleanup=node.shutdown().err().map(|error|error.to_string());
    match result {
        Ok(Completion::Mutation((tx,terminal))) => finish(&mut std::io::stdout().lock(),options.change.as_ref().ok_or("missing mutation")?,tx,&terminal,cleanup.as_deref()),
        Ok(Completion::Read(text)) => {
            if let Some(error)=cleanup { return Err(format!("protection read shutdown failed: {error}")); }
            emit(&mut std::io::stdout().lock(),&text)?;Ok(0)
        }
        Err(error) => Err(format!("protection operation failed: {error}; shutdown: {cleanup:?}{}",
            if options.change.is_some() { "; this does not prove non-commit. Recover with fg outcome using the same principal and key; do not refresh the version or replace the key" } else { "" })),
    }
}
enum Completion { Mutation((TxId,TerminalOutcome)),Read(String) }

#[cfg(test)]
mod tests {
    use super::*;
    fn set() -> Vec<String> {
        vec!["set".into(),"not-opened".into(),"11".repeat(16),"22".repeat(16),"--trusted-local".into(),
            "--principal".into(),"99".repeat(16),"--idempotency-key".into(),"secret-key".into(),
            "--expected-version".into(),"0".into(),"--expected-policy-epoch".into(),"1".into(),
            "--administrator".into(),"99".repeat(16),"--rule".into(),"refs/heads/main".into(),"33".repeat(16)]
    }
    #[test]
    fn policy_arguments_preserve_complete_replacement_and_sort_without_deduplicating() {
        let mut args=set();args.extend(["--administrator".into(),"88".repeat(16)]);
        let options=parse(&args).unwrap();let change=options.change.unwrap();
        assert_eq!(version(&change.command),0);
        assert!(change.command.policy.administrators[0]<change.command.policy.administrators[1]);
        args.extend(["--administrator".into(),"88".repeat(16)]);assert!(parse(&args).is_err());
        let mut args=set();let index=args.iter().position(|s|s=="--rule").unwrap();args.truncate(index);args.push("--clear-rules".into());
        assert!(parse(&args).unwrap().change.unwrap().command.policy.branches.is_empty());
        args.pop();assert!(parse(&args).is_err());
    }
    #[test]
    fn missing_trust_conflicting_rules_and_overflow_refuse_before_opening_storage() {
        for flag in ["--trusted-local","--administrator","--expected-policy-epoch","--expected-version","--principal","--idempotency-key"] {
            let mut args=set();let index=args.iter().position(|s|s==flag).unwrap();
            args.drain(index..index+if flag=="--trusted-local" {1}else{2});assert!(parse(&args).is_err(),"{flag}");
        }
        let mut args=set();args.push("--clear-rules".into());assert!(parse(&args).is_err());
        for value in ["01","-1","18446744073709551615","18446744073709551616"] {
            let mut args=set();let at=args.iter().position(|s|s=="--expected-version").unwrap();args[at+1]=value.into();assert!(parse(&args).is_err());
        }
        let mut args=set();let last=args.len()-1;args[last]=format!("{},{}","33".repeat(16),"33".repeat(16));assert!(parse(&args).is_err());
    }
    #[test]
    fn both_hash_formats_and_ref_names_with_equals_are_unambiguous() {
        for format in ["sha1","sha256"] {
            let mut args=set();args.extend(["--object-format".into(),format.into()]);
            let at=args.iter().position(|s|s=="--rule").unwrap();args[at+1]="refs/heads/name=literal".into();
            let options=parse(&args).unwrap();assert_eq!(options.format.as_str(),format);
            assert_eq!(options.change.unwrap().command.policy.branches[0].target.as_bytes(),b"refs/heads/name=literal");
        }
    }
}
