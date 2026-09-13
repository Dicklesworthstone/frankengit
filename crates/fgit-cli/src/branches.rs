//! Trusted local branch commands; the node owns validation and publication.
mod options;
use std::io::{Read, Write};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand, TerminalOutcome, MAX_IDEMPOTENCY_KEY_BYTES};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitOid, HeadGeneration, RefName, RepositoryAuthorityHeadId, TxId};
use super::publication_support::{describe, quote, write_terminal_receipt};
use options::{KeyInput, Operation, Options, hex, head_token};

const USAGE: &str = "usage: fg branch <create|update|delete|rename> <storage-root> <tenant-id> <repository-id>
  --trusted-local --principal <id> (--idempotency-key <key> | --key-stdin)
  (--ref <refs/heads/name> | --ref-hex <bytes>) [--object-format sha1|sha256]
  create: --target <existing-commit-oid> (destination must be absent)
  update: --expected-tip <old-oid> --target <existing-commit-oid>
  delete: --expected-tip <old-oid>
  rename: --expected-tip <old-oid> (--destination <refs/heads/name> | --destination-hex <bytes>)

usage: fg branch list <storage-root> <tenant-id> <repository-id> --trusted-local
  [--object-format sha1|sha256] [--limit <1..100>]
  [(--after <full-reference> | --after-hex <bytes>) --expected-head <snapshot-token>]

Full branch references and exact native object IDs are required. New tips must
already be verified commits reachable from visible repository refs. Rename is
one atomic expected-tip deletion and absent-destination creation, not two writes.
The canonical default branch cannot be deleted/renamed; PR metadata is not rewritten.
There is no implicit force, latest-tip lookup, automatic conflict retry, or remote auth.
Retry with identical inputs and key, or recover read-only with fg outcome. Stdin
keys are bounded and byte-exact, including any newline; keys are never printed.
Exit 0: committed/read; 3: canonical refusal; 2: input, infrastructure or cleanup error.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] || (args.len()==2 && args[1]=="--help" && matches!(args[0].as_str(),"list"|"create"|"update"|"delete"|"rename")) {
        emit(&mut std::io::stdout().lock(),USAGE)?;return Ok(0);
    }
    let options=options::parse(args)?;
    let session=match &options.operation {
        Operation::Mutate { principal, key, .. } => {
            let bytes=match key { KeyInput::Bytes(bytes)=>bytes.clone(),KeyInput::Stdin=>read_key(&mut std::io::stdin().lock())? };
            Some(LoopbackReceiveSession::authenticated(*principal,IdempotencyKey::new(bytes).map_err(|_|"invalid idempotency key")?))
        }
        Operation::List { .. } => None,
    };
    let mut node=OneNode::open_existing(NodeConfig::new(options.storage.clone(),options.tenant,options.repository)
        .with_object_format(options.format)).map_err(|error|format!("cannot open branch node: {error}"))?;
    let operation=(|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error|error.to_string())?;
        let request=node.request_context();
        match &options.operation {
            Operation::Mutate { commands, .. } => {
                let session=session.as_ref().ok_or("authenticated branch session missing")?;
                let result=node.runtime().block_on(node.admit_branch_updates_durable_in(&request,session,commands,Default::default()))
                    .map_err(|error|error.to_string())?;
                let Some(first)=result.commands.first() else { return Err("admission returned no terminal command".into()); };
                if !result.session.atomic || result.session.tx_ids!=vec![first.tx_id]
                    || result.commands.len()!=commands.len() || result.commands.iter().any(|command|command!=first) {
                    return Err(format!("inconsistent atomic branch receipt; {}",describe(first.tx_id,&first.terminal)));
                }
                Ok(Completed::Mutation(first.tx_id,first.terminal))
            }
            Operation::List { after,limit,expected_head } => node.runtime().block_on(node.list_branch_refs_in(
                &request,&Default::default(),after.as_ref(),*limit,*expected_head,
            )).map(|(head,rows,next)|Completed::Read(head,rows,next)).map_err(|error|error.to_string()),
        }
    })();
    let cleanup=node.shutdown().err().map(|error|error.to_string());
    match operation {
        Ok(Completed::Mutation(tx,terminal))=>finish_mutation(&mut std::io::stdout().lock(),&options,tx,&terminal,cleanup.as_deref()),
        Ok(Completed::Read(head,rows,next))=>{
            if let Some(error)=cleanup {return Err(format!("branch read node shutdown failed: {error}"));}
            emit(&mut std::io::stdout().lock(),&read_receipt(&options,head,&rows,next.as_ref()))?;Ok(0)
        }
        Err(error)=>{
            let cleanup=cleanup.map_or_else(String::new,|error|format!("; node shutdown also failed: {error}"));
            match options.operation {
                Operation::Mutate{..}=>Err(format!("no terminal branch outcome returned: {error}{cleanup}; this is not evidence of non-commit. Use fg outcome with the original scoped key or retry the identical command; do not change the key, branch names or expected tips")),
                Operation::List{..}=>Err(format!("branch read failed: {error}{cleanup}; no complete result was returned")),
            }
        }
    }
}
enum Completed { Mutation(TxId,TerminalOutcome), Read(RepositoryAuthorityHeadId,Vec<(RefName,GitOid)>,Option<RefName>) }
fn emit(output:&mut impl Write,text:&str)->Result<(),String> {
    writeln!(output,"{text}").and_then(|()|output.flush()).map_err(|error|format!("branch output incomplete: {error}"))
}
fn read_key(input:&mut impl Read)->Result<Vec<u8>,String> {
    let mut bytes=Vec::new();input.take((MAX_IDEMPOTENCY_KEY_BYTES+1)as u64).read_to_end(&mut bytes).map_err(|error|error.to_string())?;
    if bytes.is_empty() || bytes.len()>MAX_IDEMPOTENCY_KEY_BYTES {return Err("key must contain 1..256 exact bytes".into());}Ok(bytes)
}
fn command_json(command:&RefCommand)->String {
    let old=match command.expected_old {ExpectedOld::Exactly(oid)=>quote(&oid.to_string()),_=>"null".into()};
    let new=match command.proposed_new {ProposedNew::Update(oid)=>quote(&oid.to_string()),ProposedNew::Delete=>"null".into()};
    format!("{{\"reference_hex\":{},\"expected_tip\":{old},\"target\":{new}}}",quote(&hex(command.name.as_bytes())))
}
fn finish_mutation(output:&mut impl Write,options:&Options,tx:TxId,terminal:&TerminalOutcome,cleanup:Option<&str>)->Result<u8,String> {
    let Operation::Mutate{action,principal,commands,..}=&options.operation else {return Err("branch receipt operation mismatch".into());};
    let (state,exit,rcr,code,refusal)=match terminal.outcome {
        DecisionOutcome::Committed{repository_commit_id}=>("committed",0,quote(&repository_commit_id.to_string()),"null".into(),"null".into()),
        DecisionOutcome::Refused{code,refusal_record_id}=>("refused",3,"null".into(),quote(&format!("{code:?}")),quote(&refusal_record_id.to_string())),
    };
    let commands=commands.iter().map(command_json).collect::<Vec<_>>().join(",");
    let receipt=format!(concat!("{{\"type\":\"branch_publication\",\"schema_version\":1,\"action\":{},\"atomic\":true,",
        "\"outcome\":{},\"command_committed\":{},\"tx_id\":{},\"decision_sequence\":{},",
        "\"repository_commit_id\":{rcr},\"refusal_code\":{code},\"refusal_record_id\":{refusal},",
        "\"tenant_id\":{},\"repository_id\":{},\"principal_id\":{},\"object_format\":{},\"commands\":[{commands}],",
        "\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}"),
        quote(action),quote(state),exit==0,quote(&tx.to_string()),terminal.decision_sequence.get(),
        quote(&options.tenant.to_string()),quote(&options.repository.to_string()),quote(&principal.to_string()),
        quote(options.format.as_str()),cleanup.is_none(),cleanup.map_or_else(||"null".into(),quote), rcr=rcr, code=code, refusal=refusal, commands=commands);
    if let Err(error)=write_terminal_receipt(output,&receipt,tx,terminal) {
        return Err(cleanup.map_or(error.clone(),|cleanup|format!("{error}; node shutdown also failed: {cleanup}")));
    }
    if let Some(error)=cleanup {return Err(format!("{}; node shutdown failed: {error}",describe(tx,terminal)));}
    Ok(exit)
}
fn read_receipt(options:&Options,head:RepositoryAuthorityHeadId,rows:&[(RefName,GitOid)],next:Option<&RefName>)->String {
    let rows=rows.iter().map(|(name,oid)|format!("{{\"reference_hex\":{},\"tip\":{}}}",quote(&hex(name.as_bytes())),quote(&oid.to_string()))).collect::<Vec<_>>().join(",");
    format!(concat!("{{\"type\":\"branch_page\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},\"branches\":[{rows}],",
        "\"next_after_hex\":{},\"has_more\":{},\"node_closed\":true}}"),
        quote(&options.tenant.to_string()),quote(&options.repository.to_string()),quote(options.format.as_str()),
        quote(&head.to_string()),quote(&head_token(head)),next.map_or_else(||"null".into(),|name|quote(&hex(name.as_bytes()))),next.is_some(), rows=rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stdin_key_is_bounded_and_byte_exact() {
        assert_eq!(read_key(&mut &b"private-key\n"[..]).unwrap(),b"private-key\n");
        assert_eq!(read_key(&mut &vec![7;256][..]).unwrap().len(),256);
        assert!(read_key(&mut &vec![7;257][..]).is_err());assert!(read_key(&mut &b""[..]).is_err());
    }
}
