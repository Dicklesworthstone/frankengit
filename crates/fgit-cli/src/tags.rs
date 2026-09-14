//! Trusted-local native tags. Only OneNode can validate and publish mutations.
mod options;
use std::{fs, io::{Read, Write}, path::Path};
use fgit_authority::{IdempotencyKey, TerminalOutcome, MAX_IDEMPOTENCY_KEY_BYTES};
use fgit_forge::tags::{TagCommand, TagRead, TagSignatureState, MAX_TAG_MESSAGE_BYTES};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitOid, HeadGeneration, RefName, RepositoryAuthorityHeadId, TxId};
use super::publication_support::{describe, quote, write_terminal_receipt};
use options::{Key, Operation, Options, hex, head_token};

const USAGE: &str = "usage: fg tag <create|annotate|delete|list|show> <storage-root> <tenant-id> <repository-id>
  --trusted-local [--object-format sha1|sha256]
  create: (--ref <refs/tags/name> | --ref-hex <bytes>) --target <oid>
  annotate: (--ref <refs/tags/name> | --ref-hex <bytes>) --target <oid>
    --target-kind <commit|tree|blob|tag> --tagger 'Name <mail>' --timestamp <seconds>
    --message-file <regular-file>
  delete: (--ref <refs/tags/name> | --ref-hex <bytes>) --expected-tip <oid>
  Mutations require --principal <id> and (--idempotency-key <key> | --key-stdin).
  list: [--limit <1..100>] [(--after <ref> | --after-hex <bytes>) --expected-head <token>]
  show: (--ref <ref> | --ref-hex <bytes>) [--expected-head <token>]

Creation never replaces a tag; deletion compares its exact unpeeled tip. Original
objects must be currently visible. Messages are exact file bytes (0..65536), not
trimmed or inferred from Git configuration. Stdin keys are 1..256 exact bytes,
including any newline; keys are never printed. Show verifies native identities and
peels at most 64 annotations, 1 MiB per object and 4 MiB total including the final
object. Signature presence is not verification or trust. No force or remote auth.
Exit 0: committed/read; 3: canonical refusal; 2: input/infrastructure/cleanup error.";

fn message_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_TAG_MESSAGE_BYTES as u64 { return Err("message must be a bounded regular file, not a symlink or device".into()); }
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() > MAX_TAG_MESSAGE_BYTES as u64 { return Err("message file changed type or exceeded its bound".into()); }
    let mut bytes = Vec::new(); file.take((MAX_TAG_MESSAGE_BYTES+1) as u64).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_TAG_MESSAGE_BYTES || bytes.contains(&0) { return Err("message exceeds 65536 bytes or contains NUL".into()); }
    Ok(bytes)
}
fn read_key(key: &Key, input: &mut impl Read) -> Result<Vec<u8>, String> {
    let bytes = match key { Key::Bytes(bytes) => bytes.clone(), Key::Stdin => {
        let mut bytes = Vec::new(); input.take((MAX_IDEMPOTENCY_KEY_BYTES+1) as u64).read_to_end(&mut bytes).map_err(|e| e.to_string())?; bytes
    } };
    if bytes.is_empty() || bytes.len() > MAX_IDEMPOTENCY_KEY_BYTES { return Err("key must contain 1..256 exact bytes".into()); } Ok(bytes)
}
enum Completed { Mutation(TxId, TerminalOutcome), Read(String) }
pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] || (args.len()==2 && args[1]=="--help" && matches!(args[0].as_str(),"create"|"annotate"|"delete"|"list"|"show")) {
        write_read(&mut std::io::stdout().lock(),USAGE)?; return Ok(0);
    }
    let mut options = options::parse(args)?;
    let session = match &mut options.operation {
        Operation::Mutate { command, principal, key, message_file } => {
            if let (TagCommand::Annotated { metadata, .. }, Some(path)) = (command, message_file) { metadata.message = message_bytes(path)?; }
            Some(LoopbackReceiveSession::authenticated(*principal, IdempotencyKey::new(read_key(key, &mut std::io::stdin().lock())?).map_err(|e| e.to_string())?))
        }
        _ => None,
    };
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(),options.tenant,options.repository).with_object_format(options.format))
        .map_err(|e| format!("cannot open tag node: {e}"))?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|e| e.to_string())?;
        let request = node.request_context();
        match &options.operation {
            Operation::Mutate { command, .. } => {
                let result = node.runtime().block_on(node.admit_tag_durable_in(&request,session.as_ref().ok_or("tag authentication missing")?,command,Default::default()))
                    .map_err(|e| e.to_string())?;
                let first = result.commands.first().ok_or("tag admission returned no terminal outcome")?;
                if !result.session.atomic || result.session.tx_ids != vec![first.tx_id] || result.commands.len()!=1 {
                    return Err(format!("inconsistent tag receipt; {}",describe(first.tx_id,&first.terminal)));
                }
                Ok(Completed::Mutation(first.tx_id,first.terminal))
            }
            Operation::List { after, limit, head } => {
                let (head, rows, next) = node.runtime().block_on(node.list_tag_refs_in(&request,&Default::default(),after.as_ref(),*limit,*head)).map_err(|e| e.to_string())?;
                Ok(Completed::Read(list_receipt(&options,head,&rows,next.as_ref())))
            }
            Operation::Show { reference, head } => {
                let result = node.runtime().block_on(node.read_tag_in(&request,reference,&Default::default(),*head,Default::default())).map_err(|e| e.to_string())?;
                Ok(Completed::Read(show_receipt(&options,&result)))
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    match operation {
        Ok(Completed::Mutation(tx,terminal)) => finish_mutation(&mut std::io::stdout().lock(),&options,tx,&terminal,cleanup.as_deref()),
        Ok(Completed::Read(receipt)) => {
            if let Some(error)=cleanup { return Err(format!("tag node shutdown failed: {error}; no complete read returned")); }
            write_read(&mut std::io::stdout().lock(),&receipt)?; Ok(0)
        }
        Err(error) => {
            let cleanup=cleanup.map_or_else(String::new,|e|format!("; node shutdown also failed: {e}"));
            if session.is_some() { Err(format!("no terminal tag outcome returned: {error}{cleanup}; this is not evidence of non-commit. Retry identical inputs/key or use fg outcome; do not silently replace the key or expected tip")) }
            else { Err(format!("tag read failed: {error}{cleanup}; no complete read returned")) }
        }
    }
}
fn write_read(output: &mut impl Write, receipt: &str) -> Result<(),String> {
    writeln!(output,"{receipt}").and_then(|()|output.flush()).map_err(|e|format!("tag read output incomplete: {e}"))
}
fn scope(options: &Options) -> String {
    format!("\"tenant_id\":{},\"repository_id\":{},\"object_format\":{}",quote(&options.tenant.to_string()),quote(&options.repository.to_string()),quote(options.format.as_str()))
}
fn list_receipt(options: &Options, head: RepositoryAuthorityHeadId, rows: &[(RefName,GitOid)], next: Option<&RefName>) -> String {
    let rows = rows.iter().map(|(name,tip)|format!("{{\"reference_hex\":{},\"tip\":{}}}",quote(&hex(name.as_bytes())),quote(&tip.to_string()))).collect::<Vec<_>>().join(",");
    format!("{{\"type\":\"tag_page\",\"schema_version\":1,{},\"source_head\":{},\"snapshot_token\":{},\"tags\":[{rows}],\"next_after_hex\":{},\"has_more\":{},\"node_closed\":true,\"repository_changed\":false}}",
        scope(options),quote(&head.to_string()),quote(&head_token(head)),next.map_or_else(||"null".into(),|r|quote(&hex(r.as_bytes()))),next.is_some())
}
fn show_receipt(options: &Options, read: &TagRead) -> String {
    let annotations = read.annotations.iter().map(|a|format!("{{\"object_id\":{},\"target\":{},\"target_kind\":{},\"body_hex\":{},\"signature_state\":{}}}",
        quote(&a.id.to_string()),quote(&a.target.to_string()),quote(a.target_kind.label()),quote(&hex(&a.body)),quote(match a.signature { TagSignatureState::Absent=>"absent",TagSignatureState::OpaqueUnverifiable=>"opaque_unverifiable" }))).collect::<Vec<_>>().join(",");
    format!("{{\"type\":\"tag_object\",\"schema_version\":1,{},\"source_head\":{},\"snapshot_token\":{},\"reference_hex\":{},\"tip\":{},\"peeled\":{},\"peeled_kind\":{},\"annotations\":[{annotations}],\"signature_verification\":\"not_performed\",\"node_closed\":true,\"repository_changed\":false}}",
        scope(options),quote(&read.head.to_string()),quote(&head_token(read.head)),quote(&hex(read.reference.as_bytes())),quote(&read.tip.to_string()),quote(&read.peeled.to_string()),quote(read.peeled_kind.label()))
}
fn finish_mutation(output: &mut impl Write, options: &Options, tx: TxId, terminal: &TerminalOutcome, cleanup: Option<&str>) -> Result<u8,String> {
    let Operation::Mutate { command, principal, .. } = &options.operation else { return Err("tag receipt operation mismatch".into()); };
    let (state,exit,rcr,code,refusal) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => ("committed",0,quote(&repository_commit_id.to_string()),"null".into(),"null".into()),
        DecisionOutcome::Refused { code,refusal_record_id } => ("refused",3,"null".into(),quote(&format!("{code:?}")),quote(&refusal_record_id.to_string())),
    };
    let receipt = format!("{{\"type\":\"tag_publication\",\"schema_version\":1,{},\"action\":{},\"reference_hex\":{},\"principal_id\":{},\"atomic\":true,\"outcome\":{},\"command_committed\":{},\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{rcr},\"refusal_code\":{code},\"refusal_record_id\":{refusal},\"node_closed\":{},\"cleanup_error\":{}}}",
        scope(options),quote(&options.action),quote(&hex(command.reference().as_bytes())),quote(&principal.to_string()),quote(state),exit==0,quote(&tx.to_string()),terminal.decision_sequence.get(),cleanup.is_none(),cleanup.map_or_else(||"null".into(),quote));
    if let Err(error)=write_terminal_receipt(output,&receipt,tx,terminal) {
        return Err(cleanup.map_or(error.clone(),|c|format!("{error}; node shutdown also failed: {c}")));
    }
    if let Some(error)=cleanup {return Err(format!("{}; node shutdown failed: {error}",describe(tx,terminal)));} Ok(exit)
}

#[cfg(test)]
mod tests;
