#![forbid(unsafe_code)]
//! Trusted-local symbol index operations over an EXISTING node. Source reads
//! never create an index; builds require an explicit predecessor and all
//! original-candidate recovery is read-only. Shutdown is always explicit.
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use fgit_crypto::{IdentityDomain, internal_algorithm_id, internal_domain_tag};
use fgit_forge::source_symbols::{MAX_SYMBOL_WORK, SymbolMatchMode, SymbolQuery};
use fgit_forge::source_symbols::index::{AccessError, MAX_INDEX_BYTES};
use fgit_graph::{GenerationAuthorityError, GenerationRecovery, GraphGenerationId};
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestBytes, GitHashAlgorithm, InternalObjectId, RefName, RepositoryId, TenantId};

type Failure = AccessError<NodeWorkspaceRefusal, GenerationAuthorityError>;
const USAGE: &str = "fg-symbol-index ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 FULL_REF build genesis|INDEX_TOKEN\n\
fg-symbol-index ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 FULL_REF recover CANDIDATE_TOKEN\n\
fg-symbol-index ROOT TENANT_HEX REPOSITORY_HEX sha1|sha256 FULL_REF query exact|prefix NAME\n\
Index tokens have the form alg:CODE:LOWERCASE_HEX. No latest/force or repository initialization.";
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn token(id: &InternalObjectId) -> String {
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn generation(text: &str) -> Result<GraphGenerationId,String> {
    let algorithm = internal_algorithm_id(IdentityDomain::Generation);
    let width = fgit_crypto::DigestAlgorithm::from_id(algorithm).ok_or("Unknown generation algorithm.")?.digest_len();
    let prefix = format!("alg:{}:", algorithm.code_point());
    let raw = text.strip_prefix(&prefix).ok_or("Invalid generation token domain.")?;
    if raw.len() != width * 2 || !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("Generation token must contain exact lowercase hexadecimal bytes.".to_owned());
    }
    let digit = |b| if b <= b'9' {b-b'0'} else {b-b'a'+10};
    let bytes: Vec<_> = raw.as_bytes().chunks_exact(2).map(|p| digit(p[0])*16+digit(p[1])).collect();
    if bytes.iter().all(|b| *b == 0) { return Err("Zero candidate is not allowed.".to_owned()); }
    GraphGenerationId::from_internal_object_id(InternalObjectId::new(algorithm,
        internal_domain_tag(IdentityDomain::Generation),CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&bytes).map_err(|e|e.to_string())?)).map_err(|e|e.to_string())
}
#[derive(Debug)]
enum Action { Build(Option<GraphGenerationId>), Recover(GraphGenerationId), Query(SymbolQuery) }
struct Options {root:PathBuf,tenant:TenantId,repository:RepositoryId,format:GitHashAlgorithm,reference:RefName,action:Action}
fn parse(args:&[OsString])->Result<Options,String>{
    if !(7..=8).contains(&args.len()) || args.iter().any(|s|s.len()>4096) {return Err(USAGE.to_owned());}
    let text=|i:usize|args[i].to_str().ok_or_else(||"Only the root path may contain non-UTF-8 bytes.".to_owned());
    let tenant=TenantId::from_hex(text(1)?).map_err(|e|e.to_string())?;
    let repository=RepositoryId::from_hex(text(2)?).map_err(|e|e.to_string())?;
    let format=match text(3)?{"sha1"=>GitHashAlgorithm::Sha1,"sha256"=>GitHashAlgorithm::Sha256,_=>return Err(USAGE.to_owned())};
    let reference=RefName::try_new(text(4)?.as_bytes()).map_err(|e|e.to_string())?;
    if !reference.as_bytes().starts_with(b"refs/"){return Err("A full reference is required.".to_owned());}
    let action=match text(5)?{
        "build" if args.len()==7=>Action::Build(if text(6)?=="genesis"{None}else{Some(generation(text(6)?)?)}),
        "recover" if args.len()==7=>Action::Recover(generation(text(6)?)?),
        "query" if args.len()==8=>{
            let mode=match text(6)?{"exact"=>SymbolMatchMode::Exact,"prefix"=>SymbolMatchMode::Prefix,_=>return Err(USAGE.to_owned())};
            Action::Query(SymbolQuery::new(text(7)?.as_bytes(),mode,&[],&[],MAX_SYMBOL_WORK).map_err(|e|e.to_string())?)
        }
        _=>return Err(USAGE.to_owned()),
    };
    Ok(Options{root:PathBuf::from(&args[0]),tenant,repository,format,reference,action})
}
fn execute(node:&OneNode,options:&Options)->Result<String,Failure>{
    // Reuse the node's finite BackgroundController class; this does not deliver
    // or acknowledge any outbox event and does not renew an existing request.
    let request=node.outbox_delivery_context();
    match &options.action{
        Action::Build(predecessor)=>{
            let(source,activation)=node.runtime().block_on(node.build_source_symbol_index_local_in(&request,
                &options.reference,None,None,*predecessor,Default::default()))?;
            Ok(format!("{{\"type\":\"symbol_index_activation\",\"index_token\":\"{}\",\"index_number\":{},\"snapshot_token\":\"{}\",\"source_commit\":\"{}\",\"root_tree\":\"{}\",\"repository_transaction_created\":false}}",
                token(activation.generation_id.as_internal_object_id()),activation.authority_generation.get(),
                token(source.head.as_internal_object_id()),source.commit,source.tree))
        }
        Action::Query(query)=>{
            let report=node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&request,
                &options.reference,None,None,None,query,Default::default(),MAX_INDEX_BYTES))?;
            let matches=report.matches.iter().map(|row|format!("{{\"name_hex\":\"{}\",\"kind\":\"{}\",\"path_hex\":\"{}\",\"blob\":\"{}\",\"byte_offset\":{},\"line\":{},\"byte_column\":{},\"match_length\":{}}}",
                hex(&row.name),row.kind.as_str(),hex(&row.location.path),row.location.blob,row.location.byte_offset,
                row.location.line,row.location.byte_column,row.location.match_length)).collect::<Vec<_>>().join(",");
            Ok(format!("{{\"type\":\"symbol_index_query\",\"index_token\":\"{}\",\"index_number\":{},\"snapshot_token\":\"{}\",\"source_commit\":\"{}\",\"complete\":{},\"source_blobs_read\":0,\"read_only\":true,\"matches\":[{}]}}",
                token(&report.generation),report.generation_number,token(report.source.head.as_internal_object_id()),
                report.source.commit,report.complete,matches))
        }
        Action::Recover(candidate)=>{
            let report=node.runtime().block_on(node.recover_source_symbol_index_local_in(&request,
                &options.reference,*candidate,None,Default::default()))?;
            let state=match report{GenerationRecovery::Uninitialized=>"uninitialized",GenerationRecovery::Active{..}=>"active",
                GenerationRecovery::Superseded{..}=>"superseded",GenerationRecovery::NotInSelectedHistory{..}=>"not_in_selected_history"};
            Ok(format!("{{\"type\":\"symbol_index_recovery\",\"candidate_token\":\"{}\",\"state\":\"{state}\",\"read_only\":true,\"negative_observation_proves_rollback\":false}}",token(candidate.as_internal_object_id())))
        }
    }
}
fn main()->ExitCode{
    let args:Vec<_>=std::env::args_os().skip(1).take(9).collect();
    let options=match parse(&args){Ok(o)=>o,Err(e)=>{eprintln!("{e}");return ExitCode::FAILURE;}};
    let config=NodeConfig::new(options.root.clone(),options.tenant,options.repository).with_object_format(options.format).with_worker_threads(2);
    let mut node=match OneNode::open_existing(config){Ok(node)=>node,Err(e)=>{eprintln!("Open failed: {e}");return ExitCode::FAILURE;}};
    let ready=node.runtime().block_on(node.authenticate_authority_head()).map_err(|e|e.to_string())
        .and_then(|head|node.bring_into_service(head.receipt().generation()).map_err(|e|e.to_string()));
    if let Err(error)=ready{
        eprintln!("Authority unavailable: {error}");
        if let Err(error)=node.shutdown(){eprintln!("Shutdown also failed: {error}");}
        return ExitCode::FAILURE;
    }
    let result=execute(&node,&options);let shutdown=node.shutdown();
    let ok=match result{
        Ok(body)=>match writeln!(io::stdout().lock(),"{body}"){
            Ok(())=>true,Err(e)=>{eprintln!("Operation succeeded, but output failed: {e}. Do not infer rollback.");false}
        },
        Err(AccessError::Publication{candidate,cause})=>{
            eprintln!("Publication was not confirmed: {cause}\nCandidate: {}\nRecover the original candidate; this error does not prove rollback.",token(&candidate));false
        }
        Err(e)=>{eprintln!("Symbol index operation failed: {e}");false}
    };
    if let Err(e)=shutdown{eprintln!("Shutdown failed: {e}. Confirmed index activations are not undone.");return ExitCode::FAILURE;}
    if ok{ExitCode::SUCCESS}else{ExitCode::FAILURE}
}
#[cfg(test)]
mod tests{
    use super::*;
    fn args(tail:&[&str])->Vec<OsString>{
        let mut out:Vec<_>=["/unused-node","01010101010101010101010101010101","02020202020202020202020202020202","sha1","refs/heads/main"].into_iter().map(OsString::from).collect();
        out.extend(tail.iter().map(|s|OsString::from(*s)));out
    }
    #[test]
    fn build_and_recovery_never_guess_or_refresh_predecessors(){
        assert!(matches!(parse(&args(&["build","genesis"])).unwrap().action,Action::Build(None)));
        let id=format!("alg:2:{}","a".repeat(64));assert!(parse(&args(&["build",&id])).is_ok());assert!(parse(&args(&["recover",&id])).is_ok());
        for tail in [&["build","latest"][..],&["build","genesis","force"],&["recover","genesis"],&["init","genesis"]]{assert!(parse(&args(tail)).is_err());}
    }
    #[test]
    fn query_grammar_is_explicit_and_bounded(){
        assert!(parse(&args(&["query","prefix","Thing"])).is_ok());assert!(parse(&args(&["query","exact","type"])).is_ok());
        for tail in [&["query","regex","Thing"][..],&["query","prefix"],&["query","exact","r#type"],&["query","exact","a.*"]]{assert!(parse(&args(tail)).is_err());}
        assert!(parse(&args(&["query","exact",&"a".repeat(129)])).is_err());
    }
    #[test]
    fn namespace_tokens_and_full_refs_are_checked_before_open(){
        for i in [1,2,3,4]{let mut input=args(&["build","genesis"]);input[i]=OsString::from("bad");assert!(parse(&input).is_err());}
        for token in [format!("alg:2:{}","0".repeat(64)),format!("alg:1:{}","a".repeat(40)),format!("alg:2:{}","A".repeat(64))]{assert!(generation(&token).is_err());}
    }
}
