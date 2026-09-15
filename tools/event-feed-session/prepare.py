import os, pathlib, subprocess, tempfile
ROOT=pathlib.Path.cwd()
BASE='0050e4bb55a84276da6e20c3e1e00d139d6e1189'
def git(*args,cwd=ROOT): return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=cwd,text=True).strip()
def replace(path,old,new,work):
    p=work/path; text=p.read_text(); assert text.count(old)==1,(path,old[:100],text.count(old)); p.write_text(text.replace(old,new))
FEED=r'''//! Canonical, resumable forge-event feed over authenticated repository history.
//! No mutable event table participates: cursors name committed RCR sequence and
//! event position, and every page is reconstructed from verified authority history.
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::CryptoBodyIdentity;
use fgit_forge::ForgeEvent;
use fgit_types::{Digest, PolicyEpoch, RefusalCode, RepositoryAuthorityHeadId, TxId};
use super::{storage, unavailable};
use crate::AdmissionError;

const MAX_HISTORY_BATCHES: usize = 4096;
const MAX_HISTORY_RECORDS: usize = 65_536;
const MAX_PAGE: u16 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ForgeEventCursor {
    pub repository_sequence: u64,
    pub event_index: u32,
}
impl ForgeEventCursor {
    pub fn new(repository_sequence: u64, event_index: u32) -> Result<Self, RefusalCode> {
        if repository_sequence == 0 { return Err(RefusalCode::EvidenceInvalid); }
        Ok(Self { repository_sequence, event_index })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeEventEnvelope {
    pub cursor: ForgeEventCursor,
    pub tx_id: TxId,
    pub policy_epoch: PolicyEpoch,
    pub event: ForgeEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeEventPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub events: Vec<ForgeEventEnvelope>,
    pub next_after: Option<ForgeEventCursor>,
}

#[derive(Clone, Copy)]
struct Record {
    sequence: u64,
    tx_id: TxId,
    policy_epoch: PolicyEpoch,
    event_root: Digest,
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), AdmissionError> {
    if cancelled() { Err(unavailable(RefusalCode::CancellationInProgress)) } else { Ok(()) }
}
fn page_limit(limit: u16) -> Result<usize, AdmissionError> {
    if limit == 0 || limit > MAX_PAGE { Err(unavailable(RefusalCode::ResourceBudgetExceeded)) }
    else { Ok(usize::from(limit)) }
}

/// Read forge events in canonical repository order. `after` is an append-stable
/// cursor: it may be resumed at a later descendant head because repository
/// sequence never rewinds. Callers that need one frozen page set separately pin
/// `source_head` at the node boundary. A cursor must name an event that exists in
/// the selected history; arbitrary sequence numbers are never treated as offsets.
pub async fn read_page_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    after: Option<ForgeEventCursor>,
    limit: u16,
    cancelled: &C,
) -> Result<ForgeEventPage, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let limit = page_limit(limit)?;
    checkpoint(cancelled)?;
    if after.is_some_and(|cursor| cursor.repository_sequence == 0) {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let repository = basis.body().repository_id;
    let mut successor = basis.body().clone();
    let mut reverse = Vec::<Record>::new();
    let mut batches = 0usize;
    let mut records = 0usize;
    while let Some(batch_id) = successor.decision_tail_id {
        checkpoint(cancelled)?;
        if batches >= MAX_HISTORY_BATCHES { return Err(unavailable(RefusalCode::ResourceBudgetExceeded)); }
        batches += 1;
        let predecessor_id = successor.predecessor_head_id
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let predecessor = fgit_authority::read_authority_head_body_async(store, cx, predecessor_id).await?;
        checkpoint(cancelled)?;
        let batch = fgit_authority::read_decision_batch_body_async(store, cx, batch_id).await?;
        checkpoint(cancelled)?;
        verify_pair(&CryptoBodyIdentity, &PublicationBasis::new(predecessor_id, predecessor.clone()), &batch, &successor)
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        records = records.checked_add(batch.committed_rcrs.len())
            .filter(|count| *count <= MAX_HISTORY_RECORDS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        reverse.try_reserve(batch.committed_rcrs.len())
            .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for record in batch.committed_rcrs.iter().rev() {
            if record.repository_id != repository { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
            reverse.push(Record { sequence: record.repository_sequence.get(), tx_id: record.tx_id,
                policy_epoch: record.policy_epoch, event_root: record.forge_event_batch_root });
        }
        successor = predecessor;
    }
    if successor.repository_id != repository
        || successor.generation != fgit_types::HeadGeneration::FIRST
        || successor.predecessor_head_id.is_some()
        || successor.latest_committed_rcr_id.is_some()
        || successor.latest_decision_sequence.is_some()
        || successor.latest_repository_sequence.is_some()
    { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
    reverse.reverse();
    let mut cursor_seen = after.is_none();
    let mut output = Vec::with_capacity(limit);
    let mut has_more = false;
    'records: for record in reverse {
        checkpoint(cancelled)?;
        if after.is_some_and(|cursor| record.sequence < cursor.repository_sequence) { continue; }
        let batch = storage::read_events(store, cx, repository, record.event_root).await?;
        checkpoint(cancelled)?;
        let start = match after {
            Some(cursor) if record.sequence == cursor.repository_sequence => {
                let index = usize::try_from(cursor.event_index)
                    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
                if index >= batch.events.len() { return Err(unavailable(RefusalCode::EvidenceStale)); }
                cursor_seen = true;
                index + 1
            }
            Some(cursor) if record.sequence > cursor.repository_sequence => {
                if !cursor_seen { return Err(unavailable(RefusalCode::EvidenceStale)); }
                0
            }
            _ => 0,
        };
        for (index, event) in batch.events.into_iter().enumerate().skip(start) {
            checkpoint(cancelled)?;
            if output.len() == limit { has_more = true; break 'records; }
            let event_index = u32::try_from(index)
                .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            output.push(ForgeEventEnvelope {
                cursor: ForgeEventCursor { repository_sequence: record.sequence, event_index },
                tx_id: record.tx_id, policy_epoch: record.policy_epoch, event,
            });
        }
    }
    if !cursor_seen { return Err(unavailable(RefusalCode::EvidenceStale)); }
    let next_after = if has_more { output.last().map(|item| item.cursor) } else { None };
    checkpoint(cancelled)?;
    Ok(ForgeEventPage { source_head: basis.id(), events: output, next_after })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursors_refuse_zero_sequence_and_order_lexicographically() {
        assert_eq!(ForgeEventCursor::new(0, 0), Err(RefusalCode::EvidenceInvalid));
        let a = ForgeEventCursor::new(1, 9).unwrap();
        let b = ForgeEventCursor::new(2, 0).unwrap();
        assert!(a < b);
        assert_eq!(ForgeEventCursor::new(7, 3).unwrap(), ForgeEventCursor { repository_sequence: 7, event_index: 3 });
    }
    #[test]
    fn feed_page_bounds_are_closed_and_zero_is_not_an_empty_success() {
        assert!(page_limit(0).is_err());
        assert_eq!(page_limit(1).unwrap(), 1);
        assert_eq!(page_limit(100).unwrap(), 100);
        assert!(page_limit(101).is_err());
    }
}
'''
NODE=r'''//! Repository-wide canonical forge event feed for local integrations.
use fgit_admission::merge::native::feed::{self, ForgeEventCursor, ForgeEventPage};
use fgit_types::RepositoryAuthorityHeadId;
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode};
use super::workspace_request_live;

#[derive(Debug)]
pub enum ForgeEventReadRefusal {
    InvalidLimit,
    SnapshotMoved,
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Admission(Box<fgit_admission::AdmissionError>),
}
impl std::fmt::Display for ForgeEventReadRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(out, "forge event feed refused: {self:?}") }
}
impl std::error::Error for ForgeEventReadRefusal {}

impl OneNode {
    /// Read committed forge events in repository order from canonical authority
    /// history. A cursor remains valid when the repository advances; supplying
    /// `expected_head` instead freezes pagination to one exact authority head.
    /// This trusted-local read grants no mutation authority and maintains no
    /// second event database or process-local cursor state.
    pub async fn read_forge_events_in(
        &self,
        request: &NodeRequestContext,
        after: Option<ForgeEventCursor>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<ForgeEventPage, ForgeEventReadRefusal> {
        if limit == 0 || limit > 100 { return Err(ForgeEventReadRefusal::InvalidLimit); }
        admits_read(self.cell_state(), ReadMode::Current).map_err(ForgeEventReadRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| ForgeEventReadRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(ForgeEventReadRefusal::SnapshotMoved);
        }
        feed::read_page_at(&self.authority, request.authority(), selected.basis(), after, limit,
            &|| !workspace_request_live(request)).await
            .map_err(|error| ForgeEventReadRefusal::Admission(Box::new(error)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refusal_vocabulary_distinguishes_input_and_snapshot_movement() {
        assert!(ForgeEventReadRefusal::InvalidLimit.to_string().contains("InvalidLimit"));
        assert!(ForgeEventReadRefusal::SnapshotMoved.to_string().contains("SnapshotMoved"));
    }
}
'''
CLI=r'''//! Resumable canonical forge-event feed for trusted local integrations.
use fgit_admission::merge::native::feed::{ForgeEventCursor, ForgeEventEnvelope};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, HeadGeneration, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use std::{collections::BTreeMap, io::Write, path::PathBuf};
use crate::publication_support::quote;

const USAGE:&str="usage: fg events <storage-root> <tenant-id> <repository-id> --trusted-local
  [--object-format sha1|sha256] [--limit <1..100>] [--after <repository-sequence:event-index>]
  [--expected-head <snapshot-token>]

Reads canonical forge events in committed repository order. Cursor values remain
append-stable across later commits; --expected-head optionally pins one exact
snapshot and refuses movement. Each row includes the canonical encoded event
frame in lowercase hex, so integrations need not infer fields from display text.
This command is read-only and does not acknowledge delivery. Exit 0: complete
page; 2: input/read/output failure.";

struct Options { storage:PathBuf, tenant:TenantId, repository:RepositoryId,
    format:GitHashAlgorithm, after:Option<ForgeEventCursor>, limit:u16,
    expected_head:Option<RepositoryAuthorityHeadId> }

pub(super) fn run(args:&[String])->Result<u8,String>{
    if args==["--help"] { write_page(&mut std::io::stdout().lock(),USAGE)?; return Ok(0); }
    let options=parse(args)?;
    let mut node=OneNode::open_existing(NodeConfig::new(options.storage.clone(),options.tenant,options.repository)
        .with_object_format(options.format)).map_err(|e|e.to_string())?;
    let operation=(||{
        node.bring_into_service(HeadGeneration::FIRST).map_err(|e|e.to_string())?;
        let request=node.request_context();
        node.runtime().block_on(node.read_forge_events_in(&request,options.after,options.limit,options.expected_head))
            .map_err(|e|e.to_string())
    })();
    let cleanup=node.shutdown().err().map(|e|e.to_string());
    match (operation,cleanup) {
        (Ok(page),None)=>{ write_page(&mut std::io::stdout().lock(),&receipt(&options,&page)?)?; Ok(0) }
        (result,cleanup)=>Err(format!("no complete forge event page returned{}{}",
            result.err().map_or_else(String::new,|e|format!("; read: {e}")),
            cleanup.map_or_else(String::new,|e|format!("; shutdown: {e}"))))
    }
}
fn parse(args:&[String])->Result<Options,String>{
    if args.len()<4 || args.len()>15 || args.iter().any(|v|v.len()>8192)
        || args.iter().map(String::len).sum::<usize>()>32768 { return Err(USAGE.into()); }
    if args[0].is_empty() || args[0].len()>4096 { return Err("invalid storage path".into()); }
    let tenant=TenantId::from_hex(&args[1]).map_err(|_|"invalid tenant ID")?;
    let repository=RepositoryId::from_hex(&args[2]).map_err(|_|"invalid repository ID")?;
    let mut flags=BTreeMap::new(); let mut i=3;
    while i<args.len(){ let flag=args[i].as_str(); i+=1;
        if !matches!(flag,"--trusted-local"|"--object-format"|"--limit"|"--after"|"--expected-head") { return Err(format!("unknown events option {flag}")); }
        let value=if flag=="--trusted-local" {""} else { let v=args.get(i).ok_or_else(||format!("missing value for {flag}"))?; i+=1; v.as_str() };
        if flags.insert(flag,value).is_some(){return Err(format!("duplicate events option {flag}"));}
    }
    if !flags.contains_key("--trusted-local"){return Err("--trusted-local is required for repository metadata disclosure".into());}
    let format=match flags.get("--object-format").copied().unwrap_or("sha1") {"sha1"=>GitHashAlgorithm::Sha1,"sha256"=>GitHashAlgorithm::Sha256,_=>return Err("object format must be sha1 or sha256".into())};
    let limit=u16::try_from(flags.get("--limit").map(|v|decimal(v)).transpose()?.unwrap_or(50)).map_err(|_|"event limit overflow")?;
    if !(1..=100).contains(&limit){return Err("event limit must be 1..100".into());}
    let after=flags.get("--after").map(|v|parse_cursor(v)).transpose()?;
    let expected_head=flags.get("--expected-head").map(|v|parse_head(v)).transpose()?;
    Ok(Options{storage:args[0].clone().into(),tenant,repository,format,after,limit,expected_head})
}
fn decimal(value:&str)->Result<u64,String>{ if value.is_empty()||!value.bytes().all(|b|b.is_ascii_digit())||(value.len()>1&&value.starts_with('0')){return Err("expected canonical unsigned decimal".into());} value.parse().map_err(|_|"decimal overflow".into()) }
fn parse_cursor(value:&str)->Result<ForgeEventCursor,String>{ let (sequence,index)=value.split_once(':').ok_or("event cursor must be repository-sequence:event-index")?; let sequence=decimal(sequence)?; let index=u32::try_from(decimal(index)?).map_err(|_|"event index overflow")?; ForgeEventCursor::new(sequence,index).map_err(|_|"event sequence must be nonzero".into()) }
fn unhex(value:&str)->Result<Vec<u8>,String>{ if value.is_empty()||value.len()>128||value.len()%2!=0||!value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err("expected bounded lowercase hex digest".into());} let digit=|b|if b<=b'9'{b-b'0'}else{b-b'a'+10}; Ok(value.as_bytes().chunks_exact(2).map(|p|16*digit(p[0])+digit(p[1])).collect()) }
fn hex(bytes:&[u8])->String{bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn head_token(head:RepositoryAuthorityHeadId)->String{let id=head.as_internal_object_id();format!("alg:{}:{}",id.algorithm().code_point(),hex(id.digest().as_bytes()))}
fn parse_head(value:&str)->Result<RepositoryAuthorityHeadId,String>{ let (alg,digest)=value.strip_prefix("alg:").and_then(|v|v.split_once(':')).ok_or("expected algorithm-qualified snapshot token")?; let alg=u16::try_from(decimal(alg)?).map_err(|_|"head algorithm overflow")?; let alg=DigestAlgorithmId::try_new(alg).map_err(|_|"invalid head algorithm")?; let digest=DigestBytes::try_new(&unhex(digest)?).map_err(|_|"invalid head digest width")?; Ok(RepositoryAuthorityHeadId::from_digest(alg,CANONICAL_CODEC_VERSION,digest)) }
fn cursor(value:ForgeEventCursor)->String{format!("{}:{}",value.repository_sequence,value.event_index)}
fn row(value:&ForgeEventEnvelope)->Result<String,String>{ let frame=fgit_codec::encode_body(&value.event).map_err(|e|e.to_string())?; Ok(format!("{{\"cursor\":{},\"repository_sequence\":{},\"event_index\":{},\"tx_id\":{},\"policy_epoch\":{},\"aggregate\":{},\"aggregate_version\":{},\"kind\":{},\"event_frame_hex\":{}}}",quote(&cursor(value.cursor)),value.cursor.repository_sequence,value.cursor.event_index,quote(&value.tx_id.to_string()),value.policy_epoch.get(),quote(&value.event.aggregate.to_string()),value.event.version.get(),value.event.payload.kind(),quote(&hex(&frame)))) }
fn receipt(options:&Options,page:&fgit_admission::merge::native::feed::ForgeEventPage)->Result<String,String>{ let rows=page.events.iter().map(row).collect::<Result<Vec<_>,_>>()?.join(","); Ok(format!("{{\"type\":\"forge_event_page\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},\"events\":[{}],\"next_after\":{},\"has_more\":{},\"node_closed\":true}}",quote(&options.tenant.to_string()),quote(&options.repository.to_string()),quote(options.format.as_str()),quote(&page.source_head.to_string()),quote(&head_token(page.source_head)),rows,page.next_after.map_or_else(||"null".into(),|v|quote(&cursor(v))),page.next_after.is_some())) }
fn write_page(output:&mut impl Write,page:&str)->Result<(),String>{writeln!(output,"{page}").and_then(|()|output.flush()).map_err(|e|format!("event page output incomplete: {e}"))}

#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn parser_accepts_append_cursor_and_optional_snapshot_pin(){ let base=vec!["store".into(),"11".repeat(16),"22".repeat(16),"--trusted-local".into(),"--after".into(),"7:3".into(),"--limit".into(),"100".into()]; let parsed=parse(&base).unwrap(); assert_eq!(parsed.after,Some(ForgeEventCursor{repository_sequence:7,event_index:3})); let mut bad=base.clone(); *bad.last_mut().unwrap()="101".into(); assert!(parse(&bad).is_err()); let mut zero=base; zero[5]="0:0".into(); assert!(parse(&zero).is_err()); }
    #[test] fn cursor_parser_is_canonical_and_bounded(){ assert_eq!(parse_cursor("1:0").unwrap(),ForgeEventCursor{repository_sequence:1,event_index:0}); for bad in ["01:0","1:00","0:0","1","x:0","1:4294967296"]{assert!(parse_cursor(bad).is_err(),"{bad}");} }
    #[test] fn output_failure_is_not_a_complete_page(){ struct Broken; impl Write for Broken{fn write(&mut self,b:&[u8])->std::io::Result<usize>{Ok(b.len())} fn flush(&mut self)->std::io::Result<()> {Err(std::io::Error::other("broken"))}} assert!(write_page(&mut Broken,"{}").unwrap_err().contains("incomplete")); }
}
'''
with tempfile.TemporaryDirectory(prefix='fg-event-feed-') as td:
    work=pathlib.Path(td)/'source'; git('worktree','add','--detach',str(work),BASE)
    assert not (work/'crates/fgit-admission/src/merge/native/feed.rs').exists()
    assert not (work/'crates/fgit-node/src/treefs_workspace/events.rs').exists()
    assert not (work/'crates/fgit-cli/src/events.rs').exists()
    (work/'crates/fgit-admission/src/merge/native/feed.rs').write_text(FEED)
    (work/'crates/fgit-node/src/treefs_workspace/events.rs').write_text(NODE)
    (work/'crates/fgit-cli/src/events.rs').write_text(CLI)
    replace('crates/fgit-admission/src/merge/native.rs','pub mod delivery;\n','pub mod delivery;\npub mod feed;\n',work)
    replace('crates/fgit-node/src/treefs_workspace.rs','mod issues;\n','mod issues;\nmod events;\npub use events::ForgeEventReadRefusal;\n',work)
    replace('crates/fgit-cli/src/main.rs','mod issues;\n','mod issues;\nmod events;\n',work)
    anchor='''    if arguments.first().is_some_and(|argument| argument == "tag") {\n'''
    dispatch='''    if arguments.first().is_some_and(|argument| argument == "events") {\n        return match events::run(&arguments[1..]) {\n            Ok(code) => ExitCode::from(code),\n            Err(error) => {\n                eprintln!("{{\\\"type\\\":\\\"forge_event_error\\\",\\\"schema_version\\\":1,\\\"error\\\":{}}}", publication_support::quote(&error));\n                ExitCode::from(2)\n            }\n        };\n    }\n'''+anchor
    replace('crates/fgit-cli/src/main.rs',anchor,dispatch,work)
    changed=['crates/fgit-admission/src/merge/native.rs','crates/fgit-admission/src/merge/native/feed.rs','crates/fgit-node/src/treefs_workspace.rs','crates/fgit-node/src/treefs_workspace/events.rs','crates/fgit-cli/src/main.rs','crates/fgit-cli/src/events.rs']
    for path in changed: subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',path],cwd=work,check=True)
    subprocess.run(['git','diff','--check'],cwd=work,check=True)
    git('config','user.name','Jeff Emanuel',cwd=work); git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    groups=[('admission',changed[:2],'feat(admission): add canonical resumable forge event feed'),('node',changed[2:4],'feat(node): expose canonical forge event pages'),('cli',changed[4:],'feat(cli): add resumable fg events feed')]
    for _,paths,message in groups:
        git('add','--',*paths,cwd=work); git('commit','-m',message,cwd=work)
    source=git('rev-parse','HEAD',cwd=work); branch='tooling/event-feed-result-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out: out.write('source='+source+'\n')
    print('PRODUCT_RESULT',source,branch,flush=True)
