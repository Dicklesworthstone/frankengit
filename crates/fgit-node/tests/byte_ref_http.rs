#![forbid(unsafe_code)]
//! Real HTTP pages over byte-named branches and strict current-head pins.
#[path="source_http/support.rs"]
mod support;
use support::*;
use fgit_node::{OneNode,LoopbackReceiveSession};
use fgit_authority::{IdempotencyKey,RefCommand,ExpectedOld,ProposedNew};
use fgit_types::{GitHashAlgorithm,GitOid,RefName,DecisionOutcome};

fn seed(node:&OneNode,tip:GitOid,names:&[&[u8]],key:&str) {
    let commands:Vec<_>=names.iter().map(|name|RefCommand {name:RefName::try_new(name).unwrap(),
        expected_old:ExpectedOld::Absent,proposed_new:ProposedNew::Update(tip),force:false}).collect();
    let session=LoopbackReceiveSession::authenticated(OWNER,IdempotencyKey::new(key.as_bytes().to_vec()).unwrap());
    let result=node.runtime().block_on(node.admit_branch_transaction_durable_in(
        &node.request_context(),&session,&commands,Default::default(),
    )).unwrap();
    assert!(result.commands.iter().all(|row|matches!(row.terminal.outcome,DecisionOutcome::Committed{..})));
}

#[test]
fn byte_pages_cover_every_name_exactly_once_and_refuse_stale_head_continuation() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root=Scratch::new();let config=root.config(format);let (node,tip)=fixture(&root,format);
        seed(&node,tip,&[b"refs/heads/a\xff",b"refs/heads/b\xff",b"refs/heads/z"],"seed-bytes");
        let path=root.0.join("credentials");let header=credentials(&node,&path);replace(&path,&(header+&row('a',OWNER,"read")));
        let before=generation(&node);let server=Server::start(node,&path,6,true,false);
        let legacy=post(&server.client,"refs",'a',&format!("object_format={}&namespace=branches&limit=1",format.as_str()),false);
        status(&legacy,503);
        let expected:[&[u8];4]=[b"refs/heads/a\xff",b"refs/heads/b\xff",b"refs/heads/main",b"refs/heads/z"];
        let mut token=String::new();let mut after=None;
        for (index,name) in expected.into_iter().enumerate() {
            let mut form=format!("object_format={}&namespace=branches&limit=1&cursor_encoding=hex",format.as_str());
            if let Some(cursor)=&after {form.push_str(&format!("&after={cursor}&expected_head={token}"));}
            let reply=post(&server.client,"refs",'a',&form,index%2==1);status(&reply,200);
            assert!(reply.body.contains("\"cursor_encoding\":\"hex\""));
            assert_eq!(reply.body.matches("\"object_id\"").count(),1);
            assert!(reply.body.contains(&format!("\"ref_hex\":\"{}\"",hex(name))));
            if index==0 {token=text(&reply.body,"snapshot_token").to_owned();}
            else {assert_eq!(text(&reply.body,"snapshot_token"),token);}
            if index<3 {
                let cursor=text(&reply.body,"next_after").to_owned();assert_eq!(cursor,hex(name));after=Some(cursor);
            } else {assert!(reply.body.contains("\"next_after\":null"));}
        }
        let malformed=post(&server.client,"refs",'a',&format!("object_format={}&cursor_encoding=hex&after=abc&expected_head={token}",format.as_str()),false);status(&malformed,400);
        server.finish();let node=reopen(&config);assert_eq!(generation(&node),before);
        seed(&node,tip,&[b"refs/heads/new"],"move-head");
        let server=Server::start(node,&path,3,true,false);
        let pinned=format!("object_format={}&cursor_encoding=hex&after={}&expected_head={token}",format.as_str(),hex(b"refs/heads/a\xff"));
        let stale=post(&server.client,"refs",'a',&pinned,false);status(&stale,409);assert!(stale.body.contains("source_snapshot_moved"));
        let missing_pin=post(&server.client,"refs",'a',&format!("object_format={}&cursor_encoding=hex&after={}",format.as_str(),hex(b"refs/heads/a\xff")),false);status(&missing_pin,400);
        let valid=post(&server.client,"refs",'a',&format!("object_format={}&cursor_encoding=hex&limit=100",format.as_str()),false);status(&valid,200);assert_eq!(valid.body.matches("\"object_id\"").count(),5);
        server.finish();let node=reopen(&config);assert_eq!(generation(&node),before+1);node.shutdown().unwrap();
    }
}

#[test]
fn default_text_responses_remain_byte_identical_and_encoding_never_grants_write_access() {
    let format=GitHashAlgorithm::Sha256;let root=Scratch::new();let config=root.config(format);let(node,_)=fixture(&root,format);let before=generation(&node);
    let path=root.0.join("credentials");let header=credentials(&node,&path);replace(&path,&(header+&row('a',OWNER,"read")));
    let server=Server::start(node,&path,4,true,false);
    let plain=post(&server.client,"refs",'a',"object_format=sha256",false);status(&plain,200);
    let explicit=post(&server.client,"refs",'a',"object_format=sha256&cursor_encoding=utf8",false);status(&explicit,200);assert_eq!(plain.body,explicit.body);
    assert!(!plain.body.contains("cursor_encoding"));
    let unknown=post(&server.client,"refs",'a',"object_format=sha256&cursor_encoding=base64",false);status(&unknown,400);
    let duplicate=post(&server.client,"refs",'a',"object_format=sha256&cursor_encoding=hex&cursor_encoding=utf8",false);status(&duplicate,400);
    server.finish();let node=reopen(&config);assert_eq!(generation(&node),before);node.shutdown().unwrap();
}
