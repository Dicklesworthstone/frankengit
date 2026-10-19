#![forbid(unsafe_code)]
//! Atomic multi-branch HTTP requests use actual TCP and native publication.
//! Reuse the source API's imported native-object fixture and HTTP client.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread::{self, JoinHandle};
use std::time::Duration;

struct BranchServer {
    client: Endpoint,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl BranchServer {
    fn start(node: OneNode, path: &Path, count: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint {
            address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap(),
        };
        let path = path.to_owned();
        let worker = thread::spawn(move || {
            let result = node.serve_repository_http_with_source_bounded(
                &listener,
                GitDaemonServerLimits::try_new(count, 2).unwrap(),
                &path,
                true,
                false,
                true,
                false,
                Duration::from_secs(5),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self { client, worker: Some(worker) }
    }
    fn finish(mut self) -> GitDaemonServerReceipt {
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for BranchServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
fn grants(node: &OneNode, path: &Path) -> String {
    let header = credentials(node, path);
    replace(path, &(header.clone() + &row('a', OWNER, "read") + &row('b', OWNER, "receive")
        + &row('c', OWNER, "outcomes-read") + &row('d', FOREIGN, "receive")
        + &row('e', FOREIGN, "outcomes-read")));
    header
}
fn base(node: &OneNode, commit: GitOid) -> GitOid {
    let object = node.read_git_object(commit).unwrap();
    let text = std::str::from_utf8(object.payload()).unwrap();
    GitOid::from_hex(commit.algorithm(), text.lines().find_map(|line| line.strip_prefix("parent ")).unwrap()).unwrap()
}
fn wire(client: &Endpoint, action: &str, token: char, key: &str, form: &str, chunked: bool) -> Vec<u8> {
    let (body, framing) = if chunked {
        let mut body = Vec::new();
        for part in form.as_bytes().chunks(11) {
            body.extend(format!("{:x}\r\n", part.len()).as_bytes());
            body.extend(part);
            body.extend(b"\r\n");
        }
        body.extend(b"0\r\n\r\n");
        (body, "Transfer-Encoding: chunked\r\n".to_owned())
    } else {
        (form.as_bytes().to_vec(), format!("Content-Length: {}\r\n", form.len()))
    };
    request(client, &format!("/api/v1/source/branches/{action}"), token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\nIdempotency-Key: {key}\r\n{framing}"), &body)
}
fn change(client: &Endpoint, action: &str, key: &str, form: &str, chunked: bool) -> Reply {
    exchange(client, &wire(client, action, 'b', key, form, chunked), true)
}
fn accepted(reply: &Reply) {
    status(reply, 200);
    assert!(reply.body.contains("\"type\":\"branch_publication\""));
    assert!(reply.body.contains("\"atomic\":true,\"terminal\":true"));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    assert_eq!(reply.body.matches("\"tx_id\"").count(), 1);
}
fn refused(reply: &Reply) {
    status(reply, 409);
    assert!(reply.body.contains("\"outcome\":\"refused\""));
    assert!(reply.body.contains("\"atomic\":true"));
}
fn list(client: &Endpoint, format: GitHashAlgorithm, extra: &str) -> Reply {
    post(client, "refs", 'a', &format!("object_format={}{extra}", format.as_str()), false)
}
fn recover(client: &Endpoint, token: char, key: &str) -> Reply {
    exchange(client, &request(client, "/api/v1/outcomes", token,
        &format!("Content-Length: 0\r\nIdempotency-Key: {key}\r\n"), &[]), true)
}
fn contains_ref(reply: &Reply, name: &str, oid: GitOid) -> bool {
    reply.body.contains(&format!("\"ref\":\"{name}\",\"ref_hex\":\"{}\",\"object_id\":\"{oid}\"", hex(name.as_bytes())))
}

#[test]
fn mixed_transaction_and_stale_refusal_are_atomic_and_retries_survive_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root=Scratch::new(); let config=root.config(format);
        let (node,tip)=fixture(&root,format); let parent=base(&node,tip);
        let path=root.0.join("credentials"); grants(&node,&path);
        let server=BranchServer::start(node,&path,9);
        let creation=format!("object_format={}&create={}:{parent}&create={}:{parent}",format.as_str(),hex(b"refs/heads/a"),hex(b"refs/heads/b"));
        accepted(&change(&server.client,"transaction","setup",&creation,false));
        let before=list(&server.client,format,""); status(&before,200);
        let operations=[format!("update={}:{parent}:{tip}",hex(b"refs/heads/a")),format!("delete={}:{parent}",hex(b"refs/heads/b")),format!("create={}:{tip}",hex(b"refs/heads/raw-\xff"))];
        let body=format!("object_format={}&{}",format.as_str(),operations.join("&"));
        let committed=change(&server.client,"transaction","mixed",&body,true); accepted(&committed);
        assert!(committed.body.contains("\"operation\":\"transaction\""));
        assert_eq!(committed.body.matches("\"expected_commit\"").count(),3);
        let after=list(&server.client,format,""); status(&after,200);
        assert!(contains_ref(&after,"refs/heads/a",tip));
        assert!(!after.body.contains(&hex(b"refs/heads/b")));
        assert!(after.body.contains(&hex(b"refs/heads/raw-\xff")));
        let reordered=format!("{}&object_format={}&{}&{}",operations[2],format.as_str(),operations[0],operations[1]);
        let retried=change(&server.client,"transaction","mixed",&reordered,false); accepted(&retried);
        assert_eq!(text(&retried.body,"tx_id"),text(&committed.body,"tx_id"));
        let changed=change(&server.client,"transaction","mixed",&creation,false); status(&changed,409);
        assert!(changed.body.contains("idempotency_key_reuse"));
        let stale=format!("object_format={}&update={}:{parent}:{tip}&create={}:{tip}",format.as_str(),hex(b"refs/heads/a"),hex(b"refs/heads/never-partial"));
        let rejected=change(&server.client,"transaction","stale",&stale,false); refused(&rejected);
        let unchanged=list(&server.client,format,"");
        assert!(contains_ref(&unchanged,"refs/heads/a",tip));
        assert!(!unchanged.body.contains("never-partial"));
        assert_eq!(change(&server.client,"transaction","stale",&stale,true),rejected);
        server.finish();
        let node=reopen(&config);let generation_before=generation(&node);
        let server=BranchServer::start(node,&path,3);
        assert_eq!(change(&server.client,"transaction","mixed",&body,false),committed);
        let recovery=recover(&server.client,'c',"mixed");status(&recovery,200);
        assert_eq!(text(&recovery.body,"tx_id"),text(&committed.body,"tx_id"));
        assert_eq!(change(&server.client,"transaction","stale",&stale,false),rejected);
        server.finish();let node=reopen(&config);assert_eq!(generation(&node),generation_before);node.shutdown().unwrap();
    }
}

#[test]
fn racing_transactions_publish_one_whole_set_and_refuse_the_losing_set() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root=Scratch::new();let config=root.config(format);let (node,tip)=fixture(&root,format);
        let path=root.0.join("credentials");grants(&node,&path);
        let server=BranchServer::start(node,&path,2);let barrier=Arc::new(Barrier::new(3));
        let mut workers=Vec::new();
        for side in ["left","right"] {
            let client=Endpoint {address:server.client.address,route:server.client.route.clone()};
            let barrier=barrier.clone();
            let body=format!("object_format={}&create={}:{tip}&create={}:{tip}",format.as_str(),hex(b"refs/heads/contended"),hex(format!("refs/heads/{side}").as_bytes()));
            workers.push(thread::spawn(move || {barrier.wait();(side,change(&client,"transaction",side,&body,false))}));
        }
        barrier.wait();let results:Vec<_>=workers.into_iter().map(|w|w.join().unwrap()).collect();server.finish();
        let node=reopen(&config);let state=node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(state.snapshot().refs.len(),3);
        assert_eq!(state.snapshot().refs.get(&RefName::try_new(b"refs/heads/contended").unwrap()),Some(&tip));
        let mut winners=0;
        for (side,reply) in results {
            let present=state.snapshot().refs.contains_key(&RefName::try_new(format!("refs/heads/{side}").as_bytes()).unwrap());
            if present {accepted(&reply);winners+=1;} else {refused(&reply);}
        }
        assert_eq!(winners,1);drop(state);node.shutdown().unwrap();
    }
}

#[test]
fn transaction_authentication_revocation_and_deployment_ceiling_precede_body_intake() {
    let format=GitHashAlgorithm::Sha256;let root=Scratch::new();let config=root.config(format);
    let (node,tip)=fixture(&root,format);let path=root.0.join("credentials");let header=grants(&node,&path);
    let server=BranchServer::start(node,&path,6);
    let head=|token,key:&str| request(&server.client,"/api/v1/source/branches/transaction",token,&format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n{key}"),&[]);
    let denied=exchange(&server.client,&head('a',"Idempotency-Key: no-scope\r\n"),false);status(&denied,403);assert!(!denied.raw.contains("100 Continue"));
    let denied=exchange(&server.client,&head('b',""),false);status(&denied,400);assert!(!denied.raw.contains("100 Continue"));
    let body=format!("object_format=sha256&create={}:{tip}&create={}:{tip}",hex(b"refs/heads/one"),hex(b"refs/heads/two"));
    accepted(&change(&server.client,"transaction","authorized",&body,false));
    replace(&path,&(header.clone()+&row('a',OWNER,"read")+&row('c',OWNER,"outcomes-read")+&row('9',OWNER,"receive")));
    let revoked=exchange(&server.client,&head('b',"Idempotency-Key: authorized\r\n"),false);status(&revoked,401);assert!(!revoked.raw.contains("100 Continue"));
    let rotated=exchange(&server.client,&wire(&server.client,"transaction",'9',"authorized",&body,true),true);accepted(&rotated);
    let recovered=recover(&server.client,'c',"authorized");status(&recovered,200);assert_eq!(text(&recovered.body,"tx_id"),text(&rotated.body,"tx_id"));
    server.finish();let node=reopen(&config);let disabled=Server::start(node,&path,1,true,false);
    status(&exchange(&disabled.client,&wire(&disabled.client,"transaction",'9',"disabled",&body,false),true),403);
    disabled.finish();let node=reopen(&config);assert_eq!(node.runtime().block_on(node.materialize_admission()).unwrap().snapshot().refs.len(),3);node.shutdown().unwrap();
}

#[test]
fn malformed_or_truncated_transaction_does_not_publish_a_valid_prefix() {
    let format=GitHashAlgorithm::Sha1;let root=Scratch::new();let config=root.config(format);let (node,tip)=fixture(&root,format);let before=generation(&node);
    let path=root.0.join("credentials");grants(&node,&path);let server=BranchServer::start(node,&path,5);
    let body=format!("object_format=sha1&create={}:{tip}",hex(b"refs/heads/valid"));
    for (key,invalid) in [("unknown",body.clone()+"&force=true"),("duplicate",body.clone()+&format!("&delete={}:{tip}",hex(b"refs/heads/valid")))] {status(&change(&server.client,"transaction",key,&invalid,false),400);}
    let raw=request(&server.client,"/api/v1/source/branches/transaction",'b',&format!("Content-Type: application/x-www-form-urlencoded\r\nIdempotency-Key: truncated\r\nContent-Length: {}\r\n",body.len()+3),body.as_bytes());
    let truncated=exchange(&server.client,&raw,true);assert!(!truncated.raw.starts_with("HTTP/1.1 200"));
    let rows=list(&server.client,format,"");status(&rows,200);assert!(!rows.body.contains("refs/heads/valid"));
    accepted(&change(&server.client,"transaction","permitted",&body,false));server.finish();
    let node=reopen(&config);assert_eq!(generation(&node),before+1);node.shutdown().unwrap();
}
