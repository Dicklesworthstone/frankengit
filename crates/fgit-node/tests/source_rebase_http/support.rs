//! Real two-commit suffixes and imported native objects; the TCP client and
//! source server are the existing production-profile integration fixtures.
#[path = "../source_replay_http/support.rs"]
mod wire;
pub use wire::{BinaryReply, Endpoint, Scratch, SourceServer, OWNER, binary_exchange,
    configure, encode, extract_candidate, field, generation, hex, json, multipart,
    numeric, post_form, reopen, replace, request, row, status};

use std::fs;
use std::path::Path;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::OneNode;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid};

pub struct History { pub upstream: GitOid, pub first: GitOid, pub source: GitOid, pub onto: GitOid }
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let bytes = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let n = u16::try_from(bytes.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(n.to_le_bytes()); encoded.extend((!n).to_le_bytes()); encoded.extend(&bytes);
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521; (a, (b + a) % 65521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string(); let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap(); fs::write(directory.join(&text[2..]), encoded).unwrap(); id
}
/// Mode 0 is clean, 1 conflicts independently at both original commits, and
/// 2 already contains both changes so empty-commit policy is observable.
pub fn fixture(root: &Scratch, format: GitHashAlgorithm, mode: u8) -> (OneNode, History) {
    let source = root.0.join("rebase-source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(source.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
        GitHashAlgorithm::Sha256 => "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n",
    }).unwrap();
    let tree = |a: &[u8], b: &[u8], extra: bool| {
        let mut body = Vec::new();
        for (name, content) in [(b"a\xff".as_slice(), a), (b"b".as_slice(), b), (b"onto".as_slice(), b"onto-only\n".as_slice())] {
            if name == b"onto" && !extra { continue; }
            let blob = loose(&source, format, GitObjectKind::Blob, "blob", content);
            body.extend_from_slice(b"100644 "); body.extend_from_slice(name); body.push(0); body.extend_from_slice(blob.as_bytes());
        }
        loose(&source, format, GitObjectKind::Tree, "tree", &body)
    };
    let commit = |tree: GitOid, parent: Option<GitOid>, message: &str| {
        let body = format!("tree {tree}\n{}author Original <original@example.invalid> 5 -0330\ncommitter Original <original@example.invalid> 6 +0000\n\n{message}\n",
            parent.map_or_else(String::new, |id| format!("parent {id}\n")));
        loose(&source, format, GitObjectKind::Commit, "commit", body.as_bytes())
    };
    let upstream = commit(tree(b"base-a\n", b"base-b\n", false), None, "base");
    let first = commit(tree(b"source-a\n", b"base-b\n", false), Some(upstream), "first original message");
    let source_tip = commit(tree(b"source-a\n", b"source-b\n", false), Some(first), "second original message");
    let onto_tree = match mode {
        0 => tree(b"base-a\n", b"base-b\n", true),
        1 => tree(b"onto-a\n", b"onto-b\n", true),
        2 => tree(b"source-a\n", b"source-b\n", true),
        _ => panic!("fixture mode"),
    };
    let onto = commit(onto_tree, Some(upstream), "onto");
    fs::write(source.join("refs/heads/main"), format!("{onto}\n")).unwrap();
    fs::write(source.join("refs/heads/topic"), format!("{source_tip}\n")).unwrap();
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
    let result = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &node.request_context(), &source, OWNER, b"rebase-http-fixture")).unwrap();
    assert!(result.commands.iter().all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, History { upstream, first, source: source_tip, onto })
}
pub fn prepare_form(f: &History) -> String {
    format!("profile=linear-v1&object_format={}&source_ref=refs%2Fheads%2Ftopic&onto_ref=refs%2Fheads%2Fmain&expected_source={}&upstream={}&expected_onto={}&empty=stop&committer=Rebaser+%3Crebaser%40example.invalid%3E&timestamp=9",
        f.source.algorithm().as_str(), f.source, f.upstream, f.onto)
}
pub fn apply_form(f: &History, candidate: GitOid) -> String {
    format!("profile=linear-v1&object_format={}&ref=refs%2Fheads%2Ftopic&expected_source={}&onto={}&candidate_commit={candidate}",
        f.source.algorithm().as_str(), f.source, f.onto)
}
pub fn tip(node: &OneNode, name: &[u8]) -> GitOid {
    let state = node.runtime().block_on(node.materialize_admission()).unwrap();
    state.snapshot().refs[&fgit_types::RefName::try_new(name).unwrap()]
}
