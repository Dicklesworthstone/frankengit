//! Actual receive-pack framing and persisted outcomes, not a bypass around the daemon.
use super::*;

fn object_pack(objects: &[(GitObjectKind, Vec<u8>)]) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend(u32::try_from(objects.len()).unwrap().to_be_bytes());
    for (kind, body) in objects {
        let code = match kind {
            GitObjectKind::Commit => 1,
            GitObjectKind::Tree => 2,
            GitObjectKind::Blob => 3,
            GitObjectKind::Tag => 4,
        };
        pack.extend(object_header(code, body.len()));
        pack.extend(zlib_stored(body));
    }
    pack.extend(sha1_digest(&pack));
    pack
}

#[test]
fn ref_roots_receive_reports_noncommit_branch_refusal_without_staging_or_publication() {
    let tree = Vec::new();
    let tree_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, &tree);
    let commit = format!("tree {tree_id}\nauthor T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\nvalid commit\n").into_bytes();
    let commit_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, &commit);
    let tag = format!("object {commit_id}\ntype commit\ntag release\ntagger T <t@example.invalid> 1 +0000\n\nannotated tag\n").into_bytes();
    let objects = [
        (GitObjectKind::Tree, tree),
        (GitObjectKind::Commit, commit),
        (GitObjectKind::Tag, tag),
        (GitObjectKind::Blob, b"payload".to_vec()),
    ];
    let pack = object_pack(&objects);
    let ids = objects
        .iter()
        .map(|(kind, body)| git_object_id(GitHashAlgorithm::Sha1, *kind, body))
        .collect::<Vec<_>>();
    for index in [0, 2, 3] {
        let mut body = pkt_line(
            format!("{ZERO_OID} {} refs/heads/main\0report-status", ids[index]).as_bytes(),
        );
        body.extend_from_slice(b"0000");
        body.extend_from_slice(&pack);
        let outcome = run_session(ScratchDirectory::new(), true, body, &[]);
        let report = String::from_utf8_lossy(&outcome.report);
        assert!(
            report.contains("ng refs/heads/main"),
            "refusal must reach the raw client: {report:?}"
        );
        assert!(!report.contains("ok refs/heads/main"));
        assert!(materialized_refs(&outcome.scratch).is_empty());
        let node = OneNode::open_existing(config(outcome.scratch.0.clone())).unwrap();
        for id in &ids {
            assert!(
                node.read_git_object(*id).is_err(),
                "no partial staging for {id}"
            );
        }
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert!(selected.basis().body().latest_committed_rcr_id.is_none());
        assert!(
            selected.basis().body().latest_decision_sequence.is_none(),
            "invalid roots do not acquire a canonical transaction decision"
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn ref_roots_receive_accepts_a_native_commit_branch_and_reopens_it() {
    let tree = Vec::new();
    let tree_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, &tree);
    let commit = format!("tree {tree_id}\nauthor T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\nvalid branch\n").into_bytes();
    let id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, &commit);
    let pack = object_pack(&[
        (GitObjectKind::Tree, tree),
        (GitObjectKind::Commit, commit.clone()),
    ]);
    let mut body = pkt_line(format!("{ZERO_OID} {id} refs/heads/main\0report-status").as_bytes());
    body.extend_from_slice(b"0000");
    body.extend(pack);
    let outcome = run_session(ScratchDirectory::new(), true, body, &[]);
    outcome.server.as_ref().unwrap();
    let report = String::from_utf8_lossy(&outcome.report);
    assert!(report.contains("unpack ok") && report.contains("ok refs/heads/main"));
    assert_eq!(
        materialized_refs(&outcome.scratch),
        vec![b"refs/heads/main".to_vec()]
    );
    let node = OneNode::open_existing(config(outcome.scratch.0.clone())).unwrap();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap();
    assert_eq!(
        selected.snapshot().refs[&fgit_types::RefName::try_new(b"refs/heads/main").unwrap()],
        id
    );
    assert_eq!(node.read_git_object(id).unwrap().payload(), commit);
    node.shutdown().unwrap();
}
