//! Whole-result expectations are computed from fixture intent, not the reply.
#![forbid(unsafe_code)]
#[path = "source_change_http/support.rs"]
mod support;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, GitOid};
use support::*;

fn expected(format: GitHashAlgorithm, binary_mode: &str) -> GitOid {
    let blob = |body: &[u8]| git_object_id(format, GitObjectKind::Blob, body);
    let tree = |rows: &[(&str, &[u8], GitOid)]| {
        let mut body = Vec::new();
        for (mode, path, oid) in rows {
            body.extend_from_slice(mode.as_bytes());
            body.push(b' ');
            body.extend_from_slice(path);
            body.push(0);
            body.extend_from_slice(oid.as_bytes());
        }
        git_object_id(format, GitObjectKind::Tree, &body)
    };
    let empty = tree(&[]);
    let module = git_object_id(format, GitObjectKind::Commit,
        format!("tree {empty}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nbase\n").as_bytes());
    let nested = tree(&[("100644", b"nested.txt", blob(b"needle in nested\n"))]);
    tree(&[
        ("100644", b"alpha.txt", blob(b"Edited needle\r\nababa\n")),
        (binary_mode, BINARY_PATH, blob(BINARY)),
        ("40000", b"dir", nested),
        ("120000", b"link", blob(LINK)),
        ("160000", b"module", module),
        ("100644", b"new.txt", blob(b"no final newline")),
        ("100644", b"run", blob(b"#!/bin/sh\nneedle\n")),
    ])
}
fn pinned(client: &Endpoint, base: GitOid, patch: &[u8], root: GitOid) -> BinaryReply {
    binary_exchange(
        client,
        &change_bytes(
            client,
            "prepare",
            'a',
            None,
            &format!(
                "{}&expected_result_tree={root}",
                metadata(base, "Result+intent")
            ),
            patch,
            true,
        ),
    )
}
fn mismatch(reply: &BinaryReply) {
    assert_eq!(reply.status, 409);
    let body = std::str::from_utf8(&reply.body).unwrap();
    assert!(body.contains("patch_result_tree_mismatch"));
    assert!(!body.contains("candidate_commit") && !body.contains("root_tree"));
    assert!(!reply.head.contains("multipart/mixed"));
}
#[test]
fn complete_tree_pin_refuses_valid_extra_effect_and_returns_no_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, base) = fixture(&root, format);
        let before = generation(&node);
        let wanted = expected(format, "100644");
        let alternate = expected(format, "100755");
        let credentials = root.0.join("credentials");
        configure(&node, &credentials);
        let server = Server::start(node, &credentials, 6, true, true);
        let ordinary = extract(
            &prepare(&server.client, base, &patch(), "Result+intent", false),
            format,
        );
        let bound = extract(&pinned(&server.client, base, &patch(), wanted), format);
        assert_eq!(bound.bundle, ordinary.bundle);
        assert_eq!(
            bound
                .metadata
                .replace(&format!(",\"expected_result_tree\":\"{wanted}\""), ""),
            ordinary.metadata
        );
        mismatch(&pinned(&server.client, base, &patch(), base));
        let mut extra = patch();
        extra.extend_from_slice(
            b"diff --git \"a/bin\\377.dat\" \"b/bin\\377.dat\"\nold mode 100644\nnew mode 100755\n",
        );
        let unbound = extract(
            &prepare(&server.client, base, &extra, "Result+intent", false),
            format,
        );
        assert_eq!(text(&unbound.metadata, "root_tree"), alternate.to_string());
        mismatch(&pinned(&server.client, base, &extra, wanted));
        let permitted = extract(&pinned(&server.client, base, &extra, alternate), format);
        assert_eq!(permitted.bundle, unbound.bundle);
        server.finish();
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        assert!(node.read_git_object(bound.commit).is_err());
        assert!(node.read_git_object(permitted.commit).is_err());
        node.shutdown().unwrap();
    }
}
