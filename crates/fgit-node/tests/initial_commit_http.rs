#![forbid(unsafe_code)]
//! Empty node -> remote artifact -> native quarantine -> restart -> ordinary
//! source editing. Competing root creations and lost receipts use real TCP.
#[allow(
    dead_code,
    unused_imports,
    reason = "reuse sibling TCP clients without copying protocol fixtures"
)]
#[path = "source_change_http/support.rs"]
mod support;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::OneNode;
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use std::io::Write;
use std::net::Shutdown;
use std::sync::{Arc, Barrier};
use std::thread;
use support::*;

const INITIAL: &[u8] = concat!(
    "diff --git a/README.md b/README.md\nnew file mode 100644\n--- /dev/null\n+++ b/README.md\n@@ -0,0 +1 @@\n+hello\r\n",
    "diff --git a/bin/run b/bin/run\nnew file mode 100755\n--- /dev/null\n+++ b/bin/run\n@@ -0,0 +1 @@\n+#!/bin/sh\n",
    "diff --git a/empty b/empty\nnew file mode 100644\n",
    "diff --git \"a/raw\\377.txt\" \"b/raw\\377.txt\"\nnew file mode 100644\n--- /dev/null\n+++ \"b/raw\\377.txt\"\n@@ -0,0 +1 @@\n+raw content\n\\ No newline at end of file\n",
).as_bytes();

fn empty(root: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(selected.receipt().generation())
        .unwrap();
    node
}
fn form(format: GitHashAlgorithm, reference: &str) -> String {
    format!(
        "object_format={}&ref={reference}&expected_absent=true",
        format.as_str()
    )
}
fn prepare_form(format: GitHashAlgorithm, reference: &str, message: &str) -> String {
    form(format, reference)
        + &format!(
            "&author=Author+%3Ca%40example.invalid%3E&committer=Committer+%3Cc%40example.invalid%3E&timestamp=1&message={message}%0A"
        )
}
fn apply_form(format: GitHashAlgorithm, reference: &str, candidate: GitOid) -> String {
    form(format, reference) + &format!("&candidate_commit={candidate}")
}
fn initial_wire(
    client: &Endpoint,
    action: &str,
    token: char,
    key: Option<&str>,
    form: &str,
    payload: &[u8],
    chunked: bool,
) -> Vec<u8> {
    let original = change_bytes(client, action, token, key, form, payload, chunked);
    let old = format!("POST {}/api/v1/source/{action} ", client.route);
    let mut changed = format!("POST {}/api/v1/source/initial/{action} ", client.route).into_bytes();
    assert!(original.starts_with(old.as_bytes()));
    changed.extend_from_slice(&original[old.len()..]);
    changed
}
fn prepare_initial(
    client: &Endpoint,
    format: GitHashAlgorithm,
    reference: &str,
    message: &str,
    chunked: bool,
) -> Artifact {
    let reply = binary_exchange(
        client,
        &initial_wire(
            client,
            "prepare",
            'a',
            None,
            &prepare_form(format, reference, message),
            INITIAL,
            chunked,
        ),
    );
    let artifact = extract(&reply, format);
    assert!(
        artifact
            .metadata
            .contains("\"type\":\"initial_source_preparation\"")
    );
    assert!(
        artifact
            .metadata
            .contains("\"parents\":[],\"prerequisites\":[]")
    );
    let input = FullBundleInput::parse(&artifact.bundle, FullBundleLimits::default(), &mut || true)
        .unwrap();
    assert!(input.prerequisites().is_empty());
    assert_eq!(input.references().len(), 1);
    assert_eq!(input.references()[0].target(), &artifact.commit);
    let commit_body = unhex(text(&artifact.metadata, "candidate_commit_body_hex"));
    assert_eq!(
        git_object_id(format, GitObjectKind::Commit, &commit_body),
        artifact.commit
    );
    assert!(
        !commit_body
            .split(|b| *b == b'\n')
            .any(|line| line.starts_with(b"parent "))
    );
    artifact
}
fn apply_initial(
    client: &Endpoint,
    format: GitHashAlgorithm,
    reference: &str,
    artifact: &Artifact,
    key: &str,
    chunked: bool,
) -> Reply {
    exchange(
        client,
        &initial_wire(
            client,
            "apply",
            'b',
            Some(key),
            &apply_form(format, reference, artifact.commit),
            &artifact.bundle,
            chunked,
        ),
        true,
    )
}

#[test]
fn empty_repository_bootstrap_is_unstaged_then_enters_the_ordinary_edit_workflow() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let node = empty(&root, format);
        let before = generation(&node);
        let original = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let path = root.0.join("credentials");
        configure(&node, &path);
        let readonly = Server::start(node, &path, 4, true, false);
        let first = prepare_initial(&readonly.client, format, "refs/heads/main", "first", false); // 1
        let repeated = prepare_initial(&readonly.client, format, "refs/heads/main", "first", true); // 2
        assert_eq!(first.commit, repeated.commit);
        assert_eq!(first.bundle, repeated.bundle);
        status(
            &apply_initial(
                &readonly.client,
                format,
                "refs/heads/main",
                &first,
                "initial",
                false,
            ),
            403,
        ); // 3
        let absent = recover(&readonly.client, 'c', "initial"); // 4
        status(&absent, 200);
        assert!(absent.body.contains("\"state\":\"key_not_observed\""));
        readonly.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        assert!(node.read_git_object(first.commit).is_err());
        let tree = GitOid::from_hex(format, text(&first.metadata, "root_tree")).unwrap();
        assert!(node.read_git_object(tree).is_err());
        assert!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs
                .is_empty()
        );
        let server = Server::start(node, &path, 8, true, true);
        let receipt = apply_initial(
            &server.client,
            format,
            "refs/heads/main",
            &first,
            "initial",
            false,
        ); // 1
        committed(&receipt);
        assert_eq!(
            apply_initial(
                &server.client,
                format,
                "refs/heads/main",
                &first,
                "initial",
                true
            ),
            receipt
        ); // 2
        let read = blob(&server.client, format, b"raw\xff.txt"); // 3
        status(&read, 200);
        assert_eq!(text(&read.body, "content_hex"), hex(b"raw content"));
        let patch = b"diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-hello\r\n+edited\r\n";
        let next = extract(
            &prepare(&server.client, first.commit, patch, "next", true),
            format,
        ); // 4
        status(&inspect(&server.client, first.commit, &next), 200); // 5
        committed(&apply(&server.client, first.commit, &next, "next", false)); // 6
        assert_eq!(
            apply_initial(
                &server.client,
                format,
                "refs/heads/main",
                &first,
                "initial",
                false
            ),
            receipt
        ); // 7
        let recovered = recover(&server.client, 'c', "initial"); // 8
        status(&recovered, 200);
        assert_eq!(text(&recovered.body, "tx_id"), text(&receipt.body, "tx_id"));
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 2);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()],
            next.commit
        );
        assert_eq!(
            selected.snapshot().head_target,
            original.snapshot().head_target
        );
        assert_eq!(selected.snapshot().outbox, original.snapshot().outbox);
        assert_eq!(
            selected.basis().body().forge_position_root,
            original.basis().body().forge_position_root
        );
        assert!(node.read_git_object(first.commit).is_ok());
        node.shutdown().unwrap();
    }
}

#[test]
fn competing_first_commits_and_equal_tip_fresh_keys_never_overwrite_a_branch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let node = empty(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        configure(&node, &path);
        let server = Server::start(node, &path, 9, true, true);
        let one = prepare_initial(&server.client, format, "refs/heads/main", "one", false); // 1
        let two = prepare_initial(&server.client, format, "refs/heads/main", "two", true); // 2
        assert_ne!(one.commit, two.commit);
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for (key, candidate) in [("one", one), ("two", two)] {
            let client = server.client.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                let reply =
                    apply_initial(&client, format, "refs/heads/main", &candidate, key, true);
                (key, candidate, reply)
            }));
        } // 3, 4: actual TCP admissions share the embedded authority.
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|(_, _, reply)| reply.status == 200)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, _, reply)| reply.status == 409)
                .count(),
            1
        );
        for (key, artifact, reply) in &results {
            assert!(reply.body.contains("\"terminal\":true"));
            assert_eq!(
                apply_initial(
                    &server.client,
                    format,
                    "refs/heads/main",
                    artifact,
                    key,
                    false
                ),
                *reply
            ); // 5, 6
        }
        let (winner_key, winner, _) = results
            .iter()
            .find(|(_, _, reply)| reply.status == 200)
            .unwrap();
        let (_, loser, _) = results
            .iter()
            .find(|(_, _, reply)| reply.status == 409)
            .unwrap();
        let equal = apply_initial(
            &server.client,
            format,
            "refs/heads/main",
            winner,
            "fresh-equal-tip",
            false,
        ); // 7
        status(&equal, 409);
        assert!(equal.body.contains("\"outcome\":\"refused\""));
        let reused = apply_initial(
            &server.client,
            format,
            "refs/heads/main",
            loser,
            winner_key,
            false,
        ); // 8
        status(&reused, 409);
        assert!(reused.body.contains("idempotency_key_reuse"));
        let recovered = recover(&server.client, 'c', winner_key); // 9
        status(&recovered, 200);
        assert!(recovered.body.contains("\"state\":\"committed\""));
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 3);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(selected.snapshot().refs.len(), 1);
        assert_eq!(
            selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()],
            winner.commit
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn orphan_history_preserves_existing_refs_and_lost_receipts_recover_without_write_access() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, original_tip) = fixture(&root, format);
        let before = generation(&node);
        let original = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let path = root.0.join("credentials");
        let header = configure(&node, &path);
        let server = Server::start(node, &path, 2, true, true);
        let artifact = prepare_initial(&server.client, format, "refs/heads/orphan", "orphan", true);
        let mut socket = connect(&server.client);
        socket
            .write_all(&initial_wire(
                &server.client,
                "apply",
                'b',
                Some("lost-root"),
                &apply_form(format, "refs/heads/orphan", artifact.commit),
                &artifact.bundle,
                false,
            ))
            .unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        server.finish();
        drop(socket); // Client never reads/stores its receipt.
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()],
            original_tip
        );
        assert_eq!(
            selected.snapshot().refs[&RefName::try_new(b"refs/heads/orphan").unwrap()],
            artifact.commit
        );
        assert_eq!(
            selected.snapshot().head_target,
            original.snapshot().head_target
        );
        assert_eq!(selected.snapshot().outbox, original.snapshot().outbox);
        replace(
            &path,
            &(header.clone()
                + &row('a', OWNER, "read")
                + &row('c', OWNER, "outcomes-read")
                + &row('d', FOREIGN, "outcomes-read")),
        );
        let server = Server::start(node, &path, 5, true, false);
        let receipt = recover(&server.client, 'c', "lost-root"); // 1
        status(&receipt, 200);
        assert!(receipt.body.contains("\"state\":\"committed\""));
        let foreign = recover(&server.client, 'd', "lost-root"); // 2
        status(&foreign, 200);
        assert!(foreign.body.contains("\"state\":\"key_not_observed\""));
        let read = post(
            &server.client,
            "blob",
            'a',
            &format!(
                "object_format={}&ref=refs/heads/orphan&path_hex=524541444d452e6d64",
                format.as_str()
            ),
            true,
        ); // 3
        status(&read, 200);
        assert_eq!(text(&read.body, "content_hex"), hex(b"hello\r\n"));
        status(
            &apply_initial(
                &server.client,
                format,
                "refs/heads/orphan",
                &artifact,
                "lost-root",
                false,
            ),
            401,
        ); // 4
        replace(
            &path,
            &(header + &row('9', OWNER, "receive") + &row('c', OWNER, "outcomes-read")),
        );
        status(
            &exchange(
                &server.client,
                &initial_wire(
                    &server.client,
                    "apply",
                    '9',
                    Some("lost-root"),
                    &apply_form(format, "refs/heads/orphan", artifact.commit),
                    &artifact.bundle,
                    true,
                ),
                true,
            ),
            403,
        ); // 5
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        node.shutdown().unwrap();
    }
}

fn withheld(client: &Endpoint, action: &str, token: char, extra: &str, bytes: usize) -> Reply {
    let response = exchange(
        client,
        &request(
            client,
            &format!("/api/v1/source/initial/{action}"),
            token,
            &format!(
                "Content-Type: multipart/form-data; boundary=x\r\nContent-Length: {bytes}\r\nExpect: 100-continue\r\n{extra}"
            ),
            &[],
        ),
        false,
    );
    assert!(!response.raw.contains("100 Continue"));
    response
}
#[test]
fn deployment_scopes_and_complete_creation_only_input_gate_bootstrap() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let config = root.config(format);
    let node = empty(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    configure(&node, &path);
    let disabled = Server::start(node, &path, 2, false, true);
    status(&withheld(&disabled.client, "prepare", 'a', "", 100), 403);
    status(
        &withheld(
            &disabled.client,
            "apply",
            'b',
            "Idempotency-Key: no\r\n",
            100,
        ),
        403,
    );
    disabled.finish();
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 11, true, true);
    status(&withheld(&server.client, "prepare", 'b', "", 100), 403); // 1
    status(
        &withheld(&server.client, "apply", 'a', "Idempotency-Key: no\r\n", 100),
        403,
    ); // 2
    status(&withheld(&server.client, "apply", 'b', "", 100), 400); // 3
    status(
        &withheld(
            &server.client,
            "prepare",
            'a',
            "Idempotency-Key: no\r\n",
            100,
        ),
        400,
    ); // 4
    status(
        &withheld(&server.client, "prepare", 'a', "", 17 * 1024 * 1024),
        413,
    ); // 5
    let form = prepare_form(format, "refs/heads/main", "first");
    let malformed = b"diff --git a/existing b/existing\n--- a/existing\n+++ b/existing\n@@ -1 +1 @@\n-old\n+new\n";
    let response = binary_exchange(
        &server.client,
        &initial_wire(
            &server.client,
            "prepare",
            'a',
            None,
            &form,
            malformed,
            false,
        ),
    ); // 6
    assert_eq!(response.status, 400);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains("creation_only_patch_required")
    );
    let mut incomplete = initial_wire(&server.client, "prepare", 'a', None, &form, INITIAL, false);
    incomplete.pop();
    let response = binary_exchange(&server.client, &incomplete); // 7
    assert_eq!(response.status, 400);
    let mut incomplete = initial_wire(&server.client, "prepare", 'a', None, &form, INITIAL, true);
    incomplete.truncate(incomplete.len() - 2);
    assert_eq!(binary_exchange(&server.client, &incomplete).status, 400); // 8
    let artifact = prepare_initial(&server.client, format, "refs/heads/main", "first", false); // 9
    let mut corrupt = artifact.clone();
    *corrupt.bundle.last_mut().unwrap() ^= 1;
    let response = apply_initial(
        &server.client,
        format,
        "refs/heads/main",
        &corrupt,
        "corrupt",
        false,
    ); // 10
    assert_ne!(response.status, 200);
    committed(&apply_initial(
        &server.client,
        format,
        "refs/heads/main",
        &artifact,
        "valid",
        true,
    )); // 11
    server.finish();
    let node = reopen(&config);
    assert_eq!(generation(&node), before + 1);
    let selected = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    assert_eq!(selected.snapshot().refs.len(), 1);
    node.shutdown().unwrap();
}
