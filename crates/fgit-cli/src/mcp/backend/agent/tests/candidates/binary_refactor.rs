use super::*;
use candidate::binary_test_support::{literal_member, rename_patch};
use fgit_crypto::{GitObjectKind, git_object_id};

const BEFORE: &[u8] = b"agent MCP fixture\n";
const AFTER: &[u8] = b"\0sponsored binary\xff\r\n";
const DESTINATION: &str = "assets/moved.bin";

fn command(fixture: &CandidateFixture) -> Object {
    let mut args = fixture.preparation();
    let patch = rename_patch(
        fixture.fixture.tip.algorithm(),
        "file",
        DESTINATION,
        BEFORE,
        AFTER,
    );
    args.insert("profile".into(), text("exact-tree-binary-v1"));
    args.remove("patch");
    args.insert(
        "patch_hex_chunks".into(),
        Value::Array(vec![text(hex(patch.as_bytes()))]),
    );
    args
}

#[test]
fn sponsored_binary_refactor_retains_authenticated_request_and_inspectable_handoff() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = CandidateFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = authority(&backend);
        let args = command(&fixture);
        for profile in [None, Some("exact-tree-v1")] {
            let mut original = args.clone();
            original.remove("profile");
            if let Some(profile) = profile {
                original.insert("profile".into(), text(profile));
            }
            assert_eq!(
                backend.call(NAME, &original).unwrap_err().code,
                "invalid_source_patch"
            );
        }
        let mut server = Server::new(&mut backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"binary-candidate-agent","version":"1"}}}"#).unwrap();
        server.receive(
            &mut backend,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        let prepared = invoke(&mut server, &mut backend, 2, &args);
        let result = prepared.object().unwrap();
        assert_eq!(result["profile"], text("exact-tree-binary-v1"));
        assert_eq!(result["snapshot_token"], Value::Null);
        assert_eq!(backend.call(NAME, &args).unwrap(), prepared);
        let target_blob = git_object_id(format, GitObjectKind::Blob, AFTER);
        let Value::Array(paths) = &result["paths"] else {
            panic!("complete binary path effects");
        };
        assert_eq!(paths.len(), 2);
        let created = paths[0].object().unwrap();
        assert_eq!(created["path_hex"], text(hex(DESTINATION.as_bytes())));
        assert_eq!(created["old_blob"], Value::Null);
        assert_eq!(created["new_blob"], text(hex(target_blob.as_bytes())));
        assert_eq!(created["new_mode"], text("100755"));
        let removed = paths[1].object().unwrap();
        assert_eq!(removed["path_hex"], text(hex(b"file")));
        assert_eq!(removed["new_blob"], Value::Null);
        let input = inspection(&prepared);
        let inspected = invoke(&mut server, &mut backend, 3, &input);
        for value in [&prepared, &inspected] {
            for field in ["published", "repository_changed", "approval_granted"] {
                assert_eq!(value.object().unwrap()[field], Value::Bool(false));
            }
            assert!(!value.encode(MAX_RESPONSE).unwrap().contains(&token(0x61)));
        }
        assert_eq!(
            inspected.object().unwrap()["publication_arguments"],
            result["publication_arguments"]
        );
        assert_eq!(
            inspected.object().unwrap()["bundle_sha256"],
            result["bundle_sha256"]
        );
        let review = inspected.object().unwrap()["review"].object().unwrap();
        assert_eq!(review["completion_scope"], text("entire_candidate_tree"));
        assert_eq!(review["entry_count"], text("2"));
        let Value::Array(entries) = &review["entries"] else {
            panic!("complete review entries");
        };
        let moved = entries[0].object().unwrap();
        assert_eq!(moved["path_hex"], text(hex(DESTINATION.as_bytes())));
        assert_eq!(
            moved["after"].object().unwrap()["oid"],
            text(hex(target_blob.as_bytes()))
        );
        assert_eq!(moved["after"].object().unwrap()["mode"], text("100755"));
        assert_eq!(moved["content"].object().unwrap()["kind"], text("binary"));
        assert_eq!(
            moved["content"].object().unwrap()["after_bytes"],
            text(AFTER.len().to_string())
        );
        let candidate =
            GitOid::from_hex(format, input["expected_candidate"].text().unwrap()).unwrap();
        assert!(backend.node.read_git_object(candidate).is_err());
        assert!(backend.node.read_git_object(target_blob).is_err());
        let session = backend
            .agent
            .as_ref()
            .unwrap()
            .response
            .as_ref()
            .unwrap()
            .authenticated_session();
        let fgit_admission::evidence::AdmissionAuthentication::AgentCredential(witness) =
            session.authenticated_session().unwrap().authentication()
        else {
            panic!("lost sponsored binary request");
        };
        assert_eq!(witness.agent(), AGENT);
        assert_eq!(witness.sponsor(), SPONSOR);
        assert_eq!(witness.credential_id(), fixture.credential);
        assert!(backend.agent.as_ref().unwrap().request.is_none());
        assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
        assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
        assert_eq!(authority(&backend), before);
        // Even planted operator flags cannot make a candidate credential a
        // publisher or let the new profile disclose ordinary source reads.
        backend.options.writes.source = true;
        backend.options.principal = Some(SPONSOR);
        let mut publication = result["publication_arguments"].object().unwrap().clone();
        publication.insert(
            "idempotency_key".into(),
            text("binary-candidate-cannot-publish"),
        );
        assert_eq!(
            backend
                .call("frankengit_source_publish", &publication)
                .unwrap_err()
                .code,
            "agent_operation_not_granted"
        );
        assert_eq!(
            backend
                .call("frankengit_source_blob", &Object::new())
                .unwrap_err()
                .code,
            "agent_operation_not_granted"
        );
        backend.close().unwrap();
        let mut reopened = NodeTools::open(fixture.options.clone()).unwrap();
        assert_eq!(reopened.call(NAME, &args).unwrap(), prepared);
        assert!(reopened.call(NAME, &input).is_ok());
        assert_eq!(authority(&reopened), before);
        assert!(reopened.node.read_git_object(candidate).is_err());
        revoke(
            &reopened.node,
            fixture.credential,
            "revoke-binary-candidate",
        );
        let revoked = authority(&reopened);
        for input in [&args, &input] {
            assert_eq!(
                reopened.call(NAME, input).unwrap_err().code,
                "agent_credential_unavailable"
            );
        }
        assert_eq!(authority(&reopened), revoked);
        reopened.close().unwrap();
    }
}

#[test]
fn sponsored_binary_refactor_refuses_reverse_mismatch_and_symlinks_without_effects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = CandidateFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = authority(&backend);
        let mut args = command(&fixture);
        args.remove("patch_hex_chunks");
        let patch = rename_patch(format, "file", DESTINATION, BEFORE, AFTER).replace(
            &literal_member(BEFORE),
            &literal_member(b"wrong reverse bytes\n"),
        );
        args.insert("patch".into(), text(patch));
        assert_eq!(
            backend.call(NAME, &args).unwrap_err().code,
            "invalid_source_patch"
        );
        args.insert("patch".into(), text("diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+../../outside\n\\ No newline at end of file\n"));
        assert_eq!(
            backend.call(NAME, &args).unwrap_err().code,
            "invalid_source_patch"
        );
        args.insert("profile".into(), text("exact-symlink-v1"));
        assert_eq!(
            backend.call(NAME, &args).unwrap().object().unwrap()["profile"],
            text("exact-symlink-v1")
        );
        assert_eq!(authority(&backend), before);
        assert!(
            backend
                .node
                .read_git_object(git_object_id(format, GitObjectKind::Blob, AFTER))
                .is_err()
        );
        backend.close().unwrap();
    }
}
