//! Sponsored symlink edits use the same native candidate and independent
//! inspection paths as regular edits; target bytes never become host paths.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};

pub(super) fn command(fixture: &CandidateFixture, target: &str) -> Object {
    let mut args = fixture.preparation();
    args.insert("profile".into(), text("exact-symlink-v1"));
    args.insert(
        "patch".into(),
        text(format!(
            "diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+{target}\n\\ No newline at end of file\n"
        )),
    );
    args
}

#[test]
fn sponsored_symlink_candidates_preserve_inert_targets_and_inspectable_handoff() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = CandidateFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = authority(&backend);
        let mut server = Server::new(&mut backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"symlink-candidate-agent","version":"1"}}}"#).unwrap();
        server.receive(
            &mut backend,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        for (index, target) in ["../../outside", "/absolute/target"]
            .into_iter()
            .enumerate()
        {
            let args = command(&fixture, target);
            for profile in [None, Some("exact-tree-v1"), Some("exact-tree-binary-v1")] {
                let mut regular = args.clone();
                regular.remove("profile");
                if let Some(profile) = profile {
                    regular.insert("profile".into(), text(profile));
                }
                assert_eq!(
                    backend.call(NAME, &regular).unwrap_err().code,
                    "invalid_source_patch"
                );
            }
            let prepared = invoke(&mut server, &mut backend, 2 + index as u64 * 2, &args);
            let result = prepared.object().unwrap();
            assert_eq!(result["profile"], text("exact-symlink-v1"));
            assert_eq!(result["snapshot_token"], Value::Null);
            assert_eq!(backend.call(NAME, &args).unwrap(), prepared);
            let target_blob = git_object_id(format, GitObjectKind::Blob, target.as_bytes());
            let Value::Array(paths) = &result["paths"] else {
                panic!("complete symlink path effects");
            };
            assert_eq!(paths.len(), 1);
            let created = paths[0].object().unwrap();
            assert_eq!(created["path_hex"], text(hex(b"link")));
            assert_eq!(created["old_blob"], Value::Null);
            assert_eq!(created["new_blob"], text(hex(target_blob.as_bytes())));
            assert_eq!(created["new_mode"], text("120000"));

            let input = inspection(&prepared);
            let inspected = invoke(&mut server, &mut backend, 3 + index as u64 * 2, &input);
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
            let review = inspected.object().unwrap()["review"].object().unwrap();
            assert_eq!(review["completion_scope"], text("entire_candidate_tree"));
            let Value::Array(entries) = &review["entries"] else {
                panic!("complete review entries");
            };
            assert_eq!(entries.len(), 1, "the existing regular file is unchanged");
            let link = entries[0].object().unwrap();
            assert_eq!(link["path_hex"], text(hex(b"link")));
            assert_eq!(link["after"].object().unwrap()["mode"], text("120000"));
            assert_eq!(
                link["after"].object().unwrap()["oid"],
                text(hex(target_blob.as_bytes()))
            );
            let content = link["content"].object().unwrap();
            assert_eq!(content["kind"], text("text"));
            let Value::Array(hunks) = &content["hunks"] else {
                panic!("exact inert target bytes");
            };
            assert_eq!(hunks.len(), 1);
            assert_eq!(
                hunks[0].object().unwrap()["after_hex"],
                text(hex(target.as_bytes()))
            );
            let candidate =
                GitOid::from_hex(format, input["expected_candidate"].text().unwrap()).unwrap();
            assert!(backend.node.read_git_object(candidate).is_err());
            assert!(backend.node.read_git_object(target_blob).is_err());
            assert!(!fixture.fixture.root.join("link").exists());
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
                panic!("lost sponsored symlink request");
            };
            assert_eq!(witness.agent(), AGENT);
            assert_eq!(witness.sponsor(), SPONSOR);
            assert_eq!(witness.credential_id(), fixture.credential);
            assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
            assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
            backend.options.writes.source = true;
            backend.options.principal = Some(SPONSOR);
            assert_eq!(
                backend
                    .call(
                        "frankengit_source_publish",
                        result["publication_arguments"].object().unwrap()
                    )
                    .unwrap_err()
                    .code,
                "tool_not_granted"
            );
            assert_eq!(authority(&backend), before);
        }
        backend.close().unwrap();
        let mut reopened = NodeTools::open(fixture.options.clone()).unwrap();
        let args = command(&fixture, "../../outside");
        let prepared = reopened.call(NAME, &args).unwrap();
        assert!(reopened.call(NAME, &inspection(&prepared)).is_ok());
        assert_eq!(authority(&reopened), before);
        reopened.close().unwrap();
    }
}

#[test]
fn sponsored_symlink_native_boundary_keeps_reservation_namespace_and_base() {
    let fixture = CandidateFixture::new(GitHashAlgorithm::Sha256);
    let backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = authority(&backend);
    let args = command(&fixture, "../../outside");
    let patch = args["patch"].text().unwrap().as_bytes();
    let reference = RefName::try_new(REFERENCE.as_bytes()).unwrap();
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 2,
        message: b"native symlink boundary\n".to_vec(),
    };
    let prepare = |request: &AgentRequest, base| {
        backend
            .node
            .runtime()
            .block_on(backend.node.prepare_agent_source_symlink_patch_in(
                &request.source_candidates(&backend.node).unwrap(),
                &reference,
                base,
                patch,
                &metadata,
            ))
    };
    let insufficient = reservation(&backend, patch.len() - 1);
    assert!(matches!(
        prepare(&insufficient, fixture.fixture.tip),
        Err(NodeWorkspaceRefusal::WorkspaceCapacity)
    ));
    let exact = reservation(&backend, patch.len());
    let candidate = prepare(&exact, fixture.fixture.tip).unwrap();
    let wrong = GitOid::from_hex(GitHashAlgorithm::Sha256, &"ab".repeat(32)).unwrap();
    assert!(matches!(
        prepare(&exact, wrong),
        Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
    ));
    assert!(
        backend
            .node
            .read_git_object(candidate.candidate_commit)
            .is_err()
    );
    let proof = exact.source_candidates(&backend.node).unwrap();
    let other_fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let other = NodeTools::open(other_fixture.options.clone()).unwrap();
    assert!(matches!(
        other
            .node
            .runtime()
            .block_on(other.node.prepare_agent_source_symlink_patch_in(
                &proof,
                &reference,
                other_fixture.tip,
                patch,
                &metadata,
            )),
        Err(NodeWorkspaceRefusal::RepositoryMismatch)
    ));
    other.close().unwrap();
    assert_eq!(authority(&backend), before);
    backend.close().unwrap();
}
