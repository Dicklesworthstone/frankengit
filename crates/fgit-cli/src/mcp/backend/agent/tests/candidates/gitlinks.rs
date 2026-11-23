//! Sponsored MCP gitlinks cross the real native engines and scoped admission.
//! Their external commit pointers are inspected as identities, never as blobs.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::ExpectedVersion;
use fgit_identity::agent::{
    AgentCredentialAction, AgentCredentialCommand, OUTCOMES_READ, SOURCE_PUBLISH,
    SourcePublicationScope, agent_credential_id,
};

const PUBLISH: &str = "frankengit_source_publish";
const MODULES: &[u8] = b"[submodule \"dependency\"]\n\tpath = dependency\n\turl = https://example.invalid/dependency\n";

fn pointer(format: GitHashAlgorithm, byte: &str) -> GitOid {
    GitOid::from_hex(format, &byte.repeat(format.digest_len())).unwrap()
}

fn patch(target: GitOid) -> String {
    let zero = "0".repeat(target.algorithm().digest_len() * 2);
    format!(
        "diff --git a/.gitmodules b/.gitmodules\nnew file mode 100644\n--- /dev/null\n+++ b/.gitmodules\n@@ -0,0 +1,3 @@\n+[submodule \"dependency\"]\n+\tpath = dependency\n+\turl = https://example.invalid/dependency\ndiff --git a/dependency b/dependency\nnew file mode 160000\nindex {zero}..{target}\n--- /dev/null\n+++ b/dependency\n@@ -0,0 +1 @@\n+Subproject commit {target}\n"
    )
}

fn command(fixture: &CandidateFixture, target: GitOid) -> Object {
    let mut args = fixture.preparation();
    args.insert("profile".into(), text("exact-gitlink-v1"));
    args.insert("patch".into(), text(patch(target)));
    args
}

fn issue_publisher(
    node: &OneNode,
    byte: u8,
    reference: &str,
    paths: &[&[u8]],
) -> AgentCredentialId {
    let id = agent_credential_id(token(byte).as_bytes()).unwrap();
    let scope = SourcePublicationScope::new(
        &format!("exact:{}", hex(reference.as_bytes())),
        paths.iter().map(|path| path.to_vec()).collect(),
    )
    .unwrap();
    credential(
        node,
        AgentCredentialCommand {
            id,
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::issuance(
                grant(node, SOURCE_PUBLISH | OUTCOMES_READ),
                Some(scope),
            ),
        },
        &format!("issue-mcp-gitlink-publisher-{byte}"),
    );
    id
}

fn publisher_options(fixture: &CandidateFixture, byte: u8) -> Options {
    let mut options = fixture.options.clone();
    options.agent_token_file = fixture.fixture.replacement(byte).agent_token_file;
    options.outcomes = true;
    options.writes.source = true;
    options
}

fn tip(backend: &NodeTools) -> GitOid {
    backend
        .node
        .runtime()
        .block_on(
            backend
                .node
                .materialize_admission_in(&backend.node.request_context()),
        )
        .unwrap()
        .snapshot()
        .refs[&RefName::try_new(REFERENCE.as_bytes()).unwrap()]
}

fn publication(prepared: &Value, retry: &str) -> Object {
    let mut args = prepared.object().unwrap()["publication_arguments"]
        .object()
        .unwrap()
        .clone();
    args.insert("idempotency_key".into(), text(retry));
    args
}

#[test]
fn sponsored_mcp_gitlinks_prepare_inspect_publish_and_recover_exact_native_change() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = CandidateFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let publisher = issue_publisher(
            &backend.node,
            0x91,
            REFERENCE,
            &[b".gitmodules", b"dependency"],
        );
        let before = authority(&backend);
        let target = pointer(format, "41");
        let modules_blob = git_object_id(format, GitObjectKind::Blob, MODULES);
        let args = command(&fixture, target);
        let mut server = Server::new(&mut backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"gitlink-candidate-agent","version":"1"}}}"#).unwrap();
        server.receive(
            &mut backend,
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        let prepared = invoke(&mut server, &mut backend, 2, &args);
        let fields = prepared.object().unwrap();
        assert_eq!(fields["profile"], text("exact-gitlink-v1"));
        assert_eq!(fields["snapshot_token"], Value::Null);
        assert_eq!(backend.call(NAME, &args).unwrap(), prepared);
        let Value::Array(paths) = &fields["paths"] else {
            panic!("complete native entry effects");
        };
        assert_eq!(paths.len(), 2);
        for (row, path, object, mode) in [
            (&paths[0], b".gitmodules".as_slice(), modules_blob, "100644"),
            (&paths[1], b"dependency".as_slice(), target, "160000"),
        ] {
            let row = row.object().unwrap();
            assert_eq!(row["path_hex"], text(hex(path)));
            assert_eq!(row["old_object"], Value::Null);
            assert_eq!(row["new_object"], text(object.to_string()));
            assert_eq!(row["new_mode"], text(mode));
            assert!(!row.contains_key("old_blob"));
            assert!(!row.contains_key("new_blob"));
        }
        let inspected = invoke(&mut server, &mut backend, 3, &inspection(&prepared));
        let inspected_fields = inspected.object().unwrap();
        assert_eq!(
            inspected_fields["publication_arguments"],
            fields["publication_arguments"]
        );
        let review = inspected_fields["review"].object().unwrap();
        assert_eq!(review["completion_scope"], text("entire_candidate_tree"));
        let Value::Array(entries) = &review["entries"] else {
            panic!("complete native comparison");
        };
        assert_eq!(entries.len(), 2);
        let link = entries
            .iter()
            .map(|entry| entry.object().unwrap())
            .find(|entry| entry["path_hex"] == text(hex(b"dependency")))
            .unwrap();
        assert_eq!(link["after"].object().unwrap()["mode"], text("160000"));
        assert_eq!(
            link["after"].object().unwrap()["oid"],
            text(target.to_string())
        );
        assert_eq!(
            link["content"].object().unwrap()["kind"],
            text("object_only")
        );
        for value in [&prepared, &inspected] {
            for field in ["published", "repository_changed", "approval_granted"] {
                assert_eq!(value.object().unwrap()[field], Value::Bool(false));
            }
            assert!(!value.encode(MAX_RESPONSE).unwrap().contains(&token(0x61)));
        }
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
            panic!("gitlink preparation retained its sponsored request");
        };
        assert_eq!(witness.agent(), AGENT);
        assert_eq!(witness.sponsor(), SPONSOR);
        assert_eq!(witness.credential_id(), fixture.credential);
        let retry = "mcp-gitlink-publication";
        let publish = publication(&prepared, retry);
        let candidate =
            GitOid::from_hex(format, publish["expected_candidate"].text().unwrap()).unwrap();
        for object in [candidate, modules_blob, target] {
            assert!(backend.node.read_git_object(object).is_err());
        }
        backend.options.writes.source = true;
        assert_eq!(
            backend.call(PUBLISH, &publish).unwrap_err().code,
            "agent_operation_not_granted"
        );
        assert_eq!(
            authority(&backend),
            before,
            "candidate scope cannot authorize publication"
        );
        backend.close().unwrap();

        let options = publisher_options(&fixture, 0x91);
        let mut publisher_backend = NodeTools::open(options.clone()).unwrap();
        let published = publisher_backend.call(PUBLISH, &publish).unwrap();
        committed(&published);
        assert_eq!(tip(&publisher_backend), candidate);
        assert_eq!(
            publisher_backend
                .node
                .read_git_object(modules_blob)
                .unwrap()
                .payload(),
            MODULES
        );
        assert!(
            publisher_backend.node.read_git_object(target).is_err(),
            "no foreign commit was imported"
        );
        let original = provenance(&publisher_backend, retry);
        let witness = original.agent_provenance().unwrap();
        assert_eq!(witness.agent(), AGENT);
        assert_eq!(witness.sponsor(), SPONSOR);
        assert_eq!(witness.credential_id(), publisher);
        let committed_head = authority(&publisher_backend);
        publisher_backend.close().unwrap();
        let mut reopened = NodeTools::open(options).unwrap();
        assert_eq!(reopened.call(PUBLISH, &publish).unwrap(), published);
        let recovered = reopened
            .call("frankengit_transaction_outcome", &recovery(retry))
            .unwrap();
        committed(&recovered);
        assert_eq!(provenance(&reopened, retry), original);
        assert_eq!(authority(&reopened), committed_head);
        assert_eq!(tip(&reopened), candidate);
        assert!(reopened.node.read_git_object(target).is_err());
        reopened.close().unwrap();
        assert!(!fixture.fixture.root.join("dependency").exists());
    }
}

#[test]
fn sponsored_mcp_gitlinks_check_every_native_path_and_exact_publication_ref() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = CandidateFixture::new(format);
        let mut reader = NodeTools::open(fixture.options.clone()).unwrap();
        for (byte, reference, paths) in [
            (0x92, REFERENCE, vec![b".gitmodules".as_slice()]),
            (0x93, REFERENCE, vec![b"dependency".as_slice()]),
            (
                0x94,
                "refs/heads/main",
                vec![b".gitmodules".as_slice(), b"dependency".as_slice()],
            ),
        ] {
            issue_publisher(&reader.node, byte, reference, &paths);
        }
        let target = pointer(format, "41");
        let prepared = reader.call(NAME, &command(&fixture, target)).unwrap();
        reader.close().unwrap();
        for (byte, retry) in [
            (0x92, "gitlink-outside-path-scope"),
            (0x93, "gitmodules-outside-path-scope"),
            (0x94, "gitlink-outside-ref-scope"),
        ] {
            let mut backend = NodeTools::open(publisher_options(&fixture, byte)).unwrap();
            let args = publication(&prepared, retry);
            let candidate =
                GitOid::from_hex(format, args["expected_candidate"].text().unwrap()).unwrap();
            let refused = backend.call(PUBLISH, &args).unwrap();
            let fields = refused.object().unwrap();
            assert_eq!(fields["outcome"], text("refused"));
            assert_eq!(fields["refusal_code"], text("CapabilityScopeViolation"));
            assert_eq!(fields["ref_transaction_committed"], Value::Bool(false));
            assert!(backend.result_is_error(PUBLISH, &refused));
            assert_eq!(tip(&backend), fixture.fixture.tip);
            assert!(backend.node.read_git_object(candidate).is_err());
            assert!(backend.node.read_git_object(target).is_err());
            assert_eq!(backend.call(PUBLISH, &args).unwrap(), refused);
            backend.close().unwrap();
        }
    }
}

#[test]
fn sponsored_mcp_gitlink_grammar_limits_and_revocation_keep_real_candidate_unpublished() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = CandidateFixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = authority(&backend);
        let target = pointer(format, "41");
        let args = command(&fixture, target);
        for profile in [
            None,
            Some("exact-tree-v1"),
            Some("exact-tree-binary-v1"),
            Some("exact-symlink-v1"),
        ] {
            let mut legacy = args.clone();
            legacy.remove("profile");
            if let Some(profile) = profile {
                legacy.insert("profile".into(), text(profile));
            }
            assert_eq!(
                backend.call(NAME, &legacy).unwrap_err().code,
                "invalid_source_patch"
            );
        }
        let source = patch(target);
        let zero = "0".repeat(format.digest_len() * 2);
        let wrong_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        for invalid in [
            patch(pointer(wrong_format, "41")),
            source.replace(&format!("+Subproject commit {target}\n"), &format!("+Subproject commit {target}-dirty\n")),
            source.replace(&format!("index {zero}..{target}"), &format!("index {zero}..{}", pointer(format, "42"))),
            source.replace("a/dependency", "a/../escape").replace("b/dependency", "b/../escape"),
            "diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+inert target\n".into(),
            "diff --git a/file b/moved\nsimilarity index 100%\nrename from file\nrename to moved\n".into(),
            "diff --git a/binary b/binary\nnew file mode 100644\nGIT binary patch\nliteral 1\nA00001\n\n".into(),
        ] {
            let mut invalid_args = args.clone();
            invalid_args.insert("patch".into(), text(invalid));
            assert!(backend.call(NAME, &invalid_args).is_err());
        }
        let prepared = backend.call(NAME, &args).unwrap();
        let inspect = inspection(&prepared);
        assert!(backend.call(NAME, &inspect).is_ok());
        let mut stale = args.clone();
        stale.insert(
            "expected_base".into(),
            text(pointer(format, "43").to_string()),
        );
        assert_eq!(
            backend.call(NAME, &stale).unwrap_err().code,
            "source_commit_moved"
        );
        let mut wrong_digest = inspect.clone();
        wrong_digest.insert("expected_bundle_sha256".into(), text("00".repeat(32)));
        assert_eq!(
            backend.call(NAME, &wrong_digest).unwrap_err().code,
            "bundle_digest_mismatch"
        );
        assert_eq!(authority(&backend), before);
        revoke(
            &backend.node,
            fixture.credential,
            "revoke-mcp-gitlink-candidate",
        );
        let revoked = authority(&backend);
        for call in [&args, &inspect] {
            assert_eq!(
                backend.call(NAME, call).unwrap_err().code,
                "agent_credential_unavailable"
            );
        }
        backend.close().unwrap();
        let mut reopened = NodeTools::open(fixture.options.clone()).unwrap();
        for call in [&args, &inspect] {
            assert_eq!(
                reopened.call(NAME, call).unwrap_err().code,
                "agent_credential_unavailable"
            );
        }
        assert_eq!(authority(&reopened), revoked);
        assert_eq!(tip(&reopened), fixture.fixture.tip);
        assert!(reopened.node.read_git_object(target).is_err());
        reopened.close().unwrap();
    }
}

#[test]
fn sponsored_mcp_gitlink_native_preparation_keeps_original_reservation_and_expiry() {
    let fixture = CandidateFixture::new(GitHashAlgorithm::Sha256);
    let backend = NodeTools::open(fixture.options.clone()).unwrap();
    let before = authority(&backend);
    let target = pointer(GitHashAlgorithm::Sha256, "41");
    let patch = patch(target);
    let reference = RefName::try_new(REFERENCE.as_bytes()).unwrap();
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 2,
        message: b"native gitlink boundary\n".to_vec(),
    };
    let prepare = |request: &AgentRequest| {
        backend
            .node
            .runtime()
            .block_on(backend.node.prepare_agent_source_gitlink_patch_in(
                &request.source_candidates(&backend.node).unwrap(),
                &reference,
                fixture.fixture.tip,
                patch.as_bytes(),
                &metadata,
            ))
    };
    let insufficient = reservation(&backend, patch.len() - 1);
    assert!(matches!(
        prepare(&insufficient),
        Err(NodeWorkspaceRefusal::WorkspaceCapacity)
    ));
    let mut exact = reservation(&backend, patch.len());
    let candidate = prepare(&exact).unwrap();
    assert!(
        backend
            .node
            .read_git_object(candidate.candidate_commit)
            .is_err()
    );
    assert!(backend.node.read_git_object(target).is_err());
    exact.constrain_deadline(Instant::now() - Duration::from_secs(1));
    exact.constrain_deadline(Instant::now() + Duration::from_secs(300));
    assert!(
        exact.source_candidates(&backend.node).is_err(),
        "later phases cannot renew the request lifetime"
    );
    assert_eq!(authority(&backend), before);
    backend.close().unwrap();
}
