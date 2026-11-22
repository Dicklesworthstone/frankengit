//! Sponsored HTTP gitlink candidates use real native preparation, inspection,
//! scoped admission and original-outcome recovery. Foreign commits stay opaque.
use super::*;
use fgit_identity::agent::{OUTCOMES_READ, SOURCE_PUBLISH, SourcePublicationScope};

const MODULES: &[u8] = b"[submodule \"dependency\"]\n\tpath = dependency\n\turl = https://example.invalid/dependency\n";

fn pointer(format: GitHashAlgorithm, byte: &str) -> GitOid {
    GitOid::from_hex(format, &byte.repeat(format.digest_len())).unwrap()
}

fn patch(target: GitOid) -> Vec<u8> {
    let zero = "0".repeat(target.algorithm().digest_len() * 2);
    format!(
        "diff --git a/.gitmodules b/.gitmodules\nnew file mode 100644\n--- /dev/null\n+++ b/.gitmodules\n@@ -0,0 +1,3 @@\n+[submodule \"dependency\"]\n+\tpath = dependency\n+\turl = https://example.invalid/dependency\ndiff --git a/dependency b/dependency\nnew file mode 160000\nindex {zero}..{target}\n--- /dev/null\n+++ b/dependency\n@@ -0,0 +1 @@\n+Subproject commit {target}\n"
    )
    .into_bytes()
}

fn form(base: GitOid) -> String {
    preparation(base).replace("exact-tree-v1", "exact-gitlink-v1")
}

struct Publisher {
    bearer: String,
    grant: AgentCredentialGrant,
    scope: SourcePublicationScope,
}

fn issue_publisher(
    fixture: &mut Fixture,
    byte: &str,
    reference: &[u8],
    paths: &[&[u8]],
) -> Publisher {
    let node = reopen(fixture.config.clone());
    let bearer = format!("fgagent_{}", byte.repeat(32));
    let scope = SourcePublicationScope::new(
        &format!("exact:{}", hex(reference)),
        paths.iter().map(|path| path.to_vec()).collect(),
    )
    .unwrap();
    let grant = AgentCredentialGrant {
        operations: SOURCE_PUBLISH | OUTCOMES_READ,
        ..fixture.grant
    };
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::issuance(grant, Some(scope.clone())),
        },
        grant.sponsor,
        &format!("issue-http-gitlink-publisher-{byte}"),
    );
    fixture.generation = generation(&node);
    node.shutdown().unwrap();
    Publisher {
        bearer,
        grant,
        scope,
    }
}

fn tip(node: &OneNode) -> GitOid {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .snapshot()
        .refs[&RefName::try_new(b"refs/heads/main").unwrap()]
}

fn published(response: &[u8]) -> Value {
    binary_status(response, 200);
    let receipt = value(split_response(response).1);
    assert_eq!(field(&receipt, "type").text(), Some("source_publication"));
    assert_eq!(field(&receipt, "outcome").text(), Some("committed"));
    assert_eq!(field(&receipt, "refusal_code"), &Value::Null);
    receipt
}

#[test]
fn sponsored_http_gitlinks_prepare_inspect_scope_publish_and_recover_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let reader = issue_candidates(&mut fixture);
        let publisher = issue_publisher(
            &mut fixture,
            "e1",
            b"refs/heads/main",
            &[b".gitmodules", b"dependency"],
        );
        let missing_pointer =
            issue_publisher(&mut fixture, "e2", b"refs/heads/main", &[b".gitmodules"]);
        let other_ref = issue_publisher(
            &mut fixture,
            "e3",
            b"refs/heads/other",
            &[b".gitmodules", b"dependency"],
        );
        let target = pointer(format, "41");
        let modules_blob = git_object_id(format, GitObjectKind::Blob, MODULES);
        let bytes = patch(target);
        let preparation = form(fixture.commit);
        let prepared = exchange_upload(
            &fixture.selected,
            &reader.bearer,
            "prepare",
            &preparation,
            &bytes,
        );
        let (candidate, bundle, metadata) = extract(&prepared, format);
        assert_eq!(
            field(&metadata, "patch_profile").text(),
            Some("exact-gitlink-v1")
        );
        let paths = rows(field(&metadata, "paths"));
        assert_eq!(paths.len(), 2);
        for (row, path, object, mode) in [
            (&paths[0], b".gitmodules".as_slice(), modules_blob, 0o100644),
            (&paths[1], b"dependency".as_slice(), target, 0o160000),
        ] {
            assert_eq!(field(row, "path_hex").text(), Some(hex(path).as_str()));
            assert_eq!(field(row, "old_object"), &Value::Null);
            assert_eq!(
                field(row, "new_object").text(),
                Some(object.to_string().as_str())
            );
            assert_eq!(field(row, "new_mode").unsigned(), Some(mode));
            assert!(!row.object().unwrap().contains_key("old_blob"));
            assert!(!row.object().unwrap().contains_key("new_blob"));
        }
        let command = inspection(fixture.commit, candidate);
        let inspected = exchange_upload(
            &fixture.selected,
            &reader.bearer,
            "inspect",
            &command,
            &bundle,
        );
        binary_status(&inspected, 200);
        let inspected = value(split_response(&inspected).1);
        let entries = rows(field(field(&inspected, "comparison"), "entries"));
        assert_eq!(entries.len(), 2);
        let link = entries
            .iter()
            .find(|entry| field(entry, "path_hex").text() == Some(hex(b"dependency").as_str()))
            .unwrap();
        assert_eq!(
            field(field(link, "after"), "mode").unsigned(),
            Some(0o160000)
        );
        assert_eq!(
            field(field(link, "after"), "oid").text(),
            Some(target.to_string().as_str())
        );
        assert_eq!(
            field(field(link, "content"), "type").text(),
            Some("object_only")
        );
        assert_eq!(
            field(field(link, "content"), "content_read"),
            &Value::Bool(false)
        );
        for name in [
            "objects_staged",
            "transaction_created",
            "published",
            "publication_authorized",
        ] {
            assert_eq!(field(&inspected, name), &Value::Bool(false));
        }
        assert_eq!(
            exchange_upload(
                &fixture.selected,
                &reader.bearer,
                "prepare",
                &preparation,
                &bytes
            ),
            prepared,
            "fresh native preparation is deterministic"
        );
        binary_status(
            &exchange_upload_with_key(
                &fixture.selected,
                &reader.bearer,
                "apply",
                &command,
                &bundle,
                Some("gitlink-candidate-is-not-authority"),
            ),
            403,
        );
        for (credential, key) in [
            (&missing_pointer, "gitlink-missing-path-scope"),
            (&other_ref, "gitlink-wrong-ref-scope"),
        ] {
            let response = exchange_upload_with_key(
                &fixture.selected,
                &credential.bearer,
                "apply",
                &command,
                &bundle,
                Some(key),
            );
            binary_status(&response, 409);
            let refused = value(split_response(&response).1);
            assert_eq!(field(&refused, "outcome").text(), Some("refused"));
            assert_eq!(
                field(&refused, "refusal_code").text(),
                Some("CapabilityScopeViolation")
            );
        }
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(tip(&node), fixture.commit);
        for object in [candidate, modules_blob, target] {
            assert!(
                node.read_git_object(object).is_err(),
                "refused candidates are unstaged"
            );
        }
        node.shutdown().unwrap();

        let key = "http-gitlink-scoped-publication";
        let receipt = published(&exchange_upload_with_key(
            &fixture.selected,
            &publisher.bearer,
            "apply",
            &command,
            &bundle,
            Some(key),
        ));
        assert_eq!(
            field(&receipt, "principal_id").text(),
            Some(publisher.grant.agent.to_string().as_str())
        );
        let original = original_provenance(&fixture.request(
            &publisher.bearer,
            "POST",
            "/api/v1/outcomes",
            "",
            Some(key),
        ))
        .to_owned();
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(tip(&node), candidate);
        assert_eq!(
            node.read_git_object(modules_blob).unwrap().payload(),
            MODULES
        );
        assert!(
            node.read_git_object(target).is_err(),
            "foreign pointer is not a closure object"
        );
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(publisher.bearer.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: AgentCredentialAction::revocation(publisher.grant, Some(publisher.scope)),
            },
            publisher.grant.sponsor,
            "revoke-http-gitlink-publisher",
        );
        node.shutdown().unwrap();
        let replacement = issue_publisher(&mut fixture, "e4", b"refs/heads/main", &[b"unrelated"]);
        binary_status(
            &exchange_upload_with_key(
                &fixture.selected,
                &publisher.bearer,
                "apply",
                &command,
                &bundle,
                Some(key),
            ),
            401,
        );
        let mut damaged = bundle;
        *damaged.last_mut().unwrap() ^= 1;
        assert_eq!(
            published(&exchange_upload_with_key(
                &fixture.selected,
                &replacement.bearer,
                "apply",
                &command,
                &damaged,
                Some(key)
            )),
            receipt,
            "restart and rotation recover the original decision without revalidating or reexecuting a changed bundle"
        );
        assert_eq!(
            original_provenance(&fixture.request(
                &replacement.bearer,
                "POST",
                "/api/v1/outcomes",
                "",
                Some(key)
            )),
            original
        );
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(tip(&node), candidate);
        assert_eq!(generation(&node), fixture.generation);
        assert!(node.read_git_object(target).is_err());
        node.shutdown().unwrap();
        assert!(!root.0.join("dependency").exists());
    }
}

#[test]
fn sponsored_http_gitlink_profiles_reject_malformed_pointers_and_revoked_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let reader = issue_candidates(&mut fixture);
        let target = pointer(format, "41");
        let bytes = patch(target);
        let command = form(fixture.commit);
        for legacy in [
            command.replace("&patch_profile=exact-gitlink-v1", ""),
            command.replace("exact-gitlink-v1", "exact-tree-v1"),
            command.replace("exact-gitlink-v1", "exact-tree-binary-v1"),
            command.replace("exact-gitlink-v1", "exact-symlink-v1"),
        ] {
            binary_status(
                &exchange_upload(
                    &fixture.selected,
                    &reader.bearer,
                    "prepare",
                    &legacy,
                    &bytes,
                ),
                400,
            );
        }
        let text = String::from_utf8(bytes.clone()).unwrap();
        let zero = "0".repeat(format.digest_len() * 2);
        let wrong_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        for invalid in [
            patch(pointer(wrong_format, "41")),
            text.replace(&format!("+Subproject commit {target}\n"), &format!("+Subproject commit {target}-dirty\n")).into_bytes(),
            text.replace(&format!("index {zero}..{target}"), &format!("index {zero}..{}", pointer(format, "42"))).into_bytes(),
            text.replace("a/dependency", "a/../escape").replace("b/dependency", "b/../escape").into_bytes(),
            b"diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+inert target\n".to_vec(),
            b"diff --git a/source.rs b/moved.rs\nsimilarity index 100%\nrename from source.rs\nrename to moved.rs\n".to_vec(),
            b"diff --git a/binary b/binary\nnew file mode 100644\nGIT binary patch\nliteral 1\nA00001\n\n".to_vec(),
        ] {
            binary_status(&exchange_upload(&fixture.selected, &reader.bearer, "prepare", &command, &invalid), 400);
        }
        for (token, expected) in [
            (&fixture.source, 403),
            (&reader.legacy, 403),
            (&reader.expired, 401),
        ] {
            binary_status(
                &exchange_upload(&fixture.selected, token, "prepare", &command, &bytes),
                expected,
            );
        }
        let (candidate, bundle, _) = extract(
            &exchange_upload(
                &fixture.selected,
                &reader.bearer,
                "prepare",
                &command,
                &bytes,
            ),
            format,
        );
        let mut limited = fixture.selected.clone();
        limited.maximum_response_bytes = 512;
        binary_status(
            &exchange_upload(&limited, &reader.bearer, "prepare", &command, &bytes),
            413,
        );
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        assert!(node.read_git_object(candidate).is_err());
        assert!(node.read_git_object(target).is_err());
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(reader.bearer.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: AgentCredentialAction::Revoke(reader.grant),
            },
            reader.grant.sponsor,
            "revoke-http-gitlink-candidate",
        );
        let revoked = generation(&node);
        node.shutdown().unwrap();
        for (action, command, payload) in [
            ("prepare", command, bytes),
            ("inspect", inspection(fixture.commit, candidate), bundle),
        ] {
            binary_status(
                &exchange_upload(
                    &fixture.selected,
                    &reader.bearer,
                    action,
                    &command,
                    &payload,
                ),
                401,
            );
        }
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), revoked);
        assert_eq!(tip(&node), fixture.commit);
        node.shutdown().unwrap();
    }
}
