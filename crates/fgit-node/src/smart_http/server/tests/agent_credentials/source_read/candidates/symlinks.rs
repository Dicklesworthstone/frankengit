//! The HTTP profile selects the native inert-symlink planner under the original
//! sponsored request; neither its patch nor its bundle is source publication.
use super::*;

fn symlink_patch(target: &str) -> Vec<u8> {
    format!(
        "diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+{target}\n\\ No newline at end of file\n"
    )
    .into_bytes()
}

fn symlink_form(base: GitOid) -> String {
    preparation(base).replace("exact-tree-v1", "exact-symlink-v1")
}

#[test]
fn sponsored_http_symlink_candidates_preserve_target_bytes_and_require_explicit_profile() {
    for (format, target) in [
        (GitHashAlgorithm::Sha1, "../../outside"),
        (GitHashAlgorithm::Sha256, "/absolute/target"),
    ] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let credential = issue_candidates(&mut fixture);
        let form = symlink_form(fixture.commit);
        let patch = symlink_patch(target);
        let prepared = exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &form,
            &patch,
        );
        let (candidate, bundle, metadata) = extract(&prepared, format);
        assert_eq!(
            field(&metadata, "patch_profile").text(),
            Some("exact-symlink-v1")
        );
        let Value::Array(paths) = field(&metadata, "paths") else {
            panic!("complete native path receipts");
        };
        assert_eq!(paths.len(), 1);
        let target_blob = git_object_id(format, GitObjectKind::Blob, target.as_bytes());
        assert_eq!(
            field(&paths[0], "path_hex").text(),
            Some(hex(b"link").as_str())
        );
        assert_eq!(field(&paths[0], "new_mode").unsigned(), Some(0o120000));
        assert_eq!(
            field(&paths[0], "new_blob").text(),
            Some(target_blob.to_string().as_str())
        );
        let inspected = exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "inspect",
            &inspection(fixture.commit, candidate),
            &bundle,
        );
        binary_status(&inspected, 200);
        let inspected = value(split_response(&inspected).1);
        assert_eq!(
            field(field(&inspected, "comparison"), "entry_count").unsigned(),
            Some(1)
        );
        let Value::Array(entries) = field(field(&inspected, "comparison"), "entries") else {
            panic!("complete native comparison");
        };
        assert_eq!(
            field(&entries[0], "path_hex").text(),
            Some(hex(b"link").as_str())
        );
        let content = field(&entries[0], "content");
        let Value::Array(hunks) = field(content, "hunks") else {
            panic!("inert link target is inspected as source bytes");
        };
        assert_eq!(hunks.len(), 1);
        assert_eq!(
            field(&hunks[0], "after_hex").text(),
            Some(hex(target.as_bytes()).as_str())
        );
        for name in [
            "objects_staged",
            "transaction_created",
            "published",
            "publication_authorized",
        ] {
            assert_eq!(field(&inspected, name), &Value::Bool(false));
        }

        for legacy in [
            preparation(fixture.commit),
            form.replace("&patch_profile=exact-symlink-v1", ""),
            form.replace("exact-symlink-v1", "exact-tree-binary-v1"),
        ] {
            binary_status(
                &exchange_upload(
                    &fixture.selected,
                    &credential.bearer,
                    "prepare",
                    &legacy,
                    &patch,
                ),
                400,
            );
        }
        for (token, expected) in [
            (&fixture.source, 403),
            (&credential.legacy, 403),
            (&credential.expired, 401),
        ] {
            binary_status(
                &exchange_upload(&fixture.selected, token, "prepare", &form, &patch),
                expected,
            );
        }
        binary_status(
            &exchange_upload_with_key(
                &fixture.selected,
                &credential.bearer,
                "apply",
                &inspection(fixture.commit, candidate),
                &bundle,
                Some("symlink-candidate-cannot-publish"),
            ),
            403,
        );

        // An ordinary independently configured source reader reaches the same
        // native profile. Neither transport invents another symlink engine.
        let mut operator = fixture.selected.clone();
        operator.credentials = CredentialSource::Static {
            digest: sha256_digest(b"operator-symlink-reader"),
            principal: actor(4),
        };
        let (_, ordinary_bundle, _) = extract(
            &exchange_upload(
                &operator,
                "operator-symlink-reader",
                "prepare",
                &form,
                &patch,
            ),
            format,
        );
        assert_eq!(ordinary_bundle, bundle);
        assert!(matches!(
            fs::symlink_metadata(root.0.join("link")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        assert!(node.read_git_object(candidate).is_err());
        assert!(node.read_git_object(target_blob).is_err());
        node.shutdown().unwrap();
    }
}

#[test]
fn sponsored_http_symlink_candidates_keep_source_pins_limits_and_current_revocation() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let credential = issue_candidates(&mut fixture);
    let form = symlink_form(fixture.commit);
    let patch = symlink_patch("../../outside");
    let (candidate, bundle, _) = extract(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &form,
            &patch,
        ),
        GitHashAlgorithm::Sha256,
    );
    let mut limited = fixture.selected.clone();
    limited.maximum_response_bytes = 512;
    binary_status(
        &exchange_upload(&limited, &credential.bearer, "prepare", &form, &patch),
        413,
    );
    limited = fixture.selected.clone();
    limited.services = limited.services.with(RepositoryHttpService::Source, false);
    binary_status(
        &exchange_upload(&limited, &credential.bearer, "prepare", &form, &patch),
        403,
    );
    let stale = form.replace(&fixture.commit.to_string(), &"01".repeat(32));
    binary_status(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &stale,
            &patch,
        ),
        409,
    );
    let invalid_path = String::from_utf8(patch.clone())
        .unwrap()
        .replace("a/link", "a/../escape")
        .replace("b/link", "b/../escape");
    binary_status(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &form,
            invalid_path.as_bytes(),
        ),
        400,
    );
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(generation(&node), fixture.generation);
    super::super::super::credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(credential.bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(credential.grant),
        },
        credential.grant.sponsor,
        "revoke-symlink-candidate",
    );
    let after = generation(&node);
    node.shutdown().unwrap();
    for (action, command, payload) in [
        ("prepare", form, patch),
        ("inspect", inspection(fixture.commit, candidate), bundle),
    ] {
        binary_status(
            &exchange_upload(
                &fixture.selected,
                &credential.bearer,
                action,
                &command,
                &payload,
            ),
            401,
        );
    }
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(generation(&node), after);
    node.shutdown().unwrap();
}
