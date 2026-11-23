use super::super::binary_test_support::{literal_member, rename_patch};
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};

const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"\0edited binary\xff\r\n";
const DESTINATION: &str = "assets/moved.bin";

fn command(base: GitOid) -> Object {
    let mut args = input(base);
    args.insert("profile".into(), text("exact-tree-binary-v1"));
    args.insert(
        "patch".into(),
        text(rename_patch(
            base.algorithm(),
            "README",
            DESTINATION,
            BEFORE,
            AFTER,
        )),
    );
    args
}

#[test]
fn binary_refactor_prepares_inspects_and_publishes_exact_bytes_modes_and_tree() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, base) = setup(format);
        let before = head_bytes(&backend);
        let args = command(base);
        for profile in [None, Some("exact-tree-v1"), Some("exact-symlink-v1")] {
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
        let mut server = server(&mut backend);
        let response = invoke(&mut server, &mut backend, 2, NAME, args.clone());
        let prepared = content(&response);
        assert_eq!(prepared["profile"], text("exact-tree-binary-v1"));
        assert_eq!(prepared["snapshot_token"], Value::Null);
        assert_eq!(prepared["source_commit"], text(raw_oid(base)));
        assert_eq!(
            backend.call(NAME, &args).unwrap().object().unwrap(),
            prepared
        );
        let target_blob = git_object_id(format, GitObjectKind::Blob, AFTER);
        let old_blob = git_object_id(format, GitObjectKind::Blob, BEFORE);
        let Value::Array(paths) = &prepared["paths"] else {
            panic!("complete path receipts");
        };
        assert_eq!(paths.len(), 2);
        let removed = paths[0].object().unwrap();
        assert_eq!(removed["path_hex"], text(hex(b"README")));
        assert_eq!(removed["old_blob"], text(raw_oid(old_blob)));
        assert_eq!(removed["new_blob"], Value::Null);
        assert_eq!(removed["new_mode"], Value::Null);
        let created = paths[1].object().unwrap();
        assert_eq!(created["path_hex"], text(hex(DESTINATION.as_bytes())));
        assert_eq!(created["old_blob"], Value::Null);
        assert_eq!(created["new_blob"], text(raw_oid(target_blob)));
        assert_eq!(created["new_mode"], text("100755"));

        // Hash the complete expected Git trees independently of preparation.
        // This catches lost siblings, a retained old endpoint or a wrong mode.
        let subtree = [b"100755 moved.bin\0".as_slice(), target_blob.as_bytes()].concat();
        let subtree = git_object_id(format, GitObjectKind::Tree, &subtree);
        let sibling = git_object_id(format, GitObjectKind::Blob, b"untouched\n");
        let root = [
            b"40000 assets\0".as_slice(),
            subtree.as_bytes(),
            b"100644 sibling\0".as_slice(),
            sibling.as_bytes(),
        ]
        .concat();
        assert_eq!(
            prepared["root_tree"],
            text(raw_oid(git_object_id(format, GitObjectKind::Tree, &root)))
        );
        let inspect_args = inspection(prepared);
        let response = invoke(&mut server, &mut backend, 3, NAME, inspect_args.clone());
        let inspected = content(&response);
        for result in [prepared, inspected] {
            assert_eq!(result["complete"], Value::Bool(true));
            for field in ["published", "repository_changed", "approval_granted"] {
                assert_eq!(result[field], Value::Bool(false));
            }
        }
        assert_eq!(
            inspected["publication_arguments"],
            prepared["publication_arguments"]
        );
        assert_eq!(inspected["bundle_sha256"], prepared["bundle_sha256"]);
        let review = inspected["review"].object().unwrap();
        assert_eq!(review["completion_scope"], text("entire_candidate_tree"));
        assert_eq!(review["entry_count"], text("2"));
        let Value::Array(entries) = &review["entries"] else {
            panic!("complete review entries");
        };
        let moved = entries[1].object().unwrap();
        assert_eq!(moved["path_hex"], text(hex(DESTINATION.as_bytes())));
        assert_eq!(moved["before"], Value::Null);
        assert_eq!(
            moved["after"].object().unwrap()["oid"],
            text(raw_oid(target_blob))
        );
        assert_eq!(moved["after"].object().unwrap()["mode"], text("100755"));
        assert_eq!(moved["content"].object().unwrap()["kind"], text("binary"));
        assert_eq!(
            moved["content"].object().unwrap()["after_bytes"],
            text(AFTER.len().to_string())
        );
        let candidate = oid(&inspect_args, "expected_candidate", format).unwrap();
        assert!(backend.node.read_git_object(candidate).is_err());
        assert!(backend.node.read_git_object(target_blob).is_err());
        assert_eq!(head_bytes(&backend), before);
        let mut publication = inspected["publication_arguments"].object().unwrap().clone();
        publication.insert("idempotency_key".into(), text("reviewed-binary-refactor"));
        assert_eq!(
            backend
                .call("frankengit_source_publish", &publication)
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
        let mut options = backend.options.clone();
        backend.close().unwrap();
        let mut backend = NodeTools::open(options.clone()).unwrap();
        assert_eq!(
            backend.call(NAME, &args).unwrap().object().unwrap(),
            prepared
        );
        assert!(backend.node.read_git_object(candidate).is_err());
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();

        options.writes.source = true;
        options.principal = Some(sponsor());
        let mut backend = NodeTools::open(options.clone()).unwrap();
        let mut server = super::server(&mut backend);
        let response = invoke(
            &mut server,
            &mut backend,
            2,
            "frankengit_source_publish",
            publication.clone(),
        );
        let committed = content(&response);
        assert_eq!(committed["outcome"], text("committed"));
        let after = head_bytes(&backend);
        assert_ne!(after, before);
        assert_eq!(
            backend
                .call("frankengit_source_publish", &publication)
                .unwrap()
                .object()
                .unwrap(),
            committed
        );
        assert_eq!(head_bytes(&backend), after);
        let moved = blob(&mut backend, DESTINATION.as_bytes());
        assert_eq!(moved.object().unwrap()["bytes_hex"], text(hex(AFTER)));
        assert_eq!(
            blob(&mut backend, b"sibling").object().unwrap()["bytes_hex"],
            text(hex(b"untouched\n"))
        );
        assert!(
            backend
                .call(
                    "frankengit_source_blob",
                    &fields([
                        ("reference", text("refs/heads/main")),
                        ("path_hex", text(hex(b"README"))),
                    ])
                )
                .is_err()
        );
        assert!(backend.call(NAME, &inspect_args).is_err());
        backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        assert_eq!(head_bytes(&backend), after);
        assert_eq!(
            blob(&mut backend, DESTINATION.as_bytes()).object().unwrap()["bytes_hex"],
            text(hex(AFTER))
        );
        backend.close().unwrap();
    }
}

#[test]
fn binary_refactor_identity_destination_and_late_failures_leave_no_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, base) = setup(format);
        let before = head_bytes(&backend);
        let valid = rename_patch(format, "README", DESTINATION, BEFORE, AFTER);
        let old = git_object_id(format, GitObjectKind::Blob, BEFORE).to_string();
        let new = git_object_id(format, GitObjectKind::Blob, AFTER).to_string();
        let wrong = "ab".repeat(format.digest_len());
        for patch in [
            valid.replace(&old, &wrong),
            valid.replace(&new, &wrong),
            valid.replace(&literal_member(BEFORE), &literal_member(b"wrong!\n")),
            rename_patch(format, "README", "sibling", BEFORE, AFTER),
            valid.replace("similarity index 50%", "similarity index 100%"),
            format!(
                "{valid}diff --git a/sibling b/sibling\n--- a/sibling\n+++ b/sibling\n@@ -1 +1 @@\n-not the sibling\n+changed\n"
            ),
        ] {
            let mut args = command(base);
            args.insert("patch".into(), text(patch));
            assert!(backend.call(NAME, &args).is_err());
            assert_eq!(head_bytes(&backend), before);
            assert!(
                backend
                    .node
                    .read_git_object(git_object_id(format, GitObjectKind::Blob, AFTER))
                    .is_err()
            );
            assert_eq!(
                blob(&mut backend, b"README").object().unwrap()["bytes_hex"],
                text(hex(BEFORE))
            );
            assert_eq!(
                blob(&mut backend, b"sibling").object().unwrap()["bytes_hex"],
                text(hex(b"untouched\n"))
            );
        }
        // The same exact patch is accepted through the raw-byte transport.
        let mut args = command(base);
        args.remove("patch");
        args.insert(
            "patch_hex_chunks".into(),
            encoded_chunks(valid.as_bytes()).unwrap(),
        );
        assert!(backend.call(NAME, &args).is_ok());
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();
    }
}
