//! Payload bounds govern selected bodies, not unrelated blob metadata.

use super::*;

const BLOB_BYTES: usize = 4096;

fn reopen_with_object_limit(config: &NodeConfig, limit: usize) -> OneNode {
    let mut config = config.clone();
    config.selected_pack_limits.max_object_bytes = limit;
    let mut node = OneNode::open_existing(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}

fn assert_body_limit(
    result: &Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal>,
    response: &[u8],
    version: u8,
) {
    assert!(
        matches!(
            result,
            Err(NodeGitDaemonServeRefusal::Pack(pack)) if matches!(
                &**pack,
                NodePackMaterializationRefusal::Pack(error) if matches!(
                    &**error,
                    PackWriteError::Pack(PackError::ObjectSizeLimit { actual, limit })
                        if *actual == BLOB_BYTES && *limit == BLOB_BYTES - 1
                )
            )
        ),
        "v{version}: {result:?}"
    );
    assert!(
        !response.windows(4).any(|bytes| bytes == b"PACK"),
        "over-limit selected bodies never emit pack bytes"
    );
    assert!(
        !response.windows(4).any(|bytes| bytes == b"ERR "),
        "the failure belongs to pack selection, after advertisement"
    );
    if version == 2 {
        let text = String::from_utf8_lossy(response);
        assert!(text.contains("version 2"), "{text}");
        assert!(text.contains("4096"), "typed size refusal: {text}");
        assert!(text.contains("4095"), "typed size refusal: {text}");
    }
}

#[test]
fn oversized_unselected_blobs_allow_advertisement_filters_and_noop_fetches() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let large_body = vec![b'x'; BLOB_BYTES];
        let large = git_object_id(format, GitObjectKind::Blob, &large_body);
        let Fixture {
            scratch: _scratch,
            node,
            config,
            public,
            private,
            private_blob,
            visible,
            ..
        } = fixture_with_public_body(format, large_body);
        delete_private(&node, private);
        let original_bodies = visible
            .iter()
            .map(|id| {
                let object = node.read_git_object(*id).unwrap();
                (object.envelope().object_kind(), object.payload().to_vec())
            })
            .collect::<Vec<_>>();
        let context = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&context))
            .unwrap();
        let original_basis = before.basis().clone();
        let original_closure = before.selected_closure().closure().clone();
        node.shutdown().unwrap();
        let mut node = reopen_with_object_limit(&config, BLOB_BYTES - 1);

        // The real protocol-v2 ls-refs path advertises the public commit
        // without reading or rejecting the oversized blob's body.
        let (returned, response) = exchange_ls_refs(node, true);
        node = returned;
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.contains(&format!("{public} refs/heads/public")),
            "{text}"
        );
        assert!(!text.contains("refs/heads/private"), "{text}");

        for version in [0, 1, 2] {
            for filter in ["blob:none", "blob:limit=4096", "tree:0"] {
                let (returned, result, response) =
                    exchange_filtered(node, version, &[public], None, Some(filter), false);
                node = returned;
                assert!(result.is_ok(), "{format:?} v{version} {filter}: {result:?}");
                let expected = original_bodies
                    .iter()
                    .filter(|(kind, body)| match filter {
                        "tree:0" => *kind == fgit_object_fabric::ObjectKind::Commit,
                        "blob:limit=4096" => {
                            *kind != fgit_object_fabric::ObjectKind::Blob || body.len() < BLOB_BYTES
                        }
                        _ => *kind != fgit_object_fabric::ObjectKind::Blob,
                    })
                    .map(|(_, body)| body.clone())
                    .collect::<BTreeSet<_>>();
                assert_eq!(bodies(&response, version, format), expected);
            }

            // A client holding the current commit needs no blob bytes.
            let (returned, result, response) =
                exchange_filtered(node, version, &[public], Some(public), None, false);
            node = returned;
            assert!(result.is_ok(), "no-op {format:?} v{version}: {result:?}");
            assert!(bodies(&response, version, format).is_empty());

            // Lazy fetch of a permitted small blob succeeds even with
            // blob:none; explicit wants override the filter.
            let common_body = b"common ancestor body";
            let common = git_object_id(format, GitObjectKind::Blob, common_body);
            let (returned, result, response) = exchange_filtered(
                node,
                version,
                &[common],
                Some(public),
                Some("blob:none"),
                false,
            );
            node = returned;
            assert!(
                result.is_ok(),
                "small lazy {format:?} v{version}: {result:?}"
            );
            assert_eq!(
                bodies(&response, version, format),
                BTreeSet::from([common_body.to_vec()])
            );

            // Full clone and explicit lazy want both retain the payload cap.
            for (wanted, filter) in [(public, None), (large, Some("blob:none"))] {
                let (returned, result, response) =
                    exchange_filtered(node, version, &[wanted], None, filter, false);
                node = returned;
                assert_body_limit(&result, &response, version);
            }

            // Metadata allowances never expose retained deleted-branch data.
            let (returned, result, response) = exchange_filtered(
                node,
                version,
                &[private_blob],
                None,
                Some("blob:none"),
                false,
            );
            node = returned;
            assert!(result.is_err(), "private blob must remain undisclosable");
            assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
        }

        let context = node.request_context();
        let after = node
            .runtime()
            .block_on(node.materialize_admission_in(&context))
            .unwrap();
        assert_eq!(after.basis(), &original_basis);
        assert_eq!(after.selected_closure().closure(), &original_closure);
        node.shutdown().unwrap();

        // The exact-bound twin delivers every original native body.
        let mut node = reopen_with_object_limit(&config, BLOB_BYTES);
        let expected = original_bodies
            .into_iter()
            .map(|(_, body)| body)
            .collect::<BTreeSet<_>>();
        for version in [0, 1, 2] {
            let (returned, result, response) =
                exchange_filtered(node, version, &[public], None, None, false);
            node = returned;
            assert!(result.is_ok(), "at-limit {format:?} v{version}: {result:?}");
            assert_eq!(bodies(&response, version, format), expected);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn oversized_blob_metadata_still_requires_the_exact_stored_length() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let large_body = vec![b'x'; BLOB_BYTES];
        let large = git_object_id(format, GitObjectKind::Blob, &large_body);
        let Fixture {
            scratch,
            node,
            config,
            public,
            private,
            ..
        } = fixture_with_public_body(format, large_body);
        delete_private(&node, private);
        node.shutdown().unwrap();
        let mut stored = Vec::new();
        for namespace in std::fs::read_dir(scratch.0.join("objects")).unwrap() {
            for domain in std::fs::read_dir(namespace.unwrap().path()).unwrap() {
                let path = domain.unwrap().path().join(large.to_string());
                if path.exists() {
                    stored.push(path);
                }
            }
        }
        let [path] = stored.as_slice() else {
            panic!("one stored copy of the blob: {stored:?}");
        };
        let original = std::fs::read(path).unwrap();
        std::fs::write(path, &original[..original.len() - 1]).unwrap();
        let node = reopen_with_object_limit(&config, BLOB_BYTES - 1);
        let (node, result, response) =
            exchange_filtered(node, 2, &[public], None, Some("blob:none"), false);
        assert!(
            matches!(
                &result,
                Err(NodeGitDaemonServeRefusal::Pack(pack)) if matches!(
                    &**pack,
                    NodePackMaterializationRefusal::Pack(error) if matches!(
                        &**error,
                        PackWriteError::MissingCanonicalObject(id) if *id == large
                    )
                )
            ),
            "malformed envelope length must refuse before advertisement: {result:?}"
        );
        assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
        assert!(!String::from_utf8_lossy(&response).contains("version 2"));
        node.shutdown().unwrap();

        std::fs::write(path, original).unwrap();
        let node = reopen_with_object_limit(&config, BLOB_BYTES - 1);
        let (node, result, response) =
            exchange_filtered(node, 2, &[public], None, Some("blob:none"), false);
        assert!(result.is_ok(), "restored metadata twin: {result:?}");
        assert_eq!(bodies(&response, 2, format).len(), 4);
        node.shutdown().unwrap();
    }
}
