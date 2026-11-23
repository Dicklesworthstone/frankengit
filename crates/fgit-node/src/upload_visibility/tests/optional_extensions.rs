//! Operator opt-ins apply to the actual per-session protocol, independently of
//! immutable graph reuse. Parser support and a valid graph are insufficient.

use super::*;
use fgit_wire::smart_http::rpc::RpcError;

fn object_info_body(format: GitHashAlgorithm, oid: GitOid) -> Vec<u8> {
    encode_packets(
        &[
            Packet::Data(b"command=object-info\n".to_vec()),
            Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
            Packet::Delimiter,
            Packet::Data(b"size\n".to_vec()),
            Packet::Data(format!("oid {oid}\n").into_bytes()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap()
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|part| part == needle)
}

fn assert_disabled(error: &WireError, ref_in_want: bool) {
    if ref_in_want {
        assert!(matches!(
            error,
            WireError::UnknownCapability { capability } if capability == b"ref-in-want"
        ));
    } else {
        assert!(matches!(
            error,
            WireError::UnsupportedCommand { command } if command == b"object-info"
        ));
    }
}

fn assert_raw_disabled(
    result: Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal>,
    refs: bool,
) {
    let Err(NodeGitDaemonServeRefusal::Transport(error)) = result else {
        panic!("unadvertised extension was not refused: {result:?}");
    };
    let GitDaemonTransportRefusal::Wire(error) = error.as_ref() else {
        panic!("expected an exact wire refusal, got {error:?}");
    };
    assert_disabled(error, refs);
}

#[test]
fn defaults_omit_optional_capabilities_and_refuse_requests_without_disabling_fetch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            config,
            public,
            ..
        } = fixture(format);
        assert!(!config.upload_pack_ref_in_want_enabled());
        assert!(!config.upload_pack_object_info_enabled());
        for (refs, body) in [
            (
                true,
                ref_in_want::fetch_body(format, &[b"refs/heads/public"], &[]),
            ),
            (false, object_info_body(format, public)),
        ] {
            let (returned, result, response) = ref_in_want::raw_fetch(node, &body);
            node = returned;
            assert_raw_disabled(result, refs);
            assert!(!contains(&response, b"ref-in-want"));
            assert!(!contains(&response, b"object-info"));
            assert!(!contains(&response, b"PACK"));
            for streamed in [false, true] {
                let (result, response) = ref_in_want::http_fetch(&node, &body, streamed);
                let Err(NodeSmartHttpRefusal::Rpc(error)) = result else {
                    panic!("unadvertised HTTP extension was not refused: {result:?}");
                };
                let RpcError::Wire(error) = error.as_ref() else {
                    panic!("expected the same HTTP wire refusal, got {error:?}");
                };
                assert_disabled(error, refs);
                assert!(
                    response.is_empty(),
                    "unsupported commands produce no successful HTTP prefix"
                );
            }
        }
        // These exact native objects remain fetchable without either optional
        // extension, including through the ordinary legacy serving profile.
        for version in [0, 2] {
            let (returned, result, response) = exchange(node, version, public, None);
            node = returned;
            assert!(
                matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                "{result:?}"
            );
            assert!(extract_pack(&response, version).starts_with(b"PACK"));
            assert!(!contains(&response, b"ref-in-want"));
            assert!(!contains(&response, b"object-info"));
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn each_opt_in_enables_only_its_own_command_on_raw_and_http() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for (allow_refs, allow_info) in [(true, false), (false, true), (true, true)] {
            let Fixture {
                scratch: _scratch,
                mut node,
                public,
                ..
            } = fixture_with_configuration(format, b"current public content".to_vec(), |config| {
                config
                    .with_upload_pack_ref_in_want(allow_refs)
                    .with_upload_pack_object_info(allow_info)
            });
            for (refs, enabled, body) in [
                (
                    true,
                    allow_refs,
                    ref_in_want::fetch_body(format, &[b"refs/heads/public"], &[]),
                ),
                (false, allow_info, object_info_body(format, public)),
            ] {
                let (returned, result, response) = ref_in_want::raw_fetch(node, &body);
                node = returned;
                assert_eq!(contains(&response, b"ref-in-want"), allow_refs);
                assert_eq!(contains(&response, b"object-info"), allow_info);
                if enabled {
                    assert!(result.is_ok(), "opted-in raw command: {result:?}");
                    if refs {
                        assert!(contains(&response, b"wanted-refs\n"));
                        assert!(extract_pack(&response, 2).starts_with(b"PACK"));
                    } else {
                        assert!(!contains(&response, b"PACK"));
                        assert!(contains(&response, format!("{public} ").as_bytes()));
                    }
                } else {
                    assert_raw_disabled(result, refs);
                    assert!(!contains(&response, b"PACK"));
                }
                for streamed in [false, true] {
                    let (result, response) = ref_in_want::http_fetch(&node, &body, streamed);
                    if enabled {
                        let receipt = result.expect("opted-in HTTP command succeeds");
                        assert_eq!(receipt.pack_requested(), refs);
                        let payload = ref_in_want::http_body(&response);
                        if refs {
                            assert!(contains(&payload, b"wanted-refs\n"));
                            assert!(extract_pack(&payload, 2).starts_with(b"PACK"));
                        } else {
                            assert!(contains(&payload, format!("{public} ").as_bytes()));
                            assert!(!contains(&payload, b"PACK"));
                        }
                    } else {
                        let Err(NodeSmartHttpRefusal::Rpc(error)) = result else {
                            panic!("disabled HTTP extension was not refused: {result:?}");
                        };
                        let RpcError::Wire(error) = error.as_ref() else {
                            panic!("expected a wire refusal: {error:?}");
                        };
                        assert_disabled(error, refs);
                        assert!(response.is_empty());
                    }
                }
            }
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn reopened_children_keep_opt_ins_but_shared_graph_cache_cannot_enable_them() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            config,
            public,
            ..
        } = fixture_with_configuration(format, b"current public content".to_vec(), |config| {
            config
                .with_upload_pack_ref_in_want(true)
                .with_upload_pack_object_info(true)
        });
        let request = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::FLAT,
        );
        let selected = node
            .prepare_visible_upload_pack(&request, &materialized, &WireLimits::default(), &deadline)
            .unwrap();
        assert!(selected.repository().supports_ref_in_want());
        assert!(selected.repository().supports_object_info());
        assert_eq!(node.upload_visibility_cache_stats(), (0, 1));
        node.shutdown().unwrap();

        let disabled = config
            .clone()
            .with_upload_pack_ref_in_want(false)
            .with_upload_pack_object_info(false);
        node = OneNode::open_existing(disabled).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let next = node
            .prepare_visible_upload_pack(&request, &materialized, &WireLimits::default(), &deadline)
            .unwrap();
        assert_eq!(node.upload_visibility_cache_stats(), (1, 1));
        assert!(Arc::ptr_eq(&selected.objects, &next.objects));
        assert!(!next.repository().supports_ref_in_want());
        assert!(!next.repository().supports_object_info());
        assert!(next.repository().ref_in_want_checkpoint().is_err());
        assert!(next.repository().object_info_size(public).is_err());
        assert!(next.repository().contains_want(public));
        next.repository().negotiation_checkpoint().unwrap();
        let mut expired = next.repository().clone();
        expired.ref_in_want_deadline.as_mut().unwrap().started -= Duration::from_secs(3600);
        assert!(
            expired.negotiation_checkpoint().is_err(),
            "disabled optional features retain the ordinary fetch deadline"
        );
        node.shutdown().unwrap();

        node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (returned, result, response) =
            ref_in_want::raw_fetch(node, &object_info_body(format, public));
        node = returned;
        assert!(result.is_ok(), "reopened opted-in service: {result:?}");
        assert!(contains(&response, b"object-info"));
        assert!(contains(&response, b"ref-in-want"));
        node.shutdown().unwrap();
    }
}
