#![forbid(unsafe_code)]
//! Actual native imports, source serving, canonical branch movement and restart.
//! The pure verifier receives the original independently selected head pin.

#[allow(dead_code)]
#[path = "source_http/support.rs"]
mod support;

use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_node::{LoopbackReceiveSession, OneNode, VerifiedBlobReadRefusal};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, RefName, RepositoryAuthorityHeadId, RootLayoutVersion,
};
use fgit_verified_read::blob::{
    VerifiedBlobEnvelope, VerifiedBlobKind, decode_verified_blob_envelope,
    encode_verified_blob_envelope, verify_blob_against_head,
};
use fgit_wire::{WireLimits, visibility::RefVisibility};
use support::{BINARY, BINARY_PATH, LINK, OWNER, Scratch, TEXT, fixture_with_config};

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

fn head(node: &OneNode) -> RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .basis()
        .id()
}

fn read(
    node: &OneNode,
    path: &[u8],
    expected: RepositoryAuthorityHeadId,
) -> Result<VerifiedBlobEnvelope, VerifiedBlobReadRefusal> {
    node.runtime().block_on(node.verified_blob_in(
        &node.request_context(),
        &RefVisibility::new(),
        &reference(),
        path,
        expected,
    ))
}

#[test]
fn actual_imported_bytes_have_exact_ref_path_proofs_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::RefStateMerkleV1,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        ] {
            let scratch = Scratch::new();
            let (node, commit) = fixture_with_config(
                &scratch,
                format,
                scratch.config(format).with_root_layout(layout),
            );
            let expected = head(&node);
            for (path, body, kind) in [
                (b"alpha.txt".as_slice(), TEXT, VerifiedBlobKind::File),
                (BINARY_PATH, BINARY, VerifiedBlobKind::File),
                (
                    b"dir/nested.txt",
                    b"needle in nested\n",
                    VerifiedBlobKind::File,
                ),
                (b"empty", b"", VerifiedBlobKind::File),
                (b"link", LINK, VerifiedBlobKind::Symlink),
                (b"run", b"#!/bin/sh\nneedle\n", VerifiedBlobKind::Executable),
            ] {
                let envelope = read(&node, path, expected).unwrap();
                let frame = encode_verified_blob_envelope(&envelope).unwrap();
                let received = decode_verified_blob_envelope(&frame).unwrap();
                let verified =
                    verify_blob_against_head(expected, &reference(), path, &received).unwrap();
                assert_eq!(verified.bytes, body);
                assert_eq!(verified.source_commit, commit);
                assert_eq!(verified.kind, kind);
                assert_eq!(received.head().repository_id, node.repository_id());
            }
            assert_eq!(
                head(&node),
                expected,
                "source proofs publish no transaction or repository state"
            );
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn hidden_absent_invalid_paths_cancellation_and_legacy_layouts_refuse_without_a_frame() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, _) = fixture_with_config(
            &scratch,
            format,
            scratch
                .config(format)
                .with_root_layout(RootLayoutVersion::RefStateMerkleV1),
        );
        let expected = head(&node);
        assert!(read(&node, b"alpha.txt", expected).is_ok());
        let mut hidden = RefVisibility::new();
        hidden
            .push_rule(b"refs/heads/main", &WireLimits::default())
            .unwrap();
        assert!(matches!(
            node.runtime().block_on(node.verified_blob_in(
                &node.request_context(),
                &hidden,
                &reference(),
                b"alpha.txt",
                expected
            )),
            Err(VerifiedBlobReadRefusal::RefUnavailable)
        ));
        let absent = RefName::try_new(b"refs/heads/absent").unwrap();
        assert!(matches!(
            node.runtime().block_on(node.verified_blob_in(
                &node.request_context(),
                &RefVisibility::new(),
                &absent,
                b"alpha.txt",
                expected
            )),
            Err(VerifiedBlobReadRefusal::RefUnavailable)
        ));
        for path in [
            b"not-present".as_slice(),
            b"module",
            b"dir",
            b"link/elsewhere",
        ] {
            assert!(matches!(
                read(&node, path, expected),
                Err(VerifiedBlobReadRefusal::PathUnavailable)
            ));
        }
        for path in [
            b"".as_slice(),
            b"../alpha.txt",
            b"/alpha.txt",
            b"dir//nested.txt",
        ] {
            assert!(matches!(
                read(&node, path, expected),
                Err(VerifiedBlobReadRefusal::InvalidRequest(_))
            ));
        }
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(matches!(
            node.runtime().block_on(node.verified_blob_in(
                &cancelled,
                &RefVisibility::new(),
                &reference(),
                b"alpha.txt",
                expected
            )),
            Err(VerifiedBlobReadRefusal::Cancelled)
        ));
        assert_eq!(head(&node), expected);
        node.shutdown().unwrap();
        let legacy = Scratch::new();
        let (node, _) = support::fixture(&legacy, format);
        assert!(matches!(
            read(&node, b"alpha.txt", head(&node)),
            Err(VerifiedBlobReadRefusal::UnsupportedLayout)
        ));
        node.shutdown().unwrap();
    }
}

#[test]
fn source_proofs_survive_reopen_and_known_head_movement_never_selects_fresh_bytes_silently() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch
            .config(format)
            .with_root_layout(RootLayoutVersion::RefStateMerkleV1);
        let (node, commit) = fixture_with_config(&scratch, format, config.clone());
        let expected = head(&node);
        let original =
            encode_verified_blob_envelope(&read(&node, BINARY_PATH, expected).unwrap()).unwrap();
        node.shutdown().unwrap();
        let node = support::reopen(&config);
        assert_eq!(head(&node), expected);
        assert_eq!(
            encode_verified_blob_envelope(&read(&node, BINARY_PATH, expected).unwrap()).unwrap(),
            original
        );
        let session = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"verified-blob-head-move".to_vec()).unwrap(),
        );
        let command = RefCommand {
            name: RefName::try_new(b"refs/heads/extra").unwrap(),
            expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(commit),
            force: false,
        };
        let admitted = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &session,
                &[command],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let current = head(&node);
        assert_ne!(current, expected);
        assert!(matches!(
            read(&node, BINARY_PATH, expected),
            Err(VerifiedBlobReadRefusal::SnapshotMoved)
        ));
        let newest = read(&node, BINARY_PATH, current).unwrap();
        assert_eq!(
            verify_blob_against_head(current, &reference(), BINARY_PATH, &newest)
                .unwrap()
                .bytes,
            BINARY
        );
        assert!(verify_blob_against_head(expected, &reference(), BINARY_PATH, &newest).is_err());
        // An independently retained old snapshot remains verifiable as old;
        // this does not call it current or discover its trust from the response.
        let retained = decode_verified_blob_envelope(&original).unwrap();
        assert_eq!(
            verify_blob_against_head(expected, &reference(), BINARY_PATH, &retained)
                .unwrap()
                .bytes,
            BINARY
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn actual_served_wire_tampering_and_tighter_object_budget_cannot_return_unverified_data() {
    let format = GitHashAlgorithm::Sha256;
    let scratch = Scratch::new();
    let config = scratch
        .config(format)
        .with_root_layout(RootLayoutVersion::RefStateMerkleV1);
    let (node, _) = fixture_with_config(&scratch, format, config.clone());
    let expected = head(&node);
    let frame =
        encode_verified_blob_envelope(&read(&node, b"alpha.txt", expected).unwrap()).unwrap();
    let mut tampered = frame.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let decoded = decode_verified_blob_envelope(&tampered).unwrap();
    assert!(verify_blob_against_head(expected, &reference(), b"alpha.txt", &decoded).is_err());
    assert!(
        verify_blob_against_head(
            expected,
            &reference(),
            BINARY_PATH,
            &decode_verified_blob_envelope(&frame).unwrap()
        )
        .is_err()
    );
    node.shutdown().unwrap();
    let node = support::reopen(&config.clone().with_max_object_bytes(64));
    assert!(matches!(
        read(&node, b"alpha.txt", expected),
        Err(VerifiedBlobReadRefusal::ObjectUnavailable)
    ));
    assert_eq!(head(&node), expected);
    node.shutdown().unwrap();
    let node = support::reopen(&config);
    assert!(read(&node, b"alpha.txt", expected).is_ok());
    node.shutdown().unwrap();
}
