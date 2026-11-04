//! Persisted real native proofs cross the actual MCP boundary in both object
//! domains. The retained request coordinates, not response metadata, are the
//! inputs to the independent consumer verifier in these tests.
use super::*;
use fgit_crypto::sha256_digest;
use fgit_types::{GitHashAlgorithm, RootLayoutVersion};
use fgit_verified_read::blob::{decode_verified_blob_envelope, verify_blob_against_head};
mod support;
use support::*;

#[test]
fn persisted_native_proofs_roundtrip_raw_binary_empty_executable_and_symlink_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::RefStateMerkleV1,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        ] {
            let mut fixture = Fixture::new(format, layout);
            let before = fixture.state();
            assert!(
                fixture
                    .backend()
                    .tools()
                    .iter()
                    .any(|tool| tool.name == NAME)
            );
            assert!(!fixture.backend().is_mutation(NAME));
            for (path, expected, kind) in [
                (b"alpha.txt".as_slice(), TEXT, "file"),
                (RAW_PATH, BINARY, "file"),
                (b"dir/nested.txt".as_slice(), b"nested\n".as_slice(), "file"),
                (b"empty".as_slice(), b"".as_slice(), "file"),
                (b"link".as_slice(), LINK, "symlink"),
                (
                    b"run".as_slice(),
                    b"#!/bin/sh\nexit 0\n".as_slice(),
                    "executable",
                ),
            ] {
                let args = fixture.args(path);
                let retained = input::parse(&args).unwrap();
                let reply = fixture.protocol_call(args.clone());
                let result = content(&reply);
                assert_eq!(result["profile"].text(), Some(PROFILE));
                assert_eq!(
                    result["source_head"].text(),
                    Some(head_token(before.head).as_str())
                );
                assert_eq!(result["snapshot_token"], result["source_head"]);
                assert_eq!(result["object_format"].text(), Some(format.as_str()));
                assert_eq!(
                    result["repository_incarnation"].text(),
                    Some(
                        fixture
                            .backend()
                            .node
                            .repository_incarnation_id()
                            .to_string()
                            .as_str()
                    )
                );
                assert_eq!(
                    result["source_commit"].text(),
                    Some(fixture.commit.to_string().as_str())
                );
                assert_eq!(
                    result["reference_hex"].text(),
                    Some(hex(retained.reference.as_bytes()).as_str())
                );
                assert_eq!(result["path_hex"].text(), Some(hex(path).as_str()));
                assert_eq!(result["kind"].text(), Some(kind));
                assert_eq!(decode_chunks(result, "bytes_hex_chunks"), expected);
                let frame = decode_chunks(result, "proof_hex_chunks");
                assert_eq!(
                    result["proof_sha256"].text(),
                    Some(hex(&sha256_digest(&frame)).as_str())
                );
                assert_eq!(
                    result["proof_bytes"].text(),
                    Some(frame.len().to_string().as_str())
                );
                assert_eq!(
                    result["blob_bytes"].text(),
                    Some(expected.len().to_string().as_str())
                );
                assert!(frame.len() <= MAX_PROOF_BYTES);
                let envelope = decode_verified_blob_envelope(&frame).unwrap();
                assert_eq!(encode_verified_blob_envelope(&envelope).unwrap(), frame);
                let verified = verify_blob_against_head(
                    retained.expected_head,
                    &retained.reference,
                    &retained.path,
                    &envelope,
                )
                .unwrap();
                assert_eq!(verified.bytes, expected);
                assert_eq!(verified.source_commit, fixture.commit);
                assert_eq!(
                    result["object_id"].text(),
                    Some(verified.object_id.to_string().as_str())
                );
                for name in [
                    "read_only",
                    "complete",
                    "content_complete",
                    "proof_complete",
                    "server_verification_performed",
                    "independent_verification_required",
                ] {
                    assert_eq!(result[name], Value::Bool(true), "{name}");
                }
                for name in [
                    "repository_changed",
                    "objects_staged",
                    "transaction_created",
                    "published",
                    "approval_granted",
                ] {
                    assert_eq!(result[name], Value::Bool(false), "{name}");
                }
                assert_eq!(fixture.call(&args).unwrap().object().unwrap(), result);
                assert_eq!(fixture.state(), before);
            }
            let mut text_ref = fixture.args(b"alpha.txt");
            text_ref.remove("reference_hex");
            text_ref.insert("reference".into(), text("refs/heads/main"));
            let result = fixture.call(&text_ref).unwrap();
            let frame = decode_chunks(result.object().unwrap(), "proof_hex_chunks");
            fixture.reopen();
            assert_eq!(fixture.state(), before);
            assert_eq!(
                decode_chunks(
                    fixture.call(&text_ref).unwrap().object().unwrap(),
                    "proof_hex_chunks"
                ),
                frame
            );
        }
    }
}

#[test]
fn stale_head_missing_paths_and_legacy_layout_refuse_without_an_unproven_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, RootLayoutVersion::RefStateMerkleV1);
        let before = fixture.state();
        for path in [
            b"missing".as_slice(),
            b"dir",
            b"module",
            b"link/child",
            b"alpha.txt/child",
        ] {
            let args = fixture.args(path);
            assert!(fixture.call(&args).is_err(), "{path:?}");
            assert_eq!(fixture.state(), before);
        }
        let old = fixture.args(b"alpha.txt");
        let original = fixture.call(&old).unwrap();
        fixture.advance_head();
        assert_ne!(fixture.state().head, before.head);
        assert_eq!(
            fixture.call(&old).unwrap_err().code,
            "source_snapshot_moved"
        );
        // A retained frame still proves the retained head; that is distinct
        // from a new current read and makes no freshness claim.
        let frame = decode_chunks(original.object().unwrap(), "proof_hex_chunks");
        let envelope = decode_verified_blob_envelope(&frame).unwrap();
        let query = input::parse(&old).unwrap();
        assert_eq!(
            verify_blob_against_head(
                query.expected_head,
                &query.reference,
                &query.path,
                &envelope
            )
            .unwrap()
            .bytes,
            TEXT
        );
        let mut missing = fixture.args(b"alpha.txt");
        missing.insert("reference_hex".into(), text(hex(b"refs/heads/absent")));
        assert_eq!(
            fixture.call(&missing).unwrap_err().code,
            "source_unavailable"
        );
        drop(fixture);
        let mut legacy = Fixture::new(format, RootLayoutVersion::LegacyWholeBody);
        let before = legacy.state();
        let args = legacy.args(b"alpha.txt");
        assert_eq!(
            legacy.call(&args).unwrap_err().code,
            "verified_blob_layout_unavailable"
        );
        assert_eq!(legacy.state(), before);
    }
}

#[test]
fn launch_grant_and_direct_sponsored_guard_precede_caller_parsing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, RootLayoutVersion::RefStateMerkleV1);
        let before = fixture.state();
        let invalid = object([("principal", text("must never be read"))])
            .object()
            .unwrap()
            .clone();
        fixture.backend_mut().options.source = false;
        assert!(
            !fixture
                .backend()
                .tools()
                .iter()
                .any(|tool| tool.name == NAME)
        );
        assert_eq!(
            call(fixture.backend(), &invalid).unwrap_err().code,
            "tool_not_granted"
        );
        fixture.backend_mut().options.source = true;
        fixture.backend_mut().options.agent_token_file =
            Some(std::path::PathBuf::from("must-not-be-read"));
        assert!(
            !fixture
                .backend()
                .tools()
                .iter()
                .any(|tool| tool.name == NAME)
        );
        assert_eq!(
            call(fixture.backend(), &invalid).unwrap_err().code,
            "tool_not_granted"
        );
        fixture.backend_mut().options.agent_token_file = None;
        assert_eq!(fixture.state(), before);
    }
}

#[test]
fn complete_byte_and_proof_limits_refuse_before_hex_expansion() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let bytes: Vec<u8> = (0..MAX_BLOB_BYTES).map(|n| n as u8).collect();
        let mut fixture =
            Fixture::with_text(format, RootLayoutVersion::RefStateMerkleV1, &bytes, 0);
        let before = fixture.state();
        let mut args = fixture.args(b"alpha.txt");
        assert_eq!(
            fixture.call(&args).unwrap_err().code,
            "verified_blob_byte_limit"
        );
        args.insert("max_blob_bytes".into(), json::number(MAX_BLOB_BYTES as u64));
        let reply = fixture.protocol_call(args.clone());
        let result = content(&reply);
        assert_eq!(decode_chunks(result, "bytes_hex_chunks"), bytes);
        let Value::Array(chunks) = &result["bytes_hex_chunks"] else {
            panic!("chunks required")
        };
        assert_eq!(chunks.len(), 8);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.text().unwrap().len() == CHUNK_BYTES * 2)
        );
        assert!(
            Value::Object(result.clone())
                .encode(MAX_RESULT_BYTES)
                .is_ok()
        );
        assert_eq!(fixture.state(), before);
    }
    let mut oversize = Fixture::with_text(
        GitHashAlgorithm::Sha256,
        RootLayoutVersion::RefStateMerkleV1,
        &vec![0xff; MAX_BLOB_BYTES + 1],
        0,
    );
    let before = oversize.state();
    let mut args = oversize.args(b"alpha.txt");
    args.insert("max_blob_bytes".into(), json::number(MAX_BLOB_BYTES as u64));
    assert_eq!(
        oversize.call(&args).unwrap_err().code,
        "verified_blob_byte_limit"
    );
    assert_eq!(oversize.state(), before);
    drop(oversize);
    // The full original commit is part of the proof: a small blob alone
    // cannot make an oversized witness fit the complete-only MCP profile.
    let mut metadata = Fixture::with_text(
        GitHashAlgorithm::Sha1,
        RootLayoutVersion::RefStateMerkleV1,
        TEXT,
        MAX_PROOF_BYTES,
    );
    let before = metadata.state();
    let args = metadata.args(b"alpha.txt");
    assert_eq!(
        metadata.call(&args).unwrap_err().code,
        "verified_blob_proof_limit"
    );
    assert_eq!(metadata.state(), before);
}

#[test]
fn tampered_objects_wrong_pins_namespace_and_cancellation_never_render_content() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, RootLayoutVersion::RefStateMerkleV1);
        let args = fixture.args(RAW_PATH);
        let query = input::parse(&args).unwrap();
        let envelope = fixture.envelope(&args);
        let mut frame = encode_verified_blob_envelope(&envelope).unwrap();
        *frame.last_mut().unwrap() ^= 1;
        let tampered = decode_verified_blob_envelope(&frame).unwrap();
        assert_eq!(
            output::render(fixture.backend(), &query, &tampered, &|| true)
                .unwrap_err()
                .code,
            "verified_blob_proof_refused"
        );
        assert_eq!(
            output::render(fixture.backend(), &query, &envelope, &|| false)
                .unwrap_err()
                .code,
            "verified_blob_cancelled"
        );
        let mut wrong_path = input::parse(&args).unwrap();
        wrong_path.path = b"alpha.txt".to_vec();
        assert_eq!(
            output::render(fixture.backend(), &wrong_path, &envelope, &|| true)
                .unwrap_err()
                .code,
            "verified_blob_proof_refused"
        );
        let mut wrong_ref = input::parse(&args).unwrap();
        wrong_ref.reference = RefName::try_new(b"refs/heads/main").unwrap();
        assert!(output::render(fixture.backend(), &wrong_ref, &envelope, &|| true).is_err());
        fixture.advance_head();
        let mut wrong_head = input::parse(&args).unwrap();
        wrong_head.expected_head = fixture.state().head;
        assert!(output::render(fixture.backend(), &wrong_head, &envelope, &|| true).is_err());
        let original = fixture.backend().options.repository;
        fixture.backend_mut().options.repository = fgit_types::RepositoryId::from_bytes([0x99; 16]);
        assert_eq!(
            output::render(fixture.backend(), &query, &envelope, &|| true)
                .unwrap_err()
                .code,
            "verified_blob_namespace_mismatch"
        );
        fixture.backend_mut().options.repository = original;
        let other_format = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        fixture.backend_mut().options.format = other_format;
        assert_eq!(
            output::render(fixture.backend(), &query, &envelope, &|| true)
                .unwrap_err()
                .code,
            "verified_blob_namespace_mismatch"
        );
        fixture.backend_mut().options.format = format;
    }
}
