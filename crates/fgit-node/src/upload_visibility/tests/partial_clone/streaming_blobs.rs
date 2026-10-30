//! Explicit large-blob serving profiles use the real file-backed consumer.

use super::*;
use fgit_crypto::{
    DigestHasher, GitObjectHasher, IdentityDomain, NativeObjectIdentity, Sha256, Sha256Hasher,
};
use fgit_object_fabric::{ObjectEnvelope, ObjectKind};
use std::io::{Seek, SeekFrom};

#[test]
fn configured_blob_limits_select_v6_without_changing_small_object_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            node,
            config,
            public,
            private,
            visible,
            ..
        } = fixture_with_public_body(format, vec![b'x'; 4096]);
        delete_private(&node, private);
        node.shutdown().unwrap();
        let mut node =
            OneNode::open_existing(config.with_selected_pack_blob_limit(64 * 1024 * 1024)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let database = FsqliteCx::new();
        let exhaustion = Cell::new(None);
        let ids = visible.iter().copied().collect::<Vec<_>>();
        for (requested, selected) in [
            (
                PackWriteProfile::COMPRESSED_V5,
                PackWriteProfile::COMPRESSED_V6,
            ),
            (
                PackWriteProfile::COMPRESSED_V5_THIN,
                PackWriteProfile::COMPRESSED_V6_THIN,
            ),
            (
                PackWriteProfile::COMPRESSED_NO_DELTA_V1,
                PackWriteProfile::COMPRESSED_NO_DELTA_V2,
            ),
        ] {
            let payload = node
                .materialize_selected_pack(
                    &materialized,
                    Some(&[public]),
                    &[],
                    requested,
                    &database,
                    &exhaustion,
                    None,
                    &mut || true,
                )
                .unwrap();
            assert_eq!(payload.receipt().writer().unwrap().profile, selected);
            assert_eq!(
                payload.receipt().writer().unwrap().object_count as usize,
                visible.len()
            );
            assert_eq!(
                payload.into_bytes().unwrap(),
                planned_pack(&node, &ids, requested)
            );
        }
        drop(request);
        // These are the same native protocol consumers used by a normal fetch;
        // the wire still negotiates the same capabilities and canonical bodies.
        let expected = visible
            .iter()
            .map(|id| node.read_git_object(*id).unwrap().payload().to_vec())
            .collect::<BTreeSet<_>>();
        for version in [0, 1, 2] {
            let (returned, result, response) =
                exchange_filtered(node, version, &[public], None, None, false);
            node = returned;
            assert!(result.is_ok(), "{format:?} v{version}: {result:?}");
            assert_eq!(bodies(&response, version, format), expected);
            assert_eq!(spool_names(&scratch.0), 0);
        }
        node.shutdown().unwrap();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Constructs only the stored fixture: every body byte is a sparse zero, and
/// both identities are computed in fixed chunks. No object-sized allocation or
/// source-file disk allocation is needed to cross the production 32 MiB bound.
fn sparse_sha256_blob(node: &OneNode, length: usize) -> (GitOid, PathBuf) {
    let mut native = GitObjectHasher::<Sha256>::new(GitObjectKind::Blob, length as u64);
    let native_header = format!("blob {length}\0");
    let mut strong = Sha256Hasher::new();
    strong.update(&fgit_crypto::internal_id_preimage_header(
        IdentityDomain::GitPayloadCommitment,
        fgit_crypto::GIT_PAYLOAD_SCHEMA,
        length as u64 + native_header.len() as u64,
    ));
    strong.update(native_header.as_bytes());
    let zeros = [0; 16 * 1024];
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(zeros.len());
        native.update(&zeros[..count]).unwrap();
        strong.update(&zeros[..count]);
        remaining -= count;
    }
    let id = native.finish().unwrap().erase();
    let namespace = crate::object_namespace(node.repository_id(), node.repository_incarnation_id());
    let envelope = ObjectEnvelope::new(
        namespace.clone(),
        id,
        ObjectKind::Blob,
        length as u64,
        strong.finish(),
        b"raw".to_vec(),
        [7; 32],
        None,
        &SegmentLimits::default(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let path = node
        .storage_root()
        .join("objects")
        .join(hex(&namespace))
        .join(hex(&id.algorithm().code_point().to_be_bytes()))
        .join(id.to_string());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"FGOB").unwrap();
    file.write_all(&(envelope.len() as u32).to_be_bytes())
        .unwrap();
    file.write_all(&envelope).unwrap();
    file.set_len(8 + envelope.len() as u64 + length as u64)
        .unwrap();
    (id, path)
}

fn large_blob_supplies_no_optional_hint(
    source: &VerifiedFabricPackSource<'_>,
    blob: GitOid,
    commit: GitOid,
) {
    let served = CeiledFabricSource {
        inner: source,
        ceiling: None,
    };
    assert_eq!(served.commit_tree(&blob).unwrap(), None);
    assert!(served.tree_entries(&blob).unwrap().is_empty());
    assert!(
        served
            .thin_base_hints(
                &[blob],
                &[commit],
                &BTreeSet::from([blob]),
                &BTreeSet::from([commit])
            )
            .unwrap()
            .is_empty()
    );
    assert!(
        served
            .thin_base_hints(
                &[commit],
                &[blob],
                &BTreeSet::from([commit]),
                &BTreeSet::from([blob])
            )
            .unwrap()
            .is_empty()
    );
    // Actual metadata still takes the verified body/parser path.
    let tree = served.commit_tree(&commit).unwrap().unwrap();
    assert!(!served.tree_entries(&tree).unwrap().is_empty());
}

#[test]
fn a_blob_above_32_mib_uses_verified_file_chunks_and_never_enters_buffered_loading() {
    const LENGTH: usize = 33 * 1024 * 1024 + 17;
    let stored = RefCell::new(None);
    let Fixture {
        scratch,
        node,
        config,
        ancestor,
        ..
    } = fixture_with_public_blob(GitHashAlgorithm::Sha256, |node| {
        let (id, path) = sparse_sha256_blob(node, LENGTH);
        *stored.borrow_mut() = Some((id, path));
        id
    });
    node.shutdown().unwrap();
    let (id, path) = stored.into_inner().unwrap();
    let configured = config
        .with_selected_pack_blob_limit(LENGTH)
        .with_selected_pack_byte_envelope(LENGTH + 16 * 1024);
    let mut node = OneNode::open_existing(configured).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    // Use the actual selected-pack consumer with a fresh explicit context so
    // wall-clock contention cannot make this large deterministic fixture flaky.
    let database = FsqliteCx::new();
    let exhaustion = Cell::new(None);
    let source = VerifiedFabricPackSource {
        fabric: &node.fabric,
        object_format: GitHashAlgorithm::Sha256,
        maximum_object_bytes: LENGTH,
        database_context: &database,
        database_exhaustion: &exhaustion,
        session_is_live: None,
    };
    assert_eq!(source.buffered_object_limit(), 32 * 1024 * 1024);
    assert_eq!(source.parse_limits().max_object_bytes, 32 * 1024 * 1024);
    assert!(matches!(
        fgit_pack::CanonicalObjectSource::load(&source, &id),
        Err(PackWriteError::Pack(PackError::ObjectSizeLimit {
            actual: LENGTH,
            limit: 33_554_432,
        }))
    ));
    assert_eq!(source.object_references(&id).unwrap(), Vec::<GitOid>::new());
    large_blob_supplies_no_optional_hint(&source, id, ancestor);

    // A lazy direct blob want with an admitted have reaches the real served
    // thin-hint path. Optional hint generation must not fall back to the
    // 32 MiB buffered reader before the V6 streaming consumer is selected.
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let visible = node
        .prepare_visible_upload_pack(&request, &materialized, &WireLimits::default(), &deadline)
        .unwrap();
    let fetch = super::request(vec![id], vec![ancestor], None);
    assert_eq!(visible.path_hash_of(&id), basename_path_hash(b"public"));
    let pack_context = node.session_pack_materialization_context(&deadline);
    let prepared = node
        .prepare_upload_pack_selection(
            &materialized,
            &visible,
            &fetch,
            &deadline,
            &pack_context,
            &mut || true,
        )
        .unwrap();
    assert_eq!(prepared.keys.len(), 1);
    assert_eq!(prepared.keys[0].id, id);
    assert_eq!(prepared.keys[0].path_hash, basename_path_hash(b"public"));
    let mut payload = node
        .materialize_selected_pack_in_scope(
            &materialized,
            visible.closure_for(&materialized).unwrap(),
            Some((&visible, &fetch)),
            Some(&[id]),
            &[ancestor],
            PackWriteProfile::COMPRESSED_V5_THIN,
            &database,
            &exhaustion,
            None,
            &mut || true,
        )
        .unwrap();
    let receipt = payload.receipt().writer().unwrap().clone();
    assert_eq!(receipt.profile, PackWriteProfile::COMPRESSED_V6_THIN);
    assert_eq!(receipt.object_count, 1);
    assert_eq!(receipt.total_object_bytes, LENGTH);
    assert_eq!(receipt.delta_count, 0);
    assert_eq!(receipt.compression.len(), 1);
    assert_eq!(receipt.compression[0].input_bytes, LENGTH);
    let mut pack = Vec::new();
    while let Some(chunk) = payload.next_chunk(4096).unwrap() {
        assert!(chunk.len() <= 4096);
        assert!(
            pack.len() + chunk.len() < 1024 * 1024,
            "zeros compress without a large test buffer"
        );
        pack.extend_from_slice(&chunk);
    }
    assert_eq!(pack.len(), receipt.output_bytes);
    let limits = node.selected_pack_limits.clone();
    let body = fgit_pack::validate_pack_trailer(
        &pack,
        GitHashAlgorithm::Sha256,
        &limits,
        &fgit_pack::NativeChecksumVerifier,
    )
    .unwrap();
    assert_eq!(
        fgit_pack::parse_pack_header(body, &limits)
            .unwrap()
            .object_count,
        1
    );
    let (entry, _) = fgit_pack::decode_entry_header(&body[12..], &limits, &mut || true).unwrap();
    assert_eq!(entry.kind, fgit_pack::EntryKind::Blob);
    assert_eq!(entry.declared_size, LENGTH);
    assert_eq!(&pack[body.len()..], receipt.checksum.as_bytes());
    drop(payload);
    assert_eq!(spool_names(&scratch.0), 0);

    // The requested-body ceiling remains exact even under the streaming
    // profile. It refuses before opening any body chunk or publishing output.
    node.selected_pack_limits.max_object_bytes = LENGTH - 1;
    let refused = node.materialize_selected_pack(
        &materialized,
        Some(&[id]),
        &[],
        PackWriteProfile::COMPRESSED_V5,
        &database,
        &exhaustion,
        None,
        &mut || true,
    );
    assert!(
        matches!(refused, Err(NodePackMaterializationRefusal::Pack(error))
        if matches!(*error, PackWriteError::Pack(PackError::ObjectSizeLimit { actual, limit })
            if actual == LENGTH && limit == LENGTH - 1))
    );
    node.selected_pack_limits.max_object_bytes = LENGTH;

    // A late mismatch is caught only after tentative compressed chunks have
    // reached private scratch. No completed pack or spool name survives it.
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[1]).unwrap();
    drop(file);
    // Even corrupt, unselected blob bodies cannot break advisory hint scans;
    // their unchanged headers only exclude them. Selecting the body below
    // still verifies and refuses it, so the hint is never disclosure proof.
    large_blob_supplies_no_optional_hint(&source, id, ancestor);
    let refused = node.materialize_selected_pack(
        &materialized,
        Some(&[id]),
        &[],
        PackWriteProfile::COMPRESSED_V5,
        &database,
        &exhaustion,
        None,
        &mut || true,
    );
    assert!(
        matches!(refused, Err(NodePackMaterializationRefusal::Pack(error))
        if matches!(*error, PackWriteError::MissingCanonicalObject(observed) if observed == id))
    );
    assert_eq!(spool_names(&scratch.0), 0);
    drop(request);
    node.shutdown().unwrap();
}

#[test]
fn file_stream_rechecks_the_outer_session_between_body_chunks() {
    let Fixture {
        scratch: _scratch,
        node,
        ..
    } = fixture_with_public_body(GitHashAlgorithm::Sha256, vec![9; 64 * 1024 + 17]);
    let id = git_object_id(
        GitHashAlgorithm::Sha256,
        GitObjectKind::Blob,
        &vec![9; 64 * 1024 + 17],
    );
    let live = Cell::new(true);
    let is_live = || live.get();
    let database = FsqliteCx::new();
    let exhaustion = Cell::new(None);
    let source = VerifiedFabricPackSource {
        fabric: &node.fabric,
        object_format: GitHashAlgorithm::Sha256,
        maximum_object_bytes: 128 * 1024,
        database_context: &database,
        database_exhaustion: &exhaustion,
        session_is_live: Some(&is_live),
    };
    let mut stream = source
        .fabric
        .open_blob_stream_bounded(id, 128 * 1024)
        .unwrap();
    let mut chunk = [0; 4096];
    assert_eq!(stream.read_tentative(&mut chunk).unwrap(), chunk.len());
    let mut reader = VerifiedFabricBlobReader {
        source: &source,
        stream,
        ceiling: None,
        credited: false,
    };
    assert_eq!(reader.read(&mut chunk).unwrap(), chunk.len());
    live.set(false);
    assert_eq!(
        reader.read(&mut chunk),
        Err(PackWriteError::Pack(PackError::DeadlineExceeded))
    );
    assert!(!reader.stream.is_verified());
    assert!(!reader.credited);
    drop(reader);
    node.shutdown().unwrap();
}
