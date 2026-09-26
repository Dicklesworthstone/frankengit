use super::super::archive::{Encoder, Identity};
use super::super::profile::Profile;
use super::*;
use fgit_authority::{HeadGeneration, StoreInstanceId};
use fgit_authority_fsqlite::{
    ExportBundle, ExportedHead, ExportedIssuance, IssuanceSequence, SCHEMA_VERSION, export_bundle,
    mint_token,
};
use fgit_crypto::{GitObjectKind, git_object_id, git_payload_commitment};
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::io::Cursor;

fn sample(format: GitHashAlgorithm, payload: &[u8]) -> Vec<u8> {
    let token = mint_token(StoreInstanceId::from_raw(41), IssuanceSequence::FIRST)
        .to_opaque_bytes()
        .to_vec();
    let authority = export_bundle(&ExportBundle {
        schema_version: SCHEMA_VERSION,
        instance: 41,
        bodies: vec![],
        head: Some(ExportedHead {
            key: b"head".to_vec(),
            token: token.clone(),
            generation: HeadGeneration::FIRST.get(),
            body: b"body".to_vec(),
        }),
        issuance: vec![ExportedIssuance {
            token,
            sequence: 1,
            head_key: b"head".to_vec(),
            generation: 1,
            body: b"body".to_vec(),
        }],
    })
    .unwrap();
    let identity = Identity {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format,
    };
    let mut encoder = Encoder::new(identity, &authority, 1).unwrap();
    let proof = git_payload_commitment(GitObjectKind::Blob, payload, CANONICAL_CODEC_VERSION);
    encoder
        .object(
            git_object_id(format, GitObjectKind::Blob, payload),
            GitObjectKind::Blob,
            payload,
            &proof.digest().as_bytes().try_into().unwrap(),
        )
        .unwrap();
    encoder.finish().unwrap()
}
#[test]
fn repeated_passes_pin_both_native_domains_without_retaining_payloads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let bytes = sample(format, b"exact\0bytes\xff");
        let pin = super::super::super::sha256(&bytes);
        let deadline = Profile::default().start();
        let mut archive = PinnedArchive::new(
            Cursor::new(bytes.clone()),
            pin,
            Default::default(),
            deadline,
        )
        .unwrap();
        assert_eq!(archive.header().objects, 1);
        for _ in 0..3 {
            let mut seen = 0;
            archive
                .scan(deadline, |record| {
                    seen += 1;
                    assert_eq!(record.payload, b"exact\0bytes\xff");
                    Ok(())
                })
                .unwrap();
            assert_eq!(seen, 1);
        }
        assert_eq!(
            archive.seal(),
            Seal {
                digest: pin,
                bytes: bytes.len() as u64
            }
        );
    }
}
#[test]
fn an_individually_valid_changed_record_cannot_reuse_a_previous_pass_pin() {
    let original = sample(GitHashAlgorithm::Sha1, b"original");
    let replacement = sample(GitHashAlgorithm::Sha1, b"modified");
    let deadline = Profile::default().start();
    let mut archive = PinnedArchive::new(
        Cursor::new(original.clone()),
        super::super::super::sha256(&original),
        Default::default(),
        deadline,
    )
    .unwrap();
    *archive.input.get_mut() = replacement;
    let mut visited = 0;
    let error = archive
        .scan(deadline, |row| {
            visited += 1;
            assert_eq!(row.payload, b"modified");
            Ok(())
        })
        .unwrap_err();
    assert_eq!(
        visited, 1,
        "native identity and commitment were valid; only the fixed file pin rejects it"
    );
    assert!(error.contains("checksum mismatch"));
    *archive.input.get_mut() = original;
    archive.scan(deadline, |_| Ok(())).unwrap();
}
#[test]
fn metadata_changes_truncation_and_byte_budgets_never_yield_a_complete_pass() {
    let bytes = sample(GitHashAlgorithm::Sha256, b"bounded");
    let pin = super::super::super::sha256(&bytes);
    let deadline = Profile::default().start();
    assert!(
        PinnedArchive::new(
            Cursor::new(bytes.clone()),
            pin,
            TransferLimits {
                max_archive_bytes: bytes.len() as u64 - 1
            },
            deadline
        )
        .is_err()
    );
    let mut archive = PinnedArchive::new(
        Cursor::new(bytes.clone()),
        pin,
        TransferLimits {
            max_archive_bytes: bytes.len() as u64,
        },
        deadline,
    )
    .unwrap();
    archive.input.get_mut()[8] ^= 1;
    let error = archive
        .scan(deadline, |_| {
            panic!("changed metadata must precede visitors")
        })
        .unwrap_err();
    assert!(error.contains("metadata changed"));
    *archive.input.get_mut() = bytes.clone();
    archive.input.get_mut().pop();
    assert!(
        archive
            .scan(deadline, |_| Ok(()))
            .unwrap_err()
            .contains("truncated")
    );
    *archive.input.get_mut() = bytes;
    archive.input.get_mut().push(0);
    assert!(
        archive
            .scan(deadline, |_| Ok(()))
            .unwrap_err()
            .contains("trailing")
    );
}
#[cfg(unix)]
#[test]
fn replacing_the_path_does_not_switch_an_already_opened_input() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let root = std::env::temp_dir().join(format!(
        "fg-pinned-input-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("source.fg");
    let new = root.join("replacement.fg");
    let bytes = sample(GitHashAlgorithm::Sha1, b"original");
    std::fs::write(&path, &bytes).unwrap();
    std::fs::write(&new, sample(GitHashAlgorithm::Sha1, b"modified")).unwrap();
    let deadline = Profile::default().start();
    let mut archive = PinnedArchive::open(
        &path,
        super::super::super::sha256(&bytes),
        Default::default(),
        deadline,
    )
    .unwrap();
    std::fs::rename(&new, &path).unwrap();
    archive
        .scan(deadline, |record| {
            assert_eq!(record.payload, b"original");
            Ok(())
        })
        .unwrap();
    drop(archive);
    std::fs::remove_dir_all(root).unwrap();
}
