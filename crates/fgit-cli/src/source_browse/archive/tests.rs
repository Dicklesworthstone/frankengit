//! CLI publication remains behind successful collection and node shutdown.
use super::*;
use fgit_forge::source_archive::SourceArchivePin;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid,
    RepositoryAuthorityHeadId, RepositoryCommitId,
};

fn archive() -> SourceArchive {
    let algorithm = DigestAlgorithmId::try_new(2).unwrap();
    let oid = GitOid::from_hex(GitHashAlgorithm::Sha1, &"12".repeat(20)).unwrap();
    SourceArchive {
        pin: SourceArchivePin {
            head: RepositoryAuthorityHeadId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[9; 32]).unwrap(),
            ),
            rcr: RepositoryCommitId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[8; 32]).unwrap(),
            ),
            commit: oid,
            tree: oid,
        },
        root: oid,
        bytes: vec![0; 1024],
        entries: 1,
        gitlinks: 0,
        reads: 1,
    }
}

#[test]
fn shutdown_failure_withholds_complete_output_and_preserves_read_failure() {
    assert!(after_shutdown(Ok(archive()), Some("not quiescent".into())).is_err());
    let error = after_shutdown(Err("missing object".into()), Some("close failed".into()))
        .err()
        .unwrap();
    assert!(error.contains("missing object") && error.contains("close failed"));
    assert_eq!(after_shutdown(Ok(archive()), None).unwrap().entries, 1);
}
