use super::super::profile::Profile;
use super::tests::sample;
use super::*;
use fgit_crypto::GitObjectKind;
use fgit_types::GitHashAlgorithm;
use std::io::Cursor;

#[test]
fn streamed_scans_recheck_the_original_pin_and_require_complete_visitors() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = sample(format, b"original");
        let replacement = sample(format, b"modified");
        let deadline = Profile::default().start();
        let mut archive = PinnedArchive::new(
            Cursor::new(original.clone()),
            super::super::super::sha256(&original),
            Default::default(),
            deadline,
        )
        .unwrap();
        archive
            .scan_stream(deadline, |record, body| {
                assert_eq!(record.kind, GitObjectKind::Blob);
                assert_eq!(record.length, 8);
                let mut observed = Vec::new();
                body.read_to_end(&mut observed).map_err(|e| e.to_string())?;
                assert_eq!(observed, b"original");
                Ok(())
            })
            .unwrap();
        assert!(archive.scan_stream(deadline, |_, _| Ok(())).is_err());
        *archive.input.get_mut() = replacement;
        let mut visited = false;
        let error = archive
            .scan_stream(deadline, |_, body| {
                visited = true;
                let mut observed = Vec::new();
                body.read_to_end(&mut observed).map_err(|e| e.to_string())?;
                assert_eq!(observed, b"modified");
                Ok(())
            })
            .unwrap_err();
        assert!(visited);
        assert!(error.contains("checksum mismatch"), "{error}");
        *archive.input.get_mut() = original;
        archive
            .scan_stream(deadline, |_, body| {
                std::io::copy(body, &mut std::io::sink()).map_err(|e| e.to_string())?;
                Ok(())
            })
            .unwrap();
    }
}
