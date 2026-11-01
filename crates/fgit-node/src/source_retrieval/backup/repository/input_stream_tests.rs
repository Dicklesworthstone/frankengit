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

#[cfg(unix)]
mod replicas {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Default)]
    struct Counts {
        bytes: Cell<u64>,
        eof: Cell<usize>,
        seeks: Cell<usize>,
    }

    struct Counted {
        input: Cursor<Vec<u8>>,
        counts: Rc<Counts>,
    }
    impl Read for Counted {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.input.read(buffer)?;
            self.counts
                .bytes
                .set(self.counts.bytes.get() + count as u64);
            if count == 0 && !buffer.is_empty() {
                self.counts.eof.set(self.counts.eof.get() + 1);
            }
            Ok(count)
        }
    }
    impl Seek for Counted {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.counts.seeks.set(self.counts.seeks.get() + 1);
            self.input.seek(position)
        }
    }
    fn seal(bytes: &[u8]) -> Seal {
        Seal {
            digest: super::super::super::super::sha256(bytes),
            bytes: bytes.len() as u64,
        }
    }

    #[test]
    fn replica_admission_uses_two_real_passes_and_retains_the_same_counted_reader() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let payload = vec![0x5a; 64 * 1024 + 7];
            let bytes = sample(format, &payload);
            let expected = seal(&bytes);
            let counts = Rc::new(Counts::default());
            let input = Counted {
                input: Cursor::new(bytes),
                counts: Rc::clone(&counts),
            };
            let deadline = Profile::default().start();
            let limits = TransferLimits {
                max_archive_bytes: expected.bytes,
                max_blob_bytes: payload.len() as u64,
                ..TransferLimits::default()
            };
            let mut archive =
                PinnedArchive::from_replica_reader(input, expected, limits, deadline).unwrap();
            assert_eq!(archive.seal(), expected);
            assert_eq!(counts.bytes.get(), 2 * expected.bytes);
            assert_eq!(counts.seeks.get(), 2);
            assert!(
                counts.eof.get() >= 2,
                "both full passes must probe real EOF"
            );
            let mut observed = 0;
            archive
                .scan_stream(deadline, |record, body| {
                    assert_eq!(record.kind, GitObjectKind::Blob);
                    let mut actual = Vec::new();
                    body.read_to_end(&mut actual)
                        .map_err(|error| error.to_string())?;
                    assert_eq!(actual, payload);
                    observed += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(observed, 1);
            assert_eq!(counts.bytes.get(), 3 * expected.bytes);
            assert_eq!(counts.seeks.get(), 3);
        }
    }

    #[test]
    fn only_initial_whole_seal_disagreement_is_recoverable_copy_damage() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let bytes = sample(format, b"finite replica payload");
            let expected = seal(&bytes);
            let mut changed = bytes.clone();
            changed[0] ^= 1;
            let mut long = bytes.clone();
            long.extend_from_slice(b"trailing bytes remain bounded");
            for (input, damage, consumed) in [
                (
                    bytes[..bytes.len() - 1].to_vec(),
                    DamageKind::LengthMismatch,
                    expected.bytes - 1,
                ),
                (long, DamageKind::LengthMismatch, expected.bytes + 1),
                (
                    changed.clone(),
                    DamageKind::ChecksumMismatch,
                    expected.bytes,
                ),
            ] {
                let counts = Rc::new(Counts::default());
                let result = PinnedArchive::from_replica_reader(
                    Counted {
                        input: Cursor::new(input),
                        counts: Rc::clone(&counts),
                    },
                    expected,
                    TransferLimits {
                        max_archive_bytes: expected.bytes,
                        ..TransferLimits::default()
                    },
                    Profile::default().start(),
                );
                assert!(
                    matches!(result, Err(ReplicaInputFailure::Damaged(found)) if found == damage)
                );
                assert_eq!(counts.bytes.get(), consumed);
                assert_eq!(counts.seeks.get(), 1, "damaged copies never enter decoding");
            }
            assert_eq!(DamageKind::LengthMismatch.code(), "archive_length_mismatch");
            assert_eq!(
                DamageKind::ChecksumMismatch.code(),
                "archive_checksum_mismatch"
            );

            // The same malformed transport with its own matching trusted seal
            // is an invalid artifact, not evidence that another copy may work.
            let bad_seal = seal(&changed);
            assert!(matches!(
                PinnedArchive::from_replica_reader(
                    Cursor::new(changed),
                    bad_seal,
                    TransferLimits::default(),
                    Profile::default().start(),
                ),
                Err(ReplicaInputFailure::Fatal(_))
            ));
            let narrow = TransferLimits {
                max_blob_bytes: 1,
                ..TransferLimits::default()
            };
            assert!(matches!(
                PinnedArchive::from_replica_reader(
                    Cursor::new(bytes.clone()),
                    expected,
                    narrow,
                    Profile::default().start(),
                ),
                Err(ReplicaInputFailure::Fatal(_))
            ));
            PinnedArchive::from_replica_reader(
                Cursor::new(bytes),
                expected,
                TransferLimits::default(),
                Profile::default().start(),
            )
            .unwrap();
        }
    }

    #[test]
    fn a_valid_replacement_after_checksum_is_fatal_even_when_its_objects_verify() {
        struct Changed {
            input: Cursor<Vec<u8>>,
            replacement: Option<Vec<u8>>,
            starts: usize,
        }
        impl Read for Changed {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.input.read(buffer)
            }
        }
        impl Seek for Changed {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                if position == SeekFrom::Start(0) {
                    self.starts += 1;
                    if self.starts == 2 {
                        self.input = Cursor::new(self.replacement.take().unwrap());
                    }
                }
                self.input.seek(position)
            }
        }
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let bytes = sample(format, b"original");
            let expected = seal(&bytes);
            let replacement = sample(format, b"modified");
            assert_eq!(bytes.len(), replacement.len());
            let error = PinnedArchive::from_replica_reader(
                Changed {
                    input: Cursor::new(bytes),
                    replacement: Some(replacement),
                    starts: 0,
                },
                expected,
                TransferLimits::default(),
                Profile::default().start(),
            )
            .err()
            .unwrap();
            assert!(
                matches!(error, ReplicaInputFailure::Fatal(message) if message.contains("checksum mismatch"))
            );
        }
    }

    #[test]
    fn storage_errors_and_expired_or_invalid_profiles_are_fatal_before_another_copy() {
        struct Failed {
            kind: io::ErrorKind,
        }
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(self.kind))
            }
        }
        impl Seek for Failed {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                Ok(0)
            }
        }
        let bytes = sample(GitHashAlgorithm::Sha256, b"storage failure boundary");
        let expected = seal(&bytes);
        for kind in [
            io::ErrorKind::Other,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(matches!(
                PinnedArchive::from_replica_reader(
                    Failed { kind },
                    expected,
                    TransferLimits::default(),
                    Profile::default().start(),
                ),
                Err(ReplicaInputFailure::Fatal(_))
            ));
        }
        for (limits, profile) in [
            (
                TransferLimits {
                    max_archive_bytes: expected.bytes - 1,
                    ..TransferLimits::default()
                },
                Profile::default(),
            ),
            (
                TransferLimits::default(),
                Profile {
                    timeout: std::time::Duration::ZERO,
                    ..Profile::default()
                },
            ),
        ] {
            let counts = Rc::new(Counts::default());
            assert!(matches!(
                PinnedArchive::from_replica_reader(
                    Counted {
                        input: Cursor::new(bytes.clone()),
                        counts: Rc::clone(&counts)
                    },
                    expected,
                    limits,
                    profile.start(),
                ),
                Err(ReplicaInputFailure::Fatal(_))
            ));
            assert_eq!(counts.bytes.get(), 0);
            assert_eq!(counts.seeks.get(), 0);
        }
        PinnedArchive::from_replica_reader(
            Cursor::new(bytes),
            expected,
            TransferLimits::default(),
            Profile::default().start(),
        )
        .unwrap();
    }
}
