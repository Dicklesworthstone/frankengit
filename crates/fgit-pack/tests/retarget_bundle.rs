#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use fgit_git_object::ObjectType;
use fgit_pack::full_bundle::retarget::RetargetedBundle;
use fgit_pack::full_bundle::stream::StreamFullBundleError;
use fgit_pack::full_bundle::{
    FullBundleError, FullBundleInput, FullBundleLimits, IncrementalBundle,
};
use fgit_pack::{
    BundleReference, CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId, PackError,
    PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter,
};
use fgit_types::RefName;

struct Source(BTreeMap<ObjectId, CanonicalPackObject>);
impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

fn reference(bytes: &[u8]) -> RefName {
    RefName::try_new(bytes).unwrap()
}

fn fixture(format: ObjectFormat, message_bytes: usize) -> (Vec<u8>, ObjectId, ObjectId) {
    let tree = fgit_crypto::git_object_id(format, ObjectType::Tree, b"");
    let metadata = "author A <a@example.test> 1 +0000\ncommitter A <a@example.test> 1 +0000\n";
    let base_body = format!("tree {tree}\n{metadata}\nbase\n");
    let base = fgit_crypto::git_object_id(format, ObjectType::Commit, base_body.as_bytes());
    let mut body = format!("tree {tree}\nparent {base}\n{metadata}\n").into_bytes();
    body.extend(std::iter::repeat_n(b'x', message_bytes));
    body.push(b'\n');
    let tip = fgit_crypto::git_object_id(format, ObjectType::Commit, &body);
    let source = Source(BTreeMap::from([(
        tip,
        CanonicalPackObject::new(tip, ObjectType::Commit, body, vec![tree, base], 0, 0),
    )]));
    let limits = PackLimits::default();
    let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone())
        .plan_selected(&source, &[tip], &mut || true)
        .unwrap();
    let bundle = IncrementalBundle::write(
        &[BundleReference::new(tip, reference(b"refs/heads/main"))],
        &[base],
        &BTreeSet::from([base, tree]),
        &plan,
        &PackWriter::new(limits),
        FullBundleLimits::default(),
        &mut || true,
    )
    .unwrap()
    .into_bytes();
    (bundle, tip, base)
}

fn legacy_header(format: ObjectFormat, tip: ObjectId, base: ObjectId, target: &RefName) -> Vec<u8> {
    let mut bytes = match format {
        ObjectFormat::Sha1 => b"# v2 git bundle\n".to_vec(),
        ObjectFormat::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bytes.extend_from_slice(format!("-{base} canonical parent\n{tip} ").as_bytes());
    bytes.extend_from_slice(target.as_bytes());
    bytes.extend_from_slice(b"\n\n");
    bytes
}

#[test]
fn real_incremental_pack_is_borrowed_unchanged_across_ci_and_raw_target_advertisements() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (bytes, tip, base) = fixture(format, 7);
        let original =
            FullBundleInput::parse_incremental(&bytes, Default::default(), &mut || true).unwrap();
        original
            .verify_pack_framing(&PackLimits::default(), &mut || true)
            .unwrap();
        for target in [
            reference(b"refs/heads/ci-queue-1"),
            reference(b"refs/heads/\xff-target"),
        ] {
            let result = RetargetedBundle::parse(
                &bytes,
                &reference(b"refs/heads/main"),
                &target,
                tip,
                Default::default(),
                &mut || true,
            )
            .unwrap();
            assert!(std::ptr::eq(
                result.pack_bytes().as_ptr(),
                original.pack_bytes().as_ptr()
            ));
            assert_eq!(result.pack_bytes(), original.pack_bytes());
            assert_eq!(
                result.header_bytes(),
                legacy_header(format, tip, base, &target)
            );
            let digest = result.sha256(&mut || true).unwrap();
            let mut streamed = Vec::new();
            result.write_to(&mut streamed, &mut || true).unwrap();
            assert_eq!(result.byte_len(), streamed.len());
            assert_eq!(digest, fgit_crypto::sha256_digest(&streamed));
            assert_eq!(result.into_vec(&mut || true).unwrap(), streamed);
            let parsed =
                FullBundleInput::parse_incremental(&streamed, Default::default(), &mut || true)
                    .unwrap();
            assert_eq!(parsed.prerequisites(), &[base]);
            assert_eq!(parsed.references()[0].name(), &target);
            assert_eq!(*parsed.references()[0].target(), tip);
            parsed
                .verify_pack_framing(&PackLimits::default(), &mut || true)
                .unwrap();
        }
    }
}

#[test]
fn wrong_candidate_reference_domain_and_extra_advertisements_are_not_rebound() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (bytes, tip, base) = fixture(format, 7);
        let expected = reference(b"refs/heads/main");
        let destination = reference(b"refs/heads/ci-1");
        let parse = |input: &[u8], source: &RefName, commit| {
            RetargetedBundle::parse(
                input,
                source,
                &destination,
                commit,
                Default::default(),
                &mut || true,
            )
            .map(|_| ())
        };
        assert!(parse(&bytes, &expected, tip).is_ok());
        assert!(parse(&bytes, &destination, tip).is_err());
        assert!(parse(&bytes, &expected, base).is_err());
        for destination in [
            RefName::try_new_one_level(b"HEAD").unwrap(),
            reference(b"other/namespace"),
        ] {
            assert!(
                RetargetedBundle::parse(
                    &bytes,
                    &expected,
                    &destination,
                    tip,
                    Default::default(),
                    &mut || true,
                )
                .is_err()
            );
        }
        let other = if format == ObjectFormat::Sha1 {
            ObjectFormat::Sha256
        } else {
            ObjectFormat::Sha1
        };
        assert_eq!(
            parse(
                &bytes,
                &expected,
                ObjectId::from_hex(other, &"11".repeat(other.digest_len())).unwrap()
            ),
            Err(FullBundleError::FormatMismatch)
        );
        let input =
            FullBundleInput::parse_incremental(&bytes, Default::default(), &mut || true).unwrap();
        let header = &bytes[..input.header_bytes() - 1];
        for name in [b"HEAD".as_slice(), b"refs/heads/extra"] {
            let mut extra = header.to_vec();
            extra.extend_from_slice(format!("{tip} ").as_bytes());
            extra.extend_from_slice(name);
            extra.extend_from_slice(b"\n\n");
            extra.extend_from_slice(input.pack_bytes());
            assert!(parse(&extra, &expected, tip).is_err());
        }
        for end in 0..input.header_bytes() + 4 {
            assert!(
                parse(&bytes[..end], &expected, tip).is_err(),
                "truncation {end}"
            );
        }
    }
}

#[test]
fn longer_destination_respects_both_exact_output_bounds_before_copying_pack() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (bytes, tip, _) = fixture(format, 7);
        let source = reference(b"refs/heads/main");
        let target = reference(b"refs/heads/a-longer-queue-candidate-name");
        let good = RetargetedBundle::parse(
            &bytes,
            &source,
            &target,
            tip,
            Default::default(),
            &mut || true,
        )
        .unwrap();
        let exact = FullBundleLimits {
            max_header_bytes: good.header_bytes().len(),
            max_bundle_bytes: good.byte_len(),
            max_references: 1,
        };
        assert!(
            RetargetedBundle::parse(&bytes, &source, &target, tip, exact, &mut || true).is_ok()
        );
        for limits in [
            FullBundleLimits {
                max_header_bytes: exact.max_header_bytes - 1,
                ..exact
            },
            FullBundleLimits {
                max_bundle_bytes: exact.max_bundle_bytes - 1,
                ..exact
            },
            FullBundleLimits {
                max_references: 0,
                ..exact
            },
        ] {
            assert!(matches!(
                RetargetedBundle::parse(&bytes, &source, &target, tip, limits, &mut || true),
                Err(FullBundleError::Limit(_))
            ));
        }
    }
}

#[test]
fn cancellation_bounds_hashing_materialization_and_partial_stream_output() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (bytes, tip, _) = fixture(format, 80 * 1024);
        let source = reference(b"refs/heads/main");
        let target = reference(b"refs/heads/ci-1");
        let cancelled = FullBundleError::Pack(PackError::DeadlineExceeded);
        assert!(matches!(
            RetargetedBundle::parse(
                &bytes,
                &source,
                &target,
                tip,
                Default::default(),
                &mut || false
            ),
            Err(FullBundleError::Pack(PackError::DeadlineExceeded))
        ));
        let result = RetargetedBundle::parse(
            &bytes,
            &source,
            &target,
            tip,
            Default::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(result.sha256(&mut || false), Err(cancelled.clone()));
        let mut checkpoints = 0;
        assert_eq!(
            result.sha256(&mut || {
                checkpoints += 1;
                checkpoints < 3
            }),
            Err(cancelled.clone())
        );
        let mut output = Vec::new();
        assert!(matches!(
            result.write_to(&mut output, &mut || false),
            Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                PackError::DeadlineExceeded
            )))
        ));
        assert!(output.is_empty());
        let mut checkpoints = 0;
        assert!(
            result
                .write_to(&mut output, &mut || {
                    checkpoints += 1;
                    checkpoints < 3
                })
                .is_err()
        );
        assert_eq!(output.len(), result.header_bytes().len() + 16 * 1024);
        assert!(output.len() < result.byte_len());
        let mut checkpoints = 0;
        assert_eq!(
            result.into_vec(&mut || {
                checkpoints += 1;
                checkpoints < 3
            }),
            Err(cancelled)
        );
    }
}

#[test]
fn write_failure_remains_io_and_never_returns_complete_output() {
    struct FailsAfter {
        bytes: Vec<u8>,
        maximum: usize,
    }
    impl Write for FailsAfter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if self.bytes.len() == self.maximum {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            let count = input.len().min(self.maximum - self.bytes.len()).min(3);
            self.bytes.extend_from_slice(&input[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (bytes, tip, _) = fixture(ObjectFormat::Sha256, 7);
    let result = RetargetedBundle::parse(
        &bytes,
        &reference(b"refs/heads/main"),
        &reference(b"refs/heads/ci"),
        tip,
        Default::default(),
        &mut || true,
    )
    .unwrap();
    let mut writer = FailsAfter {
        bytes: Vec::new(),
        maximum: result.header_bytes().len() + 5,
    };
    assert!(
        matches!(result.write_to(&mut writer, &mut || true), Err(StreamFullBundleError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
    );
    assert_eq!(writer.bytes.len(), writer.maximum);
    assert_eq!(
        &writer.bytes[..result.header_bytes().len()],
        result.header_bytes()
    );
}

#[test]
fn transformation_never_claims_pack_validation() {
    let (mut bytes, tip, _) = fixture(ObjectFormat::Sha1, 7);
    *bytes.last_mut().unwrap() ^= 1;
    let result = RetargetedBundle::parse(
        &bytes,
        &reference(b"refs/heads/main"),
        &reference(b"refs/heads/ci"),
        tip,
        Default::default(),
        &mut || true,
    )
    .unwrap()
    .into_vec(&mut || true)
    .unwrap();
    let parsed =
        FullBundleInput::parse_incremental(&result, Default::default(), &mut || true).unwrap();
    assert!(
        parsed
            .verify_pack_framing(&PackLimits::default(), &mut || true)
            .is_err()
    );
}
