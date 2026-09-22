use super::*;
use crate::ObjectFormat;
use fgit_crypto::{GitObjectKind, git_object_id};

// Independent stored-zlib/base85 fixtures. No production compressor or lookup.
fn member(kind: &str, bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let size = u16::try_from(bytes.len()).unwrap();
    let mut z = vec![0x78, 1, 1];
    z.extend(size.to_le_bytes());
    z.extend((!size).to_le_bytes());
    z.extend(bytes);
    let (a, b) = bytes.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521;
        (a, (b + a) % 65521)
    });
    z.extend(((b << 16) | a).to_be_bytes());
    let mut out = format!("{kind} {}\n", bytes.len()).into_bytes();
    for row in z.chunks(52) {
        let n = row.len() as u8;
        out.push(if n <= 26 { b'A' + n - 1 } else { b'a' + n - 27 });
        for word in row.chunks(4) {
            let mut padded = [0u8; 4];
            padded[..word.len()].copy_from_slice(word);
            let mut n = u32::from_be_bytes(padded);
            let mut encoded = [0; 5];
            for digit in encoded.iter_mut().rev() {
                *digit = DIGITS[(n % 85) as usize];
                n /= 85;
            }
            out.extend(encoded);
        }
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}
fn literal(old: &[u8], new: &[u8]) -> Vec<u8> {
    [
        b"GIT binary patch\n".as_slice(),
        &member("literal", new),
        &member("literal", old),
    ]
    .concat()
}
fn id(bytes: &[u8]) -> ObjectId {
    git_object_id(ObjectFormat::Sha1, GitObjectKind::Blob, bytes)
}
fn apply(batch: &mut BinaryPatchBatch, patch: &[u8]) -> Result<Vec<u8>, BinaryPatchError> {
    batch.apply(
        patch,
        Some(id(b"old")),
        Some(id(b"new")),
        b"old",
        &mut || true,
    )
}

#[test]
fn batch_count_and_work_shares_are_bounded_before_decode() {
    for count in [0, 1025, usize::MAX] {
        assert!(BinaryPatchBatch::new(BinaryPatchLimits::default(), count).is_err());
    }
    let limits = BinaryPatchLimits {
        max_inflate_work: 17,
        max_delta_work: 19,
        ..Default::default()
    };
    let batch = BinaryPatchBatch::new(limits, 3).unwrap();
    assert_eq!(batch.limits.max_inflate_work, 5);
    assert_eq!(batch.limits.max_delta_work, 6);
    assert!(BinaryPatchBatch::new(limits, 9).is_err());
    assert!(
        BinaryPatchBatch::new(
            BinaryPatchLimits {
                max_lines: 0,
                ..limits
            },
            1
        )
        .is_err()
    );
}

#[test]
fn two_files_consume_one_exact_byte_and_line_allowance() {
    let patch = literal(b"old", b"new");
    let limits = BinaryPatchLimits {
        max_input_bytes: patch.len() * 2,
        max_expanded_bytes: 18,
        max_lines: 14,
        max_file_bytes: 3,
        ..Default::default()
    };
    let mut batch = BinaryPatchBatch::new(limits, 2).unwrap();
    for count in 1..=2 {
        assert_eq!(apply(&mut batch, &patch).unwrap(), b"new");
        assert_eq!(
            batch.usage(),
            BinaryPatchUsage {
                files: count,
                input_bytes: patch.len() * count,
                expanded_bytes: 9 * count,
                lines: 7 * count
            }
        );
    }
    assert_eq!(
        apply(&mut batch, &patch),
        Err(BinaryPatchError::Limit("binary files"))
    );
}

#[test]
fn shared_expansion_input_and_lines_never_reset_at_a_file_boundary() {
    let patch = literal(b"old", b"new");
    for limits in [
        BinaryPatchLimits {
            max_expanded_bytes: 17,
            ..Default::default()
        },
        BinaryPatchLimits {
            max_input_bytes: patch.len() * 2 - 1,
            ..Default::default()
        },
        BinaryPatchLimits {
            max_lines: 13,
            ..Default::default()
        },
    ] {
        let mut batch = BinaryPatchBatch::new(limits, 2).unwrap();
        apply(&mut batch, &patch).unwrap();
        let before = batch.usage();
        assert!(matches!(
            apply(&mut batch, &patch),
            Err(BinaryPatchError::Limit(_))
        ));
        assert_eq!(
            batch.usage(),
            before,
            "failed work cannot become a successful receipt"
        );
        assert!(matches!(
            apply(&mut batch, &patch),
            Err(BinaryPatchError::Invalid(_))
        ));
    }
}

#[test]
fn delta_program_and_both_reconstructed_images_are_charged() {
    let forward = [3, 4, 0x90, 3, 1, b'!']; // abc -> abc!
    let reverse = [4, 3, 0x90, 3]; // abc! -> abc
    let patch = [
        b"GIT binary patch\n".as_slice(),
        &member("delta", &forward),
        &member("delta", &reverse),
    ]
    .concat();
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let hash = |bytes: &[u8]| Some(git_object_id(format, GitObjectKind::Blob, bytes));
        let mut batch = BinaryPatchBatch::new(
            BinaryPatchLimits {
                max_expanded_bytes: 20,
                ..Default::default()
            },
            1,
        )
        .unwrap();
        assert_eq!(
            batch
                .apply(&patch, hash(b"abc"), hash(b"abc!"), b"abc", &mut || true)
                .unwrap(),
            b"abc!"
        );
        assert_eq!(batch.usage().expanded_bytes, 3 + 6 + 4 + 4 + 3);
        let mut small = BinaryPatchBatch::new(
            BinaryPatchLimits {
                max_expanded_bytes: 19,
                ..Default::default()
            },
            1,
        )
        .unwrap();
        assert!(matches!(
            small.apply(&patch, hash(b"abc"), hash(b"abc!"), b"abc", &mut || true),
            Err(BinaryPatchError::Limit(_))
        ));
    }
}

#[test]
fn a_failed_reverse_image_poisons_even_after_forward_identity_verification() {
    let wrong = literal(b"bad", b"new");
    let correct = literal(b"old", b"new");
    let mut batch = BinaryPatchBatch::new(BinaryPatchLimits::default(), 2).unwrap();
    assert_eq!(
        apply(&mut batch, &wrong),
        Err(BinaryPatchError::ReverseMismatch)
    );
    assert_eq!(batch.usage(), BinaryPatchUsage::default());
    assert!(matches!(
        apply(&mut batch, &correct),
        Err(BinaryPatchError::Invalid(_))
    ));
    assert_eq!(
        apply(
            &mut BinaryPatchBatch::new(Default::default(), 1).unwrap(),
            &correct
        )
        .unwrap(),
        b"new"
    );
}

#[test]
fn identity_and_malformed_member_failures_cannot_be_retried_inside_a_budget() {
    let valid = literal(b"old", b"new");
    for (body, old, new, base) in [
        (
            valid.as_slice(),
            Some(id(b"wrong")),
            Some(id(b"new")),
            b"old".as_slice(),
        ),
        (
            valid.as_slice(),
            Some(id(b"old")),
            Some(id(b"wrong")),
            b"old".as_slice(),
        ),
        (
            &valid[..valid.len() - 3],
            Some(id(b"old")),
            Some(id(b"new")),
            b"old".as_slice(),
        ),
    ] {
        let mut batch = BinaryPatchBatch::new(Default::default(), 2).unwrap();
        assert!(batch.apply(body, old, new, base, &mut || true).is_err());
        assert!(matches!(
            apply(&mut batch, &valid),
            Err(BinaryPatchError::Invalid(_))
        ));
    }
}

#[test]
fn cancellation_at_each_native_boundary_cannot_return_or_retry_tentative_bytes() {
    let patch = literal(b"old", b"new");
    let mut polls = 0;
    let mut control = || {
        polls += 1;
        true
    };
    BinaryPatchBatch::new(Default::default(), 1)
        .unwrap()
        .apply(
            &patch,
            Some(id(b"old")),
            Some(id(b"new")),
            b"old",
            &mut control,
        )
        .unwrap();
    for stop in 0..polls {
        let mut batch = BinaryPatchBatch::new(Default::default(), 1).unwrap();
        let mut count = 0;
        assert_eq!(
            batch.apply(
                &patch,
                Some(id(b"old")),
                Some(id(b"new")),
                b"old",
                &mut || {
                    let live = count < stop;
                    count += 1;
                    live
                }
            ),
            Err(BinaryPatchError::Cancelled)
        );
        assert!(matches!(
            apply(&mut batch, &patch),
            Err(BinaryPatchError::Invalid(_))
        ));
    }
}

#[test]
fn reserved_work_is_a_ceiling_not_an_unbounded_per_file_reset() {
    let patch = literal(b"old", b"new");
    let mut batch = BinaryPatchBatch::new(
        BinaryPatchLimits {
            max_inflate_work: 4,
            ..Default::default()
        },
        2,
    )
    .unwrap();
    assert!(matches!(
        apply(&mut batch, &patch),
        Err(BinaryPatchError::Limit(_))
    ));
    assert_eq!(
        apply(
            &mut BinaryPatchBatch::new(Default::default(), 2).unwrap(),
            &patch
        )
        .unwrap(),
        b"new"
    );
}

#[test]
fn empty_and_absent_sides_and_legacy_single_file_results_are_preserved() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let hash = |bytes: &[u8]| Some(git_object_id(format, GitObjectKind::Blob, bytes));
        for (old, new, from, to) in [
            (None, hash(b"\0x"), b"".as_slice(), b"\0x".as_slice()),
            (hash(b"\0x"), None, b"\0x".as_slice(), b"".as_slice()),
            (hash(b"\0x"), hash(b""), b"\0x".as_slice(), b"".as_slice()),
        ] {
            let bytes = literal(from, to);
            let legacy = crate::binary_patch::apply_binary_patch(
                &bytes,
                old,
                new,
                from,
                Default::default(),
                &mut || true,
            )
            .unwrap();
            let got = BinaryPatchBatch::new(Default::default(), 1)
                .unwrap()
                .apply(&bytes, old, new, from, &mut || true)
                .unwrap();
            assert_eq!(got, to);
            assert_eq!(got, legacy);
        }
    }
}
