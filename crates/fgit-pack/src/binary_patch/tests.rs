//! Native Git 2.47.3 --binary goldens, plus adversarial framing/identity twins.
//! Fixture generation is external conformance input, never a production path.
use super::*;
use crate::ObjectFormat;

fn id(format: ObjectFormat, bytes: &[u8]) -> ObjectId {
    git_object_id(format, GitObjectKind::Blob, bytes)
}
fn fixture(text: &str, format: ObjectFormat) -> (&[u8], Option<ObjectId>, Option<ObjectId>) {
    let index = text.lines().find_map(|s| s.strip_prefix("index ")).unwrap();
    let (old, new) = index.split_whitespace().next().unwrap().split_once("..").unwrap();
    let parse = |s: &str| if s.bytes().all(|b| b == b'0') { None }
        else { Some(ObjectId::from_hex(format, s).unwrap()) };
    let at = text.find("GIT binary patch\n").unwrap();
    (&text.as_bytes()[at..], parse(old), parse(new))
}
fn delta_inputs() -> (Vec<u8>, Vec<u8>) {
    let old: Vec<_> = (0u8..=255).cycle().take(2048).collect();
    let new = [&old[..333], b"changed\0\xff", &old[341..]].concat();
    (old, new)
}
#[test]
fn upstream_literal_creation_deletion_and_delta_goldens_match_both_native_formats() {
    for (format, fixtures) in [
        (ObjectFormat::Sha1, [include_str!("fixtures/literal-sha1.patch"), include_str!("fixtures/create-sha1.patch"),
            include_str!("fixtures/delete-sha1.patch"), include_str!("fixtures/delta-sha1.patch")]),
        (ObjectFormat::Sha256, [include_str!("fixtures/literal-sha256.patch"), include_str!("fixtures/create-sha256.patch"),
            include_str!("fixtures/delete-sha256.patch"), include_str!("fixtures/delta-sha256.patch")]),
    ] {
        let (old_delta, new_delta) = delta_inputs();
        for (text, base, expected) in [(fixtures[0], b"\0old\xff\n".as_slice(), b"\0new\xfe\r\n".as_slice()),
            (fixtures[1], &[], b"\0new\xfe\r\n"), (fixtures[2], b"\0old\xff\n", &[]),
            (fixtures[3], old_delta.as_slice(), new_delta.as_slice())] {
            let (body, old, new) = fixture(text, format);
            if let Some(old) = old { assert_eq!(id(format, base), old); }
            if let Some(new) = new { assert_eq!(id(format, expected), new); }
            let result = apply_binary_patch(body, old, new, base, BinaryPatchLimits::default(), &mut || true).unwrap();
            assert_eq!(result, expected);
            assert_eq!(apply_binary_patch(body, old, new, base, BinaryPatchLimits::default(), &mut || true).unwrap(), result);
        }
    }
}

// Independent test encoder: stored RFC 1950 member and Git base85 framing.
fn zlib(bytes: &[u8]) -> Vec<u8> {
    let len = u16::try_from(bytes.len()).unwrap();
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend(len.to_le_bytes()); out.extend((!len).to_le_bytes()); out.extend(bytes);
    let (mut a, mut b) = (1u32, 0u32);
    for byte in bytes { a = (a + u32::from(*byte)) % 65_521; b = (b + a) % 65_521; }
    out.extend(((b << 16) | a).to_be_bytes()); out
}
fn encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for row in bytes.chunks(52) {
        let count = u8::try_from(row.len()).unwrap();
        out.push(if count <= 26 { b'A' + count - 1 } else { b'a' + count - 27 });
        for word in row.chunks(4) {
            let mut padded = [0u8; 4]; padded[..word.len()].copy_from_slice(word);
            let mut n = u32::from_be_bytes(padded); let mut digits = [0u8; 5];
            for digit in digits.iter_mut().rev() { *digit = ALPHABET[(n % 85) as usize]; n /= 85; }
            out.extend(digits);
        }
        out.push(b'\n');
    }
    out
}
fn member(kind: &str, bytes: &[u8]) -> Vec<u8> {
    [format!("{kind} {}\n", bytes.len()).as_bytes(), &encode(&zlib(bytes)), b"\n"].concat()
}
fn literal(base: &[u8], result: &[u8]) -> Vec<u8> {
    [b"GIT binary patch\n".as_slice(), &member("literal", result), &member("literal", base)].concat()
}
fn run(body: &[u8], base: &[u8], result: &[u8], limits: BinaryPatchLimits) -> Result<Vec<u8>, BinaryPatchError> {
    apply_binary_patch(body, Some(id(ObjectFormat::Sha1, base)), Some(id(ObjectFormat::Sha1, result)), base, limits, &mut || true)
}
#[test]
fn every_base85_row_length_and_high_bit_pattern_preserves_exact_bytes() {
    for len in 1..=52 {
        for seed in [0u8, 1, 127, 128, 254, 255] {
            let bytes: Vec<_> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
            let row = encode(&bytes); let mut out = [0u8; 52];
            assert_eq!(decode_row(&row[..row.len() - 1], &mut out).unwrap(), len);
            assert_eq!(&out[..len], bytes);
        }
    }
    for length in [0, 1, 4, 26, 27, 51, 52, 53, 256, 4096] {
        let bytes: Vec<_> = (0..length).map(|n| n as u8).collect();
        assert_eq!(run(&literal(b"old", &bytes), b"old", &bytes, BinaryPatchLimits::default()).unwrap(), bytes);
    }
}
#[test]
fn malformed_base85_cannot_be_truncated_wrapped_or_accepted_as_padding() {
    for row in [b"".as_slice(), b"000000", b"A0000", b"A000000", b"A/////", b"A~~~~~", b"{00000", b"A00000 "] {
        assert!(decode_row(row, &mut [0; 52]).is_err(), "{row:?}");
    }
    assert_eq!(decode_row(b"A00000", &mut [0; 52]).unwrap(), 1);
}
#[test]
fn exact_source_target_and_hash_domain_are_not_optional() {
    let (body, old, new) = fixture(include_str!("fixtures/literal-sha1.patch"), ObjectFormat::Sha1);
    assert_eq!(apply_binary_patch(body, old, new, b"\0BAD\xff\n", BinaryPatchLimits::default(), &mut || true), Err(BinaryPatchError::SourceMismatch));
    assert_eq!(apply_binary_patch(body, old, Some(id(ObjectFormat::Sha1, b"wrong")), b"\0old\xff\n", BinaryPatchLimits::default(), &mut || true), Err(BinaryPatchError::TargetMismatch));
    assert!(apply_binary_patch(body, old, Some(id(ObjectFormat::Sha256, b"\0new\xfe\r\n")), b"\0old\xff\n", BinaryPatchLimits::default(), &mut || true).is_err());
    assert!(apply_binary_patch(body, None, None, &[], BinaryPatchLimits::default(), &mut || true).is_err());
    assert!(apply_binary_patch(body, Some(ObjectId::from_hex(ObjectFormat::Sha1, &"0".repeat(40)).unwrap()), new, &[], BinaryPatchLimits::default(), &mut || true).is_err());
}
#[test]
fn absence_and_empty_blob_are_distinct_and_reverse_image_must_match() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let patch = literal(b"abc", b"");
        assert_eq!(apply_binary_patch(&patch, Some(id(format, b"abc")), None, b"abc", BinaryPatchLimits::default(), &mut || true).unwrap(), b"");
        assert_eq!(apply_binary_patch(&patch, Some(id(format, b"abc")), Some(id(format, b"")), b"abc", BinaryPatchLimits::default(), &mut || true).unwrap(), b"");
        let wrong_reverse = literal(b"not abc", b"");
        assert_eq!(apply_binary_patch(&wrong_reverse, Some(id(format, b"abc")), None, b"abc", BinaryPatchLimits::default(), &mut || true), Err(BinaryPatchError::ReverseMismatch));
    }
}
#[test]
fn malformed_optional_reverse_and_third_members_refuse_the_entire_change() {
    let full = literal(b"old", b"new");
    let first_end = full.windows(2).position(|p| p == b"\n\n").unwrap() + 2;
    assert_eq!(run(&full[..first_end], b"old", b"new", BinaryPatchLimits::default()).unwrap(), b"new");
    for tail in [b"junk\n".as_slice(), b"literal 3\n", b"\n", b"diff --git a/other b/other\n"] {
        let bad = [&full[..first_end], tail].concat();
        assert!(run(&bad, b"old", b"new", BinaryPatchLimits::default()).is_err());
    }
    let third = [full, member("literal", b"other")].concat();
    assert!(run(&third, b"old", b"new", BinaryPatchLimits::default()).is_err());
}
#[test]
fn zlib_completion_checksum_and_declared_sizes_are_required() {
    let encoded = zlib(b"new");
    let mut corrupt = encoded.clone(); *corrupt.last_mut().unwrap() ^= 1;
    for bytes in [corrupt, encoded[..encoded.len()-1].to_vec(), [encoded.clone(), vec![0]].concat(),
        [encoded.clone(), encoded].concat()] {
        let patch = [b"GIT binary patch\nliteral 3\n".as_slice(), &encode(&bytes), b"\n"].concat();
        assert!(run(&patch, b"old", b"new", BinaryPatchLimits::default()).is_err());
    }
    for header in ["literal 2", "literal 4", "literal 03", "literal -3", "literal 8388609", "delta 9999999999999999999999999999999999999", "literal 3 trailing"] {
        let patch = [format!("GIT binary patch\n{header}\n").as_bytes(), &encode(&zlib(b"new")), b"\n"].concat();
        assert!(run(&patch, b"old", b"new", BinaryPatchLimits::default()).is_err());
    }
    assert!(run(b"GIT binary patch\nliteral 0\n\n", b"old", b"", BinaryPatchLimits::default()).is_err());
}
#[test]
fn delta_instructions_use_native_size_and_copy_bounds() {
    // base size 3, result size 4: copy abc, append !. Header is PROGRAM size 6.
    let valid = [3, 4, 0x90, 3, 1, b'!'];
    let patch = [b"GIT binary patch\n".as_slice(), &member("delta", &valid), &member("literal", b"abc")].concat();
    assert_eq!(run(&patch, b"abc", b"abc!", BinaryPatchLimits::default()).unwrap(), b"abc!");
    for program in [vec![4,4,0x90,3,1,b'!'], vec![3,4,0x90,4], vec![3,4,0], vec![3,4,5,b'a'], vec![3,4,0x80]] {
        let bad = [b"GIT binary patch\n".as_slice(), &member("delta", &program)].concat();
        assert!(run(&bad, b"abc", b"abc!", BinaryPatchLimits::default()).is_err());
    }
    let oversized = [3, 0xff, 0xff, 0xff, 0x7f];
    let bad = [b"GIT binary patch\n".as_slice(), &member("delta", &oversized)].concat();
    assert!(matches!(run(&bad, b"abc", b"abc!", BinaryPatchLimits::default()), Err(BinaryPatchError::Limit(_))));
}
#[test]
fn limits_charge_both_directions_and_refuse_before_unbounded_output() {
    let patch = literal(b"old", b"new");
    let limits = BinaryPatchLimits { max_expanded_bytes: 9, max_input_bytes: patch.len(), max_file_bytes: 3, max_lines: 7, ..BinaryPatchLimits::default() };
    assert_eq!(run(&patch, b"old", b"new", limits).unwrap(), b"new");
    for narrow in [BinaryPatchLimits { max_expanded_bytes: 8, ..limits },
        BinaryPatchLimits { max_input_bytes: patch.len()-1, ..limits }, BinaryPatchLimits { max_file_bytes: 2, ..limits },
        BinaryPatchLimits { max_lines: 6, ..limits }, BinaryPatchLimits { max_inflate_work: 2, ..limits }] {
        assert!(matches!(run(&patch, b"old", b"new", narrow), Err(BinaryPatchError::Limit(_))));
    }
    assert!(BinaryPatchLimits { max_expanded_bytes: usize::MAX, ..limits }.validate().is_err());
    assert!(BinaryPatchLimits { max_file_bytes: 0, ..limits }.validate().is_err());
}
#[test]
fn cancellation_never_returns_the_provisional_forward_image() {
    let patch = literal(b"old", b"new");
    let old = Some(id(ObjectFormat::Sha1, b"old")); let new = Some(id(ObjectFormat::Sha1, b"new"));
    let mut polls = 0;
    assert!(apply_binary_patch(&patch, old, new, b"old", BinaryPatchLimits::default(), &mut || { polls += 1; true }).is_ok());
    // Every boundary, including after forward validation and in the reverse hunk.
    for stop in 0..polls {
        let mut count = 0;
        let result = apply_binary_patch(&patch, old, new, b"old", BinaryPatchLimits::default(), &mut || {
            let live = count < stop; count += 1; live
        });
        assert_eq!(result, Err(BinaryPatchError::Cancelled), "stop={stop}");
    }
}
