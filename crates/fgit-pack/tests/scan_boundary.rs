#![forbid(unsafe_code)]
//! The incremental scanner finds the exact pack boundary a duplex transport
//! needs, under whole-buffer, chunked, and byte-by-byte delivery, and refuses
//! the same malformed streams the quarantine parser refuses.

mod fixtures;

use fgit_pack::{ObjectFormat, PackBoundaryScanner, PackError, PackLimits, ScanStatus};

const fn scanner() -> PackBoundaryScanner {
    PackBoundaryScanner::new(ObjectFormat::Sha1, fixtures::limits())
}

fn ofs_delta_entry(distance: u8, payload: &[u8]) -> Vec<u8> {
    let mut entry = fgit_pack_entry_header(6, payload.len());
    assert!(distance & 0x80 == 0, "single-byte ofs varint fixture");
    entry.push(distance);
    entry.extend_from_slice(
        &fixtures::entry(1, payload)[fgit_pack_entry_header(1, payload.len()).len()..],
    );
    entry
}

/// Re-derives the fixture's entry-header encoding for one kind/size pair so a
/// delta fixture can splice a base between header and member.
fn fgit_pack_entry_header(kind: u8, declared_size: usize) -> Vec<u8> {
    let plain = fixtures::entry(kind_for_probe(kind), &vec![0_u8; declared_size]);
    let member_len = plain.len() - header_len_of(&plain);
    let mut header = plain;
    header.truncate(header.len() - member_len);
    let mut fixed = header;
    fixed[0] = (fixed[0] & 0x8f) | (kind << 4);
    fixed
}

const fn kind_for_probe(kind: u8) -> u8 {
    // The shared fixture refuses delta kinds; borrow a blob header of the same
    // size shape and rewrite the type nibble.
    if matches!(kind, 1..=4) { kind } else { 3 }
}

const fn header_len_of(entry: &[u8]) -> usize {
    let mut index = 0;
    while entry[index] & 0x80 != 0 {
        index += 1;
    }
    index + 1
}

#[test]
fn one_chunk_with_a_suffix_reports_the_exact_boundary() {
    let pack = fixtures::pack_with_entries(&[
        fixtures::entry(1, b"commit-shaped payload"),
        fixtures::entry(3, b"blob payload"),
    ]);
    let mut stream = pack.clone();
    stream.extend_from_slice(b"0000BYTES-THE-CLIENT-MUST-NOT-SEND");

    let mut scan = scanner();
    let status = scan
        .push(&stream, &mut fixtures::always)
        .expect("a well-formed pack scans");

    assert_eq!(
        status,
        ScanStatus::Finished {
            pack_len: u64::try_from(pack.len()).expect("test pack length fits u64"),
        }
    );
    assert_eq!(scan.excess_bytes(), b"0000BYTES-THE-CLIENT-MUST-NOT-SEND");
}

#[test]
fn byte_by_byte_delivery_finishes_at_the_same_boundary() {
    let pack = fixtures::pack_with_entries(&[
        fixtures::entry(2, b"tree payload"),
        fixtures::entry(4, b"tag payload"),
        fixtures::entry(3, &[0x7f; 512]),
    ]);

    let mut scan = scanner();
    let mut finished = None;
    for (index, byte) in pack.iter().enumerate() {
        match scan
            .push(core::slice::from_ref(byte), &mut fixtures::always)
            .expect("every prefix of a valid pack scans")
        {
            ScanStatus::NeedInput => {}
            ScanStatus::Finished { pack_len } => {
                finished = Some((index + 1, pack_len));
                break;
            }
        }
    }

    let (fed, pack_len) = finished.expect("the trailer byte finishes the scan");
    assert_eq!(fed, pack.len());
    assert_eq!(
        pack_len,
        u64::try_from(pack.len()).expect("length fits u64")
    );
    assert!(scan.excess_bytes().is_empty());
}

#[test]
fn an_empty_pack_is_header_plus_trailer() {
    let pack = fixtures::pack_with_entries(&[]);
    let mut scan = scanner();
    let status = scan
        .push(&pack, &mut fixtures::always)
        .expect("an empty pack scans");
    assert_eq!(
        status,
        ScanStatus::Finished {
            pack_len: u64::try_from(pack.len()).expect("length fits u64"),
        }
    );
}

#[test]
fn an_ofs_delta_base_is_part_of_the_scanned_frame() {
    let first = fixtures::entry(3, b"the delta base object body");
    let first_len = first.len();
    let second = ofs_delta_entry(
        u8::try_from(first_len).expect("fixture base distance fits one varint byte"),
        b"delta program bytes",
    );
    let pack = fixtures::pack_with_entries(&[first, second]);

    let mut scan = scanner();
    let status = scan
        .push(&pack, &mut fixtures::always)
        .expect("a pack with an OFS_DELTA entry scans");
    assert_eq!(
        status,
        ScanStatus::Finished {
            pack_len: u64::try_from(pack.len()).expect("length fits u64"),
        }
    );
}

#[test]
fn a_truncated_stream_keeps_asking_for_input() {
    let pack = fixtures::pack_with_entries(&[fixtures::entry(3, b"payload")]);
    let mut scan = scanner();
    for cut in [4_usize, 11, 13, pack.len() - 1] {
        let mut fresh = scanner();
        assert_eq!(
            fresh
                .push(&pack[..cut], &mut fixtures::always)
                .expect("a truncated prefix is not an error, only incomplete"),
            ScanStatus::NeedInput,
            "cut at {cut} must still be waiting"
        );
    }
    assert_eq!(
        scan.push(&pack, &mut fixtures::always)
            .expect("the complete stream scans"),
        ScanStatus::Finished {
            pack_len: u64::try_from(pack.len()).expect("length fits u64"),
        }
    );
}

#[test]
fn a_lying_declared_size_is_refused_at_the_member_boundary() {
    let honest = fixtures::entry(3, b"honest");
    let mut lying = fgit_pack_entry_header(3, 32);
    let member_start = header_len_of(&honest);
    lying.extend_from_slice(&honest[member_start..]);
    let pack = fixtures::pack_with_entries(&[lying]);

    let mut scan = scanner();
    let refusal = scan
        .push(&pack, &mut fixtures::always)
        .expect_err("a declared size the member does not produce is refused");
    assert!(
        matches!(
            refusal,
            PackError::InflatedEntrySizeMismatch {
                declared: 32,
                actual: 6
            }
        ),
        "expected the exact mismatch, got {refusal:?}"
    );
}

#[test]
fn the_input_ceiling_applies_to_the_stream_not_only_a_slice() {
    let limits = PackLimits {
        max_input_bytes: 24,
        ..fixtures::limits()
    };
    let pack = fixtures::pack_with_entries(&[fixtures::entry(3, b"a payload over the cap")]);
    let mut scan = PackBoundaryScanner::new(ObjectFormat::Sha1, limits);
    let refusal = scan
        .push(&pack, &mut fixtures::always)
        .expect_err("a stream past the input ceiling is refused");
    assert!(matches!(refusal, PackError::InputLimit { .. }));
}
