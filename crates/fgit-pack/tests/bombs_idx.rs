#![forbid(unsafe_code)]

mod fixtures;

use fgit_pack::{
    IdxV2, ObjectFormat, PackError, parse_quarantined_pack, validate_idx_entry_crc,
    validate_idx_pack_count,
};

fn idx_with_entries(entries: &[(u8, u32, u32)]) -> Vec<u8> {
    let mut output = vec![0xff, b't', b'O', b'c'];
    output.extend_from_slice(&2_u32.to_be_bytes());
    for bucket in 0_u16..=255 {
        let count = entries
            .iter()
            .filter(|(first, _, _)| u16::from(*first) <= bucket)
            .count();
        output.extend_from_slice(
            &u32::try_from(count)
                .expect("fixture count fits u32")
                .to_be_bytes(),
        );
    }
    for (first, _, _) in entries {
        output.push(*first);
        output.extend_from_slice(&[0; 19]);
    }
    for (_, crc, _) in entries {
        output.extend_from_slice(&crc.to_be_bytes());
    }
    for (_, _, offset) in entries {
        output.extend_from_slice(&offset.to_be_bytes());
    }
    output.extend_from_slice(&fixtures::SHA1_TRAILER);
    output.extend_from_slice(&[0xbb; 20]);
    output
}

#[test]
fn idx_crc_and_pack_count_mismatches_refuse_index_association() {
    let raw_entry = fixtures::entry(3, b"crc");
    let pack = fixtures::pack_with_entries(std::slice::from_ref(&raw_entry));
    let parsed = parse_quarantined_pack(
        &pack,
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
    )
    .expect("one-entry pack remains quarantined until its index associates it");

    let zero_crc_index = IdxV2::parse(
        &idx_with_entries(&[(1, 0, 12)]),
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
    )
    .expect("well-formed idx with a deliberately wrong CRC");
    let crc = match validate_idx_entry_crc(
        &zero_crc_index.entries()[0],
        &raw_entry,
        &fixtures::limits(),
        &mut fixtures::always,
    ) {
        Err(PackError::IndexEntryCrcMismatch {
            expected: 0,
            actual,
        }) => actual,
        other => panic!("zero CRC must refuse exact pack entry, got {other:?}"),
    };
    let index = IdxV2::parse(
        &idx_with_entries(&[(1, crc, 12)]),
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
    )
    .expect("well-formed one-entry idx");
    assert_eq!(validate_idx_pack_count(&index, parsed.header), Ok(()));
    assert_eq!(
        validate_idx_entry_crc(
            &index.entries()[0],
            &raw_entry,
            &fixtures::limits(),
            &mut fixtures::always,
        ),
        Ok(())
    );

    let mut corrupt_entry = raw_entry.clone();
    corrupt_entry[0] ^= 1;
    assert!(matches!(
        validate_idx_entry_crc(
            &index.entries()[0],
            &corrupt_entry,
            &fixtures::limits(),
            &mut fixtures::always,
        ),
        Err(PackError::IndexEntryCrcMismatch { expected, .. }) if expected == crc
    ));

    let two_entry_index = IdxV2::parse(
        &idx_with_entries(&[(1, crc, 12), (2, crc, 24)]),
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
    )
    .expect("independently well-formed two-entry idx");
    assert_eq!(
        validate_idx_pack_count(&two_entry_index, parsed.header),
        Err(PackError::ObjectCountMismatch {
            declared: 1,
            actual: 2,
        })
    );
}
