//! Goldens produced from independently encoded bundles by Git 2.47.3 index-pack.
//! Includes a REF_DELTA before its base. Native tests must reproduce every byte.
use super::*;
fn bytes(hex: &str) -> Vec<u8> {
    hex.trim().as_bytes().chunks_exact(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
}
fn fixture(format: ObjectFormat) -> (Vec<u8>, (&'static str, usize), Vec<(ObjectId, u64)>) {
    match format {
        ObjectFormat::Sha1 => (
            bytes(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex")))[128..].to_vec(),
            ("7e81389280215f9a9139920f12a94d807d55cb83accd723799bc70919b010ec7", 1212),
            vec![
                (ObjectId::from_hex(format, "ec20141f0267805d3db1349c4701ed1f84f3ee61").unwrap(), 12),
                (ObjectId::from_hex(format, "4a58007052a65fbc2fc3f910f2855f45a4058e74").unwrap(), 58),
                (ObjectId::from_hex(format, "af05a70f13bc2fba5597c7aa79022b367d4ef140").unwrap(), 76),
                (ObjectId::from_hex(format, "8e66527465821b289d8ad275784255bc8825617a").unwrap(), 122),
                (ObjectId::from_hex(format, "fdf36c252d4e297cc62a161ba48176f6dcafa08a").unwrap(), 293),
            ],
        ),
        ObjectFormat::Sha256 => (
            bytes(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex")))[198..].to_vec(),
            ("ad9f3bf1c1c2dc4d5483a02bda8dbae512d5e369ba4fc481d4a45d8f5afc2579", 1296),
            vec![
                (ObjectId::from_hex(format, "7f159d843933f44185df4dcaab90c6eda9595d849d31ac3122fa3857fab799c6").unwrap(), 12),
                (ObjectId::from_hex(format, "9f8bf964b2f278e643f6ee93dd5980698a5f515048b2a27134a294e5e3376180").unwrap(), 70),
                (ObjectId::from_hex(format, "4672839c4a5ff4dc4778627c88122511b4d8da2f781beb99202c9e6dd2978321").unwrap(), 88),
                (ObjectId::from_hex(format, "c2a1cfc79b851e01921198e44377712b8ce0593cafe564873b9de729af20ec78").unwrap(), 146),
                (ObjectId::from_hex(format, "91cf791e6e424d4f8449c7f57012ce46de9c7053ed326b0c34744d522c9da04d").unwrap(), 341),
            ],
        ),
    }
}
#[test]
fn matches_git_index_pack_bytes_for_both_native_domains_and_forward_deltas() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (pack, golden, rows) = fixture(format);
        let limits = PackLimits::default();
        let encoded = build_pack_index_v2(&pack, format, &rows, &limits, &mut || true).unwrap();
        assert_eq!(fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&encoded)), golden.0);
        assert_eq!(encoded.len(), golden.1);
        let index = IdxV2::parse(&encoded, format, &limits, &mut || true).unwrap();
        for entry in index.entries() {
            let offset = usize::try_from(entry.pack_offset).unwrap();
            let end = rows.iter().map(|row| row.1).filter(|next| *next > entry.pack_offset).min()
                .map_or(pack.len() - format.digest_len(), |next| usize::try_from(next).unwrap());
            crate::validate_idx_entry_crc(entry, &pack[offset..end], &limits, &mut || true).unwrap();
        }
        let mut reversed = rows;
        reversed.reverse();
        assert_eq!(build_pack_index_v2(&pack, format, &reversed, &limits, &mut || true).unwrap(), encoded);
    }
}
#[test]
fn refuses_ambiguous_or_foreign_location_tables() {
    let format = ObjectFormat::Sha1;
    let (pack, _, rows) = fixture(format);
    let limits = PackLimits::default();
    for mutation in 0..6 {
        let mut bad = rows.clone();
        match mutation {
            0 => bad[1].1 = bad[0].1,
            1 => bad[1].0 = bad[0].0,
            2 => bad[0].1 = 13,
            3 => bad[4].1 = u64::MAX,
            4 => { bad.pop(); }
            _ => bad[1].0 = fixture(ObjectFormat::Sha256).2[1].0,
        }
        assert!(build_pack_index_v2(&pack, format, &bad, &limits, &mut || true).is_err(), "mutation {mutation}");
    }
}
#[test]
fn refuses_bad_trailers_and_enforces_index_output_and_count_limits() {
    let (mut pack, golden, rows) = fixture(ObjectFormat::Sha256);
    let mut limits = PackLimits::default();
    limits.max_index_entries = rows.len() - 1;
    assert!(build_pack_index_v2(&pack, ObjectFormat::Sha256, &rows, &limits, &mut || true).is_err());
    limits.max_index_entries = rows.len();
    limits.max_input_bytes = golden.1 - 1;
    assert!(pack.len() < limits.max_input_bytes);
    assert!(build_pack_index_v2(&pack, ObjectFormat::Sha256, &rows, &limits, &mut || true).is_err());
    limits.max_input_bytes = golden.1;
    assert!(build_pack_index_v2(&pack, ObjectFormat::Sha256, &rows, &limits, &mut || true).is_ok());
    *pack.last_mut().unwrap() ^= 1;
    assert!(matches!(build_pack_index_v2(&pack, ObjectFormat::Sha256, &rows, &limits, &mut || true), Err(PackError::TrailerChecksumMismatch)));
}
#[test]
fn every_cooperative_stop_prevents_a_completed_index() {
    let (pack, _, rows) = fixture(ObjectFormat::Sha1);
    let mut count = 0;
    build_pack_index_v2(&pack, ObjectFormat::Sha1, &rows, &PackLimits::default(), &mut || { count += 1; true }).unwrap();
    for stop in 1..=count {
        let mut calls = 0;
        assert!(build_pack_index_v2(&pack, ObjectFormat::Sha1, &rows, &PackLimits::default(), &mut || { calls += 1; calls != stop }).is_err());
    }
}
