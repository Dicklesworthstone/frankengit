#![forbid(unsafe_code)]

//! FG-052 MIDX V1 materialization tests.
//!
//! These fixtures are real idx-v2 byte images parsed through `IdxV2`; they
//! exercise the MIDX materializer over its actual source boundary rather than
//! constructing an internal index record.  The test decodes its emitted chunk
//! table directly because a MIDX is itself the compatibility product under
//! test.  It does not claim pinned-Git differential evidence.

use fgit_crypto::sha1_digest;
use fgit_pack::{
    IdxV2, MidxLimits, MidxRefusal, MidxSource, MidxV1, ObjectFormat, ObjectId, PackError,
    PackLimits,
};
use fgit_types::{
    CodecVersion, DigestAlgorithmId, DigestBytes, GitOidSha1, RepositoryCommitId, RepositoryId,
};

const SHA1_BYTES: usize = 20;
const MIDX_HEADER_BYTES: usize = 12;
const MIDX_TOC_ENTRY_BYTES: usize = 12;

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x51; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(0x8052).expect("fixture algorithm code point is nonzero"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x52; 32]).expect("fixture digest is long enough"),
    )
}

fn oid(first: u8) -> ObjectId {
    ObjectId::from(GitOidSha1::from_bytes([first; SHA1_BYTES]))
}

fn source(commit: ObjectId) -> MidxSource {
    MidxSource::new(repository_id(), rcr_id(), commit)
        .expect("fixture source commit is a nonzero native SHA-1 identity")
}

/// Builds one structurally valid idx v2 record image.  The test only needs the
/// idx materializer boundary, so checksum fields are nonzero deterministic
/// identities; `IdxV2::parse` retains the same structural, not admission,
/// classification which MIDX receipts state explicitly.
fn index(entries: &[(ObjectId, u64)], pack_checksum: ObjectId) -> IdxV2 {
    assert!(
        entries.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "fixture records must satisfy the real idx ordering rule"
    );
    let mut output = Vec::new();
    output.extend_from_slice(&[0xff, b't', b'O', b'c']);
    output.extend_from_slice(&2_u32.to_be_bytes());
    for bucket in 0_u16..=255 {
        let count = entries
            .iter()
            .filter(|(id, _)| u16::from(id.as_bytes()[0]) <= bucket)
            .count();
        output.extend_from_slice(
            &u32::try_from(count)
                .expect("fixture record count fits a v2 fanout entry")
                .to_be_bytes(),
        );
    }
    for (id, _) in entries {
        output.extend_from_slice(id.as_bytes());
    }
    for _ in entries {
        output.extend_from_slice(&0_u32.to_be_bytes());
    }
    let mut large_offsets = Vec::new();
    for (_, offset) in entries {
        if *offset < u64::from(0x8000_0000_u32) {
            output.extend_from_slice(
                &u32::try_from(*offset)
                    .expect("fixture direct offset fits the idx direct form")
                    .to_be_bytes(),
            );
        } else {
            let slot =
                u32::try_from(large_offsets.len()).expect("fixture has few large offset records");
            output.extend_from_slice(&(0x8000_0000_u32 | slot).to_be_bytes());
            large_offsets.push(*offset);
        }
    }
    for offset in large_offsets {
        output.extend_from_slice(&offset.to_be_bytes());
    }
    output.extend_from_slice(pack_checksum.as_bytes());
    output.extend_from_slice(&[0x77; SHA1_BYTES]);
    let mut live = || true;
    IdxV2::parse(
        &output,
        ObjectFormat::Sha1,
        &PackLimits::default(),
        &mut live,
    )
    .expect("fixture is structurally valid idx v2")
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("fixture layout has a complete u32"),
    )
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("fixture layout has a complete u64"),
    )
}

#[test]
fn midx_v1_sorts_packs_deduplicates_oids_and_receipts_exact_bytes() {
    let source_commit = oid(0x01);
    let later_name = index(&[(source_commit, 40), (oid(0x02), 60)], oid(0x20));
    let earlier_name = index(&[(source_commit, 80), (oid(0x03), 100)], oid(0x10));
    let mut first_live = || true;
    let first = MidxV1::write(
        source(source_commit),
        &[later_name.clone(), earlier_name.clone()],
        MidxLimits::default(),
        &mut first_live,
    )
    .expect("the source commit is in the real parsed idx records");
    let mut second_live = || true;
    let second = MidxV1::write(
        source(source_commit),
        &[earlier_name, later_name],
        MidxLimits::default(),
        &mut second_live,
    )
    .expect("input enumeration cannot change a deterministic MIDX");

    assert_eq!(first, second);
    let bytes = first.bytes();
    assert_eq!(&bytes[..4], b"MIDX");
    assert_eq!(bytes[4..8], [1, 1, 4, 0]);
    assert_eq!(read_u32(bytes, 8), 2);
    let first_chunk = MIDX_HEADER_BYTES;
    assert_eq!(&bytes[first_chunk..first_chunk + 4], b"OIDF");
    let oidf_offset = usize::try_from(read_u64(bytes, first_chunk + 4))
        .expect("fixture offset fits the host address space");
    assert_eq!(
        oidf_offset,
        MIDX_HEADER_BYTES + 5 * MIDX_TOC_ENTRY_BYTES,
        "four chunks plus a terminator are fixed before chunk data"
    );
    let oidl_toc = first_chunk + MIDX_TOC_ENTRY_BYTES;
    assert_eq!(&bytes[oidl_toc..oidl_toc + 4], b"OIDL");
    let oidl_offset = usize::try_from(read_u64(bytes, oidl_toc + 4))
        .expect("fixture offset fits the host address space");
    assert_eq!(
        &bytes[oidl_offset..oidl_offset + 3 * SHA1_BYTES],
        [
            source_commit.as_bytes(),
            oid(0x02).as_bytes(),
            oid(0x03).as_bytes()
        ]
        .concat(),
    );
    let ooff_toc = oidl_toc + MIDX_TOC_ENTRY_BYTES;
    assert_eq!(&bytes[ooff_toc..ooff_toc + 4], b"OOFF");
    let ooff_offset = usize::try_from(read_u64(bytes, ooff_toc + 4))
        .expect("fixture offset fits the host address space");
    assert_eq!(read_u32(bytes, ooff_offset), 0);
    assert_eq!(read_u32(bytes, ooff_offset + 4), 80);
    let pnam_toc = ooff_toc + MIDX_TOC_ENTRY_BYTES;
    assert_eq!(&bytes[pnam_toc..pnam_toc + 4], b"PNAM");
    let pnam_offset = usize::try_from(read_u64(bytes, pnam_toc + 4))
        .expect("fixture offset fits the host address space");
    let expected_names = format!("pack-{}.idx\0pack-{}.idx\0", oid(0x10), oid(0x20));
    assert!(bytes[pnam_offset..].starts_with(expected_names.as_bytes()));
    assert_eq!(
        &bytes[bytes.len() - SHA1_BYTES..],
        sha1_digest(&bytes[..bytes.len() - SHA1_BYTES]).as_slice(),
    );
    assert_eq!(first.receipt().source().source_commit_oid(), &source_commit);
    assert_eq!(first.receipt().pack_count(), 2);
    assert_eq!(first.receipt().object_count(), 3);
    assert_eq!(first.receipt().output_bytes(), bytes.len());
    assert_eq!(
        first.receipt().checksum().as_bytes(),
        &bytes[bytes.len() - SHA1_BYTES..],
    );
    let mut source_lookup_live = || true;
    let source_location = first
        .locate(&source_commit, &mut source_lookup_live)
        .expect("the emitted MIDX layout yields its selected source location")
        .expect("source commit occurs in the supplied indexes");
    assert_eq!(source_location.pack_index(), 0);
    assert_eq!(
        source_location.pack_name(),
        format!("pack-{}.idx", oid(0x10)).as_bytes(),
        "lookup uses the writer's lexicographically selected pack"
    );
    assert_eq!(source_location.pack_offset(), 80);
    let mut alternate_lookup_live = || true;
    let alternate_location = first
        .locate(&oid(0x02), &mut alternate_lookup_live)
        .expect("the emitted MIDX layout yields its alternate location")
        .expect("the object occurs in the second supplied index");
    assert_eq!(alternate_location.pack_index(), 1);
    assert_eq!(alternate_location.pack_offset(), 60);
    let mut absent_lookup_live = || true;
    assert_eq!(
        first
            .locate(&oid(0x04), &mut absent_lookup_live)
            .expect("an absent object is an ordinary non-answer"),
        None
    );
    let mut cancelled_lookup = || false;
    assert_eq!(
        first.locate(&source_commit, &mut cancelled_lookup),
        Err(MidxRefusal::Pack(PackError::DeadlineExceeded)),
        "lookup cancellation refuses before any binary-search result is exposed"
    );
}

#[test]
fn midx_v1_emits_large_offsets_and_refuses_missing_source_and_bound_twins() {
    let source_commit = oid(0x08);
    let large = u64::from(0x8000_0000_u32) + 9;
    let one_index = index(&[(source_commit, large)], oid(0x30));
    let mut live = || true;
    let materialized = MidxV1::write(
        source(source_commit),
        std::slice::from_ref(&one_index),
        MidxLimits::default(),
        &mut live,
    )
    .expect("a real idx large-offset record has a MIDX LOFF encoding");
    let bytes = materialized.bytes();
    assert_eq!(bytes[6], 5, "LOFF adds one chunk");
    let toc_start = MIDX_HEADER_BYTES;
    let loff_toc = toc_start + 3 * MIDX_TOC_ENTRY_BYTES;
    assert_eq!(&bytes[loff_toc..loff_toc + 4], b"LOFF");
    let loff_offset = usize::try_from(read_u64(bytes, loff_toc + 4))
        .expect("fixture offset fits the host address space");
    assert_eq!(read_u64(bytes, loff_offset), large);
    let ooff_toc = toc_start + 2 * MIDX_TOC_ENTRY_BYTES;
    let ooff_offset = usize::try_from(read_u64(bytes, ooff_toc + 4))
        .expect("fixture offset fits the host address space");
    assert_eq!(read_u32(bytes, ooff_offset + 4), 0x8000_0000);
    let mut large_lookup_live = || true;
    let large_location = materialized
        .locate(&source_commit, &mut large_lookup_live)
        .expect("LOFF-backed record remains queryable")
        .expect("source occurs in the one supplied index");
    assert_eq!(large_location.pack_index(), 0);
    assert_eq!(large_location.pack_offset(), large);

    let missing_source = oid(0x09);
    let mut missing_live = || true;
    assert_eq!(
        MidxV1::write(
            source(missing_source),
            std::slice::from_ref(&one_index),
            MidxLimits::default(),
            &mut missing_live,
        ),
        Err(MidxRefusal::SourceCommitMissing {
            object: missing_source,
        })
    );

    let mut too_small_live = || true;
    assert_eq!(
        MidxV1::write(
            source(source_commit),
            std::slice::from_ref(&one_index),
            MidxLimits {
                max_output_bytes: materialized.bytes().len() - 1,
                ..MidxLimits::default()
            },
            &mut too_small_live,
        ),
        Err(MidxRefusal::OutputBytesExceeded {
            observed: materialized.bytes().len(),
            limit: materialized.bytes().len() - 1,
        })
    );

    let mut exact_live = || true;
    assert!(
        MidxV1::write(
            source(source_commit),
            std::slice::from_ref(&one_index),
            MidxLimits {
                max_output_bytes: materialized.bytes().len(),
                ..MidxLimits::default()
            },
            &mut exact_live,
        )
        .is_ok(),
        "the one-byte-larger output-bound twin proceeds"
    );
}
