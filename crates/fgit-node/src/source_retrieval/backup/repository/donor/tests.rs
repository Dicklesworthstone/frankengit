use super::*;

use fgit_authority_fsqlite::{
    ExportBundle, ExportedHead, ExportedIssuance, IssuanceSequence, SCHEMA_VERSION, export_bundle,
    mint_token,
};
use fgit_crypto::{
    DigestHasher, GitObjectKind, Sha256Hasher, git_object_id, git_payload_commitment,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId,
};

use super::super::archive::stream::{StreamDecoder, TransferLimits};

fn flags() -> Flags {
    let mut flags = Flags::default();
    flags.set("--donor-backup", "original.fg").unwrap();
    flags.set("--donor-sha256", &"ab".repeat(32)).unwrap();
    flags.set("--donor-scratch", "new-scratch").unwrap();
    flags.set("--donor-verification-instance", "71").unwrap();
    flags
}

#[test]
fn independent_donor_pin_and_new_verification_custody_are_all_or_none() {
    assert!(Flags::default().finish().unwrap().is_none());
    let options = flags().finish().unwrap().unwrap();
    assert_eq!(options.expected, [0xab; 32]);
    assert_eq!(options.instance.raw(), 71);
    assert_eq!(options.max_ancestry_hops, DEFAULT_MAX_ANCESTRY_HOPS);
    for (flag, value) in [
        ("--donor-backup", "old.fg"),
        ("--donor-sha256", &"aa".repeat(32)),
        ("--donor-scratch", "scratch"),
        ("--donor-verification-instance", "42"),
        ("--donor-max-ancestry-hops", "4"),
    ] {
        let mut partial = Flags::default();
        partial.set(flag, value).unwrap();
        assert!(partial.finish().is_err(), "{flag}");
    }
    for flag in [
        "--donor-backup",
        "--donor-sha256",
        "--donor-scratch",
        "--donor-verification-instance",
    ] {
        assert!(flags().set(flag, "duplicate").is_err());
    }
    for bad in ["", "0", "01", "+1", "-1", "1.0", "18446744073709551616"] {
        for flag in ["--donor-verification-instance", "--donor-max-ancestry-hops"] {
            assert!(Flags::default().set(flag, bad).is_err());
        }
    }
    assert!(
        Flags::default()
            .set("--donor-verification-instance", "9223372036854775808")
            .is_err()
    );
    assert!(
        Flags::default()
            .set("--donor-max-ancestry-hops", "65537")
            .is_err()
    );
    let mut largest = flags();
    largest.set("--donor-max-ancestry-hops", "65536").unwrap();
    assert!(largest.set("--donor-max-ancestry-hops", "65536").is_err());
    assert_eq!(largest.finish().unwrap().unwrap().max_ancestry_hops, 65536);
    for pin in ["AA".repeat(32), "0".repeat(63), "g".repeat(64)] {
        assert!(Flags::default().set("--donor-sha256", &pin).is_err());
    }
}

#[test]
fn complete_export_accepts_donor_flags_without_widening_any_other_limit() {
    let mut args = [
        "export",
        "/not-opened",
        "/not-created.fg",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "--trusted-local",
    ]
    .map(str::to_owned)
    .to_vec();
    let ordinary = super::super::parse(&args).unwrap();
    assert!(ordinary.donor.is_none());
    args.extend(
        [
            "--object-format",
            "sha256",
            "--donor-backup",
            "old.fg",
            "--donor-sha256",
            &"ab".repeat(32),
            "--donor-scratch",
            "new-verify",
            "--donor-verification-instance",
            "71",
            "--donor-max-ancestry-hops",
            "32",
            "--max-archive-bytes",
            "1073741824",
            "--max-blob-bytes",
            "33554432",
            "--max-objects",
            "100000",
            "--timeout-secs",
            "300",
        ]
        .map(str::to_owned),
    );
    assert_eq!(args.len(), 26);
    let options = super::super::parse(&args).unwrap();
    assert_eq!(options.format, GitHashAlgorithm::Sha256);
    assert_eq!(options.profile.transfer, ordinary.profile.transfer);
    assert_eq!(options.profile.timeout, ordinary.profile.timeout);
    assert_eq!(options.donor.unwrap().max_ancestry_hops, 32);
    args.push("--trusted-local".into());
    assert!(super::super::parse(&args).is_err());
}

fn identity(format: GitHashAlgorithm) -> Identity {
    Identity {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format,
    }
}
// Framing oracle only: native preflight never accepts this synthetic head body.
// The native consumer tests below use actual canonical admission and storage.
fn authority(marker: u8) -> Vec<u8> {
    let token = mint_token(StoreInstanceId::from_raw(41), IssuanceSequence::FIRST)
        .to_opaque_bytes()
        .to_vec();
    export_bundle(&ExportBundle {
        schema_version: SCHEMA_VERSION,
        instance: 41,
        bodies: vec![],
        head: Some(ExportedHead {
            key: b"head".to_vec(),
            token: token.clone(),
            generation: 1,
            body: vec![marker],
        }),
        issuance: vec![ExportedIssuance {
            token,
            sequence: 1,
            head_key: b"head".to_vec(),
            generation: 1,
            body: vec![marker],
        }],
    })
    .unwrap()
}
fn proof(body: &[u8]) -> [u8; 32] {
    git_payload_commitment(GitObjectKind::Blob, body, CANONICAL_CODEC_VERSION)
        .digest()
        .as_bytes()
        .try_into()
        .unwrap()
}
fn hash(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(body);
    hash.finish()
}
fn encoded(format: GitHashAlgorithm, metadata: &[u8], bodies: &[&[u8]]) -> Vec<u8> {
    let mut records = bodies
        .iter()
        .map(|body| (git_object_id(format, GitObjectKind::Blob, body), *body))
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.0);
    let mut bytes = Vec::new();
    let mut output = StreamEncoder::new(
        &mut bytes,
        identity(format),
        metadata,
        records.len(),
        Default::default(),
        &mut || Ok(()),
    )
    .unwrap();
    for (oid, body) in records {
        output
            .object(oid, GitObjectKind::Blob, body, &proof(body), &mut || Ok(()))
            .unwrap();
    }
    output.finish(&mut || Ok(())).unwrap();
    bytes
}

#[test]
fn real_codec_composition_is_byte_identical_to_current_complete_export_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let old = b"old original bytes".as_slice();
        let ignored = b"unselected donor bytes".as_slice();
        let new = b"new current bytes".as_slice();
        let donor_bytes = encoded(format, &authority(1), &[old, ignored]);
        let current_metadata = authority(2);
        let expected = encoded(format, &current_metadata, &[old, new]);
        let old_id = git_object_id(format, GitObjectKind::Blob, old);
        let new_id = git_object_id(format, GitObjectKind::Blob, new);
        let selected = BTreeSet::from([old_id, new_id]);
        let mut actual = Vec::new();
        let mut output = StreamEncoder::new(
            &mut actual,
            identity(format),
            &current_metadata,
            selected.len(),
            Default::default(),
            &mut || Ok(()),
        )
        .unwrap();
        let counts = merge::compose(
            &selected,
            merge::Limits {
                format,
                donor_objects: 2,
                max_objects: 3,
                max_donor_payload_bytes: 1 << 20,
            },
            |visit| {
                let mut decoder =
                    StreamDecoder::new(donor_bytes.as_slice(), Default::default(), &mut || Ok(()))?;
                while decoder.visit_record(&mut || Ok(()), |header, input| visit(header, input))? {}
                decoder.finish(hash(&donor_bytes), &mut || Ok(()))?;
                Ok(())
            },
            |source| match source {
                merge::Source::Local(oid) => {
                    assert_eq!(
                        oid, new_id,
                        "donor overlap does not open damaged local bytes"
                    );
                    output.object(oid, GitObjectKind::Blob, new, &proof(new), &mut || Ok(()))
                }
                merge::Source::Donor(header, input) => output.object_stream(
                    header.oid,
                    header.kind,
                    header.length,
                    &header.commitment,
                    input,
                    &mut || Ok(()),
                ),
            },
            || Ok(()),
        )
        .unwrap();
        let seal = output.finish(&mut || Ok(())).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(seal.digest, hash(&expected));
        assert_eq!(counts.donor_objects, 1);
        assert_eq!(counts.local_objects, 1);
        let mut decoder =
            StreamDecoder::new(actual.as_slice(), TransferLimits::default(), &mut || Ok(()))
                .unwrap();
        let mut observed = BTreeSet::new();
        while decoder
            .visit_record(&mut || Ok(()), |header, input| {
                observed.insert(header.oid);
                std::io::copy(input, &mut std::io::sink()).map_err(|error| error.to_string())?;
                Ok(())
            })
            .unwrap()
        {}
        decoder.finish(seal.digest, &mut || Ok(())).unwrap();
        assert_eq!(observed, selected);
    }
}
