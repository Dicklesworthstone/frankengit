//! Canonical source-coverage semantics, independently of match pagination.
use super::*;

fn omitted(format: Format, path: &[u8]) -> Omission {
    let bytes = b"fn Discarded() {} fn Broken() {\n";
    let error = table::Table::build(
        bytes,
        &mut engine::Budget::new(engine::MAX_WORK).unwrap(),
        &|| false,
    )
    .unwrap_err();
    Omission::from_table_error(
        path,
        git_object_id(format, GitObjectKind::Blob, bytes),
        bytes.len(),
        &error,
    )
    .unwrap()
}

fn manifest(format: Format) -> (Manifest, Payload) {
    let (doc, table) = document(format, b"a.rs", b"fn A() {} fn A() {}\n");
    (
        Manifest {
            source: source(format),
            documents: vec![doc],
            unsupported: 1,
            non_regular: 0,
            omissions: vec![omitted(format, b"broken/\xff.rs")],
        },
        table,
    )
}

#[test]
fn omission_roots_roundtrip_and_are_distinct_from_complete_v1_in_both_formats() {
    for format in [Format::Sha1, Format::Sha256] {
        let (mut manifest, _) = manifest(format);
        let partial = manifest.encode(&|| false).unwrap();
        assert!(decode_body::<ManifestFrame>(&partial.bytes, decode_limits()).is_err());
        let decoded = Manifest::decode(&partial.bytes, partial.root, &|| false).unwrap();
        assert_eq!(decoded.omissions(), manifest.omissions());
        assert_eq!(decoded.documents(), manifest.documents());
        assert_eq!(decoded.source(), manifest.source());
        assert_eq!(decoded.encode(&|| false).unwrap().bytes, partial.bytes);
        let mut changed = manifest.clone();
        changed.omissions[0].byte_offset = Some(0);
        assert_ne!(changed.encode(&|| false).unwrap().root, partial.root);
        assert!(Manifest::decode(&partial.bytes, partial.root, &|| true).is_err());
        assert!(
            Manifest::decode(
                &partial.bytes[..partial.bytes.len() - 1],
                partial.root,
                &|| false
            )
            .is_err()
        );
        manifest.omissions.clear();
        let complete = manifest.encode(&|| false).unwrap();
        assert!(decode_body::<ManifestFrame>(&complete.bytes, decode_limits()).is_ok());
        assert!(decode_body::<OmissionManifestFrame>(&complete.bytes, decode_limits()).is_err());
        assert_ne!(complete.root, partial.root);
        assert!(Manifest::decode(&partial.bytes, complete.root, &|| false).is_err());
    }
}

#[test]
fn coverage_is_incomplete_for_empty_exact_full_and_truncated_match_pages() {
    let (manifest, payload) = manifest(Format::Sha256);
    for (name, limit, matches, complete) in [
        (b"Missing".as_slice(), 2, 0, true),
        (b"A".as_slice(), 2, 2, true),
        (b"A".as_slice(), 1, 1, false),
    ] {
        let query =
            SymbolQuery::new(name, SymbolMatchMode::Exact, &[], &[], engine::MAX_WORK).unwrap();
        let mut search = Query::new(&query, limit).unwrap();
        search
            .observe(&manifest.documents[0], &payload.bytes, &|| false)
            .unwrap();
        let report = search.finish(
            &manifest,
            *manifest.source.head.as_internal_object_id(),
            1,
            payload.bytes.len(),
        );
        assert_eq!(report.matches.len(), matches);
        assert_eq!(report.complete, complete);
        assert!(!report.coverage_complete);
        assert_eq!(report.omissions, manifest.omissions);
        assert_eq!(
            report.validate_coverage().unwrap(),
            manifest.omissions[0].source_bytes
        );
        let mut false_complete = report.clone();
        false_complete.coverage_complete = true;
        assert!(false_complete.validate_coverage().is_err());
        if !report.matches.is_empty() {
            let mut fabricated_hit = report.clone();
            fabricated_hit.matches[0].location.path = manifest.omissions[0].path.clone();
            assert!(fabricated_hit.validate_coverage().is_err());
        }
    }
}

#[test]
fn omissions_require_disjoint_ordered_native_sources_and_closed_diagnostics() {
    let (manifest, _) = manifest(Format::Sha1);
    let mut candidates = Vec::new();
    let mut duplicate = manifest.clone();
    duplicate.omissions.push(duplicate.omissions[0].clone());
    candidates.push(duplicate);
    let mut reversed = manifest.clone();
    reversed.omissions.push(omitted(Format::Sha1, b"b.rs"));
    candidates.push(reversed);
    let mut overlap = manifest.clone();
    overlap.omissions[0].path = overlap.documents[0].path.clone();
    candidates.push(overlap);
    let mut foreign = manifest.clone();
    foreign.omissions[0].blob = git_object_id(Format::Sha256, GitObjectKind::Blob, b"foreign");
    candidates.push(foreign);
    for path in [b"../bad.rs".as_slice(), b".git/a.rs", b"a.txt"] {
        let mut invalid = manifest.clone();
        invalid.omissions[0].path = path.to_vec();
        candidates.push(invalid);
    }
    let mut offset = manifest.clone();
    offset.omissions[0].byte_offset = Some(offset.omissions[0].source_bytes + 1);
    candidates.push(offset);
    let mut limit = manifest.clone();
    limit.omissions[0].limit = Some(100);
    candidates.push(limit);
    let mut exhausted = manifest.clone();
    exhausted.unsupported = 20_000;
    candidates.push(exhausted);
    let mut exhausted = manifest.clone();
    exhausted.omissions[0] = Omission {
        source_bytes: 64 * 1024 * 1024,
        reason: OmissionReason::FileBytes,
        byte_offset: None,
        limit: Some(engine::MAX_FILE_BYTES),
        ..exhausted.omissions[0].clone()
    };
    candidates.push(exhausted);
    for candidate in candidates {
        assert!(
            candidate.encode(&|| false).is_err(),
            "invalid omission: {candidate:?}"
        );
    }
    let mut bounded = manifest.clone();
    bounded.omissions[0].reason = OmissionReason::FileBytes;
    bounded.omissions[0].byte_offset = None;
    bounded.omissions[0].limit = Some(1);
    assert!(bounded.encode(&|| false).is_ok());
    bounded.omissions[0].limit = Some(bounded.omissions[0].source_bytes);
    assert!(bounded.encode(&|| false).is_err());
}

#[test]
fn authenticated_unknown_omission_tags_still_refuse_and_global_errors_never_skip() {
    let format = Format::Sha1;
    let entry = omitted(format, b"broken.rs");
    let mut out = Encoder::new();
    entry.write(&mut out).unwrap();
    let mut bytes = out.into_bytes();
    // This row has an offset and no limit: the reason is eleven bytes from the
    // end (reason, offset tag, u64 offset, absent limit tag = eleven bytes).
    let reason = bytes.len() - 11;
    bytes[reason] = 0xff;
    assert!(matches!(
        Omission::read(&mut Decoder::new(&bytes, decode_limits()), format),
        Err(Error::Invalid("omission reason"))
    ));
    for kind in [
        engine::ErrorKind::Cancelled,
        engine::ErrorKind::WorkLimit,
        engine::ErrorKind::FileLimit,
        engine::ErrorKind::DeclarationLimit,
    ] {
        let error = table::Error::Syntax(engine::Error {
            kind,
            byte_offset: 0,
        });
        assert!(Omission::from_table_error(b"broken.rs", entry.blob, 32, &error).is_none());
    }
    for error in [
        table::Error::Cancelled,
        table::Error::Invalid("source"),
        table::Error::Limit("work"),
    ] {
        assert!(Omission::from_table_error(b"broken.rs", entry.blob, 32, &error).is_none());
    }
    let table_limit = Omission::from_table_error(
        b"broken.rs",
        entry.blob,
        32,
        &table::Error::Limit("table bytes"),
    )
    .unwrap();
    assert_eq!(table_limit.reason, OmissionReason::TableBytes);
    assert!(table_limit.validate(format).is_ok());
}
