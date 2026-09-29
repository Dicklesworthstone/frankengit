use super::*;
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, internal_object_id};
use fgit_types::{
    CodecVersion, Digest, RepositoryCommitId, RepositoryIncarnationId, SchemaFamily, SchemaId,
};

fn args() -> Vec<String> {
    vec![
        "node".into(),
        "11".repeat(16),
        "22".repeat(16),
        "refs/heads/main".into(),
        "--trusted-local".into(),
        "--name".into(),
        "needle".into(),
    ]
}
fn source(label: &[u8]) -> data::Source {
    let head = RepositoryAuthorityHeadId::from_internal_object_id(internal_object_id(
        IdentityDomain::RepositoryAuthorityHead,
        SchemaId::new(SchemaFamily::from_static("repository-authority-head"), 1, 0),
        CodecVersion::new(1, 0),
        label,
    ))
    .unwrap();
    let rcr = RepositoryCommitId::from_internal_object_id(internal_object_id(
        IdentityDomain::RepositoryCommitRecord,
        SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
        CodecVersion::new(1, 0),
        label,
    ))
    .unwrap();
    let id = rcr.as_internal_object_id();
    let forge = Digest::new(id.algorithm(), *id.digest());
    data::Source {
        tenant: TenantId::from_bytes([0x11; 16]),
        repository: RepositoryId::from_bytes([0x22; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([0x33; 16]),
        format: GitHashAlgorithm::Sha1,
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        head,
        rcr,
        forge,
        commit: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, b"commit"),
        tree: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, b"tree"),
    }
}
fn report() -> data::Report {
    let source = source(b"original");
    let id = source.head.as_internal_object_id();
    let generation =
        GenerationId::from_digest(id.algorithm(), CANONICAL_CODEC_VERSION, *id.digest());
    data::Report {
        source,
        matches: Vec::new(),
        complete: true,
        generation: generation.as_internal_object_id().clone(),
        generation_number: u64::MAX,
        indexed_files: 4,
        indexed_declarations: 17,
        indexed_source_bytes: 1200,
        unsupported_language_files: 2,
        non_regular_entries: 1,
        tables_read: 0,
        payload_bytes_read: 1024,
        work_units: u64::MAX,
    }
}

#[test]
fn minimum_checkpoint_and_index_budget_are_explicit_and_bounded() {
    let report = report();
    let mut args = args();
    args.extend([
        "--minimum-generation".into(),
        token(&report.generation),
        "--minimum-number".into(),
        report.generation_number.to_string(),
        "--max-index-bytes".into(),
        "2048".into(),
    ]);
    let options = parse(&args).unwrap();
    let floor = options.minimum.as_ref().unwrap();
    assert_eq!(floor.authority_generation.get(), u64::MAX);
    assert_eq!(
        token(&floor.generation_id.as_internal_object_id()),
        token(&report.generation)
    );
    assert_eq!(options.maximum_payload_bytes, 2048);
    assert_eq!(options.query.query.name(), b"needle");
    for (flag, value) in [
        ("--max-index-bytes", "0"),
        ("--max-index-bytes", "33554433"),
        ("--minimum-number", "1"),
        ("--minimum-generation", "alg:1:abcd"),
        ("--after", "1"),
        ("--generation", "alg:1:abcd"),
    ] {
        let mut args = self::args();
        args.extend([flag, value].map(str::to_owned));
        assert!(parse(&args).is_err(), "{flag} {value}");
    }
    let mut duplicate = args;
    duplicate.extend(["--max-index-bytes", "10"].map(str::to_owned));
    assert!(parse(&duplicate).is_err());
    let mut untrusted = self::args();
    untrusted.retain(|arg| arg != "--trusted-local");
    assert!(parse(&untrusted).unwrap_err().contains("--trusted-local"));
}

#[test]
fn current_source_does_not_relabel_original_index_provenance_or_u64_values() {
    let options = parse(&args()).unwrap();
    let report = report();
    let current = source(b"metadata advanced");
    let text = render(&options, &current, &report).unwrap();
    let current_at = text.find("\"current_source\":{").unwrap();
    let indexed_at = text.find("\"indexed_source\":{").unwrap();
    assert!(text[current_at..indexed_at].contains(&head_token(current.head)));
    assert!(!text[current_at..indexed_at].contains(&head_token(report.source.head)));
    assert!(text[indexed_at..].contains(&head_token(report.source.head)));
    assert!(text.contains("\"distinct_index_provenance\":true"));
    assert!(text.contains("\"number\":\"18446744073709551615\""));
    assert!(text.contains("\"work_units\":\"18446744073709551615\""));
    assert!(text.contains("\"tables_read\":0"));
    assert!(
        render(&options, &report.source, &report)
            .unwrap()
            .contains("\"distinct_index_provenance\":false")
    );
}

#[test]
fn refusal_shutdown_and_broken_output_cannot_become_an_empty_success() {
    let options = parse(&args()).unwrap();
    for (operation, cleanup) in [
        (Err("Uninitialized".into()), None),
        (Err("Stale".into()), Some("shutdown".into())),
        (Ok((source(b"current"), report())), Some("shutdown".into())),
    ] {
        let mut out = Vec::new();
        assert!(finish(&mut out, &options, operation, cleanup).is_err());
        assert!(out.is_empty());
    }
    for complete in [false, true] {
        let mut report = report();
        report.complete = complete;
        let current = report.source.clone();
        let mut out = Vec::new();
        assert_eq!(
            finish(&mut out, &options, Ok((current, report)), None).unwrap(),
            if complete { 0 } else { 3 }
        );
    }
    struct Failure(bool);
    impl Write for Failure {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0 {
                Ok(bytes.len())
            } else {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    for flush_only in [false, true] {
        assert!(
            finish(
                &mut Failure(flush_only),
                &options,
                Ok((source(b"current"), report())),
                None
            )
            .is_err()
        );
    }
}

#[test]
fn both_symbol_profiles_reach_trust_validation_through_actual_dispatch() {
    for indexed in [false, true] {
        let mut args = args();
        args.retain(|arg| arg != "--trusted-local");
        if indexed {
            args.insert(0, "--indexed-current".into());
        }
        args.insert(0, "--symbols".into());
        assert!(
            crate::source_search::run(&args)
                .unwrap_err()
                .contains("--trusted-local")
        );
    }
}
