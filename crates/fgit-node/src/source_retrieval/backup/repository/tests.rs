use super::*;
use fgit_authority::{AuthorityVersionToken, HeadKey};
use fgit_authority_fsqlite::{ExportedHead, ExportedIssuance, SCHEMA_VERSION};

fn args(extra: &[&str]) -> Vec<String> {
    [
        "export",
        "/unused",
        "/unused.backup",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "--trusted-local",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect()
}
#[test]
fn export_requires_explicit_authorization_and_unambiguous_bounded_options() {
    assert_eq!(parse(&args(&[])).unwrap().format, GitHashAlgorithm::Sha1);
    assert_eq!(
        parse(&args(&["--object-format", "sha256"])).unwrap().format,
        GitHashAlgorithm::Sha256
    );
    let mut untrusted = args(&[]);
    untrusted.pop();
    assert!(parse(&untrusted).is_err());
    for extra in [
        vec!["--trusted-local"],
        vec!["--object-format"],
        vec!["--object-format", "md5"],
        vec!["--unknown", "x"],
        vec!["--object-format", "sha1", "--object-format", "sha256"],
    ] {
        assert!(parse(&args(&extra)).is_err());
    }
    let mut invalid = args(&[]);
    invalid[1] = "x".repeat(8193);
    assert!(parse(&invalid).is_err());
    assert!(parse(&[]).is_err());
}
#[test]
fn snapshot_join_checks_key_token_generation_and_exact_bytes_separately() {
    let token = AuthorityVersionToken::from_opaque_bytes([7; 16]);
    let receipt = HeadReadReceipt::new(
        HeadKey::new(b"key".to_vec()).unwrap(),
        token,
        HeadGeneration::FIRST,
        b"original".to_vec(),
    );
    let head = ExportedHead {
        key: b"key".to_vec(),
        token: token.to_opaque_bytes().to_vec(),
        generation: 1,
        body: b"original".to_vec(),
    };
    let bundle = ExportBundle {
        schema_version: SCHEMA_VERSION,
        instance: 1,
        bodies: vec![],
        head: Some(head.clone()),
        issuance: vec![ExportedIssuance {
            token: head.token.clone(),
            sequence: 1,
            head_key: head.key.clone(),
            generation: 1,
            body: head.body,
        }],
    };
    assert!(matches_head(&bundle, &receipt));
    for field in 0..4 {
        let mut changed = bundle.clone();
        let head = changed.head.as_mut().unwrap();
        match field {
            0 => head.key.push(0),
            1 => head.token[0] ^= 1,
            2 => head.generation += 1,
            _ => head.body.push(0),
        }
        assert!(!matches_head(&changed, &receipt), "field {field}");
    }
    let mut missing = bundle;
    missing.head = None;
    assert!(!matches_head(&missing, &receipt));
}
#[test]
fn export_profile_controls_total_bytes_without_widening_per_object_or_graph_limits() {
    let options = parse(&args(&[
        "--object-format",
        "sha256",
        "--max-archive-bytes",
        "2147483648",
        "--timeout-secs",
        "900",
    ]))
    .unwrap();
    assert_eq!(options.profile.transfer.max_archive_bytes, 2 << 30);
    assert_eq!(options.profile.timeout.as_secs(), 900);
    let graph = limits(options.profile.transfer);
    assert_eq!(graph.max_payload_bytes, 2 << 30);
    assert_eq!(graph.max_object_bytes, 32 * 1024 * 1024);
    assert_eq!(graph.max_objects, 100_000);
    assert_eq!(graph.max_edges, 1_000_000);
    assert!(
        parse(&args(&[
            "--max-archive-bytes",
            "1",
            "--max-archive-bytes",
            "2"
        ]))
        .is_err()
    );
}
