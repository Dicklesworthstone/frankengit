use super::*;
use fgit_types::{DigestAlgorithmId, DigestBytes};

fn args(format: GitHashAlgorithm, file: bool) -> Object {
    let head = RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    );
    let mut args = object([
        ("reference", text("refs/heads/main")),
        ("expected_head", text(head_token(head))),
        ("expected_ref_tip", text("a".repeat(format.digest_len() * 2))),
        ("at_commit", text("b".repeat(format.digest_len() * 2))),
    ])
    .object()
    .unwrap()
    .clone();
    if file {
        args.insert("path_hex".into(), text("ff"));
    }
    args
}

#[test]
fn historical_queries_require_all_three_pins_and_keep_current_browse_bounds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for file in [false, true] {
            let valid = args(format, file);
            let query = parse(&valid, file, format).unwrap();
            assert!(query.browse.expected_head.is_some());
            assert_eq!(query.browse.expected_commit, Some(query.at_commit));
            assert_ne!(query.expected_ref_tip, query.at_commit);
            for name in ["reference", "expected_head", "expected_ref_tip", "at_commit"] {
                let mut missing = valid.clone();
                missing.remove(name);
                assert!(parse(&missing, file, format).is_err(), "{name}");
            }
            for (name, value) in [
                ("expected_commit", text("a".repeat(format.digest_len() * 2))),
                ("oid", text("a".repeat(format.digest_len() * 2))),
                ("storage", text("/etc/passwd")),
                ("principal", text("administrator")),
                ("path_hex", text("2e2e2f736563726574")),
                ("reference", text("/etc/passwd")),
                ("expected_ref_tip", text("0".repeat(format.digest_len() * 2))),
                ("at_commit", text("B".repeat(format.digest_len() * 2))),
                ("at_commit", text("latest")),
                ("at_commit", json::number(1)),
                (
                    if file { "max_bytes" } else { "limit" },
                    json::number(if file { 65_537 } else { 101 }),
                ),
            ] {
                let mut bad = valid.clone();
                bad.insert(name.into(), value);
                assert!(parse(&bad, file, format).is_err(), "{name}");
            }
            let other = if format == GitHashAlgorithm::Sha1 {
                GitHashAlgorithm::Sha256
            } else {
                GitHashAlgorithm::Sha1
            };
            assert!(parse(&valid, file, other).is_err());
        }
    }
}
