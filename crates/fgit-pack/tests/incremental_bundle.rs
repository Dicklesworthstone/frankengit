#![forbid(unsafe_code)]
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits, MAX_BUNDLE_PREREQUISITES};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::fmt::Write as _;
fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}
fn prefix(format: GitHashAlgorithm) -> String {
    match format {
        GitHashAlgorithm::Sha1 => "# v2 git bundle\n".into(),
        GitHashAlgorithm::Sha256 => "# v3 git bundle\n@object-format=sha256\n".into(),
    }
}
fn parse(input: &[u8]) -> Result<FullBundleInput<'_>, fgit_pack::full_bundle::FullBundleError> {
    FullBundleInput::parse_incremental(input, FullBundleLimits::default(), &mut || true)
}
#[test]
fn prerequisite_comments_are_data_and_the_full_profile_still_refuses_them() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (a, b) = (oid(format, 1), oid(format, 2));
        let data = format!(
            "{}-{} arbitrary comment: not a ref or capability\n{b} refs/heads/main\n\nPACK",
            prefix(format),
            a.to_string().to_uppercase()
        );
        let result = parse(data.as_bytes()).unwrap();
        assert_eq!(result.format(), format);
        assert_eq!(result.prerequisites(), &[a]);
        assert_eq!(*result.references()[0].target(), b);
        assert_eq!(result.pack_bytes(), b"PACK");
        assert!(
            FullBundleInput::parse(data.as_bytes(), FullBundleLimits::default(), &mut || true)
                .is_err()
        );
    }
}
#[test]
fn malformed_incremental_headers_refuse_without_format_or_order_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (a, b) = (oid(format, 1), oid(format, 2));
        for middle in [
            format!("-{a}\n{b} refs/heads/main"),
            format!("-{a} one\n-{a} two\n{b} refs/heads/main"),
            format!("{b} refs/heads/main\n-{a} late"),
            format!(
                "-{a} first\n@object-format={}\n{b} refs/heads/main",
                format.as_str()
            ),
            format!(
                "-{} zero\n{b} refs/heads/main",
                "0".repeat(format.digest_len() * 2)
            ),
            format!("-bad bad\n{b} refs/heads/main"),
            format!("-{a} required\n{b} refs/heads/main\n{b} refs/heads/main"),
        ] {
            assert!(
                parse(format!("{}{middle}\n\nPACK", prefix(format)).as_bytes()).is_err(),
                "{middle}"
            );
        }
    }
}
#[test]
fn prerequisite_header_count_and_byte_limits_are_inclusive_and_cancellable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut text = prefix(format);
        for byte in 1..=MAX_BUNDLE_PREREQUISITES {
            let _ = writeln!(text, "-{} required", oid(format, byte as u8));
        }
        let ref_line = format!("{} refs/heads/main\n\n", oid(format, 100));
        let data = format!("{text}{ref_line}PACK");
        assert_eq!(
            parse(data.as_bytes()).unwrap().prerequisites().len(),
            MAX_BUNDLE_PREREQUISITES
        );
        let _ = writeln!(text, "-{} excess", oid(format, 101));
        assert!(parse(format!("{text}{ref_line}PACK").as_bytes()).is_err());
        let header = data.len() - 4;
        let limits = FullBundleLimits {
            max_header_bytes: header,
            max_bundle_bytes: data.len(),
            ..Default::default()
        };
        assert!(FullBundleInput::parse_incremental(data.as_bytes(), limits, &mut || true).is_ok());
        assert!(
            FullBundleInput::parse_incremental(
                data.as_bytes(),
                FullBundleLimits {
                    max_header_bytes: header - 1,
                    ..limits
                },
                &mut || true
            )
            .is_err()
        );
        assert!(
            FullBundleInput::parse_incremental(
                data.as_bytes(),
                FullBundleLimits {
                    max_bundle_bytes: data.len() - 1,
                    ..limits
                },
                &mut || true
            )
            .is_err()
        );
        assert!(
            FullBundleInput::parse_incremental(data.as_bytes(), limits, &mut || false).is_err()
        );
    }
}
