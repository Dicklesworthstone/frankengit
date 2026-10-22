//! Independently supplied complete-result intent. This is not authorization.
use fgit_types::{GitHashAlgorithm, GitOid};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExpectedTree(GitOid);
impl ExpectedTree {
    pub(super) fn parse(text: &str, format: GitHashAlgorithm) -> Result<Self, String> {
        if text.len() != format.digest_len() * 2
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(
                "expected-result-tree requires a full lowercase native ID in the base hash domain"
                    .into(),
            );
        }
        let id = GitOid::from_hex(format, text).map_err(|_| "invalid expected-result-tree")?;
        if id.is_zero() {
            return Err("expected-result-tree cannot be zero".into());
        }
        Ok(Self(id))
    }

    /// Called before bundle publication, after normal node verification/shutdown.
    /// A mismatch never produces a successful receipt or an output artifact.
    pub(super) fn receipt_field(self, actual: GitOid) -> Result<String, String> {
        if self.0 != actual {
            return Err(
                "prepared root tree differs from expected-result-tree; no bundle was published"
                    .into(),
            );
        }
        Ok(format!(",\"expected_result_tree\":\"{}\"", self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::super::options::{self, Operation};
    use super::*;
    fn args(width: usize, profile: &str) -> Vec<String> {
        [
            "prepare",
            "node",
            &"11".repeat(16),
            &"22".repeat(16),
            "refs/heads/main",
            "patch",
            "bundle",
            "--trusted-local",
            "--profile",
            profile,
            "--workspace-id",
            &"33".repeat(16),
            "--expected-base",
            &"a".repeat(width),
            "--author",
            "A <a@example.invalid>",
            "--timestamp",
            "2",
            "--message",
            "intent",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn pin_is_optional_and_independent_of_the_selected_patch_profile() {
        for (width, format) in [(40, GitHashAlgorithm::Sha1), (64, GitHashAlgorithm::Sha256)] {
            for profile in ["exact-v1", "exact-binary-v1", "exact-tree-v1"] {
                let mut args = args(width, profile);
                assert!(matches!(
                    options::parse(&args).unwrap().operation,
                    Operation::Prepare {
                        expected_result_tree: None,
                        ..
                    }
                ));
                args.extend(["--expected-result-tree".into(), "b".repeat(width)]);
                let Operation::Prepare {
                    expected_result_tree: Some(pin),
                    ..
                } = options::parse(&args).unwrap().operation
                else {
                    panic!("missing pin");
                };
                assert_eq!(
                    pin,
                    ExpectedTree::parse(&"b".repeat(width), format).unwrap()
                );
            }
        }
    }
    #[test]
    fn malformed_cross_domain_missing_and_duplicate_pins_refuse() {
        for width in [40, 64] {
            for value in [
                "".to_owned(),
                "0".repeat(width),
                "A".repeat(width),
                "g".repeat(width),
                "a".repeat(width - 1),
                "a".repeat(if width == 40 { 64 } else { 40 }),
            ] {
                let mut args = args(width, "exact-tree-v1");
                args.extend(["--expected-result-tree".into(), value]);
                assert!(options::parse(&args).is_err());
            }
            let mut missing = args(width, "exact-v1");
            missing.push("--expected-result-tree".into());
            assert!(options::parse(&missing).is_err());
            missing.extend([
                "b".repeat(width),
                "--expected-result-tree".into(),
                "b".repeat(width),
            ]);
            assert!(options::parse(&missing).is_err());
        }
    }
    #[test]
    fn mismatches_including_another_hash_domain_cannot_produce_a_receipt() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let width = format.digest_len() * 2;
            let pin = ExpectedTree::parse(&"a".repeat(width), format).unwrap();
            assert_eq!(
                pin.receipt_field(GitOid::from_hex(format, &"a".repeat(width)).unwrap())
                    .unwrap(),
                format!(",\"expected_result_tree\":\"{}\"", "a".repeat(width))
            );
            assert!(
                pin.receipt_field(GitOid::from_hex(format, &"b".repeat(width)).unwrap())
                    .is_err()
            );
            let other = if format == GitHashAlgorithm::Sha1 {
                GitHashAlgorithm::Sha256
            } else {
                GitHashAlgorithm::Sha1
            };
            assert!(
                pin.receipt_field(
                    GitOid::from_hex(other, &"a".repeat(other.digest_len() * 2)).unwrap()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn apply_cannot_replace_reviewed_commit_identity_with_a_tree_pin() {
        let args = [
            "apply",
            "node",
            &"11".repeat(16),
            &"22".repeat(16),
            "refs/heads/main",
            "bundle",
            "--trusted-local",
            "--principal",
            &"33".repeat(16),
            "--idempotency-key",
            "key",
            "--expected-base",
            &"a".repeat(40),
            "--expected-commit",
            &"b".repeat(40),
            "--expected-result-tree",
            &"c".repeat(40),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        assert!(options::parse(&args).is_err());
    }
}
