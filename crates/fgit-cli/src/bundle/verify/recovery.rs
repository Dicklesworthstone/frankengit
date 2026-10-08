//! Opt-in native layout output: fixed metadata fields, never caller paths.
use std::fmt::Write as _;
use fgit_node::source_retrieval::integrity::bundle_verify::prepare_git_bundle_recovery;
use super::{BundleExpectations, BundleVerifyLimits, RefName, anchors, checkpoint, report};

const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn execute(
    bytes: &[u8],
    limits: &BundleVerifyLimits,
    expected: Option<&BundleExpectations>,
    head: &RefName,
    live: &mut impl FnMut() -> bool,
) -> Result<String, String> {
    let plan = prepare_git_bundle_recovery(bytes, limits, expected, head, live)
        .map_err(|error| error.to_string())?;
    checkpoint(live)?;
    let mut output = match expected {
        Some(expected) => anchors::report_matched(plan.verified(), expected)?,
        None => report(plan.verified())?,
    };
    let fields = [
        ("head_ref_hex", plan.head_ref().as_bytes()),
        ("index_hex", plan.index()),
        ("packed_refs_hex", plan.packed_refs()),
        ("config_hex", plan.config()),
        ("head_hex", plan.head()),
    ];
    let total = fields.iter().try_fold(output.len().checked_add(256).ok_or("recovery report overflow")?, |n, (_, bytes)| {
        n.checked_add(bytes.len().checked_mul(2)?).and_then(|n| n.checked_add(32))
    }).ok_or("recovery report overflow")?;
    if total > MAX_REPORT_BYTES { return Err("recovery report exceeds 16 MiB".into()); }
    output.try_reserve(total - output.len()).map_err(|_| "recovery report allocation refused")?;
    if output.pop() != Some('}') { return Err("invalid verification report".into()); }
    write!(output, ",\"recovery\":{{\"profile\":\"native-bare-source-layout-v1\",\"pack_offset\":{}", plan.pack_offset())
        .map_err(|error| error.to_string())?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (name, bytes) in fields {
        write!(output, ",\"{name}\":\"").map_err(|error| error.to_string())?;
        for chunk in bytes.chunks(4096) {
            checkpoint(live)?;
            for &byte in chunk {
                output.push(char::from(HEX[usize::from(byte >> 4)]));
                output.push(char::from(HEX[usize::from(byte & 15)]));
            }
        }
        output.push('"');
    }
    output.push_str("}}");
    checkpoint(live)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_head_is_explicit_valid_and_independent_of_the_native_hash_domain() {
        let args = |values: &[&str]| values.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let head = "726566732f68656164732f6d61696e";
        let parsed = super::super::parse(&args(&["missing.bundle", "--recovery-head-hex", head])).unwrap();
        assert_eq!(parsed.recovery_head.unwrap().as_bytes(), b"refs/heads/main");
        assert!(parsed.expectations.is_none());
        assert!(super::super::parse(&args(&["file.bundle"])).unwrap().recovery_head.is_none());
        for raw in ["", "7", "zz", "48454144", "726566732f746167732f7631", "726566732f68656164732f2e2e"] {
            assert!(super::super::parse(&args(&["missing.bundle", "--recovery-head-hex", raw])).is_err());
        }
        assert!(super::super::parse(&args(&["missing.bundle", "--recovery-head-hex", head, "--recovery-head-hex", head])).is_err());
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;
    #[test]
    fn opt_in_output_contains_native_layout_and_exact_matched_expectations() {
        let hex = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"));
        let bytes = anchors::unhex(hex.trim(), 4096).unwrap();
        let expected = BundleExpectations::new(Some(fgit_crypto::sha256_digest(&bytes)), None, &[], false).unwrap();
        let head = RefName::try_new(b"refs/heads/main").unwrap();
        let output = execute(&bytes, &BundleVerifyLimits::default(), Some(&expected), &head, &mut || true).unwrap();
        assert!(output.contains("\"caller_expectations_matched\":true"));
        assert!(output.contains("\"profile\":\"native-bare-source-layout-v1\""));
        assert!(output.contains("\"pack_offset\":128"));
        assert!(output.contains("\"repository_changed\":false"));
        let index = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/native_bundle_recovery/sha1.idx.hex"));
        assert!(output.contains(&format!("\"index_hex\":\"{}\"", index.trim())));
        assert!(execute(&bytes, &BundleVerifyLimits::default(), Some(&expected), &head, &mut || false).is_err());
    }
}
