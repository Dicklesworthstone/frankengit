//! Explicit caller identity constraints for the existing native verifier.
use std::fmt::Write as _;

use fgit_crypto::lowercase_hex;
use fgit_node::source_retrieval::integrity::bundle_verify::{
    BundleExpectations, BundleVerifyLimits, MAX_EXPECTED_REFS, MatchedGitBundle,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

pub(super) fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() % 2 != 0 || value.len() > maximum * 2
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("expected complete bounded lowercase hexadecimal bytes".into());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(value.len() / 2).map_err(|_| "expectation allocation refused")?;
    for pair in value.as_bytes().chunks_exact(2) {
        let nibble = |byte| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
        bytes.push(16 * nibble(pair[0]) + nibble(pair[1]));
    }
    Ok(bytes)
}

pub(super) fn assemble(
    hash: Option<[u8; 32]>,
    format: Option<GitHashAlgorithm>,
    raw: &[(&str, bool)],
    exact: bool,
    limits: &BundleVerifyLimits,
) -> Result<Option<BundleExpectations>, String> {
    if hash.is_none() && format.is_none() && raw.is_empty() && !exact {
        return Ok(None);
    }
    if raw.len() > MAX_EXPECTED_REFS.min(limits.envelope.max_references).min(limits.graph.max_references) {
        return Err("too many expected references".into());
    }
    let mut references = Vec::new();
    references.try_reserve_exact(raw.len()).map_err(|_| "expectation allocation refused")?;
    let mut name_bytes = 0_usize;
    for &(value, hex_name) in raw {
        let format = format.ok_or("--expect-ref requires --expect-format sha1|sha256")?;
        let (name, target) = value.rsplit_once('=').ok_or("expected REF=OID or HEX=OID")?;
        let name = if hex_name {
            unhex(name, 4096)?
        } else {
            if name.is_empty() || name.len() > 4096 {
                return Err("expected reference name exceeds byte limit".into());
            }
            name.as_bytes().to_vec()
        };
        name_bytes = name_bytes.checked_add(name.len())
            .filter(|count| *count <= limits.envelope.max_header_bytes.min(1024 * 1024))
            .ok_or("expected reference byte limit exceeded")?;
        let name = RefName::try_new(&name).map_err(|error| error.to_string())?;
        let prefix = format!("{}:", format.as_str());
        let target = target.strip_prefix(prefix.as_str()).unwrap_or(target);
        // Do not infer a hash domain from the ID's length or silently accept
        // an ID explicitly tagged with another domain.
        let id = GitOid::from_hex(format, target).map_err(|error| error.to_string())?;
        references.push((name, id));
    }
    let expected = BundleExpectations::new(hash, format, &references, exact).map_err(|error| error.to_string())?;
    expected.validate_limits(limits).map_err(|error| error.to_string())?;
    Ok(Some(expected))
}

pub(super) fn report(result: &MatchedGitBundle<'_>) -> Result<String, String> {
    let mut out = super::report(result.verified())?;
    if out.pop() != Some('}') {
        return Err("invalid native verification report".into());
    }
    let expected = result.expectations();
    let sha256 = expected.sha256().map_or_else(|| "null".into(), |hash| format!("\"{}\"", lowercase_hex(hash)));
    let format = expected.format().map_or_else(|| "null".into(), |format| format!("\"{}\"", format.as_str()));
    let ref_set = if expected.references().is_empty() { "null" }
        else if expected.exact_references() { "\"exact\"" } else { "\"contains\"" };
    write!(out, ",\"caller_expectations_matched\":true,\"expectations\":{{\"artifact_sha256\":{sha256},\"object_format\":{format},\"ref_set\":{ref_set},\"references\":[")
        .map_err(|error| error.to_string())?;
    for (index, (name, id)) in expected.references().iter().enumerate() {
        if index > 0 { out.push(','); }
        write!(out, "{{\"ref_hex\":\"{}\",\"object_id\":\"{}\"}}", lowercase_hex(name.as_bytes()), lowercase_hex(id.as_bytes()))
            .map_err(|error| error.to_string())?;
    }
    out.push_str("]}}");
    Ok(out)
}
