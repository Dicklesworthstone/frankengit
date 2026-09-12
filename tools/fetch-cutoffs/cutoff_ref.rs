//! Bounded advertised-ref-only DWIM for shallow exclusions.
use super::*;

pub(super) fn resolve(repository: &impl UploadPackRepository, text: &[u8], limits: &WireLimits) -> Result<AnyGitOid, WireError> {
    let name = parse_ref_name(text, limits)?;
    if repository.advertised_refs().len() > limits.max_advertised_refs {
        return Err(WireError::TooManyAdvertisedRefs {limit:limits.max_advertised_refs});
    }
    let mut matched = None;
    for reference in repository.advertised_refs() {
        // The six native ref expansion rules; compare slices without building
        // six copies of an untrusted name. Distinct names remain ambiguous even
        // when their current targets are equal. Hidden refs are never consulted.
        let raw = reference.name.as_slice();
        let mut matches = raw == name.as_slice();
        for prefix in [b"refs/".as_slice(),b"refs/tags/",b"refs/heads/",b"refs/remotes/"] {
            matches |= raw.strip_prefix(prefix) == Some(name.as_slice());
        }
        matches |= raw.strip_prefix(b"refs/remotes/").and_then(|tail|tail.strip_suffix(b"/HEAD")) == Some(name.as_slice());
        if matches {
            if matched.is_some() { return Err(WireError::UnknownDeepenNotRef {name}); }
            if reference.oid.algorithm() != repository.object_format() {
                return Err(WireError::ObjectFormatMismatch {expected:repository.object_format(),observed:reference.oid.algorithm()});
            }
            matched=Some(reference.oid);
        }
    }
    matched.ok_or(WireError::UnknownDeepenNotRef {name})
}
