//! Closed inputs for exact one-commit replay. OIDs compare selected history;
//! they do not turn an admitted object into a caller-readable source.

use std::collections::BTreeMap;
use fgit_forge::preparation::{MergeMetadata, PreparationLimits};
use fgit_forge::preparation::replay::{ReplayDirection, ReplayRequest};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use super::super::super::issues::{ApiError, parse_decimal, parse_form, parse_snapshot};

#[derive(Debug)]
pub(super) struct Command {
    pub(super) target: RefName,
    pub(super) source: RefName,
    pub(super) inputs: ReplayRequest,
    pub(super) expected_head: Option<RepositoryAuthorityHeadId>,
    pub(super) metadata: MergeMetadata,
    pub(super) limits: PreparationLimits,
}
impl Command {
    pub(super) fn parse(bytes: &[u8], format: GitHashAlgorithm, direction: ReplayDirection) -> Result<Self, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 32)? {
            if !matches!(name.as_str(), "profile" | "object_format" | "target_ref" | "target_ref_hex"
                | "source_ref" | "source_ref_hex" | "expected_target" | "expected_source" | "commit"
                | "expected_head" | "mainline" | "author" | "committer" | "timestamp" | "message" | "message_hex"
                | "max_commits" | "max_edges" | "max_tree_entries" | "max_depth" | "max_path_bytes"
                | "max_content_merges" | "max_text_bytes" | "max_conflicts" | "max_objects" | "max_output_bytes")
            { return Err(ApiError::bad("unknown_or_inapplicable_field")); }
            if fields.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
        }
        Self::from_fields(fields, format, direction)
    }

    fn from_fields(mut fields: BTreeMap<String, String>, format: GitHashAlgorithm,
        direction: ReplayDirection,
    ) -> Result<Self, ApiError> {
        if take(&mut fields, "profile")? != "path-v1" { return Err(ApiError::bad("unsupported_replay_profile")); }
        if take(&mut fields, "object_format")? != format.as_str() { return Err(ApiError::bad("object_format_mismatch")); }
        let target = reference(&mut fields, "target_ref", "target_ref_hex")?;
        let source = reference(&mut fields, "source_ref", "source_ref_hex")?;
        let target_tip = oid(&take(&mut fields, "expected_target")?, format)?;
        let source_tip = oid(&take(&mut fields, "expected_source")?, format)?;
        let selected_commit = oid(&take(&mut fields, "commit")?, format)?;
        let mainline = fields.remove("mainline").map(|text| {
            u16::try_from(parse_decimal(&text)?).ok().filter(|n| *n != 0)
                .ok_or_else(|| ApiError::bad("invalid_mainline"))
        }).transpose()?;
        let expected_head = fields.remove("expected_head").map(|text| parse_snapshot(&text)).transpose()?;
        let author = take(&mut fields, "author")?;
        let committer = fields.remove("committer").unwrap_or_else(|| author.clone());
        let timestamp = parse_decimal(&take(&mut fields, "timestamp")?)?;
        let message = match (fields.remove("message"), fields.remove("message_hex")) {
            (Some(text), None) => text.into_bytes(),
            (None, Some(text)) => unhex(&text, 64 * 1024)?,
            _ => return Err(ApiError::bad("exactly_one_message_required")),
        };
        let metadata = MergeMetadata { author, committer, timestamp, message };
        metadata.validate().map_err(|_| ApiError::bad("invalid_commit_metadata"))?;
        let mut limits = PreparationLimits::default();
        for (name, value) in [
            ("max_commits", &mut limits.max_commits), ("max_edges", &mut limits.max_edges),
            ("max_tree_entries", &mut limits.max_tree_entries), ("max_depth", &mut limits.max_depth),
            ("max_path_bytes", &mut limits.max_path_bytes), ("max_content_merges", &mut limits.max_content_merges),
            ("max_text_bytes", &mut limits.max_text_bytes), ("max_conflicts", &mut limits.max_conflicts),
            ("max_objects", &mut limits.max_objects), ("max_output_bytes", &mut limits.max_output_bytes),
        ] {
            if let Some(text) = fields.remove(name) {
                *value = usize::try_from(parse_decimal(&text)?).map_err(|_| ApiError::bad("invalid_replay_limit"))?;
            }
        }
        limits.validate().map_err(|_| ApiError::bad("invalid_replay_limit"))?;
        if !fields.is_empty() { return Err(ApiError::bad("unknown_or_inapplicable_field")); }
        Ok(Self { target, source, inputs: ReplayRequest { direction, target: target_tip,
            source_tip, selected_commit, mainline }, expected_head, metadata, limits })
    }
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields.remove(name).ok_or_else(|| ApiError::bad("missing_replay_field"))
}
fn reference(fields: &mut BTreeMap<String, String>, text: &str, hex: &str) -> Result<RefName, ApiError> {
    let bytes = match (fields.remove(text), fields.remove(hex)) {
        (Some(value), None) => value.into_bytes(),
        (None, Some(value)) => unhex(&value, 4096)?,
        _ => return Err(ApiError::bad("exactly_one_reference_encoding_required")),
    };
    if bytes.len() > 4096 || !bytes.starts_with(b"refs/heads/") {
        return Err(ApiError::bad("branch_reference_required"));
    }
    RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_ref"))
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if text.len() != 2 * format.digest_len() { return Err(ApiError::bad("invalid_native_oid")); }
    unhex(text, format.digest_len())?;
    let id = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_native_oid"))?;
    if id.is_zero() { return Err(ApiError::bad("invalid_native_oid")); }
    Ok(id)
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if text.is_empty() || text.len() % 2 != 0 || text.len() > maximum * 2
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err(ApiError::bad("invalid_hex_bytes")); }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|p| (digit(p[0]) << 4) | digit(p[1])).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form(format: GitHashAlgorithm) -> String {
        let oid = "ab".repeat(format.digest_len());
        format!("profile=path-v1&object_format={}&target_ref=refs/heads/main&source_ref=refs/heads/topic&expected_target={oid}&expected_source={oid}&commit={oid}&author=User+%3Cu%40example.invalid%3E&timestamp=1&message=Replay", format.as_str())
    }
    #[test]
    fn both_formats_explicit_direction_mainline_and_raw_bytes_remain_exact() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let input = form(format).replace("source_ref=refs/heads/topic", "source_ref_hex=726566732f68656164732fff")
                .replace("message=Replay", "message_hex=ff0d0a") + "&mainline=2&max_objects=7";
            for direction in [ReplayDirection::CherryPick, ReplayDirection::Revert] {
                let command = Command::parse(input.as_bytes(), format, direction).unwrap();
                assert_eq!(command.inputs.direction, direction);
                assert_eq!(command.source.as_bytes(), b"refs/heads/\xff");
                assert_eq!(command.metadata.message, b"\xff\r\n");
                assert_eq!(command.inputs.mainline, Some(2));
                assert_eq!(command.limits.max_objects, 7);
            }
        }
    }
    #[test]
    fn selector_overrides_duplicate_fields_and_widened_limits_never_change_semantics() {
        let input = form(GitHashAlgorithm::Sha1);
        for extra in ["&direction=revert", "&principal=admin", "&force=true", "&commit=ab",
            "&base=ab", "&mainline=0", "&mainline=65536", "&max_objects=10001", "&max_edges=0",
            "&max_output_bytes=33554433", "&message_hex=61", "&target_ref_hex=726566732f68656164732f61"] {
            assert!(Command::parse((input.clone() + extra).as_bytes(), GitHashAlgorithm::Sha1, ReplayDirection::CherryPick).is_err(), "{extra}");
        }
        for changed in [input.replace("refs/heads/main", "refs/tags/main"),
            input.replace("timestamp=1", "timestamp=01"), input.replace("object_format=sha1", "object_format=sha256"),
            input.replace("message=Replay", "message_hex=00"), input.replace("profile=path-v1", "profile=automatic")]
        { assert!(Command::parse(changed.as_bytes(), GitHashAlgorithm::Sha1, ReplayDirection::Revert).is_err()); }
    }
}
