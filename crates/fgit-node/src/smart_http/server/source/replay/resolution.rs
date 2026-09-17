//! Every explicit choice must bind one reproduced native replay conflict.
//! Uploaded file labels name borrowed multipart bytes, never host filenames.

use std::collections::BTreeMap;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::PreparationLimits;
use fgit_forge::preparation::replay::ReplayDirection;
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice,
    ResolutionError, ResolutionKind, ResolvedPath, validate_resolutions};
use fgit_types::GitHashAlgorithm;
use super::request::{Command, unhex};
use super::super::artifact::{append, checkpoint};
use super::super::super::{Status, issues::{ApiError, parse_form, quote}, pulls::resolution_upload};

pub(super) fn parse(bytes: &[u8], boundary: Option<&str>, format: GitHashAlgorithm,
    direction: ReplayDirection, live: &mut impl FnMut() -> bool,
) -> Result<(Command, Vec<ConflictResolution>), ApiError> {
    checkpoint(live)?;
    let (form, files) = match boundary {
        Some(boundary) => resolution_upload(bytes, boundary, live)?,
        None => (bytes, BTreeMap::new()),
    };
    parse_parts(form, files, format, direction, live)
}
fn parse_parts(form: &[u8], mut files: BTreeMap<&str, &[u8]>, format: GitHashAlgorithm,
    direction: ReplayDirection, live: &mut impl FnMut() -> bool,
) -> Result<(Command, Vec<ConflictResolution>), ApiError> {
    checkpoint(live)?;
    let mut fields = BTreeMap::new();
    let mut descriptors = Vec::new();
    for (name, value) in parse_form(form, 32 + PreparationLimits::default().max_conflicts)? {
        if name == "resolution" {
            if descriptors.len() == PreparationLimits::default().max_conflicts { return Err(ApiError::too_large()); }
            descriptors.push(value);
        } else if fields.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
    }
    let command = Command::from_fields(fields, format, direction)?;
    if command.expected_head.is_none() { return Err(ApiError::bad("resolution_requires_snapshot")); }
    if descriptors.is_empty() { return Err(ApiError::bad("resolution_choices_required")); }
    if descriptors.len() > command.limits.max_conflicts { return Err(ApiError::too_large()); }
    let mut choices = Vec::with_capacity(descriptors.len());
    let mut retained = 0_usize;
    for descriptor in descriptors {
        checkpoint(live)?;
        let mut fields = descriptor.split(':');
        let path = unhex(fields.next().ok_or_else(|| ApiError::bad("invalid_resolution"))?, command.limits.max_path_bytes)?;
        retained = retained.checked_add(path.len()).ok_or_else(ApiError::too_large)?;
        let choice = match fields.next() {
            Some("base") => ResolutionChoice::Base,
            Some("ours") => ResolutionChoice::Ours,
            Some("theirs") => ResolutionChoice::Theirs,
            Some("delete") => ResolutionChoice::Delete,
            Some("file") => {
                let mode = match fields.next() {
                    Some("100644") => 0o100644, Some("100755") => 0o100755,
                    _ => return Err(ApiError::bad("invalid_resolution_mode")),
                };
                let label = fields.next().ok_or_else(|| ApiError::bad("resolution_file_required"))?;
                let content = files.remove(label).ok_or_else(|| ApiError::bad("missing_or_reused_resolution_file"))?;
                retained = retained.checked_add(content.len()).ok_or_else(ApiError::too_large)?;
                if content.len() > command.limits.max_text_bytes || retained > command.limits.max_output_bytes {
                    return Err(ApiError::too_large());
                }
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(content.len()).map_err(|_| ApiError::unavailable())?;
                bytes.extend_from_slice(content);
                ResolutionChoice::File { mode, bytes }
            }
            _ => return Err(ApiError::bad("invalid_resolution_choice")),
        };
        if fields.next().is_some() { return Err(ApiError::bad("invalid_resolution")); }
        if retained > command.limits.max_output_bytes { return Err(ApiError::too_large()); }
        choices.push(ConflictResolution { path, choice });
    }
    if !files.is_empty() { return Err(ApiError::bad("unreferenced_resolution_file")); }
    choices.sort_by(|a, b| a.path.cmp(&b.path));
    validate_resolutions(&choices, command.limits).map_err(|error| match error {
        ResolutionError::Budget => ApiError::too_large(), _ => ApiError::bad("invalid_resolution_set"),
    })?;
    checkpoint(live)?;
    Ok((command, choices))
}

pub(super) fn failure(error: &ResolutionError) -> ApiError {
    match error {
        ResolutionError::InvalidInputs | ResolutionError::InvalidResolution { .. }
        | ResolutionError::DuplicatePath(_) | ResolutionError::OverlappingPaths => ApiError::bad("invalid_resolution_set"),
        ResolutionError::NonConflictPath(_) => ApiError::new(Status::Conflict, "resolution_names_clean_path"),
        ResolutionError::MissingSide { .. } => ApiError::new(Status::Conflict, "resolution_side_missing"),
        ResolutionError::Unresolved(_) => ApiError::new(Status::Conflict, "unresolved_conflicts"),
        ResolutionError::BaseMismatch { .. } => ApiError::new(Status::Conflict, "resolution_base_mismatch"),
        ResolutionError::NoConflicts => ApiError::new(Status::Conflict, "no_conflicts_to_resolve"),
        ResolutionError::Budget => ApiError::too_large(),
        ResolutionError::Preparation(error) => super::preparation_error(error),
        ResolutionError::ReconstructionMismatch => ApiError::unavailable(),
    }
}

pub(super) fn append_receipts(out: &mut String, choices: &[ConflictResolution], paths: &[ResolvedPath],
    format: GitHashAlgorithm, limits: PreparationLimits, live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    if paths.is_empty() || paths.len() != choices.len() || paths.len() > limits.max_conflicts
        || paths.windows(2).any(|rows| rows[0].conflict.path >= rows[1].conflict.path)
    { return Err(ApiError::unavailable()); }
    append(out, "\"resolution_profile\":\"exact-path-resolutions-v1\",\"resolutions\":[")?;
    for (index, (choice, path)) in choices.iter().zip(paths).enumerate() {
        checkpoint(live)?;
        if choice.path != path.conflict.path || choice.choice.kind() != path.choice
            || (path.choice == ResolutionKind::Delete) != path.result.is_none()
        { return Err(ApiError::unavailable()); }
        let expected = match &choice.choice {
            ResolutionChoice::Base => path.conflict.base.as_ref(),
            ResolutionChoice::Ours => path.conflict.ours.as_ref(),
            ResolutionChoice::Theirs => path.conflict.theirs.as_ref(),
            ResolutionChoice::Delete => None,
            ResolutionChoice::File { mode, bytes } => {
                let result = path.result.as_ref().ok_or_else(ApiError::unavailable)?;
                if result.mode != *mode || result.oid != git_object_id(format, GitObjectKind::Blob, bytes) {
                    return Err(ApiError::unavailable());
                }
                Some(result)
            }
        };
        if path.result.as_ref() != expected { return Err(ApiError::unavailable()); }
        let selected = match path.choice { ResolutionKind::Base => "base", ResolutionKind::Ours => "ours",
            ResolutionKind::Theirs => "theirs", ResolutionKind::Delete => "delete", ResolutionKind::File => "file" };
        let conflict = super::output::conflict(&path.conflict, format, limits.max_path_bytes)?;
        let result = super::output::entry(path.result.as_ref(), &choice.path, format)?;
        append(out, &format!("{}{{\"conflict\":{conflict},\"choice\":{},\"result\":{result}}}",
            if index == 0 { "" } else { "," }, quote(selected)))?;
    }
    append(out, "],")?;
    checkpoint(live)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form() -> String {
        let id = "ab".repeat(20);
        format!("profile=path-v1&object_format=sha1&target_ref=refs/heads/main&source_ref=refs/heads/topic&expected_target={id}&expected_source={id}&commit={id}&author=U+%3Cu%40example.invalid%3E&timestamp=1&message=Resolve&expected_head=alg:1:{}", "cd".repeat(32))
    }
    #[test]
    fn exact_binary_and_empty_files_are_consumed_once_without_normalization() {
        for bytes in [b"\0\xff\r\n".as_slice(), b"".as_slice()] {
            let form = form() + "&resolution=6469722fff:file:100755:file_0&resolution=61:delete";
            let (_, choices) = parse_parts(form.as_bytes(), BTreeMap::from([("file_0", bytes)]),
                GitHashAlgorithm::Sha1, ReplayDirection::Revert, &mut || true).unwrap();
            assert_eq!(choices[0].choice, ResolutionChoice::Delete);
            assert_eq!(choices[1].path, b"dir/\xff");
            assert_eq!(choices[1].choice, ResolutionChoice::File { mode: 0o100755, bytes: bytes.to_vec() });
        }
    }
    #[test]
    fn empty_duplicate_overlapping_unpinned_and_unused_choices_cannot_fall_back() {
        for suffix in ["", "&resolution=61:ours&resolution=61:theirs", "&resolution=61:ours&resolution=612f62:ours",
            "&resolution=2e2e2f61:ours", "&resolution=61:ours:extra", "&resolution=61:file:120000:file_0",
            "&resolution=61:file:100644:file_0&resolution=62:file:100644:file_0", "&resolution=61:ours&force=true"] {
            let input = form() + suffix;
            assert!(parse_parts(input.as_bytes(), BTreeMap::new(), GitHashAlgorithm::Sha1,
                ReplayDirection::CherryPick, &mut || true).is_err(), "{suffix}");
        }
        let input = form() + "&resolution=61:ours";
        assert!(parse_parts(input.as_bytes(), BTreeMap::from([("file_0", b"unused".as_slice())]),
            GitHashAlgorithm::Sha1, ReplayDirection::CherryPick, &mut || true).is_err());
        let input = input.replace(&format!("&expected_head=alg:1:{}", "cd".repeat(32)), "");
        assert!(parse_parts(input.as_bytes(), BTreeMap::new(), GitHashAlgorithm::Sha1,
            ReplayDirection::CherryPick, &mut || true).is_err());
    }
    #[test]
    fn cancelled_parsing_and_forged_resolution_receipts_refuse() {
        let input = form() + "&resolution=61:ours";
        assert!(parse(input.as_bytes(), None, GitHashAlgorithm::Sha1, ReplayDirection::CherryPick, &mut || false).is_err());
        let (_, choices) = parse(input.as_bytes(), None, GitHashAlgorithm::Sha1, ReplayDirection::CherryPick, &mut || true).unwrap();
        let id = fgit_types::GitOid::from_hex(GitHashAlgorithm::Sha1, &"ab".repeat(20)).unwrap();
        let side = fgit_forge::preparation::MergeEntry { name: b"a".to_vec(), mode: 0o100644, oid: id };
        let mut receipt = ResolvedPath { conflict: fgit_forge::preparation::MergeConflict { path: b"a".to_vec(),
            kind: fgit_forge::preparation::ConflictKind::Content, base: None, ours: Some(side.clone()), theirs: None },
            choice: ResolutionKind::Ours, result: Some(side) };
        append_receipts(&mut String::new(), &choices, &[receipt.clone()], GitHashAlgorithm::Sha1,
            PreparationLimits::default(), &mut || true).unwrap();
        receipt.choice = ResolutionKind::Theirs;
        assert!(append_receipts(&mut String::new(), &choices, &[receipt], GitHashAlgorithm::Sha1,
            PreparationLimits::default(), &mut || true).is_err());
    }
}
