//! Exact native replay coordinates and complete candidate/conflict responses.
//! A receipt is derived evidence, never permission to publish its candidate.

use fgit_forge::preparation::{ConflictKind, MergeConflict, MergeEntry};
use fgit_forge::preparation::replay::{ReplayCoordinates, ReplayDirection, ReplayPreparation, ReplayRequest};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryAuthorityHeadId};
use crate::OneNode;
use super::request::Command;
use super::super::artifact::{Bundle, PreparedReply, append, checkpoint, hex};
use super::super::super::{Status, issues::{ApiError, quote, ref_fields}};

fn valid_oid(format: GitHashAlgorithm, id: GitOid) -> bool { !id.is_zero() && id.algorithm() == format }
fn coordinates(value: ReplayCoordinates, requested: ReplayRequest) -> Result<(), ApiError> {
    if value.request != requested
        || requested.mainline.is_some_and(|n| value.selected_mainline != Some(n))
        || !matches!((value.selected_parent, value.selected_mainline), (None, None)
            | (Some(_), Some(1..=u16::MAX)))
        || value.selected_parent.is_some_and(|id| !valid_oid(requested.target.algorithm(), id))
    { return Err(ApiError::unavailable()); }
    Ok(())
}
fn entry(value: Option<&MergeEntry>, path: &[u8], format: GitHashAlgorithm) -> Result<String, ApiError> {
    let Some(value) = value else { return Ok("null".into()); };
    if !valid_oid(format, value.oid) || path.rsplit(|b| *b == b'/').next() != Some(value.name.as_slice())
        || !matches!(value.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000)
    { return Err(ApiError::unavailable()); }
    Ok(format!("{{\"mode\":{},\"oid\":{}}}", value.mode, quote(&value.oid.to_string())))
}
fn kind(value: ConflictKind) -> &'static str {
    match value {
        ConflictKind::Content => "content", ConflictKind::Binary => "binary",
        ConflictKind::ModifyDelete => "modify_delete", ConflictKind::TypeChange => "type_change",
        ConflictKind::Mode => "mode", ConflictKind::Opaque => "opaque",
        ConflictKind::AttributesRequireDriver => "attributes_require_driver",
    }
}
fn conflict(value: &MergeConflict, format: GitHashAlgorithm, max_path: usize) -> Result<String, ApiError> {
    if value.path.is_empty() || value.path.len() > max_path || value.path.contains(&0)
        || value.path.split(|b| *b == b'/').any(|part| part.is_empty() || part == b"." || part == b"..")
    { return Err(ApiError::unavailable()); }
    Ok(format!("{{\"path_hex\":{},\"kind\":{},\"base\":{},\"ours\":{},\"theirs\":{}}}",
        quote(&hex(&value.path)), quote(kind(value.kind)), entry(value.base.as_ref(), &value.path, format)?,
        entry(value.ours.as_ref(), &value.path, format)?, entry(value.theirs.as_ref(), &value.path, format)?))
}

pub(super) fn build(node: &OneNode, command: &Command, head: RepositoryAuthorityHeadId,
    outcome: &ReplayPreparation, bundle: Option<Vec<u8>>, counts: (usize, usize),
    maximum: usize, live: &mut impl FnMut() -> bool,
) -> Result<PreparedReply, ApiError> {
    checkpoint(live)?;
    if command.expected_head.is_some_and(|expected| expected != head) { return Err(ApiError::unavailable()); }
    let point = match outcome {
        ReplayPreparation::Clean(plan) => plan.coordinates,
        ReplayPreparation::Conflicted { coordinates, .. } | ReplayPreparation::NoChange { coordinates } => *coordinates,
    };
    coordinates(point, command.inputs)?;
    let bundle = bundle.map(|bytes| Bundle::new(bytes, live)).transpose()?;
    let (pack_objects, borrowed_objects) = counts;
    let internal = head.as_internal_object_id();
    let token = format!("alg:{}:{}", internal.algorithm().code_point(), hex(internal.digest().as_bytes()));
    let direction = match command.inputs.direction { ReplayDirection::CherryPick => "cherry-pick", ReplayDirection::Revert => "revert" };
    let mut metadata = String::new();
    append(&mut metadata, &format!(concat!(
        "{{\"type\":\"replay_preparation\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"repository_incarnation\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"profile\":\"path-v1\",\"direction\":{},{},{},\"expected_target\":{},\"expected_source\":{},",
        "\"selected_commit\":{},\"selected_parent\":{},\"selected_mainline\":{},",
        "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,\"published\":false,",
        "\"publication_authorized\":false,\"author_identity_verified\":false,"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()),
        quote(&head.to_string()), quote(&token), quote(direction), ref_fields("target_ref", &command.target),
        ref_fields("source_ref", &command.source), quote(&point.request.target.to_string()),
        quote(&point.request.source_tip.to_string()), quote(&point.request.selected_commit.to_string()),
        point.selected_parent.map_or_else(|| "null".into(), |id| quote(&id.to_string())),
        point.selected_mainline.map_or_else(|| "null".into(), |n| n.to_string())))?;
    let status = match outcome {
        ReplayPreparation::Clean(plan) => {
            let bytes = bundle.as_ref().ok_or_else(ApiError::unavailable)?;
            if !valid_oid(node.object_format, plan.commit) || !valid_oid(node.object_format, plan.tree)
                || plan.commit == command.inputs.target || plan.objects.is_empty()
                || plan.objects.len() > command.limits.max_objects
                || pack_objects == 0 || pack_objects > command.limits.max_objects || borrowed_objects > pack_objects
            { return Err(ApiError::unavailable()); }
            append(&mut metadata, &format!(concat!(
                "\"state\":\"clean\",\"candidate_commit\":{},\"root_tree\":{},\"parents\":[{}],",
                "\"generated_objects\":{},\"pack_objects\":{},\"borrowed_objects\":{},",
                "\"bundle\":{{\"bytes\":{},\"sha256\":{}}},\"conflicts\":[]}}"),
                quote(&plan.commit.to_string()), quote(&plan.tree.to_string()), quote(&command.inputs.target.to_string()),
                plan.objects.len(), pack_objects, borrowed_objects, bytes.len(), quote(&bytes.digest_hex())))?;
            Status::Success
        }
        ReplayPreparation::Conflicted { conflicts, .. } => {
            if bundle.is_some() || counts != (0, 0) || conflicts.is_empty()
                || conflicts.len() > command.limits.max_conflicts
                || conflicts.windows(2).any(|rows| rows[0].path >= rows[1].path)
            { return Err(ApiError::unavailable()); }
            append(&mut metadata, "\"state\":\"conflicted\",\"candidate_commit\":null,\"root_tree\":null,\"bundle\":null,\"conflicts\":[")?;
            for (index, value) in conflicts.iter().enumerate() {
                checkpoint(live)?;
                if index != 0 { append(&mut metadata, ",")?; }
                append(&mut metadata, &conflict(value, node.object_format, command.limits.max_path_bytes)?)?;
            }
            append(&mut metadata, "]}")?;
            Status::Conflict
        }
        ReplayPreparation::NoChange { .. } => {
            if bundle.is_some() || counts != (0, 0) { return Err(ApiError::unavailable()); }
            append(&mut metadata, "\"state\":\"no_change\",\"candidate_commit\":null,\"root_tree\":null,\"bundle\":null,\"conflicts\":[]}")?;
            Status::Success
        }
    };
    checkpoint(live)?;
    PreparedReply::build(metadata, bundle, status, maximum, live)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id() -> GitOid { GitOid::from_hex(GitHashAlgorithm::Sha1, &"ab".repeat(20)).unwrap() }
    #[test]
    fn replay_response_cannot_change_direction_source_or_mainline() {
        let request = ReplayRequest { direction: ReplayDirection::CherryPick, target: id(), source_tip: id(), selected_commit: id(), mainline: None };
        let mut point = ReplayCoordinates { request, selected_parent: Some(id()), selected_mainline: Some(1) };
        coordinates(point, request).unwrap();
        point.request.direction = ReplayDirection::Revert;
        assert!(coordinates(point, request).is_err());
        point.request = request; point.selected_parent = None;
        assert!(coordinates(point, request).is_err());
        point.selected_mainline = None;
        coordinates(point, request).unwrap();
        assert!(coordinates(point, ReplayRequest { mainline: Some(1), ..request }).is_err());
    }
    #[test]
    fn conflict_paths_and_side_identities_are_lossless_and_bound() {
        let side = MergeEntry { name: b"\xff".to_vec(), mode: 0o100644, oid: id() };
        let mut value = MergeConflict { path: b"dir/\xff".to_vec(), kind: ConflictKind::Content,
            base: None, ours: Some(side.clone()), theirs: Some(side) };
        assert!(conflict(&value, GitHashAlgorithm::Sha1, 4096).unwrap().contains("6469722fff"));
        value.path = b"dir/other".to_vec();
        assert!(conflict(&value, GitHashAlgorithm::Sha1, 4096).is_err());
        value.path = b"../\xff".to_vec();
        assert!(conflict(&value, GitHashAlgorithm::Sha1, 4096).is_err());
    }
}
