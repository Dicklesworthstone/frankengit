//! Exact PR coordinates plus the same original-commit recipes as source rebase.
//! Snapshot pins are required; multipart names are byte-part labels only.

use super::{Command, preparation_field};
use crate::smart_http::server::{
    issues::{ApiError, parse_form, parse_snapshot},
    pulls::resolution_upload,
    source::decode_rebase_resolution_recipes,
};
use fgit_forge::PullRequestNumber;
use fgit_forge::preparation::PreparationLimits;
use fgit_forge::preparation::rebase::resolutions::RebaseCommitResolution;
use fgit_types::GitHashAlgorithm;
use std::collections::BTreeMap;

pub(super) fn parse(
    number: PullRequestNumber,
    bytes: &[u8],
    boundary: Option<&str>,
    format: GitHashAlgorithm,
    live: &mut impl FnMut() -> bool,
) -> Result<(Command, Vec<RebaseCommitResolution>), ApiError> {
    super::super::output::checkpoint(live)?;
    let (form, files) = match boundary {
        Some(boundary) => resolution_upload(bytes, boundary, live)?,
        None => (bytes, BTreeMap::new()),
    };
    let mut fields = BTreeMap::new();
    let mut descriptors = Vec::new();
    for (name, value) in parse_form(form, 15 + 128)? {
        super::super::output::checkpoint(live)?;
        if name == "resolution" {
            if descriptors.len() == 128 {
                return Err(ApiError::too_large());
            }
            descriptors.push(value);
        } else {
            if name != "expected_head" && !preparation_field(&name) {
                return Err(ApiError::bad("unknown_rebase_preparation_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
    }
    let expected_head = parse_snapshot(
        &fields
            .remove("expected_head")
            .ok_or_else(|| ApiError::bad("rebase_resolution_requires_snapshot"))?,
    )?;
    let mut command = Command::from_fields(number, fields, format)?;
    command.expected_head = Some(expected_head);
    let recipes = decode_rebase_resolution_recipes(
        descriptors,
        files,
        format,
        PreparationLimits::default(),
        live,
    )?;
    Ok((command, recipes))
}
