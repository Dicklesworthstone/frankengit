//! Whole-series conflict recipes bind ORIGINAL commits and exact byte paths.
//! The existing multipart engine supplies borrowed files; no host path opens.

use super::super::super::{
    issues::{ApiError, parse_form, quote},
    pulls::resolution_upload,
};
use super::super::artifact::{append, checkpoint};
use super::{
    output,
    request::{Prepare, oid, prepare_field, unhex},
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::rebase::resolutions::{
    RebaseCommitResolution, RebaseResolvedStep, validate_rebase_resolutions,
};
use fgit_forge::preparation::rebase::{RebasePreparation, RebaseStop};
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice, ResolutionKind};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CHOICES: usize = 128;

pub(super) fn parse(
    bytes: &[u8],
    boundary: Option<&str>,
    format: GitHashAlgorithm,
    live: &mut impl FnMut() -> bool,
) -> Result<(Prepare, Vec<RebaseCommitResolution>), ApiError> {
    checkpoint(live)?;
    let (form, files) = match boundary {
        Some(boundary) => resolution_upload(bytes, boundary, live)?,
        None => (bytes, BTreeMap::new()),
    };
    command(form, files, format, live)
}
fn command(
    form: &[u8],
    mut files: BTreeMap<&str, &[u8]>,
    format: GitHashAlgorithm,
    live: &mut impl FnMut() -> bool,
) -> Result<(Prepare, Vec<RebaseCommitResolution>), ApiError> {
    let mut fields = BTreeMap::new();
    let mut descriptors = Vec::new();
    for (name, value) in parse_form(form, 24 + MAX_CHOICES)? {
        checkpoint(live)?;
        if name == "resolution" {
            if descriptors.len() == MAX_CHOICES {
                return Err(ApiError::too_large());
            }
            descriptors.push(value);
        } else {
            if !prepare_field(&name) {
                return Err(ApiError::bad("unknown_rebase_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
    }
    let command = Prepare::from_fields(fields, format)?;
    if command.expected_head.is_none() {
        return Err(ApiError::bad("rebase_resolution_requires_snapshot"));
    }
    if descriptors.is_empty() {
        return Err(ApiError::bad("rebase_resolution_choices_required"));
    }
    if descriptors.len() > command.limits.max_conflicts {
        return Err(ApiError::too_large());
    }
    let mut bindings: BTreeMap<GitOid, Vec<ConflictResolution>> = BTreeMap::new();
    let mut retained = 0_usize;
    for descriptor in descriptors {
        checkpoint(live)?;
        let mut parts = descriptor.split(':');
        let original = oid(
            parts
                .next()
                .ok_or_else(|| ApiError::bad("invalid_rebase_resolution"))?,
            format,
        )?;
        let path = unhex(
            parts
                .next()
                .ok_or_else(|| ApiError::bad("invalid_rebase_resolution"))?,
            command.limits.max_path_bytes,
        )?;
        let action = parts
            .next()
            .ok_or_else(|| ApiError::bad("invalid_rebase_resolution"))?;
        retained = retained
            .checked_add(path.len())
            .filter(|n| *n <= command.limits.max_output_bytes)
            .ok_or_else(ApiError::too_large)?;
        let choice = match action {
            "base" => ResolutionChoice::Base,
            "ours" => ResolutionChoice::Ours,
            "theirs" => ResolutionChoice::Theirs,
            "delete" => ResolutionChoice::Delete,
            "file" => {
                let mode = match parts.next() {
                    Some("100644") => 0o100644,
                    Some("100755") => 0o100755,
                    _ => return Err(ApiError::bad("invalid_resolution_mode")),
                };
                let name = parts
                    .next()
                    .ok_or_else(|| ApiError::bad("resolution_file_required"))?;
                if !file_name(name) {
                    return Err(ApiError::bad("invalid_resolution_file"));
                }
                let content = files
                    .remove(name)
                    .ok_or_else(|| ApiError::bad("missing_or_reused_resolution_file"))?;
                retained = retained
                    .checked_add(content.len())
                    .filter(|n| *n <= command.limits.max_output_bytes)
                    .ok_or_else(ApiError::too_large)?;
                if content.len() > command.limits.max_text_bytes {
                    return Err(ApiError::too_large());
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(content.len())
                    .map_err(|_| ApiError::unavailable())?;
                bytes.extend_from_slice(content);
                ResolutionChoice::File { mode, bytes }
            }
            _ => return Err(ApiError::bad("invalid_resolution_choice")),
        };
        if parts.next().is_some() {
            return Err(ApiError::bad("invalid_rebase_resolution"));
        }
        let paths = bindings.entry(original).or_default();
        paths.try_reserve(1).map_err(|_| ApiError::unavailable())?;
        paths.push(ConflictResolution { path, choice });
    }
    if !files.is_empty() {
        return Err(ApiError::bad("unreferenced_resolution_file"));
    }
    let recipes: Vec<_> = bindings
        .into_iter()
        .map(|(original, mut paths)| {
            paths.sort_by(|a, b| a.path.cmp(&b.path));
            RebaseCommitResolution { original, paths }
        })
        .collect();
    validate_rebase_resolutions(format, command.limits, &recipes)
        .map_err(|error| super::rebase_error(&error))?;
    checkpoint(live)?;
    Ok((command, recipes))
}
fn file_name(name: &str) -> bool {
    let Some(number) = name.strip_prefix("file_") else {
        return false;
    };
    !number.is_empty()
        && number.len() <= 3
        && !(number.len() > 1 && number.starts_with('0'))
        && number.bytes().all(|b| b.is_ascii_digit())
        && number.parse::<usize>().is_ok_and(|n| n < MAX_CHOICES)
}

/// A stopped run may leave future recipes unused. A clean run must consume
/// every recipe. Results are checked against the exact requested side or file
/// identity, not just a count or an asserted native success flag.
fn validate(
    command: &Prepare,
    outcome: &RebasePreparation,
    recipes: &[RebaseCommitResolution],
    receipts: &[RebaseResolvedStep],
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    checkpoint(live)?;
    validate_rebase_resolutions(
        command.inputs.source_tip.algorithm(),
        command.limits,
        recipes,
    )
    .map_err(|_| ApiError::unavailable())?;
    if recipes.is_empty() || receipts.len() > recipes.len() {
        return Err(ApiError::unavailable());
    }
    let (steps, empty_stop, clean) = match outcome {
        RebasePreparation::Clean(plan) => (plan.steps.as_slice(), None, true),
        RebasePreparation::Stopped {
            completed,
            original,
            reason,
            ..
        } => (
            completed.as_slice(),
            matches!(reason, RebaseStop::BecameEmpty).then_some(*original),
            false,
        ),
    };
    let mut positions: BTreeMap<_, _> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| (s.original, i))
        .collect();
    if positions.len() != steps.len() {
        return Err(ApiError::unavailable());
    }
    if let Some(original) = empty_stop
        && positions.insert(original, steps.len()).is_some()
    {
        return Err(ApiError::unavailable());
    }
    let supplied: BTreeMap<_, _> = recipes
        .iter()
        .map(|r| (r.original, r.paths.as_slice()))
        .collect();
    let expected: BTreeSet<_> = supplied
        .keys()
        .filter(|id| positions.contains_key(*id))
        .copied()
        .collect();
    let mut observed = BTreeSet::new();
    let mut previous = None;
    let format = command.inputs.source_tip.algorithm();
    for receipt in receipts {
        checkpoint(live)?;
        let position = *positions
            .get(&receipt.original)
            .ok_or_else(ApiError::unavailable)?;
        if previous.is_some_and(|p| p >= position) || !observed.insert(receipt.original) {
            return Err(ApiError::unavailable());
        }
        previous = Some(position);
        let requested = supplied
            .get(&receipt.original)
            .ok_or_else(ApiError::unavailable)?;
        if receipt.paths.len() != requested.len() {
            return Err(ApiError::unavailable());
        }
        for (path, desired) in receipt.paths.iter().zip(requested.iter()) {
            checkpoint(live)?;
            if path.conflict.path != desired.path || path.choice != desired.choice.kind() {
                return Err(ApiError::unavailable());
            }
            let correct = match &desired.choice {
                ResolutionChoice::Base => {
                    path.result.is_some() && path.result == path.conflict.base
                }
                ResolutionChoice::Ours => {
                    path.result.is_some() && path.result == path.conflict.ours
                }
                ResolutionChoice::Theirs => {
                    path.result.is_some() && path.result == path.conflict.theirs
                }
                ResolutionChoice::Delete => path.result.is_none(),
                ResolutionChoice::File { mode, bytes } => {
                    path.result.as_ref().is_some_and(|entry| {
                        entry.mode == *mode
                            && entry.oid == git_object_id(format, GitObjectKind::Blob, bytes)
                            && desired.path.rsplit(|b| *b == b'/').next()
                                == Some(entry.name.as_slice())
                    })
                }
            };
            if !correct {
                return Err(ApiError::unavailable());
            }
            checkpoint(live)?;
        }
    }
    if observed != expected || (clean && observed.len() != supplied.len()) {
        return Err(ApiError::unavailable());
    }
    checkpoint(live)
}

pub(super) fn append_receipts(
    out: &mut String,
    command: &Prepare,
    outcome: &RebasePreparation,
    recipes: &[RebaseCommitResolution],
    receipts: &[RebaseResolvedStep],
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    validate(command, outcome, recipes, receipts, live)?;
    append(
        out,
        &format!(
            "\"resolution_profile\":\"original-commit-path-v1\",\"resolution_input_commits\":{},\"resolution_consumed_commits\":{},\"resolutions\":[",
            recipes.len(),
            receipts.len()
        ),
    )?;
    for (index, receipt) in receipts.iter().enumerate() {
        checkpoint(live)?;
        append(
            out,
            &format!(
                "{}{{\"original\":{},\"paths\":[",
                if index == 0 { "" } else { "," },
                quote(&receipt.original.to_string())
            ),
        )?;
        for (index, path) in receipt.paths.iter().enumerate() {
            checkpoint(live)?;
            append(
                out,
                if index == 0 {
                    "{\"conflict\":"
                } else {
                    ",{\"conflict\":"
                },
            )?;
            output::append_conflict(out, &path.conflict, command)?;
            let choice = match path.choice {
                ResolutionKind::Base => "base",
                ResolutionKind::Ours => "ours",
                ResolutionKind::Theirs => "theirs",
                ResolutionKind::Delete => "delete",
                ResolutionKind::File => "file",
            };
            append(
                out,
                &format!(
                    ",\"choice\":{},\"result\":{}}}",
                    quote(choice),
                    output::entry(path.result.as_ref(), command.inputs.source_tip.algorithm())?
                ),
            )?;
        }
        append(out, "]}")?;
    }
    append(out, "],")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_forge::preparation::rebase::{RebaseStep, RebaseStepKind};
    use fgit_forge::preparation::resolution::ResolvedPath;
    use fgit_forge::preparation::{ConflictKind, MergeConflict, MergeEntry};
    fn id(n: u8) -> GitOid {
        GitOid::from_hex(GitHashAlgorithm::Sha1, &format!("{n:02x}").repeat(20)).unwrap()
    }
    fn form() -> String {
        format!(
            "object_format=sha1&profile=linear-v1&source_ref=refs/heads/topic&onto_ref=refs/heads/main&expected_source={}&upstream={}&expected_onto={}&empty=stop&committer=Bot+%3Cb%40example.invalid%3E&timestamp=1&expected_head=alg:1:{}",
            id(1),
            id(2),
            id(3),
            "a".repeat(64)
        )
    }
    #[test]
    fn original_commit_scope_allows_same_path_at_different_steps_but_never_reuses_files() {
        let input = form()
            + &format!(
                "&resolution={}:ff:file:100755:file_0&resolution={}:ff:file:100644:file_1",
                id(4),
                id(1)
            );
        let files = BTreeMap::from([
            ("file_0", b"\0\xff\r\n".as_slice()),
            ("file_1", b"".as_slice()),
        ]);
        let (_, recipes) = command(input.as_bytes(), files, GitHashAlgorithm::Sha1, &mut || {
            true
        })
        .unwrap();
        assert_eq!(recipes.len(), 2);
        assert!(recipes.iter().any(|r| matches!(&r.paths[0].choice, ResolutionChoice::File { mode: 0o100644, bytes } if bytes.is_empty())));
        let reused = input.replace("file_1", "file_0");
        assert!(
            command(
                reused.as_bytes(),
                BTreeMap::from([("file_0", b"data".as_slice())]),
                GitHashAlgorithm::Sha1,
                &mut || true
            )
            .is_err()
        );
        assert!(
            command(
                (form() + &format!("&resolution={}:ff:ours", id(4))).as_bytes(),
                BTreeMap::from([("file_0", b"unused".as_slice())]),
                GitHashAlgorithm::Sha1,
                &mut || true
            )
            .is_err()
        );
    }
    #[test]
    fn snapshot_paths_modes_and_global_limits_fail_closed_before_native_work() {
        let prefix = form();
        for descriptor in [
            format!("{}:61:ours&resolution={}:61:theirs", id(4), id(4)),
            format!("{}:61:ours&resolution={}:612f62:theirs", id(4), id(4)),
            format!("{}:2e2e:delete", id(4)),
            format!("{}:61:file:120000:file_0", id(4)),
            format!("{}:61:file:100644:file_00", id(4)),
            format!("{}:61:ours:extra", id(4)),
        ] {
            assert!(
                parse(
                    (prefix.clone() + "&resolution=" + &descriptor).as_bytes(),
                    None,
                    GitHashAlgorithm::Sha1,
                    &mut || true
                )
                .is_err()
            );
        }
        let valid = prefix.clone() + &format!("&resolution={}:61:ours", id(4));
        let without = valid.replace(&format!("&expected_head=alg:1:{}", "a".repeat(64)), "");
        assert_eq!(
            parse(
                without.as_bytes(),
                None,
                GitHashAlgorithm::Sha1,
                &mut || true
            )
            .unwrap_err()
            .code,
            "rebase_resolution_requires_snapshot"
        );
        assert_eq!(
            parse(valid.as_bytes(), None, GitHashAlgorithm::Sha1, &mut || {
                false
            })
            .unwrap_err()
            .code,
            "request_timeout"
        );
        assert!(
            parse(prefix.as_bytes(), None, GitHashAlgorithm::Sha1, &mut || {
                true
            })
            .is_err()
        );
    }
    #[test]
    fn stopped_receipts_are_exact_and_cannot_claim_an_unused_future_recipe() {
        let input = form()
            + &format!(
                "&resolution={}:61:file:100644:file_0&resolution={}:62:ours",
                id(4),
                id(1)
            );
        let (command, recipes) = command(
            input.as_bytes(),
            BTreeMap::from([("file_0", b"exact".as_slice())]),
            GitHashAlgorithm::Sha1,
            &mut || true,
        )
        .unwrap();
        let outcome = RebasePreparation::Stopped {
            request: command.inputs,
            original: id(1),
            completed: vec![RebaseStep {
                original: id(4),
                rewritten: id(5),
                tree: id(6),
                kind: RebaseStepKind::Replayed,
            }],
            reason: RebaseStop::Conflicted(vec![]),
        };
        let receipt = RebaseResolvedStep {
            original: id(4),
            paths: vec![ResolvedPath {
                conflict: MergeConflict {
                    path: b"a".to_vec(),
                    kind: ConflictKind::Content,
                    base: None,
                    ours: None,
                    theirs: None,
                },
                choice: ResolutionKind::File,
                result: Some(MergeEntry {
                    name: b"a".to_vec(),
                    mode: 0o100644,
                    oid: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"exact"),
                }),
            }],
        };
        validate(
            &command,
            &outcome,
            &recipes,
            &[receipt.clone()],
            &mut || true,
        )
        .unwrap();
        let mut wrong = receipt.clone();
        wrong.paths[0].result.as_mut().unwrap().oid = id(7);
        assert!(validate(&command, &outcome, &recipes, &[wrong], &mut || true).is_err());
        let mut wrong = receipt.clone();
        wrong.paths[0].result.as_mut().unwrap().mode = 0o100755;
        assert!(validate(&command, &outcome, &recipes, &[wrong], &mut || true).is_err());
        let mut wrong = receipt;
        wrong.original = id(1);
        assert!(validate(&command, &outcome, &recipes, &[wrong], &mut || true).is_err());
        assert!(validate(&command, &outcome, &recipes, &[], &mut || true).is_err());
    }
}
