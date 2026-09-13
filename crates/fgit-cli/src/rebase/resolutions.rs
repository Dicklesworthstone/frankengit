//! Bounded local intake and deterministic receipts for explicit rebase choices.
use super::*;
use fgit_forge::preparation::rebase::resolutions::validate_rebase_resolutions;
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice, ResolutionKind};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::io::Read;

pub(super) fn parse(
    arguments: &[(&str, &str)],
    format: GitHashAlgorithm,
    limits: PreparationLimits,
) -> Result<Vec<RebaseCommitResolution>, String> {
    limits.validate().map_err(|e| e.to_string())?;
    if arguments.len() > limits.max_conflicts {
        return Err("too many rebase resolution paths".into());
    }
    let mut grouped = BTreeMap::<GitOid, Vec<ConflictResolution>>::new();
    let mut files = Vec::new();
    for (flag, input) in arguments {
        let mut pieces = input.splitn(4, ':');
        let original = parse_oid(pieces.next().ok_or("missing original commit")?)?;
        if original.is_zero() || original.algorithm() != format {
            return Err("resolution original must use the pinned native hash domain".into());
        }
        let path = unhex(
            pieces.next().ok_or("missing resolution path hex")?,
            limits.max_path_bytes,
        )?;
        let selection = pieces.next().ok_or("missing resolution choice")?;
        let file = pieces.next();
        let choice = match (*flag, selection, file) {
            ("--resolve", "base", None) => ResolutionChoice::Base,
            ("--resolve", "ours", None) => ResolutionChoice::Ours,
            ("--resolve", "theirs", None) => ResolutionChoice::Theirs,
            ("--resolve", "delete", None) => ResolutionChoice::Delete,
            ("--resolve-file", "100644" | "100755", Some(path)) if !path.is_empty() && path.len() <= 4096 => {
                files.push((original, grouped.get(&original).map_or(0, Vec::len), PathBuf::from(path)));
                ResolutionChoice::File { mode: if selection == "100644" { 0o100644 } else { 0o100755 }, bytes: Vec::new() }
            }
            _ => return Err("expected original:path-hex:base|ours|theirs|delete or original:path-hex:100644|100755:file".into()),
        };
        grouped
            .entry(original)
            .or_default()
            .push(ConflictResolution { path, choice });
    }
    let mut recipes: Vec<_> = grouped
        .into_iter()
        .map(|(original, paths)| RebaseCommitResolution { original, paths })
        .collect();
    // Validate duplicate/overlapping/traversing paths and counts before opening
    // any local content file. Files cannot alter the original/path binding.
    validate_rebase_resolutions(format, limits, &recipes).map_err(|e| e.to_string())?;
    let mut remaining = limits.max_output_bytes;
    for recipe in &recipes {
        for resolution in &recipe.paths {
            remaining = remaining
                .checked_sub(resolution.path.len())
                .ok_or("resolution byte budget exceeded")?;
        }
    }
    for (original, index, path) in files {
        let limit = remaining.min(limits.max_text_bytes);
        let before = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !before.file_type().is_file() || before.len() > limit as u64 {
            return Err(
                "resolution input must be a bounded regular file, not a link or device".into(),
            );
        }
        let file =
            std::fs::File::open(&path).map_err(|e| format!("cannot open resolution file: {e}"))?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.len() > limit as u64 {
            return Err("resolution input must be a bounded regular file".into());
        }
        let mut body = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| e.to_string())?;
        if body.len() > limit {
            return Err("resolution file grew beyond its byte budget".into());
        }
        remaining -= body.len();
        let recipe = recipes
            .iter_mut()
            .find(|r| r.original == original)
            .ok_or("resolution binding missing")?;
        let ResolutionChoice::File { bytes, .. } = &mut recipe.paths[index].choice else {
            return Err("resolution file binding mismatch".into());
        };
        *bytes = body;
    }
    validate_rebase_resolutions(format, limits, &recipes).map_err(|e| e.to_string())?;
    Ok(recipes)
}

pub(super) fn render(
    recipes: &[RebaseCommitResolution],
    resolved: &[RebaseResolvedStep],
    preparation: &RebasePreparation,
) -> Result<String, String> {
    let (steps, stopped) = match preparation {
        RebasePreparation::Clean(plan) => (plan.steps.as_slice(), None),
        RebasePreparation::Stopped {
            original,
            completed,
            ..
        } => (completed.as_slice(), Some(*original)),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut output = Vec::new();
    for row in resolved {
        if !seen.insert(row.original)
            || !steps.iter().any(|s| s.original == row.original) && stopped != Some(row.original)
        {
            return Err("resolution receipt has an unrelated or duplicate original commit".into());
        }
        let recipe = recipes
            .iter()
            .find(|r| r.original == row.original)
            .ok_or("unrequested resolution receipt")?;
        if row.paths.len() != recipe.paths.len() || row.paths.is_empty() {
            return Err("resolution receipt path count mismatch".into());
        }
        let mut paths = Vec::new();
        let mut previous: Option<&[u8]> = None;
        for decision in &row.paths {
            let path = decision.conflict.path.as_slice();
            if previous.is_some_and(|p| p >= path) {
                return Err("resolution receipt paths are not unique and ordered".into());
            }
            previous = Some(path);
            let choice = recipe
                .paths
                .iter()
                .find(|r| r.path == path)
                .ok_or("unrequested resolution path")?;
            if choice.choice.kind() != decision.choice {
                return Err("resolution choice receipt mismatch".into());
            }
            let result = decision.result.as_ref().map_or_else(
                || "null".into(),
                |entry| {
                    format!(
                        "{{\"mode\":{},\"oid\":{}}}",
                        quote(&format!("{:06o}", entry.mode)),
                        quote(&entry.oid.to_string())
                    )
                },
            );
            let kind = match decision.choice {
                ResolutionKind::Base => "base",
                ResolutionKind::Ours => "ours",
                ResolutionKind::Theirs => "theirs",
                ResolutionKind::Delete => "delete",
                ResolutionKind::File => "file",
            };
            paths.push(format!(
                "{{\"conflict\":{},\"choice\":{},\"result\":{result}}}",
                render_conflict(&decision.conflict),
                quote(kind)
            ));
        }
        output.push(format!(
            "{{\"original\":{},\"paths\":[{}]}}",
            quote(&row.original.to_string()),
            paths.join(",")
        ));
    }
    if matches!(preparation, RebasePreparation::Clean(_)) && seen.len() != recipes.len() {
        return Err("clean rebase omitted a requested resolution".into());
    }
    Ok(output.join(","))
}

#[cfg(test)]
mod tests;
