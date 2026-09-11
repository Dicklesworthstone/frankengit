//! Explicit replay-conflict choices. Host files are bounded local inputs, never
//! instructions or authority. Core resolution owns path and conflict semantics.
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::{MergeEntry, PreparationLimits};
use fgit_forge::preparation::resolution::{
    ConflictResolution, ResolvedPath, ResolutionChoice, ResolutionKind, validate_resolutions,
};
use fgit_types::GitHashAlgorithm;
use super::{quote, render_conflict, unhex};

pub(super) struct LocalResolution {
    path: Vec<u8>,
    choice: LocalChoice,
}
enum LocalChoice {
    Side(ResolutionChoice),
    File { mode: u32, source: PathBuf },
}

pub(super) fn is_choice(flag: &str) -> bool {
    matches!(flag, "--ours" | "--ours-hex" | "--theirs" | "--theirs-hex"
        | "--base" | "--base-hex" | "--delete" | "--delete-hex" | "--file" | "--file-hex")
}

pub(super) fn parse_choice(flag: &str, args: &[String], at: &mut usize) -> Result<LocalResolution, String> {
    let raw = args.get(*at).ok_or_else(|| format!("missing repository path for {flag}"))?;
    *at += 1;
    let path = if flag.ends_with("-hex") { unhex(raw, 4096)? } else {
        if raw.len() > 4096 { return Err("resolution path exceeds 4096 bytes".into()); }
        raw.as_bytes().to_vec()
    };
    let choice = match flag.trim_end_matches("-hex") {
        "--ours" => LocalChoice::Side(ResolutionChoice::Ours),
        "--theirs" => LocalChoice::Side(ResolutionChoice::Theirs),
        "--base" => LocalChoice::Side(ResolutionChoice::Base),
        "--delete" => LocalChoice::Side(ResolutionChoice::Delete),
        "--file" => {
            let mode = match args.get(*at).map(String::as_str) {
                Some("100644") => 0o100644, Some("100755") => 0o100755,
                _ => return Err("--file requires explicit mode 100644 or 100755".into()),
            };
            *at += 1;
            let source = args.get(*at).filter(|s| !s.is_empty() && s.len() <= 4096)
                .ok_or("--file requires a bounded local input filename")?;
            *at += 1;
            LocalChoice::File { mode, source: PathBuf::from(source.as_str()) }
        }
        _ => return Err("unknown conflict choice".into()),
    };
    Ok(LocalResolution { path, choice })
}

pub(super) fn validate_inputs(choices: &[LocalResolution], limits: PreparationLimits) -> Result<(), String> {
    if choices.len() > limits.max_conflicts { return Err("too many conflict choices".into()); }
    let shapes: Vec<_> = choices.iter().map(|item| ConflictResolution {
        path: item.path.clone(), choice: match &item.choice {
            LocalChoice::Side(choice) => choice.clone(),
            LocalChoice::File { mode, .. } => ResolutionChoice::File { mode: *mode, bytes: Vec::new() },
        },
    }).collect();
    validate_resolutions(&shapes, limits).map_err(|e| e.to_string())
}

pub(super) fn load(choices: &[LocalResolution], limits: PreparationLimits) -> Result<Vec<ConflictResolution>, String> {
    validate_inputs(choices, limits)?;
    let mut consumed = choices.iter().try_fold(0_usize, |sum, choice| sum.checked_add(choice.path.len()))
        .ok_or("resolution path byte overflow")?;
    let mut out = Vec::new();
    out.try_reserve(choices.len()).map_err(|_| "resolution allocation refused")?;
    for item in choices {
        let choice = match &item.choice {
            LocalChoice::Side(choice) => choice.clone(),
            LocalChoice::File { mode, source } => {
                let remaining = limits.max_output_bytes.checked_sub(consumed)
                    .ok_or("resolution input byte budget exhausted")?.min(limits.max_text_bytes);
                let bytes = read_file(source, remaining)?;
                consumed = consumed.checked_add(bytes.len()).ok_or("resolution input byte overflow")?;
                ResolutionChoice::File { mode: *mode, bytes }
            }
        };
        out.push(ConflictResolution { path: item.path.clone(), choice });
    }
    validate_resolutions(&out, limits).map_err(|e| e.to_string())?;
    Ok(out)
}

fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    // Same trusted local-filesystem boundary as existing artifact intake. This
    // refuses a final symlink/device; it does not claim hostile-host isolation.
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("resolution input metadata: {e}"))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("resolution input must be a bounded regular file, not a symlink or device".into());
    }
    let mut file = File::open(path).map_err(|e| format!("resolution input open: {e}"))?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() > limit as u64 { return Err("resolution input changed type or exceeded limit".into()); }
    let mut out = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = match file.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("resolution input read: {error}")),
        };
        if count == 0 { break; }
        if count > limit.saturating_sub(out.len()) { return Err("resolution input grew beyond its byte budget".into()); }
        out.try_reserve(count).map_err(|_| "resolution input allocation refused")?;
        out.extend_from_slice(&buffer[..count]);
    }
    Ok(out)
}

fn kind_name(kind: ResolutionKind) -> &'static str {
    match kind { ResolutionKind::Base => "base", ResolutionKind::Ours => "ours",
        ResolutionKind::Theirs => "theirs", ResolutionKind::Delete => "delete", ResolutionKind::File => "file" }
}
fn entry_json(entry: Option<&MergeEntry>) -> String {
    entry.map_or_else(|| "null".into(), |e| format!("{{\"mode\":{},\"oid\":{}}}", e.mode, quote(&e.oid.to_string())))
}

/// Cross-check every result against the supplied bytes/side before exposing a
/// bundle. The receipt remains derived review information, never an approval.
pub(super) fn decorate_receipt(
    receipt: String, requested: &[ConflictResolution], actual: &[ResolvedPath], format: GitHashAlgorithm,
) -> Result<String, String> {
    const PREFIX: &str = "{\"type\":\"commit_replay_preparation\"";
    if !receipt.starts_with(PREFIX) || !receipt.ends_with('}') || actual.is_empty()
        || actual.len() != requested.len()
        || !actual.windows(2).all(|pair| pair[0].conflict.path < pair[1].conflict.path)
    { return Err("resolution receipt shape mismatch".into()); }
    let choices: BTreeMap<_, _> = requested.iter().map(|r| (r.path.as_slice(), &r.choice)).collect();
    if choices.len() != requested.len() { return Err("duplicate requested resolution in receipt".into()); }
    let mut rows = Vec::new();
    for row in actual {
        let choice = choices.get(row.conflict.path.as_slice()).ok_or("unsolicited resolution path")?;
        let name = row.conflict.path.rsplit(|b| *b == b'/').next().filter(|name| !name.is_empty())
            .ok_or("invalid resolution path")?;
        if choice.kind() != row.choice { return Err("resolution choice mismatch".into()); }
        let expected = match choice {
            ResolutionChoice::Base => Some(row.conflict.base.clone().ok_or("missing base side")?),
            ResolutionChoice::Ours => Some(row.conflict.ours.clone().ok_or("missing target side")?),
            ResolutionChoice::Theirs => Some(row.conflict.theirs.clone().ok_or("missing applied side")?),
            ResolutionChoice::Delete => None,
            ResolutionChoice::File { mode, bytes } => Some(MergeEntry {
                name: name.to_vec(), mode: *mode, oid: git_object_id(format, GitObjectKind::Blob, bytes),
            }),
        };
        if row.result != expected || [&row.conflict.base, &row.conflict.ours, &row.conflict.theirs, &row.result]
            .iter().filter_map(|entry| entry.as_ref()).any(|entry|
                entry.name.as_slice() != name || entry.oid.is_zero() || entry.oid.algorithm() != format)
        { return Err("resolution result differs from the selected side or exact file bytes".into()); }
        rows.push(format!("{{\"conflict\":{},\"choice\":{},\"result\":{}}}",
            render_conflict(&row.conflict), quote(kind_name(row.choice)), entry_json(row.result.as_ref())));
    }
    let mut output = receipt.replacen(PREFIX, "{\"type\":\"commit_replay_resolution\"", 1);
    output.pop();
    output.push_str(&format!(",\"resolutions\":[{}]}}", rows.join(",")));
    if output.len() > 4 * 1024 * 1024 { return Err("resolution receipt exceeds output bound".into()); }
    Ok(output)
}

#[cfg(test)]
mod tests;
