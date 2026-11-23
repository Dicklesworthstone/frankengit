//! Bind Git's synthetic submodule diff images to verified parent-tree pointers.
//! No operation here loads, hashes as a blob, or follows a foreign commit.

use fgit_forge::patch::{FileChange, FilePatch, PatchError, PatchLimits, UnifiedPatch};
use fgit_types::{GitHashAlgorithm, GitOid};

const MODE: u32 = 0o160000;
const PREFIX: &[u8] = b"Subproject commit ";

const fn invalid(reason: &'static str) -> PatchError {
    PatchError::Syntax { line: 1, reason }
}

fn identity(bytes: &[u8], format: GitHashAlgorithm) -> Result<Option<GitOid>, PatchError> {
    if bytes.len() != format.digest_len() * 2
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(invalid(
            "gitlink index must use the repository's full native hash width",
        ));
    }
    if bytes.iter().all(|byte| *byte == b'0') {
        return Ok(None);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid gitlink identity"))?;
    GitOid::from_hex(format, text)
        .map(Some)
        .map_err(|_| invalid("invalid gitlink identity"))
}

fn identities(
    file: &FilePatch<'_>,
    format: GitHashAlgorithm,
) -> Result<(Option<GitOid>, Option<GitOid>), PatchError> {
    if !file.allows_gitlinks()
        || !file.is_gitlink()
        || file.renamed_from().is_some()
        || file.binary_hunks().is_some()
    {
        return Err(invalid(
            "gitlink requires the explicit pointer-edit profile",
        ));
    }
    let index = file
        .index()
        .ok_or_else(|| invalid("gitlink full index is required"))?;
    let old = identity(&index.old, format)?;
    let new = identity(&index.new, format)?;
    let shape = match file.change() {
        FileChange::Create => old.is_none() && new.is_some(),
        FileChange::Modify => old.is_some() && new.is_some(),
        FileChange::Delete => old.is_some() && new.is_none(),
    };
    if !shape {
        return Err(invalid("gitlink index presence disagrees with the edit"));
    }
    Ok((old, new))
}

/// All repository-domain checks finish before reading source bodies, including
/// ordinary files earlier in a mixed patch. A foreign-format pointer cannot be
/// mistaken for a prefix of a parent repository's native identity.
pub(super) fn preflight(
    patch: &UnifiedPatch<'_>,
    format: GitHashAlgorithm,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), PatchError> {
    for file in patch.files() {
        if cancelled() {
            return Err(PatchError::Cancelled);
        }
        if file.is_gitlink() {
            identities(file, format)?;
        }
    }
    Ok(())
}

/// Return the verified external target and its accounted synthetic output
/// length. The latter shares the patch's aggregate output budget with files.
pub(super) fn apply(
    file: &FilePatch<'_>,
    source: Option<GitOid>,
    format: GitHashAlgorithm,
    limits: PatchLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<(Option<GitOid>, usize), PatchError> {
    if cancelled() {
        return Err(PatchError::Cancelled);
    }
    let (old, new) = identities(file, format)?;
    if source != old {
        return Err(invalid(
            "gitlink old index does not match the selected source pointer",
        ));
    }
    let image = source.map(|oid| format!("Subproject commit {oid}\n").into_bytes());
    let output = file.apply(
        image.as_ref().map(|bytes| (MODE, bytes.as_slice())),
        limits,
        cancelled,
    )?;
    match output {
        None if new.is_none() => Ok((None, 0)),
        Some(output) if output.mode == MODE && new.is_some() => {
            let raw = output
                .content
                .strip_prefix(PREFIX)
                .and_then(|tail| tail.strip_suffix(b"\n"))
                .ok_or_else(|| invalid("gitlink result is not an exact subproject image"))?;
            let actual = identity(raw, format)?;
            if actual != new || actual.is_none() {
                return Err(invalid(
                    "gitlink new index does not match the exact result pointer",
                ));
            }
            Ok((actual, output.content.len()))
        }
        _ => Err(invalid(
            "gitlink result presence or mode disagrees with the edit",
        )),
    }
}
