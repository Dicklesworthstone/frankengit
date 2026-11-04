//! Shared private-file input for canonical sponsored-agent credentials.
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const TOKEN_BYTES: usize = 72;

fn validate(bytes: &[u8]) -> Result<&[u8], String> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.len() != TOKEN_BYTES
        || !bytes.starts_with(b"fgagent_")
        || !bytes[8..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(
            "token file must contain fgagent_ plus 64 lowercase hex digits and optionally one LF"
                .into(),
        );
    }
    Ok(bytes)
}

fn metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.is_file() || metadata.len() > (TOKEN_BYTES + 1) as u64 {
        return Err("agent token must be a bounded regular file, not a symlink or device".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "agent token file must have no group/world permissions (use chmod 600)".into(),
            );
        }
    }
    Ok(())
}

/// Read one bounded private credential file. The optional final LF is removed.
/// Error messages never contain file contents or bearer bytes.
///
/// The launch operator owns the stable file and its parent directories.
///
/// # Errors
///
/// Refuses symlinks, non-regular or oversized files, group/world access on Unix,
/// malformed tokens, or failed filesystem reads.
pub fn read(path: &Path) -> Result<Vec<u8>, String> {
    // The command requires a stable operator-controlled file. Neither following
    // symlinks nor accepting an oversized file is part of that profile.
    metadata(
        &fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect token file: {error}"))?,
    )?;
    let file = File::open(path).map_err(|error| format!("cannot open token file: {error}"))?;
    metadata(
        &file
            .metadata()
            .map_err(|error| format!("cannot inspect opened token: {error}"))?,
    )?;
    let mut bytes = Vec::with_capacity(TOKEN_BYTES + 2);
    file.take((TOKEN_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read token file: {error}"))?;
    Ok(validate(&bytes)?.to_vec())
}
