use crate::publication_support::quote;
use fgit_identity::agent_credential_id;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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

pub(super) fn read(path: &Path) -> Result<Vec<u8>, String> {
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

pub(super) fn generate(path: &Path, out: &mut impl Write) -> Result<u8, String> {
    let token = fgit_node::agent_credentials::generate_agent_credential_token();
    let token = validate(token.as_bytes())?;
    let id = agent_credential_id(token).map_err(|error| error.to_string())?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create new private token file: {error}"))?;
    file.write_all(token).and_then(|()| file.write_all(b"\n")).and_then(|()| file.sync_all())
        .map_err(|error| format!("new token file could not be completely written and synced: {error}; inspect the file before retrying"))?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent).and_then(|directory| directory.sync_all())
            .map_err(|error| format!("token file written but its directory could not be synced: {error}; inspect the file before retrying"))?;
    }
    let report = format!(
        "{{\"type\":\"agent_credential_token\",\"schema_version\":1,\"credential_id\":{},\"output\":{},\"created\":true}}",
        quote(&id.to_string()),
        quote(&path.to_string_lossy())
    );
    writeln!(out, "{report}")
        .and_then(|()| out.flush())
        .map_err(|error| format!("token file created; receipt output failed: {error}"))?;
    Ok(0)
}
