use crate::publication_support::quote;
use fgit_identity::agent_credential_id;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub(super) use fgit_cli::agent_credential_token::read;

pub(super) fn generate(path: &Path, out: &mut impl Write) -> Result<u8, String> {
    let token = fgit_node::agent_credentials::generate_agent_credential_token();
    let token = token.as_bytes();
    if !fgit_node::agent_credentials::valid_agent_credential_token(token) {
        return Err("generated agent token has an invalid format".into());
    }
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
