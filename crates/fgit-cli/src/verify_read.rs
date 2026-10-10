//! Verify complete native blob content against an independently supplied head.
//! Fetching an envelope never establishes the head that the user trusts.

mod http;
mod options;
#[cfg(test)]
mod tests;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use fgit_types::RepositoryAuthorityHeadId;
use fgit_verified_read::blob::{
    MAX_VERIFIED_BLOB_FRAME_BYTES, decode_verified_blob_envelope, verify_blob_against_head_while,
};
use options::{Input, Options};

const USAGE: &str = "usage: fg [--timeout-secs <seconds>] verify-read
  (--input <proof-file> | --url <http://numeric-loopback:port/repository-route>)
  --trusted-head <alg:algorithm:lowercase-digest>
  (--ref <full-ref> | --ref-hex <raw-ref-hex>)
  (--path <relative-path> | --path-hex <raw-path-hex>)
  [--token-file <file>] [--output <new-file>]

The head commitment MUST come from an independently trusted source. The server's
reply cannot choose it. Verification checks that head, its selected configuration,
the exact reference inclusion proof, and every native commit/tree/blob identity
along the requested path. Whole proof and object verification precede output.

URL mode uses the authenticated source-read endpoint, requires --token-file,
and accepts numeric loopback HTTP only, matching fg serve-http. No redirects,
DNS, HTTPS downgrade, ambient credentials, or automatic head discovery.
Input mode reads a bounded regular canonical proof file and uses no network.

Default output is the exact verified blob bytes on stdout. --output publishes a
new regular file without replacing an existing path, then emits a JSON receipt.
Symlink blobs are emitted as their literal target bytes; no symlink is followed
or created. Current-head requests fail if the supplied pin is stale. Legacy
root-layout repositories cannot serve these proofs; select --root-layout
ref-merkle-v1 explicitly when creating a NEW repository with fg init.
Limits: 16 MiB blob, 16 MiB commit/tree proof data, 64 path components, 100,000
tree entries. HTTP request targets are limited to 4,096 encoded bytes, including
the route, hex reference/path, and head pin; oversize URLs refuse before connect.
Exit 0: verified and written; 2: typed refusal or output failure.";

#[derive(Debug)]
pub(super) struct Error {
    kind: &'static str,
    detail: String,
    verified: bool,
    output_state: &'static str,
}
impl Error {
    fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            verified: false,
            output_state: "none",
        }
    }
    fn after_verification(
        kind: &'static str,
        detail: impl Into<String>,
        output_state: &'static str,
    ) -> Self {
        Self {
            kind,
            detail: detail.into(),
            verified: true,
            output_state,
        }
    }
}
pub(super) fn error_json(error: &Error) -> String {
    format!(
        "{{\"type\":\"verified_read_error\",\"schema_version\":1,\"verified\":{},\"output_state\":{},\"code\":{},\"error\":{}}}",
        error.verified,
        crate::publication_support::quote(error.output_state),
        crate::publication_support::quote(error.kind),
        crate::publication_support::quote(&error.detail)
    )
}

pub(super) fn run(arguments: &[String]) -> Result<(), Error> {
    if arguments == ["--help"] {
        return writeln!(std::io::stdout().lock(), "{USAGE}")
            .map_err(|error| Error::new("output_failed", error.to_string()));
    }
    let options = options::parse(arguments)?;
    let deadline = Instant::now()
        .checked_add(fgit_cli::command_timeout_duration())
        .ok_or_else(|| Error::new("invalid_deadline", "command timeout is not representable"))?;
    let bytes = match &options.input {
        Input::File(path) => read_regular(
            path,
            MAX_VERIFIED_BLOB_FRAME_BYTES,
            "proof_file",
            false,
            deadline,
        )?,
        Input::Http(url) => {
            let token = token(
                options.token.as_deref().ok_or_else(|| {
                    Error::new("token_required", "HTTP proof fetch requires --token-file")
                })?,
                deadline,
            )?;
            http::fetch(url, &token, &options, deadline)?
        }
    };
    publish_verified(&options, &bytes, deadline, &mut std::io::stdout().lock())
}

fn publish_verified(
    options: &Options,
    bytes: &[u8],
    deadline: Instant,
    output: &mut impl Write,
) -> Result<(), Error> {
    publish_verified_while(options, bytes, &|| Instant::now() < deadline, output)
}

fn publish_verified_while(
    options: &Options,
    bytes: &[u8],
    live: &dyn Fn() -> bool,
    output: &mut impl Write,
) -> Result<(), Error> {
    if !live() {
        return Err(Error::new("deadline_exceeded", "proof deadline expired"));
    }
    let envelope = decode_verified_blob_envelope(bytes)
        .map_err(|error| Error::new("invalid_envelope", error.to_string()))?;
    let verified = verify_blob_against_head_while(
        options.head,
        &options.reference,
        &options.path,
        &envelope,
        live,
    )
    .map_err(|error| Error::new("verification_refused", error.to_string()))?;
    if !live() {
        return Err(Error::after_verification(
            "deadline_exceeded",
            "proof deadline expired before output",
            "not_published",
        ));
    }
    if let Some(destination) = &options.output {
        fgit_cli::write_new_export_while(destination, verified.bytes, live).map_err(|error| {
            let state = if matches!(error, fgit_cli::CliRefusal::ExportVisibleCleanup { .. }) {
                "published"
            } else {
                "not_published"
            };
            let code = match &error {
                fgit_cli::CliRefusal::ExportFile { source, .. }
                | fgit_cli::CliRefusal::ExportFileCleanup { source, .. }
                    if source.kind() == std::io::ErrorKind::TimedOut =>
                {
                    "deadline_exceeded"
                }
                _ => "output_failed",
            };
            Error::after_verification(code, error.to_string(), state)
        })?;
        output_checkpoint(live, "published")?;
        writeln!(output,
            "{{\"type\":\"verified_blob\",\"schema_version\":1,\"verified\":true,\"output_state\":\"published\",\"source_head\":{},\"source_commit\":{},\"object_id\":{},\"kind\":{},\"bytes\":{},\"output\":{}}}",
            crate::publication_support::quote(&head_token(verified.source_head)),
            crate::publication_support::quote(&verified.source_commit.to_string()),
            crate::publication_support::quote(&verified.object_id.to_string()),
            crate::publication_support::quote(verified.kind.as_str()), verified.bytes.len(),
            crate::publication_support::quote(&destination.display().to_string()))
            .map_err(|error| Error::after_verification("output_receipt_failed", format!("verified file was published; receipt write failed: {error}"), "published"))?;
        output_checkpoint(live, "published")?;
        output.flush().map_err(|error| {
            Error::after_verification(
                "output_receipt_failed",
                format!("verified file was published; receipt flush failed: {error}"),
                "published",
            )
        })?;
        output_checkpoint(live, "published")?;
    } else {
        for chunk in verified.bytes.chunks(64 * 1024) {
            output_checkpoint(live, "partial_or_unwritten")?;
            output.write_all(chunk).map_err(|error| {
                Error::after_verification(
                    "output_failed",
                    error.to_string(),
                    "partial_or_unwritten",
                )
            })?;
        }
        output_checkpoint(live, "partial_or_unwritten")?;
        output.flush().map_err(|error| {
            Error::after_verification("output_failed", error.to_string(), "partial_or_unwritten")
        })?;
        output_checkpoint(live, "partial_or_unwritten")?;
    }
    Ok(())
}

fn output_checkpoint(live: &dyn Fn() -> bool, state: &'static str) -> Result<(), Error> {
    if live() {
        Ok(())
    } else {
        Err(Error::after_verification(
            "deadline_exceeded",
            "verified output exceeded the command deadline",
            state,
        ))
    }
}

fn read_regular(
    path: &Path,
    maximum: usize,
    kind: &'static str,
    private: bool,
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| Error::new(kind, error.to_string()))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(Error::new(
            kind,
            "input must be a bounded regular file, not a symlink or device",
        ));
    }
    let mut file = File::open(path).map_err(|error| Error::new(kind, error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| Error::new(kind, error.to_string()))?;
    stable_file(&metadata, &opened, private, kind)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(opened.len() as usize)
        .map_err(|_| Error::new(kind, "cannot reserve bounded regular file"))?;
    let mut chunk = [0; 64 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(Error::new(
                "deadline_exceeded",
                "regular file read exceeded the command deadline",
            ));
        }
        let wanted = (maximum + 1 - bytes.len()).min(chunk.len());
        let length = file
            .read(&mut chunk[..wanted])
            .map_err(|error| Error::new(kind, error.to_string()))?;
        if length == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..length]);
        if bytes.len() > maximum {
            return Err(Error::new(kind, "input exceeded its byte bound"));
        }
    }
    stable_file(
        &opened,
        &file
            .metadata()
            .map_err(|error| Error::new(kind, error.to_string()))?,
        private,
        kind,
    )?;
    stable_file(
        &opened,
        &fs::symlink_metadata(path).map_err(|error| Error::new(kind, error.to_string()))?,
        private,
        kind,
    )?;
    if bytes.len() as u64 != opened.len() {
        return Err(Error::new(kind, "input changed while reading"));
    }
    Ok(bytes)
}

fn stable_file(
    before: &fs::Metadata,
    after: &fs::Metadata,
    private: bool,
    kind: &'static str,
) -> Result<(), Error> {
    if !before.is_file()
        || !after.is_file()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(Error::new(kind, "input changed while reading"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || (private && (before.mode() & 0o077 != 0 || after.mode() & 0o077 != 0))
        {
            return Err(Error::new(
                kind,
                "input identity changed or credential file is not private (mode 0600 required)",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}

fn token(path: &Path, deadline: Instant) -> Result<String, Error> {
    let bytes = read_regular(path, 66, "credential_file", true, deadline)?;
    let token = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(&bytes);
    if token.len() != 64
        || !token
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(Error::new(
            "credential_file",
            "token file must contain 64 lowercase hexadecimal characters and at most one final newline",
        ));
    }
    String::from_utf8(token.to_vec())
        .map_err(|_| Error::new("credential_file", "invalid token encoding"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
