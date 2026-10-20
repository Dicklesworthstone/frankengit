//! Offline saved-result reads. No tool execution, source selection or repository writes.
use super::saved::{MAX_BUNDLE, MAX_FAILURE, MAX_RECEIPT, TERMINAL_MAGIC};
use super::{MAX_REQUEST, REQUEST_MAGIC, Refusal};
use fgit_crypto::sha256_digest;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const USAGE: &str = "usage: fg workspace recover <absolute-invocation-directory> --trusted-local --request-id <original-64-lowercase-hex> [--terminal-id <retained-64-lowercase-hex>] [--output <absolute-new-bundle-path>]\nReads saved results without executing tools or publishing repository refs. Keep the original request ID independently; local digests detect corruption, not malicious rewriting or rollback. Retain the whole private invocation directory.";

#[derive(Debug)]
struct Saved {
    terminal_id: [u8; 32],
    bundle: Vec<u8>,
    receipt: String,
}

fn read_saved(
    directory: &Path,
    expected_request: [u8; 32],
    expected_terminal: Option<[u8; 32]>,
) -> Result<Saved, String> {
    check_directory(directory)?;
    let request = read_private(&directory.join("request"), MAX_REQUEST + 48)?;
    if sha256_digest(&request) != expected_request {
        return Err("workspace request identity mismatch".into());
    }
    unframe(&request, REQUEST_MAGIC, MAX_REQUEST)?;
    let path = directory.join("terminal");
    if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Err("workspace invocation unresolved: no complete terminal record; execution may have occurred, do not rerun the tool".into());
    }
    let terminal = read_private(&path, MAX_REQUEST + 48)?;
    let terminal_id = sha256_digest(&terminal);
    if expected_terminal.is_some_and(|id| id != terminal_id) {
        return Err("workspace terminal identity mismatch".into());
    }
    let payload = unframe(&terminal, TERMINAL_MAGIC, MAX_REQUEST)?;
    let mut fields = Reader(payload);
    let state = fields.next()?;
    if fields.next()? != expected_request {
        return Err("terminal belongs to another workspace invocation".into());
    }
    if state == b"failed" {
        let detail =
            std::str::from_utf8(fields.next()?).map_err(|_| "invalid failed-result text")?;
        if detail.len() > MAX_FAILURE || !fields.0.is_empty() {
            return Err("invalid failed-result record".into());
        }
        return Err(format!(
            "workspace invocation failed; external effects may have occurred; do not rerun: {detail}"
        ));
    }
    if state != b"ready" {
        return Err("unknown workspace terminal state".into());
    }
    let bundle_len = number(fields.next()?)?;
    let bundle_digest = hash(fields.next()?)?;
    let receipt_len = number(fields.next()?)?;
    let receipt_digest = hash(fields.next()?)?;
    if !fields.0.is_empty() {
        return Err("trailing workspace terminal fields".into());
    }
    if bundle_len > MAX_BUNDLE as u64 || receipt_len > MAX_RECEIPT as u64 {
        return Err("saved-result allowance exceeded".into());
    }
    let bundle = read_private(&directory.join("candidate.bundle"), bundle_len as usize)?;
    let receipt = read_private(&directory.join("receipt.json"), receipt_len as usize)?;
    if bundle.len() as u64 != bundle_len
        || sha256_digest(&bundle) != bundle_digest
        || receipt.len() as u64 != receipt_len
        || sha256_digest(&receipt) != receipt_digest
    {
        return Err("workspace saved-result length or digest mismatch".into());
    }
    let receipt = String::from_utf8(receipt).map_err(|_| "invalid saved receipt UTF-8")?;
    // A reader can observe a complete terminal just before the writer's final
    // directory fence. Establish its own durability instead of assuming that fence.
    File::open(&path)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(Saved {
        terminal_id,
        bundle,
        receipt,
    })
}

fn check_directory(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_dir() || m.mode() & 0o077 != 0 {
        return Err(Refusal::InvalidStorage.to_string());
    }
    Ok(())
}
fn read_private(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let named = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !named.is_file() || named.mode() & 0o077 != 0 || named.nlink() != 1 {
        return Err(Refusal::InvalidStorage.to_string());
    }
    if named.len() > maximum as u64 {
        return Err("workspace record exceeds its finite read limit".into());
    }
    let file = File::open(path).map_err(|e| e.to_string())?;
    let actual = file.metadata().map_err(|e| e.to_string())?;
    if (actual.dev(), actual.ino(), actual.len()) != (named.dev(), named.ino(), named.len()) {
        return Err("workspace record changed during open".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > maximum || bytes.len() as u64 != actual.len() {
        return Err("workspace record changed or exceeds read limit".into());
    }
    Ok(bytes)
}
fn unframe<'a>(bytes: &'a [u8], magic: &[u8; 8], maximum: usize) -> Result<&'a [u8], String> {
    if bytes.len() < 48 || bytes.get(..8) != Some(magic) {
        return Err("invalid workspace record version or truncated header".into());
    }
    let length = number(&bytes[8..16])?;
    if length > maximum as u64 || length.checked_add(48) != Some(bytes.len() as u64) {
        return Err("invalid workspace record length".into());
    }
    let end = bytes.len() - 32;
    if sha256_digest(&bytes[..end]) != bytes[end..] {
        return Err("workspace record checksum mismatch".into());
    }
    Ok(&bytes[16..end])
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn next(&mut self) -> Result<&'a [u8], String> {
        let raw = self.0.get(..8).ok_or("truncated workspace field")?;
        let count = usize::try_from(number(raw)?).map_err(|_| "workspace field overflow")?;
        let end = 8usize
            .checked_add(count)
            .ok_or("workspace field overflow")?;
        let value = self.0.get(8..end).ok_or("truncated workspace field")?;
        self.0 = &self.0[end..];
        Ok(value)
    }
}
fn number(bytes: &[u8]) -> Result<u64, String> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| "invalid record integer width")?,
    ))
}
fn hash(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "invalid record digest width".into())
}
fn parse_hash(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected 64 lowercase hexadecimal digits".into());
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

pub(crate) fn recover(arguments: &[String]) -> Result<(), String> {
    if arguments.len() < 5 || arguments[0] != "recover" {
        return Err(USAGE.into());
    }
    let directory = PathBuf::from(&arguments[1]);
    if !directory.is_absolute() {
        return Err("invocation directory must be absolute".into());
    }
    let (mut request, mut terminal, mut output) = (None, None, None);
    let mut trusted = false;
    let mut i = 2;
    while i < arguments.len() {
        let flag = &arguments[i];
        i += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate trust flag".into());
            }
            trusted = true;
            continue;
        }
        let value = arguments.get(i).ok_or("missing recovery option value")?;
        i += 1;
        match flag.as_str() {
            "--request-id" => super::super::set_once(&mut request, parse_hash(value)?, flag)?,
            "--terminal-id" => super::super::set_once(&mut terminal, parse_hash(value)?, flag)?,
            "--output" => super::super::set_once(&mut output, PathBuf::from(value), flag)?,
            _ => return Err(format!("unknown recovery option {flag}")),
        }
    }
    if !trusted {
        return Err("--trusted-local is required for local invocation recovery".into());
    }
    let request =
        request.ok_or("--request-id must name the independently retained original request")?;
    let saved = read_saved(&directory, request, terminal)?;
    if let Some(path) = &output {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err("recovery output must be an absolute new filename".into());
        }
        check_directory(path.parent().ok_or("recovery output has no parent")?)?;
        super::super::publish_bundle(path, b"", &saved.bundle)?;
    }
    // The original receipt is returned as escaped text, not injected JSON. It
    // is never interpreted as authorization, commands, or filesystem paths.
    let text = format!(
        "{{\"type\":\"workspace_recovery\",\"state\":\"ready\",\"request_sha256\":\"{}\",\"terminal_sha256\":\"{}\",\"reexecuted\":false,\"published_to_repository\":false,\"receipt_json\":{},\"output\":{}}}",
        super::super::hex(&request),
        super::super::hex(&saved.terminal_id),
        super::super::quote(&saved.receipt),
        output.as_ref().map_or_else(
            || "null".into(),
            |p| super::super::quote(&p.to_string_lossy())
        )
    );
    writeln!(std::io::stdout().lock(), "{text}")
        .map_err(|e| format!("recovery output may already be published; receipt write failed: {e}"))
}
#[cfg(test)]
mod tests;
