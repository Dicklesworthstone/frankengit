//! Shared bounded artifact intake and terminal-receipt handling for local
//! workspace and merge publication. This module never opens repository state.

use fgit_authority::TerminalOutcome;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, TxId};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

pub(super) fn set_once<T>(slot: &mut Option<T>, value: T, field: &str) -> Result<(), String> {
    if slot.is_some() { return Err(format!("duplicate {field}")); }
    *slot = Some(value);
    Ok(())
}

pub(super) fn parse_oid(text: &str) -> Result<GitOid, String> {
    let format = match text.len() {
        40 => GitHashAlgorithm::Sha1,
        64 => GitHashAlgorithm::Sha256,
        _ => return Err("expected a 40- or 64-character native Git object ID".to_owned()),
    };
    let id = GitOid::from_hex(format, text).map_err(|error| error.to_string())?;
    if id.is_zero() { return Err("zero is not a commit ID".to_owned()); }
    Ok(id)
}

pub(super) fn read_bundle(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    // This local-operator profile requires a stable regular artifact under the
    // operator's control. It is not an adversarial host-filesystem boundary.
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("candidate bundle must be a bounded regular file, not a symlink or device".to_owned());
    }
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !opened.is_file() || opened.len() > limit as u64 {
        return Err("candidate bundle changed to a non-regular or oversized file".to_owned());
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = match file.read(&mut chunk) {
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        };
        if n == 0 { break; }
        if n > limit.saturating_sub(bytes.len()) {
            return Err("candidate bundle grew beyond its input limit".to_owned());
        }
        bytes.try_reserve(n).map_err(|_| "candidate bundle allocation refused")?;
        bytes.extend_from_slice(&chunk[..n]);
    }
    if bytes.is_empty() { return Err("candidate bundle is empty".to_owned()); }
    Ok(bytes)
}

pub(super) fn describe(tx_id: TxId, terminal: &TerminalOutcome) -> String {
    match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } =>
            format!("transaction {tx_id} is committed as {repository_commit_id}"),
        DecisionOutcome::Refused { code, refusal_record_id } =>
            format!("transaction {tx_id} has canonical refusal {code:?} ({refusal_record_id})"),
    }
}

pub(super) fn write_terminal_receipt(
    output: &mut impl Write, receipt: &str, tx_id: TxId, terminal: &TerminalOutcome,
) -> Result<(), String> {
    writeln!(output, "{receipt}").and_then(|()| output.flush()).map_err(|error|
        format!("{}; receipt output failed: {error}", describe(tx_id, terminal)))
}

pub(super) fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // Keep untrusted text lossless after JSON decoding without letting
            // control or bidi-formatting characters alter terminal presentation.
            // Ordinary multilingual text is preserved, not normalized or stripped.
            c if c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}'
                | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
                out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_strings_preserve_unicode_and_escape_controls() {
        assert_eq!(quote("quoted\"\n\t\\é"), "\"quoted\\\"\\u000a\\u0009\\\\é\"");
    }

    #[test]
    fn saved_pr_bidi_and_c1_escapes_do_not_change_metadata() {
        assert_eq!(quote("é\n\t\r\"\\\u{009b}\u{202e}"),
            "\"é\\u000a\\u0009\\u000d\\\"\\\\\\u009b\\u202e\"");
        for scalar in [0x061c, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202b,
            0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]
        {
            let character = char::from_u32(scalar).unwrap();
            assert_eq!(quote(&format!("before{character}after")),
                format!("\"before\\u{scalar:04x}after\""));
        }
        assert_eq!(quote("العربية עברית é 🦀"), "\"العربية עברית é 🦀\"");
        assert_eq!(quote("literal \\u202e"), "\"literal \\\\u202e\"");
    }

    #[cfg(unix)]
    #[test]
    fn bundle_symlinks_are_not_accepted_as_regular_artifacts() {
        let root = std::env::temp_dir().join(format!("fg-publication-symlink-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let original = root.join("real");
        let link = root.join("link");
        fs::write(&original, b"1234").unwrap();
        std::os::unix::fs::symlink(&original, &link).unwrap();
        assert!(read_bundle(&link, 4).is_err());
        assert_eq!(read_bundle(&original, 4).unwrap(), b"1234");
        fs::remove_dir_all(root).unwrap();
    }
}
