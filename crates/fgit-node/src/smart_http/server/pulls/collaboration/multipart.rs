//! Bounded RFC 7578 upload profile: one URL-encoded `command`, optionally one
//! binary `bundle`. Part order is immaterial. Filenames are never filesystem
//! paths. No transfer encodings, nested multipart, preamble or epilogue.
//!
//! Parsing borrows the HTTP-owned body; it does not copy a second bundle.
//! Boundary search is linear even for repeated hostile boundary prefixes.

pub(super) const MAX_COMMAND_BYTES: usize = 256 * 1024;
pub(super) const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_UPLOAD_BYTES: usize = MAX_COMMAND_BYTES + MAX_BUNDLE_BYTES + 16 * 1024;
const MAX_PART_HEAD: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error { Framing, Limit, Cancelled }

#[derive(Debug)]
pub(super) struct Upload<'a> {
    pub command: &'a [u8],
    pub bundle: Option<&'a [u8]>,
}

/// Curl/browser token boundaries, quoted or unquoted. Restricting the boundary
/// alphabet is an explicit profile refusal, not permissive MIME normalization.
pub(super) fn boundary(content_type: &str) -> Result<&str, Error> {
    let mut fields = content_type.split(';');
    if !fields.next().is_some_and(|v| v.trim().eq_ignore_ascii_case("multipart/form-data")) {
        return Err(Error::Framing);
    }
    let (name, value) = fields.next().and_then(|v| v.trim().split_once('='))
        .ok_or(Error::Framing)?;
    if !name.eq_ignore_ascii_case("boundary") || fields.next().is_some() {
        return Err(Error::Framing);
    }
    let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
    if value.is_empty() || value.len() > 70
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    { return Err(Error::Framing); }
    Ok(value)
}

fn part_name(head: &[u8]) -> Result<&str, Error> {
    if head.len() > MAX_PART_HEAD { return Err(Error::Limit); }
    let text = std::str::from_utf8(head).map_err(|_| Error::Framing)?;
    let (mut disposition, mut media) = (None, None);
    for line in text.split("\r\n") {
        if line.is_empty() || line.bytes().any(|b| b < 32 || b == 127) {
            return Err(Error::Framing);
        }
        let (name, value) = line.split_once(':').ok_or(Error::Framing)?;
        let value = value.trim_matches(' ');
        if name.eq_ignore_ascii_case("Content-Disposition") && disposition.is_none() {
            disposition = Some(value);
        } else if name.eq_ignore_ascii_case("Content-Type") && media.is_none() {
            media = Some(value);
        } else { return Err(Error::Framing); }
    }
    let mut fields = disposition.ok_or(Error::Framing)?.split(';');
    if !fields.next().is_some_and(|v| v.trim().eq_ignore_ascii_case("form-data")) {
        return Err(Error::Framing);
    }
    let (mut name, mut filename) = (None, false);
    for field in fields {
        let (key, value) = field.trim().split_once('=').ok_or(Error::Framing)?;
        let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).ok_or(Error::Framing)?;
        if value.len() > 255 || value.bytes().any(|b| b < 32 || b == 127 || b == b'"' || b == b'\\') {
            return Err(Error::Framing);
        }
        if key.eq_ignore_ascii_case("name") && name.is_none() { name = Some(value); }
        else if key.eq_ignore_ascii_case("filename") && !filename { filename = true; }
        else { return Err(Error::Framing); }
    }
    let name = name.ok_or(Error::Framing)?;
    let media = media.ok_or(Error::Framing)?;
    let valid = match name {
        "command" => media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8"),
        "bundle" => media.eq_ignore_ascii_case("application/x-git-bundle")
            || media.eq_ignore_ascii_case("application/octet-stream"),
        _ => false,
    };
    if !valid { return Err(Error::Framing); }
    Ok(name)
}

fn prefix_table(marker: &[u8]) -> Vec<usize> {
    let mut prefix = vec![0; marker.len()];
    let mut matched = 0;
    for index in 1..marker.len() {
        while matched > 0 && marker[index] != marker[matched] { matched = prefix[matched - 1]; }
        if marker[index] == marker[matched] { matched += 1; }
        prefix[index] = matched;
    }
    prefix
}

fn find_boundary(bytes: &[u8], start: usize, marker: &[u8], prefix: &[usize],
    live: &mut impl FnMut() -> bool,
) -> Result<usize, Error> {
    let mut matched = 0;
    for (offset, &byte) in bytes[start..].iter().enumerate() {
        if offset % (64 * 1024) == 0 && !live() { return Err(Error::Cancelled); }
        while matched > 0 && byte != marker[matched] { matched = prefix[matched - 1]; }
        if byte == marker[matched] { matched += 1; }
        if matched == marker.len() {
            let after = start + offset + 1;
            if matches!(bytes.get(after..after.saturating_add(2)), Some(b"\r\n" | b"--")) {
                return Ok(after - marker.len());
            }
            // An incomplete delimiter is not an end marker; it remains data.
            matched = prefix[matched - 1];
        }
    }
    Err(Error::Framing)
}

pub(super) fn parse<'a>(bytes: &'a [u8], boundary: &str,
    live: &mut impl FnMut() -> bool,
) -> Result<Upload<'a>, Error> {
    if bytes.len() > MAX_UPLOAD_BYTES { return Err(Error::Limit); }
    if !live() { return Err(Error::Cancelled); }
    // Validate independently of the HTTP entry point as this parser is also
    // used by tests and must remain total for arbitrary caller-provided input.
    if boundary.is_empty() || boundary.len() > 70
        || !boundary.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    { return Err(Error::Framing); }
    let opening = format!("--{boundary}\r\n");
    if !bytes.starts_with(opening.as_bytes()) { return Err(Error::Framing); }
    let marker = format!("\r\n--{boundary}");
    let prefix = prefix_table(marker.as_bytes());
    let mut cursor = opening.len();
    let (mut command, mut bundle) = (None, None);
    for _ in 0..2 {
        if !live() { return Err(Error::Cancelled); }
        let tail = &bytes[cursor..];
        let head_end = tail[..tail.len().min(MAX_PART_HEAD + 4)].windows(4)
            .position(|v| v == b"\r\n\r\n").ok_or(Error::Framing)?;
        let name = part_name(&tail[..head_end])?;
        cursor += head_end + 4;
        let end = find_boundary(bytes, cursor, marker.as_bytes(), &prefix, live)?;
        let content = &bytes[cursor..end];
        match name {
            "command" if command.is_none() => {
                if content.len() > MAX_COMMAND_BYTES { return Err(Error::Limit); }
                command = Some(content);
            }
            "bundle" if bundle.is_none() => {
                if content.len() > MAX_BUNDLE_BYTES { return Err(Error::Limit); }
                bundle = Some(content);
            }
            _ => return Err(Error::Framing),
        }
        cursor = end + marker.len();
        if bytes[cursor..].starts_with(b"--") {
            let trailing = &bytes[cursor + 2..];
            if !matches!(trailing, b"" | b"\r\n") { return Err(Error::Framing); }
            if !live() { return Err(Error::Cancelled); }
            return Ok(Upload { command: command.ok_or(Error::Framing)?, bundle });
        }
        // find_boundary accepted exactly CRLF or the closing marker above.
        cursor += 2;
    }
    Err(Error::Framing)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn part(name: &str, media: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!("--example\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"ignored\"\r\nContent-Type: {media}\r\n\r\n").into_bytes();
        out.extend_from_slice(body); out.extend_from_slice(b"\r\n"); out
    }
    fn upload(reverse: bool) -> Vec<u8> {
        let command = part("command", "application/x-www-form-urlencoded", b"reason=literal%252f");
        let bundle = part("bundle", "application/x-git-bundle", b"PACK\0\xff\r\n--exampleX\0");
        let mut bytes = if reverse { [bundle, command].concat() } else { [command, bundle].concat() };
        bytes.extend_from_slice(b"--example--\r\n"); bytes
    }
    #[test]
    fn binary_bundle_and_text_are_borrowed_exactly_in_either_part_order() {
        for reverse in [false, true] {
            let bytes = upload(reverse);
            let result = parse(&bytes, "example", &mut || true).unwrap();
            assert_eq!(result.command, b"reason=literal%252f");
            assert_eq!(result.bundle.unwrap(), b"PACK\0\xff\r\n--exampleX\0");
        }
        assert_eq!(boundary("multipart/form-data; boundary=\"example\"").unwrap(), "example");
    }
    #[test]
    fn truncation_duplicates_epilogues_and_transfer_encoding_fail_closed() {
        let bytes = upload(false);
        for end in 0..bytes.len() - 2 { assert!(parse(&bytes[..end], "example", &mut || true).is_err()); }
        let mut extra = bytes.clone(); extra.extend_from_slice(b"HTTP/1.1");
        assert!(parse(&extra, "example", &mut || true).is_err());
        let mut duplicate = part("command", "application/x-www-form-urlencoded", b"a=b");
        duplicate.extend(part("command", "application/x-www-form-urlencoded", b"a=c"));
        duplicate.extend_from_slice(b"--example--\r\n");
        assert!(parse(&duplicate, "example", &mut || true).is_err());
        assert!(part_name(b"Content-Disposition: form-data; name=\"bundle\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64").is_err());
        for invalid in ["multipart/form-data", "multipart/form-data; boundary=", "multipart/form-data; boundary=a; boundary=b", "multipart/form-data; boundary=\"a"] {
            assert!(boundary(invalid).is_err());
        }
    }
    #[test]
    fn cancellation_interrupts_linear_hostile_prefix_scans() {
        let mut bytes = part("command", "application/x-www-form-urlencoded", b"a=b");
        bytes.extend(part("bundle", "application/octet-stream", &b"\r\n--exampl".repeat(30_000)));
        bytes.extend_from_slice(b"--example--\r\n");
        let mut calls = 0;
        assert_eq!(parse(&bytes, "example", &mut || { calls += 1; calls < 7; }).unwrap_err(), Error::Cancelled);
        assert_eq!(parse(&bytes, "", &mut || true).unwrap_err(), Error::Framing);
    }
}
