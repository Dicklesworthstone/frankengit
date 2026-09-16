//! Bounded multipart framing shared by candidate operations. Each caller owns
//! its closed part-name/media/size grammar; the existing review profile remains
//! exactly one `command` and at most one `bundle`. Filenames are never paths.
//! No transfer encodings, nested multipart, preamble or epilogue are accepted.
//! Parsing borrows the HTTP-owned body and uses cancellable linear search.

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

#[derive(Debug)]
pub(super) struct Part<'a> {
    pub name: &'a str,
    pub media: &'a str,
    pub content: &'a [u8],
}

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
    validate_boundary(value)?;
    Ok(value)
}

fn validate_boundary(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 70
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    { return Err(Error::Framing); }
    Ok(())
}

fn part_head(head: &[u8]) -> Result<(&str, &str), Error> {
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
    Ok((name.ok_or(Error::Framing)?, media.ok_or(Error::Framing)?))
}

pub(super) fn command_media(media: &str) -> bool {
    media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
        || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
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
            matched = prefix[matched - 1];
        }
    }
    Err(Error::Framing)
}

/// Framing only: consumers must validate every part and may not publish or
/// stage effects in `accept`. Its results remain provisional until the entire
/// envelope, final marker and cancellation checkpoint succeed.
pub(super) fn visit_parts<'a>(bytes: &'a [u8], boundary: &str,
    maximum_bytes: usize, maximum_parts: usize, live: &mut impl FnMut() -> bool,
    mut accept: impl FnMut(Part<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    if maximum_parts == 0 || maximum_parts > 129 || maximum_bytes > MAX_UPLOAD_BYTES
        || bytes.len() > maximum_bytes { return Err(Error::Limit); }
    if !live() { return Err(Error::Cancelled); }
    validate_boundary(boundary)?;
    let opening = format!("--{boundary}\r\n");
    if !bytes.starts_with(opening.as_bytes()) { return Err(Error::Framing); }
    let marker = format!("\r\n--{boundary}");
    let prefix = prefix_table(marker.as_bytes());
    let mut cursor = opening.len();
    for _ in 0..maximum_parts {
        if !live() { return Err(Error::Cancelled); }
        let tail = bytes.get(cursor..).ok_or(Error::Framing)?;
        let head_end = tail[..tail.len().min(MAX_PART_HEAD + 4)].windows(4)
            .position(|v| v == b"\r\n\r\n").ok_or(Error::Framing)?;
        let (name, media) = part_head(&tail[..head_end])?;
        cursor += head_end + 4;
        let end = find_boundary(bytes, cursor, marker.as_bytes(), &prefix, live)?;
        accept(Part { name, media, content: &bytes[cursor..end] })?;
        cursor = end + marker.len();
        if bytes[cursor..].starts_with(b"--") {
            let trailing = &bytes[cursor + 2..];
            if !matches!(trailing, b"" | b"\r\n") { return Err(Error::Framing); }
            if !live() { return Err(Error::Cancelled); }
            return Ok(());
        }
        cursor += 2;
    }
    Err(Error::Limit)
}

pub(super) fn parse<'a>(bytes: &'a [u8], boundary: &str,
    live: &mut impl FnMut() -> bool,
) -> Result<Upload<'a>, Error> {
    let (mut command, mut bundle) = (None, None);
    visit_parts(bytes, boundary, MAX_UPLOAD_BYTES, 2, live, |part| {
        match part.name {
            "command" if command.is_none() && command_media(part.media) => {
                if part.content.len() > MAX_COMMAND_BYTES { return Err(Error::Limit); }
                command = Some(part.content);
            }
            "bundle" if bundle.is_none() && (part.media.eq_ignore_ascii_case("application/x-git-bundle")
                || part.media.eq_ignore_ascii_case("application/octet-stream")) => {
                if part.content.len() > MAX_BUNDLE_BYTES { return Err(Error::Limit); }
                bundle = Some(part.content);
            }
            _ => return Err(Error::Framing),
        }
        Ok(())
    })?;
    Ok(Upload { command: command.ok_or(Error::Framing)?, bundle })
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
        assert!(part_head(b"Content-Disposition: form-data; name=\"bundle\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64").is_err());
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
    #[test]
    fn shared_framing_does_not_widen_the_existing_bundle_profile() {
        let mut bytes = part("command", "application/x-www-form-urlencoded", b"a=b");
        bytes.extend(part("file_0", "application/octet-stream", b"\0\xff"));
        bytes.extend(part("file_1", "application/octet-stream", b""));
        bytes.extend_from_slice(b"--example--\r\n");
        let mut parts = Vec::new();
        visit_parts(&bytes, "example", bytes.len(), 3, &mut || true, |part| {
            parts.push((part.name, part.content)); Ok(())
        }).unwrap();
        assert_eq!(parts, [("command", b"a=b".as_slice()), ("file_0", b"\0\xff"), ("file_1", b"")]);
        assert!(parse(&bytes, "example", &mut || true).is_err());
        assert_eq!(visit_parts(&bytes, "example", bytes.len(), 2, &mut || true, |_| Ok(())).unwrap_err(), Error::Limit);
        assert_eq!(visit_parts(&bytes, "example", bytes.len() - 1, 3, &mut || true, |_| Ok(())).unwrap_err(), Error::Limit);
    }
}
