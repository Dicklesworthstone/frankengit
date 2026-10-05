//! Deterministic, bounded POSIX ustar bytes. This never touches the host tree.
use fgit_forge::source_browse::SourceEntryKind;

pub(super) const MAX_BYTES: usize = 128 * 1024 * 1024;
const BLOCK: usize = 512;

#[derive(Default)]
pub(super) struct Tar {
    bytes: Vec<u8>,
}

impl Tar {
    pub(super) fn remaining_payload(&self) -> usize {
        // Reserve an entry header, worst-case padding and the two end blocks.
        MAX_BYTES.saturating_sub(self.bytes.len().saturating_add(4 * BLOCK))
    }

    pub(super) fn append(
        &mut self,
        path: &[u8],
        kind: SourceEntryKind,
        payload: &[u8],
    ) -> Result<(), String> {
        validate_path(path)?;
        let (mode, flag, data, link): (u64, u8, &[u8], &[u8]) = match kind {
            SourceEntryKind::File => (0o644, b'0', payload, b""),
            SourceEntryKind::Executable => (0o755, b'0', payload, b""),
            SourceEntryKind::Directory | SourceEntryKind::Gitlink if payload.is_empty() => {
                (0o755, b'5', b"", b"")
            }
            SourceEntryKind::Symlink => {
                validate_link(payload)?;
                (0o777, b'2', b"", payload)
            }
            _ => return Err("archive directory cannot contain file payload bytes".into()),
        };
        let mut name = path.to_vec();
        if flag == b'5' {
            name.push(b'/');
        }
        let mut header = [0_u8; BLOCK];
        write_name(&mut header, &name)?;
        octal(&mut header[100..108], mode)?;
        octal(&mut header[108..116], 0)?;
        octal(&mut header[116..124], 0)?;
        octal(&mut header[124..136], data.len() as u64)?;
        octal(&mut header[136..148], 0)?;
        header[148..156].fill(b' ');
        header[156] = flag;
        header[157..157 + link.len()].copy_from_slice(link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        octal(&mut header[148..155], sum)?;
        header[155] = b' ';
        let padding = (BLOCK - data.len() % BLOCK) % BLOCK;
        let end = self.bytes.len()
            .checked_add(BLOCK)
            .and_then(|size| size.checked_add(data.len()))
            .and_then(|size| size.checked_add(padding))
            .filter(|size| *size <= MAX_BYTES - 2 * BLOCK)
            .ok_or("source archive exceeds 128 MiB including tar framing")?;
        self.bytes.try_reserve(end - self.bytes.len())
            .map_err(|_| "cannot allocate bounded source archive")?;
        self.bytes.extend_from_slice(&header);
        self.bytes.extend_from_slice(data);
        self.bytes.resize(end, 0);
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<Vec<u8>, String> {
        self.bytes.try_reserve(2 * BLOCK)
            .map_err(|_| "cannot allocate archive end markers")?;
        self.bytes.resize(self.bytes.len() + 2 * BLOCK, 0);
        Ok(self.bytes)
    }
}

pub(super) fn validate_component(name: &[u8]) -> Result<(), String> {
    if name.is_empty() || name == b"." || name == b".."
        || name.eq_ignore_ascii_case(b".git")
        || name.iter().any(|byte| matches!(*byte, 0 | b'/' | b'\\' | b':'))
    {
        return Err("source archive contains an unsafe path component".into());
    }
    Ok(())
}

fn validate_path(path: &[u8]) -> Result<(), String> {
    if path.len() > 256 {
        return Err("source archive path exceeds the ustar profile".into());
    }
    for component in path.split(|byte| *byte == b'/') {
        validate_component(component)?;
    }
    Ok(())
}

fn validate_link(target: &[u8]) -> Result<(), String> {
    // No parent components, even when a lexical normalization would appear
    // contained: another symlink can change what a preceding component means.
    // Refusing such links also prevents chained links from escaping the prefix.
    if target.is_empty() || target.len() > 100 || target.starts_with(b"/")
        || target.iter().any(|byte| matches!(*byte, 0 | b'\\' | b':'))
        || target.split(|byte| *byte == b'/').any(|part| part == b"..")
    {
        return Err("ustar symlink requires at most 100 relative bytes without parent traversal".into());
    }
    Ok(())
}

fn write_name(header: &mut [u8; BLOCK], path: &[u8]) -> Result<(), String> {
    if path.len() <= 100 {
        header[..path.len()].copy_from_slice(path);
        return Ok(());
    }
    // The ustar prefix ends at an actual separator. Never truncate raw names
    // or synthesize a PAX/GNU encoding with different byte semantics.
    let split = path.iter().enumerate().rev().find_map(|(at, byte)| {
        (*byte == b'/' && at > 0 && at <= 155 && path.len() - at - 1 <= 100
            && at + 1 < path.len()).then_some(at)
    }).ok_or("source path cannot be represented exactly in ustar name/prefix fields")?;
    let name = &path[split + 1..];
    header[..name.len()].copy_from_slice(name);
    header[345..345 + split].copy_from_slice(&path[..split]);
    Ok(())
}

fn octal(field: &mut [u8], mut value: u64) -> Result<(), String> {
    field.fill(b'0');
    let end = field.len() - 1;
    field[end] = 0;
    for byte in field[..end].iter_mut().rev() {
        *byte = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    if value != 0 {
        return Err("source archive numeric field overflow".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(field: &[u8]) -> u64 {
        u64::from_str_radix(std::str::from_utf8(field).unwrap().trim_matches(['\0', ' ']), 8).unwrap()
    }

    #[test]
    fn headers_have_real_ustar_checksums_modes_lengths_and_zero_padding() {
        let mut tar = Tar::default();
        tar.append(b"source/bin/run", SourceEntryKind::Executable, &[0, 255, 10]).unwrap();
        tar.append(b"source/empty", SourceEntryKind::Directory, b"").unwrap();
        tar.append(b"source/link", SourceEntryKind::Symlink, b"bin/run").unwrap();
        let bytes = tar.finish().unwrap();
        // Independently generated with Python tarfile.TarInfo in USTAR_FORMAT,
        // then parsed by tarfile; this is not a regenerated implementation golden.
        let mut expected = vec![0_u8; 3072];
        for line in include_str!("../../../tests/fixtures/source_archive/ustar_v1.hex").lines() {
            let (offset, hex) = line.split_once(' ').unwrap();
            let offset = offset.parse::<usize>().unwrap();
            for index in 0..hex.len() / 2 {
                expected[offset + index] = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
            }
        }
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 6 * BLOCK);
        for (at, mode, size, flag) in [(0, 0o755, 3, b'0'), (1024, 0o755, 0, b'5'), (1536, 0o777, 0, b'2')] {
            let head = &bytes[at..at + BLOCK];
            assert_eq!(&head[257..265], b"ustar\000");
            assert_eq!(number(&head[100..108]), mode);
            assert_eq!(number(&head[124..136]), size);
            assert_eq!(head[156], flag);
            let sum: u64 = head.iter().enumerate()
                .map(|(i, byte)| if (148..156).contains(&i) { 32 } else { u64::from(*byte) }).sum();
            assert_eq!(number(&head[148..156]), sum);
            assert_eq!(number(&head[136..148]), 0);
        }
        assert_eq!(&bytes[512..515], &[0, 255, 10]);
        assert!(bytes[515..1024].iter().all(|byte| *byte == 0));
        assert_eq!(&bytes[1536 + 157..1536 + 164], b"bin/run");
        assert!(bytes[2048..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn raw_non_utf8_names_and_prefix_splitting_preserve_every_byte() {
        let mut tar = Tar::default();
        let mut path = b"source/".to_vec();
        path.extend_from_slice(&[b'x'; 100]);
        path.extend_from_slice(b"/binary-\xff");
        tar.append(&path, SourceEntryKind::File, b"").unwrap();
        let bytes = tar.finish().unwrap();
        assert_eq!(&bytes[..8], b"binary-\xff");
        assert_eq!(&bytes[345..452], &path[..107]);
        let mut too_long = b"source/".to_vec();
        too_long.extend_from_slice(&[b'x'; 101]);
        assert!(Tar::default().append(&too_long, SourceEntryKind::File, b"").is_err());
    }

    #[test]
    fn unsafe_paths_and_links_fail_without_appending_partial_entries() {
        let mut tar = Tar::default();
        for path in [b"/absolute".as_slice(), b"source/../escape", b"source/.Git/config", b"source//file", b"source/a\\b", b"source/C:evil", b"source/nul\0x"] {
            assert!(tar.append(path, SourceEntryKind::File, b"x").is_err());
            assert!(tar.bytes.is_empty());
        }
        for target in [b"/etc/passwd".as_slice(), b"../escape", b"child/../../escape", b"a/../file", b"C:escape", b"x\\y", b"bad\0target", b""] {
            assert!(tar.append(b"source/link", SourceEntryKind::Symlink, target).is_err());
            assert!(tar.bytes.is_empty());
        }
        tar.append(b"source/link", SourceEntryKind::Symlink, b"./safe/file").unwrap();
        assert_eq!(tar.bytes.len(), BLOCK);
    }

    #[test]
    fn finish_and_small_numeric_fields_refuse_overflow_without_truncation() {
        let mut field = [0; 3];
        assert!(octal(&mut field, 0o100).is_err());
        octal(&mut field, 0o77).unwrap();
        assert_eq!(field, *b"77\0");
        assert_eq!(Tar::default().finish().unwrap(), vec![0; 1024]);
    }
}
