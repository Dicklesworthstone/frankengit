//! ZIP downloads through the actual authenticated listener. The independent
//! reader checks stored records, CRCs, offsets, names and Unix modes without
//! invoking the production collector or its ZIP implementation.
use super::*;

struct ZipMember {
    mode: u32,
    data: Vec<u8>,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ if value & 1 == 0 { 0 } else { 0xedb8_8320 };
        }
    }
    !value
}

fn zip_members(bytes: &[u8]) -> BTreeMap<Vec<u8>, ZipMember> {
    let end = bytes.len().checked_sub(22).unwrap();
    assert_eq!(u32_at(bytes, end), 0x0605_4b50);
    assert_eq!(u16_at(bytes, end + 4), 0, "one disk");
    assert_eq!(u16_at(bytes, end + 6), 0, "same central-directory disk");
    let count = usize::from(u16_at(bytes, end + 8));
    assert_eq!(usize::from(u16_at(bytes, end + 10)), count);
    assert_eq!(u16_at(bytes, end + 20), 0, "no comment or trailing bytes");
    let central_start = usize::try_from(u32_at(bytes, end + 16)).unwrap();
    assert_eq!(
        central_start + usize::try_from(u32_at(bytes, end + 12)).unwrap(),
        end
    );
    let mut central = central_start;
    let mut local = 0;
    let mut result = BTreeMap::new();
    for _ in 0..count {
        assert_eq!(u32_at(bytes, central), 0x0201_4b50);
        assert_eq!(u16_at(bytes, central + 4), (3 << 8) | 20, "Unix creator");
        assert_eq!(u16_at(bytes, central + 6), 20);
        assert_eq!(u16_at(bytes, central + 8), 1 << 11, "exact UTF-8 flag only");
        assert_eq!(u16_at(bytes, central + 10), 0, "stored, not compressed");
        assert_eq!(u16_at(bytes, central + 12), 0);
        assert_eq!(u16_at(bytes, central + 14), 33, "fixed DOS epoch");
        let crc = u32_at(bytes, central + 16);
        let size = usize::try_from(u32_at(bytes, central + 20)).unwrap();
        assert_eq!(usize::try_from(u32_at(bytes, central + 24)).unwrap(), size);
        let name_length = usize::from(u16_at(bytes, central + 28));
        for offset in [30, 32, 34, 36] {
            assert_eq!(
                u16_at(bytes, central + offset),
                0,
                "no extra, comment or disk"
            );
        }
        let attributes = u32_at(bytes, central + 38);
        assert_eq!(usize::try_from(u32_at(bytes, central + 42)).unwrap(), local);
        let name = bytes[central + 46..central + 46 + name_length].to_vec();
        assert!(std::str::from_utf8(&name).unwrap().starts_with("source/"));
        assert_eq!(u32_at(bytes, local), 0x0403_4b50);
        assert_eq!(u16_at(bytes, local + 4), 20);
        assert_eq!(u16_at(bytes, local + 6), 1 << 11);
        assert_eq!(u16_at(bytes, local + 8), 0);
        assert_eq!(u16_at(bytes, local + 10), 0);
        assert_eq!(u16_at(bytes, local + 12), 33);
        assert_eq!(u32_at(bytes, local + 14), crc);
        assert_eq!(usize::try_from(u32_at(bytes, local + 18)).unwrap(), size);
        assert_eq!(usize::try_from(u32_at(bytes, local + 22)).unwrap(), size);
        assert_eq!(usize::from(u16_at(bytes, local + 26)), name_length);
        assert_eq!(u16_at(bytes, local + 28), 0);
        assert_eq!(&bytes[local + 30..local + 30 + name_length], name);
        let start = local + 30 + name_length;
        let data = bytes[start..start + size].to_vec();
        assert_eq!(crc32(&data), crc, "member checksum");
        let mode = attributes >> 16;
        assert_eq!(
            attributes & 0xffff,
            if mode & 0o170_000 == 0o040_000 { 16 } else { 0 }
        );
        assert!(result.insert(name, ZipMember { mode, data }).is_none());
        local = start + size;
        central += 46 + name_length;
    }
    assert_eq!(
        local, central_start,
        "no hidden local records or trailing payload"
    );
    assert_eq!(central, end, "complete central directory");
    assert_eq!(result.len(), count);
    result
}

#[test]
fn zip_http_preserves_native_source_and_unix_modes_deterministically_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let binary_name = "binary-λ.dat".as_bytes();
        let (node, commit, tree) = safe_fixture_with_name(&root, format, binary_name);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 4, true, false);
        let form = common(format) + "&archive_format=zip";
        let first = archive(&server.client, 'a', &form, false);
        assert_eq!(first.status, 200, "{}", first.head);
        for (name, expected) in [
            ("Content-Type", "application/zip"),
            ("Content-Disposition", "attachment; filename=\"source.zip\""),
            ("Cache-Control", "no-store"),
            ("Vary", "Authorization"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-FrankenGit-Archive-Profile", "zip-store-source-v1"),
            ("X-FrankenGit-Archive-Entries", "7"),
            ("X-FrankenGit-Archive-Gitlinks", "1"),
        ] {
            assert_eq!(first.header(name), expected);
        }
        assert_eq!(
            first.header("X-FrankenGit-Source-Commit"),
            commit.to_string()
        );
        assert_eq!(first.header("X-FrankenGit-Root-Tree"), tree.to_string());
        assert_eq!(first.header("X-FrankenGit-Selected-Tree"), tree.to_string());
        let files = zip_members(&first.body);
        assert_eq!(files.len(), 7);
        let binary_path = [b"source/".as_slice(), binary_name].concat();
        assert_eq!(files[&binary_path].data, BINARY);
        assert_eq!(files[&binary_path].mode, 0o100_644);
        assert_eq!(files[b"source/dir/run".as_slice()].mode, 0o100_755);
        assert_eq!(
            files[b"source/dir/run".as_slice()].data,
            b"#!/bin/sh\nprintf hello\n"
        );
        assert!(files[b"source/empty".as_slice()].data.is_empty());
        assert_eq!(files[b"source/link".as_slice()].mode, 0o120_777);
        assert_eq!(files[b"source/link".as_slice()].data, b"dir/run");
        assert_eq!(files[b"source/module/".as_slice()].mode, 0o040_755);
        assert!(files[b"source/module/".as_slice()].data.is_empty());
        let pinned = format!(
            "{form}&expected_head={}&expected_commit={commit}",
            first.header("X-FrankenGit-Snapshot-Token")
        );
        let repeated = archive(&server.client, 'a', &pinned, true);
        assert_eq!(repeated.status, 200);
        assert_eq!(repeated.body, first.body);
        assert_eq!(repeated.head, first.head);
        let subtree = archive(
            &server.client,
            'a',
            &(pinned.clone() + "&path_hex=646972"),
            false,
        );
        assert_eq!(subtree.status, 200);
        assert_eq!(subtree.header("X-FrankenGit-Root-Tree"), tree.to_string());
        assert_ne!(
            subtree.header("X-FrankenGit-Selected-Tree"),
            tree.to_string()
        );
        let selected = zip_members(&subtree.body);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[b"source/run".as_slice()].mode, 0o100_755);
        let tar = archive(&server.client, 'a', &common(format), false);
        assert_eq!(tar.status, 200);
        for (name, member) in members(&tar.body) {
            let zip = &files[&name];
            assert_eq!(u64::from(zip.mode & 0o777), member.mode);
            assert_eq!(
                zip.data,
                if member.kind == b'2' {
                    member.link
                } else {
                    member.data
                }
            );
        }
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        let server = Server::start(node, &path, 1, true, false);
        let restarted = archive(&server.client, 'a', &pinned, false);
        assert_eq!(restarted.status, 200);
        assert_eq!(restarted.body, first.body);
        assert_eq!(restarted.head, first.head);
        assert_eq!(server.finish().accepted_sessions(), 1);
    }
}

#[test]
fn zip_refuses_lossy_names_and_unsupported_formats_but_preserves_safe_subtrees() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit, _) = safe_fixture(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 10, true, false);
        let base = common(format);
        let zip = base.clone() + "&archive_format=zip";
        archive(&server.client, 'a', &zip, false).error(409, "source_archive_profile_refused");
        let raw = archive(&server.client, 'a', &base, true);
        assert_eq!(
            raw.status, 200,
            "raw-byte names remain available through tar"
        );
        let subtree = format!("{zip}&path_hex=646972");
        let permitted = archive(&server.client, 'a', &subtree, true);
        assert_eq!(permitted.status, 200);
        assert_eq!(
            zip_members(&permitted.body)[b"source/run".as_slice()].mode,
            0o100_755
        );
        archive(&server.client, 'b', &subtree, false).error(403, "forbidden");
        for value in ["ZIP", "zip64", ""] {
            archive(
                &server.client,
                'a',
                &format!("{base}&archive_format={value}"),
                false,
            )
            .error(400, "unsupported_archive_format");
        }
        archive(
            &server.client,
            'a',
            &format!("{subtree}&archive_format=tar"),
            false,
        )
        .error(400, "duplicate_field");
        archive(
            &server.client,
            'a',
            &format!(
                "{subtree}&expected_commit={}",
                "ab".repeat(format.digest_len())
            ),
            false,
        )
        .error(409, "source_commit_moved");
        assert_eq!(
            archive(
                &server.client,
                'a',
                &format!("{subtree}&expected_commit={commit}"),
                false
            )
            .status,
            200
        );
        assert_eq!(server.finish().accepted_sessions(), 10);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn zip_exports_long_utf8_names_that_ustar_cannot_represent_without_extensions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let name = vec![b'b'; 180];
        let (node, _, _) = safe_fixture_with_name(&root, format, &name);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 2, true, false);
        archive(&server.client, 'a', &common(format), false)
            .error(409, "source_archive_profile_refused");
        let zip = archive(
            &server.client,
            'a',
            &(common(format) + "&archive_format=zip"),
            false,
        );
        assert_eq!(zip.status, 200);
        let files = zip_members(&zip.body);
        assert_eq!(files[&[b"source/".as_slice(), &name].concat()].data, BINARY);
        assert_eq!(server.finish().accepted_sessions(), 2);
    }
}
