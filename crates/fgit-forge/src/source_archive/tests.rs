//! Synthetic verified-read reports test export assembly, not node authentication.
use super::*;
use crate::source_browse::SourceDirectoryEntry;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, RepositoryId,
};

struct Options {
    repository: RepositoryId,
    format: GitHashAlgorithm,
    query: SourceBrowseQuery,
}
fn collect(
    options: &Options,
    reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, String>,
) -> Result<SourceArchive, SourceArchiveError<String>> {
    super::collect(options.repository, options.format, &options.query, reader)
}

fn options(format: GitHashAlgorithm, limit: u16) -> Options {
    Options {
        repository: RepositoryId::from_bytes([2; 16]),
        format,
        query: SourceBrowseQuery {
            path: None,
            expected_head: None,
            expected_commit: None,
            action: SourceBrowseAction::List { after: None, limit },
        },
    }
}
fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}
fn pin(format: GitHashAlgorithm) -> SourceArchivePin {
    let algorithm = DigestAlgorithmId::try_new(2).unwrap();
    SourceArchivePin {
        head: RepositoryAuthorityHeadId::from_digest(
            algorithm,
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[9; 32]).unwrap(),
        ),
        rcr: RepositoryCommitId::from_digest(
            algorithm,
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[8; 32]).unwrap(),
        ),
        commit: oid(format, 2),
        tree: oid(format, 1),
    }
}
fn report(format: GitHashAlgorithm, query: &SourceBrowseQuery) -> SourceBrowseReport {
    let binding = pin(format);
    let child = |name: &[u8], byte, kind| SourceDirectoryEntry {
        name: name.to_vec(),
        oid: oid(format, byte),
        kind,
    };
    let (object, content) = match &query.action {
        SourceBrowseAction::List { after, limit } => {
            let (object, all) = match query.path.as_deref() {
                None => (
                    1,
                    vec![
                        child(b"a.bin", 3, SourceEntryKind::File),
                        child(b"bin", 4, SourceEntryKind::Directory),
                        child(b"empty", 5, SourceEntryKind::File),
                        child(b"link", 6, SourceEntryKind::Symlink),
                        child(b"submodule", 7, SourceEntryKind::Gitlink),
                        child(b"\xff", 8, SourceEntryKind::File),
                    ],
                ),
                Some(b"bin") => (4, vec![child(b"run", 9, SourceEntryKind::Executable)]),
                _ => panic!("must not follow symlinks or fetch gitlinks"),
            };
            let mut rest = all
                .into_iter()
                .filter(|entry| after.as_ref().is_none_or(|last| entry.name > *last));
            let entries: Vec<_> = rest.by_ref().take(usize::from(*limit)).collect();
            let next_after = rest.next().map(|_| entries.last().unwrap().name.clone());
            (
                object,
                SourceBrowseContent::Directory {
                    entries,
                    next_after,
                },
            )
        }
        SourceBrowseAction::Read { offset, limit } => {
            let (object, kind, data): (u8, SourceEntryKind, &[u8]) = match query.path.as_deref() {
                Some(b"a.bin") => (3, SourceEntryKind::File, &[0, 255, 13, 10]),
                Some(b"bin/run") => (9, SourceEntryKind::Executable, b"echo hi\n"),
                Some(b"empty") => (5, SourceEntryKind::File, b""),
                Some(b"link") => (6, SourceEntryKind::Symlink, b"bin/run"),
                Some(b"\xff") => (8, SourceEntryKind::File, b"raw name"),
                _ => panic!("only parent-selected files may be read"),
            };
            let start = usize::try_from(*offset).unwrap();
            let end = data.len().min(start + (*limit as usize).min(2));
            (
                object,
                SourceBrowseContent::Blob {
                    kind,
                    bytes: data[start..end].to_vec(),
                    total_bytes: data.len() as u64,
                    offset: *offset,
                    next_offset: (end < data.len()).then_some(end as u64),
                },
            )
        }
    };
    SourceBrowseReport {
        repository_id: RepositoryId::from_bytes([2; 16]),
        source_head: binding.head,
        source_rcr: binding.rcr,
        source_commit: binding.commit,
        root_tree: binding.tree,
        object_id: oid(format, object),
        path: query.path.clone(),
        content,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Member {
    name: Vec<u8>,
    mode: u64,
    kind: u8,
    data: Vec<u8>,
    link: Vec<u8>,
}
fn members(bytes: &[u8]) -> Vec<Member> {
    let text = |field: &[u8]| {
        field
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .collect::<Vec<_>>()
    };
    let number = |field: &[u8]| {
        u64::from_str_radix(std::str::from_utf8(&text(field)).unwrap().trim(), 8).unwrap()
    };
    let mut result = Vec::new();
    let mut at = 0;
    while bytes[at..at + 512].iter().any(|byte| *byte != 0) {
        let header = &bytes[at..at + 512];
        let mut name = text(&header[345..500]);
        if !name.is_empty() {
            name.push(b'/');
        }
        name.extend(text(&header[..100]));
        let size = number(&header[124..136]) as usize;
        result.push(Member {
            name,
            mode: number(&header[100..108]),
            kind: header[156],
            data: bytes[at + 512..at + 512 + size].to_vec(),
            link: text(&header[157..257]),
        });
        at += 512 + size.div_ceil(512) * 512;
    }
    assert_eq!(bytes.len() - at, 1024);
    assert!(bytes[at..].iter().all(|byte| *byte == 0));
    result
}

#[test]
fn complete_archives_preserve_bytes_modes_links_and_pin_every_read_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut first = true;
        let archive = collect(&options(format, 1), |query| {
            if first {
                assert_eq!(query.expected_head, None);
                first = false;
            } else {
                assert_eq!(query.expected_head, Some(pin(format).head));
                assert_eq!(query.expected_commit, Some(pin(format).commit));
            }
            Ok(report(format, query))
        })
        .unwrap();
        assert_eq!(archive.entries, 8);
        assert_eq!(archive.gitlinks, 1);
        let entries = members(&archive.bytes);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_slice())
                .collect::<Vec<_>>(),
            vec![
                b"source/".as_slice(),
                b"source/a.bin",
                b"source/bin/",
                b"source/bin/run",
                b"source/empty",
                b"source/link",
                b"source/submodule/",
                b"source/\xff"
            ]
        );
        assert_eq!(entries[1].data, [0, 255, 13, 10]);
        assert_eq!(entries[1].mode, 0o644);
        assert_eq!(entries[3].mode, 0o755);
        assert_eq!(entries[3].data, b"echo hi\n");
        assert_eq!(entries[4].data, b"");
        assert_eq!(entries[5].kind, b'2');
        assert_eq!(entries[5].link, b"bin/run");
        assert_eq!(entries[6].kind, b'5');
        let unpaged = collect(&options(format, 1000), |query| Ok(report(format, query))).unwrap();
        assert_eq!(
            archive.bytes, unpaged.bytes,
            "page boundaries must not change the archive"
        );
        assert!(archive.reads > unpaged.reads);
    }
}

#[test]
fn selected_subdirectory_keeps_repository_pins_but_has_its_own_export_root() {
    let format = GitHashAlgorithm::Sha256;
    let mut request = options(format, 1);
    request.query.path = Some(b"bin".to_vec());
    let archive = collect(&request, |query| Ok(report(format, query))).unwrap();
    assert_eq!(archive.root, oid(format, 4));
    assert_eq!(archive.pin.tree, oid(format, 1));
    assert_eq!(members(&archive.bytes).len(), 2);
    assert_eq!(members(&archive.bytes)[1].name, b"source/run");
}

#[test]
fn snapshot_repository_path_parent_object_and_file_kind_changes_refuse() {
    let format = GitHashAlgorithm::Sha1;
    for mutation in 0..9 {
        assert!(
            collect(&options(format, 1000), |query| {
                let mut result = report(format, query);
                if query.path.as_deref() == Some(b"a.bin") {
                    match mutation {
                        0 => {
                            result.source_head = RepositoryAuthorityHeadId::from_digest(
                                DigestAlgorithmId::try_new(2).unwrap(),
                                CANONICAL_CODEC_VERSION,
                                DigestBytes::try_new(&[7; 32]).unwrap(),
                            )
                        }
                        1 => result.source_commit = oid(format, 20),
                        2 => {
                            result.source_rcr = RepositoryCommitId::from_digest(
                                DigestAlgorithmId::try_new(2).unwrap(),
                                CANONICAL_CODEC_VERSION,
                                DigestBytes::try_new(&[7; 32]).unwrap(),
                            )
                        }
                        3 => result.root_tree = oid(format, 21),
                        4 => result.repository_id = RepositoryId::from_bytes([22; 16]),
                        5 => result.path = Some(b"other".to_vec()),
                        6 => result.object_id = oid(format, 23),
                        7 => {
                            if let SourceBrowseContent::Blob { kind, .. } = &mut result.content {
                                *kind = SourceEntryKind::Executable;
                            }
                        }
                        _ => {
                            if let SourceBrowseContent::Blob { next_offset, .. } =
                                &mut result.content
                            {
                                *next_offset = None;
                            }
                        }
                    }
                }
                Ok(result)
            })
            .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn duplicate_unordered_unsafe_and_nonprogressing_directories_refuse() {
    let format = GitHashAlgorithm::Sha1;
    for mutation in 0..4 {
        assert!(
            collect(&options(format, 1000), |query| {
                let mut result = report(format, query);
                if let SourceBrowseContent::Directory {
                    entries,
                    next_after,
                } = &mut result.content
                {
                    match mutation {
                        0 => entries.swap(0, 1),
                        1 => entries[1].name = entries[0].name.clone(),
                        2 => entries[0].name = b"../escape".to_vec(),
                        _ => *next_after = Some(b"a.bin".to_vec()),
                    }
                }
                Ok(result)
            })
            .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn read_failure_and_cancellation_withhold_complete_output() {
    let format = GitHashAlgorithm::Sha1;
    assert!(
        collect(&options(format, 1), |query| {
            if query.path.is_some() {
                Err("CancellationInProgress".into())
            } else {
                Ok(report(format, query))
            }
        })
        .is_err()
    );
}

#[test]
fn partial_requests_and_exhausted_read_budget_do_not_start_a_read() {
    let format = GitHashAlgorithm::Sha256;
    let mut request = options(format, 1);
    request.query.action = SourceBrowseAction::List {
        after: Some(b"a".to_vec()),
        limit: 1,
    };
    assert!(collect(&request, |_| panic!("partial archive must not read")).is_err());
    let mut selected = Selection {
        pin: None,
        root: None,
        reads: MAX_READS,
    };
    assert!(
        selected
            .read::<String>(
                &SelectionQuery {
                    repository: request.repository,
                    format: request.format,
                    query: &request.query,
                },
                &request.query,
                None,
                &mut |_| panic!("budget must precede I/O"),
            )
            .is_err()
    );
}

#[test]
fn an_oversized_file_is_rejected_from_its_first_range_before_full_allocation() {
    let format = GitHashAlgorithm::Sha1;
    let mut files = 0;
    let result = collect(&options(format, 1000), |query| {
        let mut result = report(format, query);
        if let SourceBrowseContent::Blob { total_bytes, .. } = &mut result.content {
            files += 1;
            *total_bytes = MAX_ARCHIVE_BYTES as u64 + 1;
        }
        Ok(result)
    });
    assert!(result.is_err());
    assert_eq!(files, 1);
}

#[test]
fn narrow_archive_budget_counts_exact_framing_and_preserves_the_permitted_twin() {
    let format = GitHashAlgorithm::Sha256;
    let request = options(format, 1000);
    let read_one = |query: &SourceBrowseQuery| {
        let mut result = report(format, query);
        if let SourceBrowseContent::Directory {
            entries,
            next_after,
        } = &mut result.content
        {
            entries.truncate(1);
            *next_after = None;
        }
        Ok::<_, String>(result)
    };
    let archive =
        collect_with_limit(request.repository, format, &request.query, 2560, read_one).unwrap();
    assert_eq!(archive.bytes.len(), 2560);
    assert_eq!(members(&archive.bytes)[1].data, [0, 255, 13, 10]);
    assert_eq!(archive.bytes, collect(&request, read_one).unwrap().bytes);
    let mut file_reads = 0;
    let refused = collect_with_limit(request.repository, format, &request.query, 2559, |query| {
        if let SourceBrowseAction::Read { limit, .. } = query.action {
            file_reads += 1;
            assert_eq!(
                limit, 1,
                "a tight response budget also bounds its first source range"
            );
        }
        read_one(query)
    });
    assert!(matches!(refused, Err(SourceArchiveError::Budget(_))));
    assert_eq!(
        file_reads, 1,
        "declared length refuses before any continuation or full-file allocation"
    );
}

#[test]
fn tiny_byte_limit_and_invalid_request_refuse_before_any_source_read() {
    let format = GitHashAlgorithm::Sha1;
    let request = options(format, 1000);
    assert!(matches!(
        collect_with_limit::<String>(
            request.repository,
            format,
            &request.query,
            MIN_ARCHIVE_BYTES - 1,
            |_| panic!("a complete prefix cannot fit"),
        ),
        Err(SourceArchiveError::Budget(_))
    ));
    for path in [b"".as_slice(), b"../outside", b"a//b"] {
        let mut query = request.query.clone();
        query.path = Some(path.to_vec());
        assert!(matches!(
            super::collect::<String>(request.repository, format, &query, |_| panic!(
                "invalid paths must refuse before I/O"
            ),),
            Err(SourceArchiveError::Invalid(_))
        ));
    }
    let mut query = request.query;
    query.expected_commit = Some(oid(GitHashAlgorithm::Sha256, 3));
    assert!(matches!(
        super::collect::<String>(request.repository, format, &query, |_| panic!(
            "mismatched native domain must refuse before I/O"
        ),),
        Err(SourceArchiveError::Invalid(_))
    ));
}

#[test]
fn empty_directory_and_header_only_symlink_fit_their_exact_transport_ceilings() {
    let format = GitHashAlgorithm::Sha1;
    let request = options(format, 1000);
    let archive = collect_with_limit(
        request.repository,
        format,
        &request.query,
        MIN_ARCHIVE_BYTES,
        |query| {
            let mut result = report(format, query);
            result.content = SourceBrowseContent::Directory {
                entries: Vec::new(),
                next_after: None,
            };
            Ok::<_, String>(result)
        },
    )
    .unwrap();
    assert_eq!(archive.bytes.len(), MIN_ARCHIVE_BYTES);
    assert_eq!(members(&archive.bytes).len(), 1);
    let archive = collect_with_limit(request.repository, format, &request.query, 2048, |query| {
        let mut result = report(format, query);
        if let SourceBrowseContent::Directory {
            entries,
            next_after,
        } = &mut result.content
        {
            entries.retain(|entry| entry.kind == SourceEntryKind::Symlink);
            *next_after = None;
        }
        Ok::<_, String>(result)
    })
    .unwrap();
    assert_eq!(archive.bytes.len(), 2048);
    let entries = members(&archive.bytes);
    assert_eq!(entries[1].kind, b'2');
    assert_eq!(entries[1].link, b"bin/run");
}

#[test]
fn source_errors_keep_their_type_and_are_not_reclassified_as_profile_failures() {
    #[derive(Debug, Eq, PartialEq)]
    enum ReadFailure {
        Cancelled,
        HiddenReference,
    }
    let format = GitHashAlgorithm::Sha1;
    let request = options(format, 1000);
    for failure in [ReadFailure::Cancelled, ReadFailure::HiddenReference] {
        let expected = match failure {
            ReadFailure::Cancelled => ReadFailure::Cancelled,
            ReadFailure::HiddenReference => ReadFailure::HiddenReference,
        };
        let mut failure = Some(failure);
        let result = super::collect(request.repository, format, &request.query, |_| {
            Err(failure.take().unwrap())
        });
        assert!(matches!(result, Err(SourceArchiveError::Read(observed)) if observed == expected));
    }
    let result = collect(&request, |query| {
        let mut result = report(format, query);
        if let SourceBrowseContent::Directory { entries, .. } = &mut result.content {
            entries[0].name = b".git".to_vec();
        }
        Ok(result)
    });
    assert!(matches!(result, Err(SourceArchiveError::Invalid(_))));
}

#[test]
fn symlink_target_length_is_a_profile_refusal_beside_the_exact_permitted_limit() {
    let format = GitHashAlgorithm::Sha256;
    let request = options(format, 1000);
    for length in [100_usize, 101] {
        let result =
            collect_with_limit(request.repository, format, &request.query, 2048, |query| {
                let mut result = report(format, query);
                match &mut result.content {
                    SourceBrowseContent::Directory {
                        entries,
                        next_after,
                    } => {
                        entries.retain(|entry| entry.kind == SourceEntryKind::Symlink);
                        *next_after = None;
                    }
                    SourceBrowseContent::Blob {
                        bytes,
                        total_bytes,
                        offset,
                        next_offset,
                        ..
                    } => {
                        let SourceBrowseAction::Read { limit, .. } = query.action else {
                            panic!("symlink payload must use a source read");
                        };
                        let remaining = length - *offset as usize;
                        let count = remaining.min(limit as usize);
                        *bytes = vec![b'a'; count];
                        *total_bytes = length as u64;
                        *next_offset = (count < remaining).then_some(*offset + count as u64);
                    }
                }
                Ok::<_, String>(result)
            });
        if length == 100 {
            let archive = result.unwrap();
            assert_eq!(archive.bytes.len(), 2048);
            assert_eq!(members(&archive.bytes)[1].link, vec![b'a'; 100]);
        } else {
            assert!(matches!(result, Err(SourceArchiveError::Invalid(_))));
        }
    }
}

#[test]
fn complete_file_export_checks_all_native_domains_and_rejects_zero_ids() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let request = options(format, 1000);
        let query = SourceBrowseQuery {
            path: Some(b"a.bin".to_vec()),
            expected_head: None,
            expected_commit: None,
            action: SourceBrowseAction::Read {
                offset: 0,
                limit: 10,
            },
        };
        let alternate = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        for mutation in 0..6 {
            let result = collect_file(request.repository, format, &query, |query| {
                let mut result = report(format, query);
                let changed = if mutation < 3 {
                    oid(alternate, 4)
                } else {
                    oid(format, 0)
                };
                match mutation % 3 {
                    0 => result.source_commit = changed,
                    1 => result.root_tree = changed,
                    _ => result.object_id = changed,
                }
                Ok::<_, String>(result)
            });
            assert!(
                matches!(result, Err(SourceArchiveError::Invalid(_))),
                "mutation {mutation}"
            );
        }
        let result = collect_file(request.repository, format, &query, |query| {
            Ok::<_, String>(report(format, query))
        })
        .unwrap();
        assert_eq!(result.bytes, [0, 255, 13, 10]);
    }
}

fn collect_format(
    options: &Options,
    archive_format: SourceArchiveFormat,
    reader: impl FnMut(&SourceBrowseQuery) -> Result<SourceBrowseReport, String>,
) -> Result<SourceArchive, SourceArchiveError<String>> {
    super::collect_with_format(
        options.repository,
        options.format,
        &options.query,
        archive_format,
        reader,
    )
}

const UTF8_NAME: &[u8] = b"\xc3\xa9";

fn utf8_report(format: GitHashAlgorithm, query: &SourceBrowseQuery) -> SourceBrowseReport {
    let mut original = query.clone();
    if original.path.as_deref() == Some(UTF8_NAME) {
        original.path = Some(b"\xff".to_vec());
    }
    if let SourceBrowseAction::List {
        after: Some(after), ..
    } = &mut original.action
    {
        if after.as_slice() == UTF8_NAME {
            *after = b"\xff".to_vec();
        }
    }
    let mut result = report(format, &original);
    result.path = query.path.clone();
    if let SourceBrowseContent::Directory {
        entries,
        next_after,
    } = &mut result.content
    {
        for entry in entries {
            if entry.name == b"\xff" {
                entry.name = UTF8_NAME.to_vec();
            }
        }
        if next_after.as_deref() == Some(b"\xff".as_slice()) {
            *next_after = Some(UTF8_NAME.to_vec());
        }
    }
    result
}

/// Inspect the central-directory view and its matching local records rather
/// than relying on the production encoder's retained metadata.
fn stored_zip_members(bytes: &[u8]) -> Vec<Member> {
    let u16_at = |at| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
    let u32_at = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let end = bytes.len() - 22;
    assert_eq!(u32_at(end), 0x0605_4b50);
    assert_eq!(u16_at(end + 8), u16_at(end + 10));
    let mut cursor = u32_at(end + 16) as usize;
    assert_eq!(cursor + u32_at(end + 12) as usize, end);
    let mut members = Vec::new();
    for _ in 0..u16_at(end + 8) {
        assert_eq!(u32_at(cursor), 0x0201_4b50);
        assert_eq!(u16_at(cursor + 8), 1 << 11);
        assert_eq!(u16_at(cursor + 10), 0);
        let size = u32_at(cursor + 24) as usize;
        let name_len = usize::from(u16_at(cursor + 28));
        let name = bytes[cursor + 46..cursor + 46 + name_len].to_vec();
        let mode = u32_at(cursor + 38) >> 16;
        let local = u32_at(cursor + 42) as usize;
        assert_eq!(u32_at(local), 0x0403_4b50);
        assert_eq!(u16_at(local + 26), u16_at(cursor + 28));
        assert_eq!(&bytes[local + 30..local + 30 + name_len], name);
        assert_eq!(u32_at(local + 22) as usize, size);
        let body = local + 30 + name_len + usize::from(u16_at(local + 28));
        let body = bytes[body..body + size].to_vec();
        let kind = match mode & 0o170000 {
            0o100000 => b'0',
            0o040000 => b'5',
            0o120000 => b'2',
            other => panic!("unexpected Unix member type {other:o}"),
        };
        members.push(Member {
            name,
            mode: u64::from(mode & 0o7777),
            kind,
            data: if kind == b'2' {
                Vec::new()
            } else {
                body.clone()
            },
            link: if kind == b'2' { body } else { Vec::new() },
        });
        cursor +=
            46 + name_len + usize::from(u16_at(cursor + 30)) + usize::from(u16_at(cursor + 32));
    }
    assert_eq!(cursor, end);
    members
}

#[test]
fn stored_zip_exports_exact_source_and_pins_every_page_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut calls = 0;
        let archive = collect_format(&options(format, 1), SourceArchiveFormat::Zip, |query| {
            if calls > 0 {
                assert_eq!(query.expected_head, Some(pin(format).head));
                assert_eq!(query.expected_commit, Some(pin(format).commit));
            }
            calls += 1;
            Ok(utf8_report(format, query))
        })
        .unwrap();
        let unpaged = collect_format(&options(format, 1000), SourceArchiveFormat::Zip, |query| {
            Ok(utf8_report(format, query))
        })
        .unwrap();
        assert_eq!(archive.bytes, unpaged.bytes);
        assert!(archive.reads > unpaged.reads);
        assert_eq!(archive.entries, 8);
        assert_eq!(archive.gitlinks, 1);
        let entries = stored_zip_members(&archive.bytes);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_slice())
                .collect::<Vec<_>>(),
            vec![
                b"source/".as_slice(),
                b"source/a.bin",
                b"source/bin/",
                b"source/bin/run",
                b"source/empty",
                b"source/link",
                b"source/submodule/",
                b"source/\xc3\xa9",
            ]
        );
        assert_eq!(entries[1].data, [0, 255, 13, 10]);
        assert_eq!(entries[3].mode, 0o755);
        assert_eq!(entries[3].data, b"echo hi\n");
        assert!(entries[4].data.is_empty());
        assert_eq!(entries[5].kind, b'2');
        assert_eq!(entries[5].link, b"bin/run");
        assert_eq!(entries[6].kind, b'5');
        assert!(entries[6].data.is_empty());
        assert_eq!(entries[7].data, b"raw name");

        let mut subtree = options(format, 1);
        subtree.query.path = Some(b"bin".to_vec());
        let subtree = collect_format(&subtree, SourceArchiveFormat::Zip, |query| {
            Ok(utf8_report(format, query))
        })
        .unwrap();
        assert_eq!(subtree.root, oid(format, 4));
        assert_eq!(subtree.pin.tree, oid(format, 1));
        assert_eq!(stored_zip_members(&subtree.bytes)[1].name, b"source/run");
    }
}

#[test]
fn zip_rejects_unrepresentable_names_without_changing_the_tar_profile() {
    let format = GitHashAlgorithm::Sha1;
    assert!(
        collect_format(&options(format, 1), SourceArchiveFormat::Zip, |query| {
            Ok(report(format, query))
        })
        .is_err()
    );
    assert!(
        collect_format(&options(format, 1), SourceArchiveFormat::Tar, |query| {
            Ok(report(format, query))
        })
        .is_ok()
    );

    let mut long_path = b"source/".to_vec();
    long_path.extend_from_slice(&[b'x'; 200]);
    let long_target = vec![b'y'; 200];
    let mut zip = Encoder::new(SourceArchiveFormat::Zip, MAX_ARCHIVE_BYTES).unwrap();
    zip.append(&long_path, SourceEntryKind::File, b"exact")
        .unwrap();
    zip.append(b"source/link", SourceEntryKind::Symlink, &long_target)
        .unwrap();
    assert_eq!(stored_zip_members(&zip.finish().unwrap()).len(), 2);
    assert!(
        Encoder::new(SourceArchiveFormat::Tar, MAX_ARCHIVE_BYTES)
            .unwrap()
            .append(&long_path, SourceEntryKind::File, b"exact")
            .is_err()
    );
    assert!(
        Encoder::new(SourceArchiveFormat::Tar, MAX_ARCHIVE_BYTES)
            .unwrap()
            .append(b"source/link", SourceEntryKind::Symlink, &long_target)
            .is_err()
    );

    for target in [
        b"/etc/passwd".as_slice(),
        b"../outside",
        b"a/../file",
        b"C:escape",
        b"x\\y",
        b"",
    ] {
        assert!(
            Encoder::new(SourceArchiveFormat::Zip, MAX_ARCHIVE_BYTES)
                .unwrap()
                .append(b"source/link", SourceEntryKind::Symlink, target)
                .is_err()
        );
    }
    for path in [
        b"source/.git/config".as_slice(),
        b"source/../outside",
        b"source/a\\b",
        b"source/a:b",
        b"source/control\x01",
    ] {
        assert!(
            Encoder::new(SourceArchiveFormat::Zip, MAX_ARCHIVE_BYTES)
                .unwrap()
                .append(path, SourceEntryKind::File, b"data")
                .is_err()
        );
    }
}

#[test]
fn zip_source_movement_cancellation_and_oversized_payloads_withhold_output() {
    let format = GitHashAlgorithm::Sha256;
    for mutation in 0..4 {
        assert!(
            collect_format(&options(format, 1), SourceArchiveFormat::Zip, |query| {
                if mutation == 0 && query.path.is_some() {
                    return Err("CancellationInProgress".into());
                }
                let mut result = utf8_report(format, query);
                if query.path.as_deref() == Some(b"a.bin") {
                    match mutation {
                        1 => result.object_id = oid(format, 99),
                        2 => result.source_commit = oid(format, 99),
                        3 => {
                            if let SourceBrowseContent::Blob { total_bytes, .. } =
                                &mut result.content
                            {
                                *total_bytes = MAX_ARCHIVE_BYTES as u64 + 1;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(result)
            })
            .is_err()
        );
    }
}

#[test]
fn zip_transport_ceiling_counts_both_name_copies_and_complete_central_directory() {
    let format = GitHashAlgorithm::Sha256;
    let request = options(format, 1000);
    let read_one = |query: &SourceBrowseQuery| {
        let mut result = report(format, query);
        if let SourceBrowseContent::Directory {
            entries,
            next_after,
        } = &mut result.content
        {
            entries.truncate(1);
            *next_after = None;
        }
        Ok::<_, String>(result)
    };
    // source/ contributes 30+7+46+7, source/a.bin contributes
    // 30+12+4+46+12, and the end record contributes 22.
    let exact_bytes = 216;
    let archive = collect_with_format_and_limit(
        request.repository,
        format,
        &request.query,
        SourceArchiveFormat::Zip,
        exact_bytes,
        read_one,
    )
    .unwrap();
    assert_eq!(archive.bytes.len(), exact_bytes);
    assert_eq!(stored_zip_members(&archive.bytes)[1].data, [0, 255, 13, 10]);
    assert_eq!(
        archive.bytes,
        collect_format(&request, SourceArchiveFormat::Zip, read_one)
            .unwrap()
            .bytes
    );
    let mut reads = 0;
    let refused = collect_with_format_and_limit(
        request.repository,
        format,
        &request.query,
        SourceArchiveFormat::Zip,
        exact_bytes - 1,
        |query| {
            if let SourceBrowseAction::Read { limit, .. } = query.action {
                reads += 1;
                assert_eq!(
                    limit, 3,
                    "first source range uses the framing-adjusted ceiling"
                );
            }
            read_one(query)
        },
    );
    assert!(matches!(refused, Err(SourceArchiveError::Budget(_))));
    assert_eq!(
        reads, 1,
        "declared size refuses before continuing or allocating the body"
    );
}

#[test]
fn zip_minimum_prefix_and_typed_read_failures_refuse_without_partial_output() {
    let format = GitHashAlgorithm::Sha1;
    let request = options(format, 1000);
    assert!(matches!(
        collect_with_format_and_limit::<String>(
            request.repository,
            format,
            &request.query,
            SourceArchiveFormat::Zip,
            111,
            |_| panic!("even the source/ directory and end record cannot fit"),
        ),
        Err(SourceArchiveError::Budget(_))
    ));
    let archive = collect_with_format_and_limit(
        request.repository,
        format,
        &request.query,
        SourceArchiveFormat::Zip,
        112,
        |query| {
            let mut result = report(format, query);
            result.content = SourceBrowseContent::Directory {
                entries: Vec::new(),
                next_after: None,
            };
            Ok::<_, String>(result)
        },
    )
    .unwrap();
    assert_eq!(archive.bytes.len(), 112);
    assert_eq!(stored_zip_members(&archive.bytes).len(), 1);
    #[derive(Debug, Eq, PartialEq)]
    struct Cancelled;
    let refused = super::collect_with_format(
        request.repository,
        format,
        &request.query,
        SourceArchiveFormat::Zip,
        |_| Err(Cancelled),
    );
    assert!(matches!(refused, Err(SourceArchiveError::Read(Cancelled))));
}
