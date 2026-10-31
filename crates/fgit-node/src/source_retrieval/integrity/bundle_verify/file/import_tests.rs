//! Real private files and the production retained verifier; no manufactured
//! verification receipts, scratch spans or authority evidence.

use super::*;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

struct ScratchPath(PathBuf);

impl ScratchPath {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "fgit-bundle-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory.join("objects.scratch"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchPath {
    fn drop(&mut self) {
        let _file = fs::remove_file(&self.0);
        let _directory = fs::remove_dir(self.0.parent().unwrap());
    }
}

fn prepare(
    bytes: &[u8],
    format: GitHashAlgorithm,
    scratch: &ScratchPath,
    limits: &BundleVerifyLimits,
) -> Result<FullBundleImportPlan, BundleVerifyError> {
    prepare_full_bundle_import_reader(
        &mut Cursor::new(bytes),
        format,
        scratch.path(),
        limits,
        &mut || true,
    )
}

fn blob(plan: &mut FullBundleImportPlan, identity: GitOid) -> Vec<u8> {
    let mut live = || true;
    let mut reader = plan.open_blob(identity, &mut live).unwrap();
    let mut bytes = Vec::new();
    // Exercise reads that end within spans and require a separate terminal
    // call, rather than treating the promised byte count as authentication.
    let mut chunk = [0_u8; 7];
    loop {
        let count = reader.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    bytes
}

#[test]
fn import_plan_preserves_native_fixture_evidence_and_cleans_owned_scratch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = fixture(format);
        let expected = verify(&input).unwrap();
        let scratch = ScratchPath::new();
        let mut plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
        assert_same(plan.verified(), expected.verified());
        assert_eq!(plan.receipt().format(), format);
        assert_eq!(plan.receipt().trailer(), plan.verified().pack_checksum());
        assert_eq!(plan.receipt().pack_sha256(), *expected.pack_sha256());
        assert_eq!(plan.receipt().pack_bytes(), expected.pack_len());
        assert_eq!(
            plan.receipt().header().object_count as usize,
            plan.verified().graph().objects
        );
        let identities: Vec<_> = plan.selected_ids().iter().copied().collect();
        let mut total = 0_u64;
        for identity in identities {
            let facts = plan.object(identity).unwrap();
            let body = if facts.kind == ObjectKind::Blob {
                blob(&mut plan, identity)
            } else {
                plan.read_metadata(identity, &mut || true).unwrap()
            };
            assert_eq!(body.len(), facts.length);
            assert_eq!(git_object_id(format, facts.kind, &body), identity);
            total += body.len() as u64;
        }
        assert_eq!(total, plan.total_selected_bytes());
        assert!(scratch.path().exists());
        plan.finish().unwrap();
        assert!(!scratch.path().exists());
    }
}

#[test]
fn selected_native_graph_excludes_unrelated_uploads_and_external_gitlinks() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let body = b"selected payload";
        let payload = git_object_id(format, ObjectKind::Blob, body);
        let external = git_object_id(format, ObjectKind::Commit, b"not present locally");
        let mut tree = b"160000 external\0".to_vec();
        tree.extend_from_slice(external.as_bytes());
        tree.extend_from_slice(b"100644 kept\0");
        tree.extend_from_slice(payload.as_bytes());
        let tree_id = git_object_id(format, ObjectKind::Tree, &tree);
        let commit = format!(
            "tree {}\nauthor A <a@example.test> 0 +0000\ncommitter A <a@example.test> 0 +0000\n\nselected\n",
            lowercase_hex(tree_id.as_bytes())
        );
        let commit_id = git_object_id(format, ObjectKind::Commit, commit.as_bytes());
        let tag = format!(
            "object {}\ntype commit\ntag selected\ntagger A <a@example.test> 0 +0000\n\nselected\n",
            lowercase_hex(commit_id.as_bytes())
        );
        let tag_id = git_object_id(format, ObjectKind::Tag, tag.as_bytes());
        let unrelated = git_object_id(format, ObjectKind::Blob, b"unrelated upload");
        let input = bundle(
            format,
            &[
                record(4, tag.as_bytes(), &[]),
                record(3, b"unrelated upload", &[]),
                record(2, &tree, &[]),
                record(3, body, &[]),
                record(1, commit.as_bytes(), &[]),
            ],
            tag_id,
        );
        let scratch = ScratchPath::new();
        let mut plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
        assert_eq!(plan.verified().graph().objects, 5);
        assert_eq!(plan.verified().graph().external_gitlinks, 1);
        assert_eq!(
            plan.selected_ids(),
            &BTreeSet::from([tag_id, commit_id, tree_id, payload])
        );
        assert!(plan.object(unrelated).is_none());
        assert!(plan.object(external).is_none());
        assert_eq!(
            plan.read_metadata(tag_id, &mut || true).unwrap(),
            tag.as_bytes()
        );
        assert_eq!(
            plan.read_metadata(commit_id, &mut || true).unwrap(),
            commit.as_bytes()
        );
        assert_eq!(plan.read_metadata(tree_id, &mut || true).unwrap(), tree);
        assert_eq!(blob(&mut plan, payload), body);
        plan.finish().unwrap();
        assert!(!scratch.path().exists());
    }
}

#[test]
fn large_blob_delta_import_keeps_transport_bases_for_ofs_and_forward_ref() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = vec![b'x'; 4096];
        let mut result = base.clone();
        result.push(b'!');
        let base_id = git_object_id(format, ObjectKind::Blob, &base);
        let result_id = git_object_id(format, ObjectKind::Blob, &result);
        // Native size varints, a copy of 4096 bytes, then one inserted byte.
        let program = [0x80, 0x20, 0x81, 0x20, 0xa0, 0x10, 1, b'!'];
        let base_row = record(3, &base, &[]);
        let unrelated = record(3, b"unselected", &[]);
        let layouts = [
            vec![
                base_row.clone(),
                record(6, &program, &ofs(base_row.len() as u64)),
                unrelated.clone(),
            ],
            vec![record(7, &program, base_id.as_bytes()), unrelated, base_row],
        ];
        let limits = BundleVerifyLimits {
            max_streamed_blob_bytes: 8192,
            pack: fgit_pack::PackLimits {
                max_object_bytes: 512,
                ..BundleVerifyLimits::default().pack
            },
            graph: fgit_treefs::integrity::GraphLimits {
                max_object_bytes: 512,
                ..BundleVerifyLimits::default().graph
            },
            ..BundleVerifyLimits::default()
        };
        for records in layouts {
            let input = bundle(format, &records, result_id);
            let scratch = ScratchPath::new();
            let mut plan = prepare(&input, format, &scratch, &limits).unwrap();
            assert_eq!(plan.selected_ids(), &BTreeSet::from([base_id, result_id]));
            assert_eq!(plan.verified().graph().objects, 3);
            assert_eq!(plan.verified().delta_objects(), 1);
            assert_eq!(
                plan.total_selected_bytes(),
                (base.len() + result.len()) as u64
            );
            assert_eq!(blob(&mut plan, base_id), base);
            assert_eq!(blob(&mut plan, result_id), result);
            plan.finish().unwrap();

            let mut limited = limits.clone();
            limited.max_streamed_blob_bytes = result.len() - 1;
            assert!(prepare(&input, format, &scratch, &limited).is_err());
            assert!(!scratch.path().exists());
        }
    }
}

#[test]
fn malformed_unselected_objects_missing_dependencies_and_prerequisites_refuse() {
    let format = GitHashAlgorithm::Sha1;
    let body = b"selected";
    let target = git_object_id(format, ObjectKind::Blob, body);
    let missing = git_object_id(format, ObjectKind::Tree, b"missing");
    let commit = format!("tree {}\n\nmissing\n", lowercase_hex(missing.as_bytes()));
    let commit_id = git_object_id(format, ObjectKind::Commit, commit.as_bytes());
    let complete = bundle(format, &[record(3, body, &[])], target);
    let mut prerequisites = b"# v2 git bundle\n".to_vec();
    prerequisites
        .extend_from_slice(format!("-{} base\n", lowercase_hex(commit_id.as_bytes())).as_bytes());
    prerequisites.extend_from_slice(&complete[b"# v2 git bundle\n".len()..]);
    let inputs = [
        bundle(
            format,
            &[record(3, body, &[]), record(1, b"not a commit", &[])],
            target,
        ),
        bundle(format, &[record(1, commit.as_bytes(), &[])], commit_id),
        bundle(
            format,
            &[record(7, &delta(b"base", body), missing.as_bytes())],
            target,
        ),
        prerequisites,
    ];
    for input in inputs {
        let scratch = ScratchPath::new();
        assert!(prepare(&input, format, &scratch, &BundleVerifyLimits::default()).is_err());
        assert!(!scratch.path().exists());
    }
}

#[test]
fn wrong_format_bad_trailer_and_occupied_scratch_never_leave_a_plan() {
    let format = GitHashAlgorithm::Sha256;
    let body = b"verified";
    let target = git_object_id(format, ObjectKind::Blob, body);
    let input = bundle(format, &[record(3, body, &[])], target);
    let scratch = ScratchPath::new();
    assert!(matches!(
        prepare(
            &input,
            GitHashAlgorithm::Sha1,
            &scratch,
            &BundleVerifyLimits::default()
        ),
        Err(BundleVerifyError::Pack(
            fgit_pack::PackError::ObjectFormatMismatch { .. }
        ))
    ));
    assert!(!scratch.path().exists());
    let mut broken = input.clone();
    *broken.last_mut().unwrap() ^= 1;
    assert!(prepare(&broken, format, &scratch, &BundleVerifyLimits::default()).is_err());
    assert!(!scratch.path().exists());
    fs::write(scratch.path(), b"another owner").unwrap();
    assert!(prepare(&input, format, &scratch, &BundleVerifyLimits::default()).is_err());
    assert_eq!(fs::read(scratch.path()).unwrap(), b"another owner");
}

#[test]
fn original_scratch_checksum_and_abandoned_reader_poison_later_import_use() {
    let format = GitHashAlgorithm::Sha256;
    let body = b"original payload";
    let target = git_object_id(format, ObjectKind::Blob, body);
    let input = bundle(format, &[record(3, body, &[])], target);
    let scratch = ScratchPath::new();
    let mut plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
    let mut changed = OpenOptions::new().write(true).open(scratch.path()).unwrap();
    changed.write_all(b"X").unwrap();
    drop(changed);
    {
        let mut live = || true;
        let mut reader = plan.open_blob(target, &mut live).unwrap();
        let mut copied = Vec::new();
        assert!(reader.read_to_end(&mut copied).is_err());
        assert!(reader.read(&mut [0]).is_err());
    }
    assert!(plan.finish().is_err());
    assert!(!scratch.path().exists());

    let mut plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
    {
        let mut live = || true;
        let mut reader = plan.open_blob(target, &mut live).unwrap();
        let mut exact = vec![0; body.len()];
        reader.read_exact(&mut exact).unwrap();
        assert_eq!(exact, body);
        // Reading the declared length alone has not checked EOF/commitment.
    }
    assert!(plan.finish().is_err());
    assert!(!scratch.path().exists());
}

#[test]
fn cancellation_and_source_replacement_cleanup_without_fresh_evidence() {
    let format = GitHashAlgorithm::Sha1;
    let body = b"advertised";
    let target = git_object_id(format, ObjectKind::Blob, body);
    let input = bundle(
        format,
        &[record(3, body, &[]), record(3, b"first", &[])],
        target,
    );
    let replacement = bundle(
        format,
        &[record(3, body, &[]), record(3, b"other", &[])],
        target,
    );
    let scratch = ScratchPath::new();
    let mut source = MovingSource {
        input: Cursor::new(input.clone()),
        replacement,
        starts: 0,
    };
    assert!(matches!(
        prepare_full_bundle_import_reader(
            &mut source,
            format,
            scratch.path(),
            &BundleVerifyLimits::default(),
            &mut || true
        ),
        Err(BundleVerifyError::SourceChanged)
    ));
    assert!(!scratch.path().exists());
    for stop in [1, 8, 24] {
        let mut calls = 0;
        assert!(matches!(
            prepare_full_bundle_import_reader(
                &mut Cursor::new(&input),
                format,
                scratch.path(),
                &BundleVerifyLimits::default(),
                &mut || {
                    calls += 1;
                    calls != stop
                }
            ),
            Err(BundleVerifyError::Stopped)
        ));
        assert!(!scratch.path().exists());
    }
    let mut plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
    let mut calls = 0;
    let mut live = || {
        calls += 1;
        calls != 2
    };
    assert!(plan.open_blob(target, &mut live).is_err());
    assert!(plan.open_blob(target, &mut || true).is_err());
    assert!(plan.finish().is_err());
    assert!(!scratch.path().exists());

    let plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
    drop(plan);
    assert!(!scratch.path().exists());
}

#[test]
fn same_byte_scratch_replacements_survive_finish_and_drop() {
    let format = GitHashAlgorithm::Sha256;
    let body = b"original payload";
    let target = git_object_id(format, ObjectKind::Blob, body);
    let input = bundle(format, &[record(3, body, &[])], target);
    for explicit in [true, false] {
        let scratch = ScratchPath::new();
        let mut plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
        let original = scratch.path().with_file_name("renamed-original");
        let bytes = fs::read(scratch.path()).unwrap();
        fs::rename(scratch.path(), &original).unwrap();
        fs::write(scratch.path(), &bytes).unwrap();
        // Reads retain their original descriptor and original span checksum;
        // equal contents do not establish ownership of a replacement pathname.
        assert_eq!(blob(&mut plan, target), body);
        if explicit {
            assert!(matches!(
                plan.finish(),
                Err(BundleVerifyError::ScratchChanged)
            ));
        } else {
            drop(plan);
        }
        assert_eq!(fs::read(scratch.path()).unwrap(), bytes);
        assert_eq!(fs::read(&original).unwrap(), bytes);
        fs::remove_file(original).unwrap();
    }
}

#[test]
fn scratch_symlinks_to_the_original_survive_finish_and_drop() {
    use std::os::unix::fs::symlink;

    let format = GitHashAlgorithm::Sha1;
    let body = b"original payload";
    let target = git_object_id(format, ObjectKind::Blob, body);
    let input = bundle(format, &[record(3, body, &[])], target);
    for explicit in [true, false] {
        let scratch = ScratchPath::new();
        let plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
        let original = scratch.path().with_file_name("renamed-original");
        let bytes = fs::read(scratch.path()).unwrap();
        fs::rename(scratch.path(), &original).unwrap();
        symlink(&original, scratch.path()).unwrap();
        if explicit {
            assert!(matches!(
                plan.finish(),
                Err(BundleVerifyError::ScratchChanged)
            ));
        } else {
            drop(plan);
        }
        assert!(
            fs::symlink_metadata(scratch.path())
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(scratch.path()).unwrap(), original);
        assert_eq!(fs::read(&original).unwrap(), bytes);
        fs::remove_file(original).unwrap();
    }
}

#[test]
fn cleanup_errors_and_missing_paths_refuse_without_unowned_removal() {
    let format = GitHashAlgorithm::Sha1;
    let input = fixture(format);
    let scratch = ScratchPath::new();
    let plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
    let bytes = fs::read(scratch.path()).unwrap();
    let directory = scratch.path().parent().unwrap();
    let moved = directory.with_extension("moved");
    fs::rename(directory, &moved).unwrap();
    fs::write(directory, b"unowned parent replacement").unwrap();
    // A non-directory ancestor makes inspection fail deterministically even
    // when tests run as root; permissions alone cannot exercise that case.
    assert!(matches!(
        plan.finish(),
        Err(BundleVerifyError::Io {
            operation: "inspect bundle import scratch for cleanup",
            kind: io::ErrorKind::NotADirectory,
        })
    ));
    assert_eq!(fs::read(directory).unwrap(), b"unowned parent replacement");
    assert_eq!(
        fs::read(moved.join(scratch.path().file_name().unwrap())).unwrap(),
        bytes
    );
    fs::remove_file(directory).unwrap();
    fs::rename(&moved, directory).unwrap();
    fs::remove_file(scratch.path()).unwrap();

    let mut plan = prepare(&input, format, &scratch, &BundleVerifyLimits::default()).unwrap();
    fs::remove_file(scratch.path()).unwrap();
    // An open-but-unlinked original can still be authenticated. Completion
    // nevertheless reports the lost pathname custody, then closes that inode.
    let identity = *plan.selected_ids().iter().next().unwrap();
    let facts = plan.object(identity).unwrap();
    if facts.kind == ObjectKind::Blob {
        assert_eq!(blob(&mut plan, identity).len(), facts.length);
    } else {
        assert_eq!(
            plan.read_metadata(identity, &mut || true).unwrap().len(),
            facts.length
        );
    }
    assert!(matches!(
        plan.finish(),
        Err(BundleVerifyError::ScratchChanged)
    ));
    assert!(!scratch.path().exists());
}

#[test]
fn cancellation_cleanup_preserves_a_replacement_created_by_the_source() {
    let format = GitHashAlgorithm::Sha1;
    let input = fixture(format);
    let scratch = ScratchPath::new();
    let original = scratch.path().with_file_name("renamed-original");
    let mut replaced = false;
    assert!(matches!(
        prepare_full_bundle_import_reader(
            &mut Cursor::new(&input),
            format,
            scratch.path(),
            &BundleVerifyLimits::default(),
            &mut || {
                if !replaced && scratch.path().exists() {
                    fs::rename(scratch.path(), &original).unwrap();
                    fs::write(scratch.path(), b"another owner's replacement").unwrap();
                    replaced = true;
                    return false;
                }
                true
            },
        ),
        Err(BundleVerifyError::ScratchChanged)
    ));
    assert!(replaced);
    assert_eq!(
        fs::read(scratch.path()).unwrap(),
        b"another owner's replacement"
    );
    assert!(original.is_file());
    fs::remove_file(original).unwrap();
}

fn named_fetch_bundle(
    format: GitHashAlgorithm,
    records: &[Vec<u8>],
    references: &[(&[u8], GitOid)],
    head: Option<GitOid>,
) -> Vec<u8> {
    let original = bundle(format, records, references[0].1);
    let input =
        fgit_pack::full_bundle::FullBundleInput::parse(&original, Default::default(), &mut || true)
            .unwrap();
    let mut output = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    if let Some(head) = head {
        output.extend_from_slice(format!("{} HEAD\n", lowercase_hex(head.as_bytes())).as_bytes());
    }
    for &(name, target) in references {
        output.extend_from_slice(lowercase_hex(target.as_bytes()).as_bytes());
        output.push(b' ');
        output.extend_from_slice(name);
        output.push(b'\n');
    }
    output.push(b'\n');
    output.extend_from_slice(input.pack_bytes());
    output
}

fn fetch_commit(tree: GitOid, parent: Option<GitOid>, message: &str) -> Vec<u8> {
    let mut body = format!("tree {}\n", lowercase_hex(tree.as_bytes()));
    if let Some(parent) = parent {
        writeln!(body, "parent {}", lowercase_hex(parent.as_bytes()))
            .expect("writing to a String cannot fail");
    }
    body.push_str("author A <a@example.test> 0 +0000\ncommitter A <a@example.test> 0 +0000\n\n");
    body.push_str(message);
    body.push('\n');
    body.into_bytes()
}

fn prepare_fetch(
    bytes: &[u8],
    format: GitHashAlgorithm,
    scratch: &ScratchPath,
    sources: &[fgit_types::RefName],
    limits: &BundleVerifyLimits,
) -> Result<FullBundleImportPlan, BundleVerifyError> {
    prepare_full_bundle_fetch_reader(
        &mut Cursor::new(bytes),
        format,
        scratch.path(),
        sources,
        limits,
        &mut || true,
    )
}

#[test]
fn mapped_sources_select_only_their_native_closure_and_keep_full_original_evidence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let empty_tree = git_object_id(format, ObjectKind::Tree, b"");
        let base_body = fetch_commit(empty_tree, None, "base");
        let base = git_object_id(format, ObjectKind::Commit, &base_body);
        let body = b"selected payload";
        let payload = git_object_id(format, ObjectKind::Blob, body);
        let mut tree_body = b"100644 kept\0".to_vec();
        tree_body.extend_from_slice(payload.as_bytes());
        let tree = git_object_id(format, ObjectKind::Tree, &tree_body);
        let tip_body = fetch_commit(tree, Some(base), "selected");
        let tip = git_object_id(format, ObjectKind::Commit, &tip_body);
        let other_body = b"unselected payload";
        let other_payload = git_object_id(format, ObjectKind::Blob, other_body);
        let mut other_tree_body = b"100644 other\0".to_vec();
        other_tree_body.extend_from_slice(other_payload.as_bytes());
        let other_tree = git_object_id(format, ObjectKind::Tree, &other_tree_body);
        let other_commit_body = fetch_commit(other_tree, None, "unselected");
        let other_commit = git_object_id(format, ObjectKind::Commit, &other_commit_body);
        let input = named_fetch_bundle(
            format,
            &[
                record(1, &other_commit_body, &[]),
                record(2, b"", &[]),
                record(1, &tip_body, &[]),
                record(3, other_body, &[]),
                record(2, &tree_body, &[]),
                record(1, &base_body, &[]),
                record(2, &other_tree_body, &[]),
                record(3, body, &[]),
            ],
            &[
                (b"refs/heads/unselected", other_commit),
                (b"refs/heads/\xff", tip),
            ],
            Some(other_commit),
        );
        let full = verify(&input).unwrap();
        let selected = fgit_types::RefName::try_new(b"refs/heads/\xff").unwrap();
        // More mapping sources than distinct advertisements is ordinary fanout,
        // not an invitation to stage the other advertised branch or HEAD.
        for sources in [
            vec![selected.clone()],
            vec![selected.clone(), selected.clone(), selected.clone()],
        ] {
            let scratch = ScratchPath::new();
            let mut plan = prepare_fetch(
                &input,
                format,
                &scratch,
                &sources,
                &BundleVerifyLimits::default(),
            )
            .unwrap();
            assert_same(plan.verified(), full.verified());
            assert_eq!(plan.verified().advertised_head(), Some(other_commit));
            assert_eq!(plan.verified().graph().objects, 8);
            assert_eq!(plan.receipt().header().object_count, 8);
            assert_eq!(plan.receipt().pack_sha256(), *full.pack_sha256());
            assert_eq!(plan.receipt().trailer(), full.verified().pack_checksum());
            assert_eq!(
                plan.selected_ids(),
                &BTreeSet::from([empty_tree, base, payload, tree, tip])
            );
            for unselected in [other_payload, other_tree, other_commit] {
                assert!(plan.object(unselected).is_none());
            }
            // A true ancestor's metadata is present for the caller's native
            // fast-forward walk, even though only the tip ref was mapped.
            assert_eq!(plan.read_metadata(base, &mut || true).unwrap(), base_body);
            assert_eq!(plan.read_metadata(tip, &mut || true).unwrap(), tip_body);
            assert_eq!(plan.read_metadata(tree, &mut || true).unwrap(), tree_body);
            assert_eq!(blob(&mut plan, payload), body);
            assert_eq!(
                plan.total_selected_bytes(),
                (base_body.len() + body.len() + tree_body.len() + tip_body.len()) as u64
            );
            plan.finish().unwrap();
            assert!(!scratch.path().exists());
        }
    }
}

#[test]
fn mapped_delta_results_retain_unselected_transport_bases_in_both_native_layouts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = vec![b'x'; 4096];
        let mut result = base.clone();
        result.push(b'!');
        let base_id = git_object_id(format, ObjectKind::Blob, &base);
        let result_id = git_object_id(format, ObjectKind::Blob, &result);
        let unrelated_id = git_object_id(format, ObjectKind::Blob, b"unselected");
        let program = [0x80, 0x20, 0x81, 0x20, 0xa0, 0x10, 1, b'!'];
        let base_row = record(3, &base, &[]);
        let layouts = [
            vec![
                base_row.clone(),
                record(6, &program, &ofs(base_row.len() as u64)),
                record(3, b"unselected", &[]),
            ],
            vec![
                record(7, &program, base_id.as_bytes()),
                record(3, b"unselected", &[]),
                base_row,
            ],
        ];
        let limits = BundleVerifyLimits {
            max_streamed_blob_bytes: 8192,
            pack: fgit_pack::PackLimits {
                max_object_bytes: 512,
                ..BundleVerifyLimits::default().pack
            },
            graph: fgit_treefs::integrity::GraphLimits {
                max_object_bytes: 512,
                ..BundleVerifyLimits::default().graph
            },
            ..BundleVerifyLimits::default()
        };
        let source = fgit_types::RefName::try_new(b"refs/tags/result").unwrap();
        for records in layouts {
            let input = named_fetch_bundle(
                format,
                &records,
                &[
                    (b"refs/tags/base", base_id),
                    (b"refs/tags/unrelated", unrelated_id),
                    (b"refs/tags/result", result_id),
                ],
                None,
            );
            let scratch = ScratchPath::new();
            let mut plan = prepare_fetch(
                &input,
                format,
                &scratch,
                std::slice::from_ref(&source),
                &limits,
            )
            .unwrap();
            assert_eq!(plan.verified().graph().objects, 3);
            assert_eq!(plan.verified().delta_objects(), 1);
            assert_eq!(plan.selected_ids(), &BTreeSet::from([base_id, result_id]));
            assert!(plan.object(unrelated_id).is_none());
            assert_eq!(blob(&mut plan, base_id), base);
            assert_eq!(blob(&mut plan, result_id), result);
            plan.finish().unwrap();
            assert!(!scratch.path().exists());
        }
    }
}

#[test]
fn mapped_selection_refuses_absent_sources_and_still_audits_unselected_uploads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let body = b"selected payload";
        let target = git_object_id(format, ObjectKind::Blob, body);
        let source = fgit_types::RefName::try_new(b"refs/tags/result").unwrap();
        let absent = fgit_types::RefName::try_new(b"refs/tags/absent").unwrap();
        let complete = bundle(format, &[record(3, body, &[])], target);
        let scratch = ScratchPath::new();
        for sources in [
            vec![],
            vec![absent],
            vec![
                source.clone(),
                fgit_types::RefName::try_new(b"refs/tags/missing").unwrap(),
            ],
        ] {
            assert!(
                prepare_fetch(
                    &complete,
                    format,
                    &scratch,
                    &sources,
                    &BundleVerifyLimits::default(),
                )
                .is_err()
            );
            assert!(!scratch.path().exists());
        }
        let missing = git_object_id(format, ObjectKind::Tree, b"missing local tree");
        let disconnected_commit = fetch_commit(missing, None, "unselected missing dependency");
        let external = git_object_id(format, ObjectKind::Blob, b"external base");
        for records in [
            vec![
                record(3, body, &[]),
                record(1, b"malformed unselected commit", &[]),
            ],
            vec![record(3, body, &[]), record(1, &disconnected_commit, &[])],
            vec![
                record(3, body, &[]),
                record(
                    7,
                    &delta(b"external base", b"external result"),
                    external.as_bytes(),
                ),
            ],
        ] {
            let input = bundle(format, &records, target);
            assert!(
                prepare_fetch(
                    &input,
                    format,
                    &scratch,
                    std::slice::from_ref(&source),
                    &BundleVerifyLimits::default(),
                )
                .is_err()
            );
            assert!(!scratch.path().exists());
        }
        let mut valid = prepare_fetch(
            &complete,
            format,
            &scratch,
            &[source],
            &BundleVerifyLimits::default(),
        )
        .unwrap();
        assert_eq!(blob(&mut valid, target), body);
        valid.finish().unwrap();
        assert!(!scratch.path().exists());
    }
}
