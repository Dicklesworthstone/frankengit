//! Exact source-ref selection without object or authority fixtures.
use super::super::refs::{MAX_SYMBOLIC_REF_DEPTH, SourceRef, resolve};
use super::super::source_io::parse_source_ref;
use super::super::{ImportControl, LooseGitImportRefusal, RefName, layout::SourceLayout};
use super::{GitHashAlgorithm, GitOid, Path, PathBuf, ScratchDirectory, fs};
use std::collections::BTreeMap;

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).unwrap()
}

fn id(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}

fn alias(target: &str, path: &str) -> SourceRef {
    SourceRef::Symbolic {
        target: name(target),
        path: PathBuf::from(path),
    }
}

fn read_refs(
    root: &Path,
    format: GitHashAlgorithm,
    limit: usize,
) -> Result<BTreeMap<RefName, GitOid>, LooseGitImportRefusal> {
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    SourceLayout::resolve(root, &control)?.read_refs(format, limit, &control)
}

fn write_ref(root: &Path, name: &str, contents: &[u8]) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

#[test]
fn selected_loose_and_packed_overrides_are_resolved_before_aliases() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let root = scratch.0.join("checkout/.git");
        fs::create_dir_all(root.join("objects")).unwrap();
        let old = id(format, 1);
        let current = id(format, 2);
        write_ref(&root, "HEAD", b"ref: refs/heads/main\n");
        write_ref(&root, "packed-refs", format!(
            "{old} refs/heads/main\n{old} refs/remotes/origin/HEAD\n{old} refs/remotes/origin/main\n"
        ).as_bytes());
        write_ref(&root, "refs/heads/main", format!("{current}\n").as_bytes());
        write_ref(&root, "refs/remotes/origin/main", b"ref: refs/heads/main\n");
        write_ref(
            &root,
            "refs/remotes/origin/HEAD",
            b"ref: refs/remotes/origin/main\n",
        );
        let refs = read_refs(root.parent().unwrap(), format, 3).unwrap();
        assert_eq!(refs.len(), 3, "overrides do not spend a second ref slot");
        assert!(refs.values().all(|value| *value == current));
        assert!(matches!(
            read_refs(root.parent().unwrap(), format, 2),
            Err(LooseGitImportRefusal::RefLimitExceeded {
                observed: 3,
                limit: 2
            })
        ));
    }
}

#[test]
fn every_symbolic_target_is_a_name_in_the_selected_map() {
    let path = Path::new("refs/remotes/origin/HEAD");
    let format = GitHashAlgorithm::Sha1;
    for target in [
        "HEAD",
        "FETCH_HEAD",
        "heads/main",
        "worktrees/other/refs/heads/main",
        "/etc/passwd",
    ] {
        assert!(
            matches!(
                parse_source_ref(path, format!("ref: {target}\n").as_bytes(), format),
                Err(LooseGitImportRefusal::SymbolicRefUnsupported(_))
            ),
            "{target}"
        );
    }
    for target in [
        "refs/../outside",
        "refs/heads/main\nrefs/heads/other",
        "refs/heads/main\r",
        "refs/heads/main ",
        "refs/heads/main\0",
        "refs/heads/../main",
    ] {
        assert!(
            matches!(
                parse_source_ref(path, format!("ref: {target}\n").as_bytes(), format),
                Err(LooseGitImportRefusal::RefName { .. })
            ),
            "{target:?}"
        );
    }
    assert!(matches!(
        parse_source_ref(path, b"ref: refs/heads/main", format),
        Err(LooseGitImportRefusal::RefContents(_))
    ));
    let mut refs = BTreeMap::from([
        (name("refs/heads/main"), SourceRef::Direct(id(format, 1))),
        (
            name("refs/remotes/origin/HEAD"),
            alias("refs/remotes/origin/missing", "alias"),
        ),
    ]);
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    assert!(matches!(
        resolve(&refs, &control),
        Err(LooseGitImportRefusal::SymbolicRefTargetMissing { target, .. })
            if target == name("refs/remotes/origin/missing")
    ));
    refs.insert(
        name("refs/remotes/origin/missing"),
        SourceRef::Direct(id(format, 1)),
    );
    assert_eq!(resolve(&refs, &control).unwrap().len(), 3);
}

#[test]
fn cycles_refuse_but_an_alias_fanout_is_not_a_cycle() {
    let format = GitHashAlgorithm::Sha256;
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    for refs in [
        BTreeMap::from([(name("refs/heads/a"), alias("refs/heads/a", "a"))]),
        BTreeMap::from([
            (name("refs/heads/a"), alias("refs/heads/b", "a")),
            (name("refs/heads/b"), alias("refs/heads/a", "b")),
        ]),
    ] {
        assert!(matches!(
            resolve(&refs, &control),
            Err(LooseGitImportRefusal::SymbolicRefCycle(_))
        ));
    }
    let mut refs = BTreeMap::from([(name("refs/heads/tip"), SourceRef::Direct(id(format, 9)))]);
    for index in 0..1_000 {
        refs.insert(
            name(&format!("refs/remotes/r{index:04}")),
            alias("refs/heads/tip", "alias"),
        );
    }
    let mut checkpoints = 0usize;
    let mut live = || {
        checkpoints += 1;
        true
    };
    let result = resolve(&refs, &ImportControl::new(&mut live)).unwrap();
    assert_eq!(result.len(), 1_001);
    assert!(result.values().all(|value| *value == id(format, 9)));
    assert!(
        checkpoints < 6_000,
        "shared tails must not cause an unbounded rewalk"
    );
}

fn chain(length: usize, tail_sorts_first: bool) -> BTreeMap<RefName, SourceRef> {
    let mut refs = BTreeMap::new();
    let at = |index| {
        name(&format!(
            "refs/heads/r{:03}",
            if tail_sorts_first {
                length - index
            } else {
                index
            }
        ))
    };
    refs.insert(at(length), SourceRef::Direct(id(GitHashAlgorithm::Sha1, 3)));
    for index in 0..length {
        refs.insert(
            at(index),
            SourceRef::Symbolic {
                target: at(index + 1),
                path: PathBuf::from(format!("alias-{index}")),
            },
        );
    }
    refs
}

#[test]
fn alias_depth_is_exact_even_when_the_resolved_tail_sorts_first() {
    for tail_sorts_first in [false, true] {
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        assert_eq!(
            resolve(&chain(MAX_SYMBOLIC_REF_DEPTH, tail_sorts_first), &control)
                .unwrap()
                .len(),
            MAX_SYMBOLIC_REF_DEPTH + 1
        );
        assert!(matches!(
            resolve(
                &chain(MAX_SYMBOLIC_REF_DEPTH + 1, tail_sorts_first),
                &control
            ),
            Err(LooseGitImportRefusal::SymbolicRefDepthExceeded {
                limit: MAX_SYMBOLIC_REF_DEPTH,
                ..
            })
        ));
    }
}

#[test]
fn every_resolver_checkpoint_honors_the_original_cancellation() {
    let refs = chain(8, true);
    let mut checkpoints = 0usize;
    let mut live = || {
        checkpoints += 1;
        true
    };
    assert_eq!(
        resolve(&refs, &ImportControl::new(&mut live))
            .unwrap()
            .len(),
        9
    );
    for stop_at in 1..=checkpoints {
        let mut seen = 0usize;
        let mut live = || {
            seen += 1;
            seen < stop_at
        };
        assert!(
            matches!(
                resolve(&refs, &ImportControl::new(&mut live)),
                Err(LooseGitImportRefusal::Interrupted {
                    code: fgit_types::RefusalCode::CancellationInProgress,
                    ..
                })
            ),
            "checkpoint {stop_at}"
        );
    }
}

#[test]
fn symbolic_ref_input_has_its_own_bound_and_direct_refs_keep_theirs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        fs::create_dir_all(scratch.0.join("objects")).unwrap();
        let path = scratch.0.join("refs/remotes/origin/HEAD");
        let limit = super::super::source_io::head_input_limit();
        let mut bytes = b"ref: ".to_vec();
        bytes.resize(limit as usize + 1, b'x');
        write_ref(&scratch.0, "refs/remotes/origin/HEAD", &bytes);
        assert!(matches!(read_refs(&scratch.0, format, 2),
            Err(LooseGitImportRefusal::RefInputBytesExceeded { path: refused, limit: actual, observed })
                if *refused == path && actual == limit && observed == limit + 1
        ));
        let direct_limit = (format.digest_len() * 2 + 1) as u64;
        fs::write(&path, vec![b'1'; direct_limit as usize + 1]).unwrap();
        assert!(matches!(read_refs(&scratch.0, format, 2),
            Err(LooseGitImportRefusal::RefInputBytesExceeded { limit: actual, observed, .. })
                if actual == direct_limit && observed == direct_limit + 1
        ));
        // A legal target longer than an OID line must reach graph resolution.
        let target = format!("refs/heads/{}", "long-target-".repeat(12));
        write_ref(
            &scratch.0,
            "refs/remotes/origin/HEAD",
            format!("ref: {target}\n").as_bytes(),
        );
        assert!(matches!(read_refs(&scratch.0, format, 2),
            Err(LooseGitImportRefusal::SymbolicRefTargetMissing { target: missing, .. }) if missing == name(&target)
        ));
        write_ref(
            &scratch.0,
            &target,
            format!("{}\n", id(format, 1)).as_bytes(),
        );
        assert_eq!(read_refs(&scratch.0, format, 2).unwrap().len(), 2);
    }
}
