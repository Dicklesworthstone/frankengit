#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real authenticated input closure and strict parent-shape selection, without jobs.
#[path = "trusted_merge_workflow/custom.rs"]
mod custom;
#[path = "trusted_merge_workflow/support.rs"]
mod support;
use fgit_crypto::{GitHashAlgorithm as Hash, NativeObjectIdentity, Sha1, Sha256};
use fgit_forge::preparation::MergeCommitStyle as Style;
use fgit_node::BundleInspectionRefusal;
use fgit_treefs::{SparseCandidateManifest, SparseLimits, TreeCapability, TreePath, WorkspaceId};
use fgit_types::{ByteCount, GitHashAlgorithm, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;
use support::*;

fn select<A: Hash>(
    f: &Fixture,
    merge: &fgit_forge::event::NativeMerge,
    bytes: &[u8],
    style: Style,
    visibility: &RefVisibility,
) -> Result<
    (
        RepositoryAuthorityHeadId,
        SparseCandidateManifest<A>,
        [u8; 32],
    ),
    BundleInspectionRefusal,
> {
    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([41; 16]),
        REPOSITORY,
        inputs()
            .iter()
            .map(|p| TreePath::parse_default(p).unwrap())
            .collect(),
        Vec::new(),
    )
    .with_fetch_budget(
        ByteCount::try_new("test input", 64 * 1024 * 1024, 64 * 1024 * 1024).unwrap(),
    )
    .with_file_budget(1000);
    let n = f.node();
    n.runtime()
        .block_on(n.sparse_merge_candidate_manifest_with_style_in::<A>(
            &n.command_request_context(None),
            merge,
            bytes,
            visibility,
            None,
            &mut capability,
            0,
            SparseLimits {
                max_entries: 10_000,
                max_entry_bytes: 16 * 1024 * 1024,
                max_payload_bytes: 64 * 1024 * 1024,
            },
            style,
        ))
}
fn campaign<A: Hash>(format: GitHashAlgorithm) {
    let f = Fixture::new(format, WORKFLOW);
    let before = generation(f.node());
    let (merge, bytes) = f.custom(WORKFLOW, &[f.target]);
    let (_, manifest, digest) =
        select::<A>(&f, &merge, &bytes, Style::Squash, &RefVisibility::new()).unwrap();
    assert_eq!(
        manifest.candidate_commit_oid().digest_bytes(),
        merge.merge_commit.as_bytes()
    );
    assert_eq!(manifest.parents().len(), 1);
    assert_eq!(manifest.parents()[0].digest_bytes(), f.target.as_bytes());
    assert_eq!(digest, fgit_crypto::sha256_digest(&bytes));
    assert_eq!(manifest.entries().len(), 3);
    assert_eq!(generation(f.node()), before);
    assert!(f.node().read_git_object(merge.merge_commit).is_err());
    assert!(select::<A>(&f, &merge, &bytes, Style::TwoParent, &RefVisibility::new()).is_err());
    let (two, body) = f.prepared();
    assert!(select::<A>(&f, &two, &body, Style::TwoParent, &RefVisibility::new()).is_ok());
    assert!(select::<A>(&f, &two, &body, Style::Squash, &RefVisibility::new()).is_err());
    for parents in [vec![f.source], vec![f.target, f.source, f.base]] {
        let (wrong, body) = f.custom(WORKFLOW, &parents);
        assert!(select::<A>(&f, &wrong, &body, Style::Squash, &RefVisibility::new()).is_err());
    }
    let mut wrong = merge.clone();
    wrong.base_tip = f.source;
    assert!(select::<A>(&f, &wrong, &bytes, Style::Squash, &RefVisibility::new()).is_err());
    let mut wrong = merge.clone();
    wrong.source_tip = f.target;
    assert!(select::<A>(&f, &wrong, &bytes, Style::Squash, &RefVisibility::new()).is_err());
    let prefix = format!("-{} ", f.source).into_bytes();
    let at = bytes
        .windows(prefix.len())
        .position(|s| s == prefix)
        .unwrap();
    let len = bytes[at..].iter().position(|b| *b == b'\n').unwrap() + 1;
    let mut missing = bytes.clone();
    missing.drain(at..at + len);
    assert!(select::<A>(&f, &merge, &missing, Style::Squash, &RefVisibility::new()).is_err());
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(select::<A>(&f, &merge, &corrupt, Style::Squash, &RefVisibility::new()).is_err());
    assert_eq!(generation(f.node()), before);
    assert_eq!(std::fs::read_dir(f.parent()).unwrap().count(), 0);
}
#[test]
fn sha1_squash_inputs_preserve_both_sources_without_staging_or_execution() {
    campaign::<Sha1>(GitHashAlgorithm::Sha1);
}
#[test]
fn sha256_squash_inputs_preserve_both_sources_without_staging_or_execution() {
    campaign::<Sha256>(GitHashAlgorithm::Sha256);
}
