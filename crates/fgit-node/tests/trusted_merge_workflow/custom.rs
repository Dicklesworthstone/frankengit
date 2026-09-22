//! Adversarial native pack construction for node tests, not a CLI dependency.
use super::support::{Fixture, commit_bytes, tree_bytes};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::collections::BTreeMap;

impl Fixture {
    /// Caller-chosen actual merge bytes: deliberately not the automatic planner.
    pub fn custom(&self, workflow: &str, parents: &[GitOid]) -> (NativeMerge, Vec<u8>) {
        let format = self.target.algorithm();
        let mut objects = Objects(BTreeMap::new());
        let left = objects.put(format, GitObjectKind::Blob, b"target\n".to_vec());
        let right = objects.put(format, GitObjectKind::Blob, b"source\n".to_vec());
        let workflow = objects.put(format, GitObjectKind::Blob, workflow.as_bytes().to_vec());
        let tree = objects.put(
            format,
            GitObjectKind::Tree,
            tree_bytes(left, right, workflow),
        );
        let candidate = objects.put(
            format,
            GitObjectKind::Commit,
            commit_bytes(tree, parents, "reviewed custom merge"),
        );
        let limits = PackLimits::default();
        let ids = objects.0.keys().copied().collect::<Vec<_>>();
        let plan = PackPlanner::new(
            format,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            limits.clone(),
        )
        .plan_selected(&objects, &ids, &mut || true)
        .unwrap();
        let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
        let mut bundle = match format {
            GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
            GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
        };
        bundle.extend_from_slice(
            format!(
                "-{} target\n-{} source\n{candidate} refs/heads/main\n\n",
                self.target, self.source
            )
            .as_bytes(),
        );
        bundle.extend_from_slice(&pack);
        (self.coordinates(candidate), bundle)
    }
}
struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.0.insert(id, (kind, body));
        id
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self
            .0
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}
