#![forbid(unsafe_code)]
//! Explicit non-source inputs in a reserved private job namespace. The caller
//! verifies provenance and grants transfer; these bytes never become Git input.
use super::*;

/// Owned, bounded bytes supplied by an already-authorized workflow controller.
/// `provenance` binds the producing observation, not a cache authorization.
#[derive(Clone, Debug)]
pub struct JobInput {
    pub(super) path: TreePath,
    pub(super) body: Arc<Vec<u8>>,
    pub(super) mode: FileMode,
    pub(super) provenance: Commitment,
}
impl JobInput {
    pub fn new(
        path: &[u8],
        body: Vec<u8>,
        mode: FileMode,
        provenance: Commitment,
    ) -> Result<Self, HostRefusal> {
        let relative = TreePath::parse_default(path).map_err(HostRefusal::Path)?;
        if path.len() > 4000 || body.len() > 64 * 1024 * 1024 {
            return Err(HostRefusal::ResourceLimit);
        }
        let mut full = b".fgit-artifacts/".to_vec();
        full.extend_from_slice(relative.as_bytes());
        let path = TreePath::parse_default(&full).map_err(HostRefusal::Path)?;
        validate_path(&path)?;
        Ok(Self {
            path,
            body: Arc::new(body),
            mode,
            provenance,
        })
    }
}
impl<A: GitHashAlgorithm> SparseWorkspacePlan<A> {
    /// Install a complete input set before reserving/materializing a fresh job.
    /// The original source marker stays unchanged when this set is empty. The
    /// augmented marker binds paths, bytes, modes and provenance independently
    /// from the native source manifest. These plans cannot import Git edits.
    pub fn with_job_inputs(mut self, mut inputs: Vec<JobInput>) -> Result<Self, HostRefusal> {
        if inputs.is_empty() {
            return Ok(self);
        }
        if !self.job_inputs.is_empty() || !self.outputs.is_empty() || inputs.len() > 64 {
            return Err(HostRefusal::IdentityMismatch);
        }
        let reserved = TreePath::parse_default(b".fgit-artifacts").map_err(HostRefusal::Path)?;
        if self
            .manifest
            .entries()
            .iter()
            .any(|entry| entry.path().starts_with(&reserved))
        {
            return Err(HostRefusal::IdentityMismatch);
        }
        inputs.sort_by(|a, b| a.path.cmp(&b.path));
        let mut files = BTreeSet::new();
        let mut dirs = BTreeSet::new();
        let mut payload = self.manifest.receipt().payload_bytes();
        let mut bound = Encoder::new();
        bound.write_raw(b"frankengit/sparse-host/job-inputs/v1\0");
        frame(&mut bound, &self.marker)?;
        bound.write_scalar(inputs.len() as u64);
        for input in &inputs {
            if !files.insert(input.path.clone()) || input.body.len() > self.limits.max_entry_bytes {
                return Err(HostRefusal::ResourceLimit);
            }
            payload = payload
                .checked_add(input.body.len())
                .filter(|n| *n <= self.limits.max_payload_bytes)
                .ok_or(HostRefusal::ResourceLimit)?;
            let mut parent = input.path.parent();
            while let Some(path) = parent {
                if dirs.len() + files.len() + self.created_entries as usize
                    >= self.limits.max_entries
                {
                    return Err(HostRefusal::ResourceLimit);
                }
                dirs.insert(path.clone());
                parent = path.parent();
            }
            frame(&mut bound, input.path.as_bytes())?;
            frame(
                &mut bound,
                Commitment::of_bytes(&input.body)
                    .digest()
                    .bytes()
                    .as_bytes(),
            )?;
            frame(&mut bound, input.provenance.digest().bytes().as_bytes())?;
            bound.write_raw_byte(if input.mode == FileMode::Executable {
                1
            } else {
                0
            });
        }
        if files.iter().any(|path| dirs.contains(path)) {
            return Err(HostRefusal::IdentityMismatch);
        }
        let count = self
            .created_entries
            .checked_add((files.len() + dirs.len()) as u64)
            .filter(|n| *n <= self.limits.max_entries as u64)
            .ok_or(HostRefusal::ResourceLimit)?;
        let commitment = Commitment::of_bytes(bound.as_bytes());
        self.marker = DOMAIN.to_vec();
        self.marker
            .extend_from_slice(commitment.digest().bytes().as_bytes());
        self.reservation.plan = commitment;
        self.reservation.max_bytes =
            payload as u64 + self.marker.len() as u64 + self.limits.max_payload_bytes as u64;
        self.reservation.max_entries = count + self.limits.max_entries as u64;
        self.created_entries = count;
        self.directories.extend(dirs);
        self.job_inputs = inputs;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_crypto::{GitObjectKind, GitOid, Sha1};
    use fgit_git_object::ParseLimits;
    use fgit_resource::{LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId};
    use fgit_treefs::{BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant};
    use fgit_types::{
        CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId,
    };
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Source(BTreeMap<GitOid<Sha1>, Vec<u8>>);
    impl ObjectSource<Sha1> for Source {
        fn read_object(
            &self,
            id: &GitOid<Sha1>,
            _: GitObjectKind,
            _: &ReadGrant,
        ) -> Result<Vec<u8>, ObjectSourceError> {
            self.0.get(id).cloned().ok_or(ObjectSourceError::NotFound {
                oid_hex: "missing".into(),
            })
        }
    }
    fn plan(name: &[u8]) -> (SparseWorkspacePlan<Sha1>, TreeCapability) {
        let blob = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"source");
        let treebody = [b"100644 ".as_slice(), name, b"\0", blob.digest_bytes()].concat();
        let tree = GitOid::<Sha1>::of_object(GitObjectKind::Tree, &treebody);
        let commitbody = format!(
            "tree {}\nauthor A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\ntest\n",
            tree.digest_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let commit = GitOid::<Sha1>::of_object(GitObjectKind::Commit, commitbody.as_bytes());
        let repo = RepositoryId::from_bytes([9; 16]);
        let rcr = RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(2).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[8; 32]).unwrap(),
        );
        let base = BaseView::new(
            repo,
            rcr,
            commit,
            tree,
            ParseLimits::default(),
            PathPolicy::default(),
        );
        let source = Source(BTreeMap::from([
            (blob, b"source".to_vec()),
            (tree, treebody),
            (commit, commitbody.into_bytes()),
        ]));
        let mut cap = TreeCapability::new(
            WorkspaceId::from_bytes([7; 16]),
            repo,
            vec![TreePath::parse_default(name).unwrap()],
            Vec::new(),
        );
        let limits = SparseLimits {
            max_entries: 64,
            max_entry_bytes: 64,
            max_payload_bytes: 256,
        };
        let manifest = SparseManifest::build(&base, &source, &mut cap, 0, limits).unwrap();
        (
            SparseWorkspacePlan::new(Arc::new(manifest), Vec::new(), &cap, 0, limits).unwrap(),
            cap,
        )
    }
    fn input(path: &[u8], body: &[u8], seed: &[u8]) -> JobInput {
        JobInput::new(
            path,
            body.to_vec(),
            FileMode::Executable,
            Commitment::of_bytes(seed),
        )
        .unwrap()
    }
    #[test]
    fn input_plan_binds_exact_bytes_modes_and_provenance_and_rejects_collisions() {
        let (plan, _) = plan(b"source");
        assert_eq!(
            plan.clone()
                .with_job_inputs(Vec::new())
                .unwrap()
                .reservation(),
            plan.reservation()
        );
        let a = plan
            .clone()
            .with_job_inputs(vec![input(b"bin/tool", b"payload", b"first")])
            .unwrap();
        for other in [
            input(b"bin/tool", b"different", b"first"),
            input(b"bin/tool", b"payload", b"second"),
            input(b"other", b"payload", b"first"),
        ] {
            assert_ne!(
                a.reservation().plan,
                plan.clone()
                    .with_job_inputs(vec![other])
                    .unwrap()
                    .reservation()
                    .plan
            );
        }
        assert!(
            plan.clone()
                .with_job_inputs(vec![input(b"a", b"x", b"x"), input(b"a/b", b"x", b"x")])
                .is_err()
        );
        assert!(
            plan.clone()
                .with_job_inputs(vec![input(b"a", b"x", b"x"); 2])
                .is_err()
        );
        assert!(
            plan.clone()
                .with_job_inputs(vec![input(b"a", &[0; 65], b"x")])
                .is_err()
        );
        assert!(
            plan.clone()
                .with_job_inputs(vec![input(b"a", b"x", b"x"); 65])
                .is_err()
        );
        assert!(
            super::tests::plan(b".fgit-artifacts")
                .0
                .with_job_inputs(vec![input(b"a", b"x", b"x")])
                .is_err()
        );
        assert!(
            JobInput::new(
                b"../outside",
                vec![],
                FileMode::Regular,
                Commitment::of_bytes(b"x")
            )
            .is_err()
        );
    }
    #[test]
    fn materialized_inputs_are_private_accounted_and_never_importable_as_git() {
        let (plan, cap) = plan(b"source");
        let plan = plan
            .with_job_inputs(vec![input(b"bin/tool", b"payload", b"producer")])
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "fg-job-input-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let mut inodes = Vec::new();
        for n in 0..2 {
            let ledger = ObligationLedger::root(
                RegionId::new(n + 1),
                LeakDisposition::RecordAndContinue,
                plan.budget(),
            );
            let reserved = ledger
                .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
                .unwrap();
            let mut workspace = SparseWorkspace::materialize(
                plan.clone(),
                File::open(&root).unwrap(),
                TreePath::parse_default(format!("job-{n}").as_bytes()).unwrap(),
                reserved,
                &cap,
                0,
                &|_| false,
            )
            .unwrap();
            let file = workspace.tool_directory().join(".fgit-artifacts/bin/tool");
            assert_eq!(std::fs::read(&file).unwrap(), b"payload");
            inodes.push(std::fs::metadata(&file).unwrap().ino());
            assert!(matches!(
                workspace.import(&cap, 0, &|_| false),
                Err(HostRefusal::IdentityMismatch)
            ));
            workspace.close().unwrap();
            assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
        }
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir(&root).unwrap();
    }
    #[test]
    fn cancellation_during_supplemental_copy_reaps_the_staging_lease() {
        let (plan, cap) = plan(b"source");
        let plan = plan
            .with_job_inputs(vec![input(b"bin/tool", b"payload", b"producer")])
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "fg-job-cancel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let ledger = ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            plan.budget(),
        );
        let reserved = ledger
            .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
            .unwrap();
        assert!(matches!(
            SparseWorkspace::materialize(
                plan,
                File::open(&root).unwrap(),
                TreePath::parse_default(b"job").unwrap(),
                reserved,
                &cap,
                0,
                &|epoch| matches!(epoch, HostEpoch::Writing(1))
            ),
            Err(HostRefusal::Cancelled(_))
        ));
        assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir(&root).unwrap();
    }
}
