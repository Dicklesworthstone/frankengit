//! Commit-derived source snapshots for release attempts.
//!
//! This is deliberately a small, read-only object-store boundary.  It opens
//! the caller-named checkout's own `.git/objects` directory and its local pack
//! files using `FrankenGit` parsers; it never invokes `git` or accepts a raw
//! working-directory walk as source truth.  The working tree is compared only
//! after the exact commit tree has been assembled.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use fgit_git_object::{
    AcceptanceProfile, InflateLimits, ObjectType, ParseLimits, ZlibLooseObjectDecoder,
    parse_commit, parse_tree,
};
use fgit_pack::{
    IdxV2, NativeChecksumVerifier, PackLimits, ScalarResolver, read_verified_pack,
    verify_native_object,
};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256};

use crate::{EntryState, SourceEntry, TreeSnapshot};

/// The commit and exact file snapshot consumed by a release attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitDerivedSnapshot {
    commit: GitOid,
    tree: TreeSnapshot,
}

impl CommitDerivedSnapshot {
    /// Exact commit object named by the release caller.
    #[must_use]
    pub const fn commit(&self) -> GitOid {
        self.commit
    }

    /// Tree assembled from that commit's Git object graph.
    #[must_use]
    pub const fn tree(&self) -> &TreeSnapshot {
        &self.tree
    }

    /// Consumes the snapshot into its tree while retaining the typed commit at
    /// the caller's identity boundary.
    #[must_use]
    pub fn into_tree(self) -> TreeSnapshot {
        self.tree
    }
}

/// Bounded, first-party reader for one checkout's Git object store.
#[derive(Clone, Debug)]
pub struct GitObjectTreeAssembler {
    checkout_root: PathBuf,
}

impl GitObjectTreeAssembler {
    /// Selects the checkout whose own `.git` object store may be read.
    #[must_use]
    pub fn new(checkout_root: impl Into<PathBuf>) -> Self {
        Self {
            checkout_root: checkout_root.into(),
        }
    }

    /// Assembles the exact tree of `commit` from loose objects and verified
    /// local packs.  A missing named commit is a typed `UnknownCommit`; no
    /// ref, branch, current `HEAD`, or `git` subprocess is consulted.
    pub fn assemble(&self, commit: GitOid) -> Result<CommitDerivedSnapshot, SourceSnapshotRefusal> {
        let store = ObjectStore::open(&self.checkout_root, commit.algorithm())?;
        let (object_type, body) = store.read_object(commit).map_err(|error| match error {
            SourceSnapshotRefusal::ObjectMissing { .. } => {
                SourceSnapshotRefusal::UnknownCommit { commit }
            }
            other => other,
        })?;
        if object_type != ObjectType::Commit {
            return Err(SourceSnapshotRefusal::ExpectedCommit {
                commit,
                object_type,
            });
        }
        let parsed = parse_commit(
            &body,
            AcceptanceProfile::GitCompatibleImport,
            &store.parse_limits,
        )
        .map_err(|_| SourceSnapshotRefusal::ObjectRejected { oid: commit })?;
        let tree_text = parsed
            .tree_reference()
            .ok_or(SourceSnapshotRefusal::CommitMissingTree { commit })?;
        let tree_text = std::str::from_utf8(tree_text)
            .map_err(|_| SourceSnapshotRefusal::CommitTreeReferenceMalformed { commit })?;
        let tree = GitOid::from_hex(store.format, tree_text)
            .map_err(|_| SourceSnapshotRefusal::CommitTreeReferenceMalformed { commit })?;

        let mut snapshot = TreeSnapshot::new();
        let mut ancestry = BTreeSet::new();
        store.collect_tree(&mut snapshot, &mut ancestry, tree, "")?;
        if snapshot.is_empty() {
            return Err(SourceSnapshotRefusal::EmptyCommitTree { commit });
        }
        Ok(CommitDerivedSnapshot {
            commit,
            tree: snapshot,
        })
    }

    /// Assembles `commit` and proves that the caller's working tree contains
    /// exactly those regular file bytes.  Any difference is named as a typed
    /// `DirtyWorktree` refusal; a release never silently substitutes ambient
    /// files for the commit-derived tree.
    pub fn assemble_clean(
        &self,
        commit: GitOid,
    ) -> Result<CommitDerivedSnapshot, SourceSnapshotRefusal> {
        let snapshot = self.assemble(commit)?;
        verify_worktree(&self.checkout_root, snapshot.tree())?;
        Ok(snapshot)
    }
}

/// Why the release source boundary rejected a checkout or commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceSnapshotRefusal {
    /// The checkout does not provide a directory `.git` object store.
    GitDirectoryMissing { path: PathBuf },
    /// Linked worktree/gitdir files are not an implemented source boundary.
    GitDirectoryNotDirectory { path: PathBuf },
    /// The object store uses another hash domain than the caller-named OID.
    ObjectFormatMismatch {
        expected: GitHashAlgorithm,
        observed: GitHashAlgorithm,
    },
    /// Object-store metadata could not be read without exposing ambient text.
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
    /// A filesystem object that would be read was a symlink.
    Symlink { path: PathBuf },
    /// A filesystem object that would be read was not a regular file.
    NotRegularFile { path: PathBuf },
    /// A bounded object-store input was too large.
    InputTooLarge {
        path: PathBuf,
        bytes: u64,
        limit: u64,
    },
    /// The caller-named commit object does not exist in the local store.
    UnknownCommit { commit: GitOid },
    /// A referenced object does not exist in the local store.
    ObjectMissing { oid: GitOid },
    /// A loose object or pack object failed first-party framing/parse checks.
    ObjectRejected { oid: GitOid },
    /// A local pack or idx did not pass its bounded native verification.
    PackRejected { path: PathBuf },
    /// The local Git configuration did not have bounded UTF-8 text.
    ObjectStoreConfigMalformed { path: PathBuf },
    /// A named object was valid but had a different native type.
    ExpectedCommit {
        commit: GitOid,
        object_type: ObjectType,
    },
    /// A commit did not name exactly usable tree bytes.
    CommitMissingTree { commit: GitOid },
    /// A commit tree header did not use the store's native OID spelling.
    CommitTreeReferenceMalformed { commit: GitOid },
    /// A source tree contains no materializable regular files.
    EmptyCommitTree { commit: GitOid },
    /// A tree graph referred to itself.
    TreeCycle { tree: GitOid },
    /// A tree contains a filename unsuitable for a checkout-relative source path.
    UnsafeTreePath { path: String },
    /// A tree entry mode is not a regular file or tree in this release slice.
    UnsupportedTreeMode { path: String, mode: Vec<u8> },
    /// A commit-derived tree differs from the working tree.
    DirtyWorktree { path: String },
}

impl fmt::Display for SourceSnapshotRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GitDirectoryMissing { path } => {
                write!(f, "{} has no .git directory", path.display())
            }
            Self::GitDirectoryNotDirectory { path } => {
                write!(f, "{} is not a supported .git directory", path.display())
            }
            Self::ObjectFormatMismatch { expected, observed } => write!(
                f,
                "release named {expected} but checkout object store is {observed}"
            ),
            Self::Io {
                operation,
                path,
                kind,
            } => write!(
                f,
                "source snapshot {operation} at {} failed with {kind:?}",
                path.display()
            ),
            Self::Symlink { path } => {
                write!(f, "source snapshot refuses symlink {}", path.display())
            }
            Self::NotRegularFile { path } => write!(
                f,
                "source snapshot requires regular file {}",
                path.display()
            ),
            Self::InputTooLarge { path, bytes, limit } => write!(
                f,
                "source input {} is {bytes} bytes, exceeding {limit}",
                path.display()
            ),
            Self::UnknownCommit { commit } => write!(
                f,
                "caller-named commit {commit} is absent from this checkout"
            ),
            Self::ObjectMissing { oid } => write!(f, "commit tree references missing object {oid}"),
            Self::ObjectRejected { oid } => {
                write!(f, "object {oid} failed bounded first-party verification")
            }
            Self::PackRejected { path } => write!(
                f,
                "pack or index {} failed bounded native verification",
                path.display()
            ),
            Self::ObjectStoreConfigMalformed { path } => {
                write!(
                    f,
                    "object-store configuration {} is malformed",
                    path.display()
                )
            }
            Self::ExpectedCommit {
                commit,
                object_type,
            } => write!(f, "{commit} is a {object_type}, not a commit"),
            Self::CommitMissingTree { commit } => {
                write!(f, "commit {commit} has no usable tree header")
            }
            Self::CommitTreeReferenceMalformed { commit } => {
                write!(f, "commit {commit} has a malformed tree reference")
            }
            Self::EmptyCommitTree { commit } => {
                write!(f, "commit {commit} materializes no regular source files")
            }
            Self::TreeCycle { tree } => write!(f, "tree graph cycles through {tree}"),
            Self::UnsafeTreePath { path } => {
                write!(f, "tree path {path:?} cannot be materialized safely")
            }
            Self::UnsupportedTreeMode { path, mode } => write!(
                f,
                "tree path {path:?} has unsupported mode {}",
                String::from_utf8_lossy(mode)
            ),
            Self::DirtyWorktree { path } => {
                write!(f, "working tree differs from the named commit at {path}")
            }
        }
    }
}

impl std::error::Error for SourceSnapshotRefusal {}

const MAX_OBJECT_STORE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SOURCE_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCE_FILES: usize = 100_000;
const MAX_PACK_FILES: usize = 128;

struct ObjectStore {
    objects_dir: PathBuf,
    format: GitHashAlgorithm,
    parse_limits: ParseLimits,
    pack_limits: PackLimits,
}

impl ObjectStore {
    fn open(root: &Path, expected_format: GitHashAlgorithm) -> Result<Self, SourceSnapshotRefusal> {
        let git_dir = root.join(".git");
        let metadata = fs::symlink_metadata(&git_dir).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SourceSnapshotRefusal::GitDirectoryMissing {
                    path: git_dir.clone(),
                }
            } else {
                io_refusal("inspect .git", git_dir.clone(), error)
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SourceSnapshotRefusal::GitDirectoryNotDirectory { path: git_dir });
        }
        let format = read_object_format(&git_dir)?;
        if format != expected_format {
            return Err(SourceSnapshotRefusal::ObjectFormatMismatch {
                expected: expected_format,
                observed: format,
            });
        }
        let mut parse_limits = ParseLimits::default();
        parse_limits.max_object_bytes = MAX_SOURCE_FILE_BYTES;
        parse_limits.max_tree_entries = MAX_SOURCE_FILES;
        parse_limits.tree_reference_bytes = format.digest_len();
        let mut pack_limits = PackLimits::default();
        pack_limits.max_input_bytes =
            usize::try_from(MAX_OBJECT_STORE_FILE_BYTES).expect("64 MiB fits usize");
        pack_limits.max_object_bytes = MAX_SOURCE_FILE_BYTES;
        pack_limits.max_entries =
            u32::try_from(MAX_SOURCE_FILES).expect("source file bound fits u32");
        pack_limits.max_index_entries = MAX_SOURCE_FILES;
        Ok(Self {
            objects_dir: git_dir.join("objects"),
            format,
            parse_limits,
            pack_limits,
        })
    }

    fn read_object(&self, oid: GitOid) -> Result<(ObjectType, Vec<u8>), SourceSnapshotRefusal> {
        let text = oid.to_string();
        let loose_path = self.objects_dir.join(&text[..2]).join(&text[2..]);
        match fs::symlink_metadata(&loose_path) {
            Ok(_) => return self.read_loose(oid, &loose_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_refusal("inspect loose object", loose_path, error)),
        }
        self.read_packed(oid)?
            .ok_or(SourceSnapshotRefusal::ObjectMissing { oid })
    }

    fn read_loose(
        &self,
        oid: GitOid,
        path: &Path,
    ) -> Result<(ObjectType, Vec<u8>), SourceSnapshotRefusal> {
        let input = read_regular_bounded(path, MAX_OBJECT_STORE_FILE_BYTES)?;
        let mut inflate = InflateLimits::GIT_OBJECT;
        inflate.max_input_bytes =
            usize::try_from(MAX_OBJECT_STORE_FILE_BYTES).expect("64 MiB fits usize");
        inflate.max_pending_input_bytes = inflate.max_input_bytes;
        inflate.max_output_bytes = MAX_SOURCE_FILE_BYTES;
        let mut decoder = ZlibLooseObjectDecoder::new(inflate, self.parse_limits.clone())
            .map_err(|_| SourceSnapshotRefusal::ObjectRejected { oid })?;
        decoder
            .push(&input)
            .map_err(|_| SourceSnapshotRefusal::ObjectRejected { oid })?;
        let object = decoder
            .finish()
            .map_err(|_| SourceSnapshotRefusal::ObjectRejected { oid })?;
        if fgit_crypto::git_object_id(self.format, object.object_type, &object.body) != oid {
            return Err(SourceSnapshotRefusal::ObjectRejected { oid });
        }
        Ok((object.object_type, object.body))
    }

    fn read_packed(
        &self,
        oid: GitOid,
    ) -> Result<Option<(ObjectType, Vec<u8>)>, SourceSnapshotRefusal> {
        let pack_dir = self.objects_dir.join("pack");
        let entries = match fs::read_dir(&pack_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_refusal("enumerate pack directory", pack_dir, error)),
        };
        let mut indexes = Vec::new();
        for entry in entries {
            let entry = entry
                .map_err(|error| io_refusal("read pack directory", pack_dir.clone(), error))?;
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "idx") {
                indexes.push(path);
            }
        }
        indexes.sort();
        if indexes.len() > MAX_PACK_FILES {
            return Err(SourceSnapshotRefusal::PackRejected { path: pack_dir });
        }
        for index_path in indexes {
            let pack_path = index_path.with_extension("pack");
            let index_bytes = read_regular_bounded(&index_path, MAX_OBJECT_STORE_FILE_BYTES)?;
            let mut deadline = || true;
            let index = IdxV2::parse_verified(
                &index_bytes,
                self.format,
                &self.pack_limits,
                &mut deadline,
                &NativeChecksumVerifier,
            )
            .map_err(|_| SourceSnapshotRefusal::PackRejected {
                path: index_path.clone(),
            })?;
            if index.lookup(&oid).is_none() {
                continue;
            }
            let pack_bytes = read_regular_bounded(&pack_path, MAX_OBJECT_STORE_FILE_BYTES)?;
            let trailer_length = self.format.digest_len();
            let Some(trailer) = pack_bytes.get(pack_bytes.len().saturating_sub(trailer_length)..)
            else {
                return Err(SourceSnapshotRefusal::PackRejected { path: pack_path });
            };
            if trailer != index.pack_checksum().as_bytes() {
                return Err(SourceSnapshotRefusal::PackRejected { path: pack_path });
            }
            let quarantined = read_verified_pack(
                &pack_bytes,
                self.format,
                &self.pack_limits,
                &mut deadline,
                &NativeChecksumVerifier,
            )
            .map_err(|_| SourceSnapshotRefusal::PackRejected {
                path: pack_path.clone(),
            })?;
            let objects = quarantined
                .into_scalar_objects(|offset| {
                    index
                        .entries()
                        .iter()
                        .find(|entry| entry.pack_offset == offset)
                        .map(|entry| entry.oid)
                })
                .map_err(|_| SourceSnapshotRefusal::PackRejected {
                    path: pack_path.clone(),
                })?;
            let resolver = ScalarResolver::new(&objects, &(), &self.pack_limits, &mut deadline)
                .map_err(|_| SourceSnapshotRefusal::PackRejected {
                    path: pack_path.clone(),
                })?;
            let (object_type, body) =
                resolver
                    .resolve_id_typed(&oid, &mut deadline)
                    .map_err(|_| SourceSnapshotRefusal::PackRejected {
                        path: pack_path.clone(),
                    })?;
            verify_native_object(
                self.format,
                object_type,
                &body,
                &oid,
                AcceptanceProfile::GitCompatibleImport,
                &self.parse_limits,
            )
            .map_err(|_| SourceSnapshotRefusal::ObjectRejected { oid })?;
            return Ok(Some((object_type, body)));
        }
        Ok(None)
    }

    fn collect_tree(
        &self,
        snapshot: &mut TreeSnapshot,
        ancestry: &mut BTreeSet<GitOid>,
        tree: GitOid,
        prefix: &str,
    ) -> Result<(), SourceSnapshotRefusal> {
        if !ancestry.insert(tree) {
            return Err(SourceSnapshotRefusal::TreeCycle { tree });
        }
        let result = (|| {
            let (object_type, body) = self.read_object(tree)?;
            if object_type != ObjectType::Tree {
                return Err(SourceSnapshotRefusal::ObjectRejected { oid: tree });
            }
            let entries = parse_tree(
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &self.parse_limits,
            )
            .map_err(|_| SourceSnapshotRefusal::ObjectRejected { oid: tree })?;
            for entry in entries {
                let name = std::str::from_utf8(&entry.name).map_err(|_| {
                    SourceSnapshotRefusal::UnsafeTreePath {
                        path: prefix.to_owned(),
                    }
                })?;
                if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
                    return Err(SourceSnapshotRefusal::UnsafeTreePath {
                        path: format!("{prefix}{name}"),
                    });
                }
                let path = format!("{prefix}{name}");
                let child = oid_from_tree_bytes(self.format, &entry.object_id)
                    .ok_or_else(|| SourceSnapshotRefusal::UnsafeTreePath { path: path.clone() })?;
                if entry.is_tree() {
                    self.collect_tree(snapshot, ancestry, child, &format!("{path}/"))?;
                    continue;
                }
                if entry.mode != b"100644" && entry.mode != b"100755" {
                    return Err(SourceSnapshotRefusal::UnsupportedTreeMode {
                        path,
                        mode: entry.mode,
                    });
                }
                let (object_type, body) = self.read_object(child)?;
                if object_type != ObjectType::Blob {
                    return Err(SourceSnapshotRefusal::ObjectRejected { oid: child });
                }
                if body.len() > MAX_SOURCE_FILE_BYTES {
                    return Err(SourceSnapshotRefusal::ObjectRejected { oid: child });
                }
                *snapshot = std::mem::take(snapshot).with(SourceEntry::new(
                    path,
                    fgit_crypto::sha256_digest(&body),
                    EntryState::Clean,
                ));
                if snapshot.len() > MAX_SOURCE_FILES {
                    return Err(SourceSnapshotRefusal::ObjectRejected { oid: tree });
                }
            }
            Ok(())
        })();
        ancestry.remove(&tree);
        result
    }
}

fn read_object_format(git_dir: &Path) -> Result<GitHashAlgorithm, SourceSnapshotRefusal> {
    let config_path = git_dir.join("config");
    let config = match read_regular_bounded(&config_path, 64 * 1024) {
        Ok(bytes) => bytes,
        Err(SourceSnapshotRefusal::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => return Ok(GitHashAlgorithm::Sha1),
        Err(other) => return Err(other),
    };
    let text = std::str::from_utf8(&config).map_err(|_| {
        SourceSnapshotRefusal::ObjectStoreConfigMalformed {
            path: config_path.clone(),
        }
    })?;
    let sha256 = text.lines().any(|line| {
        let normalized = line.trim().to_ascii_lowercase();
        normalized == "objectformat = sha256" || normalized == "objectformat=sha256"
    });
    Ok(if sha256 {
        GitHashAlgorithm::Sha256
    } else {
        GitHashAlgorithm::Sha1
    })
}

fn oid_from_tree_bytes(format: GitHashAlgorithm, bytes: &[u8]) -> Option<GitOid> {
    match format {
        GitHashAlgorithm::Sha1 => bytes
            .try_into()
            .ok()
            .map(GitOidSha1::from_bytes)
            .map(GitOid::Sha1),
        GitHashAlgorithm::Sha256 => bytes
            .try_into()
            .ok()
            .map(GitOidSha256::from_bytes)
            .map(GitOid::Sha256),
    }
}

fn read_regular_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, SourceSnapshotRefusal> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_refusal("inspect input", path.to_path_buf(), error))?;
    if metadata.file_type().is_symlink() {
        return Err(SourceSnapshotRefusal::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(SourceSnapshotRefusal::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > limit {
        return Err(SourceSnapshotRefusal::InputTooLarge {
            path: path.to_path_buf(),
            bytes: metadata.len(),
            limit,
        });
    }
    let mut file =
        File::open(path).map_err(|error| io_refusal("open input", path.to_path_buf(), error))?;
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| SourceSnapshotRefusal::InputTooLarge {
            path: path.to_path_buf(),
            bytes: metadata.len(),
            limit,
        })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| io_refusal("read input", path.to_path_buf(), error))?;
    if u64::try_from(bytes.len()).expect("usize fits u64") > limit {
        return Err(SourceSnapshotRefusal::InputTooLarge {
            path: path.to_path_buf(),
            bytes: u64::try_from(bytes.len()).expect("usize fits u64"),
            limit,
        });
    }
    Ok(bytes)
}

fn verify_worktree(root: &Path, snapshot: &TreeSnapshot) -> Result<(), SourceSnapshotRefusal> {
    let mut observed = BTreeSet::new();
    verify_directory(root, root, snapshot, &mut observed)?;
    for entry in snapshot.entries() {
        if !observed.contains(entry.path()) {
            return Err(SourceSnapshotRefusal::DirtyWorktree {
                path: entry.path().to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_directory(
    root: &Path,
    directory: &Path,
    snapshot: &TreeSnapshot,
    observed: &mut BTreeSet<String>,
) -> Result<(), SourceSnapshotRefusal> {
    for entry in fs::read_dir(directory)
        .map_err(|error| io_refusal("enumerate working tree", directory.to_path_buf(), error))?
    {
        let entry = entry
            .map_err(|error| io_refusal("read working tree", directory.to_path_buf(), error))?;
        let path = entry.path();
        let relative = path.strip_prefix(root).expect("walk starts below root");
        if relative == Path::new(".git") {
            continue;
        }
        let relative_text = relative
            .to_str()
            .ok_or_else(|| SourceSnapshotRefusal::DirtyWorktree {
                path: relative.display().to_string(),
            })?
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_refusal("inspect working tree", path.clone(), error))?;
        if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
            return Err(SourceSnapshotRefusal::DirtyWorktree {
                path: relative_text,
            });
        }
        if metadata.is_dir() {
            verify_directory(root, &path, snapshot, observed)?;
            continue;
        }
        let expected = snapshot
            .entries()
            .find(|entry| entry.path() == relative_text);
        let Some(expected) = expected else {
            return Err(SourceSnapshotRefusal::DirtyWorktree {
                path: relative_text,
            });
        };
        let bytes = read_regular_bounded(
            &path,
            u64::try_from(MAX_SOURCE_FILE_BYTES).expect("bound fits u64"),
        )?;
        if fgit_crypto::sha256_digest(&bytes) != expected.digest() {
            return Err(SourceSnapshotRefusal::DirtyWorktree {
                path: relative_text,
            });
        }
        observed.insert(relative_text);
    }
    Ok(())
}

fn io_refusal(
    operation: &'static str,
    path: PathBuf,
    error: std::io::Error,
) -> SourceSnapshotRefusal {
    SourceSnapshotRefusal::Io {
        operation,
        path,
        kind: error.kind(),
    }
}
