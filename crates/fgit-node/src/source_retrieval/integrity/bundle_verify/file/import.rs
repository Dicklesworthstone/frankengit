//! Verified full-bundle custody for durable node import. Scratch is private
//! candidate data; this module neither places objects nor publishes authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};

use fgit_git_object::{AcceptanceProfile, ObjectError, ObjectType, ParseLimits, parse_object_body};
use fgit_pack::StreamPackReceipt;
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};

use super::super::{BundleVerifyError, BundleVerifyLimits, GraphRefusal, VerifiedGitBundle};
use super::resolve::Inventory;
use super::storage::{Scratch, Span, SpanReader, io_error};
use super::{FileBundleVerification, checkpoint, verify_reader_inventory};

/// Bounded facts about a selected object. No scratch offset or caller-supplied
/// commitment can be used to manufacture a reader.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FullBundleImportObject {
    pub(crate) kind: ObjectType,
    pub(crate) length: usize,
}

#[derive(Clone, Copy)]
struct SelectedObject {
    facts: FullBundleImportObject,
    span: Span,
}

/// Complete native content evidence plus exclusive scratch custody. Only the
/// advertised-ref closure and its transport delta bases may be read for import.
/// All supplied objects, including unselected ones, were nevertheless verified.
pub(crate) struct FullBundleImportPlan {
    scratch: OwnedScratch,
    verification: FileBundleVerification,
    receipt: StreamPackReceipt,
    selected: BTreeSet<GitOid>,
    objects: BTreeMap<GitOid, SelectedObject>,
    total_selected_bytes: u64,
    limits: BundleVerifyLimits,
    failed: bool,
}

impl FullBundleImportPlan {
    pub(crate) const fn verified(&self) -> &VerifiedGitBundle {
        self.verification.verified()
    }

    /// The actual native chunk-reader completion, never a synthesized receive
    /// receipt. Pack framing, trailer and exact EOF preceded this value.
    pub(crate) const fn receipt(&self) -> &StreamPackReceipt {
        &self.receipt
    }

    pub(crate) const fn selected_ids(&self) -> &BTreeSet<GitOid> {
        &self.selected
    }

    pub(crate) fn object(&self, identity: GitOid) -> Option<FullBundleImportObject> {
        self.objects.get(&identity).map(|object| object.facts)
    }

    pub(crate) const fn total_selected_bytes(&self) -> u64 {
        self.total_selected_bytes
    }

    /// Recheck the original span before returning a bounded metadata body.
    /// Blobs deliberately use `open_blob`, including small blobs.
    pub(crate) fn read_metadata(
        &mut self,
        identity: GitOid,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Vec<u8>, BundleVerifyError> {
        let result = (|| {
            self.check_live(live)?;
            let object = self.selected_object(identity)?;
            if object.facts.kind == ObjectType::Blob {
                return Err(BundleVerifyError::Graph(GraphRefusal::Limit(
                    "metadata-only import read",
                )));
            }
            let mut scratch = Scratch::reopen(
                self.scratch.file_mut()?,
                self.verification.scratch_bytes(),
                &self.limits,
                live,
            )?;
            scratch.read(object.span, self.limits.graph.max_object_bytes, live)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// A zero read with a nonempty output buffer authenticates the complete
    /// original span. Derived output must remain private until then. The reader
    /// owns the live callback until dropped; callers sharing it with another
    /// synchronous consumer can use one `RefCell` gate, as the verifier does.
    pub(crate) fn open_blob<'a>(
        &'a mut self,
        identity: GitOid,
        live: &'a mut dyn FnMut() -> bool,
    ) -> Result<FullBundleImportBlobReader<'a>, BundleVerifyError> {
        let facts = (|| {
            self.check_live(&mut || live())?;
            let object = self.selected_object(identity)?;
            if object.facts.kind != ObjectType::Blob {
                return Err(BundleVerifyError::Graph(GraphRefusal::TargetKind {
                    target: identity,
                    expected: ObjectType::Blob,
                    actual: object.facts.kind,
                }));
            }
            Ok(object)
        })();
        let object = match facts {
            Ok(object) => object,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        let file = match self.scratch.file_mut() {
            Ok(file) => file,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        let scratch = match Scratch::reopen(
            file,
            self.verification.scratch_bytes(),
            &self.limits,
            &mut || live(),
        ) {
            Ok(scratch) => scratch,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        let opened = scratch.into_reader(
            object.span,
            self.limits.max_streamed_blob_bytes,
            &mut || live(),
        );
        match opened {
            Ok(span) => Ok(FullBundleImportBlobReader {
                span,
                live,
                failed: &mut self.failed,
            }),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Remove scratch before authority admission. A read failure or an
    /// abandoned blob reader cannot be hidden by finishing with a fresh budget.
    pub(crate) fn finish(mut self) -> Result<(), BundleVerifyError> {
        self.scratch.cleanup()?;
        if self.failed {
            Err(BundleVerifyError::Graph(GraphRefusal::Failed))
        } else {
            Ok(())
        }
    }

    fn selected_object(&self, identity: GitOid) -> Result<SelectedObject, BundleVerifyError> {
        self.objects.get(&identity).copied().ok_or_else(|| {
            BundleVerifyError::Graph(GraphRefusal::MissingTarget {
                source: None,
                target: identity,
            })
        })
    }

    fn check_live(&self, live: &mut impl FnMut() -> bool) -> Result<(), BundleVerifyError> {
        if self.failed {
            return Err(BundleVerifyError::Graph(GraphRefusal::Failed));
        }
        checkpoint(live)
    }
}

/// Exact-span reader over the plan's original descriptor. Failure poisons its
/// plan, and dropping before authenticated EOF poisons it too.
pub(crate) struct FullBundleImportBlobReader<'a> {
    span: SpanReader<'a, File>,
    live: &'a mut dyn FnMut() -> bool,
    failed: &'a mut bool,
}

impl Read for FullBundleImportBlobReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if *self.failed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bundle import reader previously failed",
            ));
        }
        let result = self.span.read(output, &mut || (self.live)());
        result.map_err(|error| {
            *self.failed = true;
            io::Error::new(io::ErrorKind::InvalidData, error.to_string())
        })
    }
}

impl Drop for FullBundleImportBlobReader<'_> {
    fn drop(&mut self) {
        if !self.span.is_verified() {
            *self.failed = true;
        }
    }
}

/// Prepare a complete native bundle, refusing prerequisites and external delta
/// bases. `scratch_path` is a NEW FILE path in an existing caller-owned private
/// directory whose ancestors must remain stable. Existing paths are never
/// opened, truncated, or removed. Cleanup removes only the original regular
/// file; replaced or missing paths cause a typed refusal from `finish` and are
/// left untouched by drop. This custody profile requires Unix file identity;
/// other platforms refuse before creating scratch or reading the source.
pub(crate) fn prepare_full_bundle_import_reader<R: Read + Seek>(
    input: &mut R,
    expected_format: GitHashAlgorithm,
    scratch_path: &Path,
    limits: &BundleVerifyLimits,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<FullBundleImportPlan, BundleVerifyError> {
    let mut stopped = false;
    let mut live = || {
        if !stopped && !allow_work() {
            stopped = true;
        }
        !stopped
    };
    checkpoint(&mut live)?;
    let mut scratch = OwnedScratch::create(scratch_path)?;
    let prepared = (|| {
        checkpoint(&mut live)?;
        let mut verified = verify_reader_inventory(
            input,
            scratch.file_mut()?,
            limits,
            None,
            Some(expected_format),
            &mut live,
        )?;
        let mut workspace = Scratch::reopen(
            scratch.file_mut()?,
            verified.file.scratch_bytes(),
            limits,
            &mut live,
        )?;
        let selection = select_closure(
            &mut verified.inventory,
            &mut workspace,
            verified.file.verified(),
            limits,
            &mut live,
        )?;
        workspace.finish(&mut live)?;
        checkpoint(&mut live)?;
        Ok((verified, selection))
    })();
    let (verified, (selected, objects, total_selected_bytes)) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            scratch.cleanup()?;
            return Err(error);
        }
    };
    Ok(FullBundleImportPlan {
        scratch,
        verification: verified.file,
        receipt: verified.receipt,
        selected,
        objects,
        total_selected_bytes,
        limits: limits.clone(),
        failed: false,
    })
}

type Selection = (BTreeSet<GitOid>, BTreeMap<GitOid, SelectedObject>, u64);

fn select_closure<W: Read + io::Write + Seek>(
    inventory: &mut Inventory,
    scratch: &mut Scratch<'_, W>,
    verified: &VerifiedGitBundle,
    limits: &BundleVerifyLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<Selection, BundleVerifyError> {
    let mut pending: BTreeSet<_> = verified.references().values().copied().collect();
    let mut selected = BTreeSet::new();
    let mut objects = BTreeMap::new();
    let mut total = 0_u64;
    let mut edges_left = limits.graph.max_edges;
    while let Some(identity) = pending.pop_first() {
        checkpoint(live)?;
        inventory.charge_selection_work(1, limits)?;
        if !selected.insert(identity) {
            continue;
        }
        let object = inventory.object(identity)?;
        total = total
            .checked_add(object.span.length() as u64)
            .filter(|total| *total <= limits.graph.max_payload_bytes)
            .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                "selected payload bytes",
            )))?;
        objects.insert(
            identity,
            SelectedObject {
                facts: FullBundleImportObject {
                    kind: object.kind,
                    length: object.span.length(),
                },
                span: object.span,
            },
        );
        if let Some(base) = inventory.delta_base(identity)? {
            edges_left =
                edges_left
                    .checked_sub(1)
                    .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                        "selected graph edges",
                    )))?;
            if !selected.contains(&base) {
                pending.insert(base);
            }
        }
        if object.kind == ObjectType::Blob {
            continue;
        }
        inventory.charge_selection_work(object.span.length(), limits)?;
        let body = scratch.read(object.span, limits.graph.max_object_bytes, live)?;
        let parse_limits = ParseLimits {
            max_object_bytes: limits.graph.max_object_bytes,
            tree_reference_bytes: verified.format().digest_len(),
            max_tree_entries: edges_left.min(ParseLimits::default().max_tree_entries),
            ..ParseLimits::default()
        };
        let parsed = parse_object_body(
            object.kind,
            &body,
            AcceptanceProfile::GitCompatibleImport,
            &parse_limits,
        )
        .map_err(|cause| {
            BundleVerifyError::Graph(match cause {
                ObjectError::AllocationFailure => GraphRefusal::Allocation,
                ObjectError::ObjectTooLarge { .. } => GraphRefusal::Limit("object bytes"),
                ObjectError::TooManyTreeEntries { .. } => GraphRefusal::Limit("tree entries"),
                ObjectError::HeaderLimitExceeded { .. } => GraphRefusal::Limit("header structure"),
                cause => GraphRefusal::Malformed {
                    object: identity,
                    cause: Box::new(cause),
                },
            })
        })?;
        checkpoint(live)?;
        let edges = crate::loose_import::graph::references(
            verified.format(),
            &parsed,
            &body,
            &parse_limits,
            &mut edges_left,
            live,
        )
        .map_err(|refusal| match refusal {
            RefusalCode::CancellationInProgress => BundleVerifyError::Stopped,
            RefusalCode::ResourceBudgetExceeded => {
                BundleVerifyError::Graph(GraphRefusal::Limit("selected graph edges"))
            }
            _ => BundleVerifyError::Graph(GraphRefusal::Incomplete),
        })?;
        inventory.charge_selection_work(edges.len(), limits)?;
        for (target, expected) in edges {
            checkpoint(live)?;
            let target_object = inventory.object(target)?;
            if target_object.kind != expected {
                return Err(BundleVerifyError::Graph(GraphRefusal::TargetKind {
                    target,
                    expected,
                    actual: target_object.kind,
                }));
            }
            if !selected.contains(&target) {
                pending.insert(target);
            }
        }
    }
    checkpoint(live)?;
    Ok((selected, objects, total))
}

struct OwnedScratch {
    file: Option<File>,
    path: Option<PathBuf>,
    identity: ScratchIdentity,
}

impl OwnedScratch {
    fn create(path: &Path) -> Result<Self, BundleVerifyError> {
        if !cfg!(unix) {
            return Err(unsupported_scratch_identity());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|error| io_error("create bundle import scratch", error))?;
        // Capture the original descriptor's identity before any source or
        // caller checkpoint can replace the pathname. If identification itself
        // fails, close the descriptor without guessing which path to unlink.
        let metadata = file
            .metadata()
            .map_err(|error| io_error("identify bundle import scratch", error))?;
        let identity = ScratchIdentity::of(&metadata)?;
        Ok(Self {
            file: Some(file),
            path: Some(path.to_path_buf()),
            identity,
        })
    }

    fn file_mut(&mut self) -> Result<&mut File, BundleVerifyError> {
        self.file.as_mut().ok_or(BundleVerifyError::ScratchChanged)
    }

    fn cleanup(&mut self) -> Result<(), BundleVerifyError> {
        // Disarm both fields even on refusal. Drop must never retry a saved
        // pathname after ownership was lost or a cleanup operation failed.
        let file = self.file.take();
        let Some(path) = self.path.take() else {
            return Ok(());
        };
        let file = file.ok_or(BundleVerifyError::ScratchChanged)?;
        let descriptor_metadata = file
            .metadata()
            .map_err(|error| io_error("identify bundle import scratch", error))?;
        if ScratchIdentity::of(&descriptor_metadata)? != self.identity {
            return Err(BundleVerifyError::ScratchChanged);
        }
        let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                BundleVerifyError::ScratchChanged
            } else {
                io_error("inspect bundle import scratch for cleanup", error)
            }
        })?;
        if ScratchIdentity::of(&path_metadata)? != self.identity {
            return Err(BundleVerifyError::ScratchChanged);
        }
        // Keep the original descriptor open through unlink, preventing inode
        // reuse from making a replacement appear owned. No caller checkpoint
        // separates this final check from unlink in the stable private parent.
        let removed =
            fs::remove_file(&path).map_err(|error| io_error("remove bundle import scratch", error));
        drop(file);
        removed
    }
}

impl Drop for OwnedScratch {
    fn drop(&mut self) {
        let _cleanup = self.cleanup();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScratchIdentity {
    device: u64,
    inode: u64,
}

impl ScratchIdentity {
    fn of(metadata: &fs::Metadata) -> Result<Self, BundleVerifyError> {
        if !metadata.file_type().is_file() {
            return Err(BundleVerifyError::ScratchChanged);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Err(unsupported_scratch_identity())
        }
    }
}

const fn unsupported_scratch_identity() -> BundleVerifyError {
    BundleVerifyError::Io {
        operation: "identify bundle import scratch",
        kind: io::ErrorKind::Unsupported,
    }
}
