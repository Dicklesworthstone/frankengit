//! Optional receive policy over the fully authorized proposed native graph.
//!
//! Checking only uploaded blobs misses an empty-pack branch creation and a
//! new commit that reuses a previously admitted pointer. Walk every requested
//! nondeleted root, including its history, before staging. Existing large blob
//! headers cannot prove that a body is not a small pointer: drain their native
//! and strong commitments to exact EOF before accepting the length decision.
//! All custody is permanent in the selected local LFS profile. This check adds
//! no retention root, does not rewrite a pointer, and never publishes a ref.

use std::borrow::Cow;
use std::cell::RefCell;
use std::time::Duration;

use fgit_object_fabric::ObjectKind;
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid, LfsStore, MAX_OBJECT_BYTES};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactStorageError};

use super::{
    AcceptanceProfile, BTreeMap, BTreeSet, Deadline, GitOid, ObjectBody, ObjectSpool, ObjectType,
    ProductionQuarantineValidator, ReceiveRequest, RefusalCode, StoreRefusal, VerifiedObject,
    checkpoint, map_pack_error, verify_native_object,
};

const POINTER_BYTES: usize = 1024;
const POINTER_PREFIX: &[u8] = b"version https://git-lfs.github.com/spec/";
const LEGACY_POINTER_PREFIXES: [&str; 2] = [
    "version https://hawser.github.com/spec/",
    "version http://git-media.io/v/",
];

#[derive(Clone, Copy)]
struct Limits {
    objects: usize,
    edges: usize,
    metadata_bytes: u64,
    original_blob_bytes: u64,
    pointers: usize,
    payload_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            objects: 1_000_000,
            edges: 4_000_000,
            metadata_bytes: 256 * 1024 * 1024,
            original_blob_bytes: 4 * 1024 * 1024 * 1024,
            pointers: 4096,
            payload_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

impl ProductionQuarantineValidator<'_> {
    pub(super) fn validate_lfs_payloads(
        &self,
        request: &ReceiveRequest,
        verified: &BTreeMap<GitOid, VerifiedObject>,
        spool: &mut ObjectSpool,
        deadline: &mut impl Deadline,
    ) -> Result<(), RefusalCode> {
        if self.node.service_config.receive_lfs_root().is_none() {
            return Ok(());
        }
        self.validate_lfs_payloads_bounded(request, verified, spool, Limits::default(), deadline)
    }

    fn validate_lfs_payloads_bounded(
        &self,
        request: &ReceiveRequest,
        verified: &BTreeMap<GitOid, VerifiedObject>,
        spool: &mut ObjectSpool,
        limits: Limits,
        deadline: &mut impl Deadline,
    ) -> Result<(), RefusalCode> {
        checkpoint(deadline)?;
        let mut pending = BTreeSet::new();
        let mut expected = BTreeMap::new();
        let mut kinds = BTreeMap::new();
        for command in &request.commands {
            checkpoint(deadline)?;
            if !command.new.is_zero() {
                enqueue(
                    command.new,
                    fgit_git_object::required_ref_target_kind(&command.ref_name),
                    &mut pending,
                    &mut expected,
                    &kinds,
                    limits.objects,
                )?;
            }
        }
        if pending.is_empty() {
            return Ok(());
        }
        let mut metadata_left = limits.metadata_bytes;
        let mut original_blobs_left = limits.original_blob_bytes;
        let mut edges_left = limits.edges;
        let mut pointers = BTreeMap::new();
        let mut payload_bytes = 0_u64;
        while let Some(id) = pending.pop_first() {
            checkpoint(deadline)?;
            let (kind, body) = self.lfs_graph_object(
                id,
                verified,
                spool,
                &mut metadata_left,
                &mut original_blobs_left,
                deadline,
            )?;
            require_kind(kind, expected.get(&id).copied().flatten())?;
            kinds.insert(id, kind);
            let Some(body) = body else {
                // A verified blob larger than the supported pointer format.
                // Uploaded bytes already passed reconstruction; existing ones
                // were streamed to exact authenticated EOF above.
                continue;
            };
            if kind == ObjectType::Blob {
                observe_pointer(&body, &mut pointers, &mut payload_bytes, limits)?;
                continue;
            }
            let parsed = fgit_git_object::parse_object_body(
                kind,
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &self.parse_limits,
            )
            .map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
            let edges = crate::loose_import::graph::references(
                self.node.object_format,
                &parsed,
                &body,
                &self.parse_limits,
                &mut edges_left,
                deadline,
            )?;
            for (child, kind) in edges {
                checkpoint(deadline)?;
                enqueue(
                    child,
                    Some(kind),
                    &mut pending,
                    &mut expected,
                    &kinds,
                    limits.objects,
                )?;
            }
        }
        checkpoint(deadline)?;
        if pointers.is_empty() {
            return Ok(());
        }
        let root = self
            .node
            .service_config
            .receive_lfs_root()
            .ok_or(RefusalCode::DurabilityProfileUnavailable)?;
        let store = LfsStore::open(
            root,
            self.node.tenant_id,
            self.node.repository_id,
            self.node.repository_incarnation_id(),
        )
        .map_err(|_| RefusalCode::DurabilityProfileUnavailable)?;
        checkpoint(deadline)?;
        // One operation bounds the aggregate verification phase; the callback
        // also checks the ORIGINAL transport deadline throughout every payload.
        // A per-object timeout must not renew the receive's lifetime.
        let deadline = RefCell::new(deadline);
        let live = || deadline.borrow_mut().checkpoint();
        let operation = ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(3600), &live)
            .map_err(storage_refusal)?;
        for (oid, size) in pointers {
            if !live() {
                return Err(RefusalCode::CancellationInProgress);
            }
            if !store
                .contains(LfsObject { oid, size }, &operation)
                .map_err(storage_refusal)?
            {
                return Err(RefusalCode::ObjectClosureIncomplete);
            }
        }
        if live() {
            Ok(())
        } else {
            Err(RefusalCode::CancellationInProgress)
        }
    }

    /// Reads only native-verified metadata and supported pointer candidates.
    /// Large existing blobs use a fixed buffer and exact EOF verification;
    /// their unverified header never decides successful policy evaluation.
    fn lfs_graph_object<'a>(
        &self,
        id: GitOid,
        verified: &'a BTreeMap<GitOid, VerifiedObject>,
        spool: &mut ObjectSpool,
        metadata_left: &mut u64,
        original_blobs_left: &mut u64,
        deadline: &mut impl Deadline,
    ) -> Result<(ObjectType, Option<Cow<'a, [u8]>>), RefusalCode> {
        checkpoint(deadline)?;
        if id.is_zero() || id.algorithm() != self.node.object_format {
            return Err(RefusalCode::ObjectHeaderInvalid);
        }
        if let Some(object) = verified.get(&id) {
            let length = match &object.body {
                ObjectBody::Resident(body) => body.len(),
                ObjectBody::Spooled(handle) => handle.length,
            };
            if object.object_type == ObjectType::Blob && length > POINTER_BYTES {
                return Ok((ObjectType::Blob, None));
            }
            charge(metadata_left, length as u64)?;
            let body = match &object.body {
                ObjectBody::Resident(body) => Cow::Borrowed(body.as_slice()),
                ObjectBody::Spooled(handle) => {
                    let body = spool
                        .read(*handle)
                        .map_err(|_| RefusalCode::DurabilityProfileUnavailable)?;
                    // The spool is private scratch, not verified custody.
                    verify_native_object(
                        self.node.object_format,
                        object.object_type,
                        &body,
                        &id,
                        AcceptanceProfile::GitCompatibleImport,
                        &self.parse_limits,
                    )
                    .map_err(map_pack_error)?;
                    Cow::Owned(body)
                }
            };
            checkpoint(deadline)?;
            return Ok((object.object_type, Some(body)));
        }
        if !self.selected_closure.closure().objects().contains(&id) {
            return Err(RefusalCode::ObjectClosureIncomplete);
        }
        let header = self
            .node
            .fabric
            .read_header_bounded(id, u64::MAX)
            .map_err(native_refusal)?;
        checkpoint(deadline)?;
        if header.kind == ObjectKind::Blob {
            charge(original_blobs_left, header.payload_length)?;
            if header.payload_length > POINTER_BYTES as u64 {
                let mut stream = self
                    .node
                    .fabric
                    .open_blob_stream_bounded(id, header.payload_length)
                    .map_err(native_refusal)?;
                if stream.declared_length() != header.payload_length {
                    return Err(RefusalCode::EvidenceInvalid);
                }
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    checkpoint(deadline)?;
                    let count = stream.read_tentative(&mut buffer).map_err(native_refusal)?;
                    checkpoint(deadline)?;
                    if count == 0 {
                        break;
                    }
                }
                return Ok((ObjectType::Blob, None));
            }
        }
        charge(metadata_left, header.payload_length)?;
        if header.payload_length > self.parse_limits.max_object_bytes as u64 {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        let read = self
            .node
            .fabric
            .read_whole_bounded(id, header.payload_length)
            .map_err(native_refusal)?;
        checkpoint(deadline)?;
        if read.object.payload().len() as u64 != header.payload_length
            || read.object.envelope().object_kind() != header.kind
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let kind = match header.kind {
            ObjectKind::Blob => ObjectType::Blob,
            ObjectKind::Commit => ObjectType::Commit,
            ObjectKind::Tree => ObjectType::Tree,
            ObjectKind::Tag => ObjectType::Tag,
            ObjectKind::Internal => return Err(RefusalCode::ObjectHeaderInvalid),
        };
        Ok((kind, Some(Cow::Owned(read.object.payload().to_vec()))))
    }
}

fn charge(remaining: &mut u64, bytes: u64) -> Result<(), RefusalCode> {
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or(RefusalCode::ResourceBudgetExceeded)?;
    Ok(())
}

fn enqueue(
    id: GitOid,
    kind: Option<ObjectType>,
    pending: &mut BTreeSet<GitOid>,
    expected: &mut BTreeMap<GitOid, Option<ObjectType>>,
    kinds: &BTreeMap<GitOid, ObjectType>,
    maximum: usize,
) -> Result<(), RefusalCode> {
    if let Some(actual) = kinds.get(&id) {
        require_kind(*actual, kind)?;
    }
    if let Some(previous) = expected.get_mut(&id) {
        if let (Some(previous), Some(kind)) = (*previous, kind) {
            require_kind(previous, Some(kind))?;
        } else if previous.is_none() {
            *previous = kind;
        }
        return Ok(());
    }
    if expected.len() >= maximum {
        return Err(RefusalCode::ResourceBudgetExceeded);
    }
    expected.insert(id, kind);
    pending.insert(id);
    Ok(())
}

fn require_kind(actual: ObjectType, expected: Option<ObjectType>) -> Result<(), RefusalCode> {
    if expected.is_some_and(|expected| expected != actual) {
        Err(RefusalCode::EvidenceInvalid)
    } else {
        Ok(())
    }
}

fn observe_pointer(
    body: &[u8],
    pointers: &mut BTreeMap<LfsOid, u64>,
    payload_bytes: &mut u64,
    limits: Limits,
) -> Result<(), RefusalCode> {
    if !pointer_candidate(body) {
        return Ok(());
    }
    let object = LfsObject::parse_pointer(body).map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
    if object.size > MAX_OBJECT_BYTES {
        return Err(RefusalCode::ResourceBudgetExceeded);
    }
    if let Some(size) = pointers.get(&object.oid) {
        return if *size == object.size {
            Ok(())
        } else {
            Err(RefusalCode::ObjectHeaderInvalid)
        };
    }
    if pointers.len() >= limits.pointers {
        return Err(RefusalCode::ResourceBudgetExceeded);
    }
    *payload_bytes = payload_bytes
        .checked_add(object.size)
        .filter(|size| *size <= limits.payload_bytes)
        .ok_or(RefusalCode::ResourceBudgetExceeded)?;
    pointers.insert(object.oid, object.size);
    Ok(())
}

/// Upstream Git LFS recognizes two historical version URLs and trims Unicode
/// whitespace before decoding. It also permits extension lines before version.
/// They are candidates here, but the canonical parser still receives ORIGINAL
/// bytes and refuses those unsupported forms.
/// Otherwise a stock client could treat a blob as a pointer while this guard
/// silently classified it as ordinary content. Retain any valid UTF-8 prefix
/// so trailing malformed bytes do not hide an otherwise recognizable header.
fn pointer_candidate(body: &[u8]) -> bool {
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&body[..error.valid_up_to()]).unwrap_or(""),
    }
    .trim_start();
    for line in text.lines().filter(|line| !line.is_empty()) {
        if line.as_bytes().starts_with(POINTER_PREFIX)
            || LEGACY_POINTER_PREFIXES
                .iter()
                .any(|prefix| line.starts_with(prefix))
        {
            return true;
        }
        let Some((key, _)) = line.split_once(' ') else {
            return false;
        };
        let key = key.as_bytes();
        // Match only the upstream extension-key prefix that may precede the
        // expected version key. Other leading text makes this an ordinary blob.
        if !key.starts_with(b"ext-")
            || !key.get(4).is_some_and(u8::is_ascii_digit)
            || key.get(5) != Some(&b'-')
            || !key
                .get(6)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return false;
        }
    }
    false
}

fn native_refusal(error: StoreRefusal) -> RefusalCode {
    match error {
        StoreRefusal::ObjectAbsent => RefusalCode::EvidenceMissing,
        StoreRefusal::StreamingBudgetExceeded { .. } => RefusalCode::ResourceBudgetExceeded,
        StoreRefusal::RuntimeCheckpointRejected => RefusalCode::CancellationInProgress,
        _ => RefusalCode::EvidenceInvalid,
    }
}

fn storage_refusal(error: ArtifactStorageError) -> RefusalCode {
    match error {
        ArtifactStorageError::Cancelled => RefusalCode::CancellationInProgress,
        ArtifactStorageError::Deadline | ArtifactStorageError::PayloadLimit => {
            RefusalCode::ResourceBudgetExceeded
        }
        ArtifactStorageError::NotFound => RefusalCode::ObjectClosureIncomplete,
        ArtifactStorageError::Io { .. }
        | ArtifactStorageError::UnsafePath
        | ArtifactStorageError::PublicationUncertain { .. } => {
            RefusalCode::DurabilityProfileUnavailable
        }
        _ => RefusalCode::EvidenceInvalid,
    }
}

#[cfg(test)]
mod tests;
