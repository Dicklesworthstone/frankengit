//! Self-contained native Git bundle transport for SHA-1 and SHA-256.
//!
//! This general interchange profile complements the older canonical V2-only
//! artifact API. It accepts ordinary reference ordering and the optional HEAD
//! advertisement, but refuses prerequisites, filters and unknown capabilities.
//! Header parsing is not object admission. Importers must still run the pack
//! through native quarantine with borrowing disabled.

pub mod fetch;

use crate::{
    BundleReference, Deadline, NativeChecksumVerifier, ObjectFormat, ObjectId, PackError,
    PackLimits, PackPlan, PackWriteError, PackWriteReceipt, PackWriter, checkpoint,
    parse_pack_header, split_pack_trailer, validate_pack_trailer,
};
use fgit_types::RefName;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullBundleLimits {
    pub max_references: usize,
    pub max_header_bytes: usize,
    pub max_bundle_bytes: usize,
}
impl Default for FullBundleLimits {
    fn default() -> Self {
        Self {
            max_references: 4096,
            max_header_bytes: 1024 * 1024,
            max_bundle_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FullBundleError {
    Invalid(&'static str),
    Unsupported(&'static str),
    Limit(&'static str),
    FormatMismatch,
    MissingObject(ObjectId),
    UnreachableObject(ObjectId),
    Pack(PackError),
    Write(PackWriteError),
}
impl std::fmt::Display for FullBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "full Git bundle refused: {self:?}")
    }
}
impl std::error::Error for FullBundleError {}
impl From<PackError> for FullBundleError {
    fn from(e: PackError) -> Self {
        Self::Pack(e)
    }
}
impl From<PackWriteError> for FullBundleError {
    fn from(e: PackWriteError) -> Self {
        Self::Write(e)
    }
}

/// Bounded header plus borrowed pack bytes. No object has been admitted.
#[derive(Debug)]
pub struct FullBundleInput<'a> {
    format: ObjectFormat,
    references: Vec<BundleReference>,
    head: Option<ObjectId>,
    pack: &'a [u8],
    header_bytes: usize,
    prerequisites: Vec<ObjectId>,
}
impl<'a> FullBundleInput<'a> {
    /// Parse only the bounded transport envelope. Useful for exact terminal
    /// recovery without repeating object verification or reviving an intake.
    pub fn parse(
        input: &'a [u8],
        limits: FullBundleLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, FullBundleError> {
        Self::parse_profile(input, limits, false, deadline)
    }

    /// Accept a bounded prerequisite frontier. Comments are ignored; each
    /// prerequisite and every borrowed dependency still require native admission.
    /// The original `parse` entrypoint remains strictly self-contained.
    pub fn parse_incremental(
        input: &'a [u8],
        limits: FullBundleLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, FullBundleError> {
        Self::parse_profile(input, limits, true, deadline)
    }
    fn parse_profile(
        input: &'a [u8],
        limits: FullBundleLimits,
        incremental: bool,
        deadline: &mut impl Deadline,
    ) -> Result<Self, FullBundleError> {
        checkpoint(deadline)?;
        if input.len() > limits.max_bundle_bytes {
            return Err(FullBundleError::Limit("bundle bytes"));
        }
        let mut cursor = 0;
        let version = match line(input, &mut cursor, limits.max_header_bytes)? {
            b"# v2 git bundle" => 2,
            b"# v3 git bundle" => 3,
            _ => return Err(FullBundleError::Invalid("signature")),
        };
        let mut format = ObjectFormat::Sha1;
        let mut capability_seen = false;
        let mut refs = BTreeMap::new();
        let mut head = None;
        let mut records = 0usize;
        let mut prerequisites = BTreeSet::new();
        loop {
            checkpoint(deadline)?;
            let record = line(input, &mut cursor, limits.max_header_bytes)?;
            if record.is_empty() {
                break;
            }
            if record.starts_with(b"@") {
                if version != 3 || records != 0 || !prerequisites.is_empty() || capability_seen {
                    return Err(FullBundleError::Invalid(
                        "duplicate or misplaced capability",
                    ));
                }
                format = match record {
                    b"@object-format=sha1" => ObjectFormat::Sha1,
                    b"@object-format=sha256" => ObjectFormat::Sha256,
                    _ => return Err(FullBundleError::Unsupported("bundle capability")),
                };
                capability_seen = true;
                continue;
            }
            if let Some(record) = record.strip_prefix(b"-") {
                if !incremental {
                    return Err(FullBundleError::Unsupported(
                        "incremental bundle prerequisite",
                    ));
                }
                if records != 0 {
                    return Err(FullBundleError::Invalid("prerequisite after reference"));
                }
                if prerequisites.len() == MAX_BUNDLE_PREREQUISITES {
                    return Err(FullBundleError::Limit("prerequisites"));
                }
                let width = format.digest_len() * 2;
                if record.get(width) != Some(&b' ') {
                    return Err(FullBundleError::Invalid("prerequisite record"));
                }
                let text = std::str::from_utf8(&record[..width])
                    .map_err(|_| FullBundleError::Invalid("prerequisite identity"))?;
                let id = ObjectId::from_hex(format, &text.to_ascii_lowercase())
                    .map_err(|_| FullBundleError::Invalid("prerequisite identity"))?;
                if id.is_zero() || !prerequisites.insert(id) {
                    return Err(FullBundleError::Invalid("zero or duplicate prerequisite"));
                }
                continue;
            }
            if records == limits.max_references {
                return Err(FullBundleError::Limit("references"));
            }
            records += 1;
            let width = format.digest_len() * 2;
            if record.get(width) != Some(&b' ') {
                return Err(FullBundleError::Invalid("reference record"));
            }
            let text = std::str::from_utf8(&record[..width])
                .map_err(|_| FullBundleError::Invalid("object identity"))?;
            let id = ObjectId::from_hex(format, &text.to_ascii_lowercase())
                .map_err(|_| FullBundleError::Invalid("object identity"))?;
            if id.is_zero() {
                return Err(FullBundleError::Invalid("zero reference target"));
            }
            let name = &record[width + 1..];
            if name == b"HEAD" {
                if head.replace(id).is_some() {
                    return Err(FullBundleError::Invalid("duplicate HEAD"));
                }
            } else {
                let name = RefName::try_new(name)
                    .map_err(|_| FullBundleError::Invalid("reference name"))?;
                if !name.as_bytes().starts_with(b"refs/") {
                    return Err(FullBundleError::Unsupported("non-refs advertisement"));
                }
                if refs.insert(name, id).is_some() {
                    return Err(FullBundleError::Invalid("duplicate reference"));
                }
            }
        }
        if refs.is_empty() {
            return Err(FullBundleError::Unsupported("bundle without direct refs"));
        }
        if head.is_some_and(|id| {
            !refs
                .iter()
                .any(|(name, target)| name.as_bytes().starts_with(b"refs/heads/") && *target == id)
        }) {
            return Err(FullBundleError::Unsupported(
                "detached or unadvertised HEAD",
            ));
        }
        if !input[cursor..].starts_with(b"PACK") {
            return Err(FullBundleError::Invalid("missing pack"));
        }
        let references = refs
            .into_iter()
            .map(|(name, id)| BundleReference::new(id, name))
            .collect();
        Ok(Self {
            format,
            references,
            head,
            pack: &input[cursor..],
            header_bytes: cursor,
            prerequisites: prerequisites.into_iter().collect(),
        })
    }
    #[must_use]
    pub fn prerequisites(&self) -> &[ObjectId] {
        &self.prerequisites
    }
    #[must_use]
    pub const fn format(&self) -> ObjectFormat {
        self.format
    }
    #[must_use]
    pub fn references(&self) -> &[BundleReference] {
        &self.references
    }
    #[must_use]
    pub const fn head(&self) -> Option<ObjectId> {
        self.head
    }
    #[must_use]
    pub const fn pack_bytes(&self) -> &'a [u8] {
        self.pack
    }
    #[must_use]
    pub const fn header_bytes(&self) -> usize {
        self.header_bytes
    }

    /// Authenticate the native pack trailer and bounded header. The successful
    /// return is still quarantine data, not proof of complete object closure.
    pub fn verify_pack_framing(
        &self,
        limits: &PackLimits,
        deadline: &mut impl Deadline,
    ) -> Result<(), FullBundleError> {
        checkpoint(deadline)?;
        let (body, _) = split_pack_trailer(self.pack, self.format, limits)?;
        parse_pack_header(body, limits)?;
        validate_pack_trailer(self.pack, self.format, limits, &NativeChecksumVerifier)?;
        checkpoint(deadline)?;
        Ok(())
    }
}

fn line<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
) -> Result<&'a [u8], FullBundleError> {
    let end = maximum.min(input.len());
    if *cursor >= end {
        return Err(missing_delimiter(input, maximum));
    }
    let length = input[*cursor..end]
        .iter()
        .position(|b| *b == b'\n')
        .ok_or_else(|| missing_delimiter(input, maximum))?;
    let record = &input[*cursor..*cursor + length];
    *cursor += length + 1;
    Ok(record)
}

/// No line delimiter before the header budget ends. When the input itself
/// ended first it is a truncated or non-bundle header (invalid), not an
/// oversized one; at or past the budget it is the header limit.
const fn missing_delimiter(input: &[u8], maximum: usize) -> FullBundleError {
    if input.len() < maximum {
        FullBundleError::Invalid("header line without delimiter")
    } else {
        FullBundleError::Limit("header bytes")
    }
}

/// A complete stream produced only through the existing verified pack writer.
#[derive(Debug)]
pub struct FullBundle {
    bytes: Vec<u8>,
    pack_receipt: PackWriteReceipt,
    header_bytes: usize,
}
impl FullBundle {
    /// Emit deterministic V2/SHA-1 or V3/SHA-256 bytes. All advertised objects
    /// and local edges must be in the plan. Unreachable extra plan objects are
    /// refused rather than leaking unrelated retained history in an export.
    pub fn write(
        references: &[BundleReference],
        head: Option<ObjectId>,
        plan: &PackPlan,
        writer: &PackWriter,
        limits: FullBundleLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, FullBundleError> {
        Self::write_profile(
            references,
            head,
            &[],
            &BTreeSet::new(),
            plan,
            writer,
            limits,
            deadline,
        )
    }

    fn write_profile(
        references: &[BundleReference],
        head: Option<ObjectId>,
        prerequisites: &[ObjectId],
        external: &BTreeSet<ObjectId>,
        plan: &PackPlan,
        writer: &PackWriter,
        limits: FullBundleLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, FullBundleError> {
        checkpoint(deadline)?;
        if prerequisites.len() > MAX_BUNDLE_PREREQUISITES {
            return Err(FullBundleError::Limit("prerequisites"));
        }
        let mut boundary = BTreeSet::new();
        for &id in prerequisites {
            checkpoint(deadline)?;
            if id.algorithm() != plan.format()
                || id.is_zero()
                || !boundary.insert(id)
                || !external.contains(&id)
            {
                return Err(FullBundleError::Invalid("prerequisite closure"));
            }
        }
        if boundary.is_empty() && !external.is_empty() {
            return Err(FullBundleError::Invalid("external closure"));
        }
        if external.len() > 1_000_000 {
            return Err(FullBundleError::Limit("external closure"));
        }
        for id in external {
            checkpoint(deadline)?;
            if id.is_zero() || id.algorithm() != plan.format() {
                return Err(FullBundleError::Invalid("external closure"));
            }
        }
        let count = references
            .len()
            .checked_add(usize::from(head.is_some()))
            .ok_or(FullBundleError::Limit("references"))?;
        if references.is_empty() || count > limits.max_references {
            return Err(FullBundleError::Limit("references"));
        }
        let mut refs = BTreeMap::new();
        for reference in references {
            checkpoint(deadline)?;
            let id = *reference.target();
            if id.algorithm() != plan.format() || id.is_zero() {
                return Err(FullBundleError::FormatMismatch);
            }
            if !reference.name().as_bytes().starts_with(b"refs/") {
                return Err(FullBundleError::Invalid("full reference name required"));
            }
            if refs.insert(reference.name(), id).is_some() {
                return Err(FullBundleError::Invalid("duplicate reference"));
            }
        }
        if let Some(id) = head
            && (id.algorithm() != plan.format()
                || !refs
                    .iter()
                    .any(|(name, tip)| name.as_bytes().starts_with(b"refs/heads/") && *tip == id))
        {
            return Err(FullBundleError::Invalid(
                "HEAD must name an advertised branch tip",
            ));
        }
        let mut graph = BTreeMap::new();
        for entry in plan.entries() {
            checkpoint(deadline)?;
            if graph.insert(entry.object().id(), entry.object()).is_some() {
                return Err(FullBundleError::Invalid("duplicate planned object"));
            }
        }
        let mut pending: BTreeSet<_> = refs.values().copied().collect();
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop_first() {
            checkpoint(deadline)?;
            if !seen.insert(id) {
                continue;
            }
            if external.contains(&id) {
                continue;
            }
            let object = graph.get(&id).ok_or(FullBundleError::MissingObject(id))?;
            for target in object.references() {
                checkpoint(deadline)?;
                if !graph.contains_key(target) && !external.contains(target) {
                    return Err(FullBundleError::MissingObject(*target));
                }
                if !seen.contains(target) {
                    pending.insert(*target);
                }
            }
        }
        if let Some(id) = graph
            .keys()
            .find(|id| external.contains(id) || !seen.contains(id))
        {
            return Err(FullBundleError::UnreachableObject(*id));
        }
        let mut header = match plan.format() {
            ObjectFormat::Sha1 => b"# v2 git bundle\n".to_vec(),
            ObjectFormat::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
        };
        let maximum = limits.max_header_bytes.min(limits.max_bundle_bytes);
        if header.len() >= maximum {
            return Err(FullBundleError::Limit("header bytes"));
        }
        for id in boundary {
            checkpoint(deadline)?;
            if header.len().checked_add(1).is_none_or(|n| n >= maximum) {
                return Err(FullBundleError::Limit("header bytes"));
            }
            header
                .try_reserve(1)
                .map_err(|_| FullBundleError::Limit("allocation"))?;
            header.push(b'-');
            append_ref(&mut header, id, b"required history", maximum)?;
        }
        if let Some(id) = head {
            append_ref(&mut header, id, b"HEAD", maximum)?;
        }
        for (name, id) in refs {
            checkpoint(deadline)?;
            append_ref(&mut header, id, name.as_bytes(), maximum)?;
        }
        if header.len() >= maximum {
            return Err(FullBundleError::Limit("header bytes"));
        }
        header.push(b'\n');
        let header_bytes = header.len();
        let (pack, pack_receipt) = writer.write(plan, deadline)?;
        let length = header_bytes
            .checked_add(pack.len())
            .ok_or(FullBundleError::Limit("bundle bytes"))?;
        if length > limits.max_bundle_bytes {
            return Err(FullBundleError::Limit("bundle bytes"));
        }
        header
            .try_reserve_exact(pack.len())
            .map_err(|_| FullBundleError::Limit("allocation"))?;
        header.extend_from_slice(&pack);
        checkpoint(deadline)?;
        Ok(Self {
            bytes: header,
            pack_receipt,
            header_bytes,
        })
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    #[must_use]
    pub const fn pack_receipt(&self) -> &PackWriteReceipt {
        &self.pack_receipt
    }
    #[must_use]
    pub const fn header_bytes(&self) -> usize {
        self.header_bytes
    }
}
fn append_ref(
    output: &mut Vec<u8>,
    id: ObjectId,
    name: &[u8],
    maximum: usize,
) -> Result<(), FullBundleError> {
    let extra = id.algorithm().digest_len() * 2 + 2 + name.len();
    if output.len().checked_add(extra).is_none_or(|n| n >= maximum) {
        return Err(FullBundleError::Limit("header bytes"));
    }
    output
        .try_reserve_exact(extra)
        .map_err(|_| FullBundleError::Limit("allocation"))?;
    output.extend_from_slice(id.to_string().as_bytes());
    output.push(b' ');
    output.extend_from_slice(name);
    output.push(b'\n');
    Ok(())
}

/// Hard bound on the additional, independently verified prerequisite frontier.
pub const MAX_BUNDLE_PREREQUISITES: usize = 64;

/// A complete incremental transport stream, not a self-contained backup.
#[derive(Debug)]
pub struct IncrementalBundle(FullBundle);
impl IncrementalBundle {
    /// The caller supplies the independently verified complete closure of its
    /// declared prerequisites. This is a transfer assumption, never authority.
    /// Every transmitted edge must end in that closure or this exact pack, and
    /// unrelated planned objects are refused before any artifact is returned.
    pub fn write(
        references: &[BundleReference],
        prerequisites: &[ObjectId],
        prerequisite_closure: &BTreeSet<ObjectId>,
        plan: &PackPlan,
        writer: &PackWriter,
        limits: FullBundleLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, FullBundleError> {
        if prerequisites.is_empty() {
            return Err(FullBundleError::Invalid("empty prerequisite frontier"));
        }
        FullBundle::write_profile(
            references,
            None,
            prerequisites,
            prerequisite_closure,
            plan,
            writer,
            limits,
            deadline,
        )
        .map(Self)
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
    #[must_use]
    pub const fn pack_receipt(&self) -> &PackWriteReceipt {
        self.0.pack_receipt()
    }
    #[must_use]
    pub const fn header_bytes(&self) -> usize {
        self.0.header_bytes()
    }
}
