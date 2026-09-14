//! Native tag construction inputs and read receipts. No authority is granted
//! by a constructed object, a parsed signature, or a preparation receipt.

use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};

pub const MAX_TAG_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_TAG_IDENTITY_BYTES: usize = 1024;
pub const MAX_TAG_NAME_BYTES: usize = 4096;

/// Explicit UTC metadata. Bytes are never trimmed, normalized, or obtained
/// from ambient Git configuration. Empty messages are valid native tags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagMetadata {
    pub tagger: String,
    pub timestamp: u64,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TagCommand {
    Lightweight { name: RefName, target: GitOid },
    Annotated { name: RefName, target: GitOid, target_kind: GitObjectKind, metadata: TagMetadata },
    Delete { name: RefName, expected: GitOid },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagObject {
    pub id: GitOid,
    pub target: GitOid,
    pub body: Vec<u8>,
}

/// A proposal, not a validated closure or permission to publish it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedTag {
    pub command: RefCommand,
    pub object: Option<TagObject>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TagRefusal {
    InvalidName,
    InvalidMetadata,
    ObjectFormat,
    InvalidLimits,
    Budget(&'static str),
    SnapshotMoved,
    InvalidObject,
    TargetKindMismatch,
    Cycle,
}
impl std::fmt::Display for TagRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "native tag refused: {self:?}")
    }
}
impl std::error::Error for TagRefusal {}

pub fn validate_tag_name(name: &RefName) -> Result<(), TagRefusal> {
    if !name.as_bytes().starts_with(b"refs/tags/") || name.as_bytes().len() > MAX_TAG_NAME_BYTES {
        return Err(TagRefusal::InvalidName);
    }
    Ok(())
}
impl TagCommand {
    pub fn reference(&self) -> &RefName {
        match self { Self::Lightweight { name, .. } | Self::Annotated { name, .. } | Self::Delete { name, .. } => name }
    }

    /// Create-only tags and exact-old deletion. The receiving node verifies
    /// every native target and its visibility through ordinary quarantine.
    /// `target_kind` is committed into annotated bytes, not trusted as evidence.
    pub fn prepare(&self, format: GitHashAlgorithm) -> Result<PreparedTag, TagRefusal> {
        validate_tag_name(self.reference())?;
        let target = match self { Self::Lightweight { target, .. } | Self::Annotated { target, .. } => *target,
            Self::Delete { expected, .. } => *expected };
        if target.is_zero() || target.algorithm() != format { return Err(TagRefusal::ObjectFormat); }
        let (expected_old, proposed_new, object) = match self {
            Self::Delete { .. } => (ExpectedOld::Exactly(target), ProposedNew::Delete, None),
            Self::Lightweight { .. } => (ExpectedOld::Absent, ProposedNew::Update(target), None),
            Self::Annotated { name, target_kind, metadata, .. } => {
                let Some((person, email)) = metadata.tagger.rsplit_once(" <") else { return Err(TagRefusal::InvalidMetadata); };
                if metadata.tagger.len() > MAX_TAG_IDENTITY_BYTES || person.trim().is_empty()
                    || person.contains(['<', '>']) || !email.ends_with('>') || email.len() <= 1
                    || email[..email.len()-1].contains(['<', '>'])
                    || metadata.tagger.bytes().any(|b| b.is_ascii_control())
                    || metadata.timestamp > i64::MAX as u64 || metadata.message.contains(&0) {
                    return Err(TagRefusal::InvalidMetadata);
                }
                if metadata.message.len() > MAX_TAG_MESSAGE_BYTES { return Err(TagRefusal::Budget("message bytes")); }
                let mut body = format!("object {target}\ntype {}\ntag ", target_kind.label()).into_bytes();
                body.extend_from_slice(&name.as_bytes()[b"refs/tags/".len()..]);
                body.extend_from_slice(format!("\ntagger {} {} +0000\n\n", metadata.tagger, metadata.timestamp).as_bytes());
                body.extend_from_slice(&metadata.message);
                let id = git_object_id(format, GitObjectKind::Tag, &body);
                (ExpectedOld::Absent, ProposedNew::Update(id), Some(TagObject { id, target, body }))
            }
        };
        Ok(PreparedTag { command: RefCommand { name: self.reference().clone(), expected_old, proposed_new, force: false }, object })
    }
}

/// Signature presence is not cryptographic verification or trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagSignatureState { Absent, OpaqueUnverifiable }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagAnnotation {
    pub id: GitOid,
    pub target: GitOid,
    pub target_kind: GitObjectKind,
    pub body: Vec<u8>,
    pub signature: TagSignatureState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagRead {
    pub head: RepositoryAuthorityHeadId,
    pub reference: RefName,
    pub tip: GitOid,
    pub peeled: GitOid,
    pub peeled_kind: GitObjectKind,
    /// Outermost first; a lightweight tag has no annotation of its own.
    /// A lightweight alias of an annotated tag still exposes that object's chain.
    pub annotations: Vec<TagAnnotation>,
}

/// One shared original-byte budget including the terminal non-tag object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagReadLimits {
    pub max_tags: usize,
    pub max_object_bytes: usize,
    pub max_total_bytes: usize,
}
impl Default for TagReadLimits {
    fn default() -> Self { Self { max_tags: 64, max_object_bytes: 1024 * 1024, max_total_bytes: 4 * 1024 * 1024 } }
}
impl TagReadLimits {
    pub fn validate(self) -> Result<(), TagRefusal> {
        let ceiling = Self::default();
        if self.max_tags == 0 || self.max_tags > ceiling.max_tags
            || self.max_object_bytes == 0 || self.max_object_bytes > ceiling.max_object_bytes
            || self.max_total_bytes == 0 || self.max_total_bytes > ceiling.max_total_bytes {
            return Err(TagRefusal::InvalidLimits);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target(format: GitHashAlgorithm) -> GitOid { git_object_id(format, GitObjectKind::Blob, b"hello\n") }
    fn annotation(format: GitHashAlgorithm) -> TagCommand {
        TagCommand::Annotated { name: RefName::try_new(b"refs/tags/release/\xff").unwrap(), target: target(format),
            target_kind: GitObjectKind::Blob, metadata: TagMetadata { tagger: "Release Author <release@example.invalid>".into(), timestamp: 0, message: b"exact\r\nmessage".to_vec() } }
    }
    #[test]
    fn native_bytes_are_exact_and_lightweight_tags_synthesize_no_object() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let command = annotation(format); let prepared = command.prepare(format).unwrap(); let object = prepared.object.unwrap();
            let expected = [format!("object {}\ntype blob\ntag release/", target(format)).as_bytes(),
                b"\xff\ntagger Release Author <release@example.invalid> 0 +0000\n\nexact\r\nmessage"].concat();
            assert_eq!(object.body, expected); assert_eq!(object.id, git_object_id(format, GitObjectKind::Tag, &expected));
            assert_eq!(prepared.command.proposed_new, ProposedNew::Update(object.id)); assert!(!prepared.command.force);
            let light = TagCommand::Lightweight { name: command.reference().clone(), target: target(format) }.prepare(format).unwrap();
            assert_eq!(light.command.proposed_new, ProposedNew::Update(target(format))); assert!(light.object.is_none());
            let delete = TagCommand::Delete { name: command.reference().clone(), expected: object.id }.prepare(format).unwrap();
            assert_eq!(delete.command.expected_old, ExpectedOld::Exactly(object.id)); assert_eq!(delete.command.proposed_new, ProposedNew::Delete); assert!(delete.object.is_none());
        }
    }
    #[test]
    fn metadata_hash_domain_and_namespace_cannot_be_reinterpreted() {
        let format = GitHashAlgorithm::Sha1;
        let original = annotation(format); let mut altered = original.clone();
        if let TagCommand::Annotated { metadata, .. } = &mut altered { metadata.message.push(b'\n'); }
        assert_ne!(original.prepare(format).unwrap().command.proposed_new, altered.prepare(format).unwrap().command.proposed_new);
        assert!(original.prepare(GitHashAlgorithm::Sha256).is_err());
        for name in [b"refs/heads/v1".as_slice(), b"refs/tags-other/v1"] {
            assert!(TagCommand::Lightweight { name: RefName::try_new(name).unwrap(), target: target(format) }.prepare(format).is_err());
        }
        for tagger in ["missing", " <a@b>", "Name <>", "Name <a<b>>", "Name <a@b>\ninjected"] {
            let mut bad = original.clone(); if let TagCommand::Annotated { metadata, .. } = &mut bad { metadata.tagger = tagger.into(); }
            assert!(bad.prepare(format).is_err());
        }
        let mut empty = original.clone(); if let TagCommand::Annotated { metadata, .. } = &mut empty { metadata.message.clear(); }
        assert!(empty.prepare(format).is_ok());
        if let TagCommand::Annotated { metadata, .. } = &mut empty { metadata.message = vec![b'x'; MAX_TAG_MESSAGE_BYTES + 1]; }
        assert!(matches!(empty.prepare(format), Err(TagRefusal::Budget(_))));
    }
    #[test]
    fn each_declared_type_commits_distinct_bytes_and_read_limits_only_narrow() {
        let mut ids = std::collections::BTreeSet::new();
        for kind in GitObjectKind::ALL {
            let mut command = annotation(GitHashAlgorithm::Sha256);
            if let TagCommand::Annotated { target_kind, .. } = &mut command { *target_kind = *kind; }
            ids.insert(command.prepare(GitHashAlgorithm::Sha256).unwrap().object.unwrap().id);
        }
        assert_eq!(ids.len(),4); assert!(TagReadLimits::default().validate().is_ok());
        assert!(TagReadLimits { max_tags: 65, ..Default::default() }.validate().is_err());
        assert!(TagReadLimits { max_total_bytes: 0, ..Default::default() }.validate().is_err());
    }
}
