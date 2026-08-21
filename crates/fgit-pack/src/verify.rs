use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject};

use crate::{EntryKind, ObjectFormat, ObjectId, PackError, QuarantinedEntry};

/// Resolves the native Git type carried by a non-delta pack entry. Delta
/// entries intentionally refuse here: their type belongs to the resolved
/// base chain, never to their delta instruction bytes.
pub fn object_type_from_base_entry(kind: EntryKind) -> Result<ObjectType, PackError> {
    match kind {
        EntryKind::Commit => Ok(ObjectType::Commit),
        EntryKind::Tree => Ok(ObjectType::Tree),
        EntryKind::Blob => Ok(ObjectType::Blob),
        EntryKind::Tag => Ok(ObjectType::Tag),
        EntryKind::OfsDelta | EntryKind::RefDelta => Err(PackError::DeltaObjectTypeUnavailable),
    }
}

/// Parses and authenticates a native Git object before returning its structured
/// representation. A caller resolving a delta supplies its inherited base
/// type; this function never guesses it from delta bytes.
pub fn verify_native_object(
    format: ObjectFormat,
    object_type: ObjectType,
    content: &[u8],
    expected_oid: &ObjectId,
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<ParsedObject, PackError> {
    let actual_format = expected_oid.algorithm();
    if actual_format != format {
        return Err(PackError::ObjectFormatMismatch {
            expected: format,
            actual: actual_format,
        });
    }
    let parsed = fgit_git_object::parse_object_body(object_type, content, profile, limits)
        .map_err(PackError::ObjectParse)?;
    let actual = fgit_crypto::git_object_id(format, object_type, content);
    if &actual != expected_oid {
        return Err(PackError::NativeObjectIdMismatch);
    }
    Ok(parsed)
}

/// Verifies a base (non-delta) entry's claimed type and native identity. Delta
/// callers must resolve their base chain and use [`verify_native_object`]
/// with that inherited type instead.
pub fn verify_base_entry(
    entry: &QuarantinedEntry,
    format: ObjectFormat,
    expected_oid: &ObjectId,
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<ParsedObject, PackError> {
    let object_type = object_type_from_base_entry(entry.header.kind)?;
    verify_native_object(
        format,
        object_type,
        &entry.inflated,
        expected_oid,
        profile,
        limits,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PackEntryHeader;

    #[test]
    fn verifies_object_type_and_native_oid_without_accepting_deltas_as_typed() {
        let bytes = b"payload";
        let expected = fgit_crypto::git_object_id(ObjectFormat::Sha1, ObjectType::Blob, bytes);
        let parsed = verify_native_object(
            ObjectFormat::Sha1,
            ObjectType::Blob,
            bytes,
            &expected,
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default(),
        )
        .expect("crypto-owned native identity");
        assert!(matches!(parsed, ParsedObject::Blob(body) if body == bytes));
        assert_eq!(
            object_type_from_base_entry(EntryKind::RefDelta),
            Err(PackError::DeltaObjectTypeUnavailable)
        );
    }

    #[test]
    fn refuses_a_native_oid_mismatch_before_object_is_returned() {
        let entry = QuarantinedEntry {
            offset: 12,
            header: PackEntryHeader {
                kind: EntryKind::Blob,
                declared_size: 7,
            },
            delta_base: None,
            inflated: b"payload".to_vec(),
        };
        let wrong = fgit_crypto::git_object_id(ObjectFormat::Sha1, ObjectType::Blob, b"other");
        assert_eq!(
            verify_base_entry(
                &entry,
                ObjectFormat::Sha1,
                &wrong,
                AcceptanceProfile::GitCompatibleImport,
                &ParseLimits::default(),
            ),
            Err(PackError::NativeObjectIdMismatch)
        );
    }
}
