#![forbid(unsafe_code)]

//! frankengit-kndy: delta reconstruction carries the authenticated root type.

use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits};
use fgit_pack::{
    CachedResolver, DeltaBase, DeltaObject, EntryKind, ExternalBaseLookup, ObjectFormat, ObjectId,
    PackError, PackLimits, PackObject, ScalarResolver, verify_native_object,
};
use fgit_types::native::GitOidSha1;

const fn always() -> bool {
    true
}

fn oid(byte: u8) -> ObjectId {
    GitOidSha1::from_bytes([byte; GitOidSha1::LEN]).into()
}

fn copy_all_delta(body: &[u8]) -> Vec<u8> {
    let length = u8::try_from(body.len()).expect("small fixed test body");
    vec![length, length, 0x91, 0, length]
}

fn typed_base(offset: u64, id: Option<ObjectId>, kind: EntryKind, body: &[u8]) -> PackObject {
    PackObject::TypedBase {
        offset,
        id,
        kind,
        data: body.to_vec(),
    }
}

struct ExternalBase {
    id: ObjectId,
    object_type: Option<ObjectType>,
    body: Vec<u8>,
}

impl ExternalBaseLookup for ExternalBase {
    fn lookup(&self, id: &ObjectId) -> Option<&[u8]> {
        (id == &self.id).then_some(self.body.as_slice())
    }

    fn lookup_typed(&self, id: &ObjectId) -> Option<(ObjectType, &[u8])> {
        (id == &self.id)
            .then(|| {
                self.object_type
                    .map(|object_type| (object_type, self.body.as_slice()))
            })
            .flatten()
    }
}

/// `OFS_DELTA` chains retain the type from each kind of in-pack base root.
#[test]
fn ofs_chains_inherit_each_in_pack_root_type() {
    let body = b"typed root";
    for (kind, expected_type) in [
        (EntryKind::Blob, ObjectType::Blob),
        (EntryKind::Tree, ObjectType::Tree),
        (EntryKind::Commit, ObjectType::Commit),
        (EntryKind::Tag, ObjectType::Tag),
    ] {
        let root_id = oid(0x10);
        let resolved_id = oid(0x20);
        let delta = copy_all_delta(body);
        let objects = [
            typed_base(12, Some(root_id), kind, body),
            PackObject::Delta(DeltaObject {
                offset: 24,
                id: None,
                base: DeltaBase::Ofs(12),
                program: delta.clone(),
            }),
            PackObject::Delta(DeltaObject {
                offset: 36,
                id: Some(resolved_id),
                base: DeltaBase::Ofs(24),
                program: delta,
            }),
        ];
        let limits = PackLimits::default();
        let scalar = ScalarResolver::new(&objects, &(), &limits, &mut always)
            .expect("typed OFS fixture is bounded");
        let mut cached = CachedResolver::new(&objects, &(), &limits, &mut always)
            .expect("typed OFS fixture is bounded");

        assert_eq!(
            scalar.resolve_offset_typed(36, &mut always),
            Ok((expected_type, body.to_vec())),
            "scalar type must come from {kind:?}",
        );
        assert_eq!(
            scalar.resolve_id_typed(&resolved_id, &mut always),
            Ok((expected_type, body.to_vec())),
            "scalar by-ID type must come from {kind:?}",
        );
        assert_eq!(
            cached.resolve_offset_typed(36, &mut always),
            Ok((expected_type, body.to_vec())),
            "cached type must come from {kind:?}",
        );
        assert_eq!(
            cached.resolve_id_typed(&resolved_id, &mut always),
            Ok((expected_type, body.to_vec())),
            "cached by-ID type must come from {kind:?}",
        );
    }
}

/// A `REF_DELTA` root outside the pack can supply its type through the additive
/// typed lookup method.
#[test]
fn ref_chain_inherits_type_from_typed_external_base() {
    let external_id = oid(0x31);
    let resolved_id = oid(0x32);
    let external = ExternalBase {
        id: external_id,
        object_type: Some(ObjectType::Tag),
        body: b"external".to_vec(),
    };
    let objects = [PackObject::Delta(DeltaObject {
        offset: 12,
        id: Some(resolved_id),
        base: DeltaBase::Ref(external_id),
        program: copy_all_delta(&external.body),
    })];
    let limits = PackLimits::default();
    let scalar = ScalarResolver::new(&objects, &external, &limits, &mut always)
        .expect("typed thin-pack fixture is bounded");
    let mut cached = CachedResolver::new(&objects, &external, &limits, &mut always)
        .expect("typed thin-pack fixture is bounded");
    let expected = (ObjectType::Tag, external.body.clone());

    assert_eq!(
        scalar.resolve_offset_typed(12, &mut always),
        Ok(expected.clone())
    );
    assert_eq!(
        scalar.resolve_id_typed(&resolved_id, &mut always),
        Ok(expected.clone())
    );
    assert_eq!(
        cached.resolve_offset_typed(12, &mut always),
        Ok(expected.clone())
    );
    assert_eq!(
        cached.resolve_id_typed(&resolved_id, &mut always),
        Ok(expected)
    );
}

/// A legacy external lookup remains valid for byte resolution, but it cannot
/// become a source of guessed type authority.
#[test]
fn untyped_external_root_refuses_while_typed_twin_succeeds() {
    let external_id = oid(0x41);
    let external = ExternalBase {
        id: external_id,
        object_type: None,
        body: b"untyped".to_vec(),
    };
    let objects = [PackObject::Delta(DeltaObject {
        offset: 12,
        id: None,
        base: DeltaBase::Ref(external_id),
        program: copy_all_delta(&external.body),
    })];
    let limits = PackLimits::default();
    let scalar = ScalarResolver::new(&objects, &external, &limits, &mut always)
        .expect("legacy thin-pack fixture remains bounded");
    let mut cached = CachedResolver::new(&objects, &external, &limits, &mut always)
        .expect("legacy thin-pack fixture remains bounded");

    assert_eq!(
        scalar.resolve_offset(12, &mut always),
        Ok(external.body.clone()),
        "the established byte-only resolver remains compatible",
    );
    assert_eq!(
        scalar.resolve_offset_typed(12, &mut always),
        Err(PackError::UntypedExternalDeltaBase),
    );
    assert_eq!(
        cached.resolve_offset_typed(12, &mut always),
        Err(PackError::UntypedExternalDeltaBase),
    );
}

/// Changing the root type changes the native object identity domain, so the
/// downstream native verifier catches the mutation instead of accepting the
/// same reconstructed bytes under a substituted type.
#[test]
fn swapped_root_type_is_caught_by_native_object_verification() {
    let body = b"this is not a commit body";
    let objects = [
        typed_base(12, None, EntryKind::Commit, body),
        PackObject::Delta(DeltaObject {
            offset: 24,
            id: None,
            base: DeltaBase::Ofs(12),
            program: copy_all_delta(body),
        }),
    ];
    let limits = PackLimits::default();
    let scalar = ScalarResolver::new(&objects, &(), &limits, &mut always)
        .expect("type-mutation fixture is bounded");
    let (object_type, reconstructed) = scalar
        .resolve_offset_typed(24, &mut always)
        .expect("the resolver reports the root type with its bytes");
    let blob_identity = fgit_crypto::git_object_id(ObjectFormat::Sha1, ObjectType::Blob, body);

    assert_eq!(object_type, ObjectType::Commit);
    assert_eq!(
        verify_native_object(
            ObjectFormat::Sha1,
            object_type,
            &reconstructed,
            &blob_identity,
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default(),
        ),
        Err(PackError::NativeObjectIdMismatch),
    );
}
