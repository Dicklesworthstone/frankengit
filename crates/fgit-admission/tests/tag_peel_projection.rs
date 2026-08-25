use std::collections::{BTreeMap, BTreeSet};

use fgit_admission::{AdmissionSnapshot, PermittedObjectClosure, TagPeelLimits, TagPeelRefusal};
use fgit_crypto::git_object_id;
use fgit_git_object::{ObjectType, ParseLimits};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId, PackWriteError,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

#[derive(Default)]
struct FixtureSource {
    objects: BTreeMap<ObjectId, CanonicalPackObject>,
}

impl FixtureSource {
    fn with(objects: impl IntoIterator<Item = CanonicalPackObject>) -> Self {
        Self {
            objects: objects
                .into_iter()
                .map(|object| (object.id(), object))
                .collect(),
        }
    }
}

impl CanonicalObjectSource for FixtureSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.objects
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

fn object(object_type: ObjectType, body: impl Into<Vec<u8>>) -> CanonicalPackObject {
    let body = body.into();
    let id = git_object_id(ObjectFormat::Sha1, object_type, &body);
    CanonicalPackObject::new(id, object_type, body, Vec::new(), 0, 0)
}

fn annotated_tag(target: GitOid, declared_type: &str) -> CanonicalPackObject {
    object(
        ObjectType::Tag,
        format!(
            "object {target}\ntype {declared_type}\ntag release\ntagger A U Thor <a@example.invalid> 0 +0000\n\nmessage\n"
        ),
    )
}

fn tag_ref(name: &[u8]) -> RefName {
    RefName::try_new(name).expect("fixed valid tag ref")
}

fn snapshot(tag: RefName, target: GitOid) -> AdmissionSnapshot {
    let mut snapshot = AdmissionSnapshot::default();
    snapshot.refs.insert(tag, target);
    snapshot
}

fn closure(objects: impl IntoIterator<Item = GitOid>) -> PermittedObjectClosure {
    PermittedObjectClosure::new(objects.into_iter().collect::<BTreeSet<_>>())
}

fn derive(
    snapshot: &mut AdmissionSnapshot,
    closure: &PermittedObjectClosure,
    source: &impl CanonicalObjectSource,
    limits: TagPeelLimits,
) -> Result<(), TagPeelRefusal> {
    snapshot.derive_tag_peels(
        closure,
        source,
        GitHashAlgorithm::Sha1,
        &ParseLimits::default(),
        limits,
    )
}

#[test]
fn annotated_tag_evidence_reaches_its_verified_terminal_target() {
    let commit = object(
        ObjectType::Commit,
        b"tree 0000000000000000000000000000000000000000\n",
    );
    let tag = annotated_tag(commit.id(), "commit");
    let name = tag_ref(b"refs/tags/release");
    let mut snapshot = snapshot(name.clone(), tag.id());
    let source = FixtureSource::with([commit.clone(), tag.clone()]);
    let closure = closure([commit.id(), tag.id()]);

    derive(&mut snapshot, &closure, &source, TagPeelLimits::default())
        .expect("a tag whose body and terminal object are in the admitted closure peels");

    let evidence = snapshot
        .tag_peels
        .get(&name)
        .expect("annotated tag receives head-bound peel evidence");
    assert_eq!(evidence.tag_object(), tag.id());
    assert_eq!(evidence.peeled_object(), commit.id());
}

#[test]
fn nested_tag_evidence_is_bounded_and_dereferences_recursively() {
    let commit = object(
        ObjectType::Commit,
        b"tree 0000000000000000000000000000000000000000\n",
    );
    let inner = annotated_tag(commit.id(), "commit");
    let outer = annotated_tag(inner.id(), "tag");
    let name = tag_ref(b"refs/tags/outer");
    let source = FixtureSource::with([commit.clone(), inner.clone(), outer.clone()]);
    let closure = closure([commit.id(), inner.id(), outer.id()]);

    let mut accepted = snapshot(name.clone(), outer.id());
    derive(
        &mut accepted,
        &closure,
        &source,
        TagPeelLimits { max_depth: 2 },
    )
    .expect("the two-object annotated-tag chain fits its explicit bound");
    assert_eq!(
        accepted.tag_peels[&name].peeled_object(),
        commit.id(),
        "the evidence names the terminal native object, never the inner tag"
    );

    let mut exhausted = snapshot(name.clone(), outer.id());
    assert!(matches!(
        derive(
            &mut exhausted,
            &closure,
            &source,
            TagPeelLimits { max_depth: 1 },
        ),
        Err(TagPeelRefusal::DepthExceeded { tag_ref, limit: 1 }) if tag_ref == name
    ));
    assert!(
        exhausted.tag_peels.is_empty(),
        "a refused derivation does not retain partial evidence"
    );
}

#[test]
fn lightweight_tag_has_no_synthesized_object_or_peeled_evidence() {
    let commit = object(
        ObjectType::Commit,
        b"tree 0000000000000000000000000000000000000000\n",
    );
    let name = tag_ref(b"refs/tags/lightweight");
    let mut snapshot = snapshot(name.clone(), commit.id());
    let source = FixtureSource::with([commit.clone()]);
    let closure = closure([commit.id()]);

    derive(&mut snapshot, &closure, &source, TagPeelLimits::default())
        .expect("a lightweight tag is a permitted unpeeled ref");

    assert!(
        !snapshot.tag_peels.contains_key(&name),
        "the projection must not synthesize an annotated tag or a ^{{}} result"
    );
}

#[test]
fn declared_tag_type_must_match_the_verified_target_type() {
    let blob = object(ObjectType::Blob, b"not a commit");
    let tag = annotated_tag(blob.id(), "commit");
    let name = tag_ref(b"refs/tags/wrong-type");
    let mut snapshot = snapshot(name, tag.id());
    let source = FixtureSource::with([blob.clone(), tag.clone()]);
    let closure = closure([blob.id(), tag.id()]);

    assert!(matches!(
        derive(&mut snapshot, &closure, &source, TagPeelLimits::default()),
        Err(TagPeelRefusal::DeclaredTargetTypeMismatch {
            tag_object,
            target,
            ..
        }) if tag_object == tag.id() && target == blob.id()
    ));
    assert!(snapshot.tag_peels.is_empty());
}

#[test]
fn direct_tag_target_missing_from_closure_refuses_before_advertisement() {
    let tag = object(
        ObjectType::Tag,
        b"malformed body is irrelevant when absent from closure",
    );
    let name = tag_ref(b"refs/tags/dangling");
    let mut snapshot = snapshot(name.clone(), tag.id());

    assert!(matches!(
        derive(
            &mut snapshot,
            &PermittedObjectClosure::default(),
            &FixtureSource::default(),
            TagPeelLimits::default(),
        ),
        Err(TagPeelRefusal::RefTargetOutsideClosure { tag_ref, target }) if tag_ref == name && target == tag.id()
    ));
}
