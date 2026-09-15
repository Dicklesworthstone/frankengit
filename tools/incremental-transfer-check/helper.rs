
// Native Git bytes cross repositories; incarnation-scoped storage envelopes do
// not. Compare the entire object after rebinding ONLY the namespace, and prove
// both original envelopes remain bound to their own independently created node.
fn assert_native_transfer(source: &OneNode, destination: &OneNode, id: GitOid) {
    let original = source.read_git_object(id).unwrap();
    let received = destination.read_git_object(id).unwrap();
    assert_eq!(original.identity(), id);
    assert_eq!(received.identity(), id);
    assert_eq!(original.envelope().namespace(), source.namespace);
    assert_eq!(received.envelope().namespace(), destination.namespace);
    assert_ne!(source.repository_incarnation_id, destination.repository_incarnation_id);
    assert_ne!(original.envelope().namespace(), received.envelope().namespace());
    let envelope = original.envelope();
    let local = fgit_object_fabric::ObjectEnvelope::new(
        destination.namespace.clone(),
        envelope.object_identity(),
        envelope.object_kind(),
        envelope.declared_length(),
        envelope.payload_commitment(),
        envelope.codec_namespace().to_vec(),
        envelope.logical_content_identity(),
        envelope.manifest_reference(),
        &destination.segment_limits,
    ).unwrap();
    let expected = fgit_object_fabric::fabric::VerifiedObject::new(
        local, original.payload().to_vec(),
    ).unwrap();
    assert_eq!(received, expected, "native identity, bytes and all non-placement fields must survive transfer");
}
