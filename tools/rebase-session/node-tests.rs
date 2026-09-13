
fn rebase_inputs(f: &Fixture) -> RebaseRequest {
    RebaseRequest { source_tip:f.source,upstream:f.base,onto:f.target,empty:EmptyCommitPolicy::Stop }
}
fn committer() -> RebaseCommitter {
    RebaseCommitter { identity:"Rebaser <rebaser@example.invalid>".into(),timestamp:100 }
}
fn bundle_pack(bundle: &[u8]) -> &[u8] {
    let offset=bundle.windows(2).position(|b|b==b"\n\n").unwrap()+2;
    assert!(bundle[offset..].starts_with(b"PACK"));&bundle[offset..]
}
fn publish(node: &OneNode, old: GitOid, new: GitOid, pack: &[u8], key: &[u8]) -> fgit_admission::AdmissionResult {
    use crate::quarantine_validator::ProductionReceiveQuarantineHandoff;
    use fgit_authority::IdempotencyKey;
    use fgit_wire::receive::{ReceiveContext,ReceiveLimits,ReceivePack,SignedPushProfile};
    use fgit_wire::{Capabilities,Packet,encode_packets};
    let request=node.request_context();
    let selected=node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let limits=ReceiveLimits::default();
    let caps=format!("report-status atomic object-format={}",old.algorithm().as_str());
    let context=ReceiveContext::new(old.algorithm(),Capabilities::parse_v1(caps.as_bytes(),&limits.wire).unwrap(),limits.clone(),SignedPushProfile::Refuse).unwrap();
    let prefix=encode_packets(&[Packet::Data(format!("{old} {new} refs/heads/topic\0{caps}\n").into_bytes()),Packet::Flush],&limits.wire).unwrap();
    let validator=node.production_quarantine_validator(&selected,limits.pack.clone(),ParseLimits { tree_reference_bytes:old.algorithm().digest_len(),..ParseLimits::default() }).unwrap();
    let mut handoff=ProductionReceiveQuarantineHandoff::new(validator,selected.basis().clone());
    let mut receiver=ReceivePack::new(context).unwrap();
    receiver.push_bytes(&prefix).unwrap();receiver.push_bytes(pack).unwrap();
    receiver.finish_with_handoff(&mut handoff,&mut ||true).unwrap();
    let validated=handoff.into_validated_receive().unwrap();
    let session=crate::LoopbackReceiveSession::authenticated(principal(),IdempotencyKey::new(key.to_vec()).unwrap());
    node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(&request,&session,&validated,fgit_admission::AdmissionLimits::default())).unwrap()
}

#[test]
fn complete_series_exports_source_dependencies_and_publishes_through_native_receive() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let scratch=Scratch::new();let (node,f)=fixture(&scratch,format,false);
        let request=node.request_context();let before=node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let artifact=node.runtime().block_on(node.prepare_rebase_bundle_in(&request,&topic_ref(),&main_ref(),rebase_inputs(&f),
            &Default::default(),Some(before.basis().id()),&committer(),PreparationLimits::default())).unwrap();
        let RebasePreparation::Clean(plan)=&artifact.outcome else {panic!("clean series expected");};
        assert_eq!(plan.steps.len(),2);assert_eq!(plan.steps[0].original,f.picked);assert_eq!(plan.steps[1].original,f.source);
        assert_eq!(artifact.source_head,before.basis().id());assert_eq!(artifact.borrowed_objects,2);
        assert!(node.read_git_object(plan.commit).is_err());
        let bundle=artifact.bundle.as_ref().unwrap();
        let header=&bundle[..bundle.len()-bundle_pack(bundle).len()];
        assert!(header.windows(format!("-{} onto\n",f.target).len()).any(|p|p==format!("-{} onto\n",f.target).as_bytes()));
        assert!(!header.windows(format!("-{}",f.source).len()).any(|p|p==format!("-{}",f.source).as_bytes()));
        let pack=fgit_pack::read_verified_pack(bundle_pack(bundle),format,&PackLimits::default(),&mut ||true,&fgit_pack::NativeChecksumVerifier).unwrap();
        assert_eq!(pack.entries().len(),artifact.pack_objects);
        let expected:BTreeSet<_>=plan.objects.iter().map(|o|o.body.clone()).chain([b"selected source-only\n".to_vec(),b"later source must not appear\n".to_vec()]).collect();
        let observed:BTreeSet<_>=pack.entries().iter().map(|e|e.inflated.clone()).collect();
        assert_eq!(observed,expected,"onto-only recipient gets every source-only dependency, not the old source commits");
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(),before.basis());
        let applied=publish(&node,f.source,plan.commit,bundle_pack(bundle),b"rebase-publish");
        assert!(matches!(applied.commands[0].terminal.outcome,DecisionOutcome::Committed {..}));
        let after=node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(after.snapshot().refs[&topic_ref()],plan.commit);assert_eq!(after.snapshot().refs[&main_ref()],f.target);
        assert_eq!(after.basis().body().forge_position_root,before.basis().body().forge_position_root);
        let candidate=plan.commit;let bytes=bundle_pack(bundle).to_vec();
        node.shutdown().unwrap();
        let mut reopened=OneNode::open_existing(scratch.config(format)).unwrap();reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let retry=publish(&reopened,f.source,candidate,&bytes,b"rebase-publish");
        assert_eq!(retry.commands[0].terminal,applied.commands[0].terminal);
        let after_retry=reopened.runtime().block_on(reopened.materialize_admission_in(&reopened.request_context())).unwrap();
        assert_eq!(after_retry.basis(),after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn conflicts_bad_coordinates_hidden_refs_and_bounds_leave_canonical_state_unchanged() {
    let scratch=Scratch::new();let (node,f)=fixture(&scratch,GitHashAlgorithm::Sha1,true);
    let request=node.request_context();let before=node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let artifact=node.runtime().block_on(node.prepare_rebase_bundle_in(&request,&topic_ref(),&main_ref(),rebase_inputs(&f),
        &Default::default(),None,&committer(),PreparationLimits::default())).unwrap();
    assert!(matches!(artifact.outcome,RebasePreparation::Stopped { reason:fgit_forge::preparation::rebase::RebaseStop::Conflicted(_),.. }));
    assert!(artifact.bundle.is_none());assert_eq!(artifact.pack_objects,0);
    let mut hidden=RefVisibility::new();hidden.push_rule(b"refs/heads/topic",&fgit_wire::WireLimits::default()).unwrap();
    assert!(matches!(node.runtime().block_on(node.prepare_rebase_bundle_in(&request,&topic_ref(),&main_ref(),rebase_inputs(&f),
        &hidden,None,&committer(),PreparationLimits::default())),Err(RebasePreparationRefusal::RefUnavailable)));
    for inputs in [RebaseRequest { source_tip:f.picked,..rebase_inputs(&f) },RebaseRequest { onto:f.base,..rebase_inputs(&f) }] {
        assert!(matches!(node.runtime().block_on(node.prepare_rebase_bundle_in(&request,&topic_ref(),&main_ref(),inputs,
            &Default::default(),None,&committer(),PreparationLimits::default())),Err(RebasePreparationRefusal::TipMoved)));
    }
    let unrelated=RebaseRequest { upstream:f.target,..rebase_inputs(&f) };
    assert!(node.runtime().block_on(node.prepare_rebase_bundle_in(&request,&topic_ref(),&main_ref(),unrelated,
        &Default::default(),None,&committer(),PreparationLimits::default())).is_err());
    assert!(node.runtime().block_on(node.prepare_rebase_bundle_in(&request,&topic_ref(),&main_ref(),rebase_inputs(&f),
        &Default::default(),None,&committer(),PreparationLimits { max_commits:1,..PreparationLimits::default() })).is_err());
    assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(),before.basis());node.shutdown().unwrap();
}

#[test]
fn identity_checked_original_metadata_preserves_bytes_but_not_stale_signatures() {
    let format=GitHashAlgorithm::Sha1;
    let tree=git_object_id(format,GitObjectKind::Tree,b"");
    let make=|extra:&[u8]| {
        let mut bytes=format!("tree {tree}\nauthor Original <o@x> -1 -0430\ncommitter Old <c@x> 1 +0000\nencoding ISO-8859-1\n").into_bytes();
        bytes.extend_from_slice(extra);bytes.extend_from_slice(b"\nraw\r\n\xff\n");bytes
    };
    let signed=make(b"gpgsig old signature\n continuation\ngpgsig-sha256 old\n bytes\n");
    let id=git_object_id(format,GitObjectKind::Commit,&signed);
    let parsed=original_metadata(id,&signed,&ParseLimits::default()).unwrap();
    assert_eq!(parsed.author,b"Original <o@x> -1 -0430");assert_eq!(parsed.encoding,Some(b"ISO-8859-1".to_vec()));assert_eq!(parsed.message,b"raw\r\n\xff\n");
    for extra in [b"author Other <e@x> 1 +0000\n".as_slice(),b"committer Other <e@x> 1 +0000\n",b"encoding UTF-8\n",b"unknown-extension important\n"] {
        let body=make(extra);let id=git_object_id(format,GitObjectKind::Commit,&body);
        assert!(original_metadata(id,&body,&ParseLimits::default()).is_err());
    }
}

#[test]
fn empty_suffix_exports_a_valid_empty_pack_and_later_snapshot_pins_refuse() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let scratch=Scratch::new();let (node,f)=fixture(&scratch,format,false);
        let request=node.request_context();let before=node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let inputs=RebaseRequest { upstream:f.source,..rebase_inputs(&f) };
        let artifact=node.runtime().block_on(node.prepare_rebase_bundle_in(&request,&topic_ref(),&main_ref(),inputs,
            &Default::default(),None,&committer(),PreparationLimits::default())).unwrap();
        let RebasePreparation::Clean(plan)=&artifact.outcome else {panic!();};
        assert_eq!(plan.commit,f.target);assert!(plan.steps.is_empty());assert_eq!(artifact.pack_objects,0);
        let pack=bundle_pack(artifact.bundle.as_ref().unwrap());
        assert!(fgit_pack::read_verified_pack(pack,format,&PackLimits::default(),&mut ||true,&fgit_pack::NativeChecksumVerifier).unwrap().entries().is_empty());
        let applied=publish(&node,f.source,f.target,pack,b"empty-suffix");
        assert!(matches!(applied.commands[0].terminal.outcome,DecisionOutcome::Committed {..}));
        let inputs=RebaseRequest { source_tip:f.target,upstream:f.target,onto:f.target,empty:EmptyCommitPolicy::Stop };
        assert!(matches!(node.runtime().block_on(node.prepare_rebase_bundle_in(&request,&topic_ref(),&main_ref(),inputs,
            &Default::default(),Some(before.basis().id()),&committer(),PreparationLimits::default())),Err(RebasePreparationRefusal::SnapshotMoved)));
        node.shutdown().unwrap();
    }
}
