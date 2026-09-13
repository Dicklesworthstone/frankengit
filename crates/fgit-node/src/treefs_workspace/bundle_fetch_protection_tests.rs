#[test]
fn bundle_fetch_cannot_bypass_mandatory_review_through_a_mapped_source_name() {
    use fgit_pack::full_bundle::fetch::BundleRefMapping;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch=Scratch::new();let f=fixture(&scratch,format);
        let protected=RefName::try_new(b"refs/heads/fetch-protected").unwrap();
        let free=RefName::try_new(b"refs/heads/fetch-free").unwrap();
        let request=f.node.request_context();
        let (_,bundle)=f.node.runtime().block_on(f.node.export_full_git_bundle_in(&request,&Default::default(),None)).unwrap();
        let bytes=bundle.into_bytes();
        committed(change_policy(&f,1,b"protect-bundle-destination",&policy_command(0,PolicyEpoch::FIRST,
            protection_policy(&[protected.as_bytes()],&[1],&[3]))).unwrap());
        let before=snapshot(&f.node);
        let blocked=vec![BundleRefMapping{source:f.data.source_ref.clone(),destination:protected.clone(),expected_old:None},
            BundleRefMapping{source:f.data.source_ref.clone(),destination:free.clone(),expected_old:None}];
        let result=f.node.runtime().block_on(f.node.fetch_full_git_bundle_durable_in(&request,&session(2,"blocked-fetch"),&bytes,&blocked,AdmissionLimits::default())).unwrap();
        assert_eq!(result.commands.len(),2);assert_eq!(result.commands[0],result.commands[1]);
        assert!(matches!(result.commands[0].terminal.outcome,DecisionOutcome::Refused{code:RefusalCode::ProtectedRefTransitionDenied,..}));
        assert_eq!(snapshot(&f.node).snapshot().refs,before.snapshot().refs);
        let terminal=snapshot(&f.node);
        assert_eq!(f.node.runtime().block_on(f.node.fetch_full_git_bundle_durable_in(&request,&session(2,"blocked-fetch"),&bytes,&blocked,AdmissionLimits::default())).unwrap(),result);
        assert_eq!(snapshot(&f.node).basis(),terminal.basis());
        let allowed=[BundleRefMapping{source:f.data.source_ref.clone(),destination:free.clone(),expected_old:None}];
        let accepted=f.node.runtime().block_on(f.node.fetch_full_git_bundle_durable_in(&request,&session(2,"free-fetch"),&bytes,&allowed,AdmissionLimits::default())).unwrap();
        assert!(matches!(accepted.commands[0].terminal.outcome,DecisionOutcome::Committed{..}));
        let final_state=snapshot(&f.node);
        assert_eq!(final_state.snapshot().refs.get(&free),Some(&f.data.source_tip));
        assert!(!final_state.snapshot().refs.contains_key(&protected));
        assert_eq!(final_state.snapshot().head_target,before.snapshot().head_target);
        assert_eq!(final_state.snapshot().outbox,before.snapshot().outbox);
        assert_eq!(final_state.basis().body().forge_position_root,before.basis().body().forge_position_root);
        f.node.shutdown().unwrap();
    }
}
