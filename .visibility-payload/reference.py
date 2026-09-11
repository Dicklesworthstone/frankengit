import hashlib, pathlib
path=pathlib.Path('crates/fgit-reference/src/transition.rs')
before=path.read_bytes()
assert hashlib.sha1(b'blob '+str(len(before)).encode()+b'\0'+before).hexdigest()=='b2b1dfba4b93532f7da0a3e9673dd736c4fbad2b'
s=before.decode()
old='            | ForgeEventKind::PullRequestUpdated { target, .. } => Some(target),'
new='            | ForgeEventKind::PullRequestUpdated { target, .. }\n            | ForgeEventKind::PullRequestReviewed { target, .. } => Some(target),'
assert s.count(old)==1
s=s.replace(old,new,1)
anchor='    fn closed_event() -> ForgeEventKind {'
test='''    #[test]
    fn reviewed_pr_names_its_ref_without_claiming_a_ref_effect() {
        let target = fgit_types::RefName::try_new(b"refs/heads/main").unwrap();
        let review = ForgeEntityId::new(label("review-stream-entity"));
        let event = ForgeEventKind::PullRequestReviewed {
            review,
            target: target.clone(),
        };
        let intent = crate::intent::Intent::Forge(crate::intent::ForgeIntent {
            stream: ForgeStreamId::new(label("review-stream")),
            expected_position: ForgeStreamPosition::new(0),
            event: event.clone(),
        });
        assert_eq!(super::named_ref(&intent), Some(&target));
        assert_eq!(event.required_ref_effect(), None);
        assert_eq!(event.entity(), review);
    }

'''
assert s.count(anchor)==1
s=s.replace(anchor,test+anchor,1)
path.write_text(s)
print('Reviewed-event target now participates in canonical ref validation without requiring a ref mutation')
