
#[test]
fn overlapping_tag_creates_have_one_winner_and_stable_scoped_outcomes(){
    use std::{future::{Future, poll_fn}, task::Poll};
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let f=Fixture::new(format);let n=f.node();
        let left=annotated(b"refs/tags/contended",f.commit,GitObjectKind::Commit);
        let right=annotated(b"refs/tags/contended",f.blob,GitObjectKind::Blob);
        let a=n.request_context();let b=n.request_context();let sa=session(b"contended-a");let sb=session(b"contended-b");
        let mut fa=std::pin::pin!(n.admit_tag_durable_in(&a,&sa,&left,Default::default()));
        let mut fb=std::pin::pin!(n.admit_tag_durable_in(&b,&sb,&right,Default::default()));
        let(mut ra,mut rb)=(None,None);
        let(first,second)=n.runtime().block_on(poll_fn(|cx|{
            if ra.is_none(){if let Poll::Ready(value)=fa.as_mut().poll(cx){ra=Some(value);}}
            if rb.is_none(){if let Poll::Ready(value)=fb.as_mut().poll(cx){rb=Some(value);}}
            if ra.is_some()&&rb.is_some(){Poll::Ready((ra.take().unwrap(),rb.take().unwrap()))}else{Poll::Pending}
        }));
        let is_commit=|r:&AdmissionResult|matches!(r.commands[0].terminal.outcome,DecisionOutcome::Committed{..});
        assert_eq!(usize::from(first.as_ref().is_ok_and(is_commit))+usize::from(second.as_ref().is_ok_and(is_commit)),1);
        // A CAS-losing intake may be unavailable rather than canonically
        // refused. Resolve it only by replaying the identical scoped request.
        let a=f.apply(&left,b"contended-a").unwrap();let b=f.apply(&right,b"contended-b").unwrap();
        assert_eq!(usize::from(is_commit(&a))+usize::from(is_commit(&b)),1);
        for (initial,replayed) in [(first,&a),(second,&b)]{if let Ok(initial)=initial{assert_eq!(&initial,replayed);}}
        let winning=if is_commit(&a){&left}else{&right};let expected=winning.prepare(format).unwrap().object.unwrap().id;
        assert_eq!(f.snapshot().snapshot().refs.get(winning.reference()),Some(&expected));
        let head=f.snapshot().basis().id();assert_eq!(f.apply(&left,b"contended-a").unwrap(),a);assert_eq!(f.apply(&right,b"contended-b").unwrap(),b);
        assert_eq!(f.snapshot().basis().id(),head);
    }
}

#[test]
fn anonymous_tag_mutation_refuses_before_metadata_or_object_work(){
    let f=Fixture::new(GitHashAlgorithm::Sha1);let before=f.snapshot().basis().id();let r=f.node().request_context();
    for command in [annotated(b"refs/tags/allowed",f.commit,GitObjectKind::Commit),TagCommand::Lightweight{name:name(b"refs/heads/not-a-tag"),target:f.orphan}]{
        let result=f.node().runtime().block_on(f.node().admit_tag_durable_in(&r,&LoopbackReceiveSession::anonymous(),&command,Default::default()));
        assert!(matches!(result,Err(NodeWorkspaceRefusal::WorkspacePublication(error)) if matches!(*error,NodeReceiveTransportRefusal::Unauthenticated)));
    }
    assert_eq!(f.snapshot().basis().id(),before);
    committed(f.apply(&annotated(b"refs/tags/allowed",f.commit,GitObjectKind::Commit),b"authenticated"));
}
