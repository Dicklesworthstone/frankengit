//! Real native publications and file-backed reads with a failed process-local
//! admission cache. The fault poisons only that derived RwLock; no authority
//! body, source object, configuration or publication history is fabricated.

use super::*;
use fgit_admission::merge::native::issues::IssuePage;
use fgit_forge::IssueNumber;
use fgit_forge::event::issue::{IssueAction, IssueCommand};

fn issues_at(node: &OneNode, pin: Option<RepositoryAuthorityHeadId>) -> IssuePage {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_issues_in(&request, 0, 100, pin))
        .unwrap()
}

fn issue_command(action: IssueAction, expected_version: ExpectedVersion) -> IssueCommand {
    IssueCommand {
        number: IssueNumber::try_new(1).unwrap(),
        expected_version,
        action,
    }
}

fn publish_issue(node: &OneNode, command: &IssueCommand, key: &str) {
    let request = node.request_context();
    accepted(node.runtime().block_on(node.admit_issue_durable_in(
        &request,
        &session(key),
        command,
        AdmissionLimits::default(),
    )));
}

fn materializer_refuses_poison(node: &OneNode) {
    let request = node.request_context();
    assert!(matches!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request)),
        Err(AdmissionMaterializationRefusal::CachePoisoned)
    ));
}

#[test]
fn native_current_and_retained_metadata_survive_an_unavailable_admission_cache() {
    let format = GitHashAlgorithm::Sha256;
    let scratch = Scratch::new();
    let node = node(&scratch, format);
    let source = fixture(&node, &scratch, format);
    let open = command(&source, 1);
    accepted(apply(&node, &open, "metadata-isolation-pr-open"));
    publish_issue(
        &node,
        &issue_command(
            IssueAction::Open {
                title: "Independent issue".into(),
                body: "Read from canonical events".into(),
                labels: Vec::new(),
            },
            ExpectedVersion::NewStream,
        ),
        "metadata-isolation-issue-open",
    );
    let retained_prs = page(&node, 0, 100, None).unwrap();
    let retained_issues = issues_at(&node, None);
    let retained = retained_prs.source_head;
    assert_eq!(retained_issues.source_head, retained);

    let mut update = open;
    update.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    update.action = PullRequestAction::Update;
    update.data.title = "Current title".into();
    accepted(apply(&node, &update, "metadata-isolation-pr-update"));
    publish_issue(
        &node,
        &issue_command(
            IssueAction::Comment {
                body: "A later comment".into(),
            },
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
        ),
        "metadata-isolation-issue-comment",
    );
    let current_prs = page(&node, 0, 100, None).unwrap();
    let current_issues = issues_at(&node, None);
    assert_ne!(current_prs.source_head, retained);
    assert_eq!(current_issues.source_head, current_prs.source_head);
    assert_eq!(
        current_prs.pull_requests[0].data.as_ref().unwrap().title,
        "Current title"
    );
    assert_eq!(current_issues.issues[0].comments, 1);
    assert_eq!(retained_issues.issues[0].comments, 0);
    let before = snapshot(&node);

    // Deliberate test-only fault: a panic while holding the actual write lock
    // models an unavailable derived materializer, without changing its data.
    let cache = &node.admission_materializer.materialized;
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = cache.write().unwrap();
        panic!("seed admission-cache failure for metadata isolation");
    }));
    assert!(poisoned.is_err());
    assert!(cache.is_poisoned());
    materializer_refuses_poison(&node);

    assert_eq!(page(&node, 0, 100, None).unwrap(), current_prs);
    assert_eq!(issues_at(&node, None), current_issues);
    assert_eq!(page(&node, 0, 100, Some(retained)).unwrap(), retained_prs);
    assert_eq!(issues_at(&node, Some(retained)), retained_issues);
    // A retained token supplies no permission: each call still applies the
    // current caller visibility to both source and target before disclosure.
    for hidden in [source_ref(), target()] {
        let mut visibility = RefVisibility::new();
        visibility
            .push_rule(hidden.as_bytes(), &Default::default())
            .unwrap();
        for pin in [None, Some(retained)] {
            let request = node.request_context();
            let hidden = node
                .runtime()
                .block_on(node.read_pull_requests_in(&request, &visibility, 0, 100, pin))
                .unwrap();
            assert!(hidden.pull_requests.is_empty());
            assert_eq!(hidden.next_after, None);
        }
    }
    let cancelled = node.request_context();
    cancelled.authority().cancel();
    assert!(
        node.runtime()
            .block_on(node.read_pull_requests_in(
                &cancelled,
                &RefVisibility::new(),
                0,
                100,
                Some(retained),
            ))
            .is_err()
    );
    assert!(
        node.runtime()
            .block_on(node.read_issues_in(&cancelled, 0, 100, Some(retained),))
            .is_err()
    );
    materializer_refuses_poison(&node);
    let after = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    assert_eq!(after.receipt(), before.authenticated().receipt());
    node.shutdown().unwrap();

    // The failure was process-local. Reopening preserves the real current and
    // retained metadata, and the independently reconstructed materializer works.
    let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
    reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
    assert_eq!(page(&reopened, 0, 100, None).unwrap(), current_prs);
    assert_eq!(issues_at(&reopened, None), current_issues);
    assert_eq!(
        page(&reopened, 0, 100, Some(retained)).unwrap(),
        retained_prs
    );
    assert_eq!(issues_at(&reopened, Some(retained)), retained_issues);
    assert_eq!(snapshot(&reopened).basis(), before.basis());
    reopened.shutdown().unwrap();
}
