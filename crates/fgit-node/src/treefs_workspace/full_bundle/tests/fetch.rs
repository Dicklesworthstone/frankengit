use super::*;
use fgit_pack::full_bundle::fetch::BundleRefMapping;

fn mapping(source: &str, destination: &str, old: Option<GitOid>) -> BundleRefMapping {
    BundleRefMapping { source: reference(source), destination: reference(destination), expected_old: old }
}
fn fetch(node: &OneNode, bytes: &[u8], mappings: &[BundleRefMapping], key: &str)
    -> Result<AdmissionResult, NodeWorkspaceRefusal>
{
    let request = node.request_context();
    node.runtime().block_on(node.fetch_full_git_bundle_durable_in(&request, &session(key), bytes, mappings, Default::default()))
}
fn tip(node: &OneNode, name: &str) -> Option<GitOid> { snapshot(node).snapshot().refs.get(&reference(name)).copied() }

#[test]
fn fetch_updates_exact_tracking_refs_and_replays_after_reopen_without_importing_other_refs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (source, base, child, _) = fixture(&root, format);
        accepted(apply(&source, &[create("refs/heads/topic", base)], "topic"));
        let bytes = export(&source, &Default::default()).into_bytes();
        let target = Scratch::new(); let mut destination = empty_node(&target, format);
        let empty = snapshot(&destination);
        let initial = [mapping("refs/heads/topic", "refs/remotes/upstream/topic", None)];
        accepted(fetch(&destination, &bytes, &initial, "initial"));
        assert_eq!(snapshot(&destination).snapshot().refs.len(), 1);
        assert_eq!(tip(&destination, "refs/remotes/upstream/topic"), Some(base));
        assert!(destination.read_git_object(child).is_err(), "unselected exclusive child was staged");
        accepted(apply(&source, &[RefCommand { name: reference("refs/heads/topic"),
            expected_old: ExpectedOld::Exactly(base), proposed_new: ProposedNew::Update(child), force: false }], "advance"));
        let next = export(&source, &Default::default()).into_bytes();
        let mappings = [mapping("refs/heads/topic", "refs/remotes/upstream/topic", Some(base)),
            mapping("refs/heads/main", "refs/heads/review", None)];
        let result = accepted(fetch(&destination, &next, &mappings, "fetch"));
        assert_eq!(result.commands.len(), 2); assert_eq!(result.commands[0], result.commands[1]);
        assert_eq!(tip(&destination, "refs/remotes/upstream/topic"), Some(child));
        assert_eq!(tip(&destination, "refs/heads/review"), Some(child));
        assert!(tip(&destination, "refs/heads/main").is_none());
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().head_target, empty.snapshot().head_target);
        assert_eq!(after.snapshot().outbox, empty.snapshot().outbox);
        assert_eq!(after.basis().body().forge_position_root, empty.basis().body().forge_position_root);
        assert_eq!(destination.read_git_object(child).unwrap(), source.read_git_object(child).unwrap());
        destination.push_quota.limit.max_events = 0;
        assert_eq!(fetch(&destination, &next, &mappings, "fetch").unwrap(), result);
        assert_eq!(fetch(&destination, &next, &[mappings[1].clone(), mappings[0].clone()], "fetch").unwrap(), result);
        assert_eq!(snapshot(&destination).basis(), after.basis());
        destination.shutdown().unwrap();
        let reopened = OneNode::open_existing(target.config(format)).unwrap();
        assert_eq!(fetch(&reopened, &next, &mappings, "fetch").unwrap(), result);
        reopened.shutdown().unwrap(); source.shutdown().unwrap();
    }
}

#[test]
fn stale_expectation_refuses_the_whole_batch_and_refusal_replays() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (source, base, child, _) = fixture(&root, format);
        let bytes = export(&source, &Default::default()).into_bytes();
        let target = Scratch::new(); let destination = empty_node(&target, format);
        accepted(fetch(&destination, &bytes, &[mapping("refs/heads/main", "refs/remotes/upstream/main", None)], "initial"));
        let before = snapshot(&destination);
        let mappings = [mapping("refs/heads/main", "refs/remotes/upstream/main", Some(base)),
            mapping("refs/heads/main", "refs/heads/new", None)];
        let refused = fetch(&destination, &bytes, &mappings, "stale").unwrap();
        assert!(refused.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Refused { .. })));
        assert_eq!(snapshot(&destination).snapshot().refs, before.snapshot().refs);
        assert_eq!(tip(&destination, "refs/remotes/upstream/main"), Some(child));
        assert!(tip(&destination, "refs/heads/new").is_none());
        let after = snapshot(&destination);
        assert_eq!(fetch(&destination, &bytes, &mappings, "stale").unwrap(), refused);
        assert_eq!(snapshot(&destination).basis(), after.basis());
        assert!(fetch(&destination, &bytes, &[mapping("refs/heads/main", "refs/heads/different", None)], "initial").is_err());
        assert_eq!(snapshot(&destination).basis(), after.basis());
        destination.shutdown().unwrap(); source.shutdown().unwrap();
    }
}

#[test]
fn rewind_tag_replacement_and_noncommit_tracking_targets_never_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (source, base, child, blob) = fixture(&root, format);
        accepted(apply(&source, &[create("refs/heads/topic", base)], "topic"));
        let bytes = export(&source, &Default::default()).into_bytes();
        let target = Scratch::new(); let destination = empty_node(&target, format);
        accepted(fetch(&destination, &bytes, &[mapping("refs/heads/main", "refs/remotes/upstream/main", None),
            mapping("refs/heads/topic", "refs/tags/stable", None)], "initial"));
        let before = snapshot(&destination);
        assert!(fetch(&destination, &bytes, &[mapping("refs/heads/topic", "refs/remotes/upstream/main", Some(child)),
            mapping("refs/heads/main", "refs/heads/partial", None)], "rewind").is_err());
        assert!(fetch(&destination, &bytes, &[mapping("refs/heads/main", "refs/tags/stable", Some(base))], "tag-overwrite").is_err());
        assert_eq!(snapshot(&destination).basis(), before.basis());
        // Alter only advertised source identity; the pack remains hash-valid.
        let parsed = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let prefix = if format == GitHashAlgorithm::Sha1 { "# v2 git bundle\n" } else { "# v3 git bundle\n@object-format=sha256\n" };
        let bad = [format!("{prefix}{blob} refs/tags/blob\n\n").as_bytes(), parsed.pack_bytes()].concat();
        assert!(fetch(&destination, &bad, &[mapping("refs/tags/blob", "refs/remotes/upstream/blob", None)], "blob").is_err());
        assert_eq!(snapshot(&destination).basis(), before.basis());
        accepted(fetch(&destination, &bytes, &[mapping("refs/heads/main", "refs/remotes/upstream/main", Some(child))], "equal"));
        destination.shutdown().unwrap(); source.shutdown().unwrap();
    }
}

#[test]
fn corrupt_pack_bad_mapping_and_cancelled_intake_leave_authority_unchanged() {
    let root = Scratch::new(); let (source, _, _, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let bytes = export(&source, &Default::default()).into_bytes();
    let target = Scratch::new(); let destination = empty_node(&target, GitHashAlgorithm::Sha1);
    let before = snapshot(&destination); let mappings = [mapping("refs/heads/main", "refs/heads/main", None)];
    let mut corrupt = bytes.clone(); *corrupt.last_mut().unwrap() ^= 1;
    assert!(fetch(&destination, &corrupt, &mappings, "corrupt").is_err());
    assert!(fetch(&destination, &bytes, &[mappings[0].clone(), mappings[0].clone()], "duplicate").is_err());
    let request = destination.request_context(); request.authority().cancel();
    assert!(destination.runtime().block_on(destination.fetch_full_git_bundle_durable_in(
        &request, &session("cancel"), &bytes, &mappings, Default::default())).is_err());
    assert_eq!(snapshot(&destination).basis(), before.basis());
    accepted(fetch(&destination, &bytes, &mappings, "ok"));
    destination.shutdown().unwrap(); source.shutdown().unwrap();
}
