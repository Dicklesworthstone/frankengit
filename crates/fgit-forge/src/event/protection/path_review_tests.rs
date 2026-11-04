//! Path requirements have one required encoding and cannot reinterpret older
//! policy bytes or weaken their canonical ordering and resource limits.
use super::tests::{actor, policy, required_check};
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn rule(path: &[u8], scope: PathReviewScope) -> PathReviewRule {
    PathReviewRule {
        path: path.to_vec(),
        scope,
        reviewers: vec![actor(3), actor(4)],
        required_approvals: 1,
    }
}
fn paths_only() -> ReviewProtection {
    let mut value = policy();
    let branch = &mut value.branches[0];
    branch.reviewers.clear();
    branch.required_approvals = 0;
    branch.path_reviews = vec![rule(b"src/\xff", PathReviewScope::Subtree)];
    value
}
fn event(protection: ReviewProtection) -> ForgeEvent {
    ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection,
    }
    .proposed_event(actor(1))
    .unwrap()
}
fn change(event: &ForgeEvent) -> &NativeProtectionEvent {
    let ForgeEventPayload::ReviewProtectionChanged(value) = &event.payload else {
        panic!("expected protection");
    };
    value
}
fn payload(event: &ForgeEvent) -> Vec<u8> {
    let mut out = Encoder::new();
    change(event).write(&mut out).unwrap();
    out.into_bytes()
}
fn read(bytes: &[u8]) -> Result<NativeProtectionEvent, CodecRefusal> {
    let mut input = Decoder::new(bytes, DecodeLimits::DEFAULT);
    let value = NativeProtectionEvent::read_with_path_reviews(&mut input)?;
    input.finish()?;
    Ok(value)
}

#[test]
fn path_only_policy_has_frozen_required_field_order_and_complete_roundtrip() {
    let expected = event(paths_only());
    assert_eq!(expected.payload.kind(), 26);
    // Independent primitive construction freezes the complete new payload.
    let mut frozen = vec![1; 16];
    frozen.extend_from_slice(&1_u64.to_be_bytes());
    frozen.extend_from_slice(&1_u32.to_be_bytes());
    frozen.extend_from_slice(&[1; 16]);
    frozen.extend_from_slice(&1_u32.to_be_bytes());
    frozen.extend_from_slice(&15_u32.to_be_bytes());
    frozen.extend_from_slice(b"refs/heads/main");
    frozen.extend_from_slice(&0_u32.to_be_bytes()); // global reviewers
    frozen.extend_from_slice(&0_u16.to_be_bytes()); // global approvals
    frozen.extend_from_slice(&0_u32.to_be_bytes()); // ordinary checks
    frozen.push(0); // queue
    frozen.extend_from_slice(&0_u32.to_be_bytes()); // candidate checks
    frozen.extend_from_slice(&1_u32.to_be_bytes()); // path rules
    frozen.extend_from_slice(&5_u32.to_be_bytes());
    frozen.extend_from_slice(b"src/\xff");
    frozen.push(1); // subtree
    frozen.extend_from_slice(&2_u32.to_be_bytes());
    frozen.extend_from_slice(&[3; 16]);
    frozen.extend_from_slice(&[4; 16]);
    frozen.extend_from_slice(&1_u16.to_be_bytes());
    assert_eq!(payload(&expected), frozen);
    assert_eq!(read(&frozen).unwrap(), *change(&expected));
    let frame = encode_body(&expected).unwrap();
    let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(encode_body(&decoded).unwrap(), frame);
    for end in 0..frame.len() {
        assert!(decode_body::<ForgeEvent>(&frame[..end], DecodeLimits::DEFAULT).is_err());
    }
    let mut extra = frame;
    extra.push(0);
    assert!(decode_body::<ForgeEvent>(&extra, DecodeLimits::DEFAULT).is_err());
    let scope = frozen.len() - 2 - 32 - 4 - 1;
    for unknown in [2, 127, 255] {
        let mut invalid = frozen.clone();
        invalid[scope] = unknown;
        assert!(read(&invalid).is_err());
    }
}

#[test]
fn every_matching_selector_uses_raw_bytes_and_component_boundaries() {
    for (path, scope, yes, no) in [
        (
            b"src/security".as_slice(),
            PathReviewScope::Exact,
            vec![b"src/security".as_slice()],
            vec![
                b"src/security/key".as_slice(),
                b"src/security-old".as_slice(),
                b"SRC/security".as_slice(),
            ],
        ),
        (
            b"src/\xff".as_slice(),
            PathReviewScope::Subtree,
            vec![b"src/\xff".as_slice(), b"src/\xff/key".as_slice()],
            vec![b"src/\xff-old".as_slice(), b"src/\xef\xbf\xbd".as_slice()],
        ),
    ] {
        let selector = rule(path, scope);
        selector.validate().unwrap();
        for value in yes {
            assert!(
                selector.matches(value),
                "missing exact byte match: {value:?}"
            );
        }
        for value in no {
            assert!(!selector.matches(value), "invented byte match: {value:?}");
        }
    }
}

#[test]
fn selectors_and_reviewers_are_canonical_sets_and_counts_are_required() {
    let mut value = paths_only();
    for path in [
        b"".as_slice(),
        b"/src",
        b"src/",
        b"src//key",
        b"src/./key",
        b"src/../key",
        b"src\0key",
    ] {
        value.branches[0].path_reviews[0].path = path.to_vec();
        assert!(value.validate().is_err(), "accepted {path:?}");
    }
    value = paths_only();
    value.branches[0].path_reviews[0].path = vec![b'x'; MAX_PATH_REVIEW_PATH_BYTES];
    value.validate().unwrap();
    value.branches[0].path_reviews[0].path.push(b'x');
    assert!(value.validate().is_err());
    for reviewers in [vec![], vec![actor(4), actor(3)], vec![actor(3), actor(3)]] {
        let mut value = paths_only();
        value.branches[0].path_reviews[0].reviewers = reviewers;
        assert!(value.validate().is_err());
    }
    for count in [0, 3, u16::MAX] {
        let mut value = paths_only();
        value.branches[0].path_reviews[0].required_approvals = count;
        assert!(value.validate().is_err());
    }
    let exact = rule(b"src", PathReviewScope::Exact);
    let subtree = rule(b"src", PathReviewScope::Subtree);
    let mut value = paths_only();
    value.branches[0].path_reviews = vec![exact.clone(), subtree.clone()];
    value.validate().unwrap();
    value.branches[0].path_reviews = vec![subtree, exact.clone()];
    assert!(value.validate().is_err());
    let mut duplicate = exact.clone();
    duplicate.reviewers = vec![actor(9)];
    value.branches[0].path_reviews = vec![exact, duplicate];
    assert!(
        value.validate().is_err(),
        "reviewer changes hid a duplicate selector"
    );
}

// Encode unchecked rule lists independently of NativeProtectionEvent::write,
// so decoder bounds are exercised without the writer rejecting them first.
fn unchecked(lists: &[Vec<PathReviewRule>]) -> Vec<u8> {
    let mut out = Encoder::new();
    out.write_opaque_id(actor(1).as_bytes());
    out.write_scalar(1_u64);
    out.write_scalar(1_u32);
    out.write_opaque_id(actor(1).as_bytes());
    out.write_scalar(lists.len() as u32);
    for (index, rules) in lists.iter().enumerate() {
        out.write_ref_name(
            &RefName::try_new(format!("refs/heads/p{index:03}").as_bytes()).unwrap(),
        )
        .unwrap();
        out.write_scalar(0_u32);
        out.write_scalar(0_u16);
        out.write_scalar(0_u32);
        out.write_bool(false);
        out.write_scalar(0_u32);
        out.write_scalar(rules.len() as u32);
        for rule in rules {
            out.write_bytes("path", &rule.path).unwrap();
            out.write_scalar(match rule.scope {
                PathReviewScope::Exact => 0_u8,
                PathReviewScope::Subtree => 1_u8,
            });
            out.write_scalar(rule.reviewers.len() as u32);
            for reviewer in &rule.reviewers {
                out.write_opaque_id(reviewer.as_bytes());
            }
            out.write_scalar(rule.required_approvals);
        }
    }
    out.into_bytes()
}

#[test]
fn decoder_bounds_each_branch_and_complete_policy_before_returning_rules() {
    let list: Vec<_> = (0..MAX_BRANCH_PATH_REVIEWS)
        .map(|n| rule(format!("path-{n:03}").as_bytes(), PathReviewScope::Exact))
        .collect();
    read(&unchecked(std::slice::from_ref(&list))).unwrap();
    let mut oversized = list.clone();
    oversized.push(rule(b"path-999", PathReviewScope::Exact));
    assert!(read(&unchecked(&[oversized])).is_err());
    let mut lists = vec![list; MAX_POLICY_PATH_REVIEWS / MAX_BRANCH_PATH_REVIEWS];
    read(&unchecked(&lists)).unwrap();
    lists.push(vec![rule(b"one-too-many", PathReviewScope::Exact)]);
    assert!(read(&unchecked(&lists)).is_err());
    let mut large: Vec<_> = (0..MAX_POLICY_PATH_REVIEW_BYTES / MAX_PATH_REVIEW_PATH_BYTES)
        .map(|n| {
            let mut path = format!("{n:03}").into_bytes();
            path.resize(MAX_PATH_REVIEW_PATH_BYTES, b'x');
            rule(&path, PathReviewScope::Exact)
        })
        .collect();
    read(&unchecked(std::slice::from_ref(&large))).unwrap();
    large.push(rule(b"z", PathReviewScope::Exact));
    assert!(read(&unchecked(&[large])).is_err());
    assert!(
        read(&unchecked(&[vec![]])).is_err(),
        "kind26 cannot encode an empty rule policy"
    );
    assert!(read(&unchecked(&[])).is_err());
}

#[test]
fn path_kind_wraps_each_policy_profile_and_preserves_all_additive_requirements() {
    let mut value = policy();
    value.branches[0].reviewers.push(actor(5));
    value.branches[0].required_checks.push(required_check());
    value.branches[0]
        .required_candidate_checks
        .push(RequiredCandidateWorkflowCheck {
            publisher: actor(8),
            graph_root: [0x71; 32],
            job: "test".into(),
        });
    value.branches[0].require_merge_queue = true;
    value.branches[0].path_reviews = paths_only().branches.remove(0).path_reviews;
    for (kind, source) in [
        (26, None),
        (16, Some("policy p { default allow }")),
        (
            17,
            Some(
                "policy p { rule owner { when actor.id == \"33333333333333333333333333333333\" then allow } default deny \"owner\" }",
            ),
        ),
        (
            18,
            Some(
                "policy p { rule verified { when actor.authentication >= single_factor then allow } default deny \"credential\" }",
            ),
        ),
    ] {
        let mut value = value.clone();
        value.ref_policy = source.map(|source| compile_ref_policy(source).unwrap());
        let expected = event(value);
        assert_eq!(expected.payload.kind(), kind);
        if source.is_some() {
            assert_eq!(&payload(&expected)[..4], &26_u32.to_be_bytes());
        }
        let encoded = encode_body(&expected).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&encoded, DecodeLimits::DEFAULT).unwrap(),
            expected
        );
        for field in 0..4 {
            let mut changed = change(&expected).protection.clone();
            let rule = &mut changed.branches[0].path_reviews[0];
            match field {
                0 => rule.path.push(b'x'),
                1 => rule.scope = PathReviewScope::Exact,
                2 => rule.reviewers[1] = actor(9),
                _ => rule.required_approvals = 2,
            }
            assert_ne!(encode_body(&event(changed)).unwrap(), encoded);
        }
    }
}

#[test]
fn old_kinds_decode_to_empty_paths_and_keep_their_exact_identity() {
    let mut settings = vec![(9, policy())];
    let mut checked = policy();
    checked.branches[0].required_checks.push(required_check());
    settings.push((13, checked));
    let mut quorum = policy();
    quorum.branches[0].reviewers.push(actor(5));
    settings.push((14, quorum));
    let mut queued = policy();
    queued.branches[0].require_merge_queue = true;
    settings.push((19, queued));
    let mut candidate = policy();
    candidate.branches[0]
        .required_candidate_checks
        .push(RequiredCandidateWorkflowCheck {
            publisher: actor(8),
            graph_root: [0x71; 32],
            job: "test".into(),
        });
    settings.push((21, candidate));
    for (kind, settings) in settings {
        let expected = event(settings);
        assert_eq!(expected.payload.kind(), kind);
        let bytes = encode_body(&expected).unwrap();
        let decoded = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
        assert!(
            change(&decoded)
                .protection
                .branches
                .iter()
                .all(|branch| branch.path_reviews.is_empty())
        );
        assert_eq!(encode_body(&decoded).unwrap(), bytes);
        assert!(read(&payload(&expected)).is_err());
    }
}
