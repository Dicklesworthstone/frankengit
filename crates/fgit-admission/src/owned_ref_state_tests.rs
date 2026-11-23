//! Owned preparation preserves the immutable ref-state transition contract.

use super::*;

fn name(value: &str) -> RefName {
    RefName::try_new(value.as_bytes()).unwrap()
}

fn oid(algorithm: GitHashAlgorithm, byte: u8) -> GitOid {
    match algorithm {
        GitHashAlgorithm::Sha1 => GitOid::Sha1(fgit_types::GitOidSha1::from_bytes([byte; 20])),
        GitHashAlgorithm::Sha256 => {
            GitOid::Sha256(fgit_types::GitOidSha256::from_bytes([byte; 32]))
        }
    }
}

#[test]
fn owned_transitions_preserve_immutable_basis_and_exact_refusal_semantics() {
    for algorithm in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut initial = (0..1024)
            .map(|index| {
                (
                    name(&format!("refs/heads/inherited-{index:04}")),
                    oid(algorithm, 1),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for key in [
            "refs/heads/main",
            "refs/heads/topic/child",
            "refs/heads/topic-sibling",
            "refs/heads/flat",
        ] {
            initial.insert(name(key), oid(algorithm, 1));
        }
        let before =
            CanonicalRefState::new_with_head_target(initial, name("refs/heads/main")).unwrap();
        let original = encode_body(&before).unwrap();
        let set = |key, byte| (name(key), RefEffect::Set(oid(algorithm, byte)));
        let delete = |key| (name(key), RefEffect::Delete);
        for (changes, refusal) in [
            (vec![], None),
            (vec![set("refs/heads/new", 2)], None),
            (vec![set("refs/heads/inherited-0512", 2)], None),
            (vec![set("refs/heads/inherited-0512", 1)], None),
            (vec![delete("refs/heads/inherited-0512")], None),
            (vec![delete("refs/heads/absent")], None),
            (
                vec![delete("refs/heads/main")],
                Some(RefusalCode::ProtectedRefTransitionDenied),
            ),
            (
                vec![set("refs/heads/topic", 2)],
                Some(RefusalCode::RefNameConflict),
            ),
            (
                vec![set("refs/heads/flat/child", 2)],
                Some(RefusalCode::RefNameConflict),
            ),
            (
                vec![set("refs/heads/new", 2), set("refs/heads/new/child", 2)],
                Some(RefusalCode::RefNameConflict),
            ),
            (
                vec![set("refs/heads/topic", 2), delete("refs/heads/topic/child")],
                None,
            ),
            (
                vec![delete("refs/heads/flat"), set("refs/heads/flat/child", 2)],
                None,
            ),
            (vec![set("refs/heads/topic/other", 2)], None),
            (vec![set("refs/heads/topicx/child", 2)], None),
        ] {
            let changes: BTreeMap<_, _> = changes.into_iter().collect();
            let borrowed = before.apply(&changes);
            let actual = before.clone().into_applied(&changes);
            assert_eq!(
                actual, borrowed,
                "owned/immutable disagreement: {changes:?}"
            );
            assert_eq!(
                encode_body(&before).unwrap(),
                original,
                "borrowed basis changed"
            );
            if let Some(refusal) = refusal {
                assert_eq!(actual, Err(refusal));
                continue;
            }
            // Independent copy-and-apply after-image, including every untouched ref.
            let mut expected = before.refs().clone();
            for (key, effect) in &changes {
                match effect {
                    RefEffect::Set(value) => {
                        expected.insert(key.clone(), *value);
                    }
                    RefEffect::Delete => {
                        expected.remove(key);
                    }
                }
            }
            let expected =
                CanonicalRefState::new_with_head_target(expected, name("refs/heads/main")).unwrap();
            let actual = actual.unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                encode_body(&actual).unwrap(),
                encode_body(&expected).unwrap()
            );
        }
    }
}
