//! One golden decision trace per rule type.
//!
//! Every case compiles a policy that uses exactly one construct of the
//! language, seals it into a content-addressed snapshot, evaluates it against
//! one shared input root, and compares the rendered trace byte for byte
//! against a checked-in file.
//!
//! ## Why every case carries three subjects
//!
//! The input root holds three ref commands chosen so that each rule type has
//! both a matching and a non-matching subject in the same golden. A golden in
//! which every subject matched would pass just as happily against a predicate
//! that always holds, and one in which none matched would pass against a
//! predicate that never does. The permitted twin is inside the golden.
//!
//! ## What a golden is allowed to be regenerated for
//!
//! Nothing, without first deciding which side is wrong. These files were
//! written from the language's semantics rather than from a program's output,
//! so a mismatch is a real disagreement between what the rules say and what
//! the evaluator did.

use std::collections::BTreeSet;

use fgit_policy::basis::{
    AggregateName, AuthenticationStrength, EvidenceKind, EvidenceReceipt, IssuerLabel, LabelName,
    PolicyInputRoot, PolicyInstant, PrincipalFacts, PrincipalKind, RefUpdateFact, RefUpdateKind,
};
use fgit_policy::{PolicySnapshot, PolicySnapshotBody, compile, evaluate, render_trace};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::numeric::CodecVersion;
use fgit_types::refs::RefName;
use fgit_types::{PrincipalId, PrincipalSnapshotId};

macro_rules! golden_case {
    ($name:literal, $source:expr) => {
        (
            $name,
            $source,
            include_str!(concat!("../goldens/", $name, ".trace")),
        )
    };
}

/// Every case: policy name, source text, and the checked-in trace.
///
/// The policy's name and the golden's file stem are the same string on
/// purpose: the trace's first line is `policy <name>`, so a case that loaded
/// the wrong golden fails on line one instead of somewhere in the middle.
const CASES: &[(&str, &str, &str)] = &[
    golden_case!(
        "text_equals",
        r#"policy text_equals {
  rule main_only {
    when ref.name == "refs/heads/main"
    then deny "the main branch is protected"
  }
  default allow
}"#
    ),
    golden_case!(
        "text_in",
        r#"policy text_in {
  rule protected_set {
    when ref.name in { "refs/heads/main", "refs/heads/release" }
    then deny "protected branch"
  }
  default allow
}"#
    ),
    golden_case!(
        "text_matches",
        r#"policy text_matches {
  rule tag_namespace {
    when ref.name matches "refs/tags/**"
    then deny "tags are immutable"
  }
  default allow
}"#
    ),
    golden_case!(
        "ref_scope",
        r#"policy ref_scope {
  rule heads_scope {
    when ref.scope == "heads"
    then allow
  }
  default deny "not a branch update"
}"#
    ),
    golden_case!(
        "actor_id",
        r#"policy actor_id {
  rule known_actor {
    when actor.id == "33333333333333333333333333333333" and ref.update == create
    then allow
  }
  default deny "unknown actor or unsupported update"
}"#
    ),
    golden_case!(
        "update_kind_equals",
        r#"policy update_kind_equals {
  rule no_delete {
    when ref.update == delete
    then deny "deletions are not allowed"
  }
  default allow
}"#
    ),
    golden_case!(
        "update_kind_in",
        r#"policy update_kind_in {
  rule rewriting {
    when ref.update in { non_fast_forward, delete }
    then deny "history rewriting is not allowed"
  }
  default allow
}"#
    ),
    golden_case!(
        "principal_kind_equals",
        r#"policy principal_kind_equals {
  rule human_creates {
    when actor.kind == human and ref.update == create
    then allow
  }
  default deny "only human ref creation is permitted here"
}"#
    ),
    golden_case!(
        "principal_kind_in",
        r#"policy principal_kind_in {
  rule people_or_services_create {
    when actor.kind in { human, service } and ref.update == create
    then allow
  }
  default deny "only people and services may create refs"
}"#
    ),
    golden_case!(
        "authentication_compare",
        r#"policy authentication_compare {
  rule strong_auth_creates {
    when actor.authentication >= multi_factor and ref.update == create
    then allow
  }
  default deny "creation requires multi-factor authentication"
}"#
    ),
    golden_case!(
        "team_contains",
        r#"policy team_contains {
  rule platform_team_creates {
    when actor.teams contains platform and ref.update == create
    then allow
  }
  default deny "only the platform team may create refs"
}"#
    ),
    golden_case!(
        "capability_contains",
        r#"policy capability_contains {
  rule force_needs_admin {
    when ref.force_requested and not actor.capabilities contains admin
    then deny "forced update without the admin capability"
  }
  default allow
}"#
    ),
    golden_case!(
        "force_requested",
        r#"policy force_requested {
  rule no_force {
    when ref.force_requested
    then deny "forced updates are not allowed"
  }
  default allow
}"#
    ),
    golden_case!(
        "aggregate_compare",
        r#"policy aggregate_compare {
  aggregate open-incidents
  rule freeze_blocks_creation {
    when aggregate.open-incidents > 0 and ref.update == create
    then deny "a change freeze is in effect"
  }
  default allow
}"#
    ),
    golden_case!(
        "evidence_accepted",
        r#"policy evidence_accepted {
  evidence code-review { issuer forge.review max_age 3600 }
  rule reviewed_only {
    when not evidence code-review
    then deny "no accepted review for this ref"
  }
  default allow
}"#
    ),
    golden_case!(
        "disjunction",
        r#"policy disjunction {
  rule tags_or_deletes {
    when ref.update == delete or ref.scope == "tags"
    then deny "deletes and tag writes are refused"
  }
  default allow
}"#
    ),
    golden_case!(
        "inequality",
        r#"policy inequality {
  rule non_branch {
    when ref.scope != "heads"
    then deny "only branch updates are permitted"
  }
  default allow
}"#
    ),
    // Declared with `never_fires` first in the source and `always_fires`
    // second, while the golden lists them the other way round. That is the
    // canonical-order assertion: rules sort by identifier at compile time, so
    // source order does not reach the trace.
    golden_case!(
        "constants",
        r#"policy constants {
  rule never_fires {
    when false
    then deny "unreachable"
  }
  rule always_fires {
    when true
    then allow
  }
  default deny "no rule matched"
}"#
    ),
];

/// The number of cases, pinned against the list rather than derived from it.
///
/// A case deleted by accident would otherwise shrink every "for each case"
/// assertion below to a smaller, still-green suite.
const EXPECTED_CASES: usize = 18;

fn ref_name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).unwrap_or_else(|error| panic!("{text}: {error}"))
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn snapshot_id() -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_digest(
        DigestAlgorithmId::try_new(2).expect("a non-reserved algorithm code point"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x56; 32]).expect("a 32-byte digest"),
    )
}

fn principal() -> PrincipalFacts {
    PrincipalFacts::try_new(
        PrincipalId::from_bytes([0x33; 16]),
        snapshot_id(),
        PrincipalKind::Human,
        AuthenticationStrength::MultiFactor,
        &[
            LabelName::from_static("platform"),
            LabelName::from_static("release"),
        ],
        &[LabelName::from_static("force-push")],
    )
    .expect("the fixture principal is well formed")
}

fn updates() -> Vec<RefUpdateFact> {
    vec![
        RefUpdateFact::try_new(
            ref_name("refs/heads/main"),
            Some(oid(1)),
            Some(oid(2)),
            RefUpdateKind::NonFastForward,
            true,
        )
        .expect("a forced non-fast-forward names both values"),
        RefUpdateFact::try_new(
            ref_name("refs/tags/v1.0.0"),
            None,
            Some(oid(3)),
            RefUpdateKind::Create,
            false,
        )
        .expect("a creation names only the new value"),
        RefUpdateFact::try_new(
            ref_name("refs/heads/stale"),
            Some(oid(4)),
            None,
            RefUpdateKind::Delete,
            false,
        )
        .expect("a deletion names only the old value"),
    ]
}

fn receipt() -> EvidenceReceipt {
    EvidenceReceipt::try_new(
        EvidenceKind::from_static("code-review"),
        IssuerLabel::from_static("forge.review"),
        ref_name("refs/heads/main"),
        PolicyInstant::from_seconds(1_000),
        PolicyInstant::from_seconds(5_000),
    )
    .expect("the fixture receipt has a non-empty window")
}

/// The one input root every golden is evaluated against.
#[must_use]
pub fn input_root() -> PolicyInputRoot {
    PolicyInputRoot::try_new(
        principal(),
        updates(),
        &[receipt()],
        &[(AggregateName::from_static("open-incidents"), 2)],
        PolicyInstant::from_seconds(2_000),
    )
    .expect("the fixture input root is well formed")
}

fn seal(source: &str) -> PolicySnapshot {
    let compiled = compile(source).unwrap_or_else(|refusal| panic!("{source}\n\n{refusal}"));
    PolicySnapshot::seal(PolicySnapshotBody::new(compiled)).unwrap_or_else(|refusal| {
        panic!(
            "sealing needs `frankengit/policy-snapshot/v1` in the fgit-crypto \
             identity-domain registry: {refusal}"
        )
    })
}

#[test]
fn every_rule_type_reproduces_its_golden_trace() {
    assert_eq!(
        CASES.len(),
        EXPECTED_CASES,
        "the case list changed; a golden may now be unread"
    );
    for (name, source, golden) in CASES {
        let snapshot = seal(source);
        let input = input_root();
        let evaluation = evaluate(&snapshot, &input)
            .unwrap_or_else(|refusal| panic!("{name} must evaluate: {refusal}"));
        assert_eq!(
            render_trace(&evaluation),
            *golden,
            "{name} trace does not reproduce its golden"
        );
    }
}

#[test]
fn every_golden_file_is_read_by_a_case() {
    let named: BTreeSet<&str> = CASES.iter().map(|(name, _, _)| *name).collect();
    assert_eq!(named.len(), EXPECTED_CASES, "two cases share a name");

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens");
    let mut on_disk = BTreeSet::new();
    for entry in std::fs::read_dir(&directory).expect("the goldens directory exists") {
        let path = entry.expect("a readable directory entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "trace")
        {
            on_disk.insert(
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(str::to_owned)
                    .expect("a golden file stem is UTF-8"),
            );
        }
    }
    let on_disk: BTreeSet<&str> = on_disk.iter().map(String::as_str).collect();
    assert_eq!(
        on_disk, named,
        "the goldens on disk and the cases in this file must be the same set"
    );
}

#[test]
fn a_golden_traces_names_every_rule_in_the_policy() {
    // The explainability requirement, checked rather than assumed: for every
    // case, every rule the policy declares appears in every subject's trace,
    // matched or not.
    for (name, source, _) in CASES {
        let snapshot = seal(source);
        let input = input_root();
        let evaluation = evaluate(&snapshot, &input)
            .unwrap_or_else(|refusal| panic!("{name} must evaluate: {refusal}"));
        let declared: BTreeSet<_> = snapshot
            .policy()
            .rules()
            .iter()
            .map(|rule| rule.id())
            .collect();
        assert!(!declared.is_empty(), "{name} declares no rules");
        for subject in evaluation.subjects() {
            let consulted: BTreeSet<_> =
                subject.visits().iter().map(|visit| visit.rule()).collect();
            assert_eq!(
                consulted,
                declared,
                "{name} subject {} consulted a different set of rules than the policy declares",
                subject.index()
            );
        }
    }
}

#[test]
fn evaluation_carries_the_snapshot_it_was_made_under() {
    let (_, source, _) = CASES[0];
    let snapshot = seal(source);
    let input = input_root();
    let evaluation = evaluate(&snapshot, &input).expect("the first case evaluates");
    assert_eq!(evaluation.snapshot(), snapshot.id());

    // And not some other policy's identity: a different policy seals to a
    // different snapshot, so the equality above is a binding and not a
    // coincidence of both sides being the same expression.
    let (_, other_source, _) = CASES[1];
    let other = seal(other_source);
    assert_ne!(other.id(), snapshot.id());
    assert_ne!(evaluation.snapshot(), other.id());
}
