//! Determinism: normalization is idempotent, canonical, and blind to the order
//! independent things were written in.
//!
//! Two source texts that state the same policy differently must compile to the
//! same value and so to the same snapshot identity. Three kinds of "written
//! differently" are covered here: operand order inside `and`/`or`, element
//! order inside a set literal, and declaration order inside the policy body.
//!
//! The predicate corpus is generated from a `SplitMix64` stream with a fixed
//! seed, so a failure reproduces from the message alone. This is a bounded
//! deterministic sweep, not a shrinking property engine and not a proof.

use fgit_codec::DecodeLimits;
use fgit_policy::basis::{
    AggregateName, AuthenticationStrength, LabelName, PrincipalKind, RefUpdateKind,
};
use fgit_policy::program::{Compare, Predicate, Selector, TextLiteral};
use fgit_policy::{PolicySnapshot, PolicySnapshotBody, RefPattern, compile};

/// Fixed seed, quoted in every failure message so a failure reproduces.
const SEED: u64 = 0x0f04_3a5e_ed01_c7c7;

struct SplitMix64(u64);

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut word = self.0;
        word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        word ^ (word >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).unwrap_or(1).max(1);
        usize::try_from(self.next_u64() % bound).unwrap_or(0)
    }
}

fn leaf(generator: &mut SplitMix64) -> Predicate {
    let texts = ["refs/heads/main", "refs/heads/dev", "heads", "tags"];
    let patterns = ["refs/heads/*", "refs/tags/**", "refs/heads/release-*"];
    let labels = ["platform", "release", "admin"];
    let aggregates = ["open-incidents", "queue-depth"];
    match generator.below(12) {
        0 => Predicate::Always,
        1 => Predicate::Never,
        2 => Predicate::ForceRequested,
        3 => Predicate::TextEquals {
            selector: Selector::RefName,
            value: TextLiteral::new(texts[generator.below(texts.len())]),
        },
        4 => Predicate::TextIn {
            selector: Selector::RefScope,
            values: (0..=generator.below(3))
                .map(|_| TextLiteral::new(texts[generator.below(texts.len())]))
                .collect(),
        },
        5 => Predicate::TextMatches {
            selector: Selector::RefName,
            pattern: RefPattern::compile(patterns[generator.below(patterns.len())])
                .expect("a corpus pattern compiles"),
        },
        6 => Predicate::UpdateKindEquals(RefUpdateKind::ALL[generator.below(4)]),
        7 => Predicate::UpdateKindIn(
            (0..=generator.below(3))
                .map(|_| RefUpdateKind::ALL[generator.below(4)])
                .collect(),
        ),
        8 => Predicate::PrincipalKindIn(
            (0..=generator.below(3))
                .map(|_| PrincipalKind::ALL[generator.below(4)])
                .collect(),
        ),
        9 => Predicate::AuthenticationCompare {
            operator: Compare::ALL[generator.below(5)],
            value: AuthenticationStrength::ALL[generator.below(4)],
        },
        10 => Predicate::LabelContains {
            selector: Selector::ActorTeams,
            label: LabelName::try_new(labels[generator.below(labels.len())].as_bytes())
                .expect("a corpus label is canonical"),
        },
        _ => Predicate::AggregateCompare {
            name: AggregateName::try_new(aggregates[generator.below(aggregates.len())].as_bytes())
                .expect("a corpus aggregate is canonical"),
            operator: Compare::ALL[generator.below(5)],
            value: generator.next_u64() % 8,
        },
    }
}

fn tree(generator: &mut SplitMix64, depth: u32) -> Predicate {
    if depth == 0 {
        return leaf(generator);
    }
    match generator.below(5) {
        0 => Predicate::All(
            (0..=generator.below(4))
                .map(|_| tree(generator, depth - 1))
                .collect(),
        ),
        1 => Predicate::Any(
            (0..=generator.below(4))
                .map(|_| tree(generator, depth - 1))
                .collect(),
        ),
        2 => Predicate::Not(Box::new(tree(generator, depth - 1))),
        _ => leaf(generator),
    }
}

/// The shape [`Predicate::normalize`] promises.
fn is_canonical(predicate: &Predicate) -> Result<(), String> {
    match predicate {
        Predicate::All(operands) | Predicate::Any(operands) => {
            let conjunction = matches!(predicate, Predicate::All(_));
            let (unit, absorbing) = if conjunction {
                (&Predicate::Always, &Predicate::Never)
            } else {
                (&Predicate::Never, &Predicate::Always)
            };
            if operands.len() < 2 {
                return Err(format!("junction with {} operands", operands.len()));
            }
            for window in operands.windows(2) {
                if window[0] >= window[1] {
                    return Err("junction operands are not strictly ascending".to_owned());
                }
            }
            for operand in operands {
                if operand == unit || operand == absorbing {
                    return Err("junction retains a constant operand".to_owned());
                }
                let nested_same_kind = matches!(
                    (conjunction, operand),
                    (true, Predicate::All(_)) | (false, Predicate::Any(_))
                );
                if nested_same_kind {
                    return Err("junction was not flattened".to_owned());
                }
                is_canonical(operand)?;
            }
            Ok(())
        }
        Predicate::Not(inner) => {
            if matches!(
                **inner,
                Predicate::Not(_) | Predicate::Always | Predicate::Never
            ) {
                return Err("negation was not folded".to_owned());
            }
            is_canonical(inner)
        }
        Predicate::TextIn { values, .. } => {
            if values.len() < 2 {
                return Err("text set was not folded to an equality".to_owned());
            }
            for window in values.windows(2) {
                if window[0] >= window[1] {
                    return Err("text set is not strictly ascending".to_owned());
                }
            }
            Ok(())
        }
        Predicate::UpdateKindIn(values) => {
            if values.len() < 2 {
                return Err("update-kind set was not folded".to_owned());
            }
            for window in values.windows(2) {
                if window[0] >= window[1] {
                    return Err("update-kind set is not strictly ascending".to_owned());
                }
            }
            Ok(())
        }
        Predicate::PrincipalKindIn(values) => {
            if values.len() < 2 {
                return Err("principal-kind set was not folded".to_owned());
            }
            for window in values.windows(2) {
                if window[0] >= window[1] {
                    return Err("principal-kind set is not strictly ascending".to_owned());
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[test]
fn normalization_is_idempotent_and_reaches_canonical_shape() {
    let mut generator = SplitMix64::new(SEED);
    let mut junctions_seen = 0_usize;
    for index in 0..2_000_usize {
        let raw = tree(&mut generator, 4);
        let once = raw.clone().normalize();
        let twice = once.clone().normalize();
        assert_eq!(
            once, twice,
            "seed {SEED:#x} case {index}: normalization is not idempotent for {raw:?}"
        );
        if let Err(reason) = is_canonical(&once) {
            panic!("seed {SEED:#x} case {index}: {reason} in {once:?} (from {raw:?})");
        }
        if matches!(once, Predicate::All(_) | Predicate::Any(_)) {
            junctions_seen += 1;
        }
    }
    // The corpus must actually exercise the junction rules; a generator that
    // only ever produced leaves would satisfy every assertion above while
    // testing none of them.
    assert!(
        junctions_seen > 50,
        "seed {SEED:#x}: only {junctions_seen} normalized junctions in the corpus"
    );
}

#[test]
fn permuting_junction_operands_does_not_change_the_normal_form() {
    let mut generator = SplitMix64::new(SEED ^ 0x5555_5555_5555_5555);
    for index in 0..500_usize {
        let operands: Vec<Predicate> = (0..4).map(|_| tree(&mut generator, 2)).collect();
        let mut rotated = operands.clone();
        rotated.rotate_left(1 + generator.below(3));
        assert_eq!(
            Predicate::All(operands.clone()).normalize(),
            Predicate::All(rotated.clone()).normalize(),
            "seed {SEED:#x} case {index}: conjunction is order-sensitive"
        );
        assert_eq!(
            Predicate::Any(operands).normalize(),
            Predicate::Any(rotated).normalize(),
            "seed {SEED:#x} case {index}: disjunction is order-sensitive"
        );
    }
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

const ORDERED: &str = r#"policy ordering {
  aggregate open-incidents
  aggregate queue-depth
  evidence code-review { issuer forge.review max_age 3600 }
  evidence deploy-approval { issuer forge.deploy }

  rule alpha {
    when ref.name matches "refs/heads/**" and ref.update == create and evidence code-review
    then allow
  }
  rule beta {
    when ref.name in { "refs/heads/main", "refs/heads/release" } and aggregate.open-incidents == 0
    then deny "frozen"
  }
  default deny "no rule matched"
}"#;

/// The same policy with every independent order reversed.
const SHUFFLED: &str = r#"policy ordering {
  evidence deploy-approval { issuer forge.deploy }
  rule beta {
    when aggregate.open-incidents == 0 and ref.name in { "refs/heads/release", "refs/heads/main" }
    then deny "frozen"
  }
  aggregate queue-depth
  rule alpha {
    when evidence code-review and ref.update == create and ref.name matches "refs/heads/**"
    then allow
  }
  evidence code-review { issuer forge.review max_age 3600 }
  aggregate open-incidents
  default deny "no rule matched"
}"#;

#[test]
fn reordering_independent_declarations_does_not_change_the_snapshot() {
    let ordered = seal(ORDERED);
    let shuffled = seal(SHUFFLED);
    assert_eq!(ordered.policy(), shuffled.policy());
    assert_eq!(
        ordered.canonical_bytes().expect("ordered encodes"),
        shuffled.canonical_bytes().expect("shuffled encodes")
    );
    assert_eq!(ordered.id(), shuffled.id());
}

#[test]
fn a_material_change_does_change_the_snapshot() {
    // The permitted twin of the test above: if reordering left the identity
    // alone because the identity ignores content, this would pass too.
    let ordered = seal(ORDERED);
    let altered = seal(&ORDERED.replace(
        "aggregate.open-incidents == 0",
        "aggregate.open-incidents == 1",
    ));
    assert_ne!(ordered.policy(), altered.policy());
    assert_ne!(ordered.id(), altered.id());

    let renamed = seal(&ORDERED.replace("policy ordering", "policy ordering2"));
    assert_ne!(ordered.id(), renamed.id());

    let reason_changed = seal(&ORDERED.replace("\"frozen\"", "\"thawed\""));
    assert_ne!(ordered.id(), reason_changed.id());
}

#[test]
fn a_sealed_snapshot_round_trips_through_its_frame() {
    let sealed = seal(ORDERED);
    let frame = sealed.encode().expect("a sealed policy encodes");
    let decoded = PolicySnapshot::decode(&frame, DecodeLimits::DEFAULT).expect("its frame decodes");
    assert_eq!(decoded.policy(), sealed.policy());
    assert_eq!(decoded.id(), sealed.id());
    assert_eq!(
        decoded.encode().expect("the decoded policy re-encodes"),
        frame
    );
}
