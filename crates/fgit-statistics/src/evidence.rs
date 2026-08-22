//! The typed statistical evidence body: section 8's seven bindings, as types.
//!
//! `AGENTS.md` section 8 states the obligation in one sentence — statistical
//! evidence binds population, selection, exact sequence window, regime,
//! candidate/fallback, assumptions, and implementation/toolchain fingerprint.
//!
//! Prose cannot hold those seven. Neither can a struct of seven public strings
//! with no constructor discipline: it is a bag a caller fills in as far as is
//! convenient, and the failure mode is not a compile error but evidence that
//! still *looks* like evidence while no longer being falsifiable — a window
//! nobody measured, a regime nobody established, an assumption set nobody
//! filled in. Every one of those reads as a valid record downstream.
//!
//! So each binding is a type here, several refuse their own invalid values at
//! construction, and there is deliberately no `Default`: a body cannot be built
//! without an answer for all seven.
//!
//! # Why the selection is carried rather than recomputed
//!
//! [`PolicySelection`] is stored, not recomputed at read time. Recomputing it
//! would answer "what would this build decide now", where the evidence question
//! is "what did the run decide, and why". Those diverge exactly when it matters
//! — after the gate's inputs have moved on — and the second is the one section 8
//! requires to be replayable.
//!
//! # What this module deliberately does not do
//!
//! It defines no `identity()`. Computing one means calling
//! `fgit_crypto::internal_object_id_for_tag`, which refuses any [`DomainTag`]
//! absent from that crate's `DOMAIN_REGISTRY` — correctly, since an identity
//! under an unregistered domain is one nothing else could verify. Registering
//! `frankengit/statistical-evidence/v1` is an edit to `fgit-crypto`, another
//! crate's frozen public surface, and section 16.1 routes that through its owner
//! by mail rather than through a sibling reaching in. The canonical bytes below
//! are complete and testable without it; only the digest commitment waits.

use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{AsciiSlug, Digest, DomainTag, SchemaFamily};

use crate::fallback::{FallbackTrigger, PolicySelection};
use crate::regime::{Cusum, Scaled};

/// Why a binding could not be constructed.
///
/// Each variant names a value that would make the evidence unfalsifiable rather
/// than merely untidy, which is the line section 8 draws.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingRefusal {
    /// `last < first`: a window that ends before it begins covers nothing, so
    /// any claim made "over" it is vacuous.
    WindowInverted {
        /// First sequence number offered.
        first: u64,
        /// Last sequence number offered.
        last: u64,
    },
    /// No assumption was declared.
    ///
    /// An empty set is indistinguishable from a field nobody filled in, and a
    /// statistical mechanism with genuinely no assumptions does not exist. The
    /// honest minimum is to name one.
    AssumptionsEmpty,
    /// The same assumption was declared twice.
    ///
    /// Refused at construction rather than at encode time so the caller learns
    /// it where the mistake was made.
    AssumptionDuplicated {
        /// The repeated label.
        label: AsciiSlug,
    },
}

/// Section 8 binding 3: the exact sequence window the evidence covers.
///
/// Inclusive on both ends, and the fields are private because "exact" is a
/// property this type enforces rather than one the caller promises.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SequenceWindow {
    first: u64,
    last: u64,
}

impl SequenceWindow {
    /// Builds an inclusive window.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRefusal::WindowInverted`] when `last < first`.
    pub const fn try_new(first: u64, last: u64) -> Result<Self, BindingRefusal> {
        if last < first {
            return Err(BindingRefusal::WindowInverted { first, last });
        }
        Ok(Self { first, last })
    }

    /// First sequence number covered.
    #[must_use]
    pub const fn first(self) -> u64 {
        self.first
    }

    /// Last sequence number covered, inclusive.
    #[must_use]
    pub const fn last(self) -> u64 {
        self.last
    }

    /// How many sequence positions the window covers.
    ///
    /// Never zero: the inclusive bounds and the ordering check together make
    /// the smallest representable window one position wide.
    #[must_use]
    pub const fn len(self) -> u64 {
        // `last >= first` is an invariant, so this cannot wrap, and the `+ 1` is
        // saturating only to keep a `u64::MAX`-wide window from overflowing.
        (self.last - self.first).saturating_add(1)
    }
}

/// Section 8 binding 4: which regime, and the detector state that established it.
///
/// The detector state travels with the epoch on purpose. An epoch alone is an
/// assertion; the accumulators are the evidence for it, and section 8 requires
/// the decision path of anything affecting a decision to be reproducible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegimeBinding {
    /// The regime epoch the observations were gathered under.
    pub epoch: u64,
    /// The upward accumulator when the evidence was bound.
    pub detector_high: Scaled,
    /// The downward accumulator when the evidence was bound.
    pub detector_low: Scaled,
    /// Observations the detector had absorbed.
    pub observations: u32,
    /// Whether an accumulator had saturated and so lost excursion magnitude.
    pub saturated: bool,
}

impl RegimeBinding {
    /// Reads the binding straight off a detector, so the two cannot disagree.
    #[must_use]
    pub const fn from_detector(epoch: u64, detector: &Cusum) -> Self {
        Self {
            epoch,
            detector_high: detector.high(),
            detector_low: detector.low(),
            observations: detector.observations(),
            saturated: detector.saturated(),
        }
    }
}

/// Section 8 binding 6: the assumptions checked for this evidence.
///
/// Held sorted and duplicate-free so the canonical bytes do not depend on the
/// order the caller happened to collect them in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssumptionSet {
    checked: Vec<AsciiSlug>,
}

impl AssumptionSet {
    /// Builds an assumption set, sorting it into canonical order.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRefusal::AssumptionsEmpty`] for an empty set, or
    /// [`BindingRefusal::AssumptionDuplicated`] when a label repeats.
    pub fn try_new(mut checked: Vec<AsciiSlug>) -> Result<Self, BindingRefusal> {
        if checked.is_empty() {
            return Err(BindingRefusal::AssumptionsEmpty);
        }
        checked.sort_unstable();
        for window in checked.windows(2) {
            if window[0] == window[1] {
                return Err(BindingRefusal::AssumptionDuplicated {
                    label: window[0].clone(),
                });
            }
        }
        Ok(Self { checked })
    }

    /// The assumptions, in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[AsciiSlug] {
        &self.checked
    }

    /// How many assumptions were declared. Never zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.checked.len()
    }

    /// Always false; present because clippy asks for it beside [`Self::len`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.checked.is_empty()
    }
}

/// The wire tag for [`PolicySelection::Candidate`].
const POLICY_TAG_CANDIDATE: u8 = 0;

/// Encodes a selection as one tag byte.
///
/// `0` is the candidate; `1..=5` are the fallback triggers in
/// [`FallbackTrigger::ALL`] order, offset by one so that no trigger shares the
/// candidate's tag.
const fn policy_tag(selection: PolicySelection) -> u8 {
    match selection {
        PolicySelection::Candidate => POLICY_TAG_CANDIDATE,
        PolicySelection::Fallback(trigger) => match trigger {
            FallbackTrigger::EvidenceGap => 1,
            FallbackTrigger::SupportFailure => 2,
            FallbackTrigger::RegimeAlarm => 3,
            FallbackTrigger::NumericBoundViolation => 4,
            FallbackTrigger::StaleWindow => 5,
        },
    }
}

/// Decodes a selection tag, refusing any byte that is not a defined tag.
///
/// The refusal is the point. Decoding an unrecognised tag as
/// [`PolicySelection::Candidate`] — the obvious "be liberal in what you accept"
/// reading — would let a corrupted or forward-versioned byte silently *admit*
/// adaptation, which is the one direction section 33's fail-closed rule forbids.
/// A byte this build does not understand is a refusal.
fn policy_from_tag(tag: u8, offset: u64) -> Result<PolicySelection, CodecRefusal> {
    if tag == POLICY_TAG_CANDIDATE {
        return Ok(PolicySelection::Candidate);
    }
    let index = usize::from(tag - 1);
    FallbackTrigger::ALL
        .get(index)
        .copied()
        .map(PolicySelection::Fallback)
        .ok_or(CodecRefusal::VariantUnknown {
            field: "policy",
            observed: u32::from(tag),
            offset,
        })
}

/// One statistical claim, with all seven of section 8's bindings present.
///
/// Field order here is section 8's own order, and [`CanonicalBody::write_payload`]
/// follows it, so the canonical bytes can be read against the sentence that
/// requires them.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatisticalEvidenceBody {
    /// Binding 1: the population the observations were drawn from.
    pub population: AsciiSlug,
    /// Binding 2: the policy by which units entered the sample.
    pub selection: AsciiSlug,
    /// Binding 3: the exact sequence window covered.
    pub window: SequenceWindow,
    /// Binding 4: the regime, with the detector state that established it.
    pub regime: RegimeBinding,
    /// Binding 5: whether the candidate ran or a fallback was selected, and why.
    pub policy: PolicySelection,
    /// Binding 6: the assumptions checked.
    pub assumptions: AssumptionSet,
    /// Binding 7: the implementation and toolchain fingerprint the numbers were
    /// produced under.
    pub fingerprint: Digest,
}

impl CanonicalBody for StatisticalEvidenceBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/statistical-evidence/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("statistical-evidence");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_bytes("population", self.population.as_bytes())?;
        out.write_bytes("selection", self.selection.as_bytes())?;
        out.write_scalar(self.window.first());
        out.write_scalar(self.window.last());
        out.write_scalar(self.regime.epoch);
        out.write_scalar(self.regime.detector_high);
        out.write_scalar(self.regime.detector_low);
        out.write_scalar(self.regime.observations);
        out.write_bool(self.regime.saturated);
        out.write_scalar(policy_tag(self.policy));
        out.write_canonical_set(
            "assumptions",
            self.assumptions.as_slice(),
            |scratch, label| scratch.write_bytes("assumption", label.as_bytes()),
        )?;
        out.write_digest(&self.fingerprint)?;
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let population = AsciiSlug::try_new("population", input.read_bytes("population")?)?;
        let selection = AsciiSlug::try_new("selection", input.read_bytes("selection")?)?;
        let first = input.read_scalar::<u64>("window_first")?;
        let last = input.read_scalar::<u64>("window_last")?;
        let window = SequenceWindow::try_new(first, last).map_err(|_| {
            // An inverted window on the wire is a value this build cannot
            // represent, not a value it should quietly repair by swapping the
            // ends: the bytes were signed over as written.
            CodecRefusal::ValueUnrepresentable {
                field: "window",
                observed: first,
                limit: last,
            }
        })?;
        let regime = RegimeBinding {
            epoch: input.read_scalar::<u64>("regime_epoch")?,
            detector_high: input.read_scalar::<i64>("detector_high")?,
            detector_low: input.read_scalar::<i64>("detector_low")?,
            observations: input.read_scalar::<u32>("observations")?,
            saturated: input.read_bool("saturated")?,
        };
        let policy_offset = input.offset();
        let policy = policy_from_tag(input.read_scalar::<u8>("policy")?, policy_offset)?;
        let assumptions = input.read_canonical_set("assumptions", |scratch| {
            AsciiSlug::try_new("assumption", scratch.read_bytes("assumption")?)
                .map_err(CodecRefusal::from)
        })?;
        let assumptions = AssumptionSet::try_new(assumptions).map_err(|_| {
            // read_canonical_set already refused duplicates and disorder, so the
            // only reachable failure is an empty set.
            CodecRefusal::CountBoundExceeded {
                field: "assumptions",
                observed: 0,
                limit: 1,
            }
        })?;
        let fingerprint = input.read_digest()?;
        Ok(Self {
            population,
            selection,
            window,
            regime,
            policy,
            assumptions,
            fingerprint,
        })
    }
}
