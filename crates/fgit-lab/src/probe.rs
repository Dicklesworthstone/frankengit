//! Named failpoints, declared up front and reported on honestly.
//!
//! The bead's requirement is that the registry be *enumerable* and that a
//! campaign be able to prove which declared points it exercised. Those two
//! together are what stop "we ran ten thousand schedules" from being offered
//! as coverage: ten thousand runs that never reached the crash-after-CAS point
//! say nothing about crash-after-CAS, and the registry is what makes that
//! visible instead of arguable.
//!
//! So a failpoint must be declared before it can be armed or hit, the set of
//! declared points is enumerable in sorted order, and
//! [`FailpointRegistry::require_full_coverage`] refuses a completeness claim
//! that leaves declared points untouched.

use std::collections::BTreeMap;

use crate::refuse::LabRefusal;

/// A failpoint's stable name.
///
/// Names are hierarchical by convention (`authority.cas.after_effect`), which
/// keeps a campaign's report readable and lets a filter select a subtree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailpointId(String);

impl FailpointId {
    /// Name a failpoint.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this point sits under `prefix` in the dotted hierarchy.
    #[must_use]
    pub fn is_under(&self, prefix: &str) -> bool {
        self.0 == prefix
            || (self.0.starts_with(prefix) && self.0.as_bytes().get(prefix.len()) == Some(&b'.'))
    }
}

impl core::fmt::Display for FailpointId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the registry knows about one declared point.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Point {
    description: String,
    armed: bool,
    hits: u64,
}

/// The declared failpoints for a campaign, and what it actually exercised.
///
/// Ordering is by name throughout (`BTreeMap`), so enumeration and reports are
/// stable across runs — a report that reordered itself run to run could not be
/// diffed, which is most of what a report is for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FailpointRegistry {
    points: BTreeMap<FailpointId, Point>,
}

impl FailpointRegistry {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            points: BTreeMap::new(),
        }
    }

    /// Declare a failpoint.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::FailpointRedeclared`] if the name is already declared.
    /// Silently accepting a redeclaration would let two subsystems share a
    /// name and each believe it owned the point.
    pub fn declare(
        &mut self,
        id: FailpointId,
        description: impl Into<String>,
    ) -> Result<(), LabRefusal> {
        if self.points.contains_key(&id) {
            return Err(LabRefusal::FailpointRedeclared { name: id.0 });
        }
        self.points.insert(
            id,
            Point {
                description: description.into(),
                armed: false,
                hits: 0,
            },
        );
        Ok(())
    }

    /// Every declared point, in name order.
    #[must_use]
    pub fn declared(&self) -> Vec<FailpointId> {
        self.points.keys().cloned().collect()
    }

    /// How many points are declared.
    #[must_use]
    pub fn len(&self) -> usize {
        self.points.len()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// A point's description.
    #[must_use]
    pub fn description(&self, id: &FailpointId) -> Option<&str> {
        self.points.get(id).map(|point| point.description.as_str())
    }

    /// Arm a declared point so [`should_fire`](Self::should_fire) returns true.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::FailpointUndeclared`] for an unknown name.
    pub fn arm(&mut self, id: &FailpointId) -> Result<(), LabRefusal> {
        match self.points.get_mut(id) {
            Some(point) => {
                point.armed = true;
                Ok(())
            }
            None => Err(LabRefusal::FailpointUndeclared { name: id.0.clone() }),
        }
    }

    /// Disarm a declared point.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::FailpointUndeclared`] for an unknown name.
    pub fn disarm(&mut self, id: &FailpointId) -> Result<(), LabRefusal> {
        match self.points.get_mut(id) {
            Some(point) => {
                point.armed = false;
                Ok(())
            }
            None => Err(LabRefusal::FailpointUndeclared { name: id.0.clone() }),
        }
    }

    /// Whether a point is currently armed.
    #[must_use]
    pub fn is_armed(&self, id: &FailpointId) -> bool {
        self.points.get(id).is_some_and(|point| point.armed)
    }

    /// Record that execution reached a point, and report whether it fires.
    ///
    /// Reaching a point counts as exercising it whether or not it was armed:
    /// a campaign that proved it can *reach* crash-after-CAS has learned
    /// something real even on the pass where it chose not to crash there.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::FailpointUndeclared`] for an unknown name.
    pub fn should_fire(&mut self, id: &FailpointId) -> Result<bool, LabRefusal> {
        match self.points.get_mut(id) {
            Some(point) => {
                point.hits = point.hits.saturating_add(1);
                Ok(point.armed)
            }
            None => Err(LabRefusal::FailpointUndeclared { name: id.0.clone() }),
        }
    }

    /// How many times a point was reached.
    #[must_use]
    pub fn hits(&self, id: &FailpointId) -> u64 {
        self.points.get(id).map_or(0, |point| point.hits)
    }

    /// The coverage report for this campaign.
    #[must_use]
    pub fn coverage(&self) -> CoverageReport {
        let mut exercised = Vec::new();
        let mut unexercised = Vec::new();
        for (id, point) in &self.points {
            if point.hits > 0 {
                exercised.push((id.clone(), point.hits));
            } else {
                unexercised.push(id.clone());
            }
        }
        CoverageReport {
            exercised,
            unexercised,
        }
    }

    /// Refuse a completeness claim that left declared points untouched.
    ///
    /// # Errors
    ///
    /// [`LabRefusal::FailpointsUnexercised`] listing the untouched names.
    pub fn require_full_coverage(&self) -> Result<CoverageReport, LabRefusal> {
        let report = self.coverage();
        if report.unexercised.is_empty() {
            Ok(report)
        } else {
            Err(LabRefusal::FailpointsUnexercised {
                unexercised: report.unexercised.iter().map(|id| id.0.clone()).collect(),
            })
        }
    }
}

/// Which declared points a campaign exercised, and which it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    exercised: Vec<(FailpointId, u64)>,
    unexercised: Vec<FailpointId>,
}

impl CoverageReport {
    /// Points that were reached, with hit counts, in name order.
    #[must_use]
    pub fn exercised(&self) -> &[(FailpointId, u64)] {
        &self.exercised
    }

    /// Points that were declared but never reached, in name order.
    #[must_use]
    pub fn unexercised(&self) -> &[FailpointId] {
        &self.unexercised
    }

    /// Declared point count.
    #[must_use]
    pub const fn declared_count(&self) -> usize {
        self.exercised.len() + self.unexercised.len()
    }

    /// Whether every declared point was reached.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.unexercised.is_empty()
    }

    /// A canonical, stable, single-line rendering for a campaign report.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        let mut parts = vec![
            "fgit-lab-coverage-v1".to_owned(),
            format!("declared={}", self.declared_count()),
            format!("exercised={}", self.exercised.len()),
            format!("unexercised={}", self.unexercised.len()),
        ];
        for (id, hits) in &self.exercised {
            parts.push(format!("hit:{id}={hits}"));
        }
        for id in &self.unexercised {
            parts.push(format!("miss:{id}"));
        }
        parts.join("|")
    }
}

/// Reject a stress count offered where a coverage claim is required.
///
/// This exists as a callable refusal rather than a convention because "we ran
/// it a lot" is the single most common substitute for evidence, and a campaign
/// API that quietly accepts a run count teaches people to keep offering one.
///
/// # Errors
///
/// Always [`LabRefusal::StressIsNotCoverage`].
pub const fn refuse_stress_as_coverage(runs: u64) -> Result<(), LabRefusal> {
    Err(LabRefusal::StressIsNotCoverage { runs })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> FailpointRegistry {
        let mut registry = FailpointRegistry::new();
        registry
            .declare(
                FailpointId::new("authority.cas.after_effect"),
                "endpoint dies after the head CAS applied",
            )
            .expect("first declaration");
        registry
            .declare(
                FailpointId::new("authority.put.before_effect"),
                "request lost before the immutable body is written",
            )
            .expect("first declaration");
        registry
            .declare(
                FailpointId::new("packet.sideband.truncate"),
                "sideband frame truncated mid-payload",
            )
            .expect("first declaration");
        registry
    }

    #[test]
    fn declared_points_enumerate_in_name_order() {
        let registry = registry();
        assert_eq!(
            registry.declared(),
            vec![
                FailpointId::new("authority.cas.after_effect"),
                FailpointId::new("authority.put.before_effect"),
                FailpointId::new("packet.sideband.truncate"),
            ]
        );
        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());
        assert_eq!(
            registry.description(&FailpointId::new("packet.sideband.truncate")),
            Some("sideband frame truncated mid-payload")
        );
    }

    #[test]
    fn redeclaring_a_name_is_refused() {
        let mut registry = registry();
        let refusal = registry
            .declare(
                FailpointId::new("packet.sideband.truncate"),
                "something else",
            )
            .expect_err("a name may only be declared once");
        assert_eq!(
            refusal,
            LabRefusal::FailpointRedeclared {
                name: "packet.sideband.truncate".to_owned()
            }
        );

        // Paired permitted case: a fresh name declares fine.
        registry
            .declare(
                FailpointId::new("packet.sideband.reorder"),
                "frames reordered",
            )
            .expect("a new name is permitted");
        assert_eq!(registry.len(), 4);
    }

    #[test]
    fn an_undeclared_point_cannot_be_armed_or_hit() {
        let mut registry = registry();
        let unknown = FailpointId::new("storage.not.declared");

        assert_eq!(
            registry.arm(&unknown).expect_err("arm must refuse"),
            LabRefusal::FailpointUndeclared {
                name: "storage.not.declared".to_owned()
            }
        );
        assert_eq!(
            registry.should_fire(&unknown).expect_err("hit must refuse"),
            LabRefusal::FailpointUndeclared {
                name: "storage.not.declared".to_owned()
            }
        );

        // Paired permitted case: the same operations on a declared point.
        let known = FailpointId::new("authority.cas.after_effect");
        registry.arm(&known).expect("declared points arm");
        assert!(registry.should_fire(&known).expect("declared points fire"));
    }

    #[test]
    fn only_armed_points_fire_but_every_reach_counts_as_exercised() {
        let mut registry = registry();
        let point = FailpointId::new("authority.put.before_effect");

        // Reached while disarmed: does not fire, but is exercised.
        assert!(!registry.should_fire(&point).expect("declared"));
        assert!(!registry.is_armed(&point));
        assert_eq!(registry.hits(&point), 1);

        registry.arm(&point).expect("declared");
        assert!(registry.is_armed(&point));
        assert!(registry.should_fire(&point).expect("declared"));
        assert_eq!(registry.hits(&point), 2);

        registry.disarm(&point).expect("declared");
        assert!(!registry.should_fire(&point).expect("declared"));
        assert_eq!(registry.hits(&point), 3);
    }

    #[test]
    fn a_campaign_that_misses_declared_points_cannot_claim_completeness() {
        let mut registry = registry();
        // Exercise only one of the three declared points.
        registry
            .should_fire(&FailpointId::new("authority.cas.after_effect"))
            .expect("declared");

        let refusal = registry
            .require_full_coverage()
            .expect_err("two points were never reached");
        assert_eq!(
            refusal,
            LabRefusal::FailpointsUnexercised {
                unexercised: vec![
                    "authority.put.before_effect".to_owned(),
                    "packet.sideband.truncate".to_owned(),
                ]
            }
        );

        let report = registry.coverage();
        assert!(!report.is_complete());
        assert_eq!(report.declared_count(), 3);
        assert_eq!(report.exercised().len(), 1);
        assert_eq!(report.unexercised().len(), 2);
    }

    #[test]
    fn a_campaign_that_reaches_every_declared_point_is_accepted() {
        // The near-identical permitted twin of the refusal above.
        let mut registry = registry();
        for id in registry.declared() {
            registry.should_fire(&id).expect("declared");
        }

        let report = registry
            .require_full_coverage()
            .expect("every declared point was reached");
        assert!(report.is_complete());
        assert_eq!(report.exercised().len(), 3);
        assert!(
            report.unexercised().is_empty(),
            "every declared point was reached, yet these are unexercised: {:?}",
            report.unexercised()
        );
    }

    #[test]
    fn the_coverage_line_is_canonical_and_names_misses_explicitly() {
        let mut registry = registry();
        registry
            .should_fire(&FailpointId::new("authority.cas.after_effect"))
            .expect("declared");
        registry
            .should_fire(&FailpointId::new("authority.cas.after_effect"))
            .expect("declared");

        let line = registry.coverage().canonical_line();
        assert!(line.starts_with("fgit-lab-coverage-v1"));
        assert!(line.contains("|declared=3|exercised=1|unexercised=2"));
        assert!(line.contains("|hit:authority.cas.after_effect=2"));
        assert!(line.contains("|miss:authority.put.before_effect"));
        assert!(line.contains("|miss:packet.sideband.truncate"));

        // Stable across repeated renderings.
        assert_eq!(line, registry.coverage().canonical_line());
    }

    #[test]
    fn a_stress_count_is_never_accepted_as_coverage() {
        let refusal =
            refuse_stress_as_coverage(10_000).expect_err("a run count is not a coverage claim");
        assert_eq!(refusal, LabRefusal::StressIsNotCoverage { runs: 10_000 });
        assert!(!refusal.indicts_subject());

        // Paired permitted case: the real claim shape is a coverage report.
        let mut registry = registry();
        for id in registry.declared() {
            registry.should_fire(&id).expect("declared");
        }
        registry
            .require_full_coverage()
            .expect("a coverage report is the accepted claim");
    }

    #[test]
    fn hierarchical_names_select_by_subtree() {
        let id = FailpointId::new("authority.cas.after_effect");
        assert!(id.is_under("authority"));
        assert!(id.is_under("authority.cas"));
        assert!(id.is_under("authority.cas.after_effect"));
        // A prefix that is not a dotted boundary must not match.
        assert!(!id.is_under("auth"));
        assert!(!id.is_under("authority.ca"));
        assert!(!id.is_under("packet"));
    }
}
