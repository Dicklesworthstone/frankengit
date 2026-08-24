#![forbid(unsafe_code)]

//! The FG-041 proof bridge: the reference model's recorded histories, projected
//! onto the Lean model as test vectors.
//!
//! # What this crate is for
//!
//! FG-041c measured, and recorded on its bead, that **no refinement evidence
//! existed**: six `.fgtrace` goldens, zero Rust files referencing the Lean
//! model, and `OrderedResidue.lean:107` calling the bridge future work. A proof
//! about a model that nothing connects to the code is a proof about a model that
//! is free to drift. This crate is the connection.
//!
//! # The direction is code to model
//!
//! Every exported vector is a history the *reference model actually produced*,
//! projected onto the ordered residue. The claim it can support is that the
//! executable model's behaviour is admitted by the Lean model — bounded
//! refinement evidence over a finite corpus, not a proof and not an exhaustive
//! exploration. The claims registry must say exactly that and nothing stronger.
//!
//! # What it does not yet do, stated so nobody reads the artifact as more
//!
//! Delivery is staged, and this is stage one: the projection, the exporter and
//! the staleness gate. The Lean checker that replays these vectors against
//! `OrderedResidue.run` is stage two, and the claims rows gain a refinement
//! evidence class only when that checker runs. Adding the class first would make
//! the registry assert a bridge that still does not exist, which is the exact
//! inflation FG-041c refused.
//!
//! # Stated limits of the corpus
//!
//! The projection produces `sealRequest`, `decide`, `publish` and
//! `interruptedPublication`. It never produces `crash`, `lostResponse` or
//! `retry`: the reference model records cancellations rather than crashes, and
//! mapping one onto the other would assert a correspondence nothing checks. The
//! emitted batches also carry no ref or forge effect vectors, so these vectors
//! exercise the ordering and outcome theorems and **not**
//! `ref_and_forge_visibility_is_atomic`. Both are limits of the corpus, not of
//! the Lean model, and both are stated here rather than discovered later.

pub mod emit;
pub mod gate;
pub mod project;

pub use emit::render;
pub use gate::{ARTIFACT, BridgeRefusal, check, first_difference, write};
pub use project::{
    AbstractOp, AbstractOutcome, ProjectedStep, ProjectedTrace, ProjectionRefusal, project,
};

use std::path::Path;

/// Loads every checked-in golden and projects it.
///
/// The corpus is discovered by reading the directory rather than by a hard-coded
/// list, so a golden added by the reference model's own tests cannot be silently
/// omitted from the bridge. Names are sorted, which is what makes the rendered
/// artifact a pure function of the directory's contents rather than of the
/// filesystem's iteration order.
///
/// # Errors
///
/// A refusal naming the first golden that could not be read, decoded, or
/// projected.
pub fn project_corpus(goldens: &Path) -> Result<Vec<ProjectedTrace>, CorpusRefusal> {
    let mut names = Vec::new();
    let entries = std::fs::read_dir(goldens).map_err(|error| CorpusRefusal::Unreadable {
        message: error.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| CorpusRefusal::Unreadable {
            message: error.to_string(),
        })?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "fgtrace")
            && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
        {
            names.push((stem.to_owned(), path));
        }
    }
    names.sort();

    let mut projected = Vec::with_capacity(names.len());
    for (name, path) in names {
        let bytes = std::fs::read(&path).map_err(|error| CorpusRefusal::Unreadable {
            message: error.to_string(),
        })?;
        let trace =
            fgit_reference::trace::decode(&bytes).map_err(|error| CorpusRefusal::Undecodable {
                golden: name.clone(),
                message: format!("{error:?}"),
            })?;
        projected.push(
            project(&name, &trace).map_err(|refusal| CorpusRefusal::Unprojectable {
                golden: name.clone(),
                refusal,
            })?,
        );
    }
    Ok(projected)
}

/// Why the corpus could not be projected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorpusRefusal {
    /// The golden directory or one of its files could not be read.
    Unreadable {
        /// What the filesystem said.
        message: String,
    },
    /// A golden's bytes are not a decodable trace.
    Undecodable {
        /// Which golden.
        golden: String,
        /// What the codec said.
        message: String,
    },
    /// A golden decoded but could not be projected.
    Unprojectable {
        /// Which golden.
        golden: String,
        /// Why.
        refusal: ProjectionRefusal,
    },
}
