#![forbid(unsafe_code)]
//! Immutable, position-bound graph generations and deterministic exact graph algorithms.
//!
//! This crate owns the graph half of the generation contract shared with search:
//! a generation body is immutable, activation is an authority-head CAS against
//! its exact predecessor, and an unresolved CAS is never interpreted as a
//! negative result.  The algorithm surface is deliberately bounded and uses
//! sorted maps/sets for every observable choice, so no result or witness can
//! depend on hash-table or scheduler order.

mod algorithms;
mod generation;

pub use crate::algorithms::{
    ArticulationBridgeReport, BipartiteMatching, ComplexityTerm, CriticalPath, DeterministicGraph,
    GraphAlgorithm, GraphBuilder, GraphBuilderError, GraphDecision, GraphDecisionWitness,
    GraphEdge, GraphLimits, GraphNodeId, GraphQuery, GraphRefusal, GraphResult, GraphSnapshot,
    GraphViewPolicy, MinimumCut, Reachability, StronglyConnectedComponents, TopologicalOrder,
};
pub use crate::generation::{
    BuilderProfileId, ExactGraphGeneration, GenerationActivation, GenerationAuthority,
    GenerationAuthorityError, GraphAuthorityClass, GraphAuthorityClassRefusal, GraphGenerationBody,
    GraphGenerationId, GraphSchemaId, GraphSourceStamp, GraphViewId,
};
