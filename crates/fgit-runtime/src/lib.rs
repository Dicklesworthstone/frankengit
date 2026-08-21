#![forbid(unsafe_code)]
//! FrankenGit's Asupersync runtime profile.
//!
//! This crate is the single place where FrankenGit decides *how* it runs on
//! the one admitted runtime. It does not wrap Asupersync or hide its
//! semantics: budgets, contexts, outcomes, scopes, and obligations stay
//! Asupersync types with Asupersync meanings. What lives here is the policy
//! layer the integration profile requires on top of them —
//!
//! - [`meter`]: the budget classes, their finite defaults, and the child
//!   derivation rule that refuses widening instead of silently clamping it;
//! - [`grant`]: capability narrowing across both the runtime capability mask
//!   and FrankenGit's own repository authority set;
//! - [`obligations`]: the obligation-leak policy admissible for each profile
//!   class, with `Silent` and bare `Log` refused;
//! - [`boot`]: the named runtime profile inputs, the evidence-safe profile
//!   identity, and the production context factory;
//! - [`topology`]: the node service graph, its deterministic start order, and
//!   the dependency-ordered shutdown sequence;
//! - [`adapter`]: the service boundary that keeps all four
//!   [`asupersync::Outcome`] arms distinct;
//! - [`demo`]: one real service exercising the whole path.
//!
//! # Production context creation
//!
//! Production contexts come from the owning runtime through
//! [`boot::NodeRuntime::request_cx`] / [`boot::NodeRuntime::try_request_cx`],
//! which delegate to Asupersync's
//! [`request_cx_with_budget`](asupersync::runtime::Runtime::request_cx_with_budget)
//! and
//! [`try_request_cx_with_budget`](asupersync::runtime::RuntimeHandle::try_request_cx_with_budget).
//! Test-only or detached constructors are not production entry points and do
//! not appear anywhere in this crate's non-test sources; `no_test_only_cx`
//! in `tests/` enforces that mechanically.
//!
//! # Non-claims
//!
//! This crate does not claim a tree-wide compiled-supervisor restart contract.
//! Asupersync proves live restart per actor; higher-level restart and
//! dependency ordering are explicit here — [`topology`] computes and exposes
//! the orders, and the node applies them — rather than asserted as an
//! upstream guarantee.

pub mod adapter;
pub mod boot;
pub mod demo;
pub mod grant;
pub mod meter;
pub mod obligations;
pub mod refuse;
pub mod topology;

pub use adapter::{CommitAmbiguity, OutcomeClass, ServiceOutcome};
pub use boot::{NodeRuntime, ProfileClass, ProfileIdentity, RuntimeProfile};
pub use grant::{AuthorityCapability, AuthoritySet, CapabilityProfile, Ownership};
pub use meter::{BudgetClass, BudgetPolicy, ClassLimits, derive_child};
pub use obligations::{LeakControls, LeakPolicy, RecoverySinks};
pub use refuse::{BudgetDimension, Exhaustion, RuntimeRefusal, TopologyDefect};
pub use topology::{
    NodeSpec, ServiceSpec, ShutdownDriver, ShutdownPhase, ShutdownReceipt, StartPlan,
};
