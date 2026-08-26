#![forbid(unsafe_code)]
//! The tenant-shaped quota economy: scope hierarchy, the five admission
//! outcomes, deterministic fairness over queued contenders, and the abuse
//! skeleton (rate limiting plus reversible containment) that intake
//! surfaces evaluate before any staging happens.
pub mod abuse;
pub mod admission;
pub mod fairness;
pub mod hierarchy;
