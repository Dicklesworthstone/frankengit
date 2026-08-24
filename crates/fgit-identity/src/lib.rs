#![forbid(unsafe_code)]
//! Identity: principals, organisations, teams, and the credentials bound to
//! them.
//!
//! # What this crate is
//!
//! The identity model for FG-042. It owns:
//!
//! * [`deploy_key`] — a key identity bound to exactly one repository, with the
//!   scopes it may exercise there;
//! * [`token`] — a bounded, revocable, audience-bound grant to act as a
//!   principal, whose high-impact operations cannot be authorised without
//!   revocation evidence.
//!
//! Organisation and team aggregates and sessions land here as their
//! modules are completed under bead `frankengit-fg042a-identity-model-cas`.
//! Each is named above when its module is real, never before — and equally,
//! each is added the moment it IS real. The inverse mistake, a list that keeps
//! describing delivered work as pending, is what `frankengit-wirh` had to
//! correct in a sibling crate, so this list is maintained in both directions.
//!
//! # What this crate is not
//!
//! It is not a key authority and holds no key material. Keys are named by
//! digest here; the purpose-marker keys in `fgit-crypto` (`KeyPurposeMarker`)
//! remain the only place a key is minted or verified. A credential record that
//! could also mint the credential it describes would be a second authority for
//! the same thing.
//!
//! It does not admit. Identity aggregates are published as forge events on the
//! `fgit-forge` machinery, and admission is L4: this crate computes, records
//! and refuses, then hands the result upward.
//!
//! # Load-bearing invariants
//!
//! * A credential names the repository it is bound to, and authorization checks
//!   the binding as well as the scope. A scope that matches on the wrong
//!   repository is refused.
//! * Capabilities are never implied. `Write` does not confer `Read`; each is
//!   granted explicitly or not at all.
//! * A grant that permits nothing is refused rather than stored, so
//!   "registered" and "may do nothing" can never be the same state.

pub mod deploy_key;
pub mod token;

pub use deploy_key::{DeployKeyBinding, DeployKeyRefusal, DeployKeyScope};
pub use token::{RevocationEvidence, TokenGrant, TokenHandle, TokenOperation, TokenRefusal};
