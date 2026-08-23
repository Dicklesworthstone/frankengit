# FG-041 ordered-residue proof assumptions

The Lean development proves properties of the explicit state machine in
`OrderedResidue.lean`.  It does not claim that a proof of that model is a
proof of every Rust implementation.  The following external assumptions are
named at the model boundary and have concrete empirical gates.

| Lean boundary name | Meaning | Empirical gate | Limit |
|---|---|---|---|
| `authority_store_linearizable_cas` | A successful authority compare-and-swap has one linearization point and only accepts the exact predecessor/version. | `crates/fgit-authority-fsqlite/tests/engine_conformance.rs::fg004_history_checker_accepts_a_recorded_fsqlite_authority_history` and `::the_unchanged_fg004_conformance_suite_passes_against_the_engine` | These are finite conformance histories, not a universal proof of a storage engine. |
| `crash_retry_history_is_observed` | A client with a lost response resolves through the recorded authority/outcome history rather than inferring non-commit from cancellation. | `crates/fgit-authority-fsqlite/tests/fault_conformance.rs::fault_conformance_covers_every_declared_cell` | The gate exercises declared fault cells; it does not quantify over all failures. |
| `publication_epochs_preserve_authenticated_head` | Interrupted publication leaves the last authenticated visible head intact; visibility and durability are separate. | `crates/fgit-authority-fsqlite/tests/publication_epochs.rs` | This is backend evidence for its declared profile, not a durable-acknowledgement proof. |

The model has no ambient authority path, mutable accelerator, or partial
ref/forge projection.  That is intentional: the five theorems are only about
the ordered residue.  Trace-refinement and the differential bridge remain
open work in `fg041c`; no theorem here upgrades the Rust implementation to a
proof claim.
