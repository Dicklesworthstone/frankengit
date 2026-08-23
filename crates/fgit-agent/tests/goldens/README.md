# The Evidence-Carrying Change golden corpus

10 files: 2 valid vectors and 8 planted defects. Each carries the canonical
frame bytes as hex, the frame and payload lengths, and for a defect the
refusal it must produce.

## The property that makes this corpus worth having

The bytes were produced by `generate.py`, a separate implementation in another
language that reads the two documented layout tables — the frame table at the
top of `crates/fgit-codec/src/wire.rs` and the ECC payload table on
`impl CanonicalBody for EvidenceCarryingChange` in
`crates/fgit-agent/src/ecc.rs`. It cannot link a Rust crate, nothing in the
Rust tests invokes it, and the suite only ever reads the committed files.

## How far that independence actually reaches — read this before citing it

This corpus is **weaker** than the one under `crates/fgit-codec/tests/goldens/`,
and it must not borrow that corpus's claim.

There, the format was specified before the corpus existed and the generator was
written from the specification. Here, the same author wrote the Rust encoder,
the layout table, and the Python generator, in that order. So:

* It **does** catch the Rust encoder drifting from its documented table — a
  reordered field, a changed code point, a dropped option tag, a sequence that
  stops encoding its empty slots. That is the failure that actually happens,
  and it is why the table is the thing the generator reads rather than the
  code.
* It **does** catch `read_payload` and `write_payload` drifting apart, because
  the corpus is decoded and re-encoded rather than round-tripped in memory.
* It does **not** establish that the layout table is right. If the table is
  wrong, both implementations reproduce the same mistake and agree perfectly.
* It does **not** check body identity. The codec corpus records a `body_id` per
  vector; deriving one here would mean reimplementing `fgit-crypto`'s preimage
  in Python, and a `body_id` copied out of the Rust implementation would be the
  implementation confirming itself — exactly what this corpus exists not to be.
  Identity is checked in `fgit-codec`'s own suite, not here. This corpus proves
  bytes, not identity.

## Rules

Do not add a Rust regeneration helper, do not let `generate.py` import or shell
out to any first-party crate, and do not wire it into `cargo`. If a vector
fails, the encoder is wrong until proven otherwise; regenerating the corpus to
make a red suite green is golden regeneration (RH-3) and is forbidden by
AGENTS.md §16.3.

Regenerating is a deliberate act: run `python3 generate.py` from anywhere, diff
the result, and say in the commit message which layout changed and why.
