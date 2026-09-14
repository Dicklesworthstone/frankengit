# Native branch-target integrity

The native Git object kind of a ref root is part of intake validation. A direct
`refs/heads/*` target must be a commit, not a blob, tree, or annotated tag that
can eventually be peeled to a commit. Other namespaces may name any native
object kind. This is independent of fast-forward, force, review protection,
signatures, or access policy. Ref-name parsing remains with the existing readers.

## Shared semantic boundary

`fgit-git-object::required_ref_target_kind` owns the exact raw-byte namespace
predicate. It recognizes only the slash-terminated, case-sensitive branch
prefix. It neither reads objects nor authorizes their disclosure. Its companion
`validate_reference_target_kind` reports a typed mismatch without embedding
private ref names or object IDs in the error text.

The local-source importer retains each ref's required root kind rather than
collapsing the input immediately to untyped object IDs. Aliases strengthen the
same object's constraints regardless of enumeration order. Loose, packed, and
mixed sources retain the existing native identity verification, whole-graph
validation, unique-object accounting, byte/work ceilings, and sticky cancellation.
A valid tagged commit is not substituted for a tag stored directly in a branch.
No object is staged until the entire selected import graph passes.

Ordinary receive-pack and complete-bundle intake use the same root-kind gate.
Every non-delete branch command is checked against its actual verified target.
A target may be a full uploaded body, a reconstructed delta result, or an omitted
object reused from existing history; none of those representations changes the
namespace rule. Ref-only reuse still accepts a checksum-verified empty pack.
Complete bundles still refuse omitted dependencies and external delta bases.

All original-input visibility checks precede the new receive root-kind checks.
This ordering applies not just to omitted roots but to uploaded delta results:
an object's reconstructed kind may originate in a server-owned external base.
A branch-kind mismatch must not reveal that base's type before authorization.
The original kind cache is reused and no new body read or fresh resource budget
is introduced. Failure or cancellation prevents all upload staging and ref
publication. Cancellation after an immutable placement has already occurred
retains the existing noncanonical-placement semantics; it is not rollback.

## Regression scope

The added tests cover all four object kinds, raw non-UTF-8 branch names, aliases
in either order, exact namespace boundaries, enqueue limits, cancellation before
and immediately after reads, and malformed source refusal before placement.
File-backed node tests cover loose/packed/mixed import and shutdown/reopen,
ordinary full and delta receive, authorized reused targets, unselected originals,
and private thin bases whose result is either a new ID or the base's own ID.
Raw TCP tests assert an actual `ng` response for non-commit branches, no partially
staged objects, no new canonical decision, and successful commit-branch creation.

Older graph, transport, staging-state, and hidden-ref tests that deliberately
transfer blob/tree/tag roots now place those fixtures in non-branch namespaces.
Their assertions, hidden prefixes, byte contents, retry keys, expected outcomes,
and resource/cancellation checks are retained. New dedicated branch tests prevent
that fixture correction from masking a missing or overbroad branch-type gate.

```sh
bash scripts/verify_ref_target_integrity.sh check
bash scripts/verify_ref_target_integrity.sh test
```

The script invokes ordinary repository-owned Cargo commands. It does not depend
on a hosted workflow or another Git implementation. Source presence does not
mean those commands have run. Session-specific logs and source identities must
accompany any execution claim.

## Limits

This prevents new invalid branch targets through the production source-import
and receive/bundle quarantine paths. It does not audit or rewrite previously
admitted history, provide a migration for an invalid older store, authorize
arbitrary lower-level application-supplied authority writers, implement
fast-forward policy, or claim the entire Git compatibility matrix. It changes
no native identity, canonical schema, transaction identity, policy epoch,
dependency, lockfile, or runtime. Normal publication still uses the existing
validated closure, sealed admission, and exact-predecessor authority-head CAS.
