# Constitution goldens

Checked-in expansion goldens required by
`DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md:142` ("authority-sensitive
generated code has a checked-in schema fingerprint and golden expansion test").

## `fgit_types_identity_derives.expanded`

The `#[automatically_derived]` impl blocks that the builtin derives generate for
`fgit-types`' identity types: `InternalObjectId`, `DigestAlgorithmId`,
`CodecVersion`, `DomainTag`. Produced by
`suites/constitution/derive_expansion_golden.sh`, which is the only thing that
reads it. Only generated code is captured; hand-written impls (notably
`DigestBytes`' constant-time comparisons) are deliberately excluded.

What it protects: `#[derive(PartialEq, Ord, Hash, ...)]` generates comparison,
ordering and hashing in FIELD DECLARATION ORDER. Reordering fields on
`InternalObjectId` is a source edit with no call-site change that silently
alters total ordering and hash bucketing for the repository's canonical
identity. Nothing else in the tree would notice.

## Re-blessing

**Do not regenerate this file to make a red test go green.** That is RH-3
(golden regeneration), forbidden by AGENTS.md §16.3. A diff here means one of:

1. **A field was reordered, added, or removed.** This is the defect the golden
   exists to catch. Fix the source, do not re-bless.
2. **A derive was added to or dropped from an identity type.** Deliberate? Then
   re-bless, and say in the commit which trait moved and why.
3. **The pinned nightly changed how a derive expands.** AGENTS.md §3.4 makes a
   toolchain advancement a material change requiring exactly this evidence.
   Re-bless only with the expansion diff read and recorded in the commit
   message, not summarised as "toolchain bump".

In every case the re-blessing commit must show the diff was read. Copy the
`expansion/identity_derives.observed` artifact from the suite's run directory;
it is the same bytes the assertion compares.
