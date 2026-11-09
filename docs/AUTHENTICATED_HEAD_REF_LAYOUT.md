# Authenticated HEAD and ref proofs

The `ref-merkle-v2` layout binds the exact default-branch target to the same
authority-selected root as direct refs. It supports ordinary native writes,
reopening, verified ref reads and ref-anchored blob proofs in both Git hash
formats. The default `legacy` whole-body layout already binds HEAD and remains
supported.

An existing repository can select another existing branch with
[`fg branch set-default`](NATIVE_DEFAULT_BRANCH.md). The command publishes the
HEAD transition through the same authenticated root and decision stream, with
exact old-target/new-tip preconditions and current administrator authorization.
It supports whole-body and both V2 profiles; it does not migrate V1 data.

```sh
fg init ./fgit-data 11111111111111111111111111111111 \
  22222222222222222222222222222222 --root-layout ref-merkle-v2 \
  --initial-branch main
```

The normative byte definition is
[protocol contract §16.5](NORMATIVE_PROTOCOL_CONTRACTS.md#165-authenticated-symbolic-head-and-ref-merkle-layout-v2).
Root-layout code points 4 and 5 select the new ref tree; code point 3 remains
reserved. Every V2 tree begins with a typed HEAD leaf, even when no direct refs
exist. Direct-ref leaves follow it in exact name-byte order. The separate
schema version and leaf discriminators prevent a V1 proof, a direct ref, or
a native object identity from being substituted for HEAD. The final root also
authenticates the total leaf count. This prevents an odd-sized tree's last
leaf from being relabelled as its first direct ref to forge an absence proof.

## Historical V1 repositories

The old ref Merkle layouts (codes 1 and 2) omitted HEAD from their commitment.
Changing a stored canonical frame's target, or removing it, could therefore
leave its direct-ref root unchanged. A stored frame is not by itself proof
of the default branch. This affected the explicitly selected Merkle profiles;
the default whole-body profile includes the complete state.

The node now refuses live use of both V1 layouts, including frames with no
target. Merely ignoring HEAD would also discard its deletion protection.
Initialization refuses V1 before opening storage. Historical standalone
direct-ref proofs still use their original bytes and remain verifiable; they
make no HEAD claim. The option `--root-layout ref-merkle-v1` is not silently
redirected to the new layout.

There is no automatic in-place upgrade. Keep the original store intact.
Recovery must use an independently verified source in a separate repository,
with the intended default branch explicitly selected at creation. Copying an
old stored target into a new authenticated root would assert a fact that the
old root never established. Recreating source refs also does not migrate all
forge metadata or outcomes; a complete authority-preserving V1 migration
remains separate work.

## Proof disclosure

Membership witnesses disclose a ref and the hashes needed to verify it.
Ordered absence witnesses may disclose neighbouring names and OIDs, so their
authorization is checked separately from the requested name. For an empty
direct-ref map, the new `HeadOnly` absence witness contains the optional
unborn target. Serving it requires disclosure permission for HEAD and that
target. A denied witness refuses instead of leaking a hidden branch name.

## Regression coverage

The crypto tests use explicit leaf encodings and exercise empty and populated
maps, both native hash domains, every direct-ref boundary, changed and removed
HEAD targets, raw-byte names, malformed witnesses and cross-version replay.
They also reject index/count relabelling across odd-width tree shapes.
Verified-read tests round-trip the new witness through its bounded wire codec
and an independent pinned-head verifier, while retaining V1 proof coverage.
Node tests substitute only the ref-state frame beneath unchanged authenticated
head receipts, check cold/history paths and preserve permitted whole-body/V2
twins. Existing live Merkle fixtures now exercise V2. These coverage definitions
do not claim full release or compatibility qualification.
