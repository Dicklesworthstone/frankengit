# Profile-bound source capture and recovery

The existing `node scripts/fg_source_edit.mjs prepare` command accepts an optional
`patch_profile` in its private selection JSON. Values are exactly `exact-tree-v1`
and `exact-tree-binary-v1`; the latter enables the native edited-binary-refactoring
HTTP path. The source author, native engine and ordinary publication remain the
same owners, not new implementations inside the client.

Add the following fields to an otherwise ordinary source-edit selection:

```json
{
  "patch_profile": "exact-tree-binary-v1",
  "expected_result_tree": "FULL_INDEPENDENT_NATIVE_RESULT_TREE_ID"
}
```

The selection must still carry endpoint, exact repository scope/incarnation/hash
format, branch, expected commit, author/committer/timestamp/message and the sorted
exact affected-file path set. It does not accept executable code, source discovery,
inferred renames or a policy override. The expected result root is optional but
should be computed independently of the preparation reply when constraining the
whole intended result. It cannot substitute for source evidence or authorization.

## Explicit profile, explicit custody

Profiled acquisition uses `frankengit-source-edit-capture-v3`. The request, exact
profile echo, optional result-root echo, patch digest, candidate bundle digest,
full commit metadata and native inspection are bound together. Missing, unknown,
ignored or downgraded profile responses refuse before inspection or successful
custody. No automatic fallback retries a broader or older grammar.

Only preparation sends the profile and, when supplied, the full-result expectation.
Inspection and publication retain their historical closed coordinate forms. This
keeps original publication idempotency semantics tied to the exact reviewed bundle,
not to a recipe which could be reapplied against a different source.

Historical v1/v2 requests, captures and response expectations are unchanged when
`patch_profile` is absent, including v2's local result-root constraint. Existing
clients do not acquire newly accepted inputs just by upgrading. Old readers refuse
v3 rather than silently stripping its extra intent. A new server field is never
ignored merely because it looks familiar.

## Native directory rows are not arbitrary extra effects

The native inspector lists complete created/deleted directories alongside the
file changes underneath them. V3 validates these structural rows while preserving
them in the retained inspection. The client reuses the existing canonical tree
encoder, reconstructing each supplied added/deleted directory bottom-up from its
checked immediate file and directory children. Raw names, native hash format,
executable bits, Git tree ordering and every supplied directory identity must agree.
Nested structural gaps, empty or unrelated rows, mixed directions, changed-directory
substitution and mismatching commitments refuse. The existing 512-entry native
inspection ceiling and shared tree-entry/byte budgets apply before encoding.

Only verified structural ancestors are separated for the final file-effect check.
Every requested leaf must still match the preparation's exact old/new IDs and
result mode. This is not blanket acceptance of trees, symlinks, gitlinks or arbitrary
server extras, and it is not an independent proof of repository membership or of
all bundle objects. The receipt continues to report independent bundle-object
verification as false. Explicit full-source-evidence convenience paths remain
separate APIs; this change qualifies the ordinary `prepare`/`inspect`/`stage`/
`apply`/`recover` operator path, not every verified-package wrapper.

## Publication and recovery

Use the existing create-only candidate directory, manifest hash and independently
confirmed commit. Staging copies exact custody into a permanent journal before any
transmission. A closed stdout pipe cannot delete the result or authorize overwrite.
Changing a retained profile invalidates the original manifest; source files are
not reread to repair it. Once dispatch is recorded, an absent local terminal does
not permit resubmission. Recovery queries the original sealed key through the
existing outcomes endpoint and preserves its terminal decision. A saved terminal
can be reopened offline without another HTTP mutation.

## Verification boundary

`source_profile_client.sh` drives the actual Node CLI and actual compiled
`fg serve-http`, including 1 MiB edited binary moves in SHA-1/SHA-256, independently
computed complete trees and commits, lost stdout, changed custody, deletion of
original candidate files, lost local terminal recovery and source/server-free
terminal reopening. It binds executable digests and Node version in its receipt.

`source_edit_profiles.test.mjs` uses deliberately explicit adversarial HTTP schema
fixtures. `source_edit_profile_structure.test.mjs` constructs fixture trees and
bundles with installed Git as a test-only oracle and corrupts their inspection
rows; neither is represented as a running native service. The complete existing
source-authoring lane remains the regression command. Tests on one recorded Linux
runtime are not a cross-platform Node qualification, production TLS, hostile-code
isolation, full live-operator coverage, release or physical-power-loss claim.
