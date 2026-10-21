# Independently pinned source-edit result trees

Related: FG-032, `docs/REMOTE_SOURCE_EDITING.md` and
`docs/SOURCE_EDIT_RESULT_PLANS.md`. This constrains a local source-edit candidate;
it is not an authority receipt or Agent Protocol intent.

The explicit source-edit selection accepts optional `expected_result_tree`:

```json
"expected_result_tree": "<independently chosen native root-tree hex>"
```

Use the existing `prepare` or `prepare-verified` command with that selection.
The root must be independently calculated or selected, never copied from the
preparation response it is supposed to constrain. It uses the same SHA-1 or
SHA-256 domain as `expected_commit`. Zero, null, wrong-domain and malformed
identities refuse before network I/O; a same-domain prefix is normalized.

The acquisition owner checks the preparation root before sending its bundle
for inspection. Inspection then checks the original candidate commit bytes and
native hash against that exact tree, base parent, and explicit commit metadata.
An internally consistent candidate with different text, executable bits, binary
bytes, or an empty replacement is still the wrong candidate. There is no retry,
latest-base inference, fallback, or relaxation of the existing path allowlist.
Native prepare/inspect/apply form fields are unchanged.

The independently retained constraint is part of capture profile
`frankengit-source-edit-capture-v2`. Ordinary captures keep the exact v1 format.
Offline validation rejects a v2 capture without its result root, a v1 capture
with the new field, and a root that differs from the candidate. Payload/manifest
hashes must be retained independently; removing both the constraint and all
independent custody pins is not a supported adversarial protection model.
Old readers refuse v2 rather than silently ignore its additional intent.

This root pin composes with independently verified original-source/creation
packages and per-file result plans. Their positive membership, absence,
preimage and exact tree-effect checks remain distinct. A result root by itself
does not establish membership of every object in the uploaded pack, apply the
input patch, authorize the user, prove freshness, verify signatures or establish
search coverage. Native Rust still owns patch semantics, admission and policy.

## Verification

```bash
node --test tests/operator/source_edit_candidate.test.mjs \
  tests/operator/source_edit_result_tree.test.mjs
bash scripts/verify_source_edits.sh
```

The focused first command executes 36 new result-pin tests and 34 unchanged
acquisition regressions. Test fixtures construct genuine SHA-1/SHA-256 objects
and bundles with Git, and production acquisition/transport modules run against
native-schema HTTP peers. Git is only a nonproduction oracle. Coverage includes
fully consistent wrong-result candidates, unchanged ordinary serialization and
wire forms, capture downgrade refusal, exact budgets, cancellation, caller
mutation and private-file reopen in a fresh process. A passing fixture suite
is not a live Rust-server, native authorization/CAS or full-workspace pass.
