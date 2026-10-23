# Explicit binary refactoring over the native source HTTP endpoint

`POST /api/v1/source/prepare` admits an optional `patch_profile` in the existing
multipart `command` form. The two values are `exact-tree-v1` and
`exact-tree-binary-v1`. The first explicitly selects the historical HTTP grammar;
the second additionally permits edited binary moves. Omission retains the old
engine and successful response bytes. Empty, unknown, differently cased and
duplicate values refuse; there is no fallback or profile inference from payloads.
The preparation form admits nine fields so the profile and independently chosen
`expected_result_tree` can be supplied together. Existing byte/resource limits
are unchanged. `inspect` and `apply` reject the preparation-only profile.

The implementation selects the existing native `prepare_trusted_patch_in` or
`prepare_trusted_binary_refactor_in` owner. It does not introduce an HTTP patch
engine, host workspace, shell, Git subprocess, new dependency or second admission
path. The native parser authenticates full old/new object identities, verifies
forward and reverse binary images and charges the shared decoding budget. Both
move endpoints retain the existing path/capability checks. Occupied destinations,
chains, cycles, unsupported file kinds, corrupt images and late-file failures
refuse without a partial candidate or repository publication.

## Prepare, inspect, then publish

The command form retains `object_format`, `ref`, `expected_commit`, `author`,
`committer`, `timestamp` and `message`. Add `patch_profile=exact-tree-binary-v1` to
prepare an explicitly authored binary relocation. The patch remains the separate
`text/x-diff` multipart part; both complete Content-Length and chunked intake use
the same native path. The [private-file author](SOURCE_EDIT_REFACTORING_CLI.md)
can produce that input with the corresponding explicit native and binary profiles.

When supplied, `patch_profile` is echoed exactly in preparation metadata. It
changes neither the candidate's Git identity nor its bundle bytes. An independent
`expected_result_tree` constrains the complete result, including modes and untouched
siblings; a mismatch is HTTP 409 `patch_result_tree_mismatch` before any candidate
metadata or bundle is returned. The profile alone does not verify caller intent.

Save the exact returned bundle and inspect its exact commit, parent and complete
result through the existing inspection endpoint. Publication consumes that bundle
with the reviewed commit, expected-old base, authenticated principal and original
idempotency key. It never reapplies the patch recipe. Missing output is not
non-commit; reopening and repeating the original publication recovers its terminal
decision. Preparation itself neither stages objects nor creates a transaction.

## Authentication and evidence scope

The same `allow_source` deployment gate and repository-scoped read credential
remain mandatory for preparation and inspection. A receive-only credential cannot
prepare; a read-only credential cannot publish. Publication independently requires
`allow_receive` and a receive grant. Profile text cannot manufacture privileges or
a transaction key. This remains the existing loopback HTTP deployment, not a
production TLS endpoint, path-scoped agent API or hostile-code sandbox.

`source_binary_refactor_http.sh` starts the actual compiled `fg serve-http` and
uses the actual Node author in both SHA-1 and SHA-256, with literal, delta and
aligned-run delta encodings. Expected blobs, whole trees, modes and commits are
constructed before requests and bundles are independently decoded. Cases cover
legacy refusal and ordinary compatibility, chunked framing, malformed profiles,
wrong full-result intent, reverse-image corruption, occupied destinations,
credential separation, restart, source-free object verification and original-key
recovery. The source result-tree campaign remains a separate regression. These
focused checks are not full-workspace, release, physical-power-loss or completion
of the broader live-operator qualification obligation.
