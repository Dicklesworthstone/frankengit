# Native PR browser collaboration

## Implemented boundary

The existing PR-enabled HTTP gateway serves `<repository-route>/ui/pulls/`.
The shell is public static content with no embedded repository data. It is
independent of `allow_source` and `allow_issues`, and requires `allow_pulls`.
Data access, candidate processing, review admission, merge publication and
outcome lookup use the existing native HTTP endpoints and their independent
credential grants. No alternate repository authority, database, dependency,
listener or runtime is introduced.

This implements a bounded human-facing slice of comprehensive-plan §§24–25
and the gateway's `frankengit-asa3` composition. It does not assert completion
of that bead, the full forge or the 1.0 compatibility matrix.

## Working path

1. Connect with an operator-provisioned repository token. PR list/show pages
   retain an explicit authority snapshot. Review pagination retains the
   selected snapshot; it does not silently refresh moved state.
2. Open, update or close PR metadata using a complete explicit command:
   number, expected version, hash format, both branch refs/tips, title and body.
   Preparation creates only a local immutable request. A separate confirmed
   Send action dispatches it.
3. Select an open PR and explicitly enter policy epoch and commit metadata.
   Native preparation constructs a candidate without staging or publication.
   The browser validates the returned multipart envelope and bundle SHA-256,
   then sends the actual bundle to native read-only inspection. It validates
   the returned subject, ordered parents, bundle identity, comparison and
   native Git commit hash before selecting the candidate.
4. For a conflicted preparation, choose exactly one explicit resolution for
   every reported path: base, ours (target), theirs (source), deletion, or a
   custom regular file. A missing side cannot implicitly delete a path. The
   original PR version, tips, policy epoch, merge base and commit metadata stay
   fixed. Resolution constructs a candidate through the native read-only
   resolver; the client verifies every returned path, choice, side, mode and
   native blob identity, then requires the actual bundle to pass inspection.
5. Inspect changed paths and modes, text hunks, and explicit binary/object-only
   entries. A candidate receipt can be shared with another reviewer. Import
   ALWAYS calls native inspection again; receipt checksums are not authority.
6. Prepare an approval, request-changes or withdrawal with an explicit reviewer
   stream version and reason. The credential—not a supplied reviewer field—
   determines the actor. A merge request names an explicit nonempty distinct
   reviewer set. Displayed votes never select reviewers or grant permission.
7. Review the saved action, subject, candidate, versions and key; confirm and
   send it. The native admission path independently enforces the current
   policy, reviewer independence, native object closure and exact-head CAS.
   Reviews do not imply merge permission. Metadata writes do not move refs.

Preparing and inspecting require Git-read and PR-read on the same credential.
Review and merge use their existing separate grants. Outcome recovery requires
its separate read grant; a token lacking PR-list permission can still restore
its original saved request and query outcomes.

## Retry, recovery and cancellation

One pending mutation owns fixed canonical form fields, HTTP body, bundle,
repository incarnation, credential fingerprint, random nonce and idempotency
key. The `fgpr1` key commits to those exact bytes and route. It is a browser
request commitment, NOT a replacement for the native transaction-seal digest.
Editing forms cannot alter a staged request. No automatic retry occurs.

Only a validated native terminal receipt settles it: HTTP 200 with the
matching committed decision, or HTTP 409 with the matching canonical refusal.
An ordinary 409/error body, disconnect, timeout, framing error or malformed
receipt leaves an unknown outcome and retains the original request.

Recovery sends a bodyless POST with the ORIGINAL key. `key_not_observed`,
`seal_not_observed` and `undecided` never establish non-commit. Once a
transaction identity is observed, later absence cannot erase it. Terminal
recovery binds repository incarnation, principal and previously observed
transaction identity. Delivery acknowledgement remains unestablished.

Download a recovery receipt before leaving. It contains the exact private
request and candidate bytes, but not the token. It is bound to the original
credential fingerprint and same origin/route; restoring it verifies the full
request commitment before enabling explicit retry. A sent or exported request
cannot be discarded as an unsent draft because another session may dispatch
an exported copy. A never-exported, never-dispatched draft can be discarded.

Disconnect and page exit abort reads, invalidate candidates and clear tokens
and visible repository data. Pending requests remain in page memory for
explicit recovery export, not as evidence of rollback. Superseded responses
cannot repopulate a different connection's views. No background persistence,
automatic retry, cookies, URL credentials or browser storage is used.

## Security and resource bounds

The static handler reuses the existing strict CSP, no-store, nosniff,
no-referrer and same-origin policies. It accepts exact bodyless GET routes,
not queries, body suffixes, traversal or Git protocol parameters. Native
mutation authorization is unchanged.

All repository text is rendered through text nodes, never HTML or executable
Markdown. Paths remain lossless hex data; malformed UTF-8 is displayed with
byte escapes. Byte-only refs are readable but cannot be submitted through the
existing text-form API. Control and directionality characters are escaped in
display while exact submitted text remains unchanged.

The browser uses exact JavaScript-safe integers and refuses larger numerical
identities rather than rounding them. It supports native SHA-1 and SHA-256
objects. Bounds are intentionally narrower than some native endpoints:

- PR/inspection JSON: 8 MiB; command forms: 256 KiB.
- Candidate bundle: 16 MiB; preparation metadata: 2 MiB.
- Download/import receipts: 24 MiB; oversized files fail before reading bytes.
- Conflict resolutions: at most 128 non-overlapping exact paths, 1 MiB per
  custom file and 16 MiB combined content/path bytes. All encoded descriptors
  share the 256 KiB form ceiling; an over-envelope request is refused.
- Review requirements: 1–32 distinct principals.
- Displayed text: 512 KiB and 256 hunks, with explicit clipping warnings and a
  full validated JSON download; every changed path still gets a label.

The conflict editor makes no choices by default. Custom content uses an
explicit regular-file mode (100644 or 100755) and an explicit text or file
input. Text is encoded from the current editor value as UTF-8; file upload is
required to retain exact binary bytes or original line endings. An empty file
is distinct from deleting its path. Repository paths come only from the
verified report, never from a local upload filename. Side and custom-file
result identities are checked before candidate inspection. Invalid, incomplete,
changed or failed results cannot enable review. Editing the original candidate
inputs or disconnecting clears the retained conflict; cancellation during a
file read prevents dispatch. Native refusal retains the original choices for
an explicit read-only retry, never an implicit subject refresh.

The browser independently verifies the commit object's native hash, but does
not implement a second pack/delta/closure verifier. That remains in the native
inspection/admission engines. A valid client checksum never grants authority.

## Verification and non-claims

Repository-local JavaScript checks:

```sh
node --test tests/browser/pulls-core.test.mjs \
  tests/browser/pulls-actions.test.mjs tests/browser/pulls-view.test.mjs \
  tests/browser/pulls-resolution.test.mjs tests/browser/pulls-resolution-view.test.mjs
node --test tests/browser/*.test.mjs
```

The DOM/HTTP fixtures are test doubles, not native Git pack verification or a
live node. The candidate fixture commits are hashed independently; their
transport bundle is deliberately not presented as native conformance evidence.
Rust static-route tests are in `browser/pulls.rs`; they require the normal
`fgit-node` test target and were not executed in the implementation environment
because Rust/Cargo was unavailable. Live browser rendering and native-node
interoperability were not exercised in this implementation session. Full workspace, Clippy, release and live-node acceptance remain gates.

Automatic construction never invents conflict resolutions; all choices enter
the existing native resolver and its object-selection and policy checks. There
is no inline anchored review comment editor, CI/check collection, hosted IAM,
automatic token-rotation recovery or persistent client session here. Restored
requests require the original valid token. These limits do not weaken native
authority, publication, disclosure or policy checks.
