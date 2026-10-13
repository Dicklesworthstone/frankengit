# Compare references in the source browser

The existing repository `/ui/history/` page supports direct and merge-base
comparison through the native `POST /api/v1/source/diff` API. It requires the
source HTTP profile and the token's independent Git-read grant; PR, review and
receive grants are not needed or implied. No new Rust route, Git implementation,
third-party script or production dependency is introduced.

## Use the comparison

Open **History and blame** from the source browser. Connect with a read token
and the full reference to use as **after**, for example `refs/heads/topic`.
The history read selects an authority snapshot and checks the returned native
commit bytes. Then use **Compare branches before opening a pull request**:

1. Select the **before** reference, for example `refs/heads/main`. An independently
   obtained full native before-tip ID can be supplied as an additional constraint.
2. Choose **Direct** to compare the two selected tips, or **Merge base** to compare
   the native common ancestor with the after tip. Neither computes a merge result.
3. Optionally enter exact path-component prefixes, one per line. `src` includes
   `src/file.rs`, not `src-old/file.rs`. Spaces are preserved. Choose raw lowercase
   hex for non-UTF-8 names or names containing line separators. Blank means all paths.
4. Submit the read explicitly. The returned before tip remains pinned when
   comparing that same reference with other modes or filters. A moved snapshot
   or mismatched tip is an error; use **Reopen reference explicitly** to select
   newer state. Edits to forms do not alter a comparison already in progress.

Both SHA-1 and SHA-256 repositories are supported. Reference inputs use the native
API's full textual `refs/...` syntax; non-UTF-8 reference selection is not added by
this form. Paths and file contents retain their exact byte representation.

## Inspect either side

Each changed blob offers **Open before/after file** and **Download before/after
verified bytes**. File reads use the selected side's original authorized reference,
its original tip, and the comparison's exact commit and root tree. In merge-base
mode, the before-side file comes from the **merge-base commit**, not the before
branch's tip. The source panel continues to show the original after-reference
selection, while the file panel explicitly identifies its own authorized reference.

File range navigation retains these coordinates. **Back to reference comparison**
returns to the retained result without selecting newer state. The full-file download
reads at most 1 MiB and requires the complete payload to hash to the compared native
Git blob ID before offering it. Partial ranges never receive that claim.

Downloads use an object-ID-based `.bin` name and `application/octet-stream`, not a
repository-controlled filesystem path. Executable modes do not create executable
files; symlink targets are downloaded only as inert payload bytes. Directory and
gitlink identities are labelled but never followed by the file controls.

## Complete results versus bounded rendering

The request and validator enforce these limits independently of the server's own
authorization and resource checks:

| Resource | Ceiling |
| --- | ---: |
| Compared native tree entries | 100,000 |
| Changed paths | 512 |
| Text files | 64 |
| File bytes per side | 1 MiB |
| Path and old/new hunk bytes in aggregate | 2 MiB |
| Hunks in aggregate | 4,096 |
| Native diff-work units | 1,000,000 |
| Decoded HTTP response bytes | 8 MiB |
| Explicit path prefixes | 64 |

An over-budget or incomplete response is refused, not converted into a partial
successful diff. The display has separate limits: 25 changed paths per local page,
128 displayed hunks and 512 KiB of displayed hunk input bytes per page, with a
64 KiB per-block preview. A clipped display is labelled; all path labels on its
page remain present. **Download validated response** exports the complete retained
JSON response, including all pages and undisplayed hunks. Local paging makes no
API calls and never refreshes the snapshot.

## Trust and lifecycle boundaries

The client checks response shape, repository/incarnation/hash-domain bindings,
references, tips, mode, filter echo, change kinds, native entry modes, path order,
byte/line spans, resource ceilings and no-effect declarations. The native engine
still determines ancestry, the merge base, visibility and the diff itself. A
structurally consistent diff is **not** independent proof that the server's
ancestry or path claims are correct. A complete-file hash proves the returned
bytes' blob identity, not their path-chain membership, author identity or branch
freshness. No candidate, approval, transaction or merge permission is created.

The transport remains a closed read-only endpoint set. It sends no idempotency
keys, cookies or ambient credentials; refuses redirects; and performs no automatic
retry. Each read owns a deadline and cancellation generation. A late response
cannot revive cancelled or disconnected work. Cancelling response-stream cleanup
cannot indefinitely delay a refusal. Disconnect/pagehide clears credentials,
comparison state, displayed repository data and generated file-download URLs.

## Focused validation

Run the existing history-client regressions alongside the new client/UI cases:

```sh
node --test tests/browser/history.test.mjs \
  tests/browser/history-compare.test.mjs \
  tests/browser/history-compare-view.test.mjs
```

The new tests execute the production modules, native WebCrypto hashing, real
`Response` streams and actual page markup with explicit HTTP/DOM doubles. They
cover direct/merge-base selection, both hash formats, partial/full file reads,
binary and raw paths, either-side navigation, mode/type changes, filtering,
clipping, corruption, cancellation, old controls and form edits. These tests do
not run a Rust node or establish its authorization, ancestry or admission behavior.
A real-browser smoke attempt in the implementation environment was blocked by
Chromium navigation policy; it is not counted as passing browser acceptance.
