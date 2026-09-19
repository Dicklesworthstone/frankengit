# Native tag lifecycle in the browser

The source-enabled gateway serves `<repository-route>/ui/tags/`, linked from
source browsing. It composes the existing native source-reference and tag
APIs; no alternate authority, object store, runtime, dependency, release
publisher or signing service is introduced. The broader forge/release plan
remains incomplete. This is a bounded user-facing tag workflow, not closure
of its native admission or full compatibility work.

## Discover, inspect, create, delete

Connect an explicitly provisioned token, then load a reference snapshot in the
repository's SHA-1 or SHA-256 domain. Connection alone sends no request, so
recovery does not depend on permission to list refs. Every reference-page
continuation retains its namespace, limit, last-name cursor, scope and head.
All comparisons use raw name bytes. A truncated listing is not proof that a
tag name is absent. The native API still refuses a byte-only intermediate
continuation it cannot represent in its text cursor grammar.

Select an existing tag to inspect it at both the selected authority snapshot
and its exact direct object ID. The client checks original annotation hashes,
target IDs, declared edge kinds, chain continuity and resource bounds. It
shows direct and peeled identities separately, and can save the original
verified tag object body. Annotation text, HTML-looking bytes and directional
controls are data, not executable markup. Display previews are explicitly
bounded; the saved body retains all bytes.

Create a lightweight tag at a selected visible reference's exact object, or
create an annotated tag with explicit target kind, tagger, timestamp and
message. The client constructs the native annotation bytes and object hash
before sending anything. Metadata uses the existing native UTC `+0000` form.
Empty messages, missing final newlines and raw non-UTF-8 names/messages are
preserved. The interface offers text/LF, explicit CRLF, or exact hex messages.
No new tag overwrites an existing name. Native admission remains responsible
for target visibility, target kind, closure, policy and the expected-absent
transition; neither a selected object ID nor a claimed kind grants permission.

Deletion retains the listed tag's exact **direct** object ID, not its peeled
commit. It never refreshes a moved tag or silently changes deletion into
replacement. Both creation and deletion require a local prepared request,
a displayed old/new effect, and a separate explicit confirmation and Send.
Editor changes cannot change that saved request. Tag operations do not create
forge releases or implicitly retarget PRs or the default branch.

## Signature and identity boundaries

Object-byte hashes are not signatures. The native inspection response's
`signature_verified: false` and `tagger_is_authenticated_principal: false`
remain explicit, including for nested annotations and signature-looking
messages. No key, trusted signer, signature check, or verified-author badge is
fabricated. The final peeled object's existence/kind and the server's signature
classification remain native claims: its body is not part of this browser
report. A lightweight tag may point at another annotated object and then shows
that object's chain rather than inventing an annotation for the ref itself.

## Original-request recovery

The local request fixes operation, exact normalized form bytes, expected/new
object IDs, raw name, metadata, hash domain and one original nonce/key. Its
key commitment also binds origin, route, repository incarnation and credential
fingerprint. A network error or arbitrary HTTP 409 leaves its outcome unknown;
only a validated matching native terminal receipt settles it. Returned effects
must match the saved request, not merely the operation's name.

Explicit retry sends the same body and key without a new reference read. This
is essential after a successful deletion or expected-absent creation whose
reply was lost. Bodyless outcome lookup uses its separate grant and preserves
key-not-observed, seal-not-observed and undecided states as uncertainty. An
observed transaction or principal cannot silently change or disappear.

Token-free retry files preserve the command across reloads. Restore verifies
its original commitment and reconstructs annotated bytes, sends nothing, and
requires the original credential/route. An exported, restored or sent request
cannot be discarded as unsent work. Files contain repository metadata and must
be protected separately from credentials. Disconnect/page exit clears the
credential and views while retaining unresolved request responsibility.

## Bounds and independent profiles

Tag reads narrow native limits to 32 annotations, 512 KiB per object and 2 MiB
of original bytes; JSON replies are capped at 5 MiB. The original-byte budget
also bounds the terminal object on the native side. Reference pages are at
most 100 rows, with at most 2,048 retained rows per browser session. Names are
at most 4,096 bytes, tagger identities 1,024 UTF-8 bytes, and creation messages
64 KiB. Messages cannot contain NUL. Timestamps use exactly representable
nonnegative integers. Commands and retry files are at most 256 KiB; terminal
receipts are 64 KiB and recovery replies 32 KiB. Receipt file sizes are checked
before I/O; stale file, HTTP and hash completions cannot restore cleared state.

The static shell requires `allow_source`; each native API retains its own
read/receive/outcome credential checks and deployment write ceiling. The tag
transport permits only `source/refs`, `source/tags/inspect`, the three native
tag mutations and `outcomes`. Existing PR, branch, source-editor, initial,
search and transfer profiles gain no tag operations. Static helper access does
not grant any API capability. Force updates, replacement, signing, arbitrary
OID selection outside listed refs and cross-repository changes are not added.

## Executable evidence and unverified gates

```sh
node --test tests/browser/tags.test.mjs tests/browser/tags-view.test.mjs
node --test tests/browser/*.test.mjs
node tests/browser/tags-git-oracle.mjs
```

The implementation's restored selected-file fixture passed 323 JavaScript
tests: 232 retained regressions and 91 new tag cases (70 client/protocol and 21
UI/import-route tests), with zero failures or skips. The explicitly
non-production Git 2.47.3 oracle passed 160 checks across both hash domains,
all four target kinds, nested tags, exact body/hash round trips, non-UTF-8 names
and messages, empty messages, missing final newlines and opaque signatures.
It records the exact executable SHA-256. This validates Git object encoding,
not native Rust HTTP/admission execution or signature authenticity.

HTTP/DOM/File tests use doubles, not a complete current checkout or a live
browser/native node. Three Rust static-route regression tests are supplied but
were not executed because Rust/Cargo was unavailable. Native compilation,
live-browser interoperability, full-workspace tests, Clippy, independent
verification and release gates remain unverified.
