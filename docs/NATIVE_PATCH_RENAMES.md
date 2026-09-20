# Native rename composition used by source authoring

The native `prepare_workspace_patch_in` and `prepare_trusted_patch_in` methods
already opt into `UnifiedPatch::parse_with_renames` at the selected upstream
baseline `4fc65a48f3717ba18d40b7d02cff66c6dd470b5c`. This interface increment uses
that independently landed implementation and leaves its source and tests intact.
The locally developed alternative native patch was superseded; it is not part
of the active patch series and must not overwrite concurrent native work.

## Original source, absent destination, one candidate

Native explicit `rename from` / `rename to` metadata binds a regular-file source
and destination, rather than inferring a move from a similarity score. Source
content comes from the independently selected immutable base. Exact hunks, modes
and optional old/new native blob expectations remain mandatory where supplied.
Both endpoints require capability authorization. An occupied destination is not
absence, even with identical content, and errors do not become absence. Complete
directory disclosure is still required to preserve untouched siblings.

The node constructs the source deletion and destination write in one in-memory
intent log. All files must validate before one candidate is exported. Neither
side becomes visible during preparation. The unchanged path-receipt schema
reports deletion of the old source blob and creation at an absent destination;
the source's blob is never reported as preexisting destination content. Native
source admission later owns quarantine, policy, sealing and exact-old ref CAS.

The parser rejects conflicting endpoints, chains, cycles, ancestor overlaps,
copies, symlinks and gitlinks. Compressed `GIT binary patch` is not enabled by the
source rename path. Native parser/file/output/read budgets remain as defined by
the existing node; this UI does not change their semantics or limits.

## Existing source editor, not another transport

`<repository-route>/ui/source/` gains Rename existing file. Load the original
complete file, enter an exact UTF-8 or hex destination, and preserve or edit the
resulting bytes and executable mode. Text, NUL-containing binary, empty and
non-UTF-8 content remain byte-exact. The browser lowers the move into ordinary
paired deletion/creation hunks; uploaded native rename metadata uses the same
node candidate path. This adds no endpoint, dependency or privilege.

The queue treats both effects as one move. Removing it removes both, and editing
either half separately is refused until the group is removed. One move consumes
two of the browser's 64 touched-path slots. Both effect identities must appear in
native preparation and candidate inspection before publication can be prepared.
Publication still needs separate confirmation. Lost replies retain the same
candidate, multipart bytes and original key; recovery never refreshes a source
name that may already have been removed by a successful publication.

## Actual evidence boundary

Thirty-one new HTTP/DOM/File-double JavaScript cases exercise the real client and
controller, with 232 restored browser regressions. They pass after preserving
the concurrent binary-editor guard. This is not a complete current checkout.
The selected browser shared transport/helpers come from the earlier authoring
fixture; no full-current-workspace or live-browser acceptance is implied.

The pinned non-production Git lane applies 144 forward and explicitly generated
inverse moves plus 32 occupied-destination refusals. It checks the exact complete
index/tree, native blob IDs, bytes and modes in SHA-1 and SHA-256 repositories.
It does not execute Rust or establish native authorization. No claim is made
about Git's `-R` behavior, signed provenance, or release compatibility.

Rust/Cargo is unavailable. Native compilation/tests, live-node/browser interaction,
Clippy, full-workspace checks and independent release gates remain unverified.
See [source authoring](SOURCE_BROWSER_AUTHORING.md) for commands and limits.
