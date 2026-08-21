# FrankenGit Constitutional Registries

The registries are canonical, reviewable TSV files. They use tabs rather than a general configuration language so the bootstrap checker remains a zero-dependency, safe-Rust binary. Every file starts with `# franken-registry-v1`; the next non-comment line is the exact header; data rows are sorted by `id`.

TSV values may contain spaces, commas, colons, slashes, and Markdown-style paths, but not tabs or newlines. Schema evolution creates a new registry version and migration; it does not reinterpret old columns silently.

`cargo run -p fgit-registry-check -- all` validates schemas, IDs, statuses, cross-file requirements, Markdown integrity, toolchain/workflow policy, and first-party unsafe/FFI rules.

`crate_layers.tsv` is the source of truth for the Plan section 43.2 crate DAG.
It has one row for every workspace package, assigning it an L0–L4 layer and a
sorted restriction on first-party dependency layers. `none` means that the
crate permits no first-party dependencies. The `layer-report` checker command
emits the resolved rows and direct first-party edges as deterministic TSV; a
new crate therefore requires an explicit placement before it can join the
constitutional workspace.

The currently exceptional but deliberate placements are recorded in the
registry rather than inferred from a crate name: the independent
`fgit-codec-verify` is L0, `fgit-deflate` is the L1 pack primitive,
`fgit-diff` and `fgit-witness` are L2 canonical-engine support, the embedded
`fgit-authority-fsqlite` store is L1 beside the authority contract, and
`fgit-admission` is an L4 receive-pack product adapter. `fgit-runtime` and
`fgit-lab` are L2 because they provide execution of canonical engines rather
than an alternate product runtime.
