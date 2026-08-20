# FrankenGit Constitutional Registries

The registries are canonical, reviewable TSV files. They use tabs rather than a general configuration language so the bootstrap checker remains a zero-dependency, safe-Rust binary. Every file starts with `# franken-registry-v1`; the next non-comment line is the exact header; data rows are sorted by `id`.

TSV values may contain spaces, commas, colons, slashes, and Markdown-style paths, but not tabs or newlines. Schema evolution creates a new registry version and migration; it does not reinterpret old columns silently.

`cargo run -p fgit-registry-check -- all` validates schemas, IDs, statuses, cross-file requirements, Markdown integrity, toolchain/workflow policy, and first-party unsafe/FFI rules.
