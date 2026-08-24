#!/usr/bin/env bash
# e2e: the schema generator and its staleness gate, end to end.
#
# The Rust tests prove the emitters are deterministic and that the gate refuses
# a corrupted artifact. They cannot prove the two things this suite exists for:
#
#   1. the committed artifacts are what the REPOSITORY-OWNED COMMAND produces
#      when a human runs it, rather than what a test harness produces in
#      process — the acceptance says the generator is a command, so the command
#      is what gets exercised;
#   2. the generated TypeScript-facing and Python artifacts are consumable by
#      the languages they target. A Rust test can compare bytes; only python3
#      can say whether the Python file is a Python file.
#
# The gate's negative case runs against a COPY in a temp directory. Corrupting
# the real corpus to prove a gate works would leave sixteen panes with a red
# tree if the suite died between the corruption and the repair.
set -euo pipefail

SC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SC_REPO=$(cd "$SC_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$SC_REPO/scripts/e2e/lib.sh"

fge_init fg048a-schema-codegen
fge_context bead frankengit-fg048a-schema-codegen-ske
fge_context crate fgit-schema
fge_context generator fgit-schema-gen

# Builds run locally (AGENTS.md §16.2). Without this the rch wrapper offloads
# the build and any artifact the worker writes lands on the remote host, so a
# suite that compares generated files fails for a reason that has nothing to do
# with the generator.
export RCH_CARGO_WRAPPER_BYPASS=1

readonly SC_GENERATED="$SC_REPO/crates/fgit-schema/generated"
readonly SC_JSON="canonical-bodies.schema.json"
readonly SC_TS="canonical_bodies.ts"
readonly SC_PY="canonical_bodies.py"

fge_phase setup

fge_assert_dir FG-048A-E2E-001 "$SC_GENERATED" 'the committed artifact directory is present'
for artifact in "$SC_JSON" "$SC_TS" "$SC_PY"; do
  fge_assert_file "FG-048A-E2E-002-$artifact" "$SC_GENERATED/$artifact" "committed artifact $artifact"
  fge_context "digest_$artifact" "$(fge_digest_file "$SC_GENERATED/$artifact")"
done

fge_phase gate

# ------------------------------------------------------------------ the gate
# The committed tree must be current. This is the assertion the fast lane runs.
fge_run 'schema-gen check' \
  cargo run -q -p fgit-schema --bin fgit-schema-gen -- check "$SC_GENERATED"
fge_assert_exit FG-048A-E2E-010 0 "$FGE_LAST_EXIT" \
  'the committed artifacts are byte-identical to the descriptors'

fge_phase reproduce

# --------------------------------------------------- the command reproduces
# Generate into a scratch directory and compare digests with the committed
# files. This is the acceptance's "reproducible byte-identically", exercised
# through the command rather than through the library.
SC_WORK=$(fge_tempdir schema-regen)
fge_run 'schema-gen generate' \
  cargo run -q -p fgit-schema --bin fgit-schema-gen -- generate "$SC_WORK"
fge_assert_exit FG-048A-E2E-020 0 "$FGE_LAST_EXIT" 'the generator command succeeds'

sc_reproduced=0
for artifact in "$SC_JSON" "$SC_TS" "$SC_PY"; do
  committed=$(fge_digest_file "$SC_GENERATED/$artifact")
  regenerated=$(fge_digest_file "$SC_WORK/$artifact")
  fge_assert_eq "FG-048A-E2E-021-$artifact" "$committed" "$regenerated" \
    "$artifact regenerates byte-identically"
  [ "$committed" = "$regenerated" ] && sc_reproduced=$((sc_reproduced + 1))
done
fge_assert_eq FG-048A-E2E-022 3 "$sc_reproduced" 'all three artifacts reproduce'

fge_phase staleness

# ----------------------------------------------- the gate can actually fail
# PRESENCE CASE. A gate nobody has watched fail is decoration. Corrupt the COPY
# and require a non-zero exit, then restore it and require zero — so the
# refusal is attributable to the corruption rather than to the directory.
printf '/* drift */\n' >> "$SC_WORK/$SC_TS"
fge_run 'schema-gen check (corrupted copy)' \
  cargo run -q -p fgit-schema --bin fgit-schema-gen -- check "$SC_WORK"
fge_assert_exit FG-048A-E2E-030 1 "$FGE_LAST_EXIT" \
  'a drifted artifact is refused with exit 1'

cp "$SC_GENERATED/$SC_TS" "$SC_WORK/$SC_TS"
fge_run 'schema-gen check (restored copy)' \
  cargo run -q -p fgit-schema --bin fgit-schema-gen -- check "$SC_WORK"
fge_assert_exit FG-048A-E2E-031 0 "$FGE_LAST_EXIT" \
  'the restored copy passes, so the refusal was the drift'

# A missing artifact is a different refusal from a drifted one, and the gate
# must NOT regenerate it: the fast lane has to stay read-only.
rm -f "$SC_WORK/$SC_PY"
fge_run 'schema-gen check (missing artifact)' \
  cargo run -q -p fgit-schema --bin fgit-schema-gen -- check "$SC_WORK"
fge_assert_exit FG-048A-E2E-032 1 "$FGE_LAST_EXIT" 'a missing artifact is refused'
fge_assert_no_file FG-048A-E2E-033 "$SC_WORK/$SC_PY" \
  'check did not recreate the artifact; a gate that repairs cannot fail'

fge_phase cross-language

# ----------------------------------------- the artifacts are consumable
# The one thing no Rust test can establish: that the generated files are valid
# in the languages they target. A byte-identity gate would happily reproduce
# broken JSON or unparseable Python forever.
if command -v python3 >/dev/null 2>&1; then
  fge_run 'json is well formed' python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$SC_GENERATED/$SC_JSON"
  fge_assert_exit FG-048A-E2E-040 0 "$FGE_LAST_EXIT" 'the JSON Schema artifact parses'

  fge_run 'python artifact compiles' python3 -m py_compile "$SC_GENERATED/$SC_PY"
  fge_assert_exit FG-048A-E2E-041 0 "$FGE_LAST_EXIT" 'the Python artifact compiles'

  # Importing it exercises the dataclass definitions, which py_compile does
  # not: a field ordering error (a defaulted field before a non-defaulted one)
  # is a runtime TypeError at class creation, not a syntax error.
  fge_run 'python artifact imports' \
    python3 -c "import sys; sys.path.insert(0, '$SC_GENERATED'); import canonical_bodies as m; assert m.WIRE_ORDER"
  fge_assert_exit FG-048A-E2E-042 0 "$FGE_LAST_EXIT" \
    'the Python dataclasses construct and WIRE_ORDER is populated'
else
  fge_unsupported FG-048A-E2E-040 'python3 is unavailable, so the cross-language checks did not run'
fi

fge_phase report

fge_field described_schemas 4
fge_field undescribed_schemas 1
fge_note summary 'decision-batch is deliberately undescribed and refuses by name; see the crate docs'
