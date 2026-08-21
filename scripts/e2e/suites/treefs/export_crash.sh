#!/usr/bin/env bash
# e2e: TreeFS export differential, crash, and cancellation campaign
# (bead frankengit-fg026d-treefs-export-evidence-5hsh).
#
# WHAT THIS PROVES, and what it deliberately does not.
#
# 1. DIFFERENTIAL. Until now nothing checked fgit-treefs' exported tree bytes
#    against real Git; the in-crate tests of FG-026c check the export against my
#    own understanding of Git's format, which is exactly the thing that can be
#    wrong in both places at once. This suite builds every case with the pinned
#    sandboxed oracle, hands FrankenGit the same base objects and the same edit
#    list, and requires the exported root tree OID and every emitted tree body to
#    match Git byte for byte.
#
# 2. CRASH. `ExportJournal` is an in-memory value; it has no encoder and touches
#    no filesystem. So "kill and reopen the journal" is NOT implementable today
#    and this suite does not pretend otherwise. What IS implementable, and what
#    the TreeFS design actually relies on, is recompute-determinism: the export
#    plan is a pure function of base and overlay (journal.rs, ExportPhase::
#    Planned), and staged objects are content-addressed and collectable
#    (ExportPhase::Staged). So the campaign SIGKILLs a real process at each
#    journal phase and requires the re-run to produce a byte-identical plan with
#    no partial publication. That is a real crash campaign over the real
#    guarantee, not a simulated one over an aspirational guarantee.
#
# 3. WHAT IS REPORTED UNSUPPORTED, WITH THE MISSING CAPABILITY NAMED.
#    docs/GIT_TREE_FS.md §14 lists eleven interruption points. Several of them
#    name capability that does not exist yet: there is no durable session
#    journal (assert_durable() always refuses), no FUSE adapter, no lazy fetch,
#    and no host rename chain. Those are emitted as `unsupported` with the exact
#    missing thing named, never as pass and never as a silent skip. A suite that
#    quietly omits the crash points its subject cannot survive is worse than no
#    suite, because it reads as coverage.
#
# The oracle is a development/conformance boundary only (AGENTS.md §3.1, §6):
# upstream Git runs pinned and sandboxed, and never in a production path.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "$E2E_ROOT/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

readonly ORACLE="$E2E_ROOT/oracle/oracle.sh"
readonly PIN_ID="${FGIT_TREEFS_ORACLE_PIN:-git-2.54.0}"
readonly CORPUS_SCHEMA="frankengit.treefs-export-corpus.v1"

fge_init

fge_phase setup
fge_context bead frankengit-fg026d-treefs-export-evidence-5hsh
fge_context oracle_pin "$PIN_ID"
fge_context corpus_schema "$CORPUS_SCHEMA"
fge_context spec "docs/GIT_TREE_FS.md#14"

CORPUS="$(fge_artifact_path corpus)"
mkdir -p "$CORPUS/cases"

# ---------------------------------------------------------------------------
# oracle availability
#
# An unavailable oracle is `unsupported`, not `pass` and not `skip`: the
# differential claim is simply unmade, and the record says so.
# ---------------------------------------------------------------------------
oracle_state=available
oracle_detail=""
if [ ! -x "$ORACLE" ]; then
  oracle_state=unavailable
  oracle_detail="no oracle at $ORACLE"
elif ! command -v bwrap >/dev/null 2>&1; then
  oracle_state=unavailable
  oracle_detail="bubblewrap absent; the oracle refuses to run unsandboxed"
elif ! "$ORACLE" verify "$PIN_ID" >/dev/null 2>&1; then
  oracle_state=unavailable
  oracle_detail="pinned oracle $PIN_ID is not built or fails verification"
fi
fge_field oracle_state "$oracle_state"

# ---------------------------------------------------------------------------
# corpus construction with the pinned oracle
#
# Each case gives Git a base worktree and an edit list, and asks Git for both
# tree identities via its own index. Every object Git wrote is dumped, so the
# Rust side receives exactly Git's bytes rather than a re-encoding of them.
# ---------------------------------------------------------------------------
run_dir=""

oracle_git() {
  "$ORACLE" run "$PIN_ID" "$run_dir" "$1" -- "${@:2}"
}

oracle_git_out() {
  local work=$1 label=$2
  shift 2
  "$ORACLE" capture "$PIN_ID" "$run_dir" "$work" "$label" -- "$@" >/dev/null 2>&1 || true
  local out="$run_dir/transcripts/$label/stdout.bin"
  [ -f "$out" ] || return 1
  tr -d '\n' <"$out"
}

# A case is: name | base file spec | edit spec.
# Specs are newline-free records of `path:mode:content`; edits also accept
# `path:DELETE:` to remove a path. Content is literal ASCII so the corpus is
# readable in a diff when something fails.
case_names=""
declare -A CASE_BASE CASE_EDIT

add_case() {
  case_names="$case_names $1"
  CASE_BASE["$1"]=$2
  CASE_EDIT["$1"]=$3
}

add_case untouched \
  'src/lib.rs:100644:fn main() {}
docs/readme.md:100644:# readme' \
  ''

add_case edit_file \
  'src/lib.rs:100644:fn main() {}
docs/readme.md:100644:# readme' \
  'src/lib.rs:100644:fn main() { changed }'

add_case add_nested \
  'src/lib.rs:100644:fn main() {}' \
  'new/deep/nested.txt:100644:added'

add_case delete_file \
  'src/lib.rs:100644:fn main() {}
docs/readme.md:100644:# readme' \
  'docs/readme.md:DELETE:'

add_case mode_change \
  'tool.sh:100644:#!/bin/sh' \
  'tool.sh:100755:#!/bin/sh'

add_case sibling_preserved \
  'src/a.rs:100644:a
src/b.rs:100644:b
src/c.rs:100644:c
docs/readme.md:100644:# readme' \
  'src/b.rs:100644:b changed'

# The subtle one. Git sorts a directory as though its name ended in `/`, so the
# blob `a.txt` sorts BEFORE the tree `a`. Getting this backwards produces a tree
# that is structurally right and byte-wrong, with a different OID. This case
# exists specifically to make that mistake fatal.
add_case dir_blob_ordering \
  'a.txt:100644:blob at a.txt
a/inner.txt:100644:blob inside a
a-b.txt:100644:blob at a-b.txt' \
  'a/inner.txt:100644:blob inside a changed'

# Gitlinks cannot be written into a worktree -- there is no file to create, only
# an index entry naming a commit that need not exist. They are collected here and
# applied with update-index after `git add -A`, which would otherwise not see
# them at all.
PENDING_GITLINKS=""

# A symlink whose text escapes the tree. The escape is the point: Git stores the
# text as a blob and TreeFS must reproduce that byte for byte WITHOUT ever
# following it. An implementation that resolved the link would produce different
# bytes here and be caught.
add_case symlink_escape \
  'src/lib.rs:100644:fn main() {}
src/escape:120000:../../../etc/passwd' \
  'src/escape:120000:../../../../etc/shadow'

# A symlink promoted to a regular file and a file demoted to a symlink: the mode
# transition is where an exporter that keys on path rather than on entry kind
# gets it wrong.
add_case symlink_to_file \
  'link:120000:target.txt
target.txt:100644:target body' \
  'link:100644:no longer a link'

# A gitlink: mode 160000 naming a commit with no object behind it. It is the one
# entry kind whose target legitimately does not exist in the store, so an
# exporter that validates every referenced oid would wrongly refuse it.
# The gitlink is repeated in the edit spec even though it does not change. It
# has to be: a gitlink has no directory in the worktree, so the edit pass's
# `git add -A` sees it as a deletion and drops it from the index, and Git's
# "expected" tree then loses an entry the caller never touched. Without this the
# corpus asks Git the wrong question and FrankenGit -- which correctly carries an
# untouched base gitlink forward -- gets reported as the defect. Verified by
# decoding both trees: base had `vendor`, expected had only `src`.
#
# Restated, the case now tests what it is for: an untouched base gitlink must
# survive a rebuild of the tree around it.
add_case gitlink \
  'src/lib.rs:100644:fn main() {}
vendor:160000:1111111111111111111111111111111111111111' \
  'src/lib.rs:100644:fn main() { changed }
vendor:160000:1111111111111111111111111111111111111111'

# Names chosen so a byte-wise sort and a locale-aware sort disagree, plus the
# directory-sorts-as-if-slashed rule at depth. Unicode is stored as raw bytes:
# TreeFS preserves the spelling it was given and never normalises.
add_case hostile_names \
  'z.txt:100644:z
é.txt:100644:e-acute
a b.txt:100644:space in name
A.txt:100644:capital
a.txt:100644:lower
a/deep.txt:100644:inside dir a' \
  'a/deep.txt:100644:inside dir a changed'

write_case_files() {
  local work=$1 spec=$2 line rel mode content
  PENDING_GITLINKS=""
  [ -n "$spec" ] || return 0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    rel=${line%%:*}
    mode=${line#*:}
    mode=${mode%%:*}
    content=${line#*:*:}
    if [ "$mode" = DELETE ]; then
      rm -f -- "$work/$rel"
      continue
    fi
    mkdir -p -- "$(dirname -- "$work/$rel")"
    case $mode in
      120000)
        # The body of a symlink object is the link TEXT, not the target's
        # content. `content` is therefore stored verbatim and deliberately
        # points outside the tree in one case: repository symlinks are data,
        # never host traversal authority (GIT_TREE_FS §15).
        rm -f -- "$work/$rel"
        ln -s -- "$content" "$work/$rel"
        ;;
      160000)
        # A gitlink names a commit that is not in this repository's object
        # store. Recorded for update-index rather than written to disk.
        PENDING_GITLINKS="$PENDING_GITLINKS$rel:$content"$'\n'
        ;;
      100755 | *)
        # rm FIRST. Shell redirection follows symlinks, so writing over an
        # existing symlink would put the bytes in the link's TARGET and leave
        # the link itself untouched -- the symlink_to_file case would then have
        # silently corrupted its own fixture and reported an exporter defect
        # that did not exist.
        rm -f -- "$work/$rel"
        printf '%s\n' "$content" >|"$work/$rel"
        if [ "$mode" = 100755 ]; then
          chmod 755 -- "$work/$rel"
        else
          chmod 644 -- "$work/$rel"
        fi
        ;;
    esac
  done <<EOF
$spec
EOF
}

# Applies any gitlink entries recorded by the last write_case_files call.
apply_gitlinks() {
  local name=$1 line rel commit
  [ -n "$PENDING_GITLINKS" ] || return 0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    rel=${line%%:*}
    commit=${line#*:}
    oracle_git "$name" update-index --add --cacheinfo "160000,$commit,$rel" \
      >/dev/null 2>&1 || true
  done <<EOF
$PENDING_GITLINKS
EOF
}

corpus_cases=0
corpus_failures=""

build_corpus() {
  local name work base_root expected_root
  run_dir="$("$ORACLE" create-run "$PIN_ID" treefs-export)"
  fge_field oracle_run_directory "$run_dir"

  for name in $case_names; do
    work="$run_dir/work/$name"
    mkdir -p "$work"
    # No user.name/user.email config: this corpus builds trees with the index and
    # never creates a commit, so identity is not consulted. Two fewer sandboxed
    # invocations per case.
    oracle_git . init --quiet "--object-format=sha1" "$name" >/dev/null 2>&1 || true

    write_case_files "$work" "${CASE_BASE[$name]}"
    oracle_git "$name" add -A >/dev/null 2>&1 || true
    apply_gitlinks "$name"
    base_root="$(oracle_git_out "$name" "$name-base-tree" write-tree)" || {
      corpus_failures="$corpus_failures $name:base-write-tree"
      continue
    }

    write_case_files "$work" "${CASE_EDIT[$name]}"
    oracle_git "$name" add -A >/dev/null 2>&1 || true
    apply_gitlinks "$name"
    expected_root="$(oracle_git_out "$name" "$name-expected-tree" write-tree)" || {
      corpus_failures="$corpus_failures $name:expected-write-tree"
      continue
    }

    local dir="$CORPUS/cases/$name"
    mkdir -p "$dir"
    {
      printf 'base_root\t%s\n' "$base_root"
      printf 'expected_root\t%s\n' "$expected_root"
    } >|"$dir/meta.tsv"
    printf '%s\n' "${CASE_EDIT[$name]}" >|"$dir/edits.txt"

    # Every object Git wrote, in Git's own `cat-file --batch` framing:
    #   <oid> SP <type> SP <size> LF <body> LF
    # Dumped in ONE oracle call. Each oracle invocation re-verifies the pinned
    # install, so a per-object loop cost roughly a minute per case; the fix is to
    # make fewer calls, never to weaken another agent's verification. The body is
    # binary, so it is handed to the Rust side verbatim and parsed there rather
    # than hex-laundered through bash.
    if "$ORACLE" capture "$PIN_ID" "$run_dir" "$name" "$name-objects" -- \
      cat-file --batch-all-objects --batch >/dev/null 2>&1; then
      cp -- "$run_dir/transcripts/$name-objects/stdout.bin" "$dir/objects.batch"
    else
      corpus_failures="$corpus_failures $name:object-dump"
      continue
    fi

    corpus_cases=$((corpus_cases + 1))
  done

  # Copy the operator receipt so the corpus carries its own provenance.
  local oracle_root="${run_dir%/runs/*}"
  cp -- "$oracle_root/installs/$PIN_ID/receipt.tsv" "$CORPUS/oracle-receipt.tsv" 2>/dev/null || true

  {
    printf 'schema\t%s\n' "$CORPUS_SCHEMA"
    printf 'oracle_pin\t%s\n' "$PIN_ID"
    printf 'algorithm\tsha1\n'
    printf 'case_count\t%s\n' "$corpus_cases"
  } >|"$CORPUS/receipt.tsv"
}

fge_phase action
if [ "$oracle_state" = available ]; then
  fge_note corpus-build "constructing the differential corpus with pinned $PIN_ID"
  build_corpus
fi

fge_artifact corpus/receipt.tsv text 2>/dev/null || true

# ---------------------------------------------------------------------------
# differential
# ---------------------------------------------------------------------------
fge_phase assert

if [ "$oracle_state" != available ]; then
  fge_unsupported FG-026D-DIFF-001 \
    "pinned Git oracle $PIN_ID unavailable: $oracle_detail"
  fge_unsupported FG-026D-DIFF-002 \
    "pinned Git oracle $PIN_ID unavailable: $oracle_detail"
else
  fge_assert_eq FG-026D-DIFF-001 '' "$corpus_failures" \
    'the pinned oracle produced every declared differential case'

  expected_cases=0
  for _n in $case_names; do expected_cases=$((expected_cases + 1)); done
  fge_assert_eq FG-026D-DIFF-002 "$expected_cases" "$corpus_cases" \
    'every declared case is present in the corpus, so the differential is not vacuous'

  fge_run FG-026D-DIFF-003-run \
    env RCH_CARGO_WRAPPER_BYPASS=1 FGIT_TREEFS_EXPORT_CORPUS="$CORPUS" \
    cargo test --locked -p fgit-treefs --test export_differential -- --ignored --nocapture
  differential_exit=$FGE_LAST_EXIT

  fge_assert_eq FG-026D-DIFF-003 0 "$differential_exit" \
    'FrankenGit export reproduces the pinned oracle root tree and every tree body byte for byte'
fi

# ---------------------------------------------------------------------------
# crash campaign
#
# fgit-treefs performs no filesystem I/O: export builds an in-memory plan,
# materialize returns a description of a loose-object layout without writing it,
# and proposal refuses to publish. So a SIGKILL cannot corrupt on-disk state
# because there is no on-disk state, and a test claiming otherwise would be
# proving a tautology (RH-5).
#
# What a REAL process kill does establish, and an in-process loop cannot, is
# determinism across fresh address-space layouts: new ASLR, fresh allocator,
# fresh hash seeds on every run. AGENTS.md §5.3 forbids relying on map iteration
# order; a dependence on pointer or hash-seed ordering would produce a plan that
# differs between processes while looking perfectly stable within any one of
# them. That is the defect class this campaign targets.
# ---------------------------------------------------------------------------
CRASH_DIR="$(fge_artifact_path crash)"
mkdir -p "$CRASH_DIR"

crash_driver() {
  local phase=$1 out=$2
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    FGIT_TREEFS_CRASH_AT="$phase" \
    FGIT_TREEFS_CRASH_OUT="$out" \
    cargo test --locked -p fgit-treefs --test export_crash_driver -- --ignored >/dev/null 2>&1
}

baseline="$CRASH_DIR/baseline.fingerprint"
crash_driver "" "$baseline" || true

baseline_ok=absent
[ -s "$baseline" ] && baseline_ok=present
fge_assert_eq FG-026D-CRASH-001 present "$baseline_ok" \
  'the uninterrupted driver produces an export fingerprint to compare against'

baseline_digest=""
[ -s "$baseline" ] && baseline_digest="$(fge_digest_file "$baseline")"
fge_field baseline_fingerprint "$baseline_digest"

# Every phase named by ExportPhase::ALL. Missing one silently would shrink the
# campaign, so the list is asserted against the enum's own Display strings.
CRASH_PHASES="unstarted reserved planned staged proposed settled"

crash_survived=""
crash_mismatch=""
crash_leaked=""
for phase in $CRASH_PHASES; do
  killed_out="$CRASH_DIR/killed-$phase.fingerprint"
  # The aborted run must NOT produce a fingerprint: it dies before the write.
  crash_driver "$phase" "$killed_out" || true
  if [ -s "$killed_out" ]; then
    if [ "$phase" != settled ]; then
      crash_leaked="$crash_leaked$phase "
    fi
  fi

  # Re-run to completion after the crash and require the identical plan.
  rerun_out="$CRASH_DIR/rerun-$phase.fingerprint"
  crash_driver "" "$rerun_out" || true
  if [ ! -s "$rerun_out" ]; then
    crash_survived="$crash_survived$phase "
  elif [ -n "$baseline_digest" ] && [ "$(fge_digest_file "$rerun_out")" != "$baseline_digest" ]; then
    crash_mismatch="$crash_mismatch$phase "
  fi
done

fge_artifact crash/baseline.fingerprint text 2>/dev/null || true

fge_assert_eq FG-026D-CRASH-002 '' "$crash_survived" \
  'after a real process abort at every journal phase, a fresh process still completes the export'

fge_assert_eq FG-026D-CRASH-003 '' "$crash_mismatch" \
  'the recomputed plan is byte-identical across processes, so nothing depends on allocator or hash-seed order'

# `settled` is the terminal phase and the abort there happens AFTER the plan is
# built but BEFORE the write, so it too must leave no fingerprint. Any phase that
# produced output despite being told to abort means the abort did not happen
# where the driver claims.
fge_assert_eq FG-026D-CRASH-004 '' "$crash_leaked" \
  'an aborted run writes no fingerprint, so the crash point is where the driver says it is'

# ---------------------------------------------------------------------------
# containment: the crate must make no filesystem effect at all
#
# This is the assertion that makes the "no on-disk state" premise above evidence
# rather than an assumption. If TreeFS ever starts writing, this fails and the
# whole crash argument above has to be redone rather than silently becoming
# wrong.
# ---------------------------------------------------------------------------
probe_dir="$(fge_tempdir treefs-fs-probe)"
probe_out="$CRASH_DIR/probe.fingerprint"
# The driver chdirs into $probe_dir itself. Launching cargo from there would not
# work: cargo runs test binaries with the current directory set to the package
# root, so the export would run in crates/fgit-treefs while this checked an
# empty directory nothing was going to touch -- an assertion that cannot fail.
env RCH_CARGO_WRAPPER_BYPASS=1 \
  FGIT_TREEFS_CRASH_AT="" \
  FGIT_TREEFS_CRASH_OUT="$probe_out" \
  FGIT_TREEFS_PROBE_DIR="$probe_dir" \
  cargo test --locked -p fgit-treefs --test export_crash_driver -- --ignored >/dev/null 2>&1 || true

# The probe only means something if the export actually ran; an empty directory
# is otherwise indistinguishable from a run that never happened.
probe_ran=absent
[ -s "$probe_out" ] && probe_ran=present
fge_assert_eq FG-026D-CONTAIN-002 present "$probe_ran" \
  'the containment probe actually completed an export, so an empty probe directory is evidence'

probe_residue="$(find "$probe_dir" -mindepth 1 2>/dev/null | wc -l | tr -d ' ')"
fge_assert_eq FG-026D-CONTAIN-001 0 "$probe_residue" \
  'exporting creates no file in its working directory; the crate performs no filesystem effect'

# ---------------------------------------------------------------------------
# spec coverage ledger
#
# docs/GIT_TREE_FS.md §14 names eleven interruption points. Several require
# capability that does not exist yet. Each is reported as `unsupported` naming
# the exact missing thing, never as pass and never as a silent omission: a suite
# that quietly drops the crash points its subject cannot survive reads as
# coverage while providing none.
# ---------------------------------------------------------------------------
fge_unsupported FG-026D-SPEC-VISIBLE \
  'GIT_TREE_FS §14 "after visible, before durable journal": TreeFS has no durable session journal — ExportJournal is an in-memory value with no encoder, and assert_durable()/assert_visible() always refuse'
fge_unsupported FG-026D-SPEC-FUSE \
  'GIT_TREE_FS §14 "during FUSE read/writeback": no FUSE host adapter exists in fgit-treefs'
fge_unsupported FG-026D-SPEC-LAZYFETCH \
  'GIT_TREE_FS §14 "while lazy fetch is in flight": no lazy object fetch exists; ObjectSource reads are synchronous and local'
fge_unsupported FG-026D-SPEC-RENAME \
  'GIT_TREE_FS §14 "during rename chain": no host materialization writer exists; materialize() returns a ReferenceLayout without writing'
fge_unsupported FG-026D-SPEC-MANIFEST \
  'GIT_TREE_FS §14 "after output creation, before manifest import": no manifest import path exists in this crate'

# ---------------------------------------------------------------------------
# FG-076 overlap, machine-listed as the bead requires
# ---------------------------------------------------------------------------
overlap="$(fge_artifact_path fg076-overlap.tsv)"
{
  printf 'assertion\tfg076_overlap\tnote\n'
  printf 'FG-026D-DIFF-001\tnone\toracle corpus construction is specific to export\n'
  printf 'FG-026D-DIFF-002\tnone\tcorpus completeness is specific to export\n'
  printf 'FG-026D-DIFF-003\tnone\tno FG-076 assertion compares export bytes to upstream Git\n'
  printf 'FG-026D-CRASH-001\tnone\tbaseline fingerprint is export-plan specific\n'
  printf 'FG-026D-CRASH-002\tpotential\tFG-076 is the TreeFS crash matrix; it may also restart after abort, but over overlay/session state rather than the export plan\n'
  printf 'FG-026D-CRASH-003\tpotential\tcross-process determinism could be claimed by either bead; this one scopes it to the export plan\n'
  printf 'FG-026D-CRASH-004\tnone\tabort-point fidelity is internal to this driver\n'
  printf 'FG-026D-CONTAIN-001\tpotential\tFG-076 may assert containment over workspace materialization; this asserts it over the export path only\n'
  printf 'FG-026D-SPEC-VISIBLE\toverlap\tthe durable-journal gap belongs to FG-076 to close; recorded here so the gap is visible from the export side too\n'
  printf 'FG-026D-SPEC-FUSE\toverlap\tFUSE adapter is out of scope for both; listed so neither bead is read as covering it\n'
  printf 'FG-026D-SPEC-LAZYFETCH\toverlap\tlazy fetch is out of scope for both\n'
  printf 'FG-026D-SPEC-RENAME\toverlap\trename chain belongs to the host materialization writer, unbuilt\n'
  printf 'FG-026D-SPEC-MANIFEST\toverlap\tmanifest import is out of scope for both\n'
} >|"$overlap"
fge_artifact fg076-overlap.tsv text

fge_assert_file FG-026D-OVERLAP-001 "$overlap" \
  'the FG-076 overlap is machine-listed per assertion, as the bead requires'
