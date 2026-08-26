#!/usr/bin/env bash
# fg084 STAGED DELIVERABLE (MagentaJay, 2026-08-25): notes-differential corpus
# generator driving the pinned upstream-Git oracle.
#
# STAGING ONLY — lives outside the shared checkout per AGENTS.md 16.1. It
# becomes scripts/e2e/oracle/notes_corpus.sh only if the fg084 owner accepts
# disposition (a) from MagentaJay's review mail; otherwise discarded.
#
# Tooling only; never called by production code. Every Git invocation goes
# through oracle.sh run/capture so an ambient host Git can never masquerade
# as the declared oracle.
#
# Usage:
#   notes_corpus.sh generate <pin-id> <sha1|sha256> \
#       <absolute-output-directory> <absolute-oracle-run-directory>
#   (create the run directory first: oracle.sh create-run <pin-id> <label>)
#
# Corpus layout (<output>/corpus-<algorithm>/):
#   manifest.tsv   tab-separated case rows (schema below)
#   receipt.tsv    schema/oracle/denominator/manifest commitment
#   transcripts/   full oracle transcripts copied from the run directory
#
# manifest.tsv row kinds (tab-separated):
#   snapshot <count> <oid_label> <tree_label> <ls_label>
#   oddwidth <oid_label> <tree_label> <ls_label> <show_label>
#   mergeunion <ours_blob_label> <theirs_blob_label> <merged_bytes_label>
#   mergecsu   <ours_blob_label> <theirs_blob_label> <merged_bytes_label>
# Each label resolves to transcripts/<label>/stdout.bin (exact raw bytes).

set -euo pipefail

readonly CORPUS_SCHEMA='frankengit.notes-differential-corpus.v1'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ORACLE="${FGIT_NOTES_ORACLE_SCRIPT:-${SCRIPT_DIR}/oracle.sh}"

corpus_die() { printf 'FGIT_NOTES_CORPUS_REFUSED: %s\n' "$1" >&2; exit 64; }
corpus_usage() {
    printf 'usage: %s generate <pin-id> <sha1|sha256> <absolute-output-dir> <absolute-run-dir>\n' "$0" >&2
    exit 64
}

[[ $# -eq 5 ]] || corpus_usage
[[ "${1}" == "generate" ]] || corpus_usage
shift
PIN_ID="$1"
ALGORITHM="$2"
OUTPUT_ROOT="$3"
RUN_DIR="$4"
[[ -d "${OUTPUT_ROOT}" ]] || corpus_die "output directory missing: ${OUTPUT_ROOT}"
[[ -d "${RUN_DIR}" ]] || corpus_die "run directory missing: ${RUN_DIR}"
case "${ALGORITHM}" in sha1|sha256) ;; *) corpus_die "algorithm must be sha1|sha256" ;; esac
[[ -x "${ORACLE}" ]] || corpus_die "oracle.sh not executable: ${ORACLE}"
if [[ "${ALGORITHM}" == sha1 ]]; then readonly OID_WIDTH=40; else readonly OID_WIDTH=64; fi

CORPUS_DIRECTORY="${OUTPUT_ROOT}/corpus-${ALGORITHM}"
REPO_WORK="${RUN_DIR}/work/repo"
TRANSCRIPT_SRC="${RUN_DIR}/transcripts"
LOG="${CORPUS_DIRECTORY}/generator.log"
MANIFEST="${CORPUS_DIRECTORY}/manifest.tsv"
RECEIPT="${CORPUS_DIRECTORY}/receipt.tsv"
mkdir -p "${CORPUS_DIRECTORY}" "${REPO_WORK}"
: > "${MANIFEST}"
: > "${LOG}"

MARKERS="${RUN_DIR}/.markers"
mkdir -p "${MARKERS}"
once() {
    # once <marker-name> <command...>: run command only if its marker is
    # absent; create the marker afterwards. Makes the whole generator
    # idempotent against kills mid-run (host load, OOM, restarts).
    local name="$1"; shift
    [[ -e "${MARKERS}/${name}" ]] && return 0
    "$@"
    : > "${MARKERS}/${name}"
}

og_run() { local _label="$1"; shift; "${ORACLE}" run "${PIN_ID}" "${RUN_DIR}" repo -- "$@" >>"${LOG}" 2>&1; }
og_run_once() { local marker="$1"; shift; once "${marker}" og_run "$@"; }
# capture_step records the step's exit code in its own transcript and prints
# that code; callers classify with expect_exit instead of racing set -e.
capture_step() {
    local label="$1"; shift
    local receipt="${TRANSCRIPT_SRC}/${label}/receipt.tsv"
    if [[ -f "${receipt}" ]]; then
        sed -n 's/^exit_code=//p' "${receipt}"
        return 0
    fi
    local status=0
    "${ORACLE}" capture "${PIN_ID}" "${RUN_DIR}" repo "${label}" -- "$@" >>"${LOG}" 2>&1 || status=$?
    printf '%s\n' "${status}"
}
expect_exit() {
    [[ "$2" -eq "$1" ]] || corpus_die "$3: exit $2, wanted $1"
}
stdout_of() { printf "%s/%s/stdout.bin" "${TRANSCRIPT_SRC}" "$1"; }
first_oid_of() { head -c "${OID_WIDTH}" "$(stdout_of "$1")"; }
record_row() { local IFS=$'\t'; printf '%s\n' "$*" >> "${MANIFEST}"; }

corpus_sha256_file() {
    local digest=''
    read -r digest _ < <(sha256sum -- "$1")
    [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || corpus_die "bad sha256 for $1"
    printf '%s\n' "${digest}"
}

# Extract the object OID whose notes-tree path equals the given target hex,
# ignoring fanout '/' separators. Input: ls-tree -r output.
blob_oid_for_target() {
    local file="$1" want="$2" oid=''
    oid="$(awk -F'\t' -v want="${want}" '
        {
            path = $2; gsub(/\//, "", path)
            if (path == want) { split($1, meta, /[ \t]+/); print meta[3]; exit }
        }' "${file}")"
    [[ "${oid}" =~ ^[0-9a-f]+$ ]] || corpus_die "note blob OID not found for ${want} in ${file}"
    printf '%s\n' "${oid}"
}

# Walk every fanout subtree reachable from a root tree and store its exact
# body under <corpus>/trees/<case>/<oid>.body. `ls-tree -r` output lists
# leaves only, so the walk drives NON-recursive ls-tree per captured body
# until a level yields no further directories.
collect_subtrees() {
    # Subtree bodies are content-addressed: one flat store serves every
    # snapshot, and a seen-list prevents duplicate oracle labels when the
    # same subtree object appears under multiple snapshots (the notes ref
    # only grows, so later snapshots embed earlier subtrees verbatim).
    local root_oid="$1"
    local store="${CORPUS_DIRECTORY}/trees"
    mkdir -p "${store}"
    touch "${store}/.captured"
    local queue="${root_oid}"
    local depth=0
    while [[ -n "${queue// /}" ]] && (( depth < 40 )); do
        local next_queue=''
        for oid in ${queue}; do
            grep -qx "${oid}" "${store}/.captured" && continue
            echo "${oid}" >> "${store}/.captured"
            local cap="walk-${depth}-${oid:0:16}"
            st="$(capture_step "${cap}" cat-file tree "${oid}")"
            expect_exit 0 "${st}" "cat-file tree ${oid}"
            cp "$(stdout_of "${cap}")" "${store}/${oid}.body"
            local ls_cap="walk-${depth}-${oid:0:16}-ls"
            st="$(capture_step "${ls_cap}" ls-tree "${oid}")"
            expect_exit 0 "${st}" "ls-tree ${oid}"
            local child
            child="$(awk '$2 == "tree" { print $3 }' "$(stdout_of "${ls_cap}")")"
            next_queue="${next_queue} ${child}"
        done
        queue="${next_queue# }"
        depth=$(( depth + 1 ))
    done
}

# ---------------------------------------------------------------------------
# Repository bootstrap.
# ---------------------------------------------------------------------------
init_args=(--initial-branch=main .)
[[ "${ALGORITHM}" == sha256 ]] && init_args=(--object-format=sha256 "${init_args[@]}")
once repo-init og_run repo-init init "${init_args[@]}"
once set-name  og_run set-name  config user.name  'FrankenGit Notes Oracle'
once set-email og_run set-email config user.email 'notes-corpus@frankengit.invalid'

# ---------------------------------------------------------------------------
# 300 note-target blobs created in ONE sandboxed invocation. Host writes the
# payload files and a path list under the sandboxed repository directory;
# stdin passes through oracle.sh into git hash-object --stdin-paths.
# ---------------------------------------------------------------------------
mkdir -p "${REPO_WORK}/inputs"
: > "${REPO_WORK}/inputs/paths.list"
n=1
while (( n <= 300 )); do
    printf 'target payload %06d\n' "${n}" > "${REPO_WORK}/inputs/target-${n}.txt"
    printf 'inputs/target-%s.txt\n' "${n}" >> "${REPO_WORK}/inputs/paths.list"
    n=$(( n + 1 ))
done
once inputs-write true   # payload files are deterministic; rewrite harmlessly
st="$(capture_step targets hash-object -w --stdin-paths < "${REPO_WORK}/inputs/paths.list")"
once targets-done true
expect_exit 0 "${st}" 'hash-object targets'
mapfile -t TARGET_OIDS < <(cut -c "1-${OID_WIDTH}" "$(stdout_of targets)")
[[ ${#TARGET_OIDS[@]} -eq 300 ]] || corpus_die "expected 300 targets, got ${#TARGET_OIDS[@]}"

# ---------------------------------------------------------------------------
# Incremental notes with byte-exact snapshots at git's fanout boundary.
# ---------------------------------------------------------------------------
SNAPSHOT_COUNTS=(1 255 256 257)
for line in $(seq 1 257); do
    idx=$(( line - 1 ))
    og_run_once "add-${line}" "add-${line}" notes add -m "note body ${line}" "${TARGET_OIDS[${idx}]}"
    case " ${SNAPSHOT_COUNTS[*]} " in
        *" ${line} "*) ;;
        *) continue ;;
    esac
    if true; then
        st="$(capture_step "snap${line}-oid" rev-parse 'refs/notes/commits^{tree}')"
        expect_exit 0 "${st}" "rev-parse snapshot ${line}"
        root_oid="$(first_oid_of "snap${line}-oid")"
        [[ "${root_oid}" =~ ^[0-9a-f]+$ ]] || corpus_die "snapshot ${line}: tree OID unparsable"
        st="$(capture_step "snap${line}-tree" cat-file tree "${root_oid}")"
        expect_exit 0 "${st}" "cat-file tree snapshot ${line}"
        st="$(capture_step "snap${line}-ls" ls-tree -r 'refs/notes/commits^{tree}')"
        expect_exit 0 "${st}" "ls-tree snapshot ${line}"
        collect_subtrees "$(first_oid_of "snap${line}-oid")"
        # Emission at >=255-entry boundary carries a versioned
        # accepted-divergence flag: upstream writer shape is history-dependent
        # (two pinned-oracle runs disagree at identical counts), so our flat
        # emission there is recorded as FG084-DIV-001 rather than asserted.
        if (( line >= 255 )); then
            record_row snapshot "${line}" "snap${line}-oid" "snap${line}-tree" "snap${line}-ls" "accepted:FG084-DIV-001"
        else
            record_row snapshot "${line}" "snap${line}-oid" "snap${line}-tree" "snap${line}-ls"
        fi
    fi
done

# ---------------------------------------------------------------------------
# Odd-width fanout (3-hex root directory): proves upstream acceptance
# functionally (notes show) and supplies exact bytes for our parser.
# ---------------------------------------------------------------------------
odd_target="${TARGET_OIDS[299]}"
prefix3="${odd_target:0:3}"
suffix="${odd_target:3}"
printf 'odd-width note body\n' > "${REPO_WORK}/odd-note.txt"
st="$(capture_step odd-blob hash-object -w --stdin < "${REPO_WORK}/odd-note.txt")"
expect_exit 0 "${st}" 'odd note blob'
odd_blob="$(first_oid_of odd-blob)"
printf '100644 blob %s\t%s\n' "${odd_blob}" "${suffix}" > "${REPO_WORK}/odd-sub.spec"
st="$(capture_step odd-subtree mktree < "${REPO_WORK}/odd-sub.spec")"
expect_exit 0 "${st}" 'mktree odd subtree'
odd_subtree="$(first_oid_of odd-subtree)"
printf '040000 tree %s\t%s\n' "${odd_subtree}" "${prefix3}" > "${REPO_WORK}/odd-root.spec"
st="$(capture_step odd-roottree mktree < "${REPO_WORK}/odd-root.spec")"
expect_exit 0 "${st}" 'mktree odd root'
odd_root="$(first_oid_of odd-roottree)"
st="$(capture_step odd-commit commit-tree "${odd_root}" -m 'odd width notes tree')"
expect_exit 0 "${st}" 'commit-tree odd'
odd_commit="$(first_oid_of odd-commit)"
og_run_once odd-ref odd-ref update-ref refs/notes/commits "${odd_commit}"
# Enumeration (load_subtree) is the read-compatibility surface probed here:
# `notes show` performs a 2-hex-width lookup walk and misses arbitrary-width
# entries even when the tree is structurally valid -- observed directly
# against the pinned oracle 2026-08-25 ("no note found" on a well-formed
# odd-width tree). `notes list` must still enumerate the mapping.
# OBSERVED UPSTREAM BEHAVIOR (pinned git-2.54.0, 2026-08-25): both `notes
# show` and `notes list` treat a structurally valid 3-hex fanout directory as
# ABSENT -- lookup misses it and enumeration emits nothing, exit 0. Upstream
# silently drops what it does not understand. The row below pins that
# observation so the differential test can pair it with our own behavior
# (a typed refusal): same tree, opposite failure styles, one shared fact --
# neither implementation serves such notes as real content.
st="$(capture_step odd-final-oid rev-parse 'refs/notes/commits^{tree}')"
expect_exit 0 "${st}" 'rev-parse odd tree'
odd_final="$(first_oid_of odd-final-oid)"
st="$(capture_step odd-tree cat-file tree "${odd_final}")"
expect_exit 0 "${st}" 'cat-file odd tree'
st="$(capture_step odd-ls ls-tree -r 'refs/notes/commits^{tree}')"
expect_exit 0 "${st}" 'ls-tree odd'
collect_subtrees "${odd_final}"
st="$(capture_step odd-list notes list)"
expect_exit 0 "${st}" 'git notes list on odd-width tree'
record_row oddwidth odd-final-oid odd-tree odd-ls odd-list

# ---------------------------------------------------------------------------
# Conflicting two-side merges with FULL byte control via fast-import.
# `notes add -m` appends a newline (defeating no-NL fixtures) and `commit-tree
# -p` is sandbox-rejected, so both sides' note trees AND their commit
# ancestry are built by ONE stdin-driven fast-import stream. Fixtures:
#   variant a: ours="alpha line\n"       theirs="bravo line\n"
#   variant b: ours="alpha line, no NL"  theirs="bravo line, no NL"
# Each variant shares base blob "base line\n"; ours and theirs are sibling
# commits over it on refs/notes/{u,t}-<v>. Merges run on u-<v> merging t-<v>.
# Manifest rows carry the VARIANT; the test reconstructs the exact input
# bytes from documented constants.
# ---------------------------------------------------------------------------

printf 'alpha line\n'     > "${REPO_WORK}/fi-alpha-a.txt"
printf 'bravo line\n'     > "${REPO_WORK}/fi-bravo-a.txt"
printf 'base line\n'      > "${REPO_WORK}/fi-base.txt"
printf 'alpha line, no NL' > "${REPO_WORK}/fi-alpha-b.txt"
printf 'bravo line, no NL' > "${REPO_WORK}/fi-bravo-b.txt"

FI="${REPO_WORK}/fixtures.fast-import"
{
    emit_blob() {
        printf 'blob\nmark :%s\ndata %s\n' "$1" "$(wc -c < "$2")"
        cat "$2"; printf '\n'
    }
    emit_commit() { # <mark> <parent-mark|empty> <ref> <content-blob-mark> <msg>
        # fast-import grammar: from/merge come AFTER the message data and
        # BEFORE filemodify lines -- not adjacent to mark.
        printf 'commit %s\nmark :%s\n' "$3" "$1"
        printf 'author FrankenGit Notes Oracle <notes-corpus@frankengit.invalid> 1756100000 +0000\n'
        printf 'committer FrankenGit Notes Oracle <notes-corpus@frankengit.invalid> 1756100000 +0000\n'
        printf 'data %s\n%s\n' "$(( ${#5} + 1 ))" "$5"
        [[ -n "$2" ]] && printf 'from :%s\n' "$2"
        printf 'M 100644 :%s %s\n\n' "$4" "${TARGET_OIDS[0]}"
    }
    emit_blob 101 "${REPO_WORK}/fi-base.txt"
    emit_blob 102 "${REPO_WORK}/fi-alpha-a.txt"
    emit_blob 103 "${REPO_WORK}/fi-bravo-a.txt"
    emit_blob 104 "${REPO_WORK}/fi-alpha-b.txt"
    emit_blob 105 "${REPO_WORK}/fi-bravo-b.txt"
    emit_commit 201 ""   "refs/notes/u-base-a" 101 "base a"
    emit_commit 202 201  "refs/notes/u-a"       102 "ours a"
    emit_commit 203 201  "refs/notes/t-a"       103 "theirs a"
    emit_commit 211 ""   "refs/notes/u-base-b" 101 "base b"
    emit_commit 212 211  "refs/notes/u-b"       104 "ours b"
    emit_commit 213 211  "refs/notes/t-b"       105 "theirs b"
} > "${FI}"

# Fixture refs are rebuilt from scratch every pass: a leftover tip makes
# fast-import refuse the (intentionally historyless) new commits.
for fixture_ref in u-a t-a u-b t-b; do
    "${ORACLE}" run "${PIN_ID}" "${RUN_DIR}" repo -- update-ref -d \
        "refs/notes/${fixture_ref}" >>"${LOG}" 2>&1 || true
done
rm -f "${REPO_WORK}/.git/fast_import_crash_"* 2>/dev/null || true

if [[ ! -e "${MARKERS}/fixtures-import" ]]; then
    if "${ORACLE}" run "${PIN_ID}" "${RUN_DIR}" repo -- fast-import < "${FI}" >>"${LOG}" 2>&1; then
        mkdir -p "${MARKERS}"; : > "${MARKERS}/fixtures-import"
    else
        corpus_die "fast-import of merge fixtures failed; see ${LOG}"
    fi
fi

declare -A OURS_COMMIT THEIRS_COMMIT
for v in a b; do
    st="$(capture_step "mv-${v}-u-head" rev-parse "refs/notes/u-${v}")"
    expect_exit 0 "${st}" "variant ${v}: ours head"
    OURS_COMMIT[${v}]="$(first_oid_of "mv-${v}-u-head")"
    st="$(capture_step "mv-${v}-t-head" rev-parse "refs/notes/t-${v}")"
    expect_exit 0 "${st}" "variant ${v}: theirs head"
    THEIRS_COMMIT[${v}]="$(first_oid_of "mv-${v}-t-head")"
done

merge_variant() { # <variant> <tag> <strategy>
    local v="$1" tag="$2" strategy="$3"
    og_run "mv-${v}-${tag}-reset" update-ref "refs/notes/u-${v}" "${OURS_COMMIT[${v}]}"
    st="$(capture_step "mv-${v}-${tag}-merge" notes --ref="u-${v}" merge "--strategy=${strategy}" "t-${v}")"
    expect_exit 0 "${st}" "variant ${v}: merge ${strategy}"
    st="$(capture_step "mv-${v}-${tag}-treeoid" rev-parse "refs/notes/u-${v}^{tree}")"
    expect_exit 0 "${st}" "variant ${v} ${strategy}: result tree"
    local res_tree; res_tree="$(first_oid_of "mv-${v}-${tag}-treeoid")"
    st="$(capture_step "mv-${v}-${tag}-ls" ls-tree -r "${res_tree}")"
    expect_exit 0 "${st}" "variant ${v} ${strategy}: ls"
    local merged_blob
    merged_blob="$(blob_oid_for_target "$(stdout_of "mv-${v}-${tag}-ls")" "${TARGET_OIDS[0]}")"
    st="$(capture_step "mv-${v}-${tag}-bytes" cat-file blob "${merged_blob}")"
    expect_exit 0 "${st}" "variant ${v} ${strategy}: merged bytes"
}

for v in a b; do
    merge_variant "${v}" union union
    merge_variant "${v}" csu   cat_sort_uniq
    record_row union          "${v}" "mv-${v}-union-bytes"
    record_row cat_sort_uniq  "${v}" "mv-${v}-csu-bytes"
done

# ---------------------------------------------------------------------------
# Self-contained receipts.
# ---------------------------------------------------------------------------
cp -a "${TRANSCRIPT_SRC}" "${CORPUS_DIRECTORY}/transcripts"
{
    printf 'schema_version=%s\n' "${CORPUS_SCHEMA}"
    printf 'oracle_id=%s\n' "${PIN_ID}"
    printf 'algorithm=%s\n' "${ALGORITHM}"
    printf 'corpus_denominator=%s\n' "$(wc -l < "${MANIFEST}")"
    printf 'manifest_sha256=%s\n' "$(corpus_sha256_file "${MANIFEST}")"
} > "${RECEIPT}"

printf 'FGIT_NOTES_CORPUS_OK: %s cases in %s\n' "$(wc -l < "${MANIFEST}")" "${CORPUS_DIRECTORY}"
