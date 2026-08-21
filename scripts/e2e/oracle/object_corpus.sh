#!/usr/bin/env bash
# Generate a source-derived, byte-preserved Git-object corpus through the
# separately pinned upstream-Git oracle. This is development/conformance
# tooling only; it is never called by FrankenGit production code.
#
# Usage:
#   object_corpus.sh generate <pin-id> <sha1|sha256> <absolute-output-directory>
#
# The output directory receives one immutable corpus directory containing:
#   manifest.tsv          algorithm/type/OID/body-byte mapping
#   receipt.tsv           corpus denominator and oracle-receipt commitment
#   oracle-receipt.tsv    copied operator/build attestation receipt
#   objects/*.body        exact bytes emitted by the pinned oracle
#
# A failed oracle invocation is deliberately not translated into success. In
# particular, a missing operator/build receipt is its typed UNAVAILABLE (69),
# so a caller cannot mistake an ambient host Git for the declared oracle.

set -euo pipefail

readonly CORPUS_SCHEMA='frankengit.object-differential-corpus.v1'
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly ORACLE="${SCRIPT_DIR}/oracle.sh"

corpus_die() {
    printf 'FGIT_OBJECT_CORPUS_REFUSED: %s\n' "$1" >&2
    exit 64
}

corpus_usage() {
    printf 'usage: %s generate <pin-id> <sha1|sha256> <absolute-output-directory>\n' "$0" >&2
    exit 64
}

corpus_safe_token() {
    local value="$1"
    [[ "${value}" =~ ^[A-Za-z0-9._-]+$ ]] || corpus_die "unsafe token: ${value}"
}

corpus_sha256_file() {
    local path="$1"
    local digest=''
    local ignored=''

    [[ -f "${path}" ]] || corpus_die "missing file for SHA-256: ${path}"
    if command -v sha256sum >/dev/null 2>&1; then
        read -r digest ignored < <(sha256sum -- "${path}")
    elif command -v shasum >/dev/null 2>&1; then
        read -r digest ignored < <(shasum -a 256 -- "${path}")
    else
        corpus_die 'neither sha256sum nor shasum is available'
    fi
    [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || corpus_die "invalid SHA-256 output for ${path}"
    printf '%s\n' "${digest}"
}

corpus_hex_to_raw_oid() {
    local oid="$1"
    local index=0
    local byte=''

    while ((index < ${#oid})); do
        byte="${oid:index:2}"
        printf '%b' "\\x${byte}"
        index=$((index + 2))
    done
}

corpus_receipt_value() {
    local receipt="$1"
    local key="$2"
    local line=''

    while IFS= read -r line || [[ -n "${line}" ]]; do
        case "${line}" in
            "${key}"=*)
                printf '%s\n' "${line#*=}"
                return
                ;;
        esac
    done < "${receipt}"
    corpus_die "oracle receipt omits ${key}"
}

corpus_capture_object() {
    local pin_id="$1"
    local run_directory="$2"
    local oid_width="$3"
    local label="$4"
    local object_type="$5"
    local body_path="$6"
    local staging_directory="$7"
    local manifest_path="$8"
    local oid=''
    local hash_transcript=''
    local body_transcript=''
    local body_output=''

    corpus_safe_token "${label}"
    [[ -f "${body_path}" ]] || corpus_die "missing generated ${label} body"
    "${ORACLE}" capture "${pin_id}" "${run_directory}" repo "${label}-hash" -- \
        hash-object -w -t "${object_type}" --stdin < "${body_path}"
    hash_transcript="${run_directory}/transcripts/${label}-hash/stdout.bin"
    IFS= read -r oid < "${hash_transcript}" || corpus_die "oracle emitted no OID for ${label}"
    [[ ${#oid} -eq ${oid_width} && "${oid}" =~ ^[0-9a-f]+$ ]] || \
        corpus_die "oracle emitted an invalid ${oid_width}-hex OID for ${label}"

    "${ORACLE}" capture "${pin_id}" "${run_directory}" repo "${label}-body" -- \
        cat-file "${object_type}" "${oid}"
    body_transcript="${run_directory}/transcripts/${label}-body/stdout.bin"
    body_output="${staging_directory}/objects/${label}.body"
    cp -- "${body_transcript}" "${body_output}"
    cmp --silent -- "${body_path}" "${body_output}" || \
        corpus_die "oracle body round-trip drifted for ${label}"
    printf '%s\t%s\t%s\t%s\n' "${label}" "${object_type}" "${oid}" \
        "objects/${label}.body" >> "${manifest_path}"
    printf '%s\n' "${oid}"
}

corpus_generate() {
    local pin_id="$1"
    local algorithm="$2"
    local output_directory="$3"
    local oid_width=0
    local run_directory=''
    local staging_directory=''
    local manifest_path=''
    local oracle_root=''
    local oracle_receipt=''
    local output_corpus=''
    local empty_tree_oid=''
    local blob_oid=''
    local edge_tree_oid=''
    local base_commit_oid=''
    local complex_commit_oid=''
    local tag_oid=''
    local manifest_sha256=''
    local receipt_sha256=''
    local oracle_build_flags=''
    local count=0

    corpus_safe_token "${pin_id}"
    case "${algorithm}" in
        sha1) oid_width=40 ;;
        sha256) oid_width=64 ;;
        *) corpus_die "unsupported object format: ${algorithm}" ;;
    esac
    [[ "${output_directory}" == /* && "${output_directory}" != / ]] || \
        corpus_die 'output directory must be an absolute non-root path'
    [[ ! -L "${output_directory}" ]] || corpus_die 'output directory must not be a symlink'
    mkdir -p "${output_directory}"
    output_directory="$(cd "${output_directory}" && pwd -P)"
    output_corpus="${output_directory}/corpus-${algorithm}"
    [[ ! -e "${output_corpus}" ]] || corpus_die "refusing to overwrite ${output_corpus}"

    # create-run verifies the full pin/receipt/binary/sandbox boundary first.
    # It must succeed before any ambient Git command could be considered.
    run_directory="$("${ORACLE}" create-run "${pin_id}" "object-${algorithm}")"
    oracle_root="${run_directory%/runs/*}"
    [[ "${oracle_root}" != "${run_directory}" ]] || corpus_die 'oracle run path lacks the owned runs root'
    oracle_receipt="${oracle_root}/installs/${pin_id}/receipt.tsv"
    [[ -f "${oracle_receipt}" ]] || corpus_die 'verified oracle omitted its receipt'
    oracle_build_flags="$(corpus_receipt_value "${oracle_receipt}" build_flags)"

    staging_directory="$(mktemp -d "${output_directory}/.corpus-${algorithm}.XXXXXXXX")"
    mkdir -p "${staging_directory}/objects" "${staging_directory}/inputs"
    manifest_path="${staging_directory}/manifest.tsv"
    printf '# %s\n' "${CORPUS_SCHEMA}" > "${manifest_path}"
    printf '# label\tobject_type\tnative_oid\tbody_path\n' >> "${manifest_path}"
    cp -- "${oracle_receipt}" "${staging_directory}/oracle-receipt.tsv"

    "${ORACLE}" run "${pin_id}" "${run_directory}" . -- init --quiet \
        "--object-format=${algorithm}" repo
    "${ORACLE}" run "${pin_id}" "${run_directory}" repo -- config user.name 'FrankenGit Oracle Corpus'
    "${ORACLE}" run "${pin_id}" "${run_directory}" repo -- config user.email 'oracle-corpus@invalid.example'

    : > "${staging_directory}/inputs/empty-tree.body"
    empty_tree_oid="$(corpus_capture_object "${pin_id}" "${run_directory}" "${oid_width}" \
        "${algorithm}-tree-empty" tree "${staging_directory}/inputs/empty-tree.body" \
        "${staging_directory}" "${manifest_path}")"
    count=$((count + 1))

    printf 'line one\r\nline two\n\377' > "${staging_directory}/inputs/blob-odd.body"
    blob_oid="$(corpus_capture_object "${pin_id}" "${run_directory}" "${oid_width}" \
        "${algorithm}-blob-crlf-nonutf8" blob "${staging_directory}/inputs/blob-odd.body" \
        "${staging_directory}" "${manifest_path}")"
    count=$((count + 1))

    # This deliberately uses Git-compatible import ordering rather than
    # StrictCreate ordering: the directory/file boundary and unusual modes are
    # the corpus edge, while all object-reference bytes remain native-width.
    {
        printf '100755 z-executable\0'
        corpus_hex_to_raw_oid "${blob_oid}"
        printf '40000 a-directory\0'
        corpus_hex_to_raw_oid "${empty_tree_oid}"
        printf '120000 a-symlink\0'
        corpus_hex_to_raw_oid "${blob_oid}"
    } > "${staging_directory}/inputs/tree-order-modes.body"
    edge_tree_oid="$(corpus_capture_object "${pin_id}" "${run_directory}" "${oid_width}" \
        "${algorithm}-tree-order-modes" tree "${staging_directory}/inputs/tree-order-modes.body" \
        "${staging_directory}" "${manifest_path}")"
    count=$((count + 1))

    {
        printf 'tree %s\n' "${edge_tree_oid}"
        printf 'author Corpus Author <author@invalid.example> 0 +0000\n'
        printf 'committer Corpus Committer <committer@invalid.example> 0 +0000\n\n'
        printf 'base commit\n'
    } > "${staging_directory}/inputs/base-commit.body"
    base_commit_oid="$(corpus_capture_object "${pin_id}" "${run_directory}" "${oid_width}" \
        "${algorithm}-commit-base" commit "${staging_directory}/inputs/base-commit.body" \
        "${staging_directory}" "${manifest_path}")"
    count=$((count + 1))

    {
        printf 'tree %s\n' "${edge_tree_oid}"
        printf 'parent %s\n' "${base_commit_oid}"
        printf 'parent %s\n' "${base_commit_oid}"
        printf 'author Corpus Author <author@invalid.example> 1 +0000\n'
        printf 'committer Corpus Committer <committer@invalid.example> 1 +0000\n'
        printf 'encoding ISO-8859-1\n'
        printf 'mergetag object %s\n' "${base_commit_oid}"
        printf ' type commit\n tag corpus-merge\n tagger Corpus Tagger <tagger@invalid.example> 1 +0000\n'
        printf ' \n corpus merge tag\n'
        printf 'gpgsig -----BEGIN PGP SIGNATURE-----\n iQEzBAABCAAdFiEECORPUS\n =abcd\n -----END PGP SIGNATURE-----\n'
        printf 'x-corpus unusual-header\n\n'
        printf 'non-UTF8 commit message: \377\r\n'
    } > "${staging_directory}/inputs/complex-commit.body"
    complex_commit_oid="$(corpus_capture_object "${pin_id}" "${run_directory}" "${oid_width}" \
        "${algorithm}-commit-headers" commit "${staging_directory}/inputs/complex-commit.body" \
        "${staging_directory}" "${manifest_path}")"
    count=$((count + 1))

    {
        printf 'object %s\n' "${complex_commit_oid}"
        printf 'type commit\n'
        printf 'tag corpus-edge-%s\n' "${algorithm}"
        printf 'tagger Corpus Tagger <tagger@invalid.example> 2 +0000\n'
        printf 'gpgsig -----BEGIN PGP SIGNATURE-----\n iQEzBAABCAAdFiEECORPUS\n =efgh\n -----END PGP SIGNATURE-----\n\n'
        printf 'annotated tag body \377\n'
    } > "${staging_directory}/inputs/signed-tag.body"
    tag_oid="$(corpus_capture_object "${pin_id}" "${run_directory}" "${oid_width}" \
        "${algorithm}-tag-signed" tag "${staging_directory}/inputs/signed-tag.body" \
        "${staging_directory}" "${manifest_path}")"
    count=$((count + 1))

    manifest_sha256="$(corpus_sha256_file "${manifest_path}")"
    receipt_sha256="$(corpus_sha256_file "${staging_directory}/oracle-receipt.tsv")"
    {
        printf 'schema=%s\n' "${CORPUS_SCHEMA}"
        printf 'pin_id=%s\n' "${pin_id}"
        printf 'algorithm=%s\n' "${algorithm}"
        printf 'native_oid_hex_width=%s\n' "${oid_width}"
        printf 'corpus_denominator=%s\n' "${count}"
        printf 'object_types=blob:1,tree:2,commit:2,tag:1\n'
        printf 'manifest_sha256=%s\n' "${manifest_sha256}"
        printf 'oracle_receipt_sha256=%s\n' "${receipt_sha256}"
        printf 'oracle_build_attestation=%s\n' "${oracle_build_flags}"
        printf 'oracle_run_directory=%s\n' "${run_directory}"
        printf 'non_claim=E3 corpus evidence only; no full Git compatibility claim\n'
    } > "${staging_directory}/receipt.tsv"

    mv -- "${staging_directory}" "${output_corpus}"
    printf '%s\n' "${output_corpus}"
}

main() {
    [[ "$#" -eq 4 && "$1" == generate ]] || corpus_usage
    corpus_generate "$2" "$3" "$4"
}

main "$@"
