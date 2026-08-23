#!/usr/bin/env bash
# FrankenGit's external upstream-Git differential oracle.
#
# This script is tooling-only. Nothing below it is reachable from a production
# Rust target. It accepts only checked-in source pins, builds only from a
# verified source archive, and executes an installed oracle only through a
# Bubblewrap sandbox. A missing source archive, sandbox, receipt, or matching
# binary is UNAVAILABLE, never a successful skipped oracle run.
#
# Usage:
#   oracle.sh fetch-source <pin-id>
#   oracle.sh build <pin-id>
#   oracle.sh record-installed <pin-id> <install-prefix> <source-archive> <build-flags-fingerprint>
#   oracle.sh verify <pin-id>
#   oracle.sh create-run <pin-id> <safe-label>
#   oracle.sh run <pin-id> <run-directory> <relative-workdir> -- <git-args...>
#   oracle.sh capture <pin-id> <run-directory> <relative-workdir> <label> -- <git-args...>
#   oracle.sh clone-loopback <pin-id> <run-directory> <label> <127.0.0.1:port> <repository-path> <destination>
#   oracle.sh compare <left-transcript> <right-transcript> <byte_equal|semantically_equal_declared|divergent> [accepted-divergence-id]
#
# FGIT_ORACLE_ROOT defaults to ~/.cache/frankengit/git-oracle. It is outside
# the repository because source archives, source trees, binaries, transcripts,
# and failure-state artifacts are not source artifacts. Network access occurs
# only in `fetch-source`; `build`, `verify`, `run`, and `capture` never fetch.

set -euo pipefail

readonly ORACLE_SCHEMA_VERSION="1"
readonly ORACLE_REFUSED=64
readonly ORACLE_UNAVAILABLE=69
readonly ORACLE_INTERNAL=70

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd -P)"
PIN_MANIFEST="${FGIT_ORACLE_PIN_MANIFEST:-${SCRIPT_DIR}/pins.tsv}"
# shellcheck source=../lib.sh
. "${SCRIPT_DIR}/../lib.sh"

PIN_ID=""
PIN_VERSION=""
PIN_TAG=""
PIN_COMMIT=""
PIN_URL=""
PIN_SHA256=""
PIN_ARCHIVE=""

oracle_root() {
    local root="${FGIT_ORACLE_ROOT:-${HOME}/.cache/frankengit/git-oracle}"
    case "${root}" in
        ""|/)
            oracle_die "CONFIG" "FGIT_ORACLE_ROOT must name a dedicated absolute non-root directory"
            ;;
    esac
    [[ "${root}" == /* ]] || oracle_die "CONFIG" "FGIT_ORACLE_ROOT must name a dedicated absolute non-root directory"
    case "${root}" in
        "${REPOSITORY_ROOT}"|"${REPOSITORY_ROOT}"/*)
            oracle_die "CONFIG" "FGIT_ORACLE_ROOT must be outside the source repository"
            ;;
    esac
    mkdir -p "${root}"
    root="$(cd "${root}" && pwd -P)"
    case "${root}" in
        "${REPOSITORY_ROOT}"|"${REPOSITORY_ROOT}"/*)
            oracle_die "CONFIG" "FGIT_ORACLE_ROOT resolves inside the source repository"
            ;;
    esac
    printf '%s\n' "${root}"
}

oracle_note() {
    [[ "${FGIT_ORACLE_QUIET:-0}" == "1" && "$1" == "OK" ]] && return
    printf 'FGIT_ORACLE_%s: %s\n' "$1" "$2" >&2
}

oracle_die() {
    oracle_note "$1" "$2"
    case "$1" in
        UNAVAILABLE) exit "${ORACLE_UNAVAILABLE}" ;;
        REFUSED|CONFIG|ESCAPE) exit "${ORACLE_REFUSED}" ;;
        *) exit "${ORACLE_INTERNAL}" ;;
    esac
}

oracle_require_command() {
    command -v "$1" >/dev/null 2>&1 || oracle_die "UNAVAILABLE" "required command is unavailable: $1"
}

oracle_require_safe_token() {
    local token="$1"
    local description="$2"
    [[ "${token}" =~ ^[A-Za-z0-9._-]+$ ]] || oracle_die "REFUSED" "${description} is not a safe token"
}

oracle_sha256() {
    local file="$1"
    local digest=""
    local remainder=""
    if command -v sha256sum >/dev/null 2>&1; then
        read -r digest remainder < <(sha256sum -- "${file}")
    elif command -v shasum >/dev/null 2>&1; then
        read -r digest remainder < <(shasum -a 256 -- "${file}")
    else
        oracle_die "UNAVAILABLE" "neither sha256sum nor shasum is available"
    fi
    [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || oracle_die "INTERNAL" "digest helper returned an invalid SHA-256 for ${file}"
    printf '%s\n' "${digest}"
}

oracle_load_pin() {
    local requested_id="$1"
    local marker=""
    local id=""
    local version=""
    local tag=""
    local commit=""
    local url=""
    local sha256=""
    local archive=""

    oracle_require_safe_token "${requested_id}" "pin id"
    [[ -f "${PIN_MANIFEST}" ]] || oracle_die "UNAVAILABLE" "pin manifest is missing: ${PIN_MANIFEST}"

    IFS= read -r marker < "${PIN_MANIFEST}" || oracle_die "REFUSED" "pin manifest is empty"
    [[ "${marker}" == "# fgit-git-oracle-pins-v1" ]] || oracle_die "REFUSED" "pin manifest marker is invalid"

    while IFS=$'\t' read -r id version tag commit url sha256 archive; do
        [[ -z "${id}" || "${id}" == \#* ]] && continue
        [[ "${id}" == "id" ]] && continue
        if [[ "${id}" == "${requested_id}" ]]; then
            PIN_ID="${id}"
            PIN_VERSION="${version}"
            PIN_TAG="${tag}"
            PIN_COMMIT="${commit}"
            PIN_URL="${url}"
            PIN_SHA256="${sha256}"
            PIN_ARCHIVE="${archive}"
            break
        fi
    done < "${PIN_MANIFEST}"

    [[ -n "${PIN_ID}" ]] || oracle_die "REFUSED" "unrecognized or unpinned Git oracle: ${requested_id}"
    [[ "${PIN_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || oracle_die "REFUSED" "pin ${PIN_ID} has an invalid version"
    [[ "${PIN_TAG}" == "v${PIN_VERSION}" ]] || oracle_die "REFUSED" "pin ${PIN_ID} tag must equal v<version>"
    [[ "${PIN_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || oracle_die "REFUSED" "pin ${PIN_ID} has an invalid tag commit"
    [[ "${PIN_SHA256}" =~ ^[0-9a-f]{64}$ ]] || oracle_die "REFUSED" "pin ${PIN_ID} has an invalid SHA-256"
    [[ "${PIN_ARCHIVE}" == "git-${PIN_VERSION}.tar.xz" ]] || oracle_die "REFUSED" "pin ${PIN_ID} archive name is not canonical"
    [[ "${PIN_URL}" == "https://www.kernel.org/pub/software/scm/git/${PIN_ARCHIVE}" ]] || oracle_die "REFUSED" "pin ${PIN_ID} source URL is not the canonical Git release URL"
}

oracle_archive_path() {
    printf '%s/downloads/%s\n' "$(oracle_root)" "${PIN_ARCHIVE}"
}

oracle_install_dir() {
    printf '%s/installs/%s\n' "$(oracle_root)" "${PIN_ID}"
}

oracle_receipt_path() {
    printf '%s/receipt.tsv\n' "$(oracle_install_dir)"
}

oracle_verify_archive() {
    local archive_path
    archive_path="$(oracle_archive_path)"
    [[ -f "${archive_path}" ]] || oracle_die "UNAVAILABLE" "source archive is unavailable; run fetch-source or provide it out of band: ${archive_path}"
    [[ "$(oracle_sha256 "${archive_path}")" == "${PIN_SHA256}" ]] || oracle_die "REFUSED" "source archive digest does not match pin ${PIN_ID}"
}

oracle_fetch_source() {
    local archive_path
    local download_path

    oracle_load_pin "$1"
    archive_path="$(oracle_archive_path)"
    mkdir -p "$(dirname "${archive_path}")"

    if [[ -f "${archive_path}" ]]; then
        oracle_verify_archive
        oracle_note "OK" "verified existing source archive for ${PIN_ID}"
        return
    fi

    download_path="${archive_path}.partial.$$"
    [[ ! -e "${download_path}" ]] || oracle_die "REFUSED" "preserving an existing incomplete download: ${download_path}"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --proto '=https' --tlsv1.2 --output "${download_path}" "${PIN_URL}" || \
            oracle_die "UNAVAILABLE" "network source download failed; obtain ${PIN_ARCHIVE} out of band"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --output-document="${download_path}" "${PIN_URL}" || \
            oracle_die "UNAVAILABLE" "network source download failed; obtain ${PIN_ARCHIVE} out of band"
    else
        oracle_die "UNAVAILABLE" "no HTTPS downloader is available; obtain ${PIN_ARCHIVE} out of band"
    fi

    [[ "$(oracle_sha256 "${download_path}")" == "${PIN_SHA256}" ]] || \
        oracle_die "REFUSED" "downloaded source archive digest does not match pin ${PIN_ID}; preserved at ${download_path}"
    mv -- "${download_path}" "${archive_path}"
    oracle_note "OK" "fetched and verified source archive for ${PIN_ID}"
}

oracle_assert_archive_paths_are_safe() {
    local archive_path="$1"
    local member=""
    local component=""
    local -a components=()

    oracle_require_command tar
    # List through a checked temp file rather than a process substitution:
    # `done < <(tar ...)` discards tar's exit status, so an unreadable or
    # truncated archive passed path-safety vacuously with zero members.
    local listing=""
    listing="$(mktemp "${TMPDIR:-/tmp}/oracle-archive-listing.XXXXXXXX")"
    if ! tar -tJf "${archive_path}" > "${listing}"; then
        rm -f -- "${listing}"
        oracle_die "REFUSED" "pinned archive cannot be listed: ${archive_path}"
    fi
    while IFS= read -r member; do
        [[ -n "${member}" ]] || continue
        [[ "${member}" != /* ]] || oracle_die "REFUSED" "pinned archive contains an absolute path"
        IFS=/ read -r -a components <<< "${member}"
        for component in "${components[@]}"; do
            [[ "${component}" != ".." ]] || oracle_die "REFUSED" "pinned archive contains a parent-directory path"
        done
    done < "${listing}"
    rm -f -- "${listing}"
}

oracle_require_bwrap() {
    oracle_require_command bwrap
    bwrap --die-with-parent --new-session --unshare-all \
        --ro-bind /usr /usr \
        --symlink usr/bin /bin \
        --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 \
        --proc /proc \
        --dev /dev \
        --tmpfs /tmp \
        -- /usr/bin/true >/dev/null 2>&1 || oracle_die "UNAVAILABLE" "Bubblewrap cannot create the required isolated namespace"
}

oracle_sandbox_version() {
    local install_dir="$1"
    local version_line=""

    oracle_require_bwrap
    if ! version_line="$(bwrap --die-with-parent --new-session --unshare-all --clearenv \
        --ro-bind /usr /usr \
        --symlink usr/bin /bin \
        --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 \
        --proc /proc \
        --dev /dev \
        --tmpfs /tmp \
        --dir /home \
        --dir /home/oracle \
        --ro-bind "${install_dir}" /oracle \
        --setenv HOME /home/oracle \
        --setenv PATH /usr/bin:/bin \
        --setenv GIT_CONFIG_NOSYSTEM 1 \
        --setenv GIT_CONFIG_GLOBAL /dev/null \
        --setenv GIT_CONFIG_COUNT 2 \
        --setenv GIT_CONFIG_KEY_0 core.hooksPath \
        --setenv GIT_CONFIG_VALUE_0 /home/oracle/empty-hooks \
        --setenv GIT_CONFIG_KEY_1 credential.helper \
        --setenv GIT_CONFIG_VALUE_1 '' \
        --setenv GIT_ASKPASS /bin/false \
        --setenv GIT_TERMINAL_PROMPT 0 \
        -- /oracle/bin/git --version)"; then
        oracle_die "UNAVAILABLE" "sandboxed oracle failed while reporting its version"
    fi
    printf '%s\n' "${version_line}"
}

oracle_write_receipt() {
    local install_dir="$1"
    local build_flags="$2"
    local binary_path="${install_dir}/bin/git"
    local version_line=""
    local binary_sha256=""

    [[ -x "${binary_path}" ]] || oracle_die "UNAVAILABLE" "built or recorded Git binary is missing: ${binary_path}"
    [[ -n "${build_flags}" && "${build_flags}" != *$'\n'* && "${build_flags}" != *$'\r'* ]] || oracle_die "REFUSED" "build flags fingerprint must be a non-empty single line"
    version_line="$(oracle_sandbox_version "${install_dir}")"
    [[ "${version_line}" == "git version ${PIN_VERSION}" ]] || oracle_die "REFUSED" "Git binary version does not match pin ${PIN_ID}: ${version_line}"
    binary_sha256="$(oracle_sha256 "${binary_path}")"

    umask 077
    {
        printf 'schema_version=%s\n' "${ORACLE_SCHEMA_VERSION}"
        printf 'id=%s\n' "${PIN_ID}"
        printf 'version=%s\n' "${PIN_VERSION}"
        printf 'tag=%s\n' "${PIN_TAG}"
        printf 'commit=%s\n' "${PIN_COMMIT}"
        printf 'source_url=%s\n' "${PIN_URL}"
        printf 'source_sha256=%s\n' "${PIN_SHA256}"
        printf 'binary_relative_path=bin/git\n'
        printf 'binary_sha256=%s\n' "${binary_sha256}"
        printf 'version_line=%s\n' "${version_line}"
        printf 'build_flags=%s\n' "${build_flags}"
    } > "${install_dir}/receipt.tsv"
}

oracle_verify_release_version() {
    local source_dir="$1"
    local version_file=""
    local source_version=""

    # Git release archives carry `version`; source checkouts commonly carry
    # `GIT-VERSION-FILE`. Prefer the checkout spelling when both are present,
    # but never treat a missing or symlinked version file as equivalent.
    if [[ -f "${source_dir}/GIT-VERSION-FILE" && ! -L "${source_dir}/GIT-VERSION-FILE" ]]; then
        version_file="${source_dir}/GIT-VERSION-FILE"
    elif [[ -f "${source_dir}/version" && ! -L "${source_dir}/version" ]]; then
        version_file="${source_dir}/version"
    else
        oracle_die "REFUSED" "source archive has no regular GIT-VERSION-FILE or release version file for pin ${PIN_ID}"
    fi
    source_version="$(tr -d '\r\n' < "${version_file}")"
    [[ "${source_version}" == "${PIN_VERSION}" ]] || \
        oracle_die "REFUSED" "source archive version file does not match pin ${PIN_ID}"
}

oracle_build() {
    local jobs="${FGIT_ORACLE_JOBS:-1}"
    local root=""
    local archive_path=""
    local source_root=""
    local source_dir=""
    local install_dir=""
    local install_staging=""

    oracle_load_pin "$1"
    [[ "${jobs}" =~ ^[1-9][0-9]*$ ]] || oracle_die "CONFIG" "FGIT_ORACLE_JOBS must be a positive integer"
    oracle_verify_archive
    oracle_require_bwrap
    oracle_require_command make

    root="$(oracle_root)"
    archive_path="$(oracle_archive_path)"
    source_root="${root}/sources/${PIN_ID}"
    source_dir="${source_root}/git-${PIN_VERSION}"
    install_dir="$(oracle_install_dir)"
    install_staging="${root}/installs/.${PIN_ID}.staging"
    [[ ! -e "${source_root}" ]] || oracle_die "REFUSED" "source build directory already exists; preserve it or remove it manually: ${source_root}"
    [[ ! -e "${install_staging}" ]] || oracle_die "REFUSED" "prior build staging directory exists; preserve it or remove it manually: ${install_staging}"
    [[ ! -e "${install_dir}" ]] || oracle_die "REFUSED" "pinned oracle is already installed; verify it instead of replacing it: ${install_dir}"
    mkdir -p "${source_root}" "${install_staging}"
    oracle_assert_archive_paths_are_safe "${archive_path}"
    tar -xJf "${archive_path}" -C "${source_root}"
    [[ -d "${source_dir}" ]] || oracle_die "REFUSED" "source archive did not produce its canonical top-level directory"
    oracle_verify_release_version "${source_dir}"

    # Source acquisition is deliberately outside this command. The build itself
    # executes in a networkless, mount-isolated Bubblewrap namespace.
    bwrap --die-with-parent --new-session --unshare-all --clearenv \
        --ro-bind /usr /usr \
        --symlink usr/bin /bin \
        --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 \
        --dir /etc \
        --ro-bind /etc/alternatives /etc/alternatives \
        --proc /proc \
        --dev /dev \
        --tmpfs /tmp \
        --dir /home \
        --dir /home/oracle \
        --bind "${source_dir}" /source \
        --bind "${install_staging}" /prefix \
        --chdir /source \
        --setenv PATH /usr/bin:/bin \
        --setenv HOME /home/oracle \
        --setenv GIT_CONFIG_NOSYSTEM 1 \
        --setenv GIT_CONFIG_GLOBAL /dev/null \
        --setenv MAKEFLAGS "-j${jobs}" \
        -- /bin/sh -ec 'make configure; ./configure --prefix=/prefix; make NO_TCLTK=YesPlease NO_GETTEXT=YesPlease; make install NO_TCLTK=YesPlease NO_GETTEXT=YesPlease'

    oracle_write_receipt "${install_staging}" "configure:--prefix=/prefix;make:NO_TCLTK=YesPlease,NO_GETTEXT=YesPlease"
    mv -- "${install_staging}" "${install_dir}"
    oracle_note "OK" "built, pinned, and receipted ${PIN_ID} without network access; retained source at ${source_root}"
}

oracle_record_installed() {
    local supplied_prefix="$2"
    local source_archive="$3"
    local build_flags="$4"
    local install_dir=""
    local binary_path=""
    local exec_path=""

    oracle_load_pin "$1"
    [[ "${supplied_prefix}" == /* && -d "${supplied_prefix}" && ! -L "${supplied_prefix}" ]] || oracle_die "REFUSED" "record-installed requires an absolute non-symlinked install prefix"
    [[ "${source_archive}" == /* && -f "${source_archive}" ]] || oracle_die "REFUSED" "record-installed requires an absolute source archive path"
    [[ "$(oracle_sha256 "${source_archive}")" == "${PIN_SHA256}" ]] || oracle_die "REFUSED" "provided source archive does not match pin ${PIN_ID}"
    binary_path="${supplied_prefix}/bin/git"
    exec_path="${supplied_prefix}/libexec/git-core"
    [[ -x "${binary_path}" ]] || oracle_die "REFUSED" "record-installed prefix has no executable bin/git"
    [[ -d "${exec_path}" && ! -L "${exec_path}" ]] || oracle_die "REFUSED" "record-installed prefix has no non-symlinked libexec/git-core directory"

    install_dir="$(oracle_install_dir)"
    [[ ! -e "${install_dir}" ]] || oracle_die "REFUSED" "pinned oracle is already installed; verify it instead of replacing it: ${install_dir}"
    mkdir -p "$(dirname "${install_dir}")"
    cp -a -- "${supplied_prefix}" "${install_dir}"
    oracle_write_receipt "${install_dir}" "${build_flags}"
    oracle_note "OK" "recorded externally built install tree for ${PIN_ID}; source-to-binary provenance remains operator-attested"
}

oracle_receipt_value() {
    local receipt_path="$1"
    local key="$2"
    local line=""
    while IFS= read -r line || [[ -n "${line}" ]]; do
        case "${line}" in
            "${key}"=*)
                printf '%s\n' "${line#*=}"
                return
                ;;
        esac
    done < "${receipt_path}"
}

oracle_verify() {
    local receipt_path=""
    local install_dir=""
    local binary_relative_path=""
    local binary_path=""
    local expected_binary_sha256=""
    local version_line=""
    local build_flags=""

    oracle_load_pin "$1"
    install_dir="$(oracle_install_dir)"
    receipt_path="$(oracle_receipt_path)"
    [[ -f "${receipt_path}" ]] || oracle_die "UNAVAILABLE" "oracle ${PIN_ID} has no local binary receipt"
    [[ "$(oracle_receipt_value "${receipt_path}" schema_version)" == "${ORACLE_SCHEMA_VERSION}" ]] || oracle_die "REFUSED" "oracle receipt schema is unsupported"
    [[ "$(oracle_receipt_value "${receipt_path}" id)" == "${PIN_ID}" ]] || oracle_die "REFUSED" "oracle receipt pin id disagrees with requested pin"
    [[ "$(oracle_receipt_value "${receipt_path}" version)" == "${PIN_VERSION}" ]] || oracle_die "REFUSED" "oracle receipt version disagrees with pin"
    [[ "$(oracle_receipt_value "${receipt_path}" tag)" == "${PIN_TAG}" ]] || oracle_die "REFUSED" "oracle receipt tag disagrees with pin"
    [[ "$(oracle_receipt_value "${receipt_path}" commit)" == "${PIN_COMMIT}" ]] || oracle_die "REFUSED" "oracle receipt commit disagrees with pin"
    [[ "$(oracle_receipt_value "${receipt_path}" source_url)" == "${PIN_URL}" ]] || oracle_die "REFUSED" "oracle receipt source URL disagrees with pin"
    [[ "$(oracle_receipt_value "${receipt_path}" source_sha256)" == "${PIN_SHA256}" ]] || oracle_die "REFUSED" "oracle receipt source digest disagrees with pin"
    [[ "$(oracle_receipt_value "${receipt_path}" version_line)" == "git version ${PIN_VERSION}" ]] || oracle_die "REFUSED" "oracle receipt version fingerprint is malformed"
    build_flags="$(oracle_receipt_value "${receipt_path}" build_flags)"
    [[ -n "${build_flags}" && "${build_flags}" != *$'\n'* && "${build_flags}" != *$'\r'* ]] || oracle_die "REFUSED" "oracle receipt build flags fingerprint is malformed"

    binary_relative_path="$(oracle_receipt_value "${receipt_path}" binary_relative_path)"
    [[ "${binary_relative_path}" == "bin/git" ]] || oracle_die "REFUSED" "oracle receipt binary path is not canonical"
    binary_path="${install_dir}/${binary_relative_path}"
    [[ -x "${binary_path}" ]] || oracle_die "UNAVAILABLE" "receipted oracle binary is missing or non-executable"
    expected_binary_sha256="$(oracle_receipt_value "${receipt_path}" binary_sha256)"
    [[ "${expected_binary_sha256}" =~ ^[0-9a-f]{64}$ ]] || oracle_die "REFUSED" "oracle receipt binary digest is malformed"
    [[ "$(oracle_sha256 "${binary_path}")" == "${expected_binary_sha256}" ]] || oracle_die "REFUSED" "oracle binary digest drifted after receipt creation"
    [[ -d "${install_dir}/libexec/git-core" && ! -L "${install_dir}/libexec/git-core" ]] || oracle_die "UNAVAILABLE" "receipted oracle execution helpers are missing or symlinked"
    version_line="$(oracle_sandbox_version "${install_dir}")"
    [[ "${version_line}" == "git version ${PIN_VERSION}" ]] || oracle_die "REFUSED" "receipted oracle reports the wrong version: ${version_line}"
    oracle_note "OK" "verified pinned oracle ${PIN_ID} (source and binary digests match)"
}

oracle_canonical_directory() {
    local directory="$1"
    [[ -d "${directory}" && ! -L "${directory}" ]] || oracle_die "REFUSED" "required directory is missing or symlinked: ${directory}"
    (cd "${directory}" && pwd -P)
}

oracle_validate_relative_directory() {
    local value="$1"
    local component=""
    local -a components=()

    [[ -n "${value}" && "${value}" != /* ]] || oracle_die "ESCAPE" "sandbox work directory must be relative"
    [[ "${value}" == "." ]] && return
    IFS=/ read -r -a components <<< "${value}"
    for component in "${components[@]}"; do
        [[ -n "${component}" && "${component}" != "." && "${component}" != ".." ]] || oracle_die "ESCAPE" "sandbox work directory contains an unsafe component"
    done
}

oracle_require_work_directory() {
    local run_directory="$1"
    local work_directory="$2"
    local current_directory="${run_directory}/work"
    local component=""
    local -a components=()

    [[ "${work_directory}" == "." ]] && return
    IFS=/ read -r -a components <<< "${work_directory}"
    for component in "${components[@]}"; do
        current_directory="${current_directory}/${component}"
        [[ -d "${current_directory}" && ! -L "${current_directory}" ]] || oracle_die "ESCAPE" "sandbox working directory is missing or contains a symlink"
    done
}

oracle_validate_run_directory() {
    local run_directory="$1"
    local root="$(oracle_root)"
    local canonical_root=""
    local canonical_run=""

    mkdir -p "${root}/runs"
    canonical_root="$(oracle_canonical_directory "${root}/runs")"
    canonical_run="$(oracle_canonical_directory "${run_directory}")"
    case "${canonical_run}" in
        "${canonical_root}"/*) printf '%s\n' "${canonical_run}" ;;
        *) oracle_die "ESCAPE" "run directory is outside the oracle-owned runs directory" ;;
    esac
}

oracle_reject_escape_options() {
    local argument=""
    for argument in "$@"; do
        case "${argument}" in
            -C|-p|-P|--git-dir|--work-tree|--template|--exec-path|--config-env|--config|--super-prefix|-c|--paginate|--no-pager|--)
                oracle_die "ESCAPE" "Git option is not permitted in the sandbox runner: ${argument}"
                ;;
            -C*|--git-dir=*|--work-tree=*|--template=*|--exec-path=*|--config-env=*|--config=*|--super-prefix=*|file://*|ssh://*|git://*|http://*|https://*|/*)
                oracle_die "ESCAPE" "Git argument can escape the sandbox policy: ${argument}"
                ;;
        esac
    done
}

# The regular oracle runner is deliberately file-only and accepts a bounded
# set of ordinary Git arguments.  FIRST CLONE needs one carefully different
# mode: a real git:// request to the fgit-node that the E2E suite starts on
# loopback.  Do not turn this into a generic networked Git runner.  The public
# interface fixes both transport and address so the only network operation a
# pinned Git process can request is the named loopback clone.
oracle_validate_loopback_endpoint() {
    local endpoint="$1"
    local port=""

    if [[ "${endpoint}" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
        port="${BASH_REMATCH[1]}"
    else
        oracle_die "REFUSED" "loopback clone endpoint must be exactly 127.0.0.1:<port>"
    fi
    ((10#${port} >= 1 && 10#${port} <= 65535)) || \
        oracle_die "REFUSED" "loopback clone endpoint port must be in 1..65535"
}

oracle_validate_git_daemon_repository_path() {
    local repository_path="$1"

    [[ "${repository_path}" =~ ^/[0-9a-f]{32}\.git$ ]] || \
        oracle_die "REFUSED" "loopback clone repository path must be /<32-lower-hex>.git"
}

oracle_require_new_clone_destination() {
    local run_directory="$1"
    local destination="$2"
    local current_directory="${run_directory}/work"
    local component=""
    local -a components=()
    local last_index=0
    local index=0

    oracle_validate_relative_directory "${destination}"
    [[ "${destination}" != "." ]] || oracle_die "REFUSED" "loopback clone destination must not be the work root"
    IFS=/ read -r -a components <<< "${destination}"
    last_index=$((${#components[@]} - 1))
    for index in "${!components[@]}"; do
        component="${components[${index}]}"
        current_directory="${current_directory}/${component}"
        if [[ "${index}" -eq "${last_index}" ]]; then
            [[ ! -e "${current_directory}" && ! -L "${current_directory}" ]] || \
                oracle_die "REFUSED" "loopback clone destination already exists or is a symlink"
        else
            [[ -d "${current_directory}" && ! -L "${current_directory}" ]] || \
                oracle_die "ESCAPE" "loopback clone destination parent is missing or contains a symlink"
        fi
    done
}

oracle_create_run() {
    local requested_id="$1"
    local label="$2"
    local root=""
    local run_directory=""

    oracle_load_pin "${requested_id}"
    oracle_verify "${requested_id}"
    oracle_require_safe_token "${label}" "run label"
    root="$(oracle_root)"
    mkdir -p "${root}/runs"
    umask 077
    run_directory="$(mktemp -d "${root}/runs/${PIN_ID}-${label}.XXXXXXXX")"
    mkdir -p "${run_directory}/home/template" "${run_directory}/work" "${run_directory}/transcripts"
    chmod 700 "${run_directory}" "${run_directory}/home" "${run_directory}/work" "${run_directory}/transcripts"
    printf '%s\n' "${run_directory}"
}

oracle_run() {
    local requested_id="$1"
    local supplied_run_directory="$2"
    local work_directory="$3"
    local run_directory=""
    local install_dir=""
    local sandbox_workdir=""

    shift 3
    [[ "${1:-}" == "--" ]] || oracle_die "REFUSED" "oracle run requires -- before Git arguments"
    shift
    [[ "$#" -gt 0 ]] || oracle_die "REFUSED" "oracle run requires a Git command"

    oracle_load_pin "${requested_id}"
    FGIT_ORACLE_QUIET=1 oracle_verify "${requested_id}"
    oracle_require_bwrap
    oracle_validate_relative_directory "${work_directory}"
    oracle_reject_escape_options "$@"
    run_directory="$(oracle_validate_run_directory "${supplied_run_directory}")"
    if [[ "${work_directory}" == "." ]]; then
        sandbox_workdir="/work"
    else
        oracle_require_work_directory "${run_directory}" "${work_directory}"
        sandbox_workdir="/work/${work_directory}"
    fi
    install_dir="$(oracle_install_dir)"

    bwrap --die-with-parent --new-session --unshare-all --clearenv \
        --ro-bind /usr /usr \
        --symlink usr/bin /bin \
        --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 \
        --proc /proc \
        --dev /dev \
        --tmpfs /tmp \
        --dir /home \
        --bind "${run_directory}/home" /home/oracle \
        --bind "${run_directory}/work" /work \
        --ro-bind "${install_dir}" /oracle \
        --chdir "${sandbox_workdir}" \
        --setenv HOME /home/oracle \
        --setenv PATH /usr/bin:/bin \
        --setenv GIT_CONFIG_NOSYSTEM 1 \
        --setenv GIT_CONFIG_GLOBAL /dev/null \
        --setenv GIT_TEMPLATE_DIR /home/oracle/template \
        --setenv GIT_EXEC_PATH /oracle/libexec/git-core \
        --setenv GIT_CEILING_DIRECTORIES /work \
        --setenv GIT_ALLOW_PROTOCOL file \
        --setenv GIT_CONFIG_COUNT 2 \
        --setenv GIT_CONFIG_KEY_0 core.hooksPath \
        --setenv GIT_CONFIG_VALUE_0 /home/oracle/empty-hooks \
        --setenv GIT_CONFIG_KEY_1 credential.helper \
        --setenv GIT_CONFIG_VALUE_1 '' \
        --setenv GIT_ASKPASS /bin/false \
        --setenv GIT_TERMINAL_PROMPT 0 \
        -- /oracle/bin/git "$@"
}

oracle_run_loopback_clone() {
    local requested_id="$1"
    local supplied_run_directory="$2"
    local endpoint="$3"
    local repository_path="$4"
    local destination="$5"
    local run_directory=""
    local install_dir=""
    local remote_url=""

    oracle_load_pin "${requested_id}"
    FGIT_ORACLE_QUIET=1 oracle_verify "${requested_id}"
    oracle_require_bwrap
    oracle_validate_loopback_endpoint "${endpoint}"
    oracle_validate_git_daemon_repository_path "${repository_path}"
    run_directory="$(oracle_validate_run_directory "${supplied_run_directory}")"
    oracle_require_new_clone_destination "${run_directory}" "${destination}"
    install_dir="$(oracle_install_dir)"
    remote_url="git://${endpoint}${repository_path}"

    # `--share-net` is deliberately paired with the fixed loopback-only
    # invocation below.  The generic file-only runner retains `--unshare-all`
    # without this exception.  Numeric loopback avoids DNS, GIT_ALLOW_PROTOCOL
    # denies every non-git transport, and this command accepts no caller-owned
    # Git arguments, so an E2E cannot repurpose the mode for broader egress.
    bwrap --die-with-parent --new-session --unshare-all --share-net --clearenv \
        --ro-bind /usr /usr \
        --symlink usr/bin /bin \
        --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 \
        --proc /proc \
        --dev /dev \
        --tmpfs /tmp \
        --dir /home \
        --bind "${run_directory}/home" /home/oracle \
        --bind "${run_directory}/work" /work \
        --ro-bind "${install_dir}" /oracle \
        --chdir /work \
        --setenv HOME /home/oracle \
        --setenv PATH /usr/bin:/bin \
        --setenv GIT_CONFIG_NOSYSTEM 1 \
        --setenv GIT_CONFIG_GLOBAL /dev/null \
        --setenv GIT_TEMPLATE_DIR /home/oracle/template \
        --setenv GIT_EXEC_PATH /oracle/libexec/git-core \
        --setenv GIT_CEILING_DIRECTORIES /work \
        --setenv GIT_ALLOW_PROTOCOL git \
        --setenv GIT_CONFIG_COUNT 3 \
        --setenv GIT_CONFIG_KEY_0 core.hooksPath \
        --setenv GIT_CONFIG_VALUE_0 /home/oracle/empty-hooks \
        --setenv GIT_CONFIG_KEY_1 credential.helper \
        --setenv GIT_CONFIG_VALUE_1 '' \
        --setenv GIT_CONFIG_KEY_2 protocol.version \
        --setenv GIT_CONFIG_VALUE_2 1 \
        --setenv GIT_ASKPASS /bin/false \
        --setenv GIT_TERMINAL_PROMPT 0 \
        -- /oracle/bin/git clone --no-local "${remote_url}" "${destination}"
}

oracle_clone_loopback() {
    local requested_id="$1"
    local supplied_run_directory="$2"
    local label="$3"
    local endpoint="$4"
    local repository_path="$5"
    local destination="$6"
    local run_directory=""
    local transcript_directory=""
    local exit_code=0
    local install_receipt=""
    local binary_sha256=""

    oracle_load_pin "${requested_id}"
    oracle_require_safe_token "${label}" "loopback clone transcript label"
    oracle_validate_loopback_endpoint "${endpoint}"
    oracle_validate_git_daemon_repository_path "${repository_path}"
    run_directory="$(oracle_validate_run_directory "${supplied_run_directory}")"
    oracle_require_new_clone_destination "${run_directory}" "${destination}"
    transcript_directory="${run_directory}/transcripts/${label}"
    [[ ! -e "${transcript_directory}" ]] || oracle_die "REFUSED" "transcript label already exists: ${label}"
    mkdir -p "${transcript_directory}"

    set +e
    oracle_run_loopback_clone "${requested_id}" "${run_directory}" "${endpoint}" "${repository_path}" "${destination}" \
        > "${transcript_directory}/stdout.bin" 2> "${transcript_directory}/stderr.bin"
    exit_code=$?
    set -e
    install_receipt="$(oracle_receipt_path)"
    binary_sha256="$(oracle_receipt_value "${install_receipt}" binary_sha256)"
    [[ "${binary_sha256}" =~ ^[0-9a-f]{64}$ ]] || \
        oracle_die "REFUSED" "pinned oracle receipt has no valid binary digest for loopback clone"
    {
        printf 'schema_version=%s\n' "${ORACLE_SCHEMA_VERSION}"
        printf 'oracle_id=%s\n' "${PIN_ID}"
        printf 'oracle_version=%s\n' "${PIN_VERSION}"
        printf 'oracle_binary_sha256=%s\n' "${binary_sha256}"
        printf 'network_profile=loopback-git-only\n'
        printf 'allowed_endpoint=%s\n' "${endpoint}"
        printf 'repository_path=%s\n' "${repository_path}"
        printf 'destination=%s\n' "${destination}"
        printf 'exit_code=%s\n' "${exit_code}"
        printf 'stdout_sha256=%s\n' "$(oracle_sha256 "${transcript_directory}/stdout.bin")"
        printf 'stderr_sha256=%s\n' "$(oracle_sha256 "${transcript_directory}/stderr.bin")"
    } > "${transcript_directory}/receipt.tsv"
    oracle_note "CAPTURED" "${transcript_directory} exit=${exit_code} loopback=${endpoint}"
    return "${exit_code}"
}

oracle_capture() {
    local requested_id="$1"
    local run_directory="$2"
    local work_directory="$3"
    local label="$4"
    local transcript_directory=""
    local exit_code=0

    shift 4
    [[ "${1:-}" == "--" ]] || oracle_die "REFUSED" "oracle capture requires -- before Git arguments"
    shift
    oracle_require_safe_token "${label}" "transcript label"
    run_directory="$(oracle_validate_run_directory "${run_directory}")"
    transcript_directory="${run_directory}/transcripts/${label}"
    [[ ! -e "${transcript_directory}" ]] || oracle_die "REFUSED" "transcript label already exists: ${label}"
    mkdir -p "${transcript_directory}"

    set +e
    oracle_run "${requested_id}" "${run_directory}" "${work_directory}" -- "$@" > "${transcript_directory}/stdout.bin" 2> "${transcript_directory}/stderr.bin"
    exit_code=$?
    set -e
    {
        printf 'schema_version=%s\n' "${ORACLE_SCHEMA_VERSION}"
        printf 'oracle_id=%s\n' "${requested_id}"
        printf 'exit_code=%s\n' "${exit_code}"
        printf 'stdout_sha256=%s\n' "$(oracle_sha256 "${transcript_directory}/stdout.bin")"
        printf 'stderr_sha256=%s\n' "$(oracle_sha256 "${transcript_directory}/stderr.bin")"
    } > "${transcript_directory}/receipt.tsv"
    oracle_note "CAPTURED" "${transcript_directory} exit=${exit_code}"
    return "${exit_code}"
}

oracle_compare() {
    local left="$1"
    local right="$2"
    local classification="$3"
    local divergence_id="${4:-}"
    local left_exit=""
    local right_exit=""
    local left_stdout=""
    local right_stdout=""
    local left_stderr=""
    local right_stderr=""
    local identical="false"
    local divergence_json=""
    local observed_digest=""

    [[ -f "${left}/receipt.tsv" && -f "${right}/receipt.tsv" ]] || oracle_die "REFUSED" "both comparison operands must be completed transcripts"
    left_exit="$(oracle_receipt_value "${left}/receipt.tsv" exit_code)"
    right_exit="$(oracle_receipt_value "${right}/receipt.tsv" exit_code)"
    left_stdout="$(oracle_receipt_value "${left}/receipt.tsv" stdout_sha256)"
    right_stdout="$(oracle_receipt_value "${right}/receipt.tsv" stdout_sha256)"
    left_stderr="$(oracle_receipt_value "${left}/receipt.tsv" stderr_sha256)"
    right_stderr="$(oracle_receipt_value "${right}/receipt.tsv" stderr_sha256)"
    [[ "${left_exit}" =~ ^[0-9]+$ && "${right_exit}" =~ ^[0-9]+$ ]] || oracle_die "REFUSED" "comparison transcript exit code is malformed"
    [[ "${left_stdout}" =~ ^[0-9a-f]{64}$ && "${right_stdout}" =~ ^[0-9a-f]{64}$ && "${left_stderr}" =~ ^[0-9a-f]{64}$ && "${right_stderr}" =~ ^[0-9a-f]{64}$ ]] || oracle_die "REFUSED" "comparison transcript digest is malformed"
    # THE VERDICT IS COMPUTED OVER BYTES, NOT OVER CLAIMS ABOUT BYTES. A
    # digest stored beside mutable payloads is an unverified claim: each
    # side's transcripts are re-hashed and must match their own receipt
    # before classification, so a truncated, edited, or substituted payload
    # refuses instead of comparing stale metadata.
    for operand in "${left}" "${right}"; do
        [[ -f "${operand}/stdout.bin" && -f "${operand}/stderr.bin" ]] ||
            oracle_die "REFUSED" "comparison transcript payload is missing: ${operand}"
    done
    observed_digest="$(oracle_sha256 "${left}/stdout.bin")"
    [[ "${observed_digest}" == "${left_stdout}" ]] ||
        oracle_die "REFUSED" "left stdout bytes no longer match their receipt digest"
    observed_digest="$(oracle_sha256 "${left}/stderr.bin")"
    [[ "${observed_digest}" == "${left_stderr}" ]] ||
        oracle_die "REFUSED" "left stderr bytes no longer match their receipt digest"
    observed_digest="$(oracle_sha256 "${right}/stdout.bin")"
    [[ "${observed_digest}" == "${right_stdout}" ]] ||
        oracle_die "REFUSED" "right stdout bytes no longer match their receipt digest"
    observed_digest="$(oracle_sha256 "${right}/stderr.bin")"
    [[ "${observed_digest}" == "${right_stderr}" ]] ||
        oracle_die "REFUSED" "right stderr bytes no longer match their receipt digest"
    if [[ "${left_exit}" == "${right_exit}" && "${left_stdout}" == "${right_stdout}" && "${left_stderr}" == "${right_stderr}" ]]; then
        identical="true"
    fi

    case "${classification}" in
        byte_equal)
            [[ "${identical}" == "true" ]] || oracle_die "REFUSED" "byte_equal verdict requested for non-identical transcripts"
            ;;
        semantically_equal_declared)
            oracle_require_safe_token "${divergence_id}" "accepted divergence id"
            ;;
        divergent)
            [[ "${identical}" == "false" ]] || oracle_die "REFUSED" "divergent verdict requested for byte-identical transcripts"
            ;;
        *)
            oracle_die "REFUSED" "unknown oracle verdict classification: ${classification}"
            ;;
    esac
    divergence_json="$(fge_json_escape "${divergence_id}")"
    printf '{"schema_version":%s,"kind":"oracle_verdict","classification":"%s","byte_identical":%s,"accepted_divergence_id":"%s","left_exit":%s,"right_exit":%s,"left_stdout_sha256":"%s","right_stdout_sha256":"%s","left_stderr_sha256":"%s","right_stderr_sha256":"%s"}\n' \
        "${ORACLE_SCHEMA_VERSION}" "${classification}" "${identical}" "${divergence_json}" "${left_exit}" "${right_exit}" "${left_stdout}" "${right_stdout}" "${left_stderr}" "${right_stderr}"
}

usage() {
    printf 'usage: %s {fetch-source|build|record-installed|verify|create-run|run|capture|clone-loopback|compare} ...\n' "$0" >&2
    exit "${ORACLE_REFUSED}"
}

main() {
    local command="${1:-}"
    shift || true
    case "${command}" in
        fetch-source)
            [[ "$#" -eq 1 ]] || usage
            oracle_fetch_source "$1"
            ;;
        build)
            [[ "$#" -eq 1 ]] || usage
            oracle_build "$1"
            ;;
        record-installed)
            [[ "$#" -eq 4 ]] || usage
            oracle_record_installed "$1" "$2" "$3" "$4"
            ;;
        verify)
            [[ "$#" -eq 1 ]] || usage
            oracle_verify "$1"
            ;;
        create-run)
            [[ "$#" -eq 2 ]] || usage
            oracle_create_run "$1" "$2"
            ;;
        run)
            [[ "$#" -ge 5 ]] || usage
            oracle_run "$@"
            ;;
        capture)
            [[ "$#" -ge 6 ]] || usage
            oracle_capture "$@"
            ;;
        clone-loopback)
            [[ "$#" -eq 6 ]] || usage
            oracle_clone_loopback "$@"
            ;;
        compare)
            [[ "$#" -eq 3 || "$#" -eq 4 ]] || usage
            oracle_compare "$@"
            ;;
        *) usage ;;
    esac
}

main "$@"
