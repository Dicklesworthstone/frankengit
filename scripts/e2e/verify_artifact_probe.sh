#!/usr/bin/env bash
# e2e: validate verification replay artifacts without claiming a checker pass.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VERIFY="${REPOSITORY_ROOT}/scripts/verify.sh"
readonly DOCS_TIMEOUT_SECONDS="${VERIFY_ARTIFACT_PROBE_DOCS_TIMEOUT_SECONDS:-15}"

artifact_field_sha256() {
  local json="$1"
  local key="$2"
  local expression="\"${key}\":\"([0-9a-f]{64})\""

  if [[ "${json}" =~ ${expression} ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  fi
}

read_if_regular() {
  local path="$1"

  if [[ -f "${path}" ]]; then
    cat -- "${path}"
  fi
}

registry_checker_build_pids() {
  local process_id=""
  local command_line=""

  while read -r process_id command_line; do
    if [[ "${command_line}" == *cargo* ]] && [[ "${command_line}" == *fgit-registry-check* ]] && [[ "${command_line}" == *' check '* || "${command_line}" == *' build '* || "${command_line}" == *' run '* || "${command_line}" == *' test '* ]]; then
      printf '%s\n' "${process_id}"
    fi
  done < <(ps -eo pid=,args=)
}

if ! [[ "${DOCS_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
  printf 'verify artifact probe: invalid VERIFY_ARTIFACT_PROBE_DOCS_TIMEOUT_SECONDS=%s\n' "${DOCS_TIMEOUT_SECONDS}" >&2
  exit 2
fi

fge_init verify-artifact-probe
fge_phase setup
artifact_root="$(fge_tempdir verify-replay)"
normal_root="${artifact_root}/normal"
failure_root="${artifact_root}/failure"
no_artifact_root="${artifact_root}/no-artifact"
full_root="${artifact_root}/full"
release_root="${artifact_root}/release"

fge_phase action
set +e
fge_capture invalid-artifact-failure env VERIFY_ARTIFACT_DIR=/dev/null "${VERIFY}" invalid-lane
invalid_failure_exit=$?
set -e
fge_assert_exit FG-001-PROBE-001 2 "${invalid_failure_exit}" "artifact-directory failure preserves the verifier usage exit"

set +e
fge_capture invalid-first env VERIFY_ARTIFACT_DIR="${failure_root}" "${VERIFY}" invalid-lane
invalid_first_exit=$?
set -e
fge_assert_exit FG-001-PROBE-002 2 "${invalid_first_exit}" "invalid lane produces a replay artifact and retains exit 2"

set +e
fge_capture invalid-second env VERIFY_ARTIFACT_DIR="${failure_root}" "${VERIFY}" invalid-lane
invalid_second_exit=$?
set -e
fge_assert_exit FG-001-PROBE-003 2 "${invalid_second_exit}" "repeat invalid lane retains exit 2"

set +e
fge_capture no-artifact env VERIFY_ARTIFACT_DIR="${no_artifact_root}" "${VERIFY}" --no-artifact invalid-lane
no_artifact_exit=$?
set -e
fge_assert_exit FG-001-PROBE-004 2 "${no_artifact_exit}" "no-artifact escape hatch retains verifier exit 2"

set +e
docs_build_pids_before="$(registry_checker_build_pids)"
fge_capture docs-artifact timeout "${DOCS_TIMEOUT_SECONDS}" env VERIFY_ARTIFACT_DIR="${normal_root}" "${VERIFY}" docs
docs_exit=$?
docs_stdout_path="${FGE_LAST_STDOUT_FILE}"
docs_stderr_path="${FGE_LAST_STDERR_FILE}"
docs_build_pids_after="$(registry_checker_build_pids)"
set -e
docs_outcome='COMPLETED'
docs_expected_exit=0
docs_build_pids="${docs_build_pids_before}"$'\n'"${docs_build_pids_after}"
if [[ "${docs_exit}" -eq 124 ]]; then
  docs_outcome='BLOCKED_ON_BUILD_LOCK'
  docs_expected_exit=124
  fge_field docs_outcome "${docs_outcome}"
  fge_field docs_blocking_checker_pids "${docs_build_pids:-unobserved}"
  fge_note "${docs_outcome}" "the Cargo-backed docs lane exceeded its ${DOCS_TIMEOUT_SECONDS}s bound; no partial replay artifact is claimed"
fi
fge_assert_exit FG-001-PROBE-005 "${docs_expected_exit}" "${docs_exit}" "docs lane completes or reports a same-package Cargo build lock"

set +e
fge_capture full-refusal timeout 15 env VERIFY_ARTIFACT_DIR="${full_root}" "${VERIFY}" full
full_exit=$?
set -e
fge_assert_exit FG-001-PROBE-020 3 "${full_exit}" "full lane refuses before its 15-second execution budget"

set +e
fge_capture release-refusal timeout 15 env VERIFY_ARTIFACT_DIR="${release_root}" "${VERIFY}" release
release_exit=$?
set -e
fge_assert_exit FG-001-PROBE-021 3 "${release_exit}" "release lane refuses before its 15-second execution budget"

shopt -s nullglob
normal_artifacts=("${normal_root}"/*.json)
failure_artifacts=("${failure_root}"/*.json)
no_artifacts=("${no_artifact_root}"/*.json)
full_artifacts=("${full_root}"/*.json)
release_artifacts=("${release_root}"/*.json)
shopt -u nullglob
fge_phase assert
expected_docs_artifact_count=1
if [[ "${docs_outcome}" == 'BLOCKED_ON_BUILD_LOCK' ]]; then
  expected_docs_artifact_count=0
fi
fge_assert_eq FG-001-PROBE-006 "${expected_docs_artifact_count}" "${#normal_artifacts[@]}" "docs either emits one replay artifact or leaves no partial artifact when lock-blocked"
fge_assert_eq FG-001-PROBE-007 2 "${#failure_artifacts[@]}" "each invalid-lane invocation emits an artifact"
fge_assert_eq FG-001-PROBE-008 0 "${#no_artifacts[@]}" "no-artifact escape hatch emits no artifact"
fge_assert_eq FG-001-PROBE-022 1 "${#full_artifacts[@]}" "full refusal emits exactly one artifact"
fge_assert_eq FG-001-PROBE-023 1 "${#release_artifacts[@]}" "release refusal emits exactly one artifact"

docs_artifact="${normal_artifacts[0]:-}"
first_failure_artifact="${failure_artifacts[0]:-}"
second_failure_artifact="${failure_artifacts[1]:-}"
full_artifact="${full_artifacts[0]:-}"
release_artifact="${release_artifacts[0]:-}"
docs_json="$(read_if_regular "${docs_artifact}")"
first_failure_json="$(read_if_regular "${first_failure_artifact}")"
second_failure_json="$(read_if_regular "${second_failure_artifact}")"
if [[ "${docs_outcome}" == 'BLOCKED_ON_BUILD_LOCK' ]]; then
  fge_assert_eq FG-001-PROBE-009 '' "${docs_artifact}" "lock-blocked docs leaves no partial replay artifact"
  fge_assert_eq FG-001-PROBE-010 BLOCKED_ON_BUILD_LOCK "${docs_outcome}" "lock-blocked docs emits the typed bounded-wait outcome"
else
  fge_assert_file FG-001-PROBE-009 "${docs_artifact}" "docs replay artifact exists"
  fge_assert_ndjson FG-001-PROBE-010 "${docs_artifact}" "docs replay artifact is a parseable JSON object"
  fge_assert_contains FG-001-PROBE-011 "${docs_json}" '"schema":"frankengit.verify-replay.v1"' "artifact records its schema"
  fge_assert_contains FG-001-PROBE-012 "${docs_json}" '"lane":"docs"' "artifact records the lane"
  fge_assert_contains FG-001-PROBE-013 "${docs_json}" '"command_argv":[' "artifact records exact argv"
  fge_assert_contains FG-001-PROBE-014 "${docs_json}" '"head":"' "artifact records source revision"
  fge_assert_contains FG-001-PROBE-015 "${docs_json}" '"rustc_version":"' "artifact records the Rust compiler"
  fge_assert_contains FG-001-PROBE-016 "${docs_json}" '"cargo_version":"' "artifact records Cargo"
  fge_assert_contains FG-001-PROBE-017 "${docs_json}" '"captured_output_sha256":"' "artifact records captured output digest"
fi
fge_assert_contains FG-001-PROBE-018 "${first_failure_json}" '"exit_code":2' "artifact records preserved nonzero exit"
first_failure_output_artifact="${first_failure_artifact%.json}.output"
first_failure_output_digest="$(fge_digest_file "${first_failure_output_artifact}" || true)"
first_failure_captured_output_digest="$(artifact_field_sha256 "${first_failure_json}" captured_output_sha256)"
fge_assert_file FG-001-PROBE-026 "${first_failure_output_artifact}" "artifact retains exact captured output bytes"
fge_assert_eq FG-001-PROBE-027 "${first_failure_captured_output_digest}" "${first_failure_output_digest}" "retained output matches the replay artifact digest"
fge_assert_contains FG-001-PROBE-028 "${first_failure_json}" '"captured_output_file":"' "artifact names its retained captured output"
full_json="$(read_if_regular "${full_artifact}")"
release_json="$(read_if_regular "${release_artifact}")"
fge_assert_contains FG-001-PROBE-024 "${full_json}" '"exit_code":3' "full artifact records the typed refusal"
fge_assert_contains FG-001-PROBE-025 "${release_json}" '"exit_code":3' "release artifact records the typed refusal"

first_diff_sha256="$(artifact_field_sha256 "${first_failure_json}" dirty_diff_sha256)"
second_diff_sha256="$(artifact_field_sha256 "${second_failure_json}" dirty_diff_sha256)"
fge_assert_eq FG-001-PROBE-019 "${first_diff_sha256}" "${second_diff_sha256}" "dirty-diff digest is stable for identical source state"

if [[ -f "${docs_artifact}" ]]; then
  fge_artifact "${docs_artifact}" verify-replay-artifact
fi
