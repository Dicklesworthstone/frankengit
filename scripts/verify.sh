#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Replay artifact schema (frankengit.verify-replay.v1), written as one JSON
# object per lane invocation:
#   schema, schema_version, created_at_utc, lane, command_argv, head,
#   dirty, dirty_status, dirty_status_sha256, dirty_diff_sha256,
#   rustc_version, cargo_version, exit_code, wall_time_ms,
#   stdout_sha256, stderr_sha256, captured_output_format,
#   captured_output_file, captured_output_sha256.
# 'captured_output_sha256' hashes the exact bytes of the two captured streams
# under the explicit v1 framing "stdout\0<bytes>\0stderr\0<bytes>". Evidence
# writing retains that exact framed byte stream in the sibling
# 'captured_output_file'. Any evidence-write failure only warns on stderr and
# never replaces the lane's exit status. '--no-artifact' suppresses this wrapper
# for tight local loops.
readonly VERIFY_ARTIFACT_SCHEMA="frankengit.verify-replay.v1"
readonly VERIFY_ARTIFACT_SCHEMA_VERSION=1

export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

# Every cargo invocation below runs on THIS machine.
#
# `cargo` on PATH is the rch shim, which routes `build|test|check|clippy|bench|
# doc|nextest` through `rch exec` to a worker fleet and leaves everything else
# local. Without this export the split falls out of which subcommands the shim
# happens to intercept: `cargo run` (docs, constitution) and `cargo fmt` stayed
# local while check, test and clippy -- the three lanes that decide whether the
# tree is green -- left the machine. Nobody chose that split.
#
# It is also not merely a preference. The shim offloads with
# `RCH_REQUIRE_REMOTE=1`, which does NOT fall back locally, so those lanes could
# not complete at all without a reachable fleet. That contradicts AGENTS.md §16.2
# ("Builds run locally (128 cores): always set RCH_CARGO_WRAPPER_BYPASS=1"), §1's
# "local reproducibility over hosted-service dependence", and §14's review
# question "Can the complete verification/release path run locally?".
#
# Set deliberately rather than defaulted, so re-enabling offload is a visible
# diff to this line and not an environment variable someone exported once.
export RCH_CARGO_WRAPPER_BYPASS=1

echo_step() { printf '\033[1;36m==> %s\033[0m\n' "$*" >&2; }
artifact_warning() { printf 'verify: replay artifact unavailable: %s\n' "$1" >&2 || true; }
print_usage() {
  printf 'usage: %s [--no-artifact] {docs|constitution|fast|full|release}\n' "$0" >&2
}
refuse_dormant() {
  printf '\033[1;33m==> %s\033[0m\n' "$1" >&2
  printf 'This is a typed pre-implementation refusal, not a passing gate.\n' >&2
  exit 3
}

run_docs() {
  echo_step "Checking FrankenGit documentation and registries"
  cargo run --locked -p fgit-registry-check -- docs
}

run_constitution() {
  echo_step "Checking dependency and memory-safety constitution"
  cargo run --locked -p fgit-registry-check -- constitution
  cargo metadata --locked --no-deps --format-version 1 >/dev/null
}

run_fast() {
  run_docs
  run_constitution
  echo_step "Building locally (RCH_CARGO_WRAPPER_BYPASS=${RCH_CARGO_WRAPPER_BYPASS})"
  echo_step "Checking formatting"
  cargo fmt --all -- --check
  echo_step "Checking workspace"
  cargo check --workspace --all-targets --locked
  echo_step "Running workspace tests"
  # --no-fail-fast is mandatory: without it, cargo stops after the first test
  # binary that fails and never runs the rest, so a single red test (e.g. an
  # in-development EXPECTED-RED) silently masks every acceptance test that would
  # have run after it. That truncation produced a false-green orchestrator close
  # of the fg007b/§5.2 acceptance suite; the flag makes every failure visible.
  cargo test --workspace --all-targets --locked --no-fail-fast
  echo_step "Running Clippy"
  cargo clippy --workspace --all-targets --locked -- -D warnings
}

run_full() {
  refuse_dormant "Full conformance/lab/fault/fuzz/corpus lane is not implemented yet"
}

run_release() {
  # D14 (license model) is launch-blocking, and it is checked FIRST and on its
  # own. The dormancy refusal below is TEMPORARY: FG-035/FG-091 remove it the
  # day a releasable binary exists. A launch-blocking licensing requirement that
  # rode on that refusal would silently disappear at exactly the moment it
  # starts to matter, so it does not ride on it. See FG-062 and
  # docs/LICENSING_DECISION.md; the gate exits 3 while the decision is deferred.
  echo_step "Checking the D14 license gate"
  "$ROOT/scripts/license_gate.sh"

  # The runner probe is intentionally narrower than a release attempt: target
  # builds require a caller-supplied durable root, exact matrix, and bounded
  # fgit-runner obligation. Calling the repository-owned entrypoint here keeps
  # release behavior out of workflow YAML while the lane below remains a typed
  # exit-3 refusal until the complete native matrix exists.
  echo_step "Checking DSR release-attempt runner wiring"
  cargo run --locked -p fgit-release --bin fgit-release-attempt -- --release-gate-probe

  refuse_dormant "No releasable FrankenGit binary or complete native target matrix exists yet"
}

run_lane() {
  case "$1" in
    docs) run_docs ;;
    constitution) run_constitution ;;
    fast) run_fast ;;
    full) run_full ;;
    release) run_release ;;
    *)
      print_usage
      return 2
      ;;
  esac
}

json_escape() {
  local value="$1"
  local escaped=""
  local character=""
  local ordinal=0
  local index=0

  for ((index = 0; index < ${#value}; index++)); do
    character="${value:index:1}"
    case "${character}" in
      '"') escaped+='\"' ;;
      '\') escaped+='\\' ;;
      $'\b') escaped+='\b' ;;
      $'\f') escaped+='\f' ;;
      $'\n') escaped+='\n' ;;
      $'\r') escaped+='\r' ;;
      $'\t') escaped+='\t' ;;
      *)
        if [[ "${character}" =~ [[:cntrl:]] ]]; then
          printf -v ordinal '%d' "'${character}"
          printf -v character '\\u%04x' "${ordinal}"
        fi
        escaped+="${character}"
        ;;
    esac
  done
  printf '%s' "${escaped}"
}

json_array() {
  local item=""
  local separator=""
  local result='['

  for item in "$@"; do
    result+="${separator}\"$(json_escape "${item}")\""
    separator=','
  done
  result+=']'
  printf '%s' "${result}"
}

sha256_stdin() {
  local digest=""
  local remainder=""

  if command -v sha256sum >/dev/null 2>&1; then
    if ! read -r digest remainder < <(sha256sum); then
      return 1
    fi
  elif command -v shasum >/dev/null 2>&1; then
    if ! read -r digest remainder < <(shasum -a 256); then
      return 1
    fi
  else
    return 1
  fi
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

sha256_file() {
  local path="$1"
  [[ -f "${path}" ]] || return 1
  sha256_stdin < "${path}"
}

now_epoch_ns() {
  local value=""

  value="$(date +%s%N 2>/dev/null || true)"
  if [[ "${value}" =~ ^[0-9]{19,}$ ]]; then
    printf '%s\n' "${value}"
  else
    value="$(date +%s 2>/dev/null || printf '0')"
    printf '%s000000000\n' "${value}"
  fi
}

tool_version() {
  local tool="$1"

  if command -v "${tool}" >/dev/null 2>&1; then
    "${tool}" -V 2>&1 || printf 'unavailable'
  else
    printf 'unavailable'
  fi
}

capture_source_state() {
  VERIFY_HEAD="$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
  VERIFY_DIRTY_STATUS="$(git -c color.status=false status --porcelain=v1 --untracked-files=all 2>/dev/null || true)"
  VERIFY_DIRTY=false
  if [[ -n "${VERIFY_DIRTY_STATUS}" ]]; then
    VERIFY_DIRTY=true
  fi
  VERIFY_RUSTC_VERSION="$(tool_version rustc)"
  VERIFY_CARGO_VERSION="$(tool_version cargo)"

  if ! VERIFY_DIRTY_STATUS_SHA256="$(printf '%s' "${VERIFY_DIRTY_STATUS}" | sha256_stdin)"; then
    VERIFY_DIRTY_STATUS_SHA256=''
    artifact_warning 'cannot hash dirty status'
  fi
  if ! VERIFY_DIRTY_DIFF_SHA256="$(git -c color.ui=false diff --binary HEAD 2>/dev/null | sha256_stdin)"; then
    VERIFY_DIRTY_DIFF_SHA256=''
    artifact_warning 'cannot hash dirty diff'
  fi
}

emit_captured_output() {
  local stdout_path="$1"
  local stderr_path="$2"

  printf 'stdout\0'
  cat -- "${stdout_path}"
  printf '\0stderr\0'
  cat -- "${stderr_path}"
}

artifact_timestamp_utc() {
  local nanoseconds=""
  local seconds=""

  # Do not depend on a particular `date -u` implementation accepting a literal
  # trailing Z alongside %N.  POSIX date does not define %N, so accept it only
  # when it expands to the complete numeric subsecond suffix and otherwise
  # take the portable seconds-resolution path.  LC_ALL and TZ are deliberately
  # set for this command rather than inherited from the lane environment.
  nanoseconds="$(LC_ALL=C TZ=UTC0 date '+%Y%m%dT%H%M%S%N' 2>/dev/null || true)"
  if [[ "${nanoseconds}" =~ ^[0-9]{8}T[0-9]{6}[0-9]{9}$ ]]; then
    printf '%sZ\n' "${nanoseconds}"
    return 0
  fi

  seconds="$(LC_ALL=C TZ=UTC0 date '+%Y%m%dT%H%M%S' 2>/dev/null || true)"
  if [[ "${seconds}" =~ ^[0-9]{8}T[0-9]{6}$ ]]; then
    printf '%sZ\n' "${seconds}"
    return 0
  fi

  return 1
}

write_replay_artifact() {
  local lane_name="$1"
  local command_json="$2"
  local started_ns="$3"
  local finished_ns="$4"
  local lane_exit="$5"
  local stdout_path="$6"
  local stderr_path="$7"
  local artifact_root="${VERIFY_ARTIFACT_DIR:-${ROOT}/evidence/verify}"
  local timestamp=""
  local artifact_path=""
  local output_path=""
  local temporary_artifact_path=""
  local temporary_output_path=""
  local wall_time_ms=0
  local stdout_sha256=""
  local stderr_sha256=""
  local captured_output_sha256=""

  if ! timestamp="$(artifact_timestamp_utc)"; then
    artifact_warning 'cannot format a UTC artifact timestamp'
    return 0
  fi
  artifact_path="${artifact_root}/${timestamp}-${lane_name}.json"
  output_path="${artifact_root}/${timestamp}-${lane_name}.output"
  wall_time_ms=$(((finished_ns - started_ns) / 1000000))

  if ! stdout_sha256="$(sha256_file "${stdout_path}")"; then
    artifact_warning 'cannot hash captured stdout'
    return 0
  fi
  if ! stderr_sha256="$(sha256_file "${stderr_path}")"; then
    artifact_warning 'cannot hash captured stderr'
    return 0
  fi
  if ! mkdir -p "${artifact_root}"; then
    artifact_warning "cannot create ${artifact_root}"
    return 0
  fi
  if [[ -e "${artifact_path}" || -e "${output_path}" ]]; then
    artifact_warning "refusing to overwrite ${artifact_path} or its captured output"
    return 0
  fi
  if ! temporary_output_path="$(mktemp "${artifact_root}/.verify-output.XXXXXXXX")"; then
    artifact_warning "cannot allocate captured output for ${artifact_path}"
    return 0
  fi
  if ! emit_captured_output "${stdout_path}" "${stderr_path}" > "${temporary_output_path}"; then
    artifact_warning "cannot retain captured output for ${artifact_path}"
    rm -f -- "${temporary_output_path}" || true
    return 0
  fi
  if ! captured_output_sha256="$(sha256_file "${temporary_output_path}")"; then
    artifact_warning 'cannot hash retained captured output'
    rm -f -- "${temporary_output_path}" || true
    return 0
  fi
  if ! temporary_artifact_path="$(mktemp "${artifact_root}/.verify-artifact.XXXXXXXX")"; then
    artifact_warning "cannot allocate an artifact in ${artifact_root}"
    rm -f -- "${temporary_output_path}" || true
    return 0
  fi

  if ! {
    printf '{'
    printf '"schema":"%s",' "$(json_escape "${VERIFY_ARTIFACT_SCHEMA}")"
    printf '"schema_version":%s,' "${VERIFY_ARTIFACT_SCHEMA_VERSION}"
    printf '"created_at_utc":"%s",' "$(json_escape "${timestamp}")"
    printf '"lane":"%s",' "$(json_escape "${lane_name}")"
    printf '"command_argv":%s,' "${command_json}"
    printf '"head":"%s",' "$(json_escape "${VERIFY_HEAD}")"
    printf '"dirty":%s,' "${VERIFY_DIRTY}"
    printf '"dirty_status":"%s",' "$(json_escape "${VERIFY_DIRTY_STATUS}")"
    printf '"dirty_status_sha256":"%s",' "${VERIFY_DIRTY_STATUS_SHA256}"
    printf '"dirty_diff_sha256":"%s",' "${VERIFY_DIRTY_DIFF_SHA256}"
    printf '"rustc_version":"%s",' "$(json_escape "${VERIFY_RUSTC_VERSION}")"
    printf '"cargo_version":"%s",' "$(json_escape "${VERIFY_CARGO_VERSION}")"
    printf '"exit_code":%s,' "${lane_exit}"
    printf '"wall_time_ms":%s,' "${wall_time_ms}"
    printf '"stdout_sha256":"%s",' "${stdout_sha256}"
    printf '"stderr_sha256":"%s",' "${stderr_sha256}"
    printf '"captured_output_format":"stdout\\u0000<bytes>\\u0000stderr\\u0000<bytes>",'
    printf '"captured_output_file":"%s",' "$(json_escape "${timestamp}-${lane_name}.output")"
    printf '"captured_output_sha256":"%s"}\n' "${captured_output_sha256}"
  } > "${temporary_artifact_path}"; then
    artifact_warning "cannot write ${artifact_path}"
    rm -f -- "${temporary_artifact_path}" "${temporary_output_path}" || true
    return 0
  fi
  if ! mv -- "${temporary_output_path}" "${output_path}"; then
    artifact_warning "cannot publish captured output for ${artifact_path}"
    rm -f -- "${temporary_artifact_path}" "${temporary_output_path}" || true
    return 0
  fi
  if ! mv -- "${temporary_artifact_path}" "${artifact_path}"; then
    artifact_warning "cannot publish ${artifact_path}"
    rm -f -- "${temporary_artifact_path}" "${output_path}" || true
    return 0
  fi
}

artifact_enabled=true
declare -a command_argv=("$0" "$@")
declare -a lane_args=()
argument=""
for argument in "$@"; do
  if [[ "${argument}" == "--no-artifact" ]]; then
    artifact_enabled=false
  else
    lane_args+=("${argument}")
  fi
done

if [[ "${#lane_args[@]}" -ne 1 ]]; then
  print_usage
  exit 2
fi
lane="${lane_args[0]}"

if [[ "${artifact_enabled}" == false ]]; then
  run_lane "${lane}"
  exit "$?"
fi

capture_source_state
command_json="$(json_array "${command_argv[@]}")"
started_ns="$(now_epoch_ns)"
if ! stdout_path="$(mktemp "${TMPDIR:-/tmp}/frankengit-verify-stdout.XXXXXXXX")"; then
  artifact_warning 'cannot allocate stdout capture; running lane without an artifact'
  set +e
  (
    set -e
    run_lane "${lane}"
  )
  lane_exit=$?
  set -e
  exit "${lane_exit}"
fi
if ! stderr_path="$(mktemp "${TMPDIR:-/tmp}/frankengit-verify-stderr.XXXXXXXX")"; then
  artifact_warning 'cannot allocate stderr capture; running lane without an artifact'
  rm -f -- "${stdout_path}" || true
  set +e
  (
    set -e
    run_lane "${lane}"
  )
  lane_exit=$?
  set -e
  exit "${lane_exit}"
fi

set +e
(
  set -e
  run_lane "${lane}"
) > "${stdout_path}" 2> "${stderr_path}"
lane_exit=$?
set -e
finished_ns="$(now_epoch_ns)"
write_replay_artifact "${lane}" "${command_json}" "${started_ns}" "${finished_ns}" "${lane_exit}" "${stdout_path}" "${stderr_path}"

if ! cat -- "${stdout_path}"; then
  artifact_warning 'cannot replay captured stdout'
fi
if ! cat -- "${stderr_path}" >&2; then
  artifact_warning 'cannot replay captured stderr'
fi
rm -f -- "${stdout_path}" "${stderr_path}" || true
exit "${lane_exit}"
