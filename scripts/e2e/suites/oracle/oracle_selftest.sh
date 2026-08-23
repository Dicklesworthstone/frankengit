#!/usr/bin/env bash
# e2e: prove that the pinned upstream-Git oracle fails closed on pin, input,
# version, user-configuration, and sandbox-boundary violations.
#
# These tests use a fake Git plus a fake Bubblewrap launcher only to validate
# harness mechanics. They are not upstream-Git conformance evidence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=../../lib.sh
. "${SCRIPT_DIR}/../../lib.sh"

ORACLE="${SCRIPT_DIR}/../../oracle/oracle.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/fgit-oracle-selftest.XXXXXXXX")"

fge_init oracle-selftest
fge_cleanup_register rm -rf -- "${TEST_ROOT}"

expect_exit() {
    local acceptance_id="$1"
    local expected="$2"
    local description="$3"
    local actual=0

    shift 3
    set +e
    "$@" >"${TEST_ROOT}/${acceptance_id}.stdout" 2>"${TEST_ROOT}/${acceptance_id}.stderr"
    actual=$?
    set -e
    fge_assert_exit "${acceptance_id}" "${expected}" "${actual}" "${description}"
}

expect_file_contains() {
    local acceptance_id="$1"
    local needle="$2"
    local file="$3"
    local description="$4"

    if grep -F --quiet -- "${needle}" "${file}"; then
        fge_pass "${acceptance_id}" "${description}"
    else
        fge_fail "${acceptance_id}" "${description}: missing ${needle} in ${file}"
    fi
}

write_fake_receipt() {
    local binary_sha256="$1"
    cat > "${TEST_ROOT}/oracle-root/installs/testgit/receipt.tsv" <<EOF
schema_version=1
id=testgit
version=1.0.0
tag=v1.0.0
commit=1111111111111111111111111111111111111111
source_url=https://www.kernel.org/pub/software/scm/git/git-1.0.0.tar.xz
source_sha256=0000000000000000000000000000000000000000000000000000000000000000
binary_relative_path=bin/git
binary_sha256=${binary_sha256}
version_line=git version 1.0.0
build_flags=NO_TCLTK=YesPlease;NO_GETTEXT=YesPlease
EOF
}

mkdir -p \
    "${TEST_ROOT}/bin" \
    "${TEST_ROOT}/user-home" \
    "${TEST_ROOT}/oracle-root/installs/testgit/bin" \
    "${TEST_ROOT}/oracle-root/installs/testgit/libexec/git-core"
{
    printf '%s\n' '# fgit-git-oracle-pins-v1'
    printf '%s\n' '# id version tag commit source_url source_sha256 archive_name'
    printf 'testgit\t1.0.0\tv1.0.0\t1111111111111111111111111111111111111111\thttps://www.kernel.org/pub/software/scm/git/git-1.0.0.tar.xz\t0000000000000000000000000000000000000000000000000000000000000000\tgit-1.0.0.tar.xz\n'
} > "${TEST_ROOT}/pins.tsv"
cat > "${TEST_ROOT}/oracle-root/installs/testgit/bin/git" <<'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then
    printf 'git version 1.0.0\n'
    exit 0
fi
if [ "$1" = "emit" ]; then
    [ "${HOME}" = /home/oracle ] || exit 31
    [ "${GIT_CONFIG_NOSYSTEM}" = 1 ] || exit 32
    [ "${GIT_CONFIG_GLOBAL}" = /dev/null ] || exit 33
    [ "${GIT_CONFIG_COUNT}" = 2 ] || exit 34
    [ "${GIT_CONFIG_KEY_0}" = core.hooksPath ] || exit 35
    [ "${GIT_CONFIG_VALUE_0}" = /home/oracle/empty-hooks ] || exit 36
    [ "${GIT_CONFIG_KEY_1}" = credential.helper ] || exit 37
    [ "${GIT_CONFIG_VALUE_1}" = "" ] || exit 38
    [ "${GIT_ASKPASS}" = /bin/false ] || exit 39
    [ "${GIT_TERMINAL_PROMPT}" = 0 ] || exit 40
    printf 'stable stdout\n'
    printf 'stable stderr\n' >&2
    exit 0
fi
if [ "$1" = "clone" ]; then
    [ "${GIT_ALLOW_PROTOCOL}" = git ] || exit 41
    [ "$2" = "--no-local" ] || exit 42
    [ "$3" = "git://127.0.0.1:9418/11111111111111111111111111111111.git" ] || exit 43
    [ "$4" = "loopback-clone" ] || exit 44
    printf 'loopback clone accepted\n'
    exit 0
fi
printf 'unexpected fake git invocation\n' >&2
exit 2
EOF
chmod 700 "${TEST_ROOT}/oracle-root/installs/testgit/bin/git"

FAKE_GIT="${TEST_ROOT}/oracle-root/installs/testgit/bin/git"
cp --preserve=mode -- "${FAKE_GIT}" "${TEST_ROOT}/valid-git"
read -r FAKE_HASH _ < <(sha256sum "${FAKE_GIT}")
write_fake_receipt "${FAKE_HASH}"

cat > "${TEST_ROOT}/bin/bwrap" <<'EOF'
#!/bin/sh
clearenv=false
sandbox_home=''
sandbox_path=''
config_nosystem=''
config_global=''
config_count=''
config_key_0=''
config_value_0=''
config_key_1=''
config_value_1=''
askpass=''
terminal_prompt=''
allowed_protocol=''

while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    printf '%s\n' "$1" >> "${FGIT_ORACLE_BWRAP_LOG}"
    case "$1" in
        --clearenv)
            clearenv=true
            ;;
        --setenv)
            shift
            [ "$#" -ge 2 ] || exit 95
            key=$1
            printf '%s\n' "$key" >> "${FGIT_ORACLE_BWRAP_LOG}"
            shift
            value=$1
            printf '%s\n' "$value" >> "${FGIT_ORACLE_BWRAP_LOG}"
            case "$key" in
                HOME) sandbox_home=$value ;;
                PATH) sandbox_path=$value ;;
                GIT_CONFIG_NOSYSTEM) config_nosystem=$value ;;
                GIT_CONFIG_GLOBAL) config_global=$value ;;
                GIT_CONFIG_COUNT) config_count=$value ;;
                GIT_CONFIG_KEY_0) config_key_0=$value ;;
                GIT_CONFIG_VALUE_0) config_value_0=$value ;;
                GIT_CONFIG_KEY_1) config_key_1=$value ;;
                GIT_CONFIG_VALUE_1) config_value_1=$value ;;
                GIT_ASKPASS) askpass=$value ;;
                GIT_TERMINAL_PROMPT) terminal_prompt=$value ;;
                GIT_ALLOW_PROTOCOL) allowed_protocol=$value ;;
            esac
            ;;
    esac
    shift
done

[ "$#" -gt 0 ] || exit 97
shift
if [ "$1" = /usr/bin/true ]; then
    exit 0
fi
if [ "$1" = /oracle/bin/git ]; then
    [ "$clearenv" = true ] || exit 96
    shift
    exec env -i \
        "HOME=${sandbox_home}" \
        "PATH=${sandbox_path}" \
        "GIT_CONFIG_NOSYSTEM=${config_nosystem}" \
        "GIT_CONFIG_GLOBAL=${config_global}" \
        "GIT_CONFIG_COUNT=${config_count}" \
        "GIT_CONFIG_KEY_0=${config_key_0}" \
        "GIT_CONFIG_VALUE_0=${config_value_0}" \
        "GIT_CONFIG_KEY_1=${config_key_1}" \
        "GIT_CONFIG_VALUE_1=${config_value_1}" \
        "GIT_ASKPASS=${askpass}" \
        "GIT_TERMINAL_PROMPT=${terminal_prompt}" \
        "GIT_ALLOW_PROTOCOL=${allowed_protocol}" \
        "${FGIT_ORACLE_FAKE_GIT}" "$@"
fi
exit 98
EOF
chmod 700 "${TEST_ROOT}/bin/bwrap"

printf '[credential]\n\thelper = hostile-helper\n' > "${TEST_ROOT}/user-home/.gitconfig"
export FGIT_ORACLE_ROOT="${TEST_ROOT}/oracle-root"
export FGIT_ORACLE_PIN_MANIFEST="${TEST_ROOT}/pins.tsv"
export FGIT_ORACLE_BWRAP_LOG="${TEST_ROOT}/bwrap.log"
export FGIT_ORACLE_FAKE_GIT="${FAKE_GIT}"
export HOME="${TEST_ROOT}/user-home"
export GIT_CONFIG_GLOBAL="${TEST_ROOT}/user-home/.gitconfig"
export PATH="${TEST_ROOT}/bin:/usr/bin:/bin"

fge_phase action
expect_exit FG-000B-ORACLE-001 64 "unpinned Git identity is refused" "${ORACLE}" verify unknown-git
expect_exit FG-000B-ORACLE-002 69 "missing source archive reports UNAVAILABLE" "${ORACLE}" build testgit

printf '#!/bin/sh\nprintf "git version 9.9.9\\n"\n' > "${FAKE_GIT}"
chmod 700 "${FAKE_GIT}"
read -r WRONG_HASH _ < <(sha256sum "${FAKE_GIT}")
write_fake_receipt "${WRONG_HASH}"
expect_exit FG-000B-ORACLE-003 64 "wrong installed Git version is refused" "${ORACLE}" verify testgit
cp --preserve=mode -- "${TEST_ROOT}/valid-git" "${FAKE_GIT}"
read -r FAKE_HASH _ < <(sha256sum "${FAKE_GIT}")
write_fake_receipt "${FAKE_HASH}"

mkdir -p "${TEST_ROOT}/no-bwrap-bin"
for required_command in bash dirname mkdir sha256sum; do
    required_path="$(command -v "${required_command}")"
    ln -s "${required_path}" "${TEST_ROOT}/no-bwrap-bin/${required_command}"
done
export PATH="${TEST_ROOT}/no-bwrap-bin"
expect_exit FG-000B-ORACLE-012 69 "missing Bubblewrap reports typed UNAVAILABLE without an unsandboxed fallback" \
    "${ORACLE}" verify testgit
export PATH="${TEST_ROOT}/bin:/usr/bin:/bin"

RUN_DIRECTORY="$("${ORACLE}" create-run testgit reproducible)"
expect_exit FG-000B-ORACLE-004 64 "sandbox path-steering argument is refused" \
    "${ORACLE}" capture testgit "${RUN_DIRECTORY}" . escape -- --git-dir=/etc
expect_exit FG-000B-ORACLE-013 64 "loopback mode refuses a non-loopback endpoint before Git starts" \
    "${ORACLE}" clone-loopback testgit "${RUN_DIRECTORY}" nonloopback 192.0.2.1:9418 \
      /11111111111111111111111111111111.git loopback-clone
"${ORACLE}" capture testgit "${RUN_DIRECTORY}" . first -- emit >/dev/null
FIRST_CAPTURE_EXIT=$?
fge_assert_exit FG-000B-ORACLE-005 0 "${FIRST_CAPTURE_EXIT}" "permitted oracle command captures exact bytes"
"${ORACLE}" capture testgit "${RUN_DIRECTORY}" . second -- emit >/dev/null
SECOND_CAPTURE_EXIT=$?
fge_assert_exit FG-000B-ORACLE-006 0 "${SECOND_CAPTURE_EXIT}" "near-identical permitted oracle command is not refused"
"${ORACLE}" compare "${RUN_DIRECTORY}/transcripts/first" "${RUN_DIRECTORY}/transcripts/second" byte_equal > "${TEST_ROOT}/verdict.json"
"${ORACLE}" clone-loopback testgit "${RUN_DIRECTORY}" loopback 127.0.0.1:9418 \
  /11111111111111111111111111111111.git loopback-clone >/dev/null
LOOPBACK_CAPTURE_EXIT=$?

fge_phase assert
expect_file_contains FG-000B-ORACLE-007 '"classification":"byte_equal"' "${TEST_ROOT}/verdict.json" "identical transcripts receive a byte-equal NDJSON verdict"
expect_file_contains FG-000B-ORACLE-008 --clearenv "${FGIT_ORACLE_BWRAP_LOG}" "Bubblewrap clears inherited environment"
expect_file_contains FG-000B-ORACLE-009 GIT_CONFIG_GLOBAL "${FGIT_ORACLE_BWRAP_LOG}" "oracle explicitly disables the caller global config"
expect_file_contains FG-000B-ORACLE-010 credential.helper "${FGIT_ORACLE_BWRAP_LOG}" "oracle disables credential helpers at command scope"
fge_assert_exit FG-000B-ORACLE-014 0 "${LOOPBACK_CAPTURE_EXIT}" "bounded loopback clone mode accepts only its fixed Git invocation"
expect_file_contains FG-000B-ORACLE-015 --share-net "${FGIT_ORACLE_BWRAP_LOG}" "loopback mode opts into the host loopback network namespace"
expect_file_contains FG-000B-ORACLE-016 'GIT_ALLOW_PROTOCOL' "${FGIT_ORACLE_BWRAP_LOG}" "loopback mode declares its transport allowlist"
expect_file_contains FG-000B-ORACLE-017 'network_profile=loopback-git-only' "${RUN_DIRECTORY}/transcripts/loopback/receipt.tsv" "loopback transcript records the constrained network profile"
expect_file_contains FG-000B-ORACLE-018 'allowed_endpoint=127.0.0.1:9418' "${RUN_DIRECTORY}/transcripts/loopback/receipt.tsv" "loopback transcript binds the single allowed endpoint"
expect_file_contains FG-000B-ORACLE-019 'oracle_id=testgit' "${RUN_DIRECTORY}/transcripts/loopback/receipt.tsv" "loopback transcript binds the pinned Git identity"
if grep -F --quiet -- "${HOME}" "${FGIT_ORACLE_BWRAP_LOG}"; then
    fge_fail FG-000B-ORACLE-011 "user HOME leaked into the Bubblewrap invocation"
else
    fge_pass FG-000B-ORACLE-011 "user HOME is absent from the Bubblewrap invocation"
fi
fge_artifact "${TEST_ROOT}/verdict.json" oracle-verdict
