#!/usr/bin/env bash
# e2e: explicit import byte limits preserve native admission and retry identity.
# Git is an isolated fixture oracle, never a production dependency.
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'import profiles requires a prebuilt FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init import-profiles
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.28
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context git_version "$(git --version)"
fge_context git_digest "$(fge_digest_file "$(command -v git)")"
fge_context non_claim 'Bounded binary profile/refusal/retry coverage, not a throughput or hostile-host isolation claim.'
WORK="$(fge_tempdir import-profiles)"
fge_phase action
fge_run_timeout 300 IMPORT-PROFILES-001 python3 - "$FG_BIN" "$WORK" <<'PY'
import json, os, pathlib, subprocess, sys
fg, root = sys.argv[1], pathlib.Path(sys.argv[2])
tenant, repository, principal = '1' * 32, '2' * 32, '3' * 32
home = root / 'home'; home.mkdir()
env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_AUTHOR_NAME='Fixture', GIT_COMMITTER_NAME='Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_EMAIL='fixture@example.invalid', GIT_AUTHOR_DATE='2000-01-01T00:00:00 +0000', GIT_COMMITTER_DATE='2000-01-01T00:00:00 +0000')
def run(label, args, expected=0, data=None):
    result = subprocess.run([str(x) for x in args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=120)
    (root / (label + '.out')).write_bytes(result.stdout)
    (root / (label + '.err')).write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr); sys.stderr.buffer.flush()
    assert result.returncode == expected, (label, result.returncode, expected, result.stdout, result.stderr)
    print(json.dumps({'case': label, 'expected_exit': expected, 'actual_exit': result.returncode}), flush=True)
    return result.stdout.decode(), result.stderr.decode()
for fmt in ['sha1', 'sha256']:
    source, store = root / (fmt + '-source'), root / (fmt + '-node')
    key = 'profile-' + fmt
    import_args = [fg, 'import', store, tenant, repository, principal, key, source, '--json']
    for number in ['0', '16385']:
        run(fmt + '-bad-' + number, import_args + ['--max-expanded-mib', number], 2)
        assert not store.exists(), 'malformed profile must fail before node creation'
    run(fmt + '-fixture-init', ['git', 'init', '-q', '--bare', '-b', 'main', '--object-format=' + fmt, '--template=', source])
    payload = bytes(range(256)) * 8192
    blob = run(fmt + '-fixture-blob', ['git', '-C', source, '-c', 'core.compression=0', 'hash-object', '-w', '--stdin'], data=payload)[0].strip()
    tree = run(fmt + '-fixture-tree', ['git', '-C', source, 'mktree'], data=('100644 blob ' + blob + '\tdata.bin\n').encode())[0].strip()
    tip = run(fmt + '-fixture-commit', ['git', '-C', source, 'commit-tree', tree], data=b'import profile fixture\n')[0].strip()
    run(fmt + '-fixture-ref', ['git', '-C', source, 'update-ref', 'refs/heads/main', tip])
    run(fmt + '-init', [fg, 'init', store, tenant, repository, fmt])
    refs = [fg, 'refs', store, tenant, repository, '--trusted-local', '--object-format', fmt, '--limit', '100']
    empty = json.loads(run(fmt + '-empty', refs)[0])
    out, err = run(fmt + '-short', import_args + ['--max-expanded-mib', '1'], 2)
    assert 'exceed import limit' in err and not out
    assert json.loads(run(fmt + '-unchanged', refs)[0]) == empty
    assert not list(store.glob('.fg-import-quarantine-*'))
    accepted = json.loads(run(fmt + '-exact', import_args + ['--max-expanded-mib', '4'])[0])
    assert accepted['state'] == 'committed' and accepted['atomic'] and accepted['node_closed']
    selected = json.loads(run(fmt + '-selected', refs)[0])
    assert selected['references'] == [{'reference_hex': b'refs/heads/main'.hex(), 'tip': tip}]
    for number in ['8', '16384']:
        assert json.loads(run(fmt + '-retry-' + number, import_args + ['--max-expanded-mib', number])[0]) == accepted
    assert json.loads(run(fmt + '-legacy-retry', import_args)[0]) == accepted
    source.rename(root / (fmt + '-source-offline'))
    recovered = json.loads(run(fmt + '-outcome', [fg, 'outcome', store, tenant, repository, '--trusted-local', '--principal', principal, '--idempotency-key', key, '--object-format', fmt])[0])
    assert recovered['transaction']['tx_id'] == accepted['tx_id']
    assert recovered['state'] == 'committed'
    assert json.loads(run(fmt + '-final-refs', refs)[0]) == selected
    print(json.dumps({'case': fmt + '-complete', 'payload_bytes': len(payload), 'transaction': accepted['tx_id'], 'refusal_preserved_refs': True, 'same_terminal_across_profiles': True, 'source_free_recovery': True}), flush=True)
PY
fge_assert_exit IMPORT-PROFILES-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_note IMPORT-PROFILES-003 'Both native hash domains exercised real fg refusal, publication, profile-independent replay and source-free recovery.'
