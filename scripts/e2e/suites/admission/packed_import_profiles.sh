#!/usr/bin/env bash
# e2e: real multi-pack import, bounded refusal, cold integrity and key recovery.
# Git builds isolated fixtures only; no production Git subprocess is introduced.
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'packed import requires a prebuilt FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init packed-import-profiles
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.28
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context git_version "$(git --version)"
fge_context git_digest "$(fge_digest_file "$(command -v git)")"
fge_context non_claim 'Source-fixture and scoped local import evidence, not general Git conformance or a throughput benchmark.'
WORK="$(fge_tempdir packed-import-profiles)"
fge_phase action
fge_run_timeout 1800 PACKED-IMPORT-001 python3 - "$FG_BIN" "$WORK" <<'PY'
import hashlib, json, os, pathlib, shutil, subprocess, sys, time
fg, root = sys.argv[1], pathlib.Path(sys.argv[2])
tenant, repository, principal = '1' * 32, '2' * 32, '3' * 32
home = root / 'home'; home.mkdir()
env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_AUTHOR_NAME='Packed fixture', GIT_COMMITTER_NAME='Packed fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_EMAIL='fixture@example.invalid', GIT_AUTHOR_DATE='2000-01-01T00:00:00 +0000', GIT_COMMITTER_DATE='2000-01-01T00:00:00 +0000')
sequence = 0
records = []
def run(label, args, expected=0, data=None):
    global sequence
    sequence += 1
    start = time.monotonic()
    result = subprocess.run([str(x) for x in args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=900)
    name = f'{sequence:03d}-{label}'
    (root / (name + '.out')).write_bytes(result.stdout)
    (root / (name + '.err')).write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr); sys.stderr.buffer.flush()
    record = {'acceptance': label, 'exit_code': result.returncode, 'expected_exit': expected, 'elapsed_seconds': time.monotonic() - start}
    records.append(record)
    (root / 'commands.json').write_text(json.dumps(records, indent=2))
    assert result.returncode == expected, (label, result.returncode, result.stdout[-1000:], result.stderr[-1000:])
    return result.stdout

def campaign(format, blob_bytes, large):
    label = format + ('-large' if large else '-small')
    source, store = root / (label + '-source'), root / (label + '-node')
    run(label + '-fixture', ['git', 'init', '-q', '--bare', '-b', 'main', '--object-format=' + format, '--template=', source])
    groups = [[], [], []]; tree_lines = []; all_ids = []
    for ordinal in range(9):
        body = bytes([33 + ordinal]) * blob_bytes
        oid = run(label + '-blob', ['git', '-C', source, 'hash-object', '-w', '--stdin'], data=body).decode().strip()
        groups[ordinal // 3].append(oid); all_ids.append(oid)
        tree_lines.append(f'100644 blob {oid}\tfile{ordinal}\n')
    tree = run(label + '-tree', ['git', '-C', source, 'mktree'], data=''.join(tree_lines).encode()).decode().strip()
    commit = run(label + '-commit', ['git', '-C', source, 'commit-tree', tree], data=b'multi-pack import\n').decode().strip()
    groups[2].extend([tree, commit]); all_ids.extend([tree, commit])
    run(label + '-ref', ['git', '-C', source, 'update-ref', 'refs/heads/main', commit])
    for index, group in enumerate(groups):
        payload = run(label + '-pack', ['git', '-C', source, '-c', 'pack.threads=1', 'pack-objects', '--stdout', '--window=0', '--compression=1'], data=('\n'.join(group) + '\n').encode())
        path = source / 'objects' / 'pack' / f'part-{index}.pack'; path.write_bytes(payload)
        run(label + '-index', ['git', '-C', source, 'index-pack', '--index-version=2', path])
    for oid in all_ids:
        (source / 'objects' / oid[:2] / oid[2:]).unlink()
    run(label + '-fixture-fsck', ['git', '-C', source, 'fsck', '--strict', '--no-reflogs'])
    profile = '192' if large else '4'
    key = label + '-migration'
    args = ['import', store, tenant, repository, principal, key, source, '--max-expanded-mib', profile, '--timeout-secs', '600', '--json']
    baseline = os.environ.get('FG_PACKED_BASELINE_BIN')
    if large and baseline:
        before_store = root / (label + '-before')
        run(label + '-before-init', [baseline, 'init', before_store, tenant, repository, format])
        before_args = list(args); before_args[1] = before_store
        run(label + '-before-128mib-refusal', [baseline, *before_args], expected=2)
        refs = json.loads(run(label + '-before-refs', [baseline, 'refs', before_store, tenant, repository, '--trusted-local', '--object-format', format]))
        assert refs['references'] == []
    run(label + '-init', [fg, 'init', store, tenant, repository, format])
    if not large:
        small = list(args); small[small.index('--max-expanded-mib') + 1] = '1'
        run(label + '-small-limit', [fg, *small], expected=2)
        refs = json.loads(run(label + '-unchanged', [fg, 'refs', store, tenant, repository, '--trusted-local', '--object-format', format]))
        assert refs['references'] == []
    receipt = json.loads(run(label + '-admit', [fg, *args]))
    assert receipt['state'] == 'committed' and receipt['command_count'] == 1 and receipt['node_closed']
    refs = json.loads(run(label + '-refs', [fg, 'refs', store, tenant, repository, '--trusted-local', '--object-format', format]))
    assert len(refs['references']) == 1 and commit in json.dumps(refs)
    shutil.rmtree(source)
    run(label + '-cold-integrity', [fg, 'fsck', store, tenant, repository, '--trusted-local', '--object-format', format, '--max-bytes', str(192 * 1024 * 1024), '--timeout-secs', '600'])
    recovered = json.loads(run(label + '-recover', [fg, 'outcome', store, tenant, repository, '--trusted-local', '--principal', principal, '--idempotency-key', key, '--object-format', format]))
    assert recovered['state'] == 'committed' and recovered['transaction']['tx_id'] == receipt['tx_id']
    assert not list(store.glob('.fg-import-quarantine-*'))
    print(json.dumps({'acceptance': label, 'status': 'pass', 'native_objects': 11, 'blob_payload_bytes': 9 * blob_bytes, 'profile_mib': int(profile), 'source_removed': True}), flush=True)

for format in ['sha1', 'sha256']:
    campaign(format, 256 * 1024, False)
if os.environ.get('FG_PACKED_LARGE') == '1':
    campaign('sha256', 16 * 1024 * 1024, True)
PY
fge_phase assert
fge_assert_eq PACKED-IMPORT-EXIT 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/commands.json" command_results
