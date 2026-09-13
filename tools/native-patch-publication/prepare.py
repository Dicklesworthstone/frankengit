from pathlib import Path
import base64
import hashlib
import json
import lzma
import subprocess
import tempfile

BASE = 'd438760435c80afad82e0e5e768599939edc9204'
RESULT = 'tooling/native-patch-result-d4387604'
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
EXPECTED = json.loads((HERE / 'manifest.json').read_text())
encoded = ''.join((HERE / f'part{i}').read_text() for i in range(5))
series = lzma.decompress(base64.b64decode(encoded, validate=True), memlimit=256 * 1024 * 1024)
assert len(series) == 122083
assert hashlib.sha256(series).hexdigest() == '3036061230c036df186096d363da97ededee48ed71066aac87844890375b3369'

def git(cwd, *args):
    return subprocess.check_output(['git', *args], cwd=cwd, text=True).strip()

with tempfile.TemporaryDirectory(prefix='fg-native-patch-') as temporary:
    temporary = Path(temporary)
    source = temporary / 'source'
    patch = temporary / 'changes.patch'
    patch.write_bytes(series)
    assert git(REPO, 'rev-parse', f'{BASE}^{{commit}}') == BASE
    git(REPO, 'config', 'user.name', 'ChatGPT')
    git(REPO, 'config', 'user.email', 'chatgpt@example.invalid')
    git(REPO, 'worktree', 'add', '--detach', str(source), BASE)
    try:
        print(git(source, 'am', str(patch)), flush=True)
        commits = git(source, 'rev-list', '--reverse', f'{BASE}..HEAD').splitlines()
        assert len(commits) == len(EXPECTED) == 3
        paths = set()
        records = []
        predecessor = BASE
        for commit, expected in zip(commits, EXPECTED):
            assert git(source, 'show', '-s', '--format=%P', commit) == predecessor
            assert git(source, 'show', '-s', '--format=%s', commit) == expected['subject']
            changed = git(source, 'diff-tree', '--no-commit-id', '--name-only', '-r', commit).splitlines()
            assert set(changed) == set(expected['files']), (commit, changed)
            for path, wanted in expected['files'].items():
                actual = git(source, 'rev-parse', f'{commit}:{path}')
                assert actual == wanted, (commit, path, wanted, actual)
                assert git(source, 'ls-tree', commit, '--', path).startswith('100644 blob ')
            paths.update(changed)
            record = {'sha': commit, 'parent': predecessor, 'tree': git(source, 'rev-parse', f'{commit}^{{tree}}'), 'subject': expected['subject']}
            records.append(record)
            predecessor = commit
        assert set(git(source, 'diff', '--name-only', BASE, 'HEAD').splitlines()) == paths
        assert len(paths) == 15
        git(source, 'diff', '--check', BASE, 'HEAD')
        assert not git(source, 'status', '--porcelain')
        # Publish only source objects on a temporary result ref. The interactive
        # GitHub connector alone advances main after independently checking them.
        print(git(source, 'push', 'origin', f'HEAD:refs/heads/{RESULT}'), flush=True)
        print('PREPARED_RESULT=' + json.dumps({'base': BASE, 'result_ref': RESULT, 'commits': records, 'changed_files': len(paths), 'native_tests': 'unrun'}), flush=True)
    finally:
        git(REPO, 'worktree', 'remove', '--force', str(source))
