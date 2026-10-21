"""Actual fg push/PR branch selection, restart and canonical reporting."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import TENANT, REPOSITORY, PRINCIPAL, write_object, tree, commit
FG, ROOT = sys.argv[1], Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
RESULTS, SEQUENCE = [], 0

def invoke(label, args, code=0):
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f'{SEQUENCE:03d}-{label}.{s}' for s in ('out', 'err'))
    with out.open('wb') as stdout, err.open('wb') as stderr:
        result = subprocess.run([FG, *map(str, args)], stdout=stdout, stderr=stderr, timeout=90)
    diagnostic = err.read_bytes()
    if diagnostic:
        sys.stderr.buffer.write(diagnostic)
        sys.stderr.buffer.flush()
    assert result.returncode == code, (label, result.returncode, out.read_bytes()[-4000:], diagnostic[-4000:])
    return out.read_bytes()

def rows(data):
    return [json.loads(line) for line in data.splitlines() if line]

def record(fmt, case, **detail):
    value = dict(format=fmt, case=case, **detail)
    RESULTS.append(value)
    print(json.dumps(value), flush=True)

class Fixture:
    def __init__(self, fmt):
        self.fmt = fmt
        self.home = ROOT / fmt
        self.home.mkdir()
        self.source, self.node, self.runs, self.effects = (self.home / x for x in ('source', 'node', 'runs', 'effects'))
        self.runs.mkdir(mode=0o700)
        (self.source / 'refs/heads').mkdir(parents=True)
        (self.source / 'HEAD').write_text('ref: refs/heads/main\n')
        (self.source / 'config').write_text('[core]\nbare=true\nrepositoryformatversion=' + ('0\n' if fmt == 'sha1' else '1\n[extensions]\nobjectformat=sha256\n'))
        definitions = [
            ('push', "\n  push:\n    branches:\n      - 'topic/**'\n      - '!topic/private/**'\n      - 'topic/private/allowed'"),
            ('pr', "\n  pull_request:\n    branches:\n      - 'main'"),
            ('ignore', "\n  push:\n    branches-ignore:\n      - 'topic/**'"),
            ('manual', "\n  workflow_dispatch: ''"),
        ]
        entries = []
        for name, on in definitions:
            workflow = f"name: {name}\non: {on}\njobs:\n  {name}:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf '{name}\\n' >> {shlex.quote(str(self.effects))}\n"
            oid = write_object(self.source, fmt, 'blob', workflow.encode())
            entries.append((b'100644', (name + '.yml').encode(), oid))
        ci = write_object(self.source, fmt, 'tree', tree(sorted(entries, key=lambda x: x[1])))
        self.tree = write_object(self.source, fmt, 'tree', tree([(b'40000', b'ci', ci)]))
        self.target = write_object(self.source, fmt, 'commit', commit(self.tree, None, 1, b'base\n'))
        self.tip = write_object(self.source, fmt, 'commit', commit(self.tree, self.target, 2, b'topic\n'))
        self.next = write_object(self.source, fmt, 'commit', commit(self.tree, self.tip, 3, b'next\n'))
        names = ['main', 'topic/work', 'topic/private/no', 'topic/private/allowed', 'other-target', 'future']
        for name in names:
            path = self.source / 'refs/heads' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text((self.target if name in ('main','other-target') else self.next if name == 'future' else self.tip) + '\n')
        self.scope = [self.node, TENANT, REPOSITORY]
        invoke('init', ['init', *self.scope, fmt])
        invoke('import', ['import', *self.scope, PRINCIPAL, 'branch-filter-fixture', self.source])
        self.listing = ['pr', 'list', *self.scope, '--trusted-local', '--object-format', fmt]
    def count(self):
        return self.effects.read_text().splitlines() if self.effects.exists() else []
    def watch(self, reference, number=None, reporting=None, code=0):
        args = ['workflow', 'watch', *self.scope, reference, '--trusted-local', '--workflow', 'ci', '--input', 'ci',
                '--run-parent', self.runs, '--object-format', self.fmt]
        if number is not None:
            args += ['--pull-request', str(number)]
        if reporting:
            args += ['--publish-checks', '--principal-id', PRINCIPAL, '--expected-incarnation', reporting]
        result = rows(invoke('watch', args, code))
        assert result[-1]['node_closed']
        return next(row['poll'] for row in result if row['type'] == 'workflow_watch_poll'), result
    def pr(self, action, number, previous, target):
        return invoke(action, ['pr', action, *self.scope, str(number), '--trusted-local', '--principal', PRINCIPAL,
            '--idempotency-key', f'{action}-{number}-{previous}', '--expected-version', str(previous),
            '--source-ref', 'refs/heads/topic/private/no', '--target-ref', target, '--expected-source', self.tip,
            '--expected-target', self.target, '--title', 'Branch filters', '--body', 'Native target selection', '--object-format', self.fmt])

for fmt in ('sha1', 'sha256'):
    f = Fixture(fmt)
    for branch, selected in [('topic/work','push'), ('topic/private/no',None), ('topic/private/allowed','push'), ('main','ignore')]:
        before = f.count()
        authority = invoke('authority-before', f.listing)
        poll, output = f.watch('refs/heads/' + branch)
        dispatch = poll['dispatch']
        assert dispatch['matched_count'] == (0 if selected is None else 1)
        assert dispatch['executed_count'] == (0 if selected is None else 1)
        assert dispatch['plan']['trigger_ref_hex'] == ('refs/heads/' + branch).encode().hex()
        assert f.count() == before + ([] if selected is None else [selected])
        assert invoke('authority-after', f.listing) == authority
        again, _ = f.watch('refs/heads/' + branch)
        assert again['state'] == 'previously_settled' and f.count() == before + ([] if selected is None else [selected])
        record(fmt, 'push-' + branch.replace('/','-'), matching=dispatch['matched_count'])
    # Same source branch rejected by the push filter is accepted for a PR to main.
    f.pr('open', 7, 0, 'refs/heads/main')
    before = f.count()
    poll, _ = f.watch('refs/heads/topic/private/no', 7)
    assert poll['dispatch']['matched_count'] == 1 and f.count() == before + ['pr']
    assert poll['dispatch']['plan']['trigger_ref_hex'] == b'refs/heads/main'.hex()
    assert poll['dispatch']['runs'][0]['executed_commit'] == f.tip
    record(fmt, 'pr-target-not-source-selects-workflow')
    incarnation = poll['event']['repository_incarnation']
    before = f.count()
    poll, output = f.watch('refs/heads/topic/private/no', 7, incarnation)
    assert poll['state'] == 'previously_settled' and f.count() == before
    checks = json.loads(invoke('checks', ['pr','checks',*f.scope,'7','--trusted-local','--object-format',fmt]))['checks']
    assert len(checks) == 1 and checks[0]['job'] == 'pr' and checks[0]['conclusion'] == 'success'
    record(fmt, 'filtered-run-publishes-original-success-without-reexecution')
    f.watch('refs/heads/topic/private/no', 7, incarnation)
    assert f.count() == before
    record(fmt, 'fresh-process-publication-is-idempotent')
    # Another canonical target excludes the same source bytes and creates no check.
    f.pr('open', 8, 0, 'refs/heads/other-target')
    authority = invoke('excluded-authority-before', f.listing)
    poll, output = f.watch('refs/heads/topic/private/no', 8, incarnation)
    assert poll['dispatch']['matched_count'] == 0 and f.count() == before
    assert poll['dispatch']['plan']['trigger_ref_hex'] == b'refs/heads/other-target'.hex()
    assert not any(row['type'] == 'workflow_check_set_decision' for row in output)
    assert invoke('excluded-authority-after', f.listing) == authority
    record(fmt, 'excluded-pr-target-starts-no-job-and-publishes-no-check')
    f.pr('close', 7, 1, 'refs/heads/main')
    assert f.watch('refs/heads/topic/private/no',7,incarnation)[0]['state'] == 'pull_request_unavailable'
    assert f.count() == before
    f.pr('reopen', 7, 2, 'refs/heads/main')
    poll, _ = f.watch('refs/heads/topic/private/no',7,incarnation)
    assert poll['dispatch']['matched_count'] == 1 and f.count() == before + ['pr']
    record(fmt, 'reopen-selects-new-pr-event-with-same-target-filter')
    before=f.count()
    invoke('advance-source', ['branch','update',*f.scope,'--trusted-local','--principal',PRINCIPAL,
        '--idempotency-key','advance-filtered-source','--ref','refs/heads/topic/private/no','--expected-tip',f.tip,
        '--target',f.next,'--object-format',fmt])
    f.tip=f.next
    poll,_=f.watch('refs/heads/topic/private/no',7,incarnation)
    assert poll['dispatch']['runs'][0]['executed_commit'] == f.tip and f.count() == before + ['pr']
    record(fmt, 'source-movement-executes-current-source-with-target-filter')
(ROOT/'results.json').write_text(json.dumps(RESULTS, indent=2)+'\n')
