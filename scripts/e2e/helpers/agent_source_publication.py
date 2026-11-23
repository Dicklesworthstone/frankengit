"""Real scoped source publication, cross-transport recovery, and original evidence."""
import http.client
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlencode

from source_result_tree import AUTHOR, Fixture, HTTP, PRINCIPAL, complete_tree, oid

AGENT = 'a4' * 16
REF = 'refs/heads/main'
PUBLISH = 'frankengit_source_publish'
OUTCOME = 'frankengit_transaction_outcome'
RESULTS = []


def record(f, case, **details):
    row = dict(format=f.fmt, case=case, **details)
    RESULTS.append(row)
    print(json.dumps(row), flush=True)


def credential(f, label, reference=REF, paths=(b'src', b'lib'), candidate_only=False,
               operations=None, ref_scope=None):
    path = f.root / (label + '.token')
    f.command('generate-' + label, ['agent-credential', 'generate-token', '--output', path])
    now = int(time.time())
    operations = operations or ('source-candidates' if candidate_only else 'source-publish,outcomes-read')
    args = ['agent-credential', 'issue', *f.scope, '--trusted-local',
            '--incarnation', f.incarnation, '--principal', PRINCIPAL, '--agent', AGENT,
            '--sponsor-kind', 'human', '--token-file', path, '--issued-at', now - 1,
            '--expires-at', now + 3600, '--operations',
            operations,
            '--idempotency-key', 'issue-' + label, '--object-format', f.fmt]
    if {'source-publish', 'source-branch-create'} & set(operations.split(',')):
        args += ['--source-ref-scope', ref_scope or 'exact:' + reference.encode().hex()]
        for prefix in paths:
            args += ['--source-path-hex', prefix.hex()]
    receipt = json.loads(f.command('issue-' + label, args))
    assert receipt['outcome'] == 'committed' and receipt['cleanup_error'] is None
    return dict(path=path, token=path.read_text().strip(), id=receipt['credential_id'])


def request(server, route, grant, key, body=b'', media='application/x-www-form-urlencoded', status=200):
    connection = http.client.HTTPConnection(server.url.hostname, server.url.port, timeout=90)
    try:
        connection.request('POST', server.url.path.rstrip('/') + '/api/v1/' + route, body,
                           {'Authorization': 'Bearer ' + grant['token'],
                            'Idempotency-Key': key, 'Content-Type': media})
        response = connection.getresponse()
        data = response.read()
        assert len(data) == int(response.getheader('Content-Length'))
        server.f.sequence += 1
        (server.f.root / f'{server.f.sequence:03d}-http-{route.replace("/", "-")}.json').write_bytes(data)
        assert response.status == status, (route, response.status, data[-2000:])
        return json.loads(data)
    finally:
        connection.close()


def apply(server, grant, key, base, candidate, bundle, status=200, reference=REF):
    boundary = 'agent-source-publication'
    fields = dict(object_format=server.f.fmt, ref=reference, expected_commit=base, candidate_commit=candidate)
    parts = [('command', 'application/x-www-form-urlencoded', urlencode(fields).encode()),
             ('bundle', 'application/x-git-bundle', bundle)]
    body = b''.join(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\nContent-Type: {media}\r\n\r\n'.encode()
                    + data + b'\r\n' for name, media, data in parts) + f'--{boundary}--\r\n'.encode()
    return request(server, 'source/apply', grant, key, body, f'multipart/form-data; boundary={boundary}', status)


def arguments(key, base, candidate, bundle, reference=REF):
    assert 0 < len(bundle) <= 24 * 1024
    return dict(idempotency_key=key, reference=reference, expected_base=base, expected_candidate=candidate,
                bundle_hex_chunks=[bundle[i:i + 8192].hex() for i in range(0, len(bundle), 8192)])


def mcp(f, grant, calls, label):
    messages = [
        dict(jsonrpc='2.0', id=1, method='initialize',
             params=dict(protocolVersion='2025-06-18', capabilities={},
                         clientInfo=dict(name='source-publication-e2e', version='1'))),
        dict(jsonrpc='2.0', method='notifications/initialized')]
    messages += [dict(jsonrpc='2.0', id=i, method='tools/call', params=dict(name=name, arguments=args))
                 for i, (name, args) in enumerate(calls, 2)]
    output = f.command(label, ['mcp', *f.scope, '--agent-token-file', grant['path'],
                              '--expected-incarnation', f.incarnation, '--allow-source-writes',
                              '--allow-outcomes', '--object-format', f.fmt],
                       b''.join(json.dumps(message).encode() + b'\n' for message in messages))
    replies = [json.loads(line) for line in output.splitlines() if line]
    by_id = {reply['id']: reply for reply in replies if 'id' in reply}
    assert by_id[1]['result']['protocolVersion'] == '2025-06-18'
    results = []
    for i in range(2, 2 + len(calls)):
        reply = by_id[i]
        assert 'error' not in reply and not reply['result'].get('isError', False), reply
        results.append(reply['result']['structuredContent'])
    return results


def provenance(outcome, credential_id):
    assert outcome['terminal'] and outcome['provenance_error'] is None
    value = outcome['principal_provenance']
    assert value['state'] == 'recorded' and value['authentication'] == 'agent_credential'
    assert value['principal_id'] == AGENT
    agent = value['agent_provenance']
    assert (agent['agent'], agent['sponsor'], agent['sponsor_kind']) == (AGENT, PRINCIPAL, 'human')
    assert agent['credential_id'] == credential_id
    assert agent['grant_root']['hex'] and agent['run_commitment']
    assert agent['authenticated_at'] < agent['expires_at']
    return value


def edit_patch(f, before, after):
    old = oid(f.fmt, 'blob', (before + '\n').encode())
    new = oid(f.fmt, 'blob', (after + '\n').encode())
    return (f'diff --git a/lib/run.txt b/lib/run.txt\nindex {old}..{new} 100755\n'
            f'--- a/lib/run.txt\n+++ b/lib/run.txt\n@@ -1 +1 @@\n-{before}\n+{after}\n').encode()


def campaign(f):
    primary = credential(f, 'primary')
    wrong_ref = credential(f, 'wrong-ref', reference='refs/heads/other')
    wrong_path = credential(f, 'wrong-path', paths=(b'src',))
    candidate_only = credential(f, 'candidate-only', candidate_only=True)
    key = 'http-original-source'
    with HTTP(f, 'initial-http') as server:
        prepared, bundle = server.request('prepare', f.form(), f.patch)
        f.validate(prepared, bundle)
        record(f, 'operator-prepares-independently-verified-native-bundle')
        for label, grant in [('ref', wrong_ref), ('path', wrong_path)]:
            refused_key = 'outside-' + label
            refused = apply(server, grant, refused_key, f.base, f.candidate, bundle, status=409)
            assert refused['outcome'] == 'refused' and refused['refusal_code'] == 'CapabilityScopeViolation'
            recovered = request(server, 'outcomes', grant, refused_key)
            assert recovered['state'] == 'refused'
            assert recovered['transaction']['tx_id'] == refused['tx_id']
            assert recovered['decision']['code'] == 'CapabilityScopeViolation'
            provenance(recovered, grant['id'])
            record(f, 'http-' + label + '-scope-produces-durable-refusal')
        apply(server, candidate_only, 'candidate-only-publication', f.base, f.candidate, bundle, status=403)
        assert server.request('prepare', f.form(), f.patch) == (prepared, bundle)
        record(f, 'candidate-only-cannot-publish-and-refusals-preserve-tip')
        accepted = apply(server, primary, key, f.base, f.candidate, bundle)
        assert accepted['outcome'] == 'committed' and accepted['principal_id'] == AGENT
        original = request(server, 'outcomes', primary, key)
        assert original['state'] == 'committed' and original['transaction']['tx_id'] == accepted['tx_id']
        original_provenance = provenance(original, primary['id'])
        record(f, 'http-scoped-agent-publishes-with-original-sponsor', tx_id=accepted['tx_id'])
        second_form = dict(f.form(), expected_commit=f.candidate, timestamp='3', message='second sponsored\n')
        second_patch = edit_patch(f, 'after', 'second')
        second, second_bundle = server.request('prepare', second_form, second_patch)
        expected_files = dict(f.expected_files)
        expected_files[b'lib/run.txt'] = (b'100755', b'second\n')
        expected_tree = complete_tree(f.fmt, expected_files, lambda kind, data: oid(f.fmt, kind, data))
        expected_commit = oid(f.fmt, 'commit', f'tree {expected_tree}\nparent {f.candidate}\nauthor {AUTHOR} 3 +0000\ncommitter {AUTHOR} 3 +0000\n\nsecond sponsored\n'.encode())
        assert second['root_tree'] == expected_tree and second['candidate_commit'] == expected_commit
    replay, second_result, recovered = mcp(f, primary, [
        (PUBLISH, arguments(key, f.base, f.candidate, bundle)),
        (PUBLISH, arguments('mcp-second-source', f.candidate, expected_commit, second_bundle)),
        (OUTCOME, dict(idempotency_key=key))], 'mcp-publish')
    assert replay['outcome'] == 'committed' and replay['tx_id'] == accepted['tx_id']
    assert replay['repository_commit_id'] == accepted['decision_record']
    assert second_result['outcome'] == 'committed' and second_result['tx_id'] != accepted['tx_id']
    assert recovered['tx_id'] == accepted['tx_id'] and recovered['outcome'] == 'committed'
    assert provenance(recovered, primary['id']) == original_provenance
    record(f, 'real-mcp-replays-http-key-and-publishes-second-candidate', tx_id=second_result['tx_id'])
    replacement = credential(f, 'replacement', paths=(b'lib',))
    revoked = json.loads(f.command('revoke-primary', [
        'agent-credential', 'revoke', *f.scope, '--trusted-local', '--incarnation', f.incarnation,
        '--principal', PRINCIPAL, '--credential-id', primary['id'], '--expected-version', '1',
        '--idempotency-key', 'revoke-primary', '--object-format', f.fmt]))
    assert revoked['outcome'] == 'committed' and replacement['id'] != primary['id']
    damaged = bundle[:-1] + bytes([bundle[-1] ^ 1])
    with HTTP(f, 'reopened-http') as server:
        request(server, 'outcomes', primary, key, status=401)
        assert apply(server, replacement, key, f.base, f.candidate, damaged) == accepted
        recovered = request(server, 'outcomes', replacement, key)
        assert recovered == original
        assert provenance(recovered, primary['id']) == original_provenance
        third_patch = edit_patch(f, 'second', 'third')
        third_form = dict(second_form, expected_commit=expected_commit, timestamp='4', message='unpublished\n')
        third, _ = server.request('prepare', third_form, third_patch)
        assert third['source_commit'] == expected_commit and not third['published']
        record(f, 'rotation-revocation-reopen-retain-original-http-evidence-and-second-tip')
    replay, recovered = mcp(f, replacement, [
        (PUBLISH, arguments(key, f.base, f.candidate, damaged)),
        (OUTCOME, dict(idempotency_key=key))], 'mcp-reopened')
    assert replay['outcome'] == 'committed' and replay['tx_id'] == accepted['tx_id']
    assert replay['repository_commit_id'] == accepted['decision_record']
    assert recovered['tx_id'] == accepted['tx_id'] and recovered['outcome'] == 'committed'
    assert provenance(recovered, primary['id']) == original_provenance
    record(f, 'reopened-mcp-recovers-original-witness-under-narrower-replacement')


def task_branch_campaign(f):
    """Real branch creation closes the scoped author's branch-to-change workflow."""
    reference = 'refs/heads/agent/task-1'
    create = 'frankengit_branch_create'
    scope = 'prefix:' + b'refs/heads/agent/'.hex()
    author = credential(f, 'task-author', ref_scope=scope,
                        operations='source-candidates,source-branch-create,source-publish,outcomes-read')
    legacy = credential(f, 'legacy-author', reference=reference)
    candidate_only = credential(f, 'task-candidate-only', candidate_only=True)
    key = 'http-task-branch'
    form = dict(object_format=f.fmt, ref=reference, new_commit=f.base)
    body = urlencode(form).encode()
    create_args = dict(reference=reference, target=f.base, idempotency_key=key)
    with HTTP(f, 'task-http') as server:
        for grant in (legacy, candidate_only):
            request(server, 'source/branches/create', grant, 'legacy-cannot-create', body, status=403)
        record(f, 'legacy-publication-and-candidate-grants-cannot-create-task-branches')
        forbidden = urlencode(dict(form, ref='refs/heads/other/task-1')).encode()
        refused = request(server, 'source/branches/create', author, 'outside-task-namespace', forbidden, status=409)
        assert refused['outcome'] == 'refused' and refused['code'] == 'CapabilityScopeViolation'
        record(f, 'task-creation-enforces-credential-reference-namespace')
        created = request(server, 'source/branches/create', author, key, body)
        assert created['outcome'] == 'committed' and created['principal_id'] == AGENT
        original = request(server, 'outcomes', author, key)
        original_provenance = provenance(original, author['id'])
        assert original['transaction']['tx_id'] == created['tx_id']
        duplicate = request(server, 'source/branches/create', author, 'existing-task-branch', body, status=409)
        assert duplicate['outcome'] == 'refused'
        record(f, 'http-creates-absent-agent-branch-with-original-principal-evidence', tx_id=created['tx_id'])
        prepared, bundle = server.request('prepare', dict(f.form(), ref=reference), f.patch, token=author['token'])
        f.validate(prepared, bundle, reference)
        inspected = server.request('inspect', dict(object_format=f.fmt, ref=reference,
                                    expected_commit=f.base, candidate_commit=f.candidate),
                                   bundle, token=author['token'])
        assert inspected['candidate_commit'] == f.candidate
        record(f, 'agent-prepares-and-inspects-source-change-on-its-own-task-branch')
    replay, published, second_branch = mcp(f, author, [
        (create, create_args),
        (PUBLISH, arguments('task-source-publish', f.base, f.candidate, bundle, reference)),
        (create, dict(reference='refs/heads/agent/task-2', target=f.candidate,
                      idempotency_key='mcp-task-branch'))], 'task-mcp')
    assert replay['outcome'] == 'committed' and replay['tx_id'] == created['tx_id']
    assert published['outcome'] == 'committed' and second_branch['outcome'] == 'committed'
    record(f, 'mcp-replays-http-creation-publishes-source-and-creates-next-task', tx_id=second_branch['tx_id'])
    with HTTP(f, 'task-advance-source') as server:
        operator = dict(token=f.token)
        # The candidate bundle remains bound to its task ref. Move main to the
        # already published visible commit through native branch admission.
        advance = urlencode(dict(object_format=f.fmt, ref=REF,
                                 expected_commit=f.base, new_commit=f.candidate)).encode()
        advanced = request(server, 'source/branches/update', operator, 'advance-main-after-task', advance)
        assert advanced['outcome'] == 'committed'
        # Every visible branch has now moved off the original base. The old
        # creation still recovers from its immutable decision, not fresh scope.
        assert request(server, 'source/branches/create', author, key, body) == created
        assert request(server, 'outcomes', author, key) == original
        record(f, 'http-recovery-survives-source-and-task-tip-movement')
    replacement = credential(f, 'task-replacement', reference='refs/heads/replacement',
                             operations='source-branch-create,outcomes-read')
    revoked = json.loads(f.command('revoke-task-author', [
        'agent-credential', 'revoke', *f.scope, '--trusted-local', '--incarnation', f.incarnation,
        '--principal', PRINCIPAL, '--credential-id', author['id'], '--expected-version', '1',
        '--idempotency-key', 'revoke-task-author', '--object-format', f.fmt]))
    assert revoked['outcome'] == 'committed'
    replay, recovered = mcp(f, replacement, [
        (create, create_args), (OUTCOME, dict(idempotency_key=key))], 'task-rotated-mcp')
    assert replay['outcome'] == 'committed' and replay['tx_id'] == created['tx_id']
    assert provenance(recovered, author['id']) == original_provenance
    with HTTP(f, 'task-rotated-http') as server:
        request(server, 'source/branches/create', author, key, body, status=401)
        assert request(server, 'source/branches/create', replacement, key, body) == created
        assert request(server, 'outcomes', replacement, key) == original
    record(f, 'task-creation-retains-original-outcome-after-revocation-rotation-and-restart')


if __name__ == '__main__':
    fg, root = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for fmt in ['sha1', 'sha256']:
        campaign(Fixture(fg, root, fmt))
        task_branch_campaign(Fixture(fg, root / 'task-branches', fmt))
    (root / 'results.json').write_text(json.dumps(RESULTS, indent=2) + '\n')
