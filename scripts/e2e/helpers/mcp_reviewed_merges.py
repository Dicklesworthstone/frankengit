import hashlib, json, pathlib, struct, subprocess, sys, zlib

fg, fg_mcp, root = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
large_files = int(sys.argv[4]) if len(sys.argv) == 5 else 0
assert len(sys.argv) in (4, 5) and large_files in (0, 100000)
tenant, repository, opener, reviewer, merger = '1' * 32, '2' * 32, '3' * 32, '4' * 32, '5' * 32
commands = tool_calls = sessions = 0
cases = []
CANDIDATE, REVIEW, MERGE = 'frankengit_source_candidate', 'frankengit_pull_review', 'frankengit_pull_merge_reviewed'


def execute(label, argv, data=None):
    global commands
    commands += 1
    result = subprocess.run(list(map(str, argv)), input=data, capture_output=True, timeout=120)
    prefix = root / f'{commands:03d}-{label}'
    prefix.with_suffix('.out').write_bytes(result.stdout)
    prefix.with_suffix('.err').write_bytes(result.stderr)
    if data is not None:
        prefix.with_suffix('.requests.ndjson').write_bytes(data)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    assert result.returncode == 0, (label, result.returncode, result.stdout, result.stderr)
    return result.stdout


def native_object(source, fmt, kind, body):
    raw = kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.new(fmt, raw).hexdigest()
    path = source / 'objects' / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(raw))
    return oid


def tree(source, fmt, files, directories=()):
    entries = []
    for name, (mode, data) in files.items():
        blob = native_object(source, fmt, 'blob', data)
        entries.append((name, mode, blob))
    entries.extend((name, 0o40000, oid) for name, oid in directories)
    entries.sort(key=lambda entry: entry[0] + ('/' if entry[1] == 0o40000 else ''))
    body = b''.join(f'{mode:o} {name}'.encode() + b'\0' + bytes.fromhex(oid)
                    for name, mode, oid in entries)
    return native_object(source, fmt, 'tree', body)


def commit(source, fmt, files, parents, message, directories=()):
    root_tree = tree(source, fmt, files, directories)
    body = f'tree {root_tree}\n' + ''.join(f'parent {p}\n' for p in parents)
    body += f'author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n{message}\n'
    return native_object(source, fmt, 'commit', body.encode())


def with_selected_blob(arguments, fmt, data):
    """Append one actual inherited blob, retaining the original packed entries."""
    original = bytes.fromhex(''.join(arguments['bundle_hex_chunks']))
    assert arguments['expected_bundle_sha256'] == hashlib.sha256(original).hexdigest()
    split = original.index(b'\n\n') + 2
    pack = original[split:]
    width = hashlib.new(fmt).digest_size
    assert pack[:8] == b'PACK' + struct.pack('>I', 2)
    assert hashlib.new(fmt, pack[:-width]).digest() == pack[-width:]
    size = len(data)
    header = bytearray()
    byte, size = 0x30 | (size & 15), size >> 4
    while size:
        header.append(byte | 128)
        byte, size = size & 127, size >> 7
    header.append(byte)
    count = struct.unpack('>I', pack[8:12])[0]
    body = pack[:8] + struct.pack('>I', count + 1) + pack[12:-width] + header + zlib.compress(data)
    result = original[:split] + body + hashlib.new(fmt, body).digest()
    return dict(arguments, expected_bundle_sha256=hashlib.sha256(result).hexdigest(),
                bundle_hex_chunks=[result[i:i+4096].hex() for i in range(0, len(result), 4096)]), result


def content(response):
    assert 'error' not in response, response
    result = response['result']
    assert result['isError'] is False, result
    return result['structuredContent']


def refused(response):
    if 'error' in response:
        assert response['error']['code'] == -32602, response
        return response['error']['message']
    result = response['result']
    if result['isError']:
        assert result.get('content'), result
        return json.dumps(result)
    value = result['structuredContent']
    assert value.get('outcome') == 'refused' and value.get('command_committed') is False, value
    return value.get('refusal_code', 'refused')


def terminal_refusal(response, expected_code):
    # Parse/grant errors and an uncertain mutation are not canonical refusals.
    assert 'error' not in response, response
    result = response['result']
    assert result['isError'] is True, result
    value = result['structuredContent']
    assert value['outcome'] == 'refused' and value['command_committed'] is False, value
    assert value['terminal'] is True and value['outcome_unknown'] is False, value
    assert value['refusal_code'] == expected_code, value
    assert value['refusal_record_id'] and value['tx_id'] and int(value['decision_sequence']) > 0, value
    assert value['repository_commit_id'] is None, value
    return value


profiles = [('clean', 'merge-commit')] if large_files else [('clean', 'merge-commit'), ('clean', 'squash'), ('file', 'merge-commit'), ('file', 'squash'), ('ours', 'squash')]
for fmt in ['sha1', 'sha256']:
    for resolution, method in profiles:
        label = f'{fmt}-{resolution}-{method}'
        directory = root / label
        directory.mkdir()
        source, node = directory / 'source', directory / 'node'
        directories, inherited = (), None
        if large_files:
            from import_metadata_fixture import build
            inherited_tip, inherited_objects, inherited_pack = build(source, fmt, large_files)
            kind, body = inherited_objects[inherited_tip]
            assert kind == 'commit' and body.startswith(b'tree ')
            inherited_tree = body.split(b'\n', 1)[0][5:].decode()
            inherited_blobs = sum(kind == 'blob' for kind, _ in inherited_objects.values())
            assert inherited_blobs == large_files and len(inherited_objects) > 100000
            directories = (('wide', inherited_tree),)
            inherited = dict(files=inherited_blobs, objects=len(inherited_objects), root_tree=inherited_tree, pack=inherited_pack)
        common = {'README': (0o100644, b'base\n'), 'sibling': (0o100644, b'unchanged\n')}
        base = commit(source, fmt, common, [], 'base', directories)
        ours, theirs = dict(common), dict(common)
        if resolution == 'clean':
            ours['main-only'] = (0o100644, b'main\n')
            theirs['topic-only'] = (0o100644, b'topic\n')
            expected = dict(ours, **{'topic-only': theirs['topic-only']})
        else:
            ours['README'] = (0o100644, b'main\n')
            theirs['README'] = (0o100644, b'topic\n')
            expected = dict(ours)
            if resolution == 'file':
                expected['README'] = (0o100755, b'resolved\0\xff\r\n')
        target = commit(source, fmt, ours, [base], 'target', directories)
        tip = commit(source, fmt, theirs, [base], 'source', directories)
        expected_tree = tree(source, fmt, expected, directories)
        (source / 'refs/heads').mkdir(parents=True, exist_ok=True)
        (source / 'refs/heads/main').write_text(target + '\n')
        (source / 'refs/heads/topic').write_text(tip + '\n')
        (source / 'HEAD').write_text('ref: refs/heads/main\n')
        scope = [node, tenant, repository]
        execute(label + '-init', [fg, 'init', *scope, fmt])
        imported = json.loads(execute(label + '-import', [fg, '--timeout-secs', '120', 'import', *scope, opener, 'fixture-import', source, '--json']))
        assert imported['state'] == 'committed', imported
        incarnation = imported['repository_incarnation_id']

        def mcp(stage, calls, grants, principal=None):
            global tool_calls, sessions
            sessions += 1
            # Exercise both executable entrypoints with genuine EOF/reopen boundaries.
            argv = [fg, 'mcp'] if sessions % 2 else [fg_mcp]
            argv += [*scope, '--trusted-local', '--object-format', fmt, '--expected-incarnation', incarnation, '--max-messages', str(len(calls) + 2), *grants]
            if principal:
                argv += ['--principal', principal]
            records = [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'frankengit-reviewed-merge-e2e', 'version': '1'}}},
                       {'jsonrpc': '2.0', 'method': 'notifications/initialized'}]
            for index, (tool, arguments) in enumerate(calls, 2):
                tool_calls += 1
                records.append({'jsonrpc': '2.0', 'id': index, 'method': 'tools/call', 'params': {'name': tool, 'arguments': arguments}})
            data = b''.join(json.dumps(record, separators=(',', ':')).encode() + b'\n' for record in records)
            raw = execute(label + '-' + stage, argv, data)
            rows = [json.loads(line) for line in raw.splitlines()]
            assert len(rows) == len(calls) + 1 and rows[0]['result']['protocolVersion'] == '2025-06-18', rows
            assert [row['id'] for row in rows] == list(range(1, len(calls) + 2)), rows
            return rows[1:]

        def refs(stage):
            return execute(label + '-' + stage, [fg, 'refs', *scope, '--trusted-local', '--object-format', fmt])

        def tips(raw):
            return {bytes.fromhex(row['reference_hex']).decode(): row['tip'] for row in json.loads(raw)['references']}

        subject = {'number': '1', 'expected_version': '1', 'source_reference_hex': b'refs/heads/topic'.hex(), 'target_reference_hex': b'refs/heads/main'.hex(),
                   'expected_source': tip, 'expected_target': target, 'policy_epoch': '1'}
        opened_args = dict(subject, expected_version='0', idempotency_key='open-pr', title='Exact reviewed candidate', body='Independent read, review, and merge grants.')
        del opened_args['policy_epoch']
        opened = content(mcp('open', [('frankengit_pull_open', opened_args)], ['--allow-pull-writes'], opener)[0])
        assert opened['outcome'] == 'committed', opened
        before = refs('before-preparation')
        arguments = dict(subject, operation='prepare_pull_merge', method=method, author='Merger <merger@example.invalid>', committer='Committer <committer@example.invalid>',
                         timestamp='2', message_hex=b'Exact reviewed merge\n'.hex(), expected_head=json.loads(before)['snapshot_token'])
        read_grants = ['--allow-source', '--allow-pulls']
        if resolution != 'clean':
            conflict = content(mcp('discover-conflicts', [(CANDIDATE, arguments)], read_grants)[0])
            assert conflict['state'] == 'conflicted' and conflict['method'] == method, conflict
            choice = {'path_hex': b'README'.hex(), 'choice': resolution}
            if resolution == 'file':
                choice.update(mode='100755', bytes_hex_chunks=[expected['README'][1].hex()])
            arguments.update(operation='resolve_pull_merge', merge_base=base, resolutions=[choice])
        prepared = content(mcp('prepare', [(CANDIDATE, arguments)], read_grants)[0])
        assert prepared['method'] == method and prepared['root_tree'] == expected_tree, prepared
        expected_parents = [target] if method == 'squash' else [target, tip]
        assert prepared['parents'] == expected_parents, prepared
        inspection = prepared['inspection_arguments']
        review_args = dict(prepared['candidate_arguments'], idempotency_key='exact-approval', review_version='0', decision='approve')
        publish_args = dict(prepared['publication_arguments'], idempotency_key='exact-publication', required_reviewers=[reviewer])
        assert 'method' not in review_args and publish_args['method'] == inspection['method'] == method
        candidate = review_args['candidate_commit']
        body = bytes.fromhex(prepared['candidate_commit_body_hex'])
        assert hashlib.new(fmt, b'commit ' + str(len(body)).encode() + b'\0' + body).hexdigest() == candidate
        assert [line[7:].decode() for line in body.split(b'\n\n', 1)[0].splitlines() if line.startswith(b'parent ')] == expected_parents
        # Another process inspects the original bytes, not a recomputed candidate.
        inspected = content(mcp('inspect-after-reopen', [(CANDIDATE, inspection)], read_grants)[0])
        for key in ['method', 'parents', 'candidate_commit_body_hex', 'candidate_arguments', 'publication_arguments']:
            assert inspected[key] == prepared[key], key
        if resolution == 'ours':
            assert inspected['review']['entry_count'] == '0', inspected
        if large_files:
            thicker_args, thicker_bytes = with_selected_blob(inspection, fmt, common['sibling'][1])
            thicker = content(mcp('inspect-thicker-after-reopen', [(CANDIDATE, thicker_args)], read_grants)[0])
            for key in ['method', 'parents', 'candidate_commit', 'candidate_commit_body_hex', 'root_tree', 'review', 'closure_objects', 'prerequisites']:
                assert thicker[key] == inspected[key], key
            # Both commands carry their actual upload for independent native
            # validation. Compare every semantic field and verify each carrier
            # exactly, rather than equating different packed representations.
            minimal_bytes = bytes.fromhex(''.join(inspection['bundle_hex_chunks']))
            for name in ['candidate_arguments', 'publication_arguments']:
                before, after = inspected[name], thicker[name]
                assert before.keys() == after.keys() and 'bundle_hex_chunks' in before, name
                for key in sorted(before):
                    if key == 'bundle_hex_chunks':
                        assert bytes.fromhex(''.join(before[key])) == minimal_bytes, name
                        assert bytes.fromhex(''.join(after[key])) == thicker_bytes, name
                    else:
                        assert before[key] == after[key], (name, key)
            assert int(thicker['pack_objects']) == int(inspected['pack_objects']) + 1
            assert int(thicker['bundle_bytes']) == len(thicker_bytes)
            assert thicker['bundle_sha256'] == hashlib.sha256(thicker_bytes).hexdigest()
            assert thicker['root_tree'] == expected_tree
            corrupt = thicker_bytes[:-1] + bytes([thicker_bytes[-1] ^ 1])
            corrupt_args = dict(thicker_args, expected_bundle_sha256=hashlib.sha256(corrupt).hexdigest(),
                                bundle_hex_chunks=[corrupt[i:i+4096].hex() for i in range(0, len(corrupt), 4096)])
            corrupt_refusal = refused(mcp('corrupt-thicker-bundle', [(CANDIDATE, corrupt_args)], read_grants)[0])
            assert 'pull_candidate_inspection_failed' in corrupt_refusal, corrupt_refusal
            publish_args = dict(thicker['publication_arguments'], idempotency_key='exact-publication', required_reviewers=[reviewer])
        assert refs('after-inspection') == before
        denied = mcp('read-grants-cannot-write', [(REVIEW, review_args), (MERGE, publish_args)], read_grants)
        for row in denied:
            assert 'error' in row and row['error']['code'] == -32602, row
        assert refs('after-ungranted-writes') == before
        early = dict(publish_args, idempotency_key='before-approval')
        unapproved_refusal = terminal_refusal(mcp('unapproved-merge', [(MERGE, early)], ['--allow-reviewed-merges'], merger)[0], 'EvidenceMissing')
        assert tips(refs('after-unapproved')) == {'refs/heads/main': target, 'refs/heads/topic': tip}
        approved_rows = mcp('approve-and-repeat', [(REVIEW, review_args), (REVIEW, review_args)], ['--allow-review-writes'], reviewer)
        approved = content(approved_rows[0])
        assert approved['outcome'] == 'committed' and approved_rows[0]['result'] == approved_rows[1]['result']
        after_review = refs('after-review')
        assert content(mcp('approval-after-reopen', [(REVIEW, review_args)], ['--allow-review-writes'], reviewer)[0]) == approved
        assert refs('after-review-retry') == after_review
        wrong_method = dict(publish_args, method='merge-commit' if method == 'squash' else 'squash', idempotency_key='wrong-method')
        method_refusal = terminal_refusal(mcp('method-substitution', [(MERGE, wrong_method)], ['--allow-reviewed-merges'], merger)[0], 'EvidenceInvalid')
        assert tips(refs('after-method-refusal')) == {'refs/heads/main': target, 'refs/heads/topic': tip}
        published_rows = mcp('publish-and-repeat', [(MERGE, publish_args), (MERGE, publish_args)], ['--allow-reviewed-merges'], merger)
        published = content(published_rows[0])
        assert published['outcome'] == 'committed' and published['method'] == method and published['coupled_pr_and_ref'], published
        assert published_rows[0]['result'] == published_rows[1]['result']
        after = refs('after-publication')
        assert tips(after) == {'refs/heads/main': candidate, 'refs/heads/topic': tip}
        # Losing the original checkout cannot require preparing or executing again.
        source.rename(directory / 'source-offline')
        assert content(mcp('publication-after-restart', [(MERGE, publish_args)], ['--allow-reviewed-merges'], merger)[0]) == published
        assert refs('after-restarted-retry') == after
        changed_key = dict(publish_args, method=wrong_method['method'])
        # A changed command under a committed key can remain an uncertain tool
        # error; it is not the typed pre-publication method refusal above.
        refused(mcp('same-key-changed-method', [(MERGE, changed_key)], ['--allow-reviewed-merges'], merger)[0])
        assert refs('after-key-reuse') == after
        blobs = mcp('read-merged-bytes', [('frankengit_source_blob', {'reference': 'refs/heads/main', 'path_hex': name.encode().hex()}) for name in expected], ['--allow-source'])
        for (name, (_, data)), row in zip(expected.items(), blobs):
            assert content(row)['bytes_hex'] == data.hex(), name
        if large_files:
            for index in [0, large_files - 1]:
                path = f'wide/dir{index // 500:06d}/file{index:06d}'
                row = mcp(f'read-inherited-{index}', [('frankengit_source_blob', {'reference': 'refs/heads/main', 'path_hex': path.encode().hex()})], ['--allow-source'])[0]
                assert content(row)['bytes_hex'] == f'file {index:06d}\n'.encode().hex()
        cases.append({'format': fmt, 'resolution': resolution, 'method': method, 'candidate': candidate, 'exact_parents': expected_parents,
                      'independent_grants': True, 'unapproved_and_changed_method_refused': True, 'source_unchanged': True,
                      'unapproved_refusal_code': unapproved_refusal['refusal_code'], 'method_substitution_refusal_code': method_refusal['refusal_code'],
                      'source_free_terminal_retry': True, 'native_identity_and_content_verified': True})
        if large_files:
            cases[-1].update(inherited_repository=inherited, thicker_selected_blob_equivalent=True)
        print('PASS', label, flush=True)

(root / 'results.json').write_text(json.dumps({'top_level_commands': commands, 'mcp_sessions': sessions, 'tool_calls': tool_calls, 'cases': cases, 'native_peers_are_fixtures': False}, indent=2) + '\n')
