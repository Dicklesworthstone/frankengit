// Actual CLI entrypoints and POSIX pipe backpressure, not a native schema peer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const probe = fileURLToPath(new URL('./fixtures/workflow-cli-output-probe.py', import.meta.url));
for (const selected of ['watch', 'checks']) for (const mode of ['draining', 'blocked']) {
  test(`${selected}: ${mode} diagnostic preserves input-failure exit and bounded process lifetime`, {
    skip: process.platform !== 'linux', timeout: 20000,
  }, () => {
    const result = spawnSync('python3', [probe, process.execPath, selected, mode], { timeout: 18000, maxBuffer: 1024 * 1024 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr.toString());
    const observation = JSON.parse(result.stdout);
    assert.equal(observation.parent_intervened, false, 'the CLI must exit without the parent terminating it');
    assert.equal(observation.exit, 2);
    assert.equal(observation.stdout, '');
    assert.equal(observation.missing_config_absent, true);
    assert.equal(observation.publisher_absent, true);
    if (mode === 'blocked') assert.ok(observation.prefilled_bytes > 0);
    else {
      assert.equal(observation.prefilled_bytes, 0);
      const diagnostic = JSON.parse(observation.stderr);
      assert.equal(diagnostic.type, selected === 'watch' ? 'workflow_watch_error' : 'workflow_check_error');
      assert.equal(diagnostic.execution_retried, false);
      assert.match(diagnostic.message, /ENOENT/);
    }
  });
}
