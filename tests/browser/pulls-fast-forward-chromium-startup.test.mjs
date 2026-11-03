// Real child-process failure tests; these do not establish browser capability.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const smoke = fileURLToPath(new URL('./pulls-fast-forward-chromium.mjs', import.meta.url));
for (const failure of ['missing-executable', 'startup-signal']) {
  test(`Chromium smoke drains its fixture after ${failure}`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'fg-pr-chrome-startup-'));
    const executable = join(directory, 'chrome-startup-fault');
    try {
      // Exercise an actual signaled child, without substituting a successful browser.
      if (failure === 'startup-signal') await writeFile(executable, '#!/bin/sh\nkill -TERM "$$"\n', { mode: 0o700 });
      const result = spawnSync(process.execPath, [smoke], {
        env: { ...process.env, CHROME: executable, TMPDIR: directory },
        encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL',
      });
      assert.equal(result.error, undefined, 'startup failure must drain without the test deadline killing it');
      assert.equal(result.status, 1); assert.equal(result.signal, null);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, failure === 'startup-signal' ? /Chrome exited at startup: SIGTERM/ : /ENOENT/);
      assert.deepEqual(await readdir(directory), failure === 'startup-signal' ? ['chrome-startup-fault'] : [],
        'the owned browser profile must be removed even when startup fails');
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}
