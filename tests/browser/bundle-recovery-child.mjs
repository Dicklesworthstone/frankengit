// Test-only process-death driver. No failure switches exist in the product CLI.
import { readFile } from 'node:fs/promises';
import { recoverGitBundle } from '../../scripts/lib/source-recovery.mjs';
const [input, destination, phase, resume = 'false'] = process.argv.slice(2);
const request = { head_ref_hex: Buffer.from('refs/heads/main').toString('hex') };
try {
  const result = await recoverGitBundle(await readFile(input), destination, request, {
    resume: resume === 'true', onProgress: async event => {
      const selected = phase === 'partial-pack' ? event.phase.startsWith('writing:objects/pack/') && event.written < event.total : event.phase === phase;
      if (selected) {
        await new Promise((resolve, reject) => process.send(event, error => error ? reject(error) : resolve()));
        await new Promise(() => { setInterval(() => {}, 1000); });
      }
    },
  });
  process.send({ unexpected_completion: result.state }); process.exitCode = 1;
} catch (error) {
  process.send({ failure: error.code ?? error.message, state: error.state }); process.exitCode = 1;
}
