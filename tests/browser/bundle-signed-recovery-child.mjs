// Real process interruption seam: production authentication and recovery, not
// a simulated filesystem. The normal CLI supplies no pause or fault option.
import { readAuthenticatedSourceBackup } from '../../scripts/lib/source-attestation.mjs';
import { recoverGitBundle } from '../../scripts/lib/source-recovery.mjs';
const [input, envelope, key, repository, floor, destination, head, phase, mode] = process.argv.slice(2);
try {
  const signed = await readAuthenticatedSourceBackup(input, envelope, key, { repository, minimum_sequence: floor });
  await recoverGitBundle(signed.bytes, destination, { head_ref_hex: head }, {
    resume: mode === 'resume', async onProgress(event) {
      if (event.phase === 'verified' || event.phase === 'before_publication') signed.checkCurrent();
      const selected = phase === 'partial-pack' ? event.phase.startsWith('writing:objects/pack/') && event.phase.endsWith('.pack') && event.written < event.total : event.phase === phase;
      if (selected) {
        process.send({ ready: true, phase: event.phase, written: event.written, total: event.total });
        await new Promise(() => {});
      }
    },
  });
  process.send({ unexpected_completion: true });
} catch (error) { process.send({ error: error.code ?? error.message, state: error.state }); process.exitCode = 1; }
