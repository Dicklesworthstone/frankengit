// SIGKILL boundary driver. The parent kills this real filesystem operation.
import { readFile } from 'node:fs/promises';
import { copyAuthenticatedSourceBackup } from '../../scripts/lib/source-attestation.mjs';
const [input, destination, envelope, pub, phase] = process.argv.slice(2);
// Keep IPC alive at the parked boundary; an unsettled top-level-await exit
// would not be a process-death test of the publication protocol.
process.on('message', () => {});
await copyAuthenticatedSourceBackup(input, destination, await readFile(envelope), await readFile(pub),
  { repository: 'team/repo', minimum_sequence: '42' }, { now: Date.parse('2026-09-28T12:00:00Z'),
    async onProgress(event) {
      if (event.phase === phase && (phase !== 'copying' || event.bytes_hashed === 65536)) {
        await new Promise((resolve, reject) => process.send(event, error => error ? reject(error) : resolve()));
        await new Promise(() => {});
      }
    } });
