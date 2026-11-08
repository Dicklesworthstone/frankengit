// Real process/pipe probe only; no native workflow or forge authority is modeled.
import { writeFile } from 'node:fs/promises';
import { writeRecord, reportCliFailure } from '../../../scripts/fg_workflow_supervisor.mjs';

try {
  try {
    if (process.argv[3] === '--block-stderr') {
      process.stderr.write('x'.repeat(512 * 1024));
      throw new Error('controlled error-report failure');
    }
    await writeRecord(process.stdout, { payload: 'x'.repeat(512 * 1024) }, 100);
  } finally {
    // Prove a report timeout does not terminate inside writeRecord, before its
    // caller can finish the awaited cleanup that precedes the CLI boundary.
    await writeFile(process.argv[2], 'cleanup completed\n', { mode: 0o600, flag: 'wx' });
  }
} catch (error) {
  reportCliFailure(error);
}
