// Separate process for actual peak-RSS measurement, not an estimator.
import { readFile } from 'node:fs/promises';
import { signSourceBackupFile, authenticateSourceBackupFile } from '../../scripts/lib/source-attestation.mjs';
const [input, privatePath, publicPath, limit] = process.argv.slice(2);
const privatePem = await readFile(privatePath), publicPem = await readFile(publicPath);
const signed = await signSourceBackupFile(input, privatePem, { repository: 'team/repo', sequence: '42' }, { maximumBytes: Number(limit), timeoutMs: 50000 });
privatePem.fill(0);
const checked = await authenticateSourceBackupFile(input, signed.envelope, publicPem,
  { repository: 'team/repo', minimum_sequence: '42' }, { maximumBytes: Number(limit), timeoutMs: 50000 });
process.stdout.write(JSON.stringify({ bytes: signed.statement.artifact.bytes, sha256: signed.statement.artifact.sha256,
  signature_verified: checked.authentication.signature_verified, ...checked.streaming,
  max_rss_kib: process.resourceUsage().maxRSS }) + '\n');
