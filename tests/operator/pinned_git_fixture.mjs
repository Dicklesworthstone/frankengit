// Test-only Git executor. Reuse the repository oracle's existing pin/receipt
// verification, then isolate authored fixture bytes and explicit commit metadata.
// No ambient Git executable, network, credential helper or production consumer.
import { spawnSync } from 'node:child_process';
import { realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const PIN = 'git-2.54.0';
const ORACLE = fileURLToPath(new URL('../../scripts/e2e/oracle/oracle.sh', import.meta.url));
const COMMANDS = new Set(['--version', 'init', 'hash-object', 'mktree', 'commit-tree',
  'update-ref', 'bundle', 'cat-file', 'rev-list', 'merge-tree']);
const METADATA = ['GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL',
  'GIT_AUTHOR_DATE', 'GIT_COMMITTER_DATE'];
let installation;
function verifiedInstallation() {
  if (installation) return installation;
  const result = spawnSync(ORACLE, ['verify', PIN], { timeout: 30000, maxBuffer: 1024 * 1024 });
  if (result.stderr?.length) process.stderr.write(result.stderr);
  if (result.error || result.signal || result.status !== 0) {
    throw Error(`Pinned Git fixture oracle unavailable: ${result.error?.message ?? result.signal ?? result.status}`);
  }
  installation = realpathSync(join(resolve(process.env.FGIT_ORACLE_ROOT ?? join(homedir(), '.cache/frankengit/git-oracle')),
    'installs', PIN));
  return installation;
}

export function pinnedFixtureGit(root, env, maxBuffer) {
  const install = verifiedInstallation(), directory = realpathSync(root), info = statSync(directory);
  if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o077) !== 0 ||
      !Number.isSafeInteger(maxBuffer) || maxBuffer < 1 || maxBuffer > 4 * 1024 * 1024) {
    throw Error('A private owned fixture directory and bounded output are required.');
  }
  const sandbox = ['--die-with-parent', '--new-session', '--unshare-all', '--clearenv',
    '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
    '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
    '--bind', directory, '/fixture', '--ro-bind', install, '/oracle', '--chdir', '/fixture',
    '--setenv', 'HOME', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LC_ALL', 'C',
    '--setenv', 'TZ', 'UTC', '--setenv', 'GIT_CONFIG_NOSYSTEM', '1', '--setenv', 'GIT_CONFIG_GLOBAL', '/dev/null',
    '--setenv', 'GIT_EXEC_PATH', '/oracle/libexec/git-core', '--setenv', 'GIT_ALLOW_PROTOCOL', 'file',
    '--setenv', 'GIT_TERMINAL_PROMPT', '0'];
  for (const name of METADATA) {
    if (typeof env[name] !== 'string' || env[name].length > 256 || /[\r\n\0]/.test(env[name])) {
      throw Error('Explicit bounded Git fixture commit metadata is required.');
    }
    sandbox.push('--setenv', name, env[name]);
  }
  const run = (args, input, maximum = maxBuffer) => {
    if (!Array.isArray(args) || !COMMANDS.has(args[0]) || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > maxBuffer) {
      throw Error('Unsupported fixture Git command or output bound.');
    }
    const mapped = args.map(argument => {
      if (typeof argument !== 'string' || argument.length > 16384 || argument.includes('\0')) throw Error('Invalid fixture Git argument.');
      return argument.startsWith(root + sep) ? '/fixture/' + argument.slice(root.length + 1) : argument;
    });
    const result = spawnSync('/usr/bin/bwrap', [...sandbox, '--', '/oracle/bin/git',
      '-c', 'core.hooksPath=/dev/null', '-c', 'credential.helper=', ...mapped], { input, timeout: 10000, maxBuffer: maximum });
    if (result.stderr?.length) process.stderr.write(result.stderr);
    if (result.error) throw result.error;
    return result;
  };
  const checked = (args, input) => {
    const result = run(args, input);
    if (result.signal || result.status !== 0) throw Error(`Pinned Git fixture command ${args[0]} failed: ${result.signal ?? result.status}`);
    return result.stdout;
  };
  checked.result = run;
  return checked;
}
