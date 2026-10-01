// Child-process helper that streams output into a job log.
import { spawn } from 'node:child_process';

export function run(cmd, args, { cwd, log, env, input } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, env: { ...process.env, ...env }, windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => {
      stdout += d;
      log?.(d.toString());
    });
    child.stderr.on('data', (d) => {
      stderr += d;
      log?.(d.toString());
    });
    child.on('error', reject);
    if (input !== undefined) child.stdin.end(input);
    child.on('close', (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${cmd} ${args.join(' ')} exited with code ${code}${stderr ? `: ${stderr.trim().split('\n').pop()}` : ''}`));
    });
  });
}
