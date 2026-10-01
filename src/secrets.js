// At-rest protection for private keys stored in data/*.json.
//
//   Windows  DPAPI (current user), via PowerShell.               blob: "dpapi:<base64>"
//   Linux    AES-256-GCM with a 32-byte master key, taken from:   blob: "aes:<iv>.<tag>.<ciphertext>"
//              1. $CREDENTIALS_DIRECTORY/master-key  (systemd LoadCredential/LoadCredentialEncrypted)
//              2. $PROWLER_MANAGE_KEY_FILE
//              3. <data dir>/master.key, created on first use with mode 0600 (development / manual runs)
//            A configured source that is missing is an error, never a reason to fall back: a fresh
//            fallback key would make everything encrypted with the real key unreadable.
//
// "plain:" blobs written by older Linux builds are still readable; certificates generated from now on are encrypted.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { run } from './exec.js';
import { DATA_DIR } from './store.js';

const PS_PROTECT =
  "Add-Type -AssemblyName System.Security; $t=[Console]::In.ReadToEnd(); " +
  "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($t),$null,'CurrentUser'))";
const PS_UNPROTECT =
  'Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); ' +
  "[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))";

let masterKey = null;

function keyFile() {
  const credDir = process.env.CREDENTIALS_DIRECTORY;
  if (credDir) {
    const f = path.join(credDir, 'master-key');
    if (!fs.existsSync(f)) {
      throw new Error(`systemd credential "master-key" is configured for this service but missing from ${credDir}; check LoadCredential/LoadCredentialEncrypted in the unit`);
    }
    return { file: f, source: 'systemd credential "master-key"' };
  }
  if (process.env.PROWLER_MANAGE_KEY_FILE) {
    const f = process.env.PROWLER_MANAGE_KEY_FILE;
    if (!fs.existsSync(f)) throw new Error(`PROWLER_MANAGE_KEY_FILE points to ${f}, which does not exist`);
    return { file: f, source: f };
  }
  return { file: path.join(DATA_DIR, 'master.key'), source: path.join(DATA_DIR, 'master.key'), create: true };
}

/** Where the master key comes from (for diagnostics); throws if a configured source is missing. */
export function masterKeySource() {
  if (process.platform === 'win32') return 'Windows DPAPI (current user)';
  return keyFile().source;
}

/** Load the master key now (Linux), so a broken setup shows up at startup rather than at renewal time. */
export function checkMasterKey() {
  if (process.platform === 'win32') return masterKeySource();
  loadMasterKey();
  return masterKeySource();
}

function loadMasterKey() {
  if (masterKey) return masterKey;
  const { file, create } = keyFile();
  if (create && !fs.existsSync(file)) {
    fs.writeFileSync(file, `${crypto.randomBytes(32).toString('base64')}\n`, { mode: 0o600, flag: 'wx' });
  }
  const raw = fs.readFileSync(file, 'utf8').trim();
  const key = /^[A-Za-z0-9+/=]{43,44}$/.test(raw) ? Buffer.from(raw, 'base64') : crypto.createHash('sha256').update(raw).digest();
  if (key.length !== 32) throw new Error(`Master key in ${file} is not 32 bytes`);
  masterKey = key;
  return key;
}

export async function protect(text) {
  if (process.platform === 'win32') {
    const { stdout } = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PS_PROTECT], { input: text });
    return `dpapi:${stdout.trim()}`;
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', loadMasterKey(), iv);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return `aes:${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${ct.toString('base64')}`;
}

export async function unprotect(blob) {
  const i = blob.indexOf(':');
  const [kind, data] = [blob.slice(0, i), blob.slice(i + 1)];
  if (kind === 'plain') return Buffer.from(data, 'base64').toString('utf8');
  if (kind === 'aes') {
    const [iv, tag, ct] = data.split('.').map((x) => Buffer.from(x, 'base64'));
    const decipher = crypto.createDecipheriv('aes-256-gcm', loadMasterKey(), iv);
    decipher.setAuthTag(tag);
    try {
      return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
    } catch {
      throw new Error(`Cannot decrypt a stored key with the master key from ${masterKeySource()} (was the key replaced?)`);
    }
  }
  if (kind === 'dpapi') {
    if (process.platform !== 'win32') throw new Error('This key was encrypted with Windows DPAPI and can only be read on the Windows machine that created it');
    const { stdout } = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PS_UNPROTECT], { input: data });
    return stdout.trim();
  }
  throw new Error(`Unknown key encryption "${kind}"`);
}
