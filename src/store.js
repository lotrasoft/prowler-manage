// JSON-file persistence for manager settings and the instance registry.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DATA_DIR = process.env.PROWLER_MANAGE_DATA || path.join(ROOT, 'data');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const INSTANCES_FILE = path.join(DATA_DIR, 'instances.json');

const DEFAULT_SETTINGS = {
  instancesDir: process.env.PROWLER_MANAGE_INSTANCES || path.join(ROOT, 'instances'),
  baseDomain: '',
  uiPortBase: 3100,
  apiPortBase: 8100,
  neo4jMemory: '512M',
  certLifetimeMonths: 6,
  certRenewBeforeDays: 14,
  // Public client used for the delegated admin sign-in that creates each tenant's app registration.
  // Default: Microsoft Graph Command Line Tools (the client Connect-MgGraph uses). Replace with your own
  // multi-tenant public client (redirect URI http://localhost) if tenants block that app.
  setupClientId: '14d82eec-204b-4c2f-b7e8-296a70dab67e',
  cloudflare: {
    // "api": remotely-managed tunnel (token-based service), routes set via Cloudflare API
    // "local": locally-managed tunnel, routes written to config.yml
    // "none": don't publish, local access only
    mode: 'api',
    apiToken: '',
    accountId: '',
    tunnelId: '',
    zoneId: '',
    configPath: '',
    tunnelName: '',
  },
};

// Holds admin passwords, stack secrets and the Cloudflare token: owner-only on Linux (ignored on Windows).
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
if (process.platform !== 'win32') {
  // Tighten folders/files created by older versions or a permissive umask.
  try {
    fs.chmodSync(DATA_DIR, 0o700);
    for (const f of fs.readdirSync(DATA_DIR)) if (/\.(json|key)$/.test(f)) fs.chmodSync(path.join(DATA_DIR, f), 0o600);
  } catch {}
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.chmodSync(tmp, 0o600); // also tightens files created by older versions
  fs.renameSync(tmp, file);
}

export function getSettings() {
  const saved = readJson(SETTINGS_FILE, {});
  return {
    ...DEFAULT_SETTINGS,
    ...saved,
    cloudflare: { ...DEFAULT_SETTINGS.cloudflare, ...(saved.cloudflare || {}) },
  };
}

export function saveSettings(settings) {
  writeJson(SETTINGS_FILE, settings);
}

export function listInstances() {
  return readJson(INSTANCES_FILE, []);
}

export function getInstance(id) {
  return listInstances().find((i) => i.id === id);
}

export function upsertInstance(instance) {
  const all = listInstances();
  const idx = all.findIndex((i) => i.id === instance.id);
  instance.updatedAt = new Date().toISOString();
  if (idx === -1) all.push(instance);
  else all[idx] = instance;
  writeJson(INSTANCES_FILE, all);
  return instance;
}

export function patchInstance(id, patch) {
  const inst = getInstance(id);
  if (!inst) throw new Error(`Instance ${id} not found`);
  return upsertInstance({ ...inst, ...patch });
}

export function removeInstance(id) {
  writeJson(INSTANCES_FILE, listInstances().filter((i) => i.id !== id));
}
