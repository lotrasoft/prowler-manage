// Publishes instance hostnames through the existing cloudflared tunnel.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import YAML from 'yaml';
import { run } from './exec.js';

const CF_API = 'https://api.cloudflare.com/client/v4';

/**
 * Read the cloudflared service's command line (and environment) from the OS service manager:
 * the Windows service ImagePath, or the systemd unit's ExecStart/Environment on Linux.
 * Returns null when no cloudflared service is installed.
 */
async function serviceCommandLine() {
  if (process.platform === 'win32') {
    try {
      const { stdout } = await run('reg', ['query', 'HKLM\SYSTEM\CurrentControlSet\Services\cloudflared', '/v', 'ImagePath']);
      return stdout;
    } catch {
      return null;
    }
  }
  try {
    const { stdout } = await run('systemctl', ['show', 'cloudflared', '-p', 'LoadState', '-p', 'ExecStart', '-p', 'Environment', '-p', 'EnvironmentFiles']);
    if (/^LoadState=not-found/m.test(stdout)) return null;
    // `cloudflared service install <token>` may keep the token in an EnvironmentFile.
    let text = stdout;
    for (const m of stdout.matchAll(/^EnvironmentFiles=(\S+)/gm)) {
      try {
        text += `\n${fs.readFileSync(m[1], 'utf8')}`;
      } catch {}
    }
    return text;
  } catch {
    return null;
  }
}

/**
 * Work out the tunnel type from the service command line. A remotely-managed tunnel runs as
 * `cloudflared tunnel run --token <base64 JSON {a: accountId, t: tunnelId, s: secret}>` (or with
 * TUNNEL_TOKEN in its environment). Only the account and tunnel ids are returned; the tunnel
 * secret is never kept.
 */
export function parseServiceCommandLine(text, platform = process.platform) {
  const result = { serviceInstalled: true, mode: null, accountId: '', tunnelId: '', configPath: '' };
  const token = text.match(/--token[\s=]+"?([A-Za-z0-9+/=_-]{20,})"?/) || text.match(/TUNNEL_TOKEN=["']?([A-Za-z0-9+/=_-]{20,})/);
  if (token) {
    try {
      const decoded = JSON.parse(Buffer.from(token[1], 'base64').toString('utf8'));
      result.mode = 'api';
      result.accountId = decoded.a || '';
      result.tunnelId = decoded.t || '';
    } catch {}
    return result;
  }
  const cfg = text.match(/--config[\s=]+"?([^"\s;]+?\.ya?ml)"?/i);
  result.mode = 'local';
  if (cfg) result.configPath = cfg[1];
  else if (platform === 'win32') result.configPath = path.join(os.homedir(), '.cloudflared', 'config.yml');
  else result.configPath = ['/etc/cloudflared/config.yml', '/usr/local/etc/cloudflared/config.yml', path.join(os.homedir(), '.cloudflared', 'config.yml')].find((f) => fs.existsSync(f)) || '/etc/cloudflared/config.yml';
  return result;
}

export async function detectTunnel() {
  const text = await serviceCommandLine();
  if (text === null) return { serviceInstalled: false, mode: null, accountId: '', tunnelId: '', configPath: '' };
  return parseServiceCommandLine(text);
}

async function restartService(log) {
  if (process.platform === 'win32') {
    await run('powershell', ['-NoProfile', '-Command', 'Restart-Service cloudflared'], { log });
    return;
  }
  try {
    await run('systemctl', ['restart', 'cloudflared'], { log });
  } catch {
    // Non-root service user: needs a sudoers rule (see deploy/sudoers.d-prowler-manage).
    await run('sudo', ['-n', 'systemctl', 'restart', 'cloudflared'], { log });
  }
}

// ---------- Remotely-managed tunnel (Cloudflare API) ----------

async function cf(settings, method, apiPath, body) {
  const token = settings.cloudflare.apiToken || process.env.CLOUDFLARE_API_TOKEN;
  if (!token) throw new Error('Cloudflare API token is not configured (Settings → Cloudflare)');
  const res = await fetch(`${CF_API}${apiPath}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.success === false) {
    const msg = (json.errors || []).map((e) => `${e.code}: ${e.message}`).join('; ') || res.statusText;
    throw new Error(`Cloudflare API ${method} ${apiPath} failed: ${msg}`);
  }
  return json.result;
}

async function resolveIds(settings) {
  const c = settings.cloudflare;
  let { accountId, tunnelId } = c;
  if (!accountId || !tunnelId) {
    const d = await detectTunnel();
    accountId ||= d.accountId;
    tunnelId ||= d.tunnelId;
  }
  if (!accountId || !tunnelId) throw new Error('Cloudflare account/tunnel id unknown; set them in Settings');
  return { accountId, tunnelId };
}

async function findZoneId(settings, hostname) {
  if (settings.cloudflare.zoneId) return settings.cloudflare.zoneId;
  const labels = hostname.split('.');
  for (let i = labels.length - 2; i >= 0; i--) {
    const name = labels.slice(i).join('.');
    const zones = await cf(settings, 'GET', `/zones?name=${encodeURIComponent(name)}`);
    if (zones?.length) return zones[0].id;
  }
  throw new Error(`No Cloudflare zone found for ${hostname}`);
}

function withRoute(ingress, hostname, service) {
  const rules = (ingress || []).filter((r) => r.hostname !== hostname);
  let catchAllIdx = rules.findIndex((r) => !r.hostname && !r.path);
  if (catchAllIdx === -1) {
    rules.push({ service: 'http_status:404' });
    catchAllIdx = rules.length - 1;
  }
  if (service) rules.splice(catchAllIdx, 0, { hostname, service, originRequest: {} });
  return rules;
}

async function apiSetRoute(settings, hostname, service, log) {
  const { accountId, tunnelId } = await resolveIds(settings);
  const base = `/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`;
  const current = (await cf(settings, 'GET', base))?.config || {};
  const ingress = withRoute(current.ingress, hostname, service);
  await cf(settings, 'PUT', base, { config: { ...current, ingress } });
  log(service ? `Tunnel ingress: ${hostname} → ${service}` : `Tunnel ingress: removed ${hostname}`);

  const zoneId = await findZoneId(settings, hostname);
  const target = `${tunnelId}.cfargotunnel.com`;
  const existing = await cf(settings, 'GET', `/zones/${zoneId}/dns_records?name=${encodeURIComponent(hostname)}`);
  if (service) {
    const record = { type: 'CNAME', name: hostname, content: target, proxied: true, comment: 'prowler-manage' };
    const cname = existing.find((r) => r.type === 'CNAME');
    if (cname) {
      await cf(settings, 'PUT', `/zones/${zoneId}/dns_records/${cname.id}`, record);
    } else if (existing.length) {
      throw new Error(`DNS name ${hostname} already has a ${existing[0].type} record; remove it first`);
    } else {
      await cf(settings, 'POST', `/zones/${zoneId}/dns_records`, record);
    }
    log(`DNS: ${hostname} CNAME ${target} (proxied)`);
  } else {
    for (const r of existing.filter((r) => r.type === 'CNAME' && r.content === target)) {
      await cf(settings, 'DELETE', `/zones/${zoneId}/dns_records/${r.id}`);
      log(`DNS: removed ${hostname}`);
    }
  }
}

// ---------- Locally-managed tunnel (config.yml) ----------

async function localSetRoute(settings, hostname, service, log) {
  const c = settings.cloudflare;
  const configPath = c.configPath || (await detectTunnel()).configPath;
  if (!configPath || !fs.existsSync(configPath)) throw new Error(`cloudflared config not found: ${configPath}`);
  const doc = YAML.parseDocument(fs.readFileSync(configPath, 'utf8'));
  const cfg = doc.toJS() || {};
  cfg.ingress = withRoute(cfg.ingress, hostname, service).map(({ originRequest, ...r }) => r);
  fs.copyFileSync(configPath, `${configPath}.bak`);
  fs.writeFileSync(configPath, YAML.stringify(cfg));
  log(`Updated ${configPath} (backup: config.yml.bak)`);

  const tunnel = c.tunnelName || c.tunnelId || cfg.tunnel;
  if (service && tunnel) {
    try {
      await run('cloudflared', ['tunnel', 'route', 'dns', '--overwrite-dns', tunnel, hostname], { log });
    } catch (e) {
      log(`WARNING: could not create DNS route (${e.message}); add a CNAME for ${hostname} manually`);
    }
  }
  try {
    await restartService(log);
    log('Restarted cloudflared service');
  } catch (e) {
    log(`WARNING: could not restart cloudflared (${e.message}); restart it manually (requires admin/root)`);
  }
}

export async function publish(settings, hostname, service, log) {
  const mode = settings.cloudflare.mode;
  if (mode === 'none' || !hostname) return log('Cloudflare publishing disabled; skipping');
  if (mode === 'local') return localSetRoute(settings, hostname, service, log);
  return apiSetRoute(settings, hostname, service, log);
}

export async function unpublish(settings, hostname, log) {
  const mode = settings.cloudflare.mode;
  if (mode === 'none' || !hostname) return;
  if (mode === 'local') return localSetRoute(settings, hostname, null, log);
  return apiSetRoute(settings, hostname, null, log);
}
