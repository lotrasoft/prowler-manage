import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import * as store from './store.js';
import * as prowler from './prowler.js';
import * as tunnel from './cloudflare.js';
import * as renewal from './renewal.js';
import * as onboarding from './onboarding.js';
import * as msp from './msp.js';
import { masterKeySource, checkMasterKey } from './secrets.js';
import { startJob, getJob, isBusy, busyKeys } from './jobs.js';
import * as updater from './updater.js';

const PORT = Number(process.env.PORT || 4500);
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

const app = express();
app.use(express.json({ limit: '1mb' }));

// OAuth redirects from Microsoft sign-in / admin consent land on the root URL.
app.get('/', async (req, res, next) => {
  if (!req.query.state) return next();
  try {
    res.redirect(await onboarding.handleRedirect(req.query));
  } catch (e) {
    next(e);
  }
});
app.use(express.static(PUBLIC_DIR));

const DOMAIN_RE = /^(?!-)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.(?!-)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,}$/;
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);

function slugify(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'instance';
}

function portFree(port) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
  });
}

async function allocatePort(base, used) {
  for (let p = base; p < base + 1000; p++) if (!used.has(p) && (await portFree(p))) return p;
  throw new Error(`No free port found from ${base}`);
}

const stripCert = (r) => r && { thumbprint: r.thumbprint, notBefore: r.notBefore, notAfter: r.notAfter, verified: r.verified, keyId: r.keyId, removeError: r.removeError };

function certSummary(c = {}) {
  return { current: stripCert(c.current), next: stripCert(c.next), previous: stripCert(c.previous), autoRenew: c.autoRenew || {} };
}

function credentialSummary(inst) {
  const settings = store.getSettings();
  if (inst.authMethod === 'msp') {
    return { method: 'msp', ...certSummary(settings.msp?.cert), consent: inst.mspConsent || {}, renewBeforeDays: settings.certRenewBeforeDays };
  }
  if (inst.authMethod !== 'certificate') return { method: 'secret' };
  const c = inst.cert || {};
  const strip = stripCert;
  return {
    method: 'certificate',
    current: strip(c.current),
    next: strip(c.next),
    previous: strip(c.previous),
    autoRenew: c.autoRenew || {},
    renewBeforeDays: settings.certRenewBeforeDays,
  };
}

/** Public view of an instance: no secrets. */
function view(inst, statuses) {
  const { secrets, adminPassword, cert, ...rest } = inst;
  rest.credential = credentialSummary(inst);
  let runtime = 'unknown';
  if (statuses) {
    const s = statuses[prowler.projectName(inst)];
    // The one-shot api-init container always shows as exited(1) next to the running services.
    const exited = Number(s?.match(/exited\((\d+)\)/)?.[1] || 0);
    runtime = !s ? 'not deployed' : /running/.test(s) ? (exited > 1 ? 'degraded' : 'running') : 'stopped';
    rest.runtimeDetail = s || '';
  }
  return { ...rest, runtime, url: prowler.publicUrl(inst), localUrl: `http://localhost:${inst.uiPort}`, busy: isBusy(inst.id) };
}

function requireInstance(id) {
  const inst = store.getInstance(id);
  if (!inst) throw new HttpError(404, 'Instance not found');
  if (isBusy(id)) throw new HttpError(409, 'Another operation is running for this instance');
  return inst;
}

function validateCreds(body, { requireSecret }) {
  const creds = {
    tenantId: (body.tenantId || '').trim(),
    clientId: (body.clientId || '').trim(),
    clientSecret: body.clientSecret || '',
  };
  if (!GUID_RE.test(creds.tenantId)) throw new HttpError(400, 'Tenant ID must be a GUID');
  if (!GUID_RE.test(creds.clientId)) throw new HttpError(400, 'Client (application) ID must be a GUID');
  if (requireSecret && !creds.clientSecret) throw new HttpError(400, 'Client secret is required');
  return creds;
}

function validateHostname(hostname, selfId) {
  if (!hostname) return '';
  hostname = hostname.trim().toLowerCase();
  if (!DOMAIN_RE.test(hostname)) throw new HttpError(400, 'Hostname is not a valid domain name');
  if (store.listInstances().some((i) => i.hostname === hostname && i.id !== selfId)) {
    throw new HttpError(409, `Hostname ${hostname} is already used by another instance`);
  }
  return hostname;
}

// M365 credentials awaiting first-time initialization. Held in memory only (never written to
// disk) so a create that fails part-way can be resumed with Launch while the manager is running.
const pendingCreds = new Map();

// Deploy (or re-deploy) the stack, publish it and run first-time initialization.
async function launch(inst, creds, log, job) {
  if (creds) pendingCreds.set(inst.id, creds);
  creds ||= pendingCreds.get(inst.id);
  const settings = store.getSettings();
  const save = (patch) => Object.assign(inst, store.patchInstance(inst.id, patch));
  const useCert = inst.authMethod === 'certificate';
  // Show the certificate upload instructions right away so the admin can upload while the stack boots.
  if (useCert) await renewal.prepareBootstrap(inst, log, job);
  prowler.rewriteConfig(inst, settings);
  log(`Starting ${prowler.projectName(inst)}`);
  try {
    await prowler.compose(inst, ['up', '-d', '--remove-orphans'], log);
  } catch (e) {
    // Slow first boots can trip a dependency healthcheck; the second attempt usually succeeds.
    log(`First start attempt failed (${e.message}); retrying once`);
    await prowler.compose(inst, ['up', '-d', '--remove-orphans'], log);
  }
  await prowler.waitHealthy(inst, log);
  if (inst.authMethod === 'msp') {
    if (!inst.mspConsent?.consented) save({ state: 'awaiting consent' });
    creds = await msp.ensureConsent(inst, save, log, job);
  }
  if (useCert) {
    save({ state: inst.cert?.current?.verified ? inst.state : 'awaiting certificate' });
    creds = await renewal.ensureBootstrapped(inst, log, job);
  }
  if (!inst.init?.done) {
    save({ state: 'initializing' });
    await prowler.initialize(inst, creds, save, log);
  }
  pendingCreds.delete(inst.id);
  if (useCert) {
    await renewal.syncProwler(inst, log);
    await renewal.checkReadiness(inst, log);
  }
  if (inst.authMethod === 'msp') await msp.syncProwler(inst, log);
  if (inst.hostname && !inst.published) {
    await tunnel.publish(settings, inst.hostname, `http://localhost:${inst.uiPort}`, log);
    save({ published: true });
  }
  save({ state: 'ready', lastError: null });
  log(`Prowler is available at ${prowler.publicUrl(inst)}`);
}

// ---------- Settings ----------

/** Public addresses of this manager (e.g. its Cloudflare hostname): https origins only. */
function parseManagerUrls(value) {
  const list = (Array.isArray(value) ? value : String(value).split(/[\s,]+/)).map((x) => x.trim()).filter(Boolean);
  return [
    ...new Set(
      list.map((x) => {
        let u;
        try {
          u = new URL(/^[a-z]+:\/\//i.test(x) ? x : `https://${x}`);
        } catch {
          throw new HttpError(400, `Invalid manager address: ${x}`);
        }
        if (u.protocol !== 'https:') throw new HttpError(400, `Manager address must use https: ${x}`);
        return u.origin;
      }),
    ),
  ];
}

app.get('/api/settings', wrap(async (req, res) => {
  const s = store.getSettings();
  const mspInfo = s.msp?.clientId ? { ...s.msp, cert: certSummary(s.msp.cert), instances: store.listInstances().filter((i) => i.authMethod === 'msp').length, busy: isBusy('msp') } : null;
  // How this request reached us: through Cloudflare (tunnel) and whether Cloudflare Access vouched for it.
  const access = {
    viaCloudflare: !!(req.get('cf-ray') || req.get('cf-connecting-ip')),
    cloudflareAccess: !!req.get('cf-access-jwt-assertion'),
    user: req.get('cf-access-authenticated-user-email') || null,
  };
  res.json({ ...s, msp: mspInfo, access, cloudflare: { ...s.cloudflare, apiToken: undefined, hasApiToken: !!(s.cloudflare.apiToken || process.env.CLOUDFLARE_API_TOKEN) } });
}));

app.get('/api/settings/detect', wrap(async (req, res) => {
  const [tunnelInfo, release, docker] = await Promise.all([
    tunnel.detectTunnel(),
    prowler.latestRelease().catch((e) => `error: ${e.message}`),
    prowler.dockerCheck(),
  ]);
  let keyStorage;
  try {
    keyStorage = masterKeySource();
  } catch (e) {
    keyStorage = `ERROR: ${e.message}`;
  }
  res.json({ tunnel: tunnelInfo, latestRelease: release, docker, platform: process.platform, keyStorage });
}));

app.put('/api/settings', wrap(async (req, res) => {
  const cur = store.getSettings();
  const b = req.body || {};
  const cf = { ...cur.cloudflare, ...(b.cloudflare || {}) };
  if (!b.cloudflare?.apiToken) cf.apiToken = cur.cloudflare.apiToken; // blank = keep
  delete cf.hasApiToken;
  if (!['api', 'local', 'none'].includes(cf.mode)) throw new HttpError(400, 'Invalid Cloudflare mode');
  const next = {
    ...cur,
    instancesDir: b.instancesDir || cur.instancesDir,
    baseDomain: (b.baseDomain ?? cur.baseDomain).trim().toLowerCase(),
    uiPortBase: Number(b.uiPortBase) || cur.uiPortBase,
    apiPortBase: Number(b.apiPortBase) || cur.apiPortBase,
    neo4jMemory: b.neo4jMemory || cur.neo4jMemory,
    managerUrls: b.managerUrls !== undefined ? parseManagerUrls(b.managerUrls) : cur.managerUrls || [],
    certLifetimeMonths: Math.min(24, Math.max(1, Number(b.certLifetimeMonths) || cur.certLifetimeMonths)),
    certRenewBeforeDays: Math.min(90, Math.max(1, Number(b.certRenewBeforeDays) || cur.certRenewBeforeDays)),
    cloudflare: cf,
  };
  if (next.certRenewBeforeDays >= next.certLifetimeMonths * 28) {
    throw new HttpError(400, 'Renewal window must be shorter than the certificate lifetime');
  }
  store.saveSettings(next);
  res.json({ ok: true });
}));

// ---------- Instances ----------

app.get('/api/instances', wrap(async (req, res) => {
  const statuses = await prowler.composeStatuses();
  res.json({ dockerAvailable: statuses !== null, instances: store.listInstances().map((i) => view(i, statuses)) });
}));

app.get('/api/instances/:id/credentials', wrap(async (req, res) => {
  const inst = store.getInstance(req.params.id);
  if (!inst) throw new HttpError(404, 'Instance not found');
  res.json({ email: inst.adminEmail, password: inst.adminPassword });
}));

app.get('/api/instances/:id/logs', wrap(async (req, res) => {
  const inst = store.getInstance(req.params.id);
  if (!inst) throw new HttpError(404, 'Instance not found');
  const service = /^[a-z-]+$/.test(req.query.service || '') ? [req.query.service] : [];
  const { stdout } = await prowler.compose(inst, ['logs', '--no-color', '--tail', '300', ...service]).catch((e) => ({ stdout: e.message }));
  res.type('text/plain').send(stdout);
}));

// ---------- Tenant onboarding (Microsoft sign-in) ----------

app.post('/api/onboarding', wrap(async (req, res) => {
  const b = req.body || {};
  try {
    // The browser's Origin header says which address the manager is being used from (localhost,
    // or e.g. a Cloudflare hostname); sign-ins return there if it's an approved address.
    const origin = req.get('origin') || null;
    res.json(await onboarding.startSession({ kind: b.kind, name: (b.name || '').trim(), customer: b.customer, instanceId: b.instanceId, origin }));
  } catch (e) {
    throw new HttpError(400, e.message);
  }
}));

// ---------- MSP app ----------

app.get('/api/msp/consent-link', wrap(async (req, res) => {
  try {
    const tenantId = await msp.resolveTenant(req.query.customer);
    res.json({ tenantId, link: msp.consentLink(tenantId) });
  } catch (e) {
    throw new HttpError(400, e.message);
  }
}));

app.post('/api/msp/renew-certificate', wrap(async (req, res) => {
  if (!store.getSettings().msp?.clientId) throw new HttpError(400, 'The MSP app is not set up');
  if (isBusy('msp')) throw new HttpError(409, 'A certificate operation for the MSP app is already running');
  const job = startJob('msp', 'Renew MSP app certificate', null, (log, job) => renewal.renewMspNow(log, job));
  res.status(202).json({ jobId: job.id });
}));

app.get('/api/msp/certificate.cer', wrap(async (req, res) => {
  const cert = store.getSettings().msp?.cert;
  const slot = ['current', 'next', 'previous'].includes(req.query.slot) ? req.query.slot : 'current';
  const rec = cert?.[slot];
  if (!rec) throw new HttpError(404, 'Certificate not found');
  res.set('Content-Type', 'application/pkix-cert');
  res.set('Content-Disposition', `attachment; filename="prowler-msp-${rec.thumbprint.slice(0, 8)}.cer"`);
  res.send(Buffer.from(rec.certDer, 'base64'));
}));

app.get('/api/onboarding/:id', wrap(async (req, res) => {
  const s = onboarding.getSession(req.params.id);
  if (!s) throw new HttpError(404, 'Tenant connection not found or expired');
  res.json(s);
}));

app.post('/api/instances', wrap(async (req, res) => {
  const b = req.body || {};
  const settings = store.getSettings();
  const name = (b.name || '').trim();
  if (!name) throw new HttpError(400, 'Name is required');
  // Tenant source: a completed Microsoft sign-in (MSP approval or dedicated app), an MSP customer
  // that will approve later through the consent link, or details entered by hand.
  let connected = null;
  let authMethod;
  let tenantDomain;
  let creds;
  if (b.onboardingId) {
    try {
      connected = onboarding.completedSession(b.onboardingId);
    } catch (e) {
      throw new HttpError(400, e.message);
    }
    authMethod = connected.kind === 'msp' ? 'msp' : 'certificate';
    tenantDomain = connected.tenantDomain;
    creds = { tenantId: connected.tenantId, clientId: connected.clientId };
  } else if (b.mspCustomer) {
    let m;
    try {
      m = msp.config();
      creds = { tenantId: await msp.resolveTenant(b.mspCustomer), clientId: m.clientId };
    } catch (e) {
      throw new HttpError(400, e.message);
    }
    authMethod = 'msp';
    tenantDomain = String(b.mspCustomer).trim().toLowerCase();
  } else {
    authMethod = b.authMethod === 'secret' ? 'secret' : 'certificate';
    tenantDomain = (b.tenantDomain || '').trim().toLowerCase();
    creds = validateCreds(b, { requireSecret: authMethod === 'secret' });
  }
  if (!DOMAIN_RE.test(tenantDomain)) throw new HttpError(400, 'Tenant domain must look like contoso.onmicrosoft.com');
  const all = store.listInstances();
  if (all.some((i) => i.tenantDomain === tenantDomain || i.tenantId === creds.tenantId)) {
    throw new HttpError(409, 'An instance for this Microsoft 365 tenant already exists');
  }
  let slug = slugify(b.slug || name);
  for (let n = 2; all.some((i) => i.slug === slug); n++) slug = `${slugify(b.slug || name)}-${n}`;

  let hostname = b.hostname?.trim() || (settings.baseDomain ? `prowler-${slug}.${settings.baseDomain}` : '');
  hostname = validateHostname(hostname);
  if (!hostname && settings.cloudflare.mode !== 'none') {
    throw new HttpError(400, 'Hostname is required (or set a base domain in Settings)');
  }
  const adminEmail = (b.adminEmail || '').trim();
  if (!EMAIL_RE.test(adminEmail)) throw new HttpError(400, 'Admin email is invalid');
  const adminPassword = b.adminPassword || prowler.generatePassword();
  if (adminPassword.length < 12) throw new HttpError(400, 'Admin password must be at least 12 characters');

  const usedUi = new Set(all.map((i) => i.uiPort));
  const usedApi = new Set(all.map((i) => i.apiPort));
  const inst = {
    id: crypto.randomUUID(),
    name,
    slug,
    tenantDomain,
    tenantId: creds.tenantId,
    clientId: creds.clientId,
    authMethod,
    ...(connected?.kind === 'direct'
      ? { appCreatedByManager: true, cert: { appObjectId: connected.appObjectId, current: { ...connected.cert, verified: true, verifiedAt: new Date().toISOString(), prowlerSynced: true } } }
      : {}),
    ...(authMethod === 'msp'
      ? { mspConsent: connected ? { consented: true, globalReader: connected.globalReader, checkedAt: new Date().toISOString() } : { consented: false } }
      : {}),
    hostname,
    adminEmail,
    adminPassword,
    uiPort: await allocatePort(settings.uiPortBase, usedUi),
    apiPort: await allocatePort(settings.apiPortBase, usedApi),
    dir: path.join(settings.instancesDir, slug),
    version: null,
    secrets: prowler.generateSecrets(),
    init: {},
    published: false,
    state: 'creating',
    createdAt: new Date().toISOString(),
  };
  store.upsertInstance(inst);
  if (connected) onboarding.discardSession(b.onboardingId);

  const job = startJob(inst.id, `Create ${name}`, 'installing', async (log, job) => {
    if (authMethod === 'certificate') await renewal.prepareBootstrap(inst, log, job);
    inst.version = await prowler.latestRelease();
    log(`Latest Prowler release: ${inst.version}`);
    store.patchInstance(inst.id, { version: inst.version });
    await prowler.writeStack(inst, settings, log);
    log('Pulling images (this can take several minutes the first time)');
    await prowler.compose(inst, ['pull'], log);
    await launch(inst, authMethod === 'secret' ? creds : null, log, job);
  });
  res.status(202).json({ instance: view(inst, null), jobId: job.id });
}));

app.put('/api/instances/:id', wrap(async (req, res) => {
  const inst = requireInstance(req.params.id);
  const b = req.body || {};
  const settings = store.getSettings();
  const name = (b.name ?? inst.name).trim() || inst.name;
  const hostname = b.hostname !== undefined ? validateHostname(b.hostname, inst.id) : inst.hostname;
  const oldMethod = inst.authMethod || 'secret';
  if (oldMethod === 'msp') {
    // Credentials come from the MSP app; only name, hostname and upgrades can change.
    delete b.authMethod;
    delete b.tenantId;
    delete b.clientId;
    delete b.clientSecret;
  }
  const authMethod = b.authMethod ? (b.authMethod === 'secret' ? 'secret' : 'certificate') : oldMethod;
  const switching = authMethod !== oldMethod;
  const ids = validateCreds({ tenantId: b.tenantId || inst.tenantId, clientId: b.clientId || inst.clientId }, { requireSecret: false });
  const idsChanged = ids.tenantId !== inst.tenantId || ids.clientId !== inst.clientId;
  let creds = null;
  if (oldMethod !== 'msp' && authMethod === 'secret' && (switching || idsChanged || b.clientSecret)) {
    creds = validateCreds({ ...ids, clientSecret: b.clientSecret }, { requireSecret: true });
  }
  // A new app registration (or switching auth method) means starting over with a new certificate.
  const resetCert = oldMethod !== 'msp' && (switching || (authMethod === 'certificate' && idsChanged));
  const upgrade = !!b.upgrade;

  const job = startJob(inst.id, `Update ${name}`, 'updating', async (log, job) => {
    const oldHost = inst.hostname;
    const hostChanged = hostname !== oldHost;
    if (resetCert && inst.cert?.current) {
      log(`Note: certificate ${inst.cert.current.thumbprint} is no longer used; remove it from the old app registration`);
    }
    Object.assign(inst, store.patchInstance(inst.id, { name, hostname, ...ids, authMethod, ...(resetCert ? { cert: null } : {}) }));

    if (upgrade) {
      const latest = await prowler.latestRelease();
      if (latest === inst.version) log(`Already on latest release ${latest}`);
      else {
        log(`Upgrading ${inst.version} → ${latest}`);
        inst.version = latest;
        store.patchInstance(inst.id, { version: latest });
        await prowler.writeStack(inst, settings, log);
        await prowler.compose(inst, ['pull'], log);
      }
    } else {
      prowler.rewriteConfig(inst, settings);
    }

    if (hostChanged && oldHost && inst.published) {
      await tunnel.unpublish(settings, oldHost, log);
      Object.assign(inst, store.patchInstance(inst.id, { published: false }));
    }
    const wasInitialized = !!inst.init?.done;
    log('Applying configuration');
    await launch(inst, creds, log, job);
    if (creds && wasInitialized) await prowler.updateCredentials(inst, creds, log);
  });
  res.status(202).json({ jobId: job.id });
}));

app.post('/api/instances/:id/launch', wrap(async (req, res) => {
  const inst = requireInstance(req.params.id);
  const job = startJob(inst.id, `Launch ${inst.name}`, 'starting', async (log, job) => {
    if (!fs.existsSync(path.join(inst.dir, 'docker-compose.yml'))) {
      if (!inst.version) inst.version = await prowler.latestRelease();
      store.patchInstance(inst.id, { version: inst.version });
      await prowler.writeStack(inst, store.getSettings(), log);
    }
    await launch(inst, null, log, job);
  });
  res.status(202).json({ jobId: job.id });
}));

app.post('/api/instances/:id/renew-certificate', wrap(async (req, res) => {
  const inst = requireInstance(req.params.id);
  if (inst.authMethod !== 'certificate' || !inst.cert?.current?.verified) {
    throw new HttpError(400, 'This instance does not use an active certificate');
  }
  const job = startJob(inst.id, `Renew certificate · ${inst.name}`, null, (log, job) => renewal.renewNow(inst, log, job));
  res.status(202).json({ jobId: job.id });
}));

app.get('/api/instances/:id/certificate.cer', wrap(async (req, res) => {
  const inst = store.getInstance(req.params.id);
  const slot = ['current', 'next', 'previous'].includes(req.query.slot) ? req.query.slot : 'current';
  const rec = inst?.cert?.[slot];
  if (!rec) throw new HttpError(404, 'Certificate not found');
  res.set('Content-Type', 'application/pkix-cert');
  res.set('Content-Disposition', `attachment; filename="prowler-${inst.slug}-${rec.thumbprint.slice(0, 8)}.cer"`);
  res.send(Buffer.from(rec.certDer, 'base64'));
}));

app.post('/api/instances/:id/stop', wrap(async (req, res) => {
  const inst = requireInstance(req.params.id);
  const job = startJob(inst.id, `Stop ${inst.name}`, 'stopping', async (log) => {
    await prowler.compose(inst, ['stop'], log);
    store.patchInstance(inst.id, { state: 'stopped' });
  });
  res.status(202).json({ jobId: job.id });
}));

app.delete('/api/instances/:id', wrap(async (req, res) => {
  const inst = requireInstance(req.params.id);
  const deleteApp = req.query.deleteApp === '1';
  const job = startJob(inst.id, `Delete ${inst.name}`, 'deleting', async (log) => {
    const settings = store.getSettings();
    if (inst.authMethod === 'msp') {
      log(`Note: the "${store.getSettings().msp?.displayName || 'Prowler'}" enterprise app stays in ${inst.tenantDomain}; the customer can remove it under Enterprise applications`);
    } else if (deleteApp) await renewal.deleteAppRegistration(inst, log);
    if (inst.hostname && inst.published) await tunnel.unpublish(settings, inst.hostname, log);
    if (fs.existsSync(path.join(inst.dir, 'docker-compose.yml'))) {
      log('Removing containers, networks and volumes');
      await prowler.compose(inst, ['down', '-v', '--remove-orphans'], log);
    }
    if (fs.existsSync(inst.dir)) {
      log(`Deleting ${inst.dir}`);
      await prowler.removeInstanceDir(inst.dir, log);
    }
    store.removeInstance(inst.id);
    pendingCreds.delete(inst.id);
  });
  res.status(202).json({ jobId: job.id });
}));

// ---------- Self-update ----------

app.get('/api/update/source', wrap(async (req, res) => {
  res.json(await updater.source());
}));

app.get('/api/update/check', wrap(async (req, res) => {
  try {
    res.json(await updater.check());
  } catch (e) {
    throw new HttpError(502, `Update check failed: ${e.message}`);
  }
}));

app.get('/api/version', wrap(async (req, res) => {
  res.json(await updater.currentVersion());
}));

app.post('/api/update', wrap(async (req, res) => {
  const c = await updater.check().catch((e) => {
    throw new HttpError(502, `Update check failed: ${e.message}`);
  });
  if (!c.updateAvailable) throw new HttpError(409, 'Already up to date');
  if (!c.canUpdate) throw new HttpError(409, c.reason || 'Update not possible');
  const running = busyKeys();
  if (running.length) {
    // A restart would kill installs, renewals or approvals in progress.
    throw new HttpError(409, `Wait for the ${running.length} running operation(s) to finish first`);
  }
  const job = startJob('manager', `Update Prowler Manager to ${c.latest}`, null, (log) => updater.update(log, { shutdown }));
  res.status(202).json({ jobId: job.id, from: c.current, to: c.latest });
}));

app.get('/api/jobs/:id', wrap(async (req, res) => {
  const job = getJob(req.params.id);
  if (!job) throw new HttpError(404, 'Job not found (the manager may have restarted)');
  const since = Number(req.query.since || 0);
  res.json({ ...job, log: job.log.slice(since), logLength: job.log.length });
}));

app.use((err, req, res, next) => {
  if (!err.status) console.error(err);
  res.status(err.status || 500).json({ error: err.message });
});

// Jobs live in memory; anything mid-flight when the manager stopped is marked as interrupted.
for (const inst of store.listInstances()) {
  if (['creating', 'installing', 'initializing', 'awaiting certificate', 'awaiting consent', 'starting', 'updating', 'stopping', 'deleting'].includes(inst.state)) {
    store.patchInstance(inst.id, { state: 'error', lastError: `Interrupted while ${inst.state}; use Launch to resume` });
  }
}

renewal.startScheduler();

function shutdown(code = 0) {
  server.close(() => process.exit(code));
  setTimeout(() => process.exit(code), 3000).unref();
}

// After a self-update the new process starts while the old one is still releasing the port.
let listenAttempts = 0;
function onListenError(e) {
  if (e.code === 'EADDRINUSE' && ++listenAttempts <= 20) {
    setTimeout(() => server.listen(PORT, HOST), 1000);
    return;
  }
  console.error(`Cannot listen on ${HOST}:${PORT}: ${e.message}`);
  process.exit(1);
}

const server = app.listen(PORT, HOST, async () => {
  console.log(`Prowler Manager running at http://${HOST}:${PORT}`);
  await updater.init().catch(() => {});
  try {
    console.log(`Private keys are encrypted with: ${checkMasterKey()}`);
  } catch (e) {
    console.error(`ERROR: ${e.message}. Certificate operations will fail until this is fixed.`);
  }
  const docker = await prowler.dockerCheck();
  for (const problem of docker.problems) console.warn(`WARNING: ${problem}`);
});
server.on('error', onListenError);

// systemd / Ctrl+C: stop accepting requests and exit. Prowler stacks keep running; jobs that were
// in flight are marked interrupted on the next start (see above) and resume with Launch.
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    console.log(`${sig} received, shutting down`);
    shutdown(0);
  });
}
