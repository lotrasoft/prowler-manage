// Interactive Microsoft sign-in flows (run in a popup; Microsoft redirects back to http://localhost:PORT).
//
// msp-app  One-time. Sign in to the MSP's own tenant; create the multi-tenant "Prowler" app there
//          (Prowler's application permissions, a certificate, self-ownership for renewal).
//
// msp      Per customer: "Approve now", in two steps:
//            1. Microsoft's admin-consent page for the MSP app in the customer tenant
//               (/{tenant}/adminconsent). Whoever approves, a customer Privileged Role Admin or the MSP
//               through GDAP, creates the enterprise app there with all its permissions.
//            2. A sign-in with Microsoft's Graph Command Line Tools client (localhost, or a device
//               code from a public address), used once to assign the Global Reader role, which
//               consent alone can't do. The MSP app itself declares no delegated permissions, so
//               customers never grant it a standing RoleManagement.ReadWrite.Directory consent;
//               a grant left by older versions is removed here.
//          If step 2 fails, the approval from step 1 still counts; Global Reader is reported missing.
//
// direct   Per customer, without the MSP app: a customer admin signs in, the manager creates a
//          dedicated app registration in that tenant, then Microsoft's admin-consent page grants it.
//          With an instanceId it recreates the app registration of an existing certificate instance
//          whose app was deleted (the user confirms first), and switches the instance and its
//          Prowler to the new app.
//
// azure    Per instance: an admin with Owner or User Access Administrator on the customer's Azure
//          subscriptions signs in (Azure CLI's public client, Azure Resource Manager scope); the
//          manager assigns Prowler's roles on every subscription and registers them (src/azure.js).
//
// Return address: Microsoft sends the browser back to the address the manager is being used from
// (http://localhost:PORT, or a public https address such as a Cloudflare hostname), taken from the
// browser itself. The Graph Command Line Tools client only accepts localhost, so from a public
// address the flows that use it (msp-app, direct) sign in with a device code instead.
//
// Admin tokens live only in memory and are dropped as soon as a flow finishes.
import crypto from 'node:crypto';
import * as store from './store.js';
import * as msp from './msp.js';
import * as azure from './azure.js';
import * as prowler from './prowler.js';
import { certCreds } from './renewal.js';
import { isBusy } from './jobs.js';
import { createCertificate, sealCertificate, openCertificate, EntraApp, jwtClaims } from './certs.js';

const LOGIN = 'https://login.microsoftonline.com';
const GRAPH = 'https://graph.microsoft.com/v1.0';
const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';

const g = (scope) => `https://graph.microsoft.com/${scope}`;
const SCOPES = {
  direct: ['openid', 'profile', g('User.Read'), g('Application.ReadWrite.All'), g('RoleManagement.ReadWrite.Directory')].join(' '),
  'msp-app': ['openid', 'profile', g('User.Read'), g('Application.ReadWrite.All'), g('AppRoleAssignment.ReadWrite.All')].join(' '),
  'msp-app-update': ['openid', 'profile', g('User.Read'), g('Application.ReadWrite.All'), g('AppRoleAssignment.ReadWrite.All')].join(' '),
  // "Approve now" step 2 (Graph Command Line Tools, the admin's own token): assign Global Reader.
  msp: ['openid', 'profile', g('User.Read'), g('RoleManagement.ReadWrite.Directory')].join(' '),
  // Re-approving an existing customer: also remove the delegated grant older versions left behind.
  'msp-cleanup': ['openid', 'profile', g('User.Read'), g('RoleManagement.ReadWrite.Directory'), g('DelegatedPermissionGrant.ReadWrite.All')].join(' '),
  azure: azure.SIGN_IN_SCOPE,
};
const scopesFor = (s) => SCOPES[s.kind === 'msp' && s.cleanupGrant ? 'msp-cleanup' : s.kind];

// Application permissions Prowler's M365 provider uses, per resource API. Missing APIs (e.g. Teams
// in a tenant without Teams) are skipped with a warning.
const REQUIRED = [
  {
    name: 'Microsoft Graph',
    appId: GRAPH_APP_ID,
    roles: [
      'AccessReview.Read.All',
      'AuditLog.Read.All',
      'Directory.Read.All',
      'OnPremDirectorySynchronization.Read.All',
      'Policy.Read.All',
      'RoleManagementPolicy.Read.Directory',
      'SecurityIdentitiesHealth.Read.All',
      'SecurityIdentitiesSensors.Read.All',
      'SharePointTenantSettings.Read.All',
      'ThreatHunting.Read.All',
      'DeviceManagementServiceConfig.Read.All',
      'DeviceManagementConfiguration.Read.All',
      'DeviceManagementManagedDevices.Read.All',
    ],
  },
  { name: 'Office 365 Exchange Online', appId: '00000002-0000-0ff1-ce00-000000000000', roles: ['Exchange.ManageAsApp'] },
  { name: 'Skype and Teams Tenant Admin API', appId: '48ac35b8-9aa8-4d74-927d-1f4a14a0b239', roles: ['application_access'] },
];
// Lets an app roll its own certificate (renewal.js). Declared by dedicated per-tenant apps; for the
// MSP app it is granted only in the MSP tenant, never requested from customers.
const OWNED_BY = 'Application.ReadWrite.OwnedBy';

const sessions = new Map();
const SESSION_TTL = 2 * 3600000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Where our own apps (MSP app, dedicated apps) send the browser back to, under the manager's address. */
export const CALLBACK_PATH = '/auth/callback';

export function localRedirect(port = process.env.PORT || 4500) {
  return `http://localhost:${port}`;
}

export const isLocalUrl = (url) => new URL(url).hostname === 'localhost';

/**
 * Where Microsoft should send the browser back to: the address the browser is using the manager
 * from. It's only trusted when the request really arrived on that address (Origin matches Host):
 * true for the manager's own page, false for a request triggered by any other website.
 */
export function resolveReturnUrl(origin, host) {
  if (!origin) return localRedirect();
  let u;
  try {
    u = new URL(origin);
  } catch {
    throw new Error(`Invalid address ${origin}`);
  }
  if (['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)) {
    // Microsoft treats localhost specially (any port); 127.0.0.1 would need its own registration.
    return localRedirect(u.port || (u.protocol === 'https:' ? 443 : 80));
  }
  if (!host || u.host.toLowerCase() !== String(host).toLowerCase()) {
    throw new Error('Microsoft sign-in must be started from the manager\'s own page');
  }
  if (u.protocol !== 'https:') {
    throw new Error(`Microsoft only returns to https addresses (or localhost); open the manager at https://${u.host}`);
  }
  return u.origin;
}

function publicSession(s) {
  const { verifier, token, refreshToken, cert, deviceCode, clientSecret, ...pub } = s;
  return pub;
}

export function getSession(id) {
  const s = sessions.get(id);
  return s && publicSession(s);
}

/** Session data needed to create an instance. Call discardSession once the instance is saved. */
export function completedSession(id) {
  const s = sessions.get(id);
  if (!s || !['direct', 'msp'].includes(s.kind)) throw new Error('Tenant connection not found or expired; connect the tenant again');
  if (s.status !== 'done') throw new Error('Tenant connection has not finished yet');
  return {
    kind: s.kind,
    tenantId: s.tenantId,
    tenantDomain: s.tenantDomain,
    orgName: s.orgName,
    clientId: s.clientId,
    appObjectId: s.appObjectId,
    cert: s.cert,
    globalReader: s.globalReader,
  };
}

export function discardSession(id) {
  sessions.delete(id);
}

/** Begin a flow; returns the Microsoft URL to open in a popup. */
export async function startSession({ kind = 'direct', name, customer, instanceId, clientSecret, origin, host }) {
  for (const [id, s] of sessions) if (Date.now() - s.createdAt > SESSION_TTL) sessions.delete(id);
  if (!SCOPES[kind]) throw new Error(`Unknown connection type ${kind}`);
  const settings = store.getSettings();
  const s = { id: crypto.randomBytes(16).toString('hex'), kind, name: name || 'Prowler', status: 'signing-in', steps: [], createdAt: Date.now() };
  s.verifier = crypto.randomBytes(32).toString('base64url');
  // base: the manager's address in the browser. redirect: return URL for our own apps (registered on
  // them). signInRedirect: where the sign-in itself returns (Graph CLI Tools only accepts the bare
  // http://localhost, so its sign-in uses the base address).
  s.base = resolveReturnUrl(origin, host);
  s.redirect = s.base + CALLBACK_PATH;
  s.signInRedirect = s.base;
  s.signInClientId = settings.setupClientId;
  s.authority = 'organizations';
  const extra = { prompt: 'select_account' };

  if (kind === 'msp-app') {
    if (settings.msp?.clientId) throw new Error('The MSP app is already set up');
  } else if (kind === 'msp-app-update') {
    if (!settings.msp?.clientId) throw new Error('The MSP app is not set up yet');
  } else if (kind === 'msp') {
    const m = msp.config();
    s.tenantId = await msp.resolveTenant(customer);
    const existing = store.listInstances().find((i) => i.tenantId === s.tenantId);
    // Re-approving an existing MSP instance (e.g. to add Global Reader) is fine; anything else is a duplicate.
    if (existing && !(existing.authMethod === 'msp' && existing.id === instanceId)) {
      throw new Error(`This tenant already has an instance ("${existing.name}")`);
    }
    s.instanceId = instanceId || null;
    s.cleanupGrant = Boolean(existing);
    s.authority = s.tenantId;
    s.clientId = m.clientId;
    delete extra.prompt; // the admin just signed in on the consent page; reuse that session
    // The consent page returns to an address registered on the MSP app (when it was created, or with
    // Settings → Re-approve MSP app). Apps from older versions were registered without the path.
    const registered = await msp.registeredRedirects();
    const pick = [s.base + CALLBACK_PATH, s.base, `${s.base}/`].find((u) => registered.includes(u));
    if (!pick) {
      throw new Error(`${s.base} is not a return address of the MSP app. Open Settings → Re-approve MSP app from this address once to register it, or use the manager from a registered address (${registered.filter((u) => !u.includes('nativeclient')).join(', ') || 'none'}).`);
    }
    s.redirect = pick;
  } else if (kind === 'direct' && instanceId) {
    // Recreate a deleted app registration for an existing instance.
    const inst = store.getInstance(instanceId);
    if (!inst) throw new Error('Instance not found');
    if (isBusy(inst.id)) throw new Error('Another operation is running for this instance');
    if (!(await appMissing(inst))) throw new Error(`App registration ${inst.clientId} still exists in ${inst.tenantDomain}; nothing to recreate`);
    s.instanceId = inst.id;
    s.name = inst.name;
    s.authority = inst.tenantId;
  } else if (kind === 'azure') {
    const inst = store.getInstance(instanceId);
    if (!inst) throw new Error('Instance not found');
    if (!inst.init?.done) throw new Error('Finish setting up the instance first (Launch)');
    if (isBusy(inst.id)) throw new Error('Another operation is running for this instance');
    if (inst.authMethod === 'secret' && !clientSecret) throw new Error("Enter the app's client secret");
    s.instanceId = inst.id;
    s.tenantId = inst.tenantId;
    s.orgName = inst.name;
    s.tenantDomain = inst.tenantDomain;
    s.clientSecret = inst.authMethod === 'secret' ? clientSecret : null;
    s.signInClientId = AZURE_CLI_CLIENT;
    s.authority = inst.tenantId;
  }
  sessions.set(s.id, s);

  // Public address + a localhost-only public client: sign in with a device code.
  if (kind !== 'msp' && !isLocalUrl(s.base) && [DEFAULT_SETUP_CLIENT, AZURE_CLI_CLIENT].includes(s.signInClientId)) {
    await startDeviceCode(s);
    return { id: s.id, authUrl: `/onboarding.html?id=${s.id}` };
  }
  const params = new URLSearchParams({
    client_id: s.signInClientId,
    response_type: 'code',
    redirect_uri: s.signInRedirect,
    response_mode: 'query',
    scope: scopesFor(s),
    state: `${s.id}.signin`,
    code_challenge: crypto.createHash('sha256').update(s.verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...extra,
  });
  const signInUrl = `${LOGIN}/${s.authority}/oauth2/v2.0/authorize?${params}`;
  if (kind === 'msp') {
    // Step 1 is the admin-consent page; step 2 (this sign-in) follows once it's approved.
    s.signInUrl = signInUrl;
    const consent = new URLSearchParams({ client_id: s.clientId, redirect_uri: s.redirect, state: `${s.id}.mspconsent` });
    return { id: s.id, authUrl: `${LOGIN}/${s.tenantId}/adminconsent?${consent}` };
  }
  return { id: s.id, authUrl: signInUrl };
}

const DEFAULT_SETUP_CLIENT = '14d82eec-204b-4c2f-b7e8-296a70dab67e';
// Azure CLI: a Microsoft public client pre-authorized for Azure Resource Manager (localhost or device code).
const AZURE_CLI_CLIENT = '04b07795-8ddb-461a-bbee-02f9e1bf7b46';

/** Device-code sign-in: the admin enters a short code at microsoft.com/devicelogin. */
async function startDeviceCode(s) {
  const res = await fetch(`${LOGIN}/${s.authority}/oauth2/v2.0/devicecode`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: s.signInClientId, scope: scopesFor(s) }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Device sign-in unavailable: ${(json.error_description || json.error || res.statusText).split(/\r?\n/)[0]}`);
  s.deviceCode = json.device_code;
  s.userCode = json.user_code;
  s.verificationUri = json.verification_uri;
  s.status = 'device-code';
  step(s, 'Waiting for the sign-in code to be entered at Microsoft');
  pollDeviceCode(s, Number(json.interval) || 5, Date.now() + (Number(json.expires_in) || 900) * 1000)
    .catch((e) => (s.kind === 'msp' && s.consented ? mspSignInFailed(s, e) : fail(s, e)));
}

async function pollDeviceCode(s, interval, deadline) {
  const next = { direct: directSetup, 'msp-app': createMspApp, 'msp-app-update': updateMspApp, msp: mspApproved, azure: azureSetup }[s.kind];
  while (Date.now() < deadline) {
    await sleep(interval * 1000);
    if (s.status !== 'device-code') return; // abandoned or failed
    const res = await fetch(`${LOGIN}/${s.authority}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: s.signInClientId, grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: s.deviceCode }),
    });
    const json = await res.json().catch(() => ({}));
    if (res.ok) {
      s.deviceCode = null;
      s.status = 'working';
      acceptTokens(s, json);
      return next(s);
    }
    if (json.error === 'authorization_pending') continue;
    if (json.error === 'slow_down') {
      interval += 5;
      continue;
    }
    throw new Error(`Sign-in failed: ${(json.error_description || json.error || res.statusText).split(/\r?\n/)[0]}`);
  }
  throw new Error('The sign-in code expired; start again');
}

function step(s, text) {
  s.steps.push(text);
}

function fail(s, err) {
  s.status = 'error';
  s.error = err.message || String(err);
  s.token = null;
  s.refreshToken = null;
  s.clientSecret = null;
}

function done(s) {
  s.status = 'done';
  s.token = null;
  s.refreshToken = null;
  s.clientSecret = null;
}

async function graph(s, method, path, body) {
  const res = await fetch(`${GRAPH}${path}`, {
    method,
    headers: { Authorization: `Bearer ${s.token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const msg = json.error?.message || res.statusText;
    const hint = res.status === 403 ? ' (sign in as a Privileged Role Administrator; through GDAP, your role for this customer must include it)' : '';
    const err = new Error(`${method} ${path.split('?')[0]} → ${res.status}: ${msg}${hint}`);
    err.status = res.status;
    throw err;
  }
  return json;
}

/** Handle the OAuth redirect back to the manager (GET /?state=…). Returns where to send the browser. */
export async function handleRedirect(query) {
  const [id, phase] = String(query.state || '').split('.');
  const s = sessions.get(id);
  if (!s) return '/onboarding.html?expired=1';
  const page = `/onboarding.html?id=${id}`;

  if (s.kind === 'msp' && phase === 'mspconsent') {
    if (query.error || String(query.admin_consent).toLowerCase() !== 'true') {
      fail(s, new Error(query.error ? `${query.error}: ${(query.error_description || '').split(/\r?\n/)[0]}` : 'The permissions were not approved'));
      return page;
    }
    s.consented = true;
    step(s, 'Prowler app approved (enterprise app created in the customer tenant)');
    step(s, 'Signing in once more to assign the Global Reader role…');
    if (isLocalUrl(s.base)) return s.signInUrl; // straight on to step 2
    // Graph Command Line Tools only returns to localhost: from a public address, use a device code.
    startDeviceCode(s).catch((e) => mspSignInFailed(s, e));
    return page;
  }
  if (s.kind === 'msp' && phase === 'signin' && query.error && s.consented) {
    s.status = 'working';
    mspSignInFailed(s, new Error(`sign-in for the Global Reader assignment failed (${(query.error_description || query.error).split(/\r?\n/)[0]})`));
    return page;
  }

  if (query.error) {
    // Right after creation a new app may not have replicated to the consent endpoint yet.
    if (phase === 'consent' && /AADSTS700016/.test(query.error_description || '') && (s.consentRetries = (s.consentRetries || 0) + 1) <= 6) {
      step(s, 'App registration not visible to the consent page yet; retrying…');
      s.status = 'preparing-consent';
      setTimeout(() => (s.status = 'awaiting-consent'), 10000);
      return page;
    }
    fail(s, new Error(`${query.error}: ${(query.error_description || '').split(/\r?\n/)[0]}`));
    return page;
  }

  if (phase === 'signin' && s.status === 'signing-in' && query.code) {
    s.status = 'working';
    const next = { direct: directSetup, 'msp-app': createMspApp, 'msp-app-update': updateMspApp, msp: mspApproved, azure: azureSetup }[s.kind];
    exchangeCode(s, query.code)
      .then(() => next(s))
      .catch((e) => (s.kind === 'msp' && s.consented ? mspSignInFailed(s, e) : fail(s, e)));
    return page;
  }
  if (phase === 'consent' && ['awaiting-consent', 'preparing-consent'].includes(s.status)) {
    if (String(query.admin_consent).toLowerCase() !== 'true') {
      fail(s, new Error('Permissions were not granted'));
      return page;
    }
    s.status = 'verifying';
    step(s, 'Permissions granted');
    removeTemporaryRedirect(s)
      .then(() => waitForPermissions(s))
      .catch((e) => fail(s, e));
  }
  return page;
}

async function exchangeCode(s, code) {
  const form = {
    client_id: s.signInClientId,
    grant_type: 'authorization_code',
    code,
    redirect_uri: s.signInRedirect,
    code_verifier: s.verifier,
    scope: scopesFor(s),
  };
  const res = await fetch(`${LOGIN}/${s.authority}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Sign-in failed: ${(json.error_description || json.error || res.statusText).split(/\r?\n/)[0]}`);
  acceptTokens(s, json);
}

function acceptTokens(s, json) {
  const idClaims = jwtClaims(json.id_token);
  s.token = json.access_token;
  // Azure: kept to redeem a Graph token for the same admin if the app can't add its own secret.
  if (s.kind === 'azure') s.refreshToken = json.refresh_token || null;
  s.signInTenantId = idClaims.tid;
  s.signedInAs = idClaims.preferred_username || idClaims.name;
  step(s, `Signed in as ${s.signedInAs}`);
}

async function organization(s) {
  const org = (await graph(s, 'GET', '/organization?$select=id,displayName,verifiedDomains')).value[0];
  s.orgName = org.displayName;
  s.tenantDomain = (org.verifiedDomains.find((d) => d.isInitial) || org.verifiedDomains.find((d) => d.isDefault)).name.toLowerCase();
  return org;
}

async function resourceAccess(s, { includeOwnedBy }) {
  const access = [];
  const grantable = [];
  for (const api of REQUIRED) {
    let sp;
    try {
      sp = await graph(s, 'GET', `/servicePrincipals(appId='${api.appId}')?$select=id,appRoles,oauth2PermissionScopes`);
    } catch (e) {
      if (e.status !== 404) throw e;
      try {
        // First-party service principal missing in this tenant; creating it usually works.
        sp = await graph(s, 'POST', '/servicePrincipals', { appId: api.appId });
      } catch {
        step(s, `WARNING: ${api.name} is not available in this tenant; skipped`);
        continue;
      }
    }
    const roles = [...api.roles, ...(includeOwnedBy && api.appId === GRAPH_APP_ID ? [OWNED_BY] : [])];
    const entries = [];
    for (const value of roles) {
      const role = sp.appRoles?.find((r) => r.value === value);
      if (!role) {
        step(s, `WARNING: permission ${value} not found on ${api.name}; skipped`);
        continue;
      }
      entries.push({ id: role.id, type: 'Role' });
    }
    if (entries.length) access.push({ resourceAppId: api.appId, resourceAccess: entries });
    if (api.appId === GRAPH_APP_ID) grantable.push(sp);
  }
  return { access, graphSp: grantable[0] };
}

async function assignGlobalReader(s, spId) {
  const existing = await graph(s, 'GET', `/roleManagement/directory/roleAssignments?$filter=principalId eq '${spId}'`).catch(() => ({ value: [] }));
  if (existing.value.some((a) => a.roleDefinitionId === msp.GLOBAL_READER)) {
    step(s, 'Global Reader role already assigned');
    return true;
  }
  try {
    await graph(s, 'POST', '/roleManagement/directory/roleAssignments', { principalId: spId, roleDefinitionId: msp.GLOBAL_READER, directoryScopeId: '/' });
    step(s, 'Assigned the Global Reader role (needed for Exchange and Teams checks)');
    return true;
  } catch (e) {
    step(s, `WARNING: could not assign Global Reader (${e.message}); Exchange/Teams checks will fail until it is assigned`);
    return false;
  }
}

// ---------- msp-app: one-time, in the MSP tenant ----------

/** Return URLs registered on the MSP app: localhost and the address it was set up from. */
function mspReturnUrls(s, existing = []) {
  return [...new Set([...existing, localRedirect() + CALLBACK_PATH, s.redirect, msp.NATIVE_REDIRECT])];
}

/**
 * Prowler's application permissions only. No delegated permissions: the "Approve now" sign-in uses
 * Graph Command Line Tools, so customers never consent to a delegated grant for the MSP app.
 */
async function mspPermissions(s) {
  return resourceAccess(s, { includeOwnedBy: false });
}

/** Self-ownership + Application.ReadWrite.OwnedBy (MSP tenant only), for certificate self-renewal. */
async function ensureSelfRenewal(s, appObjectId, spId, graphSp) {
  try {
    await graph(s, 'POST', `/applications/${appObjectId}/owners/$ref`, { '@odata.id': `https://graph.microsoft.com/v1.0/directoryObjects/${spId}` });
  } catch (e) {
    if (!/already exist/i.test(e.message)) throw e;
  }
  const ownedBy = graphSp.appRoles.find((r) => r.value === OWNED_BY);
  try {
    await graph(s, 'POST', `/servicePrincipals/${graphSp.id}/appRoleAssignedTo`, { principalId: spId, resourceId: graphSp.id, appRoleId: ownedBy.id });
  } catch (e) {
    if (!/already exist/i.test(e.message)) throw e;
  }
}

/**
 * Settings → Re-approve MSP app: bring the existing MSP app up to date. Adds this browser address as
 * a return URL, refreshes the permission list, and re-checks self-ownership and OwnedBy.
 */
async function updateMspApp(s) {
  const m = store.getSettings().msp;
  await organization(s);
  if (s.signInTenantId !== m.tenantId) throw new Error(`Sign in to the MSP tenant (${m.tenantDomain}); you signed in to ${s.tenantDomain}`);
  const app = await graph(s, 'GET', `/applications/${m.appObjectId}?$select=id,appId,displayName,web`);
  const { access, graphSp } = await mspPermissions(s);
  const redirectUris = mspReturnUrls(s, app.web?.redirectUris || []);
  await graph(s, 'PATCH', `/applications/${app.id}`, { requiredResourceAccess: access, web: { redirectUris } });
  step(s, `Updated "${app.displayName}": return address ${s.redirect}, permissions refreshed (application permissions only; no delegated permissions)`);
  const sp = await graph(s, 'GET', `/servicePrincipals(appId='${app.appId}')?$select=id`);
  await ensureSelfRenewal(s, app.id, sp.id, graphSp);
  step(s, 'Checked self-ownership and certificate self-renewal permission');
  const settings = store.getSettings();
  store.saveSettings({ ...settings, msp: { ...settings.msp, redirectUris } });
  step(s, 'Customers that approved earlier keep working; ones approved from now on get the refreshed permissions');
  done(s);
}

async function createMspApp(s) {
  await organization(s);
  step(s, `MSP tenant: ${s.orgName} (${s.tenantDomain})`);
  const { access, graphSp } = await mspPermissions(s);

  const material = createCertificate('prowler-msp', store.getSettings().certLifetimeMonths);
  const sealed = await sealCertificate(material);
  const displayName = `Prowler – ${s.orgName}`;
  const app = await graph(s, 'POST', '/applications', {
    displayName,
    signInAudience: 'AzureADMultipleOrgs',
    notes: 'Prowler Microsoft 365 security scanning (read-only), operated by prowler-manage. Customers approve it through admin consent.',
    requiredResourceAccess: access,
    keyCredentials: [{ type: 'AsymmetricX509Cert', usage: 'Verify', key: material.certDer, displayName: `prowler-manage ${material.thumbprint}` }],
    web: { redirectUris: mspReturnUrls(s) },
  });
  step(s, `Created multi-tenant app "${displayName}" (${app.appId}) with certificate ${material.thumbprint.slice(0, 8)}…`);
  const sp = await graph(s, 'POST', '/servicePrincipals', { appId: app.appId });
  await ensureSelfRenewal(s, app.id, sp.id, graphSp);
  step(s, 'Allowed the app to renew its own certificate (owner of itself + Application.ReadWrite.OwnedBy, in your tenant only)');

  const settings = store.getSettings();
  store.saveSettings({
    ...settings,
    msp: {
      clientId: app.appId,
      appObjectId: app.id,
      tenantId: s.signInTenantId,
      tenantDomain: s.tenantDomain,
      displayName,
      redirectUris: mspReturnUrls(s),
      createdBy: s.signedInAs,
      createdAt: new Date().toISOString(),
      cert: { appObjectId: app.id, current: { ...sealed, verified: true, verifiedAt: new Date().toISOString() } },
    },
  });
  step(s, 'MSP app ready');
  done(s);
}

// ---------- msp: customer approved the MSP app ----------

async function mspApproved(s) {
  if (s.signInTenantId && s.signInTenantId !== s.tenantId) step(s, 'Signed in through partner (GDAP) access');
  await organization(s);
  step(s, `Customer: ${s.orgName} (${s.tenantDomain})`);
  const sp = await graph(s, 'GET', `/servicePrincipals(appId='${s.clientId}')?$select=id`);
  s.globalReader = await assignGlobalReader(s, sp.id);
  if (s.cleanupGrant) await removeDelegatedGrants(s, sp.id);
  s.token = null;
  await waitForAppRoles(s, await msp.currentCert());
  if (s.instanceId) {
    store.patchInstance(s.instanceId, { tenantDomain: s.tenantDomain, mspConsent: { consented: true, globalReader: s.globalReader, checkedAt: new Date().toISOString() } });
  }
  step(s, 'Customer connected');
  done(s);
}

/**
 * Older versions had the MSP app declare delegated User.Read + RoleManagement.ReadWrite.Directory,
 * so admin consent left a tenant-wide delegated grant. Prowler only uses application permissions;
 * remove the grant.
 */
async function removeDelegatedGrants(s, spId) {
  try {
    const grants = await graph(s, 'GET', `/oauth2PermissionGrants?$filter=clientId eq '${spId}'`);
    for (const grant of grants.value) await graph(s, 'DELETE', `/oauth2PermissionGrants/${grant.id}`);
    if (grants.value.length) step(s, `Removed the Prowler app's delegated permission grant (${grants.value.map((x) => x.scope.trim()).join(', ')}); it only needs its application permissions`);
  } catch (e) {
    step(s, `WARNING: could not remove the Prowler app's old delegated permission grant (${e.message}); remove it in the Entra admin center under Enterprise applications → the Prowler app → Permissions`);
  }
}

/** The Global Reader sign-in failed after approval: the approval stands; finish without it. */
function mspSignInFailed(s, err) {
  step(s, `WARNING: ${err.message}`);
  s.token = null;
  s.status = 'working';
  return finishMspWithoutSignIn(s).catch((e) => fail(s, e));
}

/** Approved, but no delegated sign-in: finish with the app's own token; Global Reader as found. */
async function finishMspWithoutSignIn(s) {
  const cert = await msp.currentCert();
  await waitForAppRoles(s, cert);
  const info = await msp.inspectCustomer(s.tenantId, cert);
  if (!info) throw new Error('The approval has not taken effect yet; try again in a few minutes');
  s.orgName = info.orgName;
  s.tenantDomain = info.tenantDomain;
  s.globalReader = info.globalReader === true;
  if (!s.globalReader) step(s, 'WARNING: Global Reader is not assigned; Exchange and Teams checks will fail until it is (use Approve on the instance later, or ask the customer)');
  if (s.instanceId) {
    store.patchInstance(s.instanceId, { tenantDomain: s.tenantDomain, mspConsent: { consented: true, globalReader: s.globalReader, checkedAt: new Date().toISOString() } });
  }
  step(s, `Customer connected: ${s.orgName}`);
  done(s);
}

// ---------- direct: dedicated app registration in the customer tenant ----------

/**
 * Whether a certificate instance's app registration no longer exists in the customer tenant (deleted
 * in Entra ID): Entra ID answers the app's own sign-in with AADSTS700016.
 */
export async function appMissing(inst) {
  if (inst.authMethod !== 'certificate' || !inst.cert?.current?.verified) return false;
  try {
    await new EntraApp(inst).token(await openCertificate(inst.cert.current));
    return false;
  } catch (e) {
    return e.aadCode === 700016;
  }
}

async function directSetup(s) {
  s.tenantId = s.signInTenantId;
  await organization(s);
  step(s, `Tenant: ${s.orgName} (${s.tenantDomain})`);
  if (s.instanceId) {
    const inst = store.getInstance(s.instanceId);
    if (!inst) throw new Error('Instance not found');
    if (s.tenantId !== inst.tenantId) throw new Error(`Sign in to ${inst.tenantDomain}; you signed in to ${s.tenantDomain}`);
  }
  const existing = store.listInstances().find((i) => i.tenantId === s.tenantId);
  if (existing && existing.id !== s.instanceId) throw new Error(`This tenant already has an instance ("${existing.name}")`);

  const { access } = await resourceAccess(s, { includeOwnedBy: true });
  const { certLifetimeMonths } = store.getSettings();
  const material = createCertificate(`prowler-${s.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`, certLifetimeMonths);
  s.cert = await sealCertificate(material);

  const app = await graph(s, 'POST', '/applications', {
    displayName: `Prowler – ${s.name}`,
    signInAudience: 'AzureADMyOrg',
    notes: 'Created by prowler-manage for Prowler Microsoft 365 security scanning (read-only). The certificate is renewed automatically.',
    requiredResourceAccess: access,
    keyCredentials: [{ type: 'AsymmetricX509Cert', usage: 'Verify', key: material.certDer, displayName: `prowler-manage ${material.thumbprint}` }],
    // Only needed for the admin-consent redirect; removed again afterwards.
    web: { redirectUris: [s.redirect] },
  });
  s.clientId = app.appId;
  s.appObjectId = app.id;
  step(s, `Created app registration "${app.displayName}" (${app.appId}) with certificate ${material.thumbprint.slice(0, 8)}…`);

  const sp = await graph(s, 'POST', '/servicePrincipals', { appId: app.appId });
  await graph(s, 'POST', `/applications/${app.id}/owners/$ref`, { '@odata.id': `https://graph.microsoft.com/v1.0/directoryObjects/${sp.id}` });
  step(s, 'Made the app an owner of its own registration (for certificate self-renewal)');
  s.globalReader = await assignGlobalReader(s, sp.id);

  const params = new URLSearchParams({ client_id: app.appId, redirect_uri: s.redirect, state: `${s.id}.consent` });
  s.consentUrl = `${LOGIN}/${s.tenantId}/adminconsent?${params}`;
  // Give the new app a moment to replicate before sending the admin to its consent page.
  s.status = 'preparing-consent';
  step(s, 'Preparing the permission request…');
  setTimeout(() => {
    if (s.status === 'preparing-consent') s.status = 'awaiting-consent';
  }, 15000);
}

async function removeTemporaryRedirect(s) {
  try {
    await graph(s, 'PATCH', `/applications/${s.appObjectId}`, { web: { redirectUris: [] } });
  } catch (e) {
    step(s, `WARNING: could not remove the temporary redirect URI (${e.message})`);
  }
}

async function waitForAppRoles(s, cert) {
  s.status = 'verifying';
  const app = new EntraApp({ tenantId: s.tenantId, clientId: s.clientId });
  step(s, 'Waiting for the permissions to take effect…');
  const deadline = Date.now() + 10 * 60000;
  for (;;) {
    try {
      const roles = jwtClaims(await app.token(cert)).roles || [];
      if (roles.includes('Directory.Read.All')) return;
    } catch {}
    if (Date.now() > deadline) throw new Error('Permissions did not take effect within 10 minutes; try again');
    await sleep(10000);
  }
}

async function waitForPermissions(s) {
  s.token = null;
  const cert = await openCertificate(s.cert);
  await waitForAppRoles(s, cert);
  if (s.instanceId) await replaceInstanceApp(s, cert);
  step(s, 'Tenant connected');
  done(s);
}

/** Recreated app registration: switch the instance, and its Prowler, to the new app and certificate. */
async function replaceInstanceApp(s, cert) {
  const inst = store.getInstance(s.instanceId);
  if (!inst) throw new Error('Instance not found');
  const oldClientId = inst.clientId;
  let updated = store.patchInstance(inst.id, {
    clientId: s.clientId,
    appCreatedByManager: true,
    cert: { appObjectId: s.appObjectId, current: { ...s.cert, verified: true, verifiedAt: new Date().toISOString(), prowlerSynced: false } },
    // The Azure client secret belonged to the deleted app; connecting Azure again adds a new one.
    ...(inst.azure ? { azure: { ...inst.azure, appSecret: null, renewError: null } } : {}),
  });
  step(s, `Instance switched from the deleted app ${oldClientId} to ${s.clientId}`);
  try {
    if (!(await prowler.isApiUp(updated))) {
      step(s, 'Prowler is not running; it receives the new app on the next Launch');
    } else {
      await prowler.updateCredentials(updated, certCreds(updated, cert), (t) => step(s, `Prowler: ${t}`));
      updated = store.patchInstance(inst.id, { cert: { ...updated.cert, current: { ...updated.cert.current, prowlerSynced: true } } });
    }
  } catch (e) {
    step(s, `WARNING: could not update Prowler (${e.message}); it receives the new app on the next Launch`);
  }
  if (inst.azure?.subscriptions?.length) {
    step(s, 'Azure subscriptions need the new app: run Azure again to assign its roles and update Prowler');
  }
}

// ---------- azure: roles on the customer's Azure subscriptions ----------

async function azureSetup(s) {
  const inst = store.getInstance(s.instanceId);
  if (!inst) throw new Error('Instance not found');
  if (s.signInTenantId && s.signInTenantId !== inst.tenantId) step(s, `Signed in to ${inst.tenantDomain} as a guest or partner account`);
  await azure.connect(inst, s.token, s.clientSecret, (text) => step(s, text), () => adminGraphToken(s));
  step(s, 'Azure subscriptions connected');
  done(s);
}

/** Graph token for the admin who signed in for Azure (same Azure CLI sign-in, refresh token). */
async function adminGraphToken(s) {
  if (!s.refreshToken) throw new Error('The sign-in did not return a refresh token; sign in again');
  const res = await fetch(`${LOGIN}/${s.authority}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: s.signInClientId, grant_type: 'refresh_token', refresh_token: s.refreshToken, scope: 'https://graph.microsoft.com/.default offline_access' }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Could not get a Microsoft Graph token for your sign-in: ${(json.error_description || json.error || res.statusText).split(/\r?\n/)[0]}`);
  return json.access_token;
}
