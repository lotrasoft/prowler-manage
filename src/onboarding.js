// Interactive Microsoft sign-in flows (run in a popup; Microsoft redirects back to http://localhost:PORT).
//
// msp-app  One-time. Sign in to the MSP's own tenant; create the multi-tenant "Prowler" app there
//          (Prowler's application permissions, a certificate, self-ownership for renewal).
//
// msp      Per customer: "Approve now", in two steps:
//            1. Microsoft's admin-consent page for the MSP app in the customer tenant
//               (/{tenant}/adminconsent). Whoever approves, the customer's Global Admin or the MSP
//               through GDAP, creates the enterprise app there with all its permissions.
//            2. A normal sign-in with the MSP app (its delegated permissions were just consented),
//               used once to assign the Global Reader role, which consent alone can't do.
//          If step 2 fails, the approval from step 1 still counts; Global Reader is reported missing.
//
// direct   Per customer, without the MSP app: a customer admin signs in, the manager creates a
//          dedicated app registration in that tenant, then Microsoft's admin-consent page grants it.
//
// Admin tokens live only in memory and are dropped as soon as a flow finishes.
import crypto from 'node:crypto';
import * as store from './store.js';
import * as msp from './msp.js';
import { createCertificate, sealCertificate, openCertificate, EntraApp, jwtClaims, clientAssertion } from './certs.js';

const LOGIN = 'https://login.microsoftonline.com';
const GRAPH = 'https://graph.microsoft.com/v1.0';
const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';

const g = (scope) => `https://graph.microsoft.com/${scope}`;
const SCOPES = {
  direct: ['openid', 'profile', g('User.Read'), g('Application.ReadWrite.All'), g('RoleManagement.ReadWrite.Directory')].join(' '),
  'msp-app': ['openid', 'profile', g('User.Read'), g('Application.ReadWrite.All'), g('AppRoleAssignment.ReadWrite.All')].join(' '),
  // Delegated permissions the MSP app declares; consented in step 1, used to assign Global Reader.
  msp: ['openid', 'profile', g('User.Read'), g('RoleManagement.ReadWrite.Directory')].join(' '),
};
// Delegated permissions the MSP app declares so the "Approve now" sign-in can assign Global Reader.
const MSP_DELEGATED = ['User.Read', 'RoleManagement.ReadWrite.Directory'];

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

export function redirectUri() {
  return `http://localhost:${process.env.PORT || 4500}`;
}

function publicSession(s) {
  const { verifier, token, cert, ...pub } = s;
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
export async function startSession({ kind = 'direct', name, customer, instanceId }) {
  for (const [id, s] of sessions) if (Date.now() - s.createdAt > SESSION_TTL) sessions.delete(id);
  if (!SCOPES[kind]) throw new Error(`Unknown connection type ${kind}`);
  const settings = store.getSettings();
  const s = { id: crypto.randomBytes(16).toString('hex'), kind, name: name || 'Prowler', status: 'signing-in', steps: [], createdAt: Date.now() };
  s.verifier = crypto.randomBytes(32).toString('base64url');
  s.signInClientId = settings.setupClientId;
  s.authority = 'organizations';
  const extra = { prompt: 'select_account' };

  if (kind === 'msp-app') {
    if (settings.msp?.clientId) throw new Error('The MSP app is already set up');
  } else if (kind === 'msp') {
    const m = msp.config();
    s.tenantId = await msp.resolveTenant(customer);
    const existing = store.listInstances().find((i) => i.tenantId === s.tenantId);
    // Re-approving an existing MSP instance (e.g. to add Global Reader) is fine; anything else is a duplicate.
    if (existing && !(existing.authMethod === 'msp' && existing.id === instanceId)) {
      throw new Error(`This tenant already has an instance ("${existing.name}")`);
    }
    s.instanceId = instanceId || null;
    s.signInClientId = m.clientId;
    s.authority = s.tenantId;
    s.clientId = m.clientId;
    delete extra.prompt; // the admin just signed in on the consent page; reuse that session
  }
  sessions.set(s.id, s);
  const params = new URLSearchParams({
    client_id: s.signInClientId,
    response_type: 'code',
    redirect_uri: redirectUri(),
    response_mode: 'query',
    scope: SCOPES[kind],
    state: `${s.id}.signin`,
    code_challenge: crypto.createHash('sha256').update(s.verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...extra,
  });
  const signInUrl = `${LOGIN}/${s.authority}/oauth2/v2.0/authorize?${params}`;
  if (kind === 'msp') {
    // Step 1 is the admin-consent page; step 2 (this sign-in) follows once it's approved.
    s.signInUrl = signInUrl;
    const consent = new URLSearchParams({ client_id: s.clientId, redirect_uri: redirectUri(), state: `${s.id}.mspconsent` });
    return { id: s.id, authUrl: `${LOGIN}/${s.tenantId}/adminconsent?${consent}` };
  }
  return { id: s.id, authUrl: signInUrl };
}

function step(s, text) {
  s.steps.push(text);
}

function fail(s, err) {
  s.status = 'error';
  s.error = err.message || String(err);
  s.token = null;
}

function done(s) {
  s.status = 'done';
  s.token = null;
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
    const hint = res.status === 403 ? ' (sign in as a Global Administrator or Privileged Role Administrator; through GDAP, your role for this customer must include one of them)' : '';
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
    return s.signInUrl; // straight on to step 2
  }
  if (s.kind === 'msp' && phase === 'signin' && query.error && s.consented) {
    step(s, `WARNING: sign-in for the Global Reader assignment failed (${(query.error_description || query.error).split(/\r?\n/)[0]})`);
    s.status = 'working';
    finishMspWithoutSignIn(s).catch((e) => fail(s, e));
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
    const next = { direct: directSetup, 'msp-app': createMspApp, msp: mspApproved }[s.kind];
    exchangeCode(s, query.code)
      .then(() => next(s))
      .catch((e) => {
        if (s.kind !== 'msp' || !s.consented) return fail(s, e);
        // The approval stands even if the Global Reader step didn't work out.
        step(s, `WARNING: ${e.message}`);
        s.token = null;
        return finishMspWithoutSignIn(s).catch((e2) => fail(s, e2));
      });
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
    redirect_uri: redirectUri(),
    code_verifier: s.verifier,
    scope: SCOPES[s.kind],
  };
  if (s.kind === 'msp') {
    // The MSP app is a confidential client: authenticate with its certificate.
    form.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    form.client_assertion = clientAssertion(await msp.currentCert(), s.tenantId, s.signInClientId);
  }
  const res = await fetch(`${LOGIN}/${s.authority}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Sign-in failed: ${(json.error_description || json.error || res.statusText).split(/\r?\n/)[0]}`);
  const idClaims = jwtClaims(json.id_token);
  s.token = json.access_token;
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

async function createMspApp(s) {
  await organization(s);
  step(s, `MSP tenant: ${s.orgName} (${s.tenantDomain})`);
  const { access, graphSp } = await resourceAccess(s, { includeOwnedBy: false });
  const graphEntry = access.find((a) => a.resourceAppId === GRAPH_APP_ID);
  for (const value of MSP_DELEGATED) {
    const scope = graphSp.oauth2PermissionScopes.find((p) => p.value === value);
    if (scope) graphEntry.resourceAccess.push({ id: scope.id, type: 'Scope' });
  }

  const material = createCertificate('prowler-msp', store.getSettings().certLifetimeMonths);
  const sealed = await sealCertificate(material);
  const displayName = `Prowler – ${s.orgName}`;
  const app = await graph(s, 'POST', '/applications', {
    displayName,
    signInAudience: 'AzureADMultipleOrgs',
    notes: 'Prowler Microsoft 365 security scanning (read-only), operated by prowler-manage. Customers approve it through admin consent.',
    requiredResourceAccess: access,
    keyCredentials: [{ type: 'AsymmetricX509Cert', usage: 'Verify', key: material.certDer, displayName: `prowler-manage ${material.thumbprint}` }],
    web: { redirectUris: [redirectUri(), msp.NATIVE_REDIRECT] },
  });
  step(s, `Created multi-tenant app "${displayName}" (${app.appId}) with certificate ${material.thumbprint.slice(0, 8)}…`);
  const sp = await graph(s, 'POST', '/servicePrincipals', { appId: app.appId });
  await graph(s, 'POST', `/applications/${app.id}/owners/$ref`, { '@odata.id': `https://graph.microsoft.com/v1.0/directoryObjects/${sp.id}` });
  const ownedBy = graphSp.appRoles.find((r) => r.value === OWNED_BY);
  await graph(s, 'POST', `/servicePrincipals/${graphSp.id}/appRoleAssignedTo`, { principalId: sp.id, resourceId: graphSp.id, appRoleId: ownedBy.id });
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
  s.token = null;
  await waitForAppRoles(s, await msp.currentCert());
  if (s.instanceId) {
    store.patchInstance(s.instanceId, { tenantDomain: s.tenantDomain, mspConsent: { consented: true, globalReader: s.globalReader, checkedAt: new Date().toISOString() } });
  }
  step(s, 'Customer connected');
  done(s);
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

async function directSetup(s) {
  s.tenantId = s.signInTenantId;
  await organization(s);
  step(s, `Tenant: ${s.orgName} (${s.tenantDomain})`);
  const existing = store.listInstances().find((i) => i.tenantId === s.tenantId);
  if (existing) throw new Error(`This tenant already has an instance ("${existing.name}")`);

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
    web: { redirectUris: [redirectUri()] },
  });
  s.clientId = app.appId;
  s.appObjectId = app.id;
  step(s, `Created app registration "${app.displayName}" (${app.appId}) with certificate ${material.thumbprint.slice(0, 8)}…`);

  const sp = await graph(s, 'POST', '/servicePrincipals', { appId: app.appId });
  await graph(s, 'POST', `/applications/${app.id}/owners/$ref`, { '@odata.id': `https://graph.microsoft.com/v1.0/directoryObjects/${sp.id}` });
  step(s, 'Made the app an owner of its own registration (for certificate self-renewal)');
  s.globalReader = await assignGlobalReader(s, sp.id);

  const params = new URLSearchParams({ client_id: app.appId, redirect_uri: redirectUri(), state: `${s.id}.consent` });
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
  await waitForAppRoles(s, await openCertificate(s.cert));
  step(s, 'Tenant connected');
  done(s);
}
