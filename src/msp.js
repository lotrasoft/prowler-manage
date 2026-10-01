// MSP mode: one multi-tenant "Prowler" app registered in the MSP's own tenant. Each customer tenant
// approves it once through Microsoft's admin-consent URL (the customer's Global Admin, or the MSP
// itself through GDAP), which creates the enterprise app in the customer tenant. All MSP instances
// authenticate with the MSP app's certificate; tenant_id selects the customer.
import * as store from './store.js';
import * as prowler from './prowler.js';
import { openCertificate, EntraApp, jwtClaims } from './certs.js';

const LOGIN = 'https://login.microsoftonline.com';
export const NATIVE_REDIRECT = 'https://login.microsoftonline.com/common/oauth2/nativeclient';
export const GLOBAL_READER = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function config() {
  const m = store.getSettings().msp;
  if (!m?.clientId) throw new Error('Set up the MSP app first (Settings → MSP app)');
  return m;
}

/** Resolve a customer domain (or tenant ID) to its tenant ID via OpenID discovery. */
export async function resolveTenant(domainOrId) {
  const q = String(domainOrId || '').trim().toLowerCase();
  if (!q) throw new Error('Enter the customer\'s domain, e.g. contoso.com or contoso.onmicrosoft.com');
  const res = await fetch(`${LOGIN}/${encodeURIComponent(q)}/v2.0/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`No Microsoft 365 tenant found for "${q}"`);
  const { issuer } = await res.json();
  const tenantId = issuer.match(/[0-9a-f-]{36}/i)?.[0];
  if (!tenantId) throw new Error(`Could not resolve the tenant for "${q}"`);
  return tenantId;
}

/**
 * Make sure `uri` is a registered return address of the MSP app (Microsoft only redirects to those).
 * The app edits its own registration (it owns itself and has Application.ReadWrite.OwnedBy in the
 * MSP tenant). Returns true if the address was added just now.
 */
export async function ensureRedirectUri(uri) {
  const m = config();
  if ((m.redirectUris || []).includes(uri)) return false;
  const app = new EntraApp({ tenantId: m.tenantId, clientId: m.clientId });
  let token;
  try {
    token = await app.token(await currentCert());
  } catch (e) {
    throw new Error(`Could not sign in as the MSP app to register ${uri}: ${e.message}`);
  }
  const current = (await app.graph(token, 'GET', `/applications/${m.appObjectId}?$select=web`)).web?.redirectUris || [];
  let added = false;
  if (!current.includes(uri)) {
    try {
      await app.graph(token, 'PATCH', `/applications/${m.appObjectId}`, { web: { redirectUris: [...current, uri] } });
    } catch (e) {
      throw new Error(`Could not add ${uri} to the MSP app's redirect URIs (${e.message}). Add it by hand: Entra admin center → App registrations → ${m.displayName} → Authentication → Web → Redirect URIs`);
    }
    added = true;
  }
  const s = store.getSettings();
  store.saveSettings({ ...s, msp: { ...s.msp, redirectUris: [...new Set([...current, uri])] } });
  return added;
}

/** The link a customer's Global Admin opens to approve the MSP app in their tenant. */
export function consentLink(tenantId) {
  const params = new URLSearchParams({ client_id: config().clientId, redirect_uri: NATIVE_REDIRECT });
  return `${LOGIN}/${tenantId}/adminconsent?${params}`;
}

export async function currentCert() {
  return openCertificate(config().cert.current);
}

export function creds(inst, opened) {
  return { tenantId: inst.tenantId, clientId: config().clientId, certificateContent: opened.pfx };
}

/**
 * Check whether the customer approved the MSP app and whether it has Global Reader there.
 * Returns null if not consented yet.
 */
export async function inspectCustomer(tenantId, cert) {
  const m = config();
  const app = new EntraApp({ tenantId, clientId: m.clientId });
  let token;
  try {
    token = await app.token(cert);
  } catch {
    return null; // app not in the tenant yet (not consented)
  }
  const roles = jwtClaims(token).roles || [];
  if (!roles.includes('Directory.Read.All')) return null;
  const org = (await app.graph(token, 'GET', '/organization?$select=id,displayName,verifiedDomains')).value[0];
  const domain = (org.verifiedDomains.find((d) => d.isInitial) || org.verifiedDomains.find((d) => d.isDefault)).name.toLowerCase();
  let globalReader = null;
  try {
    const sp = await app.graph(token, 'GET', `/servicePrincipals(appId='${m.clientId}')?$select=id`);
    const ra = await app.graph(token, 'GET', `/roleManagement/directory/roleAssignments?$filter=principalId eq '${sp.id}'`);
    globalReader = ra.value.some((a) => a.roleDefinitionId === GLOBAL_READER);
  } catch {}
  return { orgName: org.displayName, tenantDomain: domain, roles, globalReader };
}

export function globalReaderInstructions(inst) {
  const name = config().displayName || 'the Prowler app';
  return [
    `"${name}" does not have the Global Reader role in ${inst.tenantDomain}, so Exchange and Teams checks will fail.`,
    'Fix it with "Approve now" on the instance (sign in as the customer\'s admin or through GDAP), or have the customer assign it:',
    `  Entra admin center → Roles & admins → Global Reader → Add assignments → "${name}"`,
  ].join('\n');
}

/**
 * Wait (inside a job) until the customer approves the MSP app. Shows the consent link meanwhile.
 * Returns Prowler credentials.
 */
export async function ensureConsent(inst, save, log, job) {
  const cert = await currentCert();
  if (!inst.mspConsent?.consented) {
    const link = consentLink(inst.tenantId);
    if (job) {
      job.notice = [
        `Waiting for ${inst.tenantDomain} to approve the Prowler app.`,
        'Send this link to the customer\'s Global Administrator, or open it yourself if you have Global Administrator there through GDAP:',
        '',
        link,
        '',
        'After approving, Microsoft shows a blank page; that is expected. The manager checks every 15 seconds and continues on its own.',
      ].join('\n');
      job.links = [{ label: 'Open consent page', href: link }];
    }
    log('ACTION NEEDED: the customer must approve the Prowler app (see the link above)');
    const deadline = Date.now() + 60 * 60000;
    let info = null;
    let lastLog = Date.now();
    while (!(info = await inspectCustomer(inst.tenantId, cert))) {
      if (Date.now() > deadline) throw new Error('The customer has not approved the app yet; use Launch again once they have');
      if (Date.now() - lastLog > 120000) {
        log('…still waiting for approval');
        lastLog = Date.now();
      }
      await sleep(15000);
    }
    if (job) {
      job.notice = null;
      job.links = [];
    }
    log(`Approved by ${info.orgName}`);
    save({ tenantDomain: info.tenantDomain, mspConsent: { consented: true, globalReader: info.globalReader, checkedAt: new Date().toISOString() } });
  }
  if (inst.mspConsent.globalReader === false) {
    const info = await inspectCustomer(inst.tenantId, cert).catch(() => null);
    if (info) save({ mspConsent: { ...inst.mspConsent, globalReader: info.globalReader, checkedAt: new Date().toISOString() } });
    if (inst.mspConsent.globalReader === false) for (const line of globalReaderInstructions(inst).split('\n')) log(`WARNING: ${line}`);
  }
  return creds(inst, cert);
}

/** After a launch: make sure Prowler has the MSP app's current certificate. */
export async function syncProwler(inst, log) {
  if (inst.authMethod !== 'msp' || !inst.init?.done) return;
  const cert = await currentCert();
  if (inst.prowlerCertThumbprint === cert.thumbprint) return;
  await prowler.updateCredentials(inst, creds(inst, cert), log);
  store.patchInstance(inst.id, { prowlerCertThumbprint: cert.thumbprint });
}

/** After the MSP certificate rotates: update every running MSP instance (others sync on Launch). */
export async function pushCertificateToInstances(opened, log) {
  for (const inst of store.listInstances().filter((i) => i.authMethod === 'msp' && i.init?.done)) {
    try {
      if (await prowler.isApiUp(inst)) {
        await prowler.updateCredentials(inst, creds(inst, opened), log);
        store.patchInstance(inst.id, { prowlerCertThumbprint: opened.thumbprint });
        log(`${inst.name}: switched to the new certificate`);
      } else {
        log(`${inst.name}: not running; will switch on next Launch (old certificate stays valid during the overlap)`);
      }
    } catch (e) {
      log(`WARNING: ${inst.name}: could not update Prowler (${e.message}); it will retry on next Launch`);
    }
  }
}
