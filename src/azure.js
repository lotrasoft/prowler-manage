// Azure subscriptions for an instance, per Prowler's Azure provider requirements:
//   https://docs.prowler.com/user-guide/providers/azure/authentication
//
// The instance's app (MSP app, dedicated app or existing app registration) already has the Graph
// permissions Prowler's Azure provider needs (AuditLog.Read.All, Directory.Read.All, Policy.Read.All;
// they're part of the M365 set). What's missing is Azure RBAC on each subscription:
//   - Reader
//   - ProwlerRole, a custom role for the checks Reader doesn't cover
// An admin signs in once (delegated Azure Resource Manager token, Owner or User Access Administrator
// on the subscriptions); the manager creates/updates ProwlerRole and assigns both roles to the app's
// service principal on every enabled subscription in the tenant, then registers each subscription as
// an Azure provider in Prowler.
//
// Prowler's Azure provider only accepts a client secret (no certificate). For certificate and MSP
// instances the manager adds a password to the app registration itself (the app owns itself and has
// Application.ReadWrite.OwnedBy, as for certificate renewal) and renews it before it expires. The
// secret is only ever sent to Prowler; it is not written to disk. Instances that use a client secret
// reuse that secret.
import crypto from 'node:crypto';
import * as store from './store.js';
import * as prowler from './prowler.js';
import * as msp from './msp.js';
import { openCertificate, clientAssertion, jwtClaims, EntraApp } from './certs.js';

const LOGIN = 'https://login.microsoftonline.com';
const ARM = 'https://management.azure.com';
const GRAPH = 'https://graph.microsoft.com/v1.0';
// Built-in Reader role.
const READER = 'acdd72a7-3385-48ef-bd42-f606fba81ae7';
const PROWLER_ROLE = 'ProwlerRole';
const PROWLER_ACTIONS = ['Microsoft.Web/sites/host/listkeys/action', 'Microsoft.Web/sites/config/list/Action'];
// Graph application permissions Prowler's Azure provider uses.
const GRAPH_ROLES = ['AuditLog.Read.All', 'Directory.Read.All', 'Policy.Read.All'];
const DAY = 86400000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Delegated Azure Resource Manager scope for the admin sign-in. */
export const SIGN_IN_SCOPE = ['openid', 'profile', 'offline_access', `${ARM}/user_impersonation`].join(' ');

/** Stable GUID from arbitrary parts, so re-runs reuse the same role definition and assignments. */
function guidFrom(...parts) {
  const h = crypto.createHash('sha256').update(parts.join('|')).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

async function arm(token, method, path, body) {
  const res = await fetch(`${ARM}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = new Error(`Azure ${method} ${path.split('?')[0]} → ${res.status}: ${json.error?.message || res.statusText}`);
    err.status = res.status;
    err.code = json.error?.code;
    throw err;
  }
  return json;
}

/** App-only token with a certificate or a client secret. */
async function appToken(tenantId, clientId, { cert, secret }, scope) {
  const form = { client_id: clientId, grant_type: 'client_credentials', scope };
  if (cert) {
    form.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    form.client_assertion = clientAssertion(cert, tenantId, clientId);
  } else form.client_secret = secret;
  const res = await fetch(`${LOGIN}/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Entra ID sign-in failed: ${(json.error_description || json.error || res.statusText).split(/\r?\n/)[0]}`);
  return json.access_token;
}

/** The app Prowler uses for this instance, as seen from the customer tenant. */
async function instanceApp(inst, clientSecret) {
  if (inst.authMethod === 'msp') return { clientId: msp.config().clientId, auth: { cert: await msp.currentCert() } };
  if (inst.authMethod === 'certificate') return { clientId: inst.clientId, auth: { cert: await openCertificate(inst.cert.current) } };
  if (!clientSecret) throw new Error('This instance uses a client secret; enter it to connect Azure');
  return { clientId: inst.clientId, auth: { secret: clientSecret } };
}

/**
 * Where the manager can add/remove the Azure client secret: the app registration's home tenant,
 * signed in as the app itself. Null for instances that use a client secret of their own.
 */
async function secretOwner(inst) {
  if (inst.authMethod === 'msp') {
    const m = msp.config();
    const app = new EntraApp({ tenantId: m.tenantId, clientId: m.clientId });
    return { app, token: await app.token(await msp.currentCert()), appObjectId: m.appObjectId, label: m.displayName || 'the MSP app' };
  }
  if (inst.authMethod === 'certificate') {
    const app = new EntraApp(inst);
    const token = await app.token(await openCertificate(inst.cert.current));
    const appObjectId = inst.cert.appObjectId || (await app.application(token)).id;
    return { app, token, appObjectId, label: `app ${inst.clientId}` };
  }
  return null;
}

const ownedByHint = ' (the app needs the Graph permission Application.ReadWrite.OwnedBy and must own its own registration; the certificate auto-renewal check shows whether it does)';

async function addSecret(inst, owner) {
  const months = store.getSettings().certLifetimeMonths || 6;
  const end = new Date(Date.now() + months * 30 * DAY);
  try {
    const r = await owner.app.graph(owner.token, 'POST', `/applications/${owner.appObjectId}/addPassword`, {
      passwordCredential: { displayName: `prowler-manage azure ${inst.slug}`, endDateTime: end.toISOString() },
    });
    return { keyId: r.keyId, secretText: r.secretText, expires: r.endDateTime };
  } catch (e) {
    throw new Error(`Could not add a client secret to ${owner.label}: ${e.message}${e.status === 403 ? ownedByHint : ''}`);
  }
}

async function removeSecret(owner, keyId, log) {
  try {
    await owner.app.graph(owner.token, 'POST', `/applications/${owner.appObjectId}/removePassword`, { keyId });
    log(`Removed the previous Azure client secret from ${owner.label}`);
  } catch (e) {
    log(`WARNING: could not remove the previous Azure client secret ${keyId} from ${owner.label} (${e.message}); it expires on its own`);
  }
}

/** A new secret takes a little while to replicate; wait until the customer tenant accepts it. */
async function waitForSecret(inst, clientId, secret, log) {
  const deadline = Date.now() + 5 * 60000;
  for (;;) {
    try {
      return await appToken(inst.tenantId, clientId, { secret }, `${ARM}/.default`);
    } catch (e) {
      if (Date.now() > deadline) throw new Error(`The new client secret was not accepted within 5 minutes: ${e.message}`);
      log('Waiting for the new client secret to take effect…');
      await sleep(15000);
    }
  }
}

/** Find or create ProwlerRole so it can be assigned on all `subs`. Returns subId → role definition id. */
async function ensureProwlerRole(token, inst, subs, log) {
  const result = new Map();
  // Prefer an existing ProwlerRole (e.g. created by hand per Prowler's docs) where it's assignable.
  for (const sub of subs) {
    const found = await arm(token, 'GET', `/subscriptions/${sub.id}/providers/Microsoft.Authorization/roleDefinitions?$filter=roleName eq '${PROWLER_ROLE}'&api-version=2022-04-01`).catch(() => ({ value: [] }));
    if (found.value?.[0]) result.set(sub.id, found.value[0].name);
  }
  const missing = subs.filter((s) => !result.has(s.id));
  if (!missing.length) {
    log(`${PROWLER_ROLE} already exists on every subscription`);
    return result;
  }
  // One manager-owned definition, assignable on every subscription that lacks one.
  const roleId = guidFrom('prowler-manage', inst.tenantId, PROWLER_ROLE);
  const at = `/subscriptions/${missing[0].id}/providers/Microsoft.Authorization/roleDefinitions/${roleId}?api-version=2022-04-01`;
  const existing = await arm(token, 'GET', at).catch(() => null);
  const scopes = [...new Set([...(existing?.properties?.assignableScopes || []), ...missing.map((s) => `/subscriptions/${s.id}`)])];
  const body = (roleName) => ({
    properties: {
      roleName,
      type: 'CustomRole',
      description: 'Role used for checks that require read-only access to Azure resources and are not covered by the Reader role. Managed by prowler-manage.',
      permissions: [{ actions: PROWLER_ACTIONS, notActions: [] }],
      assignableScopes: scopes,
    },
  });
  try {
    await arm(token, 'PUT', at, body(existing?.properties?.roleName || PROWLER_ROLE));
  } catch (e) {
    // A ProwlerRole elsewhere in the tenant that isn't assignable on these subscriptions.
    if (e.code !== 'RoleDefinitionWithSameNameExists') throw e;
    await arm(token, 'PUT', at, body(`${PROWLER_ROLE} (prowler-manage)`));
  }
  log(`${existing ? 'Updated' : 'Created'} custom role ${PROWLER_ROLE} for ${missing.length} subscription(s)`);
  for (const s of missing) result.set(s.id, roleId);
  return result;
}

/** Assign a role on a subscription; new roles and principals can take a minute to replicate. */
async function assignRole(token, subId, roleId, principalId, label, log) {
  const id = guidFrom('prowler-manage', subId, roleId, principalId);
  const body = {
    properties: {
      roleDefinitionId: `/subscriptions/${subId}/providers/Microsoft.Authorization/roleDefinitions/${roleId}`,
      principalId,
      principalType: 'ServicePrincipal',
    },
  };
  for (let attempt = 1; ; attempt++) {
    try {
      await arm(token, 'PUT', `/subscriptions/${subId}/providers/Microsoft.Authorization/roleAssignments/${id}?api-version=2022-04-01`, body);
      log(`Assigned ${label}`);
      return;
    } catch (e) {
      if (e.code === 'RoleAssignmentExists') {
        log(`${label} already assigned`);
        return;
      }
      if (!['RoleDefinitionDoesNotExist', 'PrincipalNotFound'].includes(e.code) || attempt >= 12) throw e;
      await sleep(10000);
    }
  }
}

/**
 * Connect every enabled Azure subscription of the instance's tenant. `token` is the admin's
 * delegated Azure Resource Manager token; `step` reports progress.
 */
export async function connect(inst, token, clientSecret, step) {
  const subs = (await arm(token, 'GET', '/subscriptions?api-version=2022-12-01')).value
    .filter((s) => s.tenantId === inst.tenantId && s.state === 'Enabled')
    .map((s) => ({ id: s.subscriptionId, name: s.displayName }));
  if (!subs.length) {
    throw new Error(`No enabled Azure subscriptions in ${inst.tenantDomain} are visible to this account. Sign in as an Owner or User Access Administrator of the subscriptions (a Global Administrator can grant themselves that under Entra ID → Properties → Access management for Azure resources).`);
  }
  step(`Found ${subs.length} subscription(s): ${subs.map((s) => s.name).join(', ')}`);

  // The app's service principal in the customer tenant, and its Graph permissions.
  const { clientId, auth } = await instanceApp(inst, clientSecret);
  const graphToken = await appToken(inst.tenantId, clientId, auth, 'https://graph.microsoft.com/.default');
  const missingRoles = GRAPH_ROLES.filter((r) => !(jwtClaims(graphToken).roles || []).includes(r));
  if (missingRoles.length) step(`WARNING: the app lacks Graph permission(s) ${missingRoles.join(', ')}; some Azure checks will fail until they are granted`);
  const spRes = await fetch(`${GRAPH}/servicePrincipals(appId='${clientId}')?$select=id`, { headers: { Authorization: `Bearer ${graphToken}` } });
  if (!spRes.ok) throw new Error(`Could not find the app's service principal in ${inst.tenantDomain} (${spRes.status})`);
  const principalId = (await spRes.json()).id;

  // Roles on each subscription.
  const prowlerRoles = await ensureProwlerRole(token, inst, subs, step);
  const connected = [];
  for (const sub of subs) {
    try {
      await assignRole(token, sub.id, READER, principalId, `Reader on ${sub.name}`, step);
      await assignRole(token, sub.id, prowlerRoles.get(sub.id), principalId, `${PROWLER_ROLE} on ${sub.name}`, step);
      connected.push(sub);
    } catch (e) {
      step(`WARNING: ${sub.name}: ${e.message}${e.status === 403 ? ' (you need Owner or User Access Administrator on this subscription)' : ''}; skipped`);
    }
  }
  if (!connected.length) throw new Error('No subscription could be configured; see the warnings above');

  // Client secret for Prowler's Azure provider.
  let secret = clientSecret;
  let appSecret = null;
  const owner = await secretOwner(inst);
  if (owner) {
    const created = await addSecret(inst, owner);
    step(`Added a client secret for Azure scanning to ${owner.label} (expires ${created.expires.slice(0, 10)}; renewed automatically)`);
    await waitForSecret(inst, clientId, created.secretText, step);
    secret = created.secretText;
    appSecret = { keyId: created.keyId, expires: created.expires };
  }

  // Prowler providers.
  const prev = inst.azure || {};
  const subscriptions = await prowler.connectAzure(inst, connected, { tenantId: inst.tenantId, clientId, clientSecret: secret }, prev.subscriptions || [], step);
  if (owner && prev.appSecret?.keyId) await removeSecret(owner, prev.appSecret.keyId, step);
  store.patchInstance(inst.id, {
    azure: { subscriptions, appSecret: appSecret || null, connectedAt: new Date().toISOString(), renewError: null, lastRenewAttemptAt: null },
  });
}

/** Renew the manager-created Azure client secret before it expires and switch Prowler to it. */
export async function renewSecret(inst, log) {
  const az = inst.azure;
  if (!az?.appSecret) return;
  store.patchInstance(inst.id, { azure: { ...az, lastRenewAttemptAt: new Date().toISOString() } });
  try {
    if (!(await prowler.isApiUp(inst))) throw new Error('Prowler is not running; the secret is renewed once it is');
    const owner = await secretOwner(inst);
    const created = await addSecret(inst, owner);
    log(`Added a new Azure client secret (expires ${created.expires.slice(0, 10)})`);
    const { clientId } = await instanceApp(inst);
    await waitForSecret(inst, clientId, created.secretText, log);
    await prowler.updateAzureSecrets(inst, { tenantId: inst.tenantId, clientId, clientSecret: created.secretText }, log);
    await removeSecret(owner, az.appSecret.keyId, log);
    store.patchInstance(inst.id, { azure: { ...store.getInstance(inst.id).azure, appSecret: { keyId: created.keyId, expires: created.expires }, renewError: null } });
  } catch (e) {
    store.patchInstance(inst.id, { azure: { ...store.getInstance(inst.id).azure, renewError: e.message } });
    throw e;
  }
}

/** Whether the manager-created secret is due for renewal (and not backing off after a failure). */
export function renewalDue(inst) {
  const az = inst.azure;
  if (!az?.appSecret?.expires || !['msp', 'certificate'].includes(inst.authMethod)) return false;
  const { certRenewBeforeDays } = store.getSettings();
  if (Date.now() < new Date(az.appSecret.expires) - certRenewBeforeDays * DAY) return false;
  return !(az.renewError && az.lastRenewAttemptAt && Date.now() - new Date(az.lastRenewAttemptAt) < 6 * 3600000);
}

/** On delete: remove the manager-created secret (role assignments stay; listed in the log). */
export async function cleanup(inst, log) {
  const az = inst.azure;
  if (!az) return;
  if (az.appSecret?.keyId) {
    try {
      await removeSecret(await secretOwner(inst), az.appSecret.keyId, log);
    } catch (e) {
      log(`WARNING: could not remove the Azure client secret (${e.message})`);
    }
  }
  if (az.subscriptions?.length) {
    log(`Note: the Reader and ${PROWLER_ROLE} role assignments stay on ${az.subscriptions.map((s) => s.name).join(', ')}; remove them under Access control (IAM) if no longer needed`);
  }
}
