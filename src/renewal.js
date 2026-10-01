// Certificate lifecycle. A certificate belongs to a "holder": either one instance (its own app
// registration in the customer tenant) or the MSP app (one multi-tenant app shared by all MSP
// instances, registered in the MSP tenant).
//
//   bootstrap: (instance holders only) generate cert → admin uploads .cer once → wait until accepted
//   rotate:    `certRenewBeforeDays` before expiry, generate the next cert and register it with
//              Graph addKey (proof signed by the current cert), wait until it's accepted, switch
//              Prowler to it. The old cert stays registered until it expires (overlap window).
//   cleanup:   once the old cert has expired, remove it from the app registration (removeKey).
//
// Cert records: holder.cert = { current, next, previous, appObjectId, autoRenew }.
import * as store from './store.js';
import * as prowler from './prowler.js';
import * as msp from './msp.js';
import { startJob, isBusy } from './jobs.js';
import { createCertificate, sealCertificate, openCertificate, EntraApp, findKeyCredential } from './certs.js';

const DAY = 86400000;
const HOUR = 3600000;

function publicRecord(record) {
  const { secret, ...pub } = record;
  return pub;
}

export function certCreds(inst, opened) {
  return { tenantId: inst.tenantId, clientId: inst.clientId, certificateContent: opened.pfx };
}

// ---------- Holders ----------

function instanceHolder(inst) {
  const saveCert = (patch) => Object.assign(inst, store.patchInstance(inst.id, { cert: { ...(inst.cert || {}), ...patch } }));
  return {
    key: inst.id,
    label: inst.name,
    tenantId: inst.tenantId,
    clientId: inst.clientId,
    commonName: `prowler-${inst.slug}`,
    get cert() {
      return inst.cert;
    },
    saveCert,
    downloadHref: (slot) => `/api/instances/${inst.id}/certificate.cer?slot=${slot}`,
    instructions: () => setupInstructions(inst),
    // Switch this instance's Prowler to the new cert (now, or on next Launch if it's down).
    async onPromote(opened, log) {
      let synced = false;
      if (inst.init?.done && (await prowler.isApiUp(inst))) {
        await prowler.updateCredentials(inst, certCreds(inst, opened), log);
        synced = true;
      } else {
        log('Prowler is not running; it will receive the new certificate on the next Launch');
      }
      return { prowlerSynced: synced };
    },
  };
}

export function mspHolder() {
  const m = store.getSettings().msp;
  if (!m?.clientId) throw new Error('The MSP app is not set up');
  const saveCert = (patch) => {
    const s = store.getSettings();
    store.saveSettings({ ...s, msp: { ...s.msp, cert: { ...(s.msp.cert || {}), ...patch } } });
  };
  return {
    key: 'msp',
    label: 'MSP app',
    tenantId: m.tenantId,
    clientId: m.clientId,
    commonName: 'prowler-msp',
    get cert() {
      return store.getSettings().msp.cert;
    },
    saveCert,
    downloadHref: (slot) => `/api/msp/certificate.cer?slot=${slot}`,
    instructions: () =>
      [
        `Upload the certificate to the MSP app registration ${m.clientId} in your own tenant:`,
        '  Entra admin center → App registrations → (app) → Certificates & secrets → Certificates → Upload certificate',
        'The manager checks every 15 seconds and continues on its own once Entra ID accepts it.',
      ].join('\n'),
    async onPromote(opened, log) {
      await msp.pushCertificateToInstances(opened, log);
      return {};
    },
  };
}

const saveAutoRenew = (h, patch) => h.saveCert({ autoRenew: { ...(h.cert?.autoRenew || {}), ...patch } });

async function newCertRecord(h) {
  const { certLifetimeMonths } = store.getSettings();
  return sealCertificate(createCertificate(h.commonName, certLifetimeMonths));
}

function certLink(h, slot) {
  return { label: `Download certificate (.cer) · ${h.cert[slot].thumbprint.slice(0, 8)}…`, href: h.downloadHref(slot) };
}

// ---------- Bootstrap (instances with their own, pre-existing app registration) ----------

export function setupInstructions(inst) {
  return [
    `Upload the certificate to the app registration ${inst.clientId} in ${inst.tenantDomain}:`,
    '  Entra admin center → App registrations → (app) → Certificates & secrets → Certificates → Upload certificate',
    'The manager checks every 15 seconds and continues on its own once Entra ID accepts it.',
    '',
    'For automatic renewal the app also needs, once:',
    '  1. Microsoft Graph application permission Application.ReadWrite.OwnedBy (admin consent)',
    '  2. Its own service principal as an owner of the app registration, e.g. with Azure CLI:',
    `     az ad app owner add --id ${inst.clientId} --owner-object-id $(az ad sp show --id ${inst.clientId} --query id -o tsv)`,
  ].join('\n');
}

/** Generate the first certificate if needed and show upload instructions (doesn't wait). */
export async function prepareBootstrap(inst, log, job) {
  const h = instanceHolder(inst);
  if (!inst.cert?.current) {
    h.saveCert({ current: { ...(await newCertRecord(h)), verified: false } });
    log(`Generated certificate ${inst.cert.current.thumbprint} (expires ${inst.cert.current.notAfter.slice(0, 10)})`);
  }
  if (!inst.cert.current.verified && job) {
    job.notice = setupInstructions(inst);
    job.links = [certLink(h, 'current')];
    log('ACTION NEEDED: download the certificate and upload it to the app registration (see instructions above)');
  }
}

/** Make sure the current certificate is accepted by Entra ID; returns Prowler credentials. */
export async function ensureBootstrapped(inst, log, job) {
  const h = instanceHolder(inst);
  await prepareBootstrap(inst, log, job);
  const cur = await openCertificate(inst.cert.current);
  if (!inst.cert.current.verified) {
    await new EntraApp(inst).waitUntilAccepted(cur, 60 * 60000, log, 'Waiting for the certificate to be uploaded to the app registration…');
    log('Entra ID accepted the certificate');
    if (job) {
      job.notice = null;
      job.links = [];
    }
    // A fresh instance gets the cert during initialization; an existing one must be updated.
    h.saveCert({ current: { ...inst.cert.current, verified: true, verifiedAt: new Date().toISOString(), prowlerSynced: !inst.init?.done } });
  }
  return certCreds(inst, cur);
}

/** Push the current certificate to Prowler if a rotation happened while the stack was down. */
export async function syncProwler(inst, log) {
  if (inst.authMethod !== 'certificate' || inst.cert?.current?.prowlerSynced !== false || !inst.init?.done) return;
  const cur = await openCertificate(inst.cert.current);
  await prowler.updateCredentials(inst, certCreds(inst, cur), log);
  instanceHolder(inst).saveCert({ current: { ...inst.cert.current, prowlerSynced: true } });
}

// ---------- Generic lifecycle ----------

async function checkHolder(h, log) {
  try {
    const cur = await openCertificate(h.cert.current);
    const r = await new EntraApp(h).checkRenewalReadiness(cur);
    if (r.appObjectId) h.saveCert({ appObjectId: r.appObjectId });
    saveAutoRenew(h, { ready: r.ready, reasons: r.reasons, checkedAt: new Date().toISOString() });
    if (r.ready) log(`Automatic certificate renewal (${h.label}): ready`);
    else for (const reason of r.reasons) log(`Automatic certificate renewal (${h.label}) not ready: ${reason}`);
  } catch (e) {
    saveAutoRenew(h, { ready: false, reasons: [e.message], checkedAt: new Date().toISOString() });
    log(`WARNING: renewal readiness check failed: ${e.message}`);
  }
}

// Switch to `next`, keep the old cert as `previous` until it expires.
async function promote(h, nextOpened, oldKeyId, log) {
  const extra = await h.onPromote(nextOpened, log);
  if (h.cert.previous) {
    await removePreviousFor(h, log).catch((e) => log(`WARNING: could not remove older certificate: ${e.message}`));
  }
  const old = h.cert.current;
  h.saveCert({
    previous: { ...publicRecord(old), keyId: oldKeyId || old.keyId || null },
    current: { ...h.cert.next, verified: true, verifiedAt: new Date().toISOString(), ...extra },
    next: null,
  });
  saveAutoRenew(h, { lastRenewedAt: new Date().toISOString(), lastError: null });
  log(`Now using certificate ${h.cert.current.thumbprint}, valid until ${h.cert.current.notAfter.slice(0, 10)}`);
  log(`Previous certificate ${old.thumbprint} stays registered until it expires on ${old.notAfter.slice(0, 10)}`);
}

/** Automatic rotation: the app registers its next certificate itself. Resumable. */
async function rotateFor(h, log) {
  saveAutoRenew(h, { lastAttemptAt: new Date().toISOString() });
  try {
    const cur = await openCertificate(h.cert.current);
    if (new Date(cur.notAfter) <= new Date()) throw new Error('Current certificate has expired; renew manually');
    const app = new EntraApp(h);
    const token = await app.token(cur);
    const appObj = await app.application(token);
    h.saveCert({ appObjectId: appObj.id });

    if (!h.cert.next) {
      h.saveCert({ next: await newCertRecord(h) });
      log(`Generated next certificate ${h.cert.next.thumbprint} (expires ${h.cert.next.notAfter.slice(0, 10)})`);
    }
    const next = await openCertificate(h.cert.next);
    if (!h.cert.next.keyId) {
      // A previous attempt may have registered it before being interrupted.
      const existing = findKeyCredential(appObj.keyCredentials, h.cert.next);
      const keyId = existing?.keyId || (await app.addKey(token, appObj.id, cur, next));
      h.saveCert({ next: { ...h.cert.next, keyId } });
      log(existing ? 'Next certificate was already registered' : `Registered next certificate on the app registration (addKey, keyId ${keyId})`);
    }
    await app.waitUntilAccepted(next, 20 * 60000, log);
    log('Entra ID accepts the new certificate');
    const oldKeyId = h.cert.current.keyId || findKeyCredential(appObj.keyCredentials, h.cert.current)?.keyId;
    await promote(h, next, oldKeyId, log);
  } catch (e) {
    saveAutoRenew(h, { lastError: e.message });
    throw e;
  }
}

/** Manual renewal (current cert expired or app can't roll its own keys): admin uploads the .cer. */
async function manualRenewFor(h, log, job) {
  if (!h.cert.next) {
    h.saveCert({ next: await newCertRecord(h) });
    log(`Generated certificate ${h.cert.next.thumbprint} (expires ${h.cert.next.notAfter.slice(0, 10)})`);
  }
  job.notice = h.instructions();
  job.links = [certLink(h, 'next')];
  log('ACTION NEEDED: download the certificate and upload it to the app registration (see instructions above)');
  const next = await openCertificate(h.cert.next);
  const app = new EntraApp(h);
  const token = await app.waitUntilAccepted(next, 60 * 60000, log, 'Waiting for the certificate to be uploaded to the app registration…');
  job.notice = null;
  job.links = [];
  log('Entra ID accepted the certificate');
  let oldKeyId = null;
  try {
    const appObj = await app.application(token);
    h.saveCert({ appObjectId: appObj.id });
    oldKeyId = findKeyCredential(appObj.keyCredentials, h.cert.current)?.keyId;
  } catch {}
  await promote(h, next, oldKeyId, log);
  saveAutoRenew(h, { lastError: null });
}

async function renewNowFor(h, log, job) {
  const expired = new Date(h.cert.current.notAfter) <= new Date();
  if (!expired && !h.cert.next?.keyId) {
    await checkHolder(h, log);
    if (h.cert.autoRenew?.ready) return rotateFor(h, log);
    log('Falling back to manual upload');
  }
  if (h.cert.next?.keyId) return rotateFor(h, log);
  return manualRenewFor(h, log, job);
}

/** Remove the previous (expired or superseded) certificate from the app registration. */
async function removePreviousFor(h, log) {
  const prev = h.cert.previous;
  if (!prev) return;
  try {
    const cur = await openCertificate(h.cert.current);
    const app = new EntraApp(h);
    const token = await app.token(cur);
    const appObj = await app.application(token);
    const key = findKeyCredential(appObj.keyCredentials, prev);
    if (key) {
      await app.removeKey(token, appObj.id, cur, key.keyId);
      log(`Removed certificate ${prev.thumbprint} from the app registration (removeKey)`);
    } else {
      log(`Certificate ${prev.thumbprint} is no longer on the app registration`);
    }
    h.saveCert({ previous: null });
  } catch (e) {
    h.saveCert({ previous: { ...prev, lastRemoveAttemptAt: new Date().toISOString(), removeError: e.message } });
    throw e;
  }
}

// Instance-facing API
export const checkReadiness = (inst, log) => checkHolder(instanceHolder(inst), log);
export const rotate = (inst, log) => rotateFor(instanceHolder(inst), log);
export const removePrevious = (inst, log) => removePreviousFor(instanceHolder(inst), log);
export const renewNow = (inst, log, job) => renewNowFor(instanceHolder(inst), log, job);

// MSP-app API
export const checkMspReadiness = (log) => checkHolder(mspHolder(), log);
export const renewMspNow = (log, job) => renewNowFor(mspHolder(), log, job);

// ---------- Scheduler ----------

const recent = (iso, ms) => iso && Date.now() - new Date(iso) < ms;

function scheduleHolder(h, busyKey) {
  const { certRenewBeforeDays } = store.getSettings();
  const cert = h.cert;
  if (!cert?.current?.verified || isBusy(busyKey)) return;
  const now = Date.now();
  const expiresAt = new Date(cert.current.notAfter).getTime();
  const ar = cert.autoRenew || {};
  if (cert.next?.keyId || now >= expiresAt - certRenewBeforeDays * DAY) {
    if (now >= expiresAt) return; // needs manual renewal; the UI shows it as expired
    if (ar.lastError && recent(ar.lastAttemptAt, 6 * HOUR)) return; // back off after failures
    startJob(busyKey, `Renew certificate · ${h.label}`, null, (log) => rotateFor(h, log));
  } else if (cert.previous && now >= new Date(cert.previous.notAfter).getTime()) {
    if (recent(cert.previous.lastRemoveAttemptAt, 24 * HOUR)) return;
    startJob(busyKey, `Remove expired certificate · ${h.label}`, null, (log) => removePreviousFor(h, log));
  } else if (!recent(ar.checkedAt, 24 * HOUR)) {
    startJob(busyKey, `Check certificate renewal · ${h.label}`, null, (log) => checkHolder(h, log));
  }
}

function tick() {
  if (store.getSettings().msp?.clientId) {
    try {
      scheduleHolder(mspHolder(), 'msp');
    } catch (e) {
      console.error('Certificate scheduler (MSP app):', e.message);
    }
  }
  for (const inst of store.listInstances()) {
    if (inst.authMethod !== 'certificate' || !inst.init?.done) continue;
    try {
      scheduleHolder(instanceHolder(inst), inst.id);
    } catch (e) {
      console.error(`Certificate scheduler (${inst.name}):`, e.message);
    }
  }
}

export function startScheduler() {
  setTimeout(tick, 10000);
  setInterval(tick, HOUR);
}

/**
 * Delete the tenant's app registration using the app's own certificate (it owns itself and has
 * Application.ReadWrite.OwnedBy). Also removes its service principal and role assignments.
 */
export async function deleteAppRegistration(inst, log) {
  if (inst.authMethod !== 'certificate' || !inst.cert?.current) {
    log('App registration uses a client secret; delete it in Entra ID manually');
    return;
  }
  try {
    const cur = await openCertificate(inst.cert.current);
    const app = new EntraApp(inst);
    const token = await app.token(cur);
    const id = inst.cert.appObjectId || (await app.application(token)).id;
    await app.graph(token, 'DELETE', `/applications/${id}`);
    log(`Deleted app registration ${inst.clientId} from ${inst.tenantDomain} (restorable from Deleted applications for 30 days)`);
  } catch (e) {
    log(`WARNING: could not delete the app registration (${e.message}); delete app ${inst.clientId} in Entra ID manually`);
  }
}
