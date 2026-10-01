// Self-signed app certificates for M365 tenants: generation, at-rest protection, and the Entra ID /
// Microsoft Graph calls used to authenticate with them and roll them (addKey/removeKey).
import crypto from 'node:crypto';
import forge from 'node-forge';
import { protect, unprotect } from './secrets.js';

const GRAPH = 'https://graph.microsoft.com/v1.0';
const POP_AUDIENCE = '00000002-0000-0000-c000-000000000000';
const WRITE_ROLES = ['Application.ReadWrite.OwnedBy', 'Application.ReadWrite.All'];

const b64url = (buf) => Buffer.from(buf).toString('base64url');

// ---------- Generation ----------

/** Create a self-signed RSA-2048 client-auth certificate valid for `months` months. */
export function createCertificate(commonName, months) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  const key = forge.pki.privateKeyFromPem(privateKey);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicKey);
  cert.serialNumber = `01${crypto.randomBytes(15).toString('hex')}`;
  const notBefore = new Date(Date.now() - 5 * 60000);
  const notAfter = new Date(notBefore);
  notAfter.setMonth(notAfter.getMonth() + months);
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;
  const subject = [{ name: 'commonName', value: commonName }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', clientAuth: true },
  ]);
  cert.sign(key, forge.md.sha256.create());

  const der = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary');
  // Prowler loads the PFX without a password (Python azure-identity and .NET X509Certificate2).
  const p12 = forge.pkcs12.toPkcs12Asn1(key, [cert], null, { algorithm: '3des', friendlyName: commonName });
  const pfx = Buffer.from(forge.asn1.toDer(p12).getBytes(), 'binary');

  return {
    subject: `CN=${commonName}`,
    thumbprint: crypto.createHash('sha1').update(der).digest('hex').toUpperCase(),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    certDer: der.toString('base64'),
    keyPem: privateKey,
    pfx: pfx.toString('base64'),
  };
}

// ---------- At-rest protection (see secrets.js) ----------

/** Persistable record: public metadata in clear, private key + PFX encrypted (DPAPI on Windows, AES-GCM on Linux). */
export async function sealCertificate(material) {
  const { keyPem, pfx, ...pub } = material;
  return { ...pub, secret: await protect(JSON.stringify({ keyPem, pfx })) };
}

export async function openCertificate(record) {
  return { ...record, ...JSON.parse(await unprotect(record.secret)) };
}

// ---------- Tokens ----------

function signJwt(cert, payload) {
  const header = { alg: 'RS256', typ: 'JWT', x5t: b64url(Buffer.from(cert.thumbprint, 'hex')), kid: cert.thumbprint };
  const data = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  return `${data}.${b64url(crypto.sign('sha256', Buffer.from(data), cert.keyPem))}`;
}

/** Signed JWT that authenticates a confidential client with its certificate at a tenant's token endpoint. */
export function clientAssertion(cert, tenantId, clientId) {
  const aud = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
  const now = Math.floor(Date.now() / 1000);
  return signJwt(cert, { aud, iss: clientId, sub: clientId, jti: crypto.randomUUID(), nbf: now, iat: now, exp: now + 600 });
}

export function jwtClaims(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return {};
  }
}

export class EntraApp {
  constructor({ tenantId, clientId }) {
    this.tenantId = tenantId;
    this.clientId = clientId;
  }

  /** App-only Graph token via client-credentials with a certificate assertion. */
  async token(cert) {
    const aud = `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`;
    const assertion = clientAssertion(cert, this.tenantId, this.clientId);
    const res = await fetch(aud, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.clientId,
        grant_type: 'client_credentials',
        scope: 'https://graph.microsoft.com/.default',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      }),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(`Entra ID sign-in failed: ${(json.error_description || json.error || res.statusText).split('\r\n')[0]}`);
      err.aadCode = (json.error_codes || [])[0];
      throw err;
    }
    return json.access_token;
  }

  async graph(token, method, path, body) {
    const res = await fetch(`${GRAPH}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    const json = text ? JSON.parse(text) : {};
    if (!res.ok) {
      const err = new Error(`Graph ${method} ${path.split('?')[0]} → ${res.status}: ${json.error?.message || res.statusText}`);
      err.status = res.status;
      throw err;
    }
    return json;
  }

  application(token) {
    return this.graph(token, 'GET', `/applications(appId='${this.clientId}')?$select=id,displayName,keyCredentials`);
  }

  /**
   * Wait until Entra ID accepts `cert` for sign-in (after an upload or addKey; replication takes a
   * few seconds to minutes). Fails fast on errors that waiting can't fix.
   */
  async waitUntilAccepted(cert, timeoutMs, log, waitingMessage) {
    const deadline = Date.now() + timeoutMs;
    let lastLog = 0;
    for (;;) {
      try {
        return await this.token(cert);
      } catch (e) {
        // 700016: app not found in tenant, 90002/900023: tenant not found or invalid
        if ([700016, 90002, 900023].includes(e.aadCode)) throw e;
        if (Date.now() > deadline) throw new Error(`Certificate ${cert.thumbprint} was not accepted in time (${e.message})`);
        if (Date.now() - lastLog > 60000) {
          log(waitingMessage || `Waiting for Entra ID to accept certificate ${cert.thumbprint}…`);
          lastLog = Date.now();
        }
      }
      await new Promise((r) => setTimeout(r, 15000));
    }
  }

  /**
   * Check that the app can roll its own keys: it needs Application.ReadWrite.OwnedBy (or .All)
   * and, for OwnedBy, its service principal must be an owner of the app registration.
   */
  async checkRenewalReadiness(cert) {
    const reasons = [];
    const token = await this.token(cert);
    const roles = jwtClaims(token).roles || [];
    const hasAll = roles.includes('Application.ReadWrite.All');
    if (!roles.some((r) => WRITE_ROLES.includes(r))) {
      reasons.push('Grant the Microsoft Graph application permission Application.ReadWrite.OwnedBy and admin consent');
    }
    let appObjectId = null;
    try {
      appObjectId = (await this.application(token)).id;
      if (!hasAll) {
        const sp = await this.graph(token, 'GET', `/servicePrincipals(appId='${this.clientId}')?$select=id`);
        const owners = await this.graph(token, 'GET', `/applications/${appObjectId}/owners?$select=id`);
        if (!owners.value.some((o) => o.id === sp.id)) {
          reasons.push('Add the app\'s service principal as an owner of its own app registration');
        }
      }
    } catch (e) {
      reasons.push(`Can't read the app registration (${e.message})`);
    }
    return { ready: reasons.length === 0, reasons, appObjectId };
  }

  proof(cert, appObjectId) {
    const now = Math.floor(Date.now() / 1000);
    return signJwt(cert, { aud: POP_AUDIENCE, iss: appObjectId, nbf: now, exp: now + 600 });
  }

  /** Register `newCert` on the app registration, proving possession of `currentCert`. */
  async addKey(token, appObjectId, currentCert, newCert) {
    const r = await this.graph(token, 'POST', `/applications/${appObjectId}/addKey`, {
      keyCredential: {
        type: 'AsymmetricX509Cert',
        usage: 'Verify',
        key: newCert.certDer,
        // Thumbprint in the name lets a resumed rotation recognise its own key without guessing.
        displayName: `prowler-manage ${newCert.thumbprint}`,
      },
      passwordCredential: null,
      proof: this.proof(currentCert, appObjectId),
    });
    return r.keyId;
  }

  async removeKey(token, appObjectId, signingCert, keyId) {
    await this.graph(token, 'POST', `/applications/${appObjectId}/removeKey`, {
      keyId,
      proof: this.proof(signingCert, appObjectId),
    });
  }
}

/**
 * Find the keyCredential on an application that corresponds to a certificate record. Matches
 * exactly only: by stored keyId, by customKeyIdentifier (the portal sets it to the thumbprint), or
 * by the thumbprint in displayName (set by addKey above). Never by dates or subject: every cert of
 * an instance shares the subject, and two certs created close together share the dates.
 */
export function findKeyCredential(keyCredentials, record) {
  const thumb = record.thumbprint.toUpperCase();
  return (keyCredentials || []).find((k) => {
    if (record.keyId && k.keyId === record.keyId) return true;
    if (k.customKeyIdentifier) {
      const raw = Buffer.from(k.customKeyIdentifier, 'base64');
      if (raw.toString('hex').toUpperCase() === thumb || raw.toString('utf8').toUpperCase() === thumb) return true;
    }
    return (k.displayName || '').toUpperCase().includes(thumb);
  });
}
