const $ = (sel) => document.querySelector(sel);
let instances = [];
let settings = null;
let editing = null;
let jobPoll = null;

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json.error || res.statusText);
  return json;
}

/** Tiny element builder: h('td', {class: 'x'}, 'text', childEl, ...). */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}

function closeDialog(id) {
  $(`#${id}`).close();
}

function link(href, text) {
  return h('a', { href, target: '_blank', rel: 'noopener' }, text);
}

function statusCell(i) {
  if (i.busy) return [h('span', { class: 'pill busy' }, `${i.state}…`)];
  if (i.state === 'error') {
    return [h('span', { class: 'pill err' }, 'error'), h('span', { class: 'errtext', title: i.lastError || '' }, i.lastError || '')];
  }
  const cls = { running: 'ok', degraded: 'warn' }[i.runtime] || '';
  return [h('span', { class: `pill ${cls}`, title: i.runtimeDetail || '' }, i.runtime)];
}

function credentialCell(i) {
  const c = i.credential || {};
  if (c.method === 'msp') {
    if (!c.consent?.consented) return [h('span', { class: 'pill warn' }, 'awaiting customer approval'), h('div', { class: 'sub' }, 'MSP app')];
    const days = c.current ? Math.ceil((new Date(c.current.notAfter) - Date.now()) / 86400000) : 0;
    const out = [h('span', { class: `pill ${days <= 0 ? 'err' : days <= c.renewBeforeDays ? 'warn' : 'ok'}`, title: 'Shared certificate of the MSP app (renewed in Settings)' }, `MSP app · cert ${days}d`)];
    if (c.consent.globalReader === false) out.push(h('span', { class: 'errtext', title: 'Exchange and Teams checks need the Global Reader role. Use Approve to assign it.' }, 'Global Reader missing'));
    else out.push(h('div', { class: 'sub' }, 'approved'));
    return out;
  }
  if (c.method !== 'certificate') return [h('span', { class: 'pill' }, 'client secret')];
  const cur = c.current;
  if (!cur) return [h('span', { class: 'pill warn' }, 'certificate pending')];
  if (!cur.verified) return [h('span', { class: 'pill warn', title: cur.thumbprint }, 'awaiting upload')];
  const days = Math.ceil((new Date(cur.notAfter) - Date.now()) / 86400000);
  const cls = days <= 0 ? 'err' : days <= c.renewBeforeDays ? 'warn' : 'ok';
  const label = days <= 0 ? 'certificate expired' : `cert · ${days}d left`;
  const ar = c.autoRenew || {};
  let sub;
  if (days <= 0) sub = h('span', { class: 'errtext' }, 'Use Renew cert to upload a new one');
  else if (ar.lastError) sub = h('span', { class: 'errtext', title: ar.lastError }, `renewal failed: ${ar.lastError}`);
  else if (c.next) sub = h('div', { class: 'sub' }, 'renewal in progress');
  else if (ar.ready === false) sub = h('span', { class: 'errtext', title: (ar.reasons || []).join('\n') }, 'auto-renew not ready (hover)');
  else if (ar.ready) sub = h('div', { class: 'sub' }, `auto-renews ${new Date(new Date(cur.notAfter) - c.renewBeforeDays * 86400000).toLocaleDateString()}`);
  else sub = h('div', { class: 'sub' }, 'auto-renew not checked yet');
  const prev = c.previous ? h('div', { class: 'sub', title: c.previous.thumbprint }, `old cert kept until ${new Date(c.previous.notAfter).toLocaleDateString()}`) : null;
  return [h('span', { class: `pill ${cls}`, title: `${cur.thumbprint}\nexpires ${new Date(cur.notAfter).toLocaleString()}` }, label), sub, prev];
}

function azureCell(i) {
  const az = i.azure;
  if (!az?.subscriptions?.length) return null;
  const names = az.subscriptions.map((s) => s.name).join(', ');
  if (az.renewError) return h('span', { class: 'errtext', title: az.renewError }, `Azure secret renewal failed: ${az.renewError}`);
  const n = az.subscriptions.length;
  return h('div', { class: 'sub', title: names }, `Azure: ${n} subscription${n === 1 ? '' : 's'}`);
}

function rowButton(act, label, inst, { disabled = false, cls = '' } = {}) {
  return h('button', { class: `btn sm ${cls}`, disabled, onclick: () => action(act, inst) }, label);
}

function render() {
  const rows = instances.map((i) => {
    const running = i.runtime === 'running' || i.runtime === 'degraded';
    return h('tr', {},
      h('td', {}, h('b', {}, i.name), h('div', { class: 'sub' }, i.slug)),
      h('td', {}, i.tenantDomain, h('div', { class: 'sub' }, i.tenantId), azureCell(i)),
      h('td', {},
        link(i.url, i.hostname || i.localUrl),
        h('div', { class: 'sub' }, 'local: ', link(i.localUrl, `:${i.uiPort}`), ` · api :${i.apiPort}`)),
      h('td', {}, i.version || '—'),
      h('td', {}, credentialCell(i)),
      h('td', {}, statusCell(i)),
      h('td', { class: 'right' }, h('div', { class: 'row-actions' },
        rowButton('launch', running && i.state === 'ready' ? 'Open' : 'Launch', i, { disabled: i.busy }),
        running && rowButton('stop', 'Stop', i, { disabled: i.busy }),
        rowButton('edit', 'Edit', i, { disabled: i.busy }),
        rowButton('creds', 'Sign-in', i),
        rowButton('logs', 'Logs', i),
        i.credential?.method === 'msp' && (!i.credential.consent?.consented || i.credential.consent.globalReader === false) && rowButton('approve', 'Approve', i),
        i.credential?.method === 'certificate' && i.credential.current?.verified && rowButton('renew', 'Renew cert', i, { disabled: i.busy }),
        i.init?.done && running && rowButton('azure', 'Azure', i, { disabled: i.busy }),
        i.busy && i.lastJobId && rowButton('job', 'Progress', i),
        rowButton('delete', 'Delete', i, { disabled: i.busy, cls: 'danger-text' }))));
  });
  $('#rows').replaceChildren(...rows);
  $('#empty').classList.toggle('hidden', instances.length > 0);
  const up = instances.filter((i) => i.runtime === 'running').length;
  $('#summary').textContent = instances.length ? `${instances.length} total · ${up} running` : '';
}

function setBanner(...content) {
  const banner = $('#banner');
  banner.replaceChildren(...content);
  banner.classList.toggle('hidden', content.length === 0);
}

async function refresh() {
  try {
    const data = await api('GET', '/api/instances');
    instances = data.instances;
    const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
    const version = await api('GET', '/api/version').catch(() => null);
    if (version?.restartPending) {
      setBanner(h('b', {}, 'Restart needed: '), `the code was updated to ${version.diskSha.slice(0, 7)}, but the manager is still running ${version.sha.slice(0, 7)}. Restart the service (or the process) so the page and the server match.`);
    } else if (settings?.access?.viaCloudflare && !settings.access.cloudflareAccess) {
      setBanner(h('b', {}, 'This manager is reachable from the internet without Cloudflare Access. '),
        'It has no login of its own: anyone with this address can read Prowler passwords, approve tenants and delete instances. Put a Cloudflare Access application in front of this hostname now.');
    } else if (!isLocal && location.protocol !== 'https:') {
      setBanner(`Microsoft sign-ins can only return to https addresses or localhost; open this manager at https://${location.host}.`);
    } else if (!data.dockerAvailable) {
      setBanner('Docker is not reachable. Start Docker Desktop to see instance status and run operations.');
    } else if (settings?.cloudflare.mode === 'api' && !settings.cloudflare.hasApiToken) {
      setBanner('Cloudflare API token is not set, so new instances can\'t be published. Open ',
        h('a', { href: '#', onclick: (e) => { e.preventDefault(); openSettings(); } }, 'Settings'), '.');
    } else setBanner();
    render();
  } catch (e) {
    console.error(e);
  }
}

// ---------- Microsoft sign-in popups ----------

const STATUS_TEXT = {
  'signing-in': 'Waiting for Microsoft sign-in in the popup window…',
  'device-code': 'Enter the code shown in the popup at microsoft.com/devicelogin…',
  working: 'Setting things up…',
  'preparing-consent': 'Preparing the permission request…',
  'awaiting-consent': 'Waiting for you to approve the permissions in the popup window…',
  verifying: 'Waiting for the permissions to take effect…',
};

/**
 * Start a sign-in flow (see src/onboarding.js) in a popup and report progress to `onUpdate(session)`.
 * Returns a stop() function.
 */
function popupSession(params, onUpdate) {
  // Open the popup synchronously (inside the click) so the browser doesn't block it.
  const popup = window.open('about:blank', 'prowler-connect', 'width=560,height=760');
  let timer = null;
  let stopped = false;
  (async () => {
    try {
      const r = await api('POST', '/api/onboarding', params);
      if (stopped) return;
      const url = new URL(r.authUrl, location.origin).href;
      if (popup) popup.location = url;
      else window.open(url, 'prowler-connect');
      onUpdate({ id: r.id, status: 'signing-in', steps: [] });
      timer = setInterval(async () => {
        try {
          const s = await api('GET', `/api/onboarding/${r.id}`);
          onUpdate(s);
          if (s.status === 'done' || s.status === 'error') clearInterval(timer);
        } catch (e) {
          clearInterval(timer);
          onUpdate({ status: 'error', error: e.message, steps: [] });
        }
      }, 1500);
    } catch (e) {
      popup?.close();
      onUpdate({ status: 'error', error: e.message, steps: [] });
    }
  })();
  return () => {
    stopped = true;
    clearInterval(timer);
  };
}

/** Render a session's progress into a status span + steps list; returns true when done. */
function renderSession(s, statusEl, stepsEl, doneText) {
  stepsEl.replaceChildren(...(s.steps || []).map((t) => h('li', { class: t.startsWith('WARNING') ? 'warn' : '' }, t)));
  if (s.status === 'done') {
    statusEl.textContent = doneText(s);
    statusEl.className = 'small connected';
    return true;
  }
  if (s.status === 'error') {
    statusEl.textContent = s.error;
    statusEl.className = 'small error-inline';
  } else {
    statusEl.textContent = STATUS_TEXT[s.status] || s.status;
    statusEl.className = 'small muted';
  }
  return false;
}

// ---------- Create / edit ----------

let session = null; // { id, done, kind }
let stopSession = null;

function tenantMode() {
  if (editing) return 'manual';
  return $('#form-instance').querySelector('input[name="tenantMode"]:checked').value;
}

/** Show the fields that apply to the current mode and disable hidden inputs (skips validation). */
function syncFields() {
  const f = $('#form-instance');
  const mode = tenantMode();
  const mspEdit = editing?.credential?.method === 'msp';
  const manual = mode === 'manual' && !mspEdit;
  const cert = f.authMethod.value === 'certificate';
  document.querySelectorAll('.tenant-connect').forEach((el) => el.classList.toggle('hidden', mode !== 'connect'));
  document.querySelectorAll('.tenant-msp').forEach((el) => el.classList.toggle('hidden', mode !== 'msp'));
  const mspReady = !!settings?.msp?.clientId;
  $('#msp-missing').classList.toggle('hidden', mspReady);
  $('#msp-ready').classList.toggle('hidden', !mspReady);
  if (mspReady) $('#msp-app-name').textContent = `"${settings.msp.displayName}"`;
  f.mspCustomer.disabled = mode !== 'msp' || !mspReady || !!session?.done;
  f.mspCustomer.required = mode === 'msp';
  document.querySelectorAll('.tenant-manual').forEach((el) => {
    const show = manual && (!el.classList.contains('auth-secret') || !cert) && (!el.classList.contains('auth-cert') || cert);
    el.classList.toggle('hidden', !show);
    el.querySelectorAll('input, select').forEach((i) => (i.disabled = !show || (i.name === 'tenantDomain' && !!editing)));
  });
  const switchingToSecret = editing && (editing.credential?.method || 'secret') !== 'secret';
  f.clientSecret.required = manual && !cert && (!editing || switchingToSecret);
  f.clientSecret.placeholder = editing && !switchingToSecret ? 'Leave blank to keep current secret' : '';
}

function toggleMode(isEdit) {
  document.querySelectorAll('.create-only').forEach((el) => el.classList.toggle('hidden', isEdit));
  document.querySelectorAll('.edit-only').forEach((el) => el.classList.toggle('hidden', !isEdit));
  $('#dlg-instance-sub').classList.toggle('hidden', isEdit);
  $('#form-error').classList.add('hidden');
}

function resetSession() {
  stopSession?.();
  stopSession = null;
  session = null;
  for (const [btn, label] of [['#btn-connect', 'Connect Microsoft 365 tenant'], ['#btn-msp-approve', 'Approve now']]) {
    $(btn).disabled = false;
    $(btn).textContent = label;
  }
  for (const id of ['#connect-status', '#msp-status']) {
    $(id).textContent = '';
    $(id).className = 'small muted';
  }
  $('#connect-steps').replaceChildren();
  $('#msp-steps').replaceChildren();
}

function openCreate() {
  editing = null;
  const f = $('#form-instance');
  f.reset();
  toggleMode(false);
  resetSession();
  $('#dlg-instance-title').textContent = 'New instance';
  $('#btn-instance-submit').textContent = 'Create';
  f.authMethod.value = 'certificate';
  f.adminEmail.required = true;
  f.hostname.placeholder = settings?.baseDomain ? `prowler-<name>.${settings.baseDomain}` : 'prowler-contoso.example.com';
  syncFields();
  $('#dlg-instance').showModal();
}

function openEdit(inst) {
  editing = inst;
  const f = $('#form-instance');
  f.reset();
  toggleMode(true);
  $('#dlg-instance-title').textContent = `Edit ${inst.name}`;
  $('#btn-instance-submit').textContent = 'Save & apply';
  f.name.value = inst.name;
  f.tenantDomain.value = inst.tenantDomain;
  f.tenantId.value = inst.tenantId;
  f.clientId.value = inst.clientId;
  f.authMethod.value = inst.credential?.method === 'secret' ? 'secret' : 'certificate';
  f.adminEmail.required = false;
  f.hostname.value = inst.hostname || '';
  syncFields();
  $('#dlg-instance').showModal();
}

function startTenantSession(kind, btn, statusEl, stepsEl, extra) {
  resetSession();
  btn.disabled = true;
  statusEl.textContent = 'Opening Microsoft sign-in…';
  stopSession = popupSession({ kind, name: $('#form-instance').name.value.trim(), ...extra }, (s) => {
    session = { id: s.id || session?.id, kind, done: false };
    const finished = renderSession(s, statusEl, stepsEl, (x) => `Connected: ${x.orgName} (${x.tenantDomain})${x.globalReader === false ? ' (Global Reader missing)' : ''}`);
    if (finished) {
      session.done = true;
      btn.textContent = 'Connected';
      const f = $('#form-instance');
      if (!f.name.value) f.name.value = s.orgName;
      syncFields();
    } else if (s.status === 'error') {
      btn.disabled = false;
      btn.textContent = 'Try again';
    }
  });
}

$('#btn-connect').addEventListener('click', () => startTenantSession('direct', $('#btn-connect'), $('#connect-status'), $('#connect-steps')));

$('#btn-msp-approve').addEventListener('click', () => {
  const customer = $('#form-instance').mspCustomer.value.trim();
  if (!customer) {
    $('#msp-status').textContent = 'Enter the customer domain first';
    $('#msp-status').className = 'small error-inline';
    return;
  }
  startTenantSession('msp', $('#btn-msp-approve'), $('#msp-status'), $('#msp-steps'), { customer });
});

$('#btn-msp-copy').addEventListener('click', async () => {
  const status = $('#msp-status');
  try {
    const r = await api('GET', `/api/msp/consent-link?customer=${encodeURIComponent($('#form-instance').mspCustomer.value.trim())}`);
    await navigator.clipboard.writeText(r.link);
    status.textContent = 'Consent link copied. Send it to the customer\'s Global Administrator.';
    status.className = 'small connected';
  } catch (e) {
    status.textContent = e.message;
    status.className = 'small error-inline';
  }
});

$('#form-instance').querySelectorAll('input[name="tenantMode"]').forEach((r) =>
  r.addEventListener('change', () => {
    resetSession();
    syncFields();
  }),
);

$('#form-instance').authMethod.addEventListener('change', () => {
  const f = $('#form-instance');
  if (editing && f.authMethod.value !== (editing.credential?.method || 'secret') && f.authMethod.value === 'certificate') {
    $('#form-error').textContent = 'Switching to a certificate: you will be asked to upload a new certificate to the app registration.';
    $('#form-error').classList.remove('hidden');
  } else $('#form-error').classList.add('hidden');
  syncFields();
});

$('#form-instance').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const body = Object.fromEntries(new FormData(f));
  body.upgrade = f.upgrade.checked;
  const err = $('#form-error');
  const mode = tenantMode();
  if (!editing && mode === 'connect') {
    if (!session?.done) {
      err.textContent = 'Connect the Microsoft 365 tenant first.';
      err.classList.remove('hidden');
      return;
    }
    body.onboardingId = session.id;
  }
  if (!editing && mode === 'msp') {
    if (!settings?.msp?.clientId) {
      err.textContent = 'Set up the MSP app in Settings first.';
      err.classList.remove('hidden');
      return;
    }
    if (session?.done) body.onboardingId = session.id;
    else body.mspCustomer = f.mspCustomer.value.trim(); // approve later via consent link
  }
  const btn = $('#btn-instance-submit');
  btn.disabled = true;
  try {
    const r = editing ? await api('PUT', `/api/instances/${editing.id}`, body) : await api('POST', '/api/instances', body);
    stopSession?.();
    closeDialog('dlg-instance');
    await refresh();
    showJob(r.jobId);
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
});

// "Approve" on an existing MSP instance (customer hasn't approved yet, or Global Reader is missing).
let approveStop = null;
function approveInstance(inst) {
  approveStop?.();
  const dlg = $('#dlg-approve');
  $('#approve-title').textContent = `Approve Prowler for ${inst.tenantDomain}`;
  $('#approve-steps').replaceChildren();
  dlg.showModal();
  approveStop = popupSession({ kind: 'msp', customer: inst.tenantId, instanceId: inst.id }, (s) => {
    if (renderSession(s, $('#approve-status'), $('#approve-steps'), (x) => `Approved by ${x.orgName}${x.globalReader === false ? ' (Global Reader still missing)' : ''}`)) refresh();
  });
}
$('#dlg-approve').addEventListener('close', () => approveStop?.());

// "Azure" on a ready instance: assign Prowler's roles on the tenant's Azure subscriptions (src/azure.js).
let azureStop = null;
let azureInst = null;
function openAzure(inst) {
  azureStop?.();
  azureInst = inst;
  const secretMode = inst.credential?.method === 'secret';
  $('#azure-title').textContent = `Connect Azure subscriptions · ${inst.name}`;
  $('#azure-secret-row').classList.toggle('hidden', !secretMode);
  $('#azure-secret').value = '';
  $('#azure-secret-note').textContent = secretMode
    ? "Prowler's Azure provider uses the same app and client secret as Microsoft 365. Enter the secret again; it is sent to Prowler only."
    : "Prowler's Azure provider only accepts a client secret, so the manager adds one to the app registration and renews it before it expires. It is sent to Prowler only.";
  const n = inst.azure?.subscriptions?.length;
  $('#azure-status').textContent = n ? `Connected: ${inst.azure.subscriptions.map((s) => s.name).join(', ')}. Run again to add new subscriptions or repair roles.` : '';
  $('#azure-status').className = 'small muted';
  $('#azure-steps').replaceChildren();
  $('#btn-azure-start').disabled = false;
  $('#dlg-azure').showModal();
}
$('#btn-azure-start').addEventListener('click', () => {
  const inst = azureInst;
  const clientSecret = $('#azure-secret').value;
  if (inst.credential?.method === 'secret' && !clientSecret) {
    $('#azure-status').textContent = "Enter the app's client secret first";
    $('#azure-status').className = 'small error-inline';
    return;
  }
  azureStop?.();
  $('#btn-azure-start').disabled = true;
  azureStop = popupSession({ kind: 'azure', instanceId: inst.id, clientSecret }, (s) => {
    if (renderSession(s, $('#azure-status'), $('#azure-steps'), () => 'Azure subscriptions connected. The first scans are starting in Prowler.')) {
      $('#azure-secret').value = '';
      refresh();
    } else if (s.status === 'error') $('#btn-azure-start').disabled = false;
  });
});
$('#dlg-azure').addEventListener('close', () => {
  azureStop?.();
  $('#azure-secret').value = '';
});

// ---------- Jobs ----------

function showJob(jobId) {
  clearInterval(jobPoll);
  const logEl = $('#job-log');
  logEl.textContent = '';
  $('#job-notice').classList.add('hidden');
  $('#job-notice-text').textContent = '';
  let since = 0;
  $('#dlg-job').showModal();
  const tick = async () => {
    try {
      const j = await api('GET', `/api/jobs/${jobId}?since=${since}`);
      $('#job-title').textContent = j.title;
      const st = $('#job-status');
      st.textContent = j.status;
      st.className = `pill ${j.status}`;
      const notice = $('#job-notice');
      notice.classList.toggle('hidden', !j.notice);
      if (j.notice && $('#job-notice-text').textContent !== j.notice) {
        $('#job-notice-text').textContent = j.notice;
        $('#job-links').replaceChildren(
          ...j.links.flatMap((l) =>
            l.href.startsWith('/')
              ? [h('a', { class: 'btn primary sm', href: l.href, download: '' }, l.label)]
              : [
                  h('a', { class: 'btn primary sm', href: l.href, target: '_blank', rel: 'noopener' }, l.label),
                  h('button', { class: 'btn sm', onclick: () => navigator.clipboard.writeText(l.href) }, 'Copy link'),
                ],
          ),
        );
      }
      if (j.log.length) {
        const atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 20;
        logEl.textContent += j.log.join('\n') + '\n';
        if (atBottom) logEl.scrollTop = logEl.scrollHeight;
      }
      since = j.logLength;
      if (j.status !== 'running') {
        clearInterval(jobPoll);
        refresh();
      }
    } catch (e) {
      logEl.textContent += `\n${e.message}\n`;
      clearInterval(jobPoll);
    }
  };
  tick();
  jobPoll = setInterval(tick, 1500);
}

$('#dlg-job').addEventListener('close', () => clearInterval(jobPoll));

// ---------- Row actions ----------

async function action(act, inst) {
  try {
    if (act === 'launch') {
      if (inst.runtime === 'running' && inst.state === 'ready') return window.open(inst.url, '_blank', 'noopener');
      const r = await api('POST', `/api/instances/${inst.id}/launch`);
      showJob(r.jobId);
    } else if (act === 'stop') {
      const r = await api('POST', `/api/instances/${inst.id}/stop`);
      showJob(r.jobId);
    } else if (act === 'renew') {
      if (!confirm(`Renew the certificate for ${inst.name} now?`)) return;
      const r = await api('POST', `/api/instances/${inst.id}/renew-certificate`);
      showJob(r.jobId);
    } else if (act === 'approve') return approveInstance(inst);
    else if (act === 'azure') return openAzure(inst);
    else if (act === 'edit') openEdit(inst);
    else if (act === 'job') showJob(inst.lastJobId);
    else if (act === 'creds') {
      const c = await api('GET', `/api/instances/${inst.id}/credentials`);
      $('#cred-email').textContent = c.email;
      $('#cred-pass').textContent = c.password;
      $('#dlg-creds').showModal();
    } else if (act === 'logs') openLogs(inst);
    else if (act === 'delete') openDelete(inst);
    await refresh();
  } catch (e) {
    alert(e.message);
  }
}

$('#cred-copy').addEventListener('click', () => navigator.clipboard.writeText($('#cred-pass').textContent));

let logsInst = null;
async function loadLogs() {
  const svc = $('#logs-service').value;
  const body = $('#logs-body');
  body.textContent = 'Loading…';
  const res = await fetch(`/api/instances/${logsInst.id}/logs${svc ? `?service=${svc}` : ''}`);
  body.textContent = await res.text();
  body.scrollTop = body.scrollHeight;
}
function openLogs(inst) {
  logsInst = inst;
  $('#logs-title').textContent = `Logs · ${inst.name}`;
  $('#dlg-logs').showModal();
  loadLogs();
}
$('#logs-service').addEventListener('change', loadLogs);
$('#logs-refresh').addEventListener('click', loadLogs);

let deleting = null;
function openDelete(inst) {
  deleting = inst;
  $('#del-name').textContent = inst.name;
  $('#del-host').textContent = inst.hostname || '(no hostname)';
  $('#del-confirm').value = '';
  const certBased = inst.credential?.method === 'certificate';
  $('#del-app-row').classList.toggle('hidden', !certBased);
  $('#del-app').checked = certBased && !!inst.appCreatedByManager;
  $('#btn-del').disabled = true;
  $('#dlg-delete').showModal();
}
$('#del-confirm').addEventListener('input', (e) => ($('#btn-del').disabled = e.target.value !== deleting?.name));
$('#form-delete').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  closeDialog('dlg-delete');
  try {
    const r = await api('DELETE', `/api/instances/${deleting.id}${$('#del-app').checked ? '?deleteApp=1' : ''}`);
    showJob(r.jobId);
    refresh();
  } catch (e) {
    alert(e.message);
  }
});

// ---------- Settings ----------

async function loadSettings() {
  settings = await api('GET', '/api/settings');
}

function syncModeFields() {
  const mode = $('#form-settings')['cf.mode'].value;
  document.querySelectorAll('.mode-api').forEach((el) => el.classList.toggle('hidden', mode !== 'api'));
  document.querySelectorAll('.mode-local').forEach((el) => el.classList.toggle('hidden', mode !== 'local'));
}

let mspCreateStop = null;

function renderMspSettings() {
  const m = settings.msp;
  $('#msp-settings-missing').classList.toggle('hidden', !!m);
  $('#msp-settings-ready').classList.toggle('hidden', !m);
  if (!m) return;
  $('#msp-s-name').textContent = m.displayName;
  $('#msp-s-client').textContent = m.clientId;
  $('#msp-s-tenant').textContent = `${m.tenantDomain} · ${m.instances} instance${m.instances === 1 ? '' : 's'}`;
  const cur = m.cert?.current;
  const days = cur ? Math.ceil((new Date(cur.notAfter) - Date.now()) / 86400000) : 0;
  $('#msp-s-cert').textContent = cur ? `${cur.thumbprint.slice(0, 8)}… · expires ${new Date(cur.notAfter).toLocaleDateString()} (${days}d)` : '—';
  const ar = m.cert?.autoRenew || {};
  $('#msp-s-renew').textContent = ar.lastError ? `failed: ${ar.lastError}` : ar.ready ? 'ready' : ar.ready === false ? `not ready: ${(ar.reasons || []).join('; ')}` : 'not checked yet';
  $('#btn-msp-renew').disabled = !!m.busy;
  const urls = (m.redirectUris || []).filter((u) => !u.includes('/oauth2/nativeclient'));
  $('#msp-s-urls').replaceChildren(...(urls.length ? urls.flatMap((u, i) => [i ? h('br') : '', u]) : ['not known yet']));
  const here = `${location.origin}/auth/callback`;
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  const registered = urls.some((u) => u === here || u === location.origin || u === `${location.origin}/`) || (local && urls.some((u) => u.startsWith('http://localhost')));
  $('#btn-msp-reapprove').classList.toggle('primary', !registered);
  if (!registered && !$('#msp-reapprove-status').textContent) {
    $('#msp-reapprove-status').textContent = `${location.origin} is not registered yet; Re-approve from here to use Approve now from this address.`;
  }
}

let mspReapproveStop = null;
$('#btn-msp-reapprove').addEventListener('click', () => {
  mspReapproveStop?.();
  $('#btn-msp-reapprove').disabled = true;
  mspReapproveStop = popupSession({ kind: 'msp-app-update' }, async (s) => {
    if (renderSession(s, $('#msp-reapprove-status'), $('#msp-reapprove-steps'), () => 'MSP app updated')) {
      $('#btn-msp-reapprove').disabled = false;
      await loadSettings();
      renderMspSettings();
    } else if (s.status === 'error') $('#btn-msp-reapprove').disabled = false;
  });
});

$('#btn-msp-create').addEventListener('click', () => {
  mspCreateStop?.();
  $('#btn-msp-create').disabled = true;
  mspCreateStop = popupSession({ kind: 'msp-app' }, async (s) => {
    if (renderSession(s, $('#msp-create-status'), $('#msp-create-steps'), () => 'MSP app created')) {
      await loadSettings();
      renderMspSettings();
    } else if (s.status === 'error') $('#btn-msp-create').disabled = false;
  });
});

$('#btn-msp-renew').addEventListener('click', async () => {
  if (!confirm('Renew the MSP app certificate now? All MSP instances will switch to the new certificate.')) return;
  try {
    const r = await api('POST', '/api/msp/renew-certificate');
    closeDialog('dlg-settings');
    showJob(r.jobId);
  } catch (e) {
    alert(e.message);
  }
});

async function openSettings() {
  await loadSettings();
  renderMspSettings();
  const f = $('#form-settings');
  for (const k of ['instancesDir', 'baseDomain', 'neo4jMemory', 'uiPortBase', 'apiPortBase', 'certLifetimeMonths', 'certRenewBeforeDays']) f[k].value = settings[k] ?? '';
  for (const k of ['mode', 'accountId', 'tunnelId', 'zoneId', 'configPath', 'tunnelName']) f[`cf.${k}`].value = settings.cloudflare[k] ?? '';
  f['cf.apiToken'].value = '';
  f['cf.apiToken'].placeholder = settings.cloudflare.hasApiToken ? 'Saved — leave blank to keep' : 'Required for remotely-managed tunnels';
  $('#settings-error').classList.add('hidden');
  syncModeFields();
  $('#dlg-settings').showModal();

  const info = $('#detect-info');
  info.textContent = 'Detecting cloudflared…';
  try {
    const d = await api('GET', '/api/settings/detect');
    const t = d.tunnel;
    if (!t.serviceInstalled) info.textContent = `cloudflared ${d.platform === 'win32' ? 'Windows service' : 'systemd service'} not found.`;
    else if (t.mode === 'api') {
      info.textContent = `Detected token-based (remotely-managed) tunnel ${t.tunnelId}. Latest Prowler: ${d.latestRelease}.`;
      f['cf.accountId'].placeholder = t.accountId;
      f['cf.tunnelId'].placeholder = t.tunnelId;
    } else {
      info.textContent = `Detected locally-managed tunnel using ${t.configPath}. Latest Prowler: ${d.latestRelease}.`;
      f['cf.configPath'].placeholder = t.configPath;
    }
    const sys = $('#system-info');
    const docker = d.docker.ok ? `Docker ${d.docker.docker}, Compose ${d.docker.compose}` : d.docker.problems.join(' ');
    sys.textContent = `${docker} · Keys encrypted with: ${d.keyStorage}`;
    sys.className = d.docker.ok ? 'muted small' : 'small error-inline';
  } catch (e) {
    info.textContent = `Detection failed: ${e.message}`;
  }
}

$('#form-settings')['cf.mode'].addEventListener('change', syncModeFields);
$('#form-settings').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = { cloudflare: {} };
  for (const [k, v] of new FormData(ev.target)) {
    if (k.startsWith('cf.')) body.cloudflare[k.slice(3)] = v.trim();
    else body[k] = v;
  }
  try {
    await api('PUT', '/api/settings', body);
    await loadSettings();
    closeDialog('dlg-settings');
    refresh();
  } catch (e) {
    const el = $('#settings-error');
    el.textContent = e.message;
    el.classList.remove('hidden');
  }
});

// ---------- Self-update ----------

async function loadUpdateSource() {
  try {
    const src = await api('GET', '/api/update/source');
    const a = $('#upd-url');
    if (src.url) {
      a.href = src.url;
      a.textContent = src.url;
    } else {
      a.removeAttribute('href');
      a.textContent = src.mode === 'none' ? 'unknown (not a git clone or installer-based install)' : 'unknown';
    }
    $('#upd-branch').textContent = src.branch ? `branch ${src.branch}` : '';
  } catch {}
}

async function checkUpdates({ quiet = false } = {}) {
  const status = $('#upd-status');
  const apply = $('#upd-apply');
  if (!quiet) {
    status.textContent = 'Checking GitHub…';
    status.className = 'small muted';
    apply.disabled = true;
  }
  try {
    const c = await api('GET', '/api/update/check');
    $('#update-dot').classList.toggle('hidden', !c.updateAvailable);
    if (quiet) return c;
    if (c.url) {
      $('#upd-url').href = c.url;
      $('#upd-url').textContent = c.url;
    }
    $('#upd-current').textContent = c.current || '—';
    $('#upd-latest').textContent = c.latest || '—';
    $('#upd-commits').replaceChildren(
      ...(c.commits || []).map((x) =>
        h('li', {}, h('code', {}, x.short), h('span', {}, x.message), h('span', { class: 'when' }, `${x.author || ''} · ${x.date ? new Date(x.date).toLocaleDateString() : ''}`)),
      ),
    );
    if (!c.updateAvailable) {
      status.textContent = c.reason || 'You are on the latest version.';
      status.className = c.reason ? 'small error-inline' : 'small connected';
    } else {
      const count = c.commits.length ? `${c.commits.length} new commit${c.commits.length === 1 ? '' : 's'}. ` : '';
      status.textContent = c.canUpdate
        ? `${c.warning ? `${c.warning}. ` : ''}${count}Updating restarts the manager; Prowler instances keep running.`
        : c.reason;
      status.className = c.canUpdate ? 'small' : 'small error-inline';
    }
    apply.disabled = !c.canUpdate;
    const last = c.lastResult;
    $('#upd-last').textContent = last ? `Last update: ${last.state} ${last.finishedAt ? new Date(last.finishedAt).toLocaleString() : ''} ${last.message || ''}` : '';
    return c;
  } catch (e) {
    if (!quiet) {
      status.textContent = e.message;
      status.className = 'small error-inline';
    }
    return null;
  }
}

async function openUpdates() {
  $('#upd-commits').replaceChildren();
  $('#upd-last').textContent = '';
  $('#upd-current').textContent = '…';
  $('#upd-latest').textContent = '…';
  $('#dlg-update').showModal();
  await loadUpdateSource();
  await checkUpdates();
}

/** After an update starts, wait for the manager to come back on a new version, then reload. */
async function waitForNewVersion(oldSha) {
  const status = $('#upd-status');
  status.className = 'small';
  const started = Date.now();
  while (Date.now() - started < 10 * 60000) {
    await new Promise((r) => setTimeout(r, 3000));
    try {
      const v = await api('GET', '/api/version');
      if (v.sha && v.sha !== oldSha) {
        status.textContent = `Updated to ${v.sha.slice(0, 7)}. Reloading…`;
        setTimeout(() => location.reload(), 1000);
        return;
      }
      status.textContent = 'Updating… (the manager is still on the old version)';
    } catch {
      status.textContent = 'Updating… the manager is restarting';
    }
  }
  status.textContent = 'The manager has not come back on a new version yet. Check again in a minute, or look at the service log.';
  status.className = 'small error-inline';
}

$('#upd-check').addEventListener('click', () => checkUpdates());
$('#upd-apply').addEventListener('click', async () => {
  if (!confirm('Update Prowler Manager now? The manager restarts; Prowler instances keep running.')) return;
  const btn = $('#upd-apply');
  btn.disabled = true;
  try {
    const before = await api('GET', '/api/version');
    const r = await api('POST', '/api/update');
    $('#upd-status').textContent = `Updating ${r.from} → ${r.to}…`;
    waitForNewVersion(before.sha);
  } catch (e) {
    $('#upd-status').textContent = e.message;
    $('#upd-status').className = 'small error-inline';
    btn.disabled = false;
  }
});
$('#btn-updates').addEventListener('click', openUpdates);

// Quiet background check: show a dot on the Updates button when a new version exists.
checkUpdates({ quiet: true });
setInterval(() => checkUpdates({ quiet: true }), 6 * 3600000);

$('#btn-add').addEventListener('click', openCreate);
$('#btn-settings').addEventListener('click', openSettings);

loadSettings().then(refresh);
setInterval(refresh, 5000);
