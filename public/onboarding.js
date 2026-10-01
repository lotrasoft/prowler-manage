// Popup page between the Microsoft sign-in and admin-consent pages.
const params = new URLSearchParams(location.search);
const id = params.get('id');
const $ = (sel) => document.querySelector(sel);
let redirected = false;

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  Object.assign(e, attrs);
  e.append(...children);
  return e;
}

function setStatus(text, { busy = false, cls = '' } = {}) {
  const status = $('#status');
  status.className = cls;
  status.replaceChildren(...(busy ? [el('span', { className: 'spinner' })] : []), text);
}

function closeButton() {
  $('#actions').replaceChildren(el('button', { className: 'btn primary', onclick: () => window.close() }, 'Close window'));
}

const WAITING = {
  'signing-in': 'Completing sign-in…',
  working: 'Setting things up…',
  'preparing-consent': 'Preparing the permission request…',
  verifying: 'Permissions granted. Waiting for them to take effect…',
};

async function tick() {
  let s;
  try {
    const res = await fetch(`/api/onboarding/${id}`);
    s = await res.json();
    if (!res.ok) throw new Error(s.error || res.statusText);
  } catch (e) {
    setStatus(e.message, { cls: 'error-inline' });
    closeButton();
    return;
  }
  $('#steps').replaceChildren(...s.steps.map((t) => el('li', { className: t.startsWith('WARNING') ? 'warn' : '' }, t)));

  if (s.status === 'awaiting-consent' && s.consentUrl && !redirected) {
    redirected = true;
    setStatus('Next, Microsoft will ask you to approve Prowler\'s read-only permissions…', { busy: true });
    setTimeout(() => location.assign(s.consentUrl), 1500);
    return;
  }
  if (s.status === 'done') {
    setStatus(`Connected ${s.orgName} (${s.tenantDomain}). You can return to Prowler Manager.`, { cls: 'connected' });
    closeButton();
    setTimeout(() => window.close(), 2500);
    return;
  }
  if (s.status === 'error') {
    setStatus(s.error, { cls: 'error-inline' });
    closeButton();
    return;
  }
  setStatus(WAITING[s.status] || s.status, { busy: true });
  setTimeout(tick, 1500);
}

if (params.get('expired') || !id) {
  setStatus('This connection request has expired. Start again from Prowler Manager.', { cls: 'error-inline' });
  closeButton();
} else {
  tick();
}
