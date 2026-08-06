const IDENTITIES = [
  { label: 'You — premium', userId: 1001, isPremium: true },
  { label: 'You — free', userId: 1001, isPremium: false },
  { label: 'Someone else — premium', userId: 987654321, isPremium: true },
  { label: 'Someone else — free', userId: 987654321, isPremium: false },
];

const APP_DOMAIN = 'zktele-login.demo';

const state = {
  attempts: 0,
  lastProofPayload: null,
  seenUsers: new Map(),
};

const $ = (sel) => document.querySelector(sel);

function renderIdentities() {
  const container = $('#identities');
  container.innerHTML = '';
  for (const identity of IDENTITIES) {
    const btn = document.createElement('button');
    btn.textContent = `Log in as: ${identity.label}`;
    btn.className = 'identity';
    btn.addEventListener('click', () => login(identity));
    container.appendChild(btn);
  }
}

async function post(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) {
    const err = new Error(json.error || `HTTP ${res.status}`);
    err.payload = json;
    throw err;
  }
  return json;
}

function shortHash(hex) {
  if (!hex) return '';
  return hex.length > 24 ? `${hex.slice(0, 12)}…${hex.slice(-12)}` : hex;
}

async function login(identity) {
  const result = $('#result');
  result.classList.remove('hidden');
  setStatus('working', 'Authenticating… (generating BLS12-381 proof)');
  $('#detail').innerHTML = '';

  try {
    const { initData } = await post('/api/init', {
      userId: identity.userId,
      isPremium: identity.isPremium,
    });

    const auth = await post('/api/authenticate', { initData });
    const verification = await post('/api/verify', {
      proofPayload: auth.proofPayload,
    });

    state.lastProofPayload = auth.proofPayload;
    state.attempts += 1;

    const nullifier = verification.nullifierHash || auth.nullifierHash;
    const seen = state.seenUsers.get(identity.userId);
    state.seenUsers.set(identity.userId, (seen || 0) + 1);

    if (verification.isValid) {
      setStatus('ok', `Login verified — valid Groth16 proof`);
    } else {
      setStatus('error', `Login FAILED: ${verification.error}`);
    }

    $('#detail').innerHTML = `
      <div class="row"><dt>Identity</dt><dd>${identity.label} <span class="dim">(known only to this page)</span></dd></div>
      <div class="row"><dt>Nullifier</dt><dd class="mono">${shortHash(nullifier)}</dd></div>
      ${
        seen
          ? `<div class="row"><dt>Same user before?</dt><dd>Yes, but this is a <em>fresh</em> nullifier → the two logins are <strong>unlinkable</strong> server-side.</dd></div>`
          : `<div class="row"><dt>Same user before?</dt><dd>No — first time this identity logged in.</dd></div>`
      }
      <div class="row"><dt>appDomainHash</dt><dd class="mono dim">${shortHash(verification.appDomainHash || auth.proofPayload.appDomainHash)}</dd></div>
      <div class="row"><dt>Timestamp</dt><dd>${new Date((auth.proofPayload.timestamp || 0) * 1000).toISOString()}</dd></div>
      <div class="row"><dt>Proof size</dt><dd>${proofSize(auth.proofPayload.proof)}</dd></div>
      <div class="row"><dt>Server received</dt><dd><pre class="mono dim">${JSON.stringify({ ...auth, proofPayload: '…' }, null, 2)}</pre></dd></div>
      <div class="row"><dt>Proof public signals</dt><dd><pre class="mono dim">${JSON.stringify(auth.proofPayload.publicSignals, null, 2)}</pre></dd></div>
    `;
  } catch (err) {
    setStatus('error', err.message || String(err));
  }
}

function proofSize(proof) {
  try {
    const kb = Math.round(JSON.stringify(proof).length / 1024);
    return `${kb} KB`;
  } catch {
    return '?';
  }
}

function setStatus(kind, text) {
  $('#status').className = `status ${kind}`;
  $('#status').textContent = text;
}

renderIdentities();
