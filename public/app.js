const DEV_IDENTITIES = [
  { label: 'Member 1001 — premium', userId: 1001, isPremium: true },
  { label: 'Member 1001 — free', userId: 1001, isPremium: false },
  { label: 'Member 987654321 — premium', userId: 987654321, isPremium: true },
];

const state = {
  attempts: 0,
  config: null,
  lastAttestation: null,
};

const select = (selector) => document.querySelector(selector);

async function requestJson(url, { method = 'GET', body } = {}) {
  const options = { method, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  const response = await fetch(url, options);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`HTTP ${response.status}: invalid server response`);
  }
  if (!response.ok) {
    const error = new Error(payload.error || `HTTP ${response.status}`);
    error.payload = payload;
    throw error;
  }
  return payload;
}

function shortHash(value) {
  if (!value) return '';
  return value.length > 28 ? `${value.slice(0, 14)}…${value.slice(-14)}` : value;
}

function setStatus(kind, message) {
  const status = select('#status');
  status.className = `status ${kind}`;
  status.textContent = message;
}

function appendDetail(label, content, { monospace = false } = {}) {
  const wrapper = document.createElement('div');
  wrapper.className = 'row';
  const term = document.createElement('dt');
  term.textContent = label;
  const description = document.createElement('dd');
  if (monospace) description.className = 'mono';
  if (content instanceof Node) description.appendChild(content);
  else description.textContent = content;
  wrapper.append(term, description);
  select('#detail').appendChild(wrapper);
}

function addLogRow(source, nullifier, success, message = '') {
  state.attempts += 1;
  const row = document.createElement('tr');
  const values = [
    `#${state.attempts}`,
    source,
    nullifier ? shortHash(nullifier) : '—',
    success ? 'VALID' : message || 'INVALID',
  ];
  values.forEach((value, index) => {
    const cell = document.createElement('td');
    cell.textContent = value;
    if (index === 2) cell.className = 'mono';
    if (index === 3) cell.className = success ? 'ok' : 'err';
    row.appendChild(cell);
  });
  select('#log tbody').prepend(row);
}

function proofSize(proof) {
  return `${Math.max(1, Math.round(JSON.stringify(proof).length / 1024))} KB`;
}

async function authenticate(initData, source) {
  select('#result').classList.remove('hidden');
  select('#detail').replaceChildren();
  setStatus('working', 'Validating Telegram data and generating proof…');
  try {
    const challenge = await requestJson('/api/challenge');
    const gatewayBase = state.config.gatewayOrigin || '';
    const attestPath = gatewayBase ? `${gatewayBase}/v1/attest` : '/v1/attest';
    const { attestation } = await requestJson(attestPath, {
      method: 'POST',
      body: {
        initData,
        challenge: challenge.challenge,
        audience: challenge.audience,
        appDomain: challenge.appDomain,
        actionId: challenge.actionId,
      },
    });
    const verification = await requestJson('/api/verify', {
      method: 'POST',
      body: { attestation },
    });
    if (!verification.isValid) throw new Error(verification.error || 'verification failed');

    state.lastAttestation = attestation;
    setStatus('ok', 'Telegram session and gateway-attested proof verified');
    appendDetail('Source', source);
    appendDetail('Nullifier', shortHash(verification.nullifierHash), { monospace: true });
    appendDetail('Issuer', verification.issuer);
    appendDetail('Action', verification.actionId);
    appendDetail('Expires', new Date(verification.expiresAt * 1000).toISOString());
    appendDetail('Gateway key', shortHash(state.config.gatewayPublicKeyFingerprint), { monospace: true });
    appendDetail('Proof size', proofSize(attestation.proofPayload.proof));

    const signals = document.createElement('pre');
    signals.className = 'mono dim';
    signals.textContent = JSON.stringify(attestation.proofPayload.publicSignals, null, 2);
    appendDetail('Public signals', signals);

    addLogRow(source, verification.nullifierHash, true);
    select('#tamper').disabled = false;
    select('#claim').disabled = false;
    select('#cross-domain').disabled = false;
    select('#claim-result').classList.add('hidden');
  } catch (error) {
    setStatus('error', error.message || String(error));
    addLogRow(source, null, false, error.message);
  }
}

function telegramInitData() {
  const telegram = globalThis.Telegram;
  const webApp = telegram && typeof telegram === 'object' ? telegram.WebApp : null;
  if (!webApp || typeof webApp.initData !== 'string' || !webApp.initData) return '';
  if (typeof webApp.ready === 'function') webApp.ready();
  return webApp.initData;
}

select('#telegram-login').addEventListener('click', async () => {
  const initData = telegramInitData();
  if (!initData) {
    setStatus('error', 'No Telegram Mini App session is available. Open this page through the configured bot.');
    select('#result').classList.remove('hidden');
    return;
  }
  await authenticate(initData, 'Telegram Mini App');
});

select('#tamper').addEventListener('click', async () => {
  if (!state.lastAttestation) return;
  const tampered = structuredClone(state.lastAttestation);
  tampered.proofPayload.proof.pi_a[0] = '1';
  const verification = await requestJson('/api/verify', {
    method: 'POST',
    body: { attestation: tampered },
  });
  const rejected = !verification.isValid;
  setStatus(rejected ? 'ok' : 'error', rejected
    ? `Tampered attestation rejected: ${verification.error}`
    : 'Tampered attestation was unexpectedly accepted');
  addLogRow('Tampered attestation', null, false, verification.error || 'unexpectedly accepted');
});

select('#cross-domain').addEventListener('click', async () => {
  if (!state.lastAttestation) return;
  const verification = await requestJson('/api/verify', {
    method: 'POST',
    body: { attestation: state.lastAttestation, appDomain: 'other.example' },
  });
  const rejected = !verification.isValid;
  setStatus(rejected ? 'ok' : 'error', rejected
    ? `Cross-domain use rejected: ${verification.error}`
    : 'Cross-domain use was unexpectedly accepted');
  addLogRow('Cross-domain verification', null, false, verification.error || 'unexpectedly accepted');
});

async function claim() {
  if (!state.lastAttestation) return;
  const output = select('#claim-result');
  output.classList.remove('hidden');
  output.className = 'status working';
  output.textContent = 'Submitting claim…';
  try {
    const result = await requestJson('/api/claim', {
      method: 'POST',
      body: { attestation: state.lastAttestation },
    });
    output.className = 'status ok';
    output.textContent = `Claim accepted (${result.claims} total claims).`;
    select('#reclaim').disabled = false;
  } catch (error) {
    output.className = 'status error';
    output.textContent = `Claim rejected: ${error.message}`;
  }
}

select('#claim').addEventListener('click', claim);
select('#reclaim').addEventListener('click', claim);

async function enableDevelopmentSimulation() {
  const panel = select('#dev-panel');
  panel.classList.remove('hidden');
  const container = select('#identities');
  for (const identity of DEV_IDENTITIES) {
    const button = document.createElement('button');
    button.className = 'identity';
    button.textContent = `Simulate: ${identity.label}`;
    button.addEventListener('click', async () => {
      const { initData } = await requestJson('/api/dev/init', {
        method: 'POST',
        body: { userId: identity.userId, isPremium: identity.isPremium },
      });
      await authenticate(initData, identity.label);
    });
    container.appendChild(button);
  }
}

async function initialize() {
  state.config = await requestJson('/api/config');
  const telegramData = telegramInitData();
  select('#telegram-help').textContent = telegramData
    ? 'Telegram session detected and ready to authenticate.'
    : 'Open through the configured Telegram bot. Local simulation is available only in development mode.';
  if (state.config.devSimulationEnabled) await enableDevelopmentSimulation();
}

initialize().catch((error) => {
  select('#result').classList.remove('hidden');
  setStatus('error', `Application initialization failed: ${error.message}`);
});
