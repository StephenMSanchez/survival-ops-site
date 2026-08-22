// Client-side app: passcode gate + decrypt + render.
//
// IMPORTANT: content is genuinely encrypted (AES-256-GCM), not merely hidden by JS.
// Without a passcode that successfully unwraps a page's content key, the browser has
// no way to recover that page's plaintext -- inspecting page source only reveals
// ciphertext. See README.md for the full security model and its limits.
'use strict';

const PBKDF2_ITERATIONS = 200000;
const SESSION_KEY = 'sos_unlocked_v1';

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function contextSaltBytes(baseSaltBytes, context) {
  const ctxBytes = new TextEncoder().encode(':' + context);
  const combined = new Uint8Array(baseSaltBytes.length + ctxBytes.length);
  combined.set(baseSaltBytes, 0);
  combined.set(ctxBytes, baseSaltBytes.length);
  return combined;
}

async function deriveAesKey(passcode, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passcode),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

async function aesGcmDecryptToBytes(key, ivB64, ctB64) {
  const iv = b64ToBytes(ivB64);
  const ct = b64ToBytes(ctB64);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(ptBuf);
}

// Attempts to unlock a single page's data with the given passcode.
// Returns {title, html} on success, or null if this passcode doesn't unlock this page.
async function tryUnlockPage(passcode, pageData) {
  const baseSalt = b64ToBytes(pageData.salt);
  for (const w of pageData.wrapped) {
    try {
      const salt = contextSaltBytes(baseSalt, w.context);
      const kek = await deriveAesKey(passcode, salt);
      const pageKeyBytes = await aesGcmDecryptToBytes(kek, w.iv, w.ct);
      const pageKey = await crypto.subtle.importKey('raw', pageKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
      const contentBytes = await aesGcmDecryptToBytes(pageKey, pageData.content.iv, pageData.content.ct);
      return JSON.parse(new TextDecoder().decode(contentBytes));
    } catch (e) {
      // Wrong passcode for this wrapped entry -- try the next one.
      continue;
    }
  }
  return null;
}

async function attemptUnlock(passcode) {
  const manifestRes = await fetch('pages/manifest.json', { cache: 'no-store' });
  const manifest = await manifestRes.json();

  const unlocked = {};
  await Promise.all(
    manifest.map(async (entry) => {
      const res = await fetch('pages/' + entry.id + '.json', { cache: 'no-store' });
      const pageData = await res.json();
      const result = await tryUnlockPage(passcode, pageData);
      if (result) {
        unlocked[entry.id] = result;
      }
    })
  );
  return unlocked;
}

function saveSession(unlocked) {
  try {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(unlocked));
  } catch (e) {
    // sessionStorage unavailable -- unlock still works for this page load, just won't persist.
  }
}

function loadSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

function clearSession() {
  try {
    sessionStorage.removeItem(SESSION_KEY);
  } catch (e) {
    // ignore
  }
}

function renderApp(unlocked) {
  const ids = Object.keys(unlocked);
  document.getElementById('gate').hidden = true;
  document.getElementById('app').hidden = false;

  const navList = document.getElementById('nav-list');
  const content = document.getElementById('content');
  navList.innerHTML = '';

  if (ids.length === 0) {
    content.innerHTML = '<p class="empty-state">No pages available for this code.</p>';
    return;
  }

  ids.forEach((id, idx) => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = '#' + id;
    a.textContent = unlocked[id].title;
    a.dataset.id = id;
    if (idx === 0) a.classList.add('active');
    li.appendChild(a);
    navList.appendChild(li);
  });

  function showPage(id) {
    const page = unlocked[id];
    if (!page) return;
    content.innerHTML = page.html;
    document.querySelectorAll('#nav-list a').forEach((a) => {
      a.classList.toggle('active', a.dataset.id === id);
    });
  }

  navList.addEventListener('click', (e) => {
    const a = e.target.closest('a');
    if (!a) return;
    e.preventDefault();
    showPage(a.dataset.id);
    window.location.hash = a.dataset.id;
  });

  const initial = window.location.hash ? window.location.hash.slice(1) : ids[0];
  showPage(unlocked[initial] ? initial : ids[0]);

  // Lets links outside #nav-list (e.g. the header banner) jump to a page too.
  window.addEventListener('hashchange', () => {
    const id = window.location.hash ? window.location.hash.slice(1) : ids[0];
    showPage(unlocked[id] ? id : ids[0]);
  });

  document.getElementById('lock-btn').addEventListener('click', () => {
    clearSession();
    window.location.hash = '';
    window.location.reload();
  });
}

function showGateError(message) {
  const err = document.getElementById('gate-error');
  err.textContent = message;
  err.hidden = false;
}

async function init() {
  const cached = loadSession();
  if (cached && Object.keys(cached).length > 0) {
    renderApp(cached);
    return;
  }

  const form = document.getElementById('gate-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('passcode-input');
    const passcode = input.value;
    const submitBtn = form.querySelector('button');
    submitBtn.disabled = true;
    document.getElementById('gate-error').hidden = true;

    try {
      const unlocked = await attemptUnlock(passcode);
      if (Object.keys(unlocked).length === 0) {
        showGateError('Invalid passcode.');
        input.value = '';
        input.focus();
        return;
      }
      saveSession(unlocked);
      renderApp(unlocked);
    } catch (err) {
      showGateError('Something went wrong checking that code. Try again.');
    } finally {
      submitBtn.disabled = false;
    }
  });
}

init();
