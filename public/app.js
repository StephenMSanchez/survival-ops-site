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

  // Fetch/decrypt concurrently, but Promise.all preserves manifest order in its
  // results regardless of which one finishes first -- unlike assigning into an
  // object from inside each async task, which would order keys by completion
  // time instead of manifest order.
  const results = await Promise.all(
    manifest.map(async (entry) => {
      const res = await fetch('pages/' + entry.id + '.json', { cache: 'no-store' });
      const pageData = await res.json();
      const result = await tryUnlockPage(passcode, pageData);
      return { id: entry.id, result };
    })
  );

  const unlocked = {};
  for (const { id, result } of results) {
    if (result) unlocked[id] = result;
  }
  return { unlocked, manifest };
}

function saveSession(state) {
  try {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(state));
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

function renderApp(state) {
  const { unlocked, manifest } = state;
  const allIds = manifest.map((m) => m.id);
  const titleById = {};
  manifest.forEach((m) => {
    titleById[m.id] = m.title;
  });

  document.getElementById('gate').hidden = true;
  document.getElementById('app').hidden = false;

  const navList = document.getElementById('nav-list');
  const content = document.getElementById('content');
  const modal = document.getElementById('access-modal');
  const modalMessage = document.getElementById('access-modal-message');
  navList.innerHTML = '';

  if (allIds.length === 0) {
    content.innerHTML = '<p class="empty-state">No pages configured.</p>';
    return;
  }

  allIds.forEach((id) => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = '#' + id;
    a.textContent = titleById[id];
    a.dataset.id = id;
    if (!unlocked[id]) a.classList.add('locked');
    li.appendChild(a);
    navList.appendChild(li);
  });

  function showAccessDenied(id) {
    modalMessage.textContent = 'You do not have clearance for ' + titleById[id] + '.';
    modal.hidden = false;
  }

  function hideAccessDenied() {
    modal.hidden = true;
  }

  document.getElementById('access-modal-dismiss').addEventListener('click', hideAccessDenied);
  modal.addEventListener('click', (e) => {
    if (e.target === modal) hideAccessDenied();
  });

  function renderHome() {
    const links = allIds
      .map((id) => {
        const locked = !unlocked[id];
        return (
          '<li><a href="#' + id + '" data-id="' + id + '"' + (locked ? ' class="locked"' : '') + '>' +
          titleById[id] + '</a></li>'
        );
      })
      .join('');
    content.innerHTML =
      '<h2>STAC-OPS</h2>\n' +
      '<p>Select a section to continue.</p>\n' +
      '<ul class="home-links">' + links + '</ul>';
    document.querySelectorAll('#nav-list a').forEach((a) => a.classList.remove('active'));
  }

  function renderPage(pageId, subId) {
    const page = unlocked[pageId];

    if (!page) {
      content.innerHTML =
        '<h2>' + titleById[pageId] + '</h2>\n' +
        '<div class="access-denied-inline">\n' +
        '  <p class="access-denied-title">Access Denied</p>\n' +
        '  <p>You do not have clearance for this section.</p>\n' +
        '</div>';
      return;
    }

    const subpages = page.subpages;
    const active = subpages.find((s) => s.id === subId) || subpages[0];

    const tabs = subpages
      .map(
        (s) =>
          '<button class="subtab' + (s.id === active.id ? ' active' : '') + '" data-sub="' +
          s.id + '">' + s.title + '</button>'
      )
      .join('');

    content.innerHTML =
      '<h2>' + page.title + '</h2>\n' +
      (subpages.length > 1 ? '<div class="subtabs">' + tabs + '</div>\n' : '') +
      '<div class="subpage-body">' + active.content + '</div>';

    content.querySelectorAll('.subtab').forEach((btn) => {
      btn.addEventListener('click', () => {
        window.location.hash = pageId + '/' + btn.dataset.sub;
      });
    });
  }

  function showPage(rawId) {
    const [pageId, subId] = (rawId || '').split('/');
    if (!pageId || pageId === 'home' || !allIds.includes(pageId)) {
      renderHome();
      return;
    }
    renderPage(pageId, subId);
    document.querySelectorAll('#nav-list a').forEach((a) => {
      a.classList.toggle('active', a.dataset.id === pageId);
    });
  }

  function handleNavClick(e) {
    const a = e.target.closest('a[data-id]');
    if (!a) return;
    e.preventDefault();
    const id = a.dataset.id;
    if (!unlocked[id]) {
      showAccessDenied(id);
      return;
    }
    showPage(id);
    window.location.hash = id;
  }

  navList.addEventListener('click', handleNavClick);
  // Delegated so it keeps working after renderHome() replaces #content's markup.
  content.addEventListener('click', (e) => {
    if (e.target.closest('.home-links')) handleNavClick(e);
  });
  const brandSubtitle = document.querySelector('.brand-subtitle');
  if (brandSubtitle) brandSubtitle.addEventListener('click', handleNavClick);

  const initial = window.location.hash ? window.location.hash.slice(1) : 'home';
  showPage(initial);

  // Lets links outside #nav-list/#content (e.g. the header banner) jump around too.
  window.addEventListener('hashchange', () => {
    const id = window.location.hash ? window.location.hash.slice(1) : 'home';
    showPage(id);
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
  if (cached && cached.unlocked && Object.keys(cached.unlocked).length > 0) {
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
      const { unlocked, manifest } = await attemptUnlock(passcode);
      if (Object.keys(unlocked).length === 0) {
        showGateError('Invalid passcode.');
        input.value = '';
        input.focus();
        return;
      }
      const state = { unlocked, manifest };
      saveSession(state);
      renderApp(state);
    } catch (err) {
      showGateError('Something went wrong checking that code. Try again.');
    } finally {
      submitBtn.disabled = false;
    }
  });
}

init();
