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

// Decrypts a page's content using an already-derived key-encryption-key
// against one specific wrapped entry. Returns {title, subpages} on success,
// or null if that entry doesn't unwrap with this key (wrong secret).
async function tryWrappedEntry(kek, wrapped, pageData) {
  try {
    const pageKeyBytes = await aesGcmDecryptToBytes(kek, wrapped.iv, wrapped.ct);
    const pageKey = await crypto.subtle.importKey('raw', pageKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const contentBytes = await aesGcmDecryptToBytes(pageKey, pageData.content.iv, pageData.content.ct);
    return JSON.parse(new TextDecoder().decode(contentBytes));
  } catch (e) {
    return null;
  }
}

// Username+passcode login: only bothers trying the one wrapped entry that
// was built for this exact username (if this page grants it access at all),
// deriving the key from "username:passcode" together -- both must be right.
async function tryUnlockPageAsUser(username, passcode, pageData) {
  const wrapped = pageData.wrapped.find((w) => w.context === 'user:' + username);
  if (!wrapped) return null;
  const baseSalt = b64ToBytes(pageData.salt);
  const salt = contextSaltBytes(baseSalt, wrapped.context);
  const kek = await deriveAesKey(username + ':' + passcode, salt);
  return tryWrappedEntry(kek, wrapped, pageData);
}

// Rotating-code login (no username): tries the passcode alone against each
// totp: entry (one per tolerated time window).
async function tryUnlockPageAsTotp(passcode, pageData) {
  const baseSalt = b64ToBytes(pageData.salt);
  for (const w of pageData.wrapped) {
    if (!w.context.startsWith('totp:')) continue;
    const salt = contextSaltBytes(baseSalt, w.context);
    const kek = await deriveAesKey(passcode, salt);
    const result = await tryWrappedEntry(kek, w, pageData);
    if (result) return result;
  }
  return null;
}

async function attemptUnlock(username, passcode) {
  const manifestRes = await fetch('pages/manifest.json', { cache: 'no-store' });
  const manifest = await manifestRes.json();
  const useUsername = username.trim().length > 0;

  // Fetch/decrypt concurrently, but Promise.all preserves manifest order in its
  // results regardless of which one finishes first -- unlike assigning into an
  // object from inside each async task, which would order keys by completion
  // time instead of manifest order.
  const results = await Promise.all(
    manifest.map(async (entry) => {
      const res = await fetch('pages/' + entry.id + '.json', { cache: 'no-store' });
      const pageData = await res.json();
      const result = useUsername
        ? await tryUnlockPageAsUser(username.trim(), passcode, pageData)
        : await tryUnlockPageAsTotp(passcode, pageData);
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
  // "admin" gets its own dedicated button (styled like Lock Site) instead of
  // living in the regular page list/nav/home links.
  const contentIds = allIds.filter((id) => id !== 'admin');
  const titleById = {};
  manifest.forEach((m) => {
    titleById[m.id] = m.title;
  });

  document.getElementById('gate').hidden = true;
  const appEl = document.getElementById('app');
  appEl.hidden = false;

  const navList = document.getElementById('nav-list');
  const content = document.getElementById('content');
  const modal = document.getElementById('access-modal');
  const modalMessage = document.getElementById('access-modal-message');
  const adminBtn = document.getElementById('admin-btn');
  navList.innerHTML = '';

  if (allIds.length === 0) {
    content.innerHTML = '<p class="empty-state">No pages configured.</p>';
    return;
  }

  contentIds.forEach((id) => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = '#' + id;
    a.textContent = titleById[id];
    a.dataset.id = id;
    if (!unlocked[id]) a.classList.add('locked');
    li.appendChild(a);
    navList.appendChild(li);
  });

  if (allIds.includes('admin')) {
    adminBtn.hidden = false;
    adminBtn.classList.toggle('locked', !unlocked.admin);
  }

  const CLEARANCE_CODES = { survival: 'SURV', technical: 'TECH', tactical: 'TAC' };

  function clearanceMessage(id) {
    const code = CLEARANCE_CODES[id];
    return code ? 'You do not have ' + code + ' clearance.' : 'You do not have clearance for ' + titleById[id] + '.';
  }

  function showAccessDenied(id) {
    modalMessage.textContent = clearanceMessage(id);
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
    delete appEl.dataset.page;
    const links = contentIds
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
    adminBtn.classList.remove('active');
  }

  function renderPage(pageId, subId) {
    appEl.dataset.page = pageId;
    const page = unlocked[pageId];

    if (!page) {
      content.innerHTML =
        '<h2>' + titleById[pageId] + '</h2>\n' +
        '<div class="access-denied-inline">\n' +
        '  <p class="access-denied-title">Access Denied</p>\n' +
        '  <p>' + clearanceMessage(pageId) + '</p>\n' +
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
    adminBtn.classList.toggle('active', pageId === 'admin');
  }

  function goToPageOrDeny(id) {
    if (!unlocked[id]) {
      showAccessDenied(id);
      return;
    }
    showPage(id);
    window.location.hash = id;
  }

  function handleNavClick(e) {
    const a = e.target.closest('a[data-id]');
    if (!a) return;
    e.preventDefault();
    goToPageOrDeny(a.dataset.id);
  }

  navList.addEventListener('click', handleNavClick);
  // Delegated so it keeps working after renderHome() replaces #content's markup.
  content.addEventListener('click', (e) => {
    if (e.target.closest('.home-links')) handleNavClick(e);
  });
  const brandSubtitle = document.querySelector('.brand-subtitle');
  if (brandSubtitle) brandSubtitle.addEventListener('click', handleNavClick);
  adminBtn.addEventListener('click', () => goToPageOrDeny('admin'));

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
    const usernameInput = document.getElementById('username-input');
    const passcodeInput = document.getElementById('passcode-input');
    const username = usernameInput.value;
    const passcode = passcodeInput.value;
    const submitBtn = form.querySelector('button');
    submitBtn.disabled = true;
    document.getElementById('gate-error').hidden = true;

    try {
      const { unlocked, manifest } = await attemptUnlock(username, passcode);
      if (Object.keys(unlocked).length === 0) {
        showGateError(username.trim() ? 'Invalid username or passcode.' : 'Invalid rotating code.');
        passcodeInput.value = '';
        passcodeInput.focus();
        return;
      }
      const state = { unlocked, manifest };
      saveSession(state);
      renderApp(state);
    } catch (err) {
      showGateError('Something went wrong checking that login. Try again.');
    } finally {
      submitBtn.disabled = false;
    }
  });
}

init();
