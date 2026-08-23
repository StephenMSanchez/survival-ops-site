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

// Decrypts one sub-page's content using an already-derived key-encryption-key
// against one specific wrapped entry. Returns the plaintext HTML string on
// success, or null if that entry doesn't unwrap with this key (wrong secret).
// Access is granted per sub-page, not per page -- each sub-page has its own
// key and its own wrapped-entry list, so a login can be scoped to exactly
// one tab within a page.
async function tryUnwrapSubpage(kek, wrapped, subpage) {
  try {
    const subKeyBytes = await aesGcmDecryptToBytes(kek, wrapped.iv, wrapped.ct);
    const subKey = await crypto.subtle.importKey('raw', subKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const contentBytes = await aesGcmDecryptToBytes(subKey, subpage.content.iv, subpage.content.ct);
    return new TextDecoder().decode(contentBytes);
  } catch (e) {
    return null;
  }
}

// Username+passcode login: for each sub-page, only bothers trying the one
// wrapped entry built for this exact username (if that sub-page grants it
// access at all), deriving the key from "username:passcode" together -- both
// must be right. Returns the subset of sub-pages this login can decrypt.
async function tryUnlockPageAsUser(username, passcode, pageData) {
  const unlockedSubpages = [];
  for (const sub of pageData.subpages) {
    const wrapped = sub.wrapped.find((w) => w.context === 'user:' + username);
    if (!wrapped) continue;
    const baseSalt = b64ToBytes(sub.salt);
    const salt = contextSaltBytes(baseSalt, wrapped.context);
    const kek = await deriveAesKey(username + ':' + passcode, salt);
    const html = await tryUnwrapSubpage(kek, wrapped, sub);
    if (html !== null) unlockedSubpages.push({ id: sub.id, title: sub.title, content: html });
  }
  return unlockedSubpages;
}

// Rotating-code login (no username): tries the passcode alone against each
// sub-page's totp: entries (one per tolerated time window).
async function tryUnlockPageAsTotp(passcode, pageData) {
  const unlockedSubpages = [];
  for (const sub of pageData.subpages) {
    const baseSalt = b64ToBytes(sub.salt);
    for (const w of sub.wrapped) {
      if (!w.context.startsWith('totp:')) continue;
      const salt = contextSaltBytes(baseSalt, w.context);
      const kek = await deriveAesKey(passcode, salt);
      const html = await tryUnwrapSubpage(kek, w, sub);
      if (html !== null) {
        unlockedSubpages.push({ id: sub.id, title: sub.title, content: html });
        break;
      }
    }
  }
  return unlockedSubpages;
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
      const unlockedSubpages = useUsername
        ? await tryUnlockPageAsUser(username.trim(), passcode, pageData)
        : await tryUnlockPageAsTotp(passcode, pageData);
      const subpageMeta = pageData.subpages.map((s) => ({ id: s.id, title: s.title }));
      return { id: entry.id, title: pageData.title, unlockedSubpages, subpageMeta };
    })
  );

  const unlocked = {};
  const pageMeta = {};
  for (const { id, title, unlockedSubpages, subpageMeta } of results) {
    pageMeta[id] = subpageMeta;
    if (unlockedSubpages.length > 0) unlocked[id] = { title, subpages: unlockedSubpages };
  }
  return { unlocked, manifest, pageMeta };
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
  const { unlocked, manifest, pageMeta } = state;
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

  // A page is "locked" with zero granted tabs, "limited" with some but not
  // all, or neither (full access) -- distinct from a single sub-tab's own
  // locked state, shown separately on its subtab button.
  function accessClass(id) {
    const page = unlocked[id];
    if (!page) return 'locked';
    const total = (pageMeta[id] || []).length;
    return page.subpages.length < total ? 'limited' : '';
  }

  contentIds.forEach((id) => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = '#' + id;
    a.textContent = titleById[id];
    a.dataset.id = id;
    const cls = accessClass(id);
    if (cls) a.classList.add(cls);
    li.appendChild(a);
    navList.appendChild(li);
  });

  if (allIds.includes('admin')) {
    adminBtn.hidden = false;
    adminBtn.classList.toggle('locked', !unlocked.admin);
  }

  const CLEARANCE_CODES = { survival: 'SURV', technical: 'TECH', tactical: 'TAC' };

  // A page can now be partially unlocked (some sub-tabs visible, others not),
  // so the message differs: no access to the page at all uses the short
  // clearance-code phrasing; missing just one sub-tab names that sub-tab.
  function clearanceMessage(pageId, subTitle, hasPageAccess) {
    if (!hasPageAccess) {
      const code = CLEARANCE_CODES[pageId];
      return code ? 'You do not have ' + code + ' clearance.' : 'You do not have clearance for ' + titleById[pageId] + '.';
    }
    return 'You do not have clearance for ' + subTitle + '.';
  }

  function showAccessDenied(message) {
    modalMessage.textContent = message;
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
        const cls = accessClass(id);
        return (
          '<li><a href="#' + id + '" data-id="' + id + '"' + (cls ? ' class="' + cls + '"' : '') + '>' +
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
    // Sub-page id/title metadata is public (unlike its content), so a locked
    // page can still show its title and tab labels -- just no body content.
    const meta = pageMeta[pageId] || [];
    const activeId = meta.some((s) => s.id === subId) ? subId : meta[0] && meta[0].id;

    const tabs = meta
      .map((s) => {
        const isLocked = !(page && page.subpages.some((p) => p.id === s.id));
        return (
          '<button class="subtab' + (s.id === activeId ? ' active' : '') + (isLocked ? ' locked' : '') +
          '" data-sub="' + s.id + '">' + s.title + '</button>'
        );
      })
      .join('');
    const tabsHtml = meta.length > 1 ? '<div class="subtabs">' + tabs + '</div>\n' : '';
    const activeMeta = meta.find((s) => s.id === activeId);
    const subHeaderHtml = activeMeta ? '<h3 class="subpage-title">' + activeMeta.title + '</h3>\n' : '';

    // "page" exists whenever the login unlocks at least one sub-tab here, but
    // that doesn't mean this specific sub-tab is one of them -- check both.
    const activeSub = page && page.subpages.find((s) => s.id === activeId);

    if (!activeSub) {
      const heading = page ? page.title : titleById[pageId];
      content.innerHTML = '<h2>' + heading + '</h2>\n' + tabsHtml + subHeaderHtml;
      wireSubtabClicks(pageId);
      showAccessDenied(clearanceMessage(pageId, activeMeta && activeMeta.title, !!page));
      return;
    }

    content.innerHTML =
      '<h2>' + page.title + '</h2>\n' + tabsHtml + subHeaderHtml +
      '<div class="subpage-body">' + activeSub.content + '</div>';
    wireSubtabClicks(pageId);
    wirePackTiers();
  }

  function wireSubtabClicks(pageId) {
    content.querySelectorAll('.subtab').forEach((btn) => {
      btn.addEventListener('click', () => {
        window.location.hash = pageId + '/' + btn.dataset.sub;
      });
    });
  }

  // Content set via innerHTML never runs its own <script> tags, so the
  // pack-tiers markup (Emergency Packs: GHB/BOB/SRS checklists) needs its
  // tier-switching, checkbox persistence, and progress bar reimplemented
  // here rather than relying on script tags baked into the content HTML.
  function wirePackTiers() {
    const tiersEl = content.querySelector('.pack-tiers');
    if (!tiersEl) return;
    const STORAGE_PREFIX = 'sos_pack_';

    content.querySelectorAll('.pack-tier-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const tier = btn.dataset.tier;
        content.querySelectorAll('.pack-tier-btn').forEach((b) => b.classList.toggle('active', b.dataset.tier === tier));
        content.querySelectorAll('.pack-tier-panel').forEach((p) => p.classList.toggle('active', p.dataset.tier === tier));
      });
    });

    content.querySelectorAll('.pack-tier-panel').forEach((panel) => {
      const tier = panel.dataset.tier;
      const storageKey = STORAGE_PREFIX + tier;
      const checkboxes = Array.from(panel.querySelectorAll('.pack-item input[type="checkbox"]'));
      const countEl = panel.querySelector('.pack-checked-count');
      const totalEl = panel.querySelector('.pack-total-count');
      const fillEl = panel.querySelector('.pack-progress-fill');
      const resetBtn = panel.querySelector('.pack-reset');

      function loadState() {
        try {
          const raw = localStorage.getItem(storageKey);
          return raw ? JSON.parse(raw) : {};
        } catch (e) {
          return {};
        }
      }

      function saveState(state) {
        try {
          localStorage.setItem(storageKey, JSON.stringify(state));
        } catch (e) {
          // storage unavailable -- checks still work for this page load
        }
      }

      function updateProgress() {
        const checked = checkboxes.filter((cb) => cb.checked).length;
        countEl.textContent = String(checked);
        totalEl.textContent = String(checkboxes.length);
        fillEl.style.width = (checkboxes.length ? (checked / checkboxes.length) * 100 : 0) + '%';
      }

      const state = loadState();
      checkboxes.forEach((cb) => {
        if (state[cb.id]) {
          cb.checked = true;
          cb.closest('.pack-item').classList.add('checked');
        }
        cb.addEventListener('change', () => {
          cb.closest('.pack-item').classList.toggle('checked', cb.checked);
          state[cb.id] = cb.checked;
          saveState(state);
          updateProgress();
        });
      });

      if (resetBtn) {
        resetBtn.addEventListener('click', () => {
          checkboxes.forEach((cb) => {
            cb.checked = false;
            cb.closest('.pack-item').classList.remove('checked');
          });
          saveState({});
          updateProgress();
        });
      }

      updateProgress();
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

  function goToPage(id) {
    showPage(id);
    window.location.hash = id;
  }

  function handleNavClick(e) {
    const a = e.target.closest('a[data-id]');
    if (!a) return;
    e.preventDefault();
    goToPage(a.dataset.id);
  }

  navList.addEventListener('click', handleNavClick);
  // Delegated so it keeps working after renderHome() replaces #content's markup.
  content.addEventListener('click', (e) => {
    if (e.target.closest('.home-links')) handleNavClick(e);
  });
  const brandSubtitle = document.querySelector('.brand-subtitle');
  if (brandSubtitle) brandSubtitle.addEventListener('click', handleNavClick);
  adminBtn.addEventListener('click', () => goToPage('admin'));

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
      const { unlocked, manifest, pageMeta } = await attemptUnlock(username, passcode);
      if (Object.keys(unlocked).length === 0) {
        showGateError(username.trim() ? 'Invalid username or passcode.' : 'Invalid rotating code.');
        passcodeInput.value = '';
        passcodeInput.focus();
        return;
      }
      const state = { unlocked, manifest, pageMeta };
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
