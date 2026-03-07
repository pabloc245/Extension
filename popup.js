// ─── Config ────────────────────────────────────────────────────────────────

const API_URL = 'https://ferney.uk';

// ─── State ─────────────────────────────────────────────────────────────────

let stats  = { err: 10, ok: 0, levels: [] };
let params = { highlight: false, color: 'yellow', network: true, auto: false, delais: 1000, freetrial: true};
let ctx    = null;

// ─── Views ─────────────────────────────────────────────────────────────────

const VIEWS = ['login-view', 'main-view', 'payment-view'];

function showView(id) {
  VIEWS.forEach(v => {
    document.getElementById(v).classList.toggle('active', v === id);
  });
}

const showLogin   = () => showView('login-view');
const showMain    = () => showView('main-view');
const showPayment = () => showView('payment-view');

// ─── Render ─────────────────────────────────────────────────────────────────

function render() {
  document.getElementById('err').textContent         = stats.err;
  document.getElementById('ok').textContent          = stats.ok;
  document.getElementById('delay-value').textContent = params.delais;

  const list = document.getElementById('list');
  list.innerHTML = '';
  stats.levels.slice(-12).forEach(l => {
    const li      = document.createElement('li');
    li.textContent = `level_${l.id}.json`;
    li.className   = l.err ? 'err' : 'ok';
    list.appendChild(li);
  });

}

// ─── Messaging ─────────────────────────────────────────────────────────────

function updateParam(partial) {
  return browser.runtime.sendMessage({ type: 'UPDATE_PARAMS', payload: partial });
}

// ─── Login ─────────────────────────────────────────────────────────────────

async function initLogin() {
  const loginBtn   = document.getElementById('login-btn');
  const emailInput = document.getElementById('email');
  const codeInput  = document.getElementById('code');
  const errorEl    = document.getElementById('login-error');

  function setError(msg, isSuccess = false) {
    errorEl.style.color = isSuccess ? '#7fff7f' : '';
    errorEl.textContent = msg;
  }
  function setLoading(loading) {
    loginBtn.disabled    = loading;
    loginBtn.textContent = loading ? 'SENDING...' : 'VERIFY';
  }

  // Restore state if extension was closed mid-login
  codeInput.classList.add('hidden');
  const { pendingEmail } = await browser.storage.local.get(['pendingEmail']);
  if (pendingEmail) {
    emailInput.value = pendingEmail;
    codeInput.classList.remove('hidden');
    codeInput.focus();
    setError('Code already sent, check your email', true);
  }

  async function doLogin() {
    const email = emailInput.value.trim();
    const code  = codeInput.value.trim();
    setError('');

    if (!email) { setError('Email required'); return; }

    if (!code && codeInput.classList.contains('hidden')) {
      // Step 1: request code
      setLoading(true);
      try {
        const res  = await fetch(`${API_URL}/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        const data = await res.json();
        if (res.ok) {
          await browser.storage.local.set({ pendingEmail: email });
          codeInput.classList.remove('hidden');
          codeInput.focus();
          setError('Code sent to email', true);
        } else {
          setError(data.error || 'Registration failed');
        }
      } catch(e) {
        setError('Network error');
      } finally {
        setLoading(false);
      }
      return;
    }

    setLoading(true);
    loginBtn.textContent = 'VERIFYING...';
    try {
      const res  = await fetch(`${API_URL}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code }),
      });
      const data = await res.json();
      if (res.ok) {
        if (!data.token || !data.refresh_token) {
          setError('Server error: no token received');
          return;
        }
        await browser.storage.local.remove(['pendingEmail']);
        await browser.storage.local.set({
          authToken:    data.token,
          authEmail:    email,
          authExpires:  data.expires_at,
          refreshToken: data.refresh_token,
        });
        showMain();
        initMain();
      } else {
        setError(data.error || 'Invalid code');
      }
    } catch {
      setError('Network error');
    } finally {
      setLoading(false);
      loginBtn.textContent = 'VERIFY';
    }
  }

  loginBtn.onclick = doLogin;
  [emailInput, codeInput].forEach(el =>
    el.addEventListener('keypress', e => e.key === 'Enter' && (e.preventDefault(), doLogin()))
  );
}

// ─── Payment ────────────────────────────────────────────────────────────────

function initPayment() {
  const PAYMENT_URL = 'https://kbhnb.gumroad.com/l/candide';
  browser.storage.local.get(['authEmail']).then(({ authEmail = '' }) => {
    const url = new URL(PAYMENT_URL);
    url.searchParams.set('email', authEmail);
    document.getElementById('payment-btn').href = url.toString();
  });
}

// ─── Main ───────────────────────────────────────────────────────────────────

function initMain() {
  const dpr    = window.devicePixelRatio || 1;
  
  // Controls mapping: [elementId, event, paramKey, getValue]
  const controls = [
    ['auto',     'change', 'auto',      el => el.checked],
    ['hl',       'change', 'highlight', el => el.checked],
    ['net',      'change', 'network',   el => el.checked],
    ['hlColor',  'input',  'color',     el => String(el.value)],
  ];

  controls.forEach(([id, event, key, getValue]) => {
    document.getElementById(id)?.addEventListener(event, ({ target }) => {
      params[key] = getValue(target);
      updateParam({ [key]: params[key] });
    });
  });

  document.getElementById('delay-plus')?.addEventListener('click', () => {
    if (params.delais >= 5000) return;
    params.delais += 100;
    updateParam({ delais: params.delais });
    render();
  });

  document.getElementById('delay-minus')?.addEventListener('click', () => {
    if (params.delais <= 0) return;
    params.delais -= 100;
    updateParam({ delais: params.delais });
    render();
  });

  document.getElementById('reset')?.addEventListener('click', () => {
    params.delais = 1000;
    updateParam({ delais: params.delais });
    render();
  });
  render();
}


// ─── Boot ───────────────────────────────────────────────────────────────────

function fetchParams() {
  return browser.runtime.sendMessage({ type: 'GET_PARAMS' })  
    .then(p => {
      console.log('p reçu:', p);
      if (!p){ 
        console.error('No params received');
        return;
      }
      params.freetrial = p.freetrial ?? params.freetrial;
      document.getElementById('auto').checked  = !!p.auto;
      document.getElementById('hl').checked    = !!p.highlight;
      document.getElementById('net').checked   = !!p.network;
      document.getElementById('hlColor').value = p.color || params.color;
      params.delais  = p.delais || params.delais;
      stats.levels   = (p.levels || []).map(id => ({ id }));
      stats.err      = p.errors || 0;
      render();
    })
  .catch(() => render());
}

browser.storage.local.get(['authToken']).then(async ({ authToken}) => {

  if (!authToken) {
    console.log('No auth token found, showing login');
    showLogin();
    initLogin();
    return;
  }

  try {
    await fetchParams();
    if (getValidToken()!=null && 0) {
      if (params.freetrial == true) { 
        console.log('User authenticated with active subscription');
        showMain();
        initMain();
      } else {
        console.log('User authenticated but no active subscription');
        showPayment();
        initPayment();
      }
    } else {  
      console.log('Authentication failed, showing login');
      showLogin();
      initLogin();
    }
  } catch {
    console.log('Network error during authentication, showing login');
    showMain();
    initMain();
  }
});



async function getValidToken() {
    const { authToken, authExpires, refreshToken } = await browser.storage.local.get(
        ['authToken', 'authExpires', 'refreshToken']
    );
    
    if (Date.now() < new Date(authExpires) - 3000) {
        return authToken; 
    }
    
    const res = await fetch(`${API_URL}/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken })
    });
    
    if (res.ok) {
        const data = await res.json();
        await browser.storage.local.set({ authToken: data.token, authExpires: data.expires_at });
        return data.token;
    }
    
    return null;
}