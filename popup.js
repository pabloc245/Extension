const SIZE = 100;
const CENTER = SIZE / 2;
const RADIUS_BG = 45;
const RADIUS_FG = 45;
const LINE_BG = 10;
const LINE_FG = 10;
const API_URL = 'http://localhost:8000'; 


let stats = { err: 10, ok: 0, levels: [] };
let params = { highlight: false, color: "yellow", network: true, auto: false, delais: 1000 };
let canvas, ctx;

function showLogin() {
  document.getElementById('login-view').style.display = 'flex';
  document.getElementById('main-view').style.display = 'none';
}

function showMain() {
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('main-view').style.display = 'flex';
}

function drawGauge() {
  if (!ctx) return;
  const total = stats.err + stats.ok || 1;
  const ratio = stats.err / total;

  ctx.clearRect(0, 0, SIZE, SIZE);
  ctx.lineWidth = LINE_BG;
  ctx.beginPath();
  ctx.strokeStyle = '#7fff7f';
  ctx.arc(CENTER, CENTER, RADIUS_BG, 0, Math.PI * 2);
  ctx.stroke();

  ctx.lineWidth = LINE_FG;
  ctx.beginPath();
  ctx.strokeStyle = '#be1f27';
  ctx.arc(CENTER, CENTER, RADIUS_FG, -Math.PI / 2, Math.PI * 2 * ratio - Math.PI / 2);
  ctx.stroke();
}

function render() {
  document.getElementById('err').textContent = stats.err;
  document.getElementById('ok').textContent = stats.ok;
  document.getElementById("delay-value").textContent = params.delais;
  
  const list = document.getElementById('list');
  list.innerHTML = '';
  stats.levels.slice(-12).forEach(l => {
    const li = document.createElement('li');
    li.textContent = `level_${l.id}.json`;
    li.className = l.err ? 'err' : 'ok';
    list.appendChild(li);
  });
  
  drawGauge();
}

function updateParam(partial) {
  return browser.runtime.sendMessage({ type: "UPDATE_PARAMS", payload: partial });
}

function initLogin() {
  const loginBtn = document.getElementById('login-btn');
  const emailInput = document.getElementById('email');
  const codeInput = document.getElementById('code');
  const errorEl = document.getElementById('login-error');

  const doLogin = async () => {
    const email = emailInput.value.trim();
    const code = codeInput.value.trim();
    errorEl.textContent = '';

    if (!email) {
      errorEl.textContent = 'Email required';
      return;
    }

    if (!code) {
      try {
        loginBtn.disabled = true;
        loginBtn.textContent = 'SENDING...';
        
        const res = await fetch(`${API_URL}/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });

        const data = await res.json();

        if (res.ok) {
          errorEl.style.color = '#7fff7f';
          errorEl.textContent = 'Code sent to email';
          codeInput.focus();
        } else {
          errorEl.textContent = data.error || 'Registration failed';
        }
      } catch (e) {
        console.error('[POPUP] Register error:', e);
        errorEl.textContent = 'Network error';
      } finally {
        loginBtn.disabled = false;
        loginBtn.textContent = 'VERIFY';
      }
      return;
    }

    try {
      loginBtn.disabled = true;
      loginBtn.textContent = 'VERIFYING...';

      const res = await fetch(`${API_URL}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code })
      });

      const data = await res.json();

      if (res.ok) {
        await browser.storage.local.set({ 
          authToken: data.token || email, 
          authEmail: email 
        });
        showMain();
        initMain();
      } else {
        errorEl.textContent = data.error || 'Invalid code';
      }
    } catch (e) {
      console.error('[POPUP] Verify error:', e);
      errorEl.textContent = 'Network error';
    } finally {
      loginBtn.disabled = false;
      loginBtn.textContent = 'VERIFY';
    }
  };

  loginBtn.onclick = doLogin;
  
  emailInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      doLogin();
    }
  });
  
  codeInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      doLogin();
    }
  });
}

function initMain() {
  canvas = document.getElementById('gauge');
  ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = SIZE * dpr;
  canvas.height = SIZE * dpr;
  canvas.style.width = canvas.style.height = `${SIZE}px`;
  ctx.scale(dpr, dpr);
  ctx.lineCap = 'round';

  const els = {
    auto: document.getElementById("auto"),
    highlight: document.getElementById("hl"),
    network: document.getElementById("net"),
    color: document.getElementById("hlColor"),
    delayPlus: document.getElementById("delay-plus"),
    delayMinus: document.getElementById("delay-minus"),
    reset: document.getElementById("reset")
  };

  els.auto?.addEventListener("change", () => {
    params.auto = els.auto.checked;
    updateParam({ auto: params.auto });
  });

  els.highlight?.addEventListener("change", () => {
    params.highlight = els.highlight.checked;
    updateParam({ highlight: params.highlight });
  });

  els.network?.addEventListener("change", () => {
    params.network = els.network.checked;
    updateParam({ network: params.network });
  });

  els.color?.addEventListener("input", () => {
    params.color = String(els.color.value);
    updateParam({ color: params.color });
  });

  els.delayPlus?.addEventListener("click", () => {
    if (params.delais < 5000) {
      params.delais += 100;
      updateParam({ delais: params.delais });
      render();
    }
  });

  els.delayMinus?.addEventListener("click", () => {
    if (params.delais > 0) {
      params.delais -= 100;
      updateParam({ delais: params.delais });
      render();
    }
  });

  els.reset?.addEventListener("click", () => {
    params.delais = 1000;
    updateParam({ delais: params.delais });
    render();
  });

  browser.runtime.sendMessage({ type: "GET_PARAMS" })
    .then(p => {
      if (!p) return;
      els.auto.checked = !!p.auto;
      els.highlight.checked = !!p.highlight;
      els.network.checked = !!p.network;
      els.color.value = p.color || params.color;
      params.delais = p.delais || params.delais;
      stats.levels = [...(p.levels || [])].map(id => ({ id }));
      stats.err = p.errors || 0;
      render();
    })
    .catch(() => render());
}

browser.storage.local.get(['authToken']).then(result => {
  if (result.authToken) {
    showMain();
    initMain();
  } else {
    showLogin();
    initLogin();
  } 
});