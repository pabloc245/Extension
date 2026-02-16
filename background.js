
const URL_PATTERNS = ['/levels/'];
const MAX_PHRASES = 10000;
const SEND_TIMEOUT = 5000;

console.log('[DECRYPT] Background loaded');

const seenLevels = new Set();
const phrasesMap = new Map();
const pendingMessages = new Set();
const API_URL = 'http://localhost:8000'; 


function normalize(text) {
  if (!text) return "";
  return text
    .toLowerCase()
    .normalize("NFC")
    .replace(/[''`´]/g, "'")
    .replace(/\s*'\s*/g, "'")
    .replace(/[.,!?;:"]/g, "")
    .replace(/\s*([-–—])\s*/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
}

let params = {
  highlight: true,
  color: "yellow",
  network: true,
  auto: false,
  errors: 0,
  mistake: 0,
  levels: [],
  delais: 1000,
};

let lastSendTime = 0;

function shouldIntercept(url) {
  return URL_PATTERNS.some(pattern => url.includes(pattern));
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function parseAndStoreRules(rules) {
  if (!Array.isArray(rules)) {
    console.error('[DECRYPT] Invalid rules format');
    return;
  }

  console.log('[DECRYPT] Parsing', rules.length, 'rules');
  let stored = 0;
  
  for (const rule of rules) {
    if (!rule?.exercises) continue;
    
    for (const exercise of rule.exercises) {
      if (!exercise?.sentence) continue;
      
      if (phrasesMap.size >= MAX_PHRASES) {
        console.warn('[DECRYPT] Max phrases reached, clearing old entries');
        const entries = [...phrasesMap.entries()];
        phrasesMap.clear();
        entries.slice(-Math.floor(MAX_PHRASES * 0.8)).forEach(([k, v]) => phrasesMap.set(k, v));
      }
      
      const fullText = exercise.sentence.map(part => {
        let text = part.text || "";
        if (part.before) text = part.before + text;
        if (part.after) text = text + part.after;
        return text;
      }).join(" ");

      const normalized = normalize(fullText).trim();
      
      if (!normalized) continue;
      
      if (phrasesMap.has(normalized)) {
        console.warn('[DECRYPT] Duplicate key:', normalized.substring(0, 50));
        continue;
      }
      
      if (!exercise.hasMistake) {
        phrasesMap.set(normalized, { 
          hasMistake: false,
          id: exercise.id 
        });
        stored++;
        continue;
      }
      
      const mistakePart = exercise.sentence.find(part => part.mistake === true);
      const mistakeText = mistakePart?.text?.trim() || null;
      
      let correctionText = null;
      if (exercise.correction?.[0]) {
        const correctionPart = exercise.correction[0].find(part => part.correction === true);
        correctionText = correctionPart?.text?.trim() || null;
      }
      
      phrasesMap.set(normalized, {
        hasMistake: true,
        mistakeText,
        correctionText,
        id: exercise.id
      });
      stored++;
    }
  }
  console.log('[DECRYPT] Stored', stored, 'phrases. Total:', phrasesMap.size);
}
async function decrypt(data) {
  try {
    const res = await fetch(`${API_URL}/decode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: data  // ArrayBuffer ou Uint8Array
    });
    
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    
    const json = await res.json();
    return json.data;  // Retourne le JSON déchiffré
    
  } catch (e) {
    console.error('[DECRYPT] Error:', e);
    return null;
  }
}

function checkPhrase(text) {
  if (!text) return { found: false };
  
  const normalized = normalize(text);
  const result = phrasesMap.get(normalized);
  
  if (!result) {
    console.log('[DECRYPT] no match: ', normalized);
  }
  
  return result ? { found: true, ...result } : { found: false };
}

function sendMessageWithTimeout(tabId, message, options = {}) {
  const msgId = `${Date.now()}_${Math.random()}`;
  pendingMessages.add(msgId);

  const timeout = setTimeout(() => {
    if (pendingMessages.has(msgId)) {
      pendingMessages.delete(msgId);
      console.warn('[DECRYPT] Message timeout:', message.type);
    }
  }, SEND_TIMEOUT);

  return browser.tabs.sendMessage(tabId, message, options)
    .then(response => {
      clearTimeout(timeout);
      pendingMessages.delete(msgId);
      return response;
    })
    .catch(err => {
      clearTimeout(timeout);
      pendingMessages.delete(msgId);
      console.error('[DECRYPT] Send failed:', err);
      throw err;
    });
}

browser.runtime.onMessage.addListener((message, sender) => {
  try {
    if (message.type == "PHRASE_FOUND") {
      if (!message?.texte || !message?.texteArray || !sender?.tab?.id) {
        console.error('[DECRYPT] Invalid message format');
        return;
      }

      const fullText = message.texte;
      const phraseResult = checkPhrase(fullText);

      if (!phraseResult.hasMistake) {
        sendMessageWithTimeout(
          sender.tab.id,
          { type: "NO_MISTAKE" },
          { frameId: sender.frameId }
        ).catch(() => {});
        return;
      }

      if (!phraseResult.found || !phraseResult.hasMistake) return;

      const targetText = phraseResult.mistakeText;
      if (!targetText) {
        console.warn('[DECRYPT] No mistake text found');
        return;
      }

      const index = message.texteArray.findIndex(part => part.trim() === targetText.trim().split(/\s+/)[0]);

      if (index === -1) {
        console.warn('[DECRYPT] Target not found in array:', targetText);
        return;
      }

      const sendMessage = () => {
          sendMessageWithTimeout(
            sender.tab.id,
            {
              type: "MODIFY_ELEMENT",
              index,
              auto: params.auto,
              highlight: params.highlight,
              styles: { backgroundColor: String(params.color) }
            },
            { frameId: sender.frameId }
          ).catch(() => {});
        };

        if (params.auto && params.delais > 0) {
          const now = Date.now();
          const timeSinceLastSend = now - lastSendTime;
          const del = params.delais;
          const randomDelay = Math.floor(Math.random() * (del - del/2) + del/2);
          const actualDelay = Math.max(randomDelay, params.delais - timeSinceLastSend);

          
          setTimeout(() => {
            lastSendTime = Date.now();
            sendMessage();
          }, actualDelay);
        } else {
          sendMessage();
        }
    }

    if (message.type === "UPDATE_PARAMS") {
      updateParams(message.payload);
      saveParams();
      return Promise.resolve({ ok: true, params });
    }

    if (message.type === "GET_PARAMS") {
      return Promise.resolve(params);
    }
  } catch (e) {
    console.error('[DECRYPT] Message handler error:', e);
    return Promise.reject(e);
  }
});

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      if (!shouldIntercept(details.url)) return {};
      
      const match = details.url.match(/levels\/(\d+)\.json/);
      if (!match) return {};
      
      const levelId = match[1];
      if (seenLevels.has(levelId)) return {};
      
      console.log('[DECRYPT] Intercepting level', levelId);
      
      const filter = browser.webRequest.filterResponseData(details.requestId);
      const chunks = [];
      let filterClosed = false;
      
      const closeFilter = () => {
        if (!filterClosed) {
          filterClosed = true;
          try {
            filter.disconnect();
          } catch (e) {
            console.error('[DECRYPT] Filter disconnect error:', e);
          }
        }
      };
      
      filter.ondata = (event) => {
        try {
          chunks.push(new Uint8Array(event.data));
          filter.write(event.data);
        } catch (e) {
          console.error('[DECRYPT] Filter ondata error:', e);
          closeFilter();
        }
      };
      
      filter.onstop = async () => {
        try {
          const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
          const combined = new Uint8Array(totalLength);
          let offset = 0;
          for (const chunk of chunks) {
            combined.set(chunk, offset);
            offset += chunk.length;
          }
          
          const firstChar = String.fromCharCode(combined[0]);
          if (firstChar === '{' || firstChar === '[') {
            closeFilter();
            return;
          }
          
          seenLevels.add(levelId);
          await decrypt(combined);
          closeFilter();
        } catch (e) {
          console.error('[DECRYPT] Filter onstop error:', e);
          closeFilter();
        }
      };

      filter.onerror = (e) => {
        console.error('[DECRYPT] Filter error:', e);
        closeFilter();
      };
      
      return {};
    } catch (e) {
      console.error('[DECRYPT] Request listener error:', e);
      return {};
    }
  },
  { urls: ["https://apprentissage.appli3.projet-voltaire.fr/*", "https://content-prd.projet-voltaire.fr/v55/*"]},
  ["blocking"]
);

function updateParams(update) {
  if (!update || typeof update !== 'object') {
    console.error('[DECRYPT] Invalid update object');
    return;
  }

  if ("highlight" in update) {
    params.highlight = !!update.highlight;
  }

  if ("network" in update) {
    params.network = !!update.network;
  }

  if ("auto" in update) {
    params.auto = !!update.auto;
  }

  if ("color" in update) {
    params.color = "yellow";
    //params.color = String(update.color);
  }
  if("delais" in update){
    params.delais = update.delais;
  }

  console.log("params mis à jour :", params);
}

function saveParams() {
  browser.storage.local.set({ params })
    .catch(err => console.error('[DECRYPT] Save params failed:', err));
}

function loadParams() {
  browser.storage.local.get('params')
    .then(result => {
      if (result?.params) {
        Object.assign(params, result.params);
        console.log('[DECRYPT] Params loaded:', params);
        params.color ='yellow';
      }
    })
    .catch(err => console.error('[DECRYPT] Load params failed:', err));
}

loadParams();

function clamp(v) {
  return Math.min(255, Math.max(0, v));
}
