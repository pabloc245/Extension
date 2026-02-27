let currentElements = [];
let currentMinKey = null;
let isModifying = false;
let timeout;
let observer = null;
let lastProcessedText = null;
let nextTimeout = null;

// Vérifier si le runtime est connecté
function isRuntimeValid() {
    try {
        return browser.runtime?.id !== undefined;
    } catch {
        return false;
    }
}

function selectPhrase() {
    console.log('[CONTENT] selectPhrase called, isModifying:', isModifying);
    
    if (isModifying) {
        console.log('[CONTENT] Blocked by isModifying flag');
        return;
    }

    // Vérifier que le runtime est valide
    if (!isRuntimeValid()) {
        console.error('[CONTENT] Runtime disconnected, reloading page');
        window.location.reload();
        return;
    }

    try {
        const resultats = [...document.querySelectorAll('div[dir="auto"]')].filter(el => {
            const text = el.textContent?.trim();
            if (!text || text.length > 50) return false;
            const style = getComputedStyle(el);
            return (
                parseFloat(style.fontSize) === 24 &&
                style.color === "rgb(22, 27, 39)" &&
                el.children.length === 0 &&
                el.offsetParent !== null
            );
        });

        console.log('[CONTENT] Found', resultats.length, 'candidate elements');

        if (resultats.length === 0) {
            console.log('[CONTENT] No elements found');
            return;
        }

        const groupesParClasse = {};
        resultats.forEach(el => {
            el.classList.forEach(cls => {
                groupesParClasse[cls] ??= [];
                groupesParClasse[cls].push(el);
            });
        });

        const keys = Object.keys(groupesParClasse);
        console.log('[CONTENT] Found', keys.length, 'class groups');
        
        if (keys.length === 0) {
            console.log('[CONTENT] No class groups');
            return;
        }

        const minKey = keys.reduce((a, b) =>
            groupesParClasse[a].length < groupesParClasse[b].length ? a : b
        );
        currentElements = groupesParClasse[minKey];

        const textes = groupesParClasse[minKey].map(el => el.textContent.trim());
        const texteComplet = textes.join(" ");

        console.log('[CONTENT] Text found:', texteComplet);
        console.log('[CONTENT] Last processed:', lastProcessedText);

        if (texteComplet === lastProcessedText) {
            console.log('[CONTENT] Same text as before, skipping');
            return;
        }
        
        lastProcessedText = texteComplet;

        console.log('[CONTENT] Sending PHRASE_FOUND message');
        browser.runtime.sendMessage({
            type: "PHRASE_FOUND",
            texte: texteComplet,
            texteArray: textes,
            class: minKey,
            count: currentElements.length
        }).then(() => {
            console.log('[CONTENT] Message sent successfully');
        }).catch(err => {
            console.error('[CONTENT] Send failed:', err);
            // Si erreur DeadObject, recharger la page
            if (err.message?.includes('dead') || !isRuntimeValid()) {
                console.log('[CONTENT] Runtime dead, reloading page in 1s');
                setTimeout(() => window.location.reload(), 1000);
            }
        });
    } catch (e) {
        console.error('[CONTENT] selectPhrase error:', e);
    }
}

function suivant() {
    console.log('[CONTENT] suivant called');
    try {
        lastProcessedText = null;
        currentElements = [];
        
        const button = [...document.querySelectorAll('[data-testid="button-text"]')].find(el => el.textContent.trim() === 'SUIVANT');
        if (button) {
            console.log('[CONTENT] Clicking SUIVANT button');
            button.dispatchEvent(new MouseEvent("click", {
                bubbles: true,
                cancelable: true,
                view: window
            }));
        } else {
            console.log('[CONTENT] SUIVANT button not found');
        }
    } catch (e) {
        console.error('[CONTENT] suivant error:', e);
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function dispatchClick(el) {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
}

function scheduleNext() {
    clearTimeout(nextTimeout);
    nextTimeout = setTimeout(suivant, 100);
}

function unlock() {
    isModifying = false;
}

// ─── Message Handler ─────────────────────────────────────────────────────────

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('[CONTENT] Message received:', message.type);

    try {
        switch (message.type) {

            case "MODIFY_ELEMENT": {
                if (message.index == null) {
                    sendResponse({ success: false, error: "Invalid index" });
                    return true;
                }

                const el = currentElements[message.index];
                if (!el) {
                    console.warn('[CONTENT] Element not found at index', message.index);
                    unlock();
                    sendResponse({ success: false, error: "Element not found" });
                    return true;
                }

                console.log('[CONTENT] Modifying element', message.index);
                Object.assign(el.style, message.highlight ? message.styles : { backgroundColor: "" });

                if (message.auto) {
                    console.log('[CONTENT] Auto mode: clicking element');
                    dispatchClick(el);
                    scheduleNext();
                }

                unlock();
                sendResponse({ success: true });
                return true;
            }

            case "NO_MISTAKE": {
                if (!message.auto) {
                    sendResponse({ success: true , auto: false });
                    return true;
                }

                const button = [...document.querySelectorAll('[data-testid="button-text"]')]
                    .find(el => el.textContent.trim() === "Il n'y a pas de faute");

                if (!button) {
                    console.warn('[CONTENT] No mistake button not found');
                    sendResponse({ success: false, error: "Element not found" });
                    return true;
                }

                console.log('[CONTENT] No mistake: clicking button');
                dispatchClick(button);
                scheduleNext();
                sendResponse({ success: true, auto: true });
                return true;
            }

            case "FORCE_RECHECK": {
                console.log('[CONTENT] Force recheck triggered');
                lastProcessedText = null;
                unlock();
                clearTimeout(nextTimeout);
                nextTimeout = setTimeout(() => selectPhrase(), 100);
                sendResponse({ success: true });
                return true;
            }

            case "RESET_DETECTION": {
                console.log('[CONTENT] Reset detection');
                lastProcessedText = null;
                currentElements = [];
                unlock();
                clearTimeout(nextTimeout);
                clearTimeout(timeout);
                nextTimeout = setTimeout(() => selectPhrase(), 100);
                sendResponse({ success: true });
                return true;
            }

            default:
                sendResponse({ success: false, error: `Unknown message type: ${message.type}` });
                return true;
        }

    } catch (e) {
        console.error('[CONTENT] Message handler error:', e);
        unlock();
        sendResponse({ success: false, error: e.message });
        return true;
    }
});

function startObserver() {
    console.log('[CONTENT] Starting observer');
    try {
        if (observer) {
            observer.disconnect();
        }

        observer = new MutationObserver((mutations) => {
            console.log('[CONTENT] Mutation detected, mutations count:', mutations.length);
            
            const isOwnModification = mutations.some(m => 
                Array.from(m.addedNodes).concat(Array.from(m.removedNodes))
                    .some(n => currentElements.includes(n))
            );
            
            if (isOwnModification) {
                console.log('[CONTENT] Ignoring own modification');
                return;
            }
            
            clearTimeout(timeout);
            console.log('[CONTENT] Scheduling selectPhrase in 300ms');
            timeout = setTimeout(() => {
                console.log('[CONTENT] Timeout fired, calling selectPhrase');
                selectPhrase();
            }, 300);
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
        
        console.log('[CONTENT] Observer started');
    } catch (e) {
        console.error('[CONTENT] Observer error:', e);
    }
}

function cleanup() {
    console.log('[CONTENT] Cleanup called');
    try {
        if (observer) {
            observer.disconnect();
            observer = null;
        }
        clearTimeout(timeout);
        currentElements = [];
        isModifying = false;
        lastProcessedText = null;
    } catch (e) {
        console.error('[CONTENT] Cleanup error:', e);
    }
}

window.addEventListener('unload', cleanup);
window.addEventListener('pagehide', cleanup);

console.log('[CONTENT] Script loaded, starting...');
startObserver();
selectPhrase();