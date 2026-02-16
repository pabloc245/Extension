let currentElements = [];
let currentMinKey = null;
let isModifying = false;
let timeout;
let observer = null;

function selectPhrase() {
    if (isModifying) return;

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

        if (resultats.length === 0) return;

        const groupesParClasse = {};
        resultats.forEach(el => {
            el.classList.forEach(cls => {
                groupesParClasse[cls] ??= [];
                groupesParClasse[cls].push(el);
            });
        });

        const keys = Object.keys(groupesParClasse);
        if (keys.length === 0) return;

        const minKey = keys.reduce((a, b) =>
            groupesParClasse[a].length < groupesParClasse[b].length ? a : b
        );
        currentElements = groupesParClasse[minKey]; 

        const textes = groupesParClasse[minKey].map(el => el.textContent.trim());

        browser.runtime.sendMessage({ 
            type: "PHRASE_FOUND",
            texte: textes.join(" "),  
            texteArray: textes,       
            class: minKey,
            count: currentElements.length
        }).catch(err => console.error('[CONTENT] Send failed:', err));
    } catch (e) {
        console.error('[CONTENT] selectPhrase error:', e);
    }
}   

function suivant() {
    try {
        const button = [...document.querySelectorAll('[data-testid="button-text"]')].find(el => el.textContent.trim() === 'SUIVANT');
        if (button) {
            button.dispatchEvent(new MouseEvent("click", {
                bubbles: true,
                cancelable: true,
                view: window
            }));
        }
    } catch (e) {
        console.error('[CONTENT] suivant error:', e);
    }
}

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    try {
        if (message.type === "MODIFY_ELEMENT") {
            if (!message?.index && message.index !== 0) {
                sendResponse({ success: false, error: "Invalid index" });
                return true;
            }

            const el = currentElements[message.index];
            if (el) {
                isModifying = true; 
                
                Object.assign(el.style, message.highlight ? message.styles : {backgroundColor : ""});                  
 

                if (message.auto) {    
                    const clickEvent = new MouseEvent("click", {
                        bubbles: true,
                        cancelable: true,
                        view: window
                    });
                    el.dispatchEvent(clickEvent);
                    setTimeout(suivant, 100);
                }

                isModifying = false;
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: "Element not found" });
            }
            return true;
        } 

        if (message.type === "NO_MISTAKE") {
            const button = [...document.querySelectorAll('[data-testid="button-text"]')].find(el => el.textContent.trim() === "Il n'y a pas de faute");
            if (button) {
                button.dispatchEvent(new MouseEvent("click", {
                    bubbles: true,
                    cancelable: true,
                    view: window
                }));
                setTimeout(suivant, 100);
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: "Element not found" });
            }
            return true;
        }
    } catch (e) {
        console.error('[CONTENT] Message handler error:', e);
        sendResponse({ success: false, error: e.message });
        return true;
    }
});

function startObserver() {
    try {
        if (observer) {
            observer.disconnect();
        }

        observer = new MutationObserver((mutations) => {
            clearTimeout(timeout);
            timeout = setTimeout(selectPhrase, 300);
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    } catch (e) {
        console.error('[CONTENT] Observer error:', e);
    }
}

function cleanup() {
    try {
        if (observer) {
            observer.disconnect();
            observer = null;
        }
        clearTimeout(timeout);
        currentElements = [];
        isModifying = false;
    } catch (e) {
        console.error('[CONTENT] Cleanup error:', e);
    }
}

window.addEventListener('unload', cleanup);
window.addEventListener('pagehide', cleanup);

startObserver();
selectPhrase();
