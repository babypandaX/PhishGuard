const API_ENDPOINT = 'http://localhost:5000/check';
const RISK_THRESHOLD = 30;
const IGNORED_SCHEMES = ['chrome://', 'about:', 'file://', 'chrome-extension://'];
let allowedUrls = new Set();

// Initialize from storage
chrome.storage.local.get(['allowedUrls'], (result) => {
  allowedUrls = new Set(result.allowedUrls || []);
});

// Heartbeat monitoring
chrome.alarms.create('phishguard-hb', { periodInMinutes: 1 });

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  const url = details.url;
  console.log('[PhishGuard] Checking:', url);
// Skip non-web URLs
  if (!url.startsWith('http')) {
    console.log('[PhishGuard] Skipping non-HTTP URL:', url);
    return;
  }
  
  if (details.frameId !== 0 || IGNORED_SCHEMES.some(s => url.startsWith(s))) return;

  try {
    if (allowedUrls.has(url)) {
      console.log('[PhishGuard] Bypassing allowed URL:', url);
      allowedUrls.delete(url);
      await chrome.storage.local.set({ allowedUrls: [...allowedUrls] });
      return;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);
    
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status} ${await response.text()}`);
    }
    
    const result = await response.json();
    
    if (result.risk_score >= RISK_THRESHOLD) {
      console.log('[PhishGuard] Blocking URL:', url, 'Score:', result.risk_score);
      await chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}`)
      });
    }
  } catch (error) {
    console.error('[PhishGuard] Navigation Error:', error);
    const errorType = error.name === 'AbortError' ? 'timeout' : 'error';
    
    await chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL(
        `warning.html?url=${encodeURIComponent(url)}&error=${errorType}`
      )
    });
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  (async () => {
    try {
      switch(request.action) {
        case 'getRiskData':
          const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: request.url })
          });
          sendResponse(await response.json());
          break;

        case 'allowUrl':
          allowedUrls.add(request.url);
          await chrome.storage.local.set({ allowedUrls: [...allowedUrls] });
          sendResponse({ status: 'allowed' });
          break;

        case 'keepAlive':
          sendResponse({ status: 'alive' });
          break;

        default: 
          sendResponse({ error: 'Invalid action' });
      }
    } catch (error) {
      console.error('Message Error:', error);
      sendResponse({ error: error.message });
    }
  })();
  return true;
});
