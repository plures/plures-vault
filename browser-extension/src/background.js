// Plures Vault — Background Service Worker
// Communicates with the native vault process via Native Messaging

const NATIVE_HOST = "com.plures.vault";
let nativePort = null;
let vaultUnlocked = false;
let cachedCredentials = [];

// ── Native Messaging ─────────────────────────────────────────────────────────

function connectNative() {
  if (nativePort) return;

  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST);

    nativePort.onMessage.addListener((msg) => {
      handleNativeMessage(msg);
    });

    nativePort.onDisconnect.addListener(() => {
      console.log("[plures] Native host disconnected:", chrome.runtime.lastError?.message);
      nativePort = null;
      vaultUnlocked = false;
      cachedCredentials = [];
      updateBadge();
    });

    console.log("[plures] Connected to native host");
  } catch (e) {
    console.error("[plures] Failed to connect:", e);
  }
}

function sendNative(msg) {
  if (!nativePort) connectNative();
  if (nativePort) {
    nativePort.postMessage(msg);
  } else {
    console.error("[plures] No native connection");
  }
}

function handleNativeMessage(msg) {
  switch (msg.type) {
    case "unlock_result":
      vaultUnlocked = msg.success;
      updateBadge();
      break;

    case "credentials_list":
      cachedCredentials = msg.credentials || [];
      break;

    case "credential_detail":
      // Forward to popup
      chrome.runtime.sendMessage({ type: "credential_detail", data: msg.credential });
      break;

    case "autofill_data":
      // Forward to content script
      if (msg.tabId) {
        chrome.tabs.sendMessage(msg.tabId, {
          type: "autofill",
          username: msg.username,
          password: msg.password,
        });
      }
      break;

    case "error":
      console.error("[plures] Native error:", msg.message);
      chrome.runtime.sendMessage({ type: "error", message: msg.message });
      break;
  }
}

// ── Badge ────────────────────────────────────────────────────────────────────

function updateBadge() {
  if (vaultUnlocked) {
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
  } else {
    chrome.action.setBadgeText({ text: "🔒" });
    chrome.action.setBadgeBackgroundColor({ color: "#6b7280" });
  }
}

// ── Message handler from popup / content script ──────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {
    case "unlock":
      sendNative({ type: "unlock", password: msg.password });
      sendResponse({ ok: true });
      break;

    case "lock":
      sendNative({ type: "lock" });
      vaultUnlocked = false;
      cachedCredentials = [];
      updateBadge();
      sendResponse({ ok: true });
      break;

    case "list_credentials":
      sendNative({ type: "list" });
      // Return cached immediately, update will come async
      sendResponse({ credentials: cachedCredentials });
      break;

    case "get_credential":
      sendNative({ type: "get", id: msg.id });
      sendResponse({ ok: true });
      break;

    case "autofill_request":
      // Find matching credential for current URL
      const url = msg.url;
      const match = findBestMatch(url);
      if (match) {
        sendNative({ type: "get_for_autofill", id: match.id, tabId: sender.tab?.id });
      }
      sendResponse({ found: !!match });
      break;

    case "get_status":
      sendResponse({ unlocked: vaultUnlocked, count: cachedCredentials.length });
      break;

    case "save_credential":
      sendNative({
        type: "save",
        title: msg.title,
        username: msg.username,
        password: msg.password,
        url: msg.url,
        notes: msg.notes,
      });
      sendResponse({ ok: true });
      break;
  }
  return true; // async response
});

// ── Commands ─────────────────────────────────────────────────────────────────

chrome.commands.onCommand.addListener((command) => {
  if (command === "autofill") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const url = tabs[0].url;
        const match = findBestMatch(url);
        if (match) {
          sendNative({ type: "get_for_autofill", id: match.id, tabId: tabs[0].id });
        }
      }
    });
  }
});

// ── URL matching ─────────────────────────────────────────────────────────────

function findBestMatch(url) {
  if (!url || !cachedCredentials.length) return null;

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // Exact URL match first
    let match = cachedCredentials.find((c) => c.url && c.url === url);
    if (match) return match;

    // Hostname match
    match = cachedCredentials.find((c) => {
      if (!c.url) return false;
      try {
        return new URL(c.url).hostname === hostname;
      } catch {
        return false;
      }
    });
    if (match) return match;

    // Domain match (e.g. github.com matches api.github.com)
    match = cachedCredentials.find((c) => {
      if (!c.url) return false;
      try {
        const credHost = new URL(c.url).hostname;
        return hostname.endsWith(credHost) || credHost.endsWith(hostname);
      } catch {
        return false;
      }
    });

    return match || null;
  } catch {
    return null;
  }
}

// ── Init ─────────────────────────────────────────────────────────────────────

updateBadge();
