// Plures Vault — Popup UI Controller

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let currentCredentials = [];
let currentCredential = null;
let passwordVisible = false;

// ── Screens ──────────────────────────────────────────────────────────────────

function showScreen(id) {
  $$(".screen").forEach((s) => s.classList.add("hidden"));
  $(id).classList.remove("hidden");
}

// ── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  const status = await sendMessage({ type: "get_status" });

  if (status.unlocked) {
    showScreen("#main-screen");
    loadCredentials();
  } else {
    showScreen("#lock-screen");
    $("#master-password").focus();
  }
}

// ── Messaging ────────────────────────────────────────────────────────────────

function sendMessage(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, resolve);
  });
}

// ── Lock/Unlock ──────────────────────────────────────────────────────────────

$("#unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const password = $("#master-password").value;
  if (!password) return;

  const result = await sendMessage({ type: "unlock", password });

  // Wait a beat for native response
  setTimeout(async () => {
    const status = await sendMessage({ type: "get_status" });
    if (status.unlocked) {
      $("#master-password").value = "";
      showScreen("#main-screen");
      loadCredentials();
    } else {
      $("#unlock-error").textContent = "Invalid master password";
      $("#unlock-error").classList.remove("hidden");
      $("#master-password").select();
    }
  }, 500);
});

$("#btn-lock").addEventListener("click", async () => {
  await sendMessage({ type: "lock" });
  currentCredentials = [];
  currentCredential = null;
  showScreen("#lock-screen");
  $("#master-password").focus();
});

// ── Credentials List ─────────────────────────────────────────────────────────

async function loadCredentials() {
  const result = await sendMessage({ type: "list_credentials" });
  currentCredentials = result.credentials || [];
  renderCredentials(currentCredentials);
}

function renderCredentials(credentials) {
  const list = $("#credentials-list");
  const empty = $("#empty-state");

  if (credentials.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");

  list.innerHTML = credentials
    .map(
      (c) => `
    <div class="credential-item" data-id="${c.id}">
      <div class="credential-icon">${getFavicon(c)}</div>
      <div class="credential-info">
        <div class="credential-title">${escapeHtml(c.title)}</div>
        <div class="credential-username">${escapeHtml(c.username || "")}</div>
      </div>
    </div>
  `
    )
    .join("");

  // Click handlers
  list.querySelectorAll(".credential-item").forEach((item) => {
    item.addEventListener("click", () => {
      const id = item.dataset.id;
      showCredentialDetail(id);
    });
  });
}

function getFavicon(credential) {
  if (!credential.url) return "🔑";
  try {
    const host = new URL(credential.url).hostname;
    // Common site emojis
    if (host.includes("github")) return "🐙";
    if (host.includes("google")) return "🔍";
    if (host.includes("microsoft") || host.includes("azure")) return "🪟";
    if (host.includes("slack")) return "💬";
    if (host.includes("twitter") || host.includes("x.com")) return "🐦";
    return "🌐";
  } catch {
    return "🔑";
  }
}

// ── Search ───────────────────────────────────────────────────────────────────

$("#search").addEventListener("input", (e) => {
  const query = e.target.value.toLowerCase();
  if (!query) {
    renderCredentials(currentCredentials);
    return;
  }

  const filtered = currentCredentials.filter(
    (c) =>
      c.title.toLowerCase().includes(query) ||
      (c.username && c.username.toLowerCase().includes(query)) ||
      (c.url && c.url.toLowerCase().includes(query))
  );
  renderCredentials(filtered);
});

// ── Detail View ──────────────────────────────────────────────────────────────

function showCredentialDetail(id) {
  const cred = currentCredentials.find((c) => c.id === id);
  if (!cred) return;

  currentCredential = cred;
  passwordVisible = false;

  $("#detail-title").textContent = cred.title;
  $("#detail-username").textContent = cred.username || "(none)";
  $("#detail-password").textContent = "••••••••";
  $("#detail-password").classList.add("masked");

  if (cred.url) {
    $("#detail-url").href = cred.url;
    $("#detail-url").textContent = cred.url;
    $("#detail-url-group").classList.remove("hidden");
  } else {
    $("#detail-url-group").classList.add("hidden");
  }

  if (cred.notes) {
    $("#detail-notes").textContent = cred.notes;
    $("#detail-notes-group").classList.remove("hidden");
  } else {
    $("#detail-notes-group").classList.add("hidden");
  }

  showScreen("#detail-screen");

  // Request full credential (with decrypted password)
  sendMessage({ type: "get_credential", id });
}

// Listen for full credential data from background
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "credential_detail" && msg.data) {
    if (currentCredential && currentCredential.id === msg.data.id) {
      currentCredential = msg.data;
    }
  }
});

$("#btn-back").addEventListener("click", () => {
  showScreen("#main-screen");
  currentCredential = null;
});

$("#btn-toggle-pw").addEventListener("click", () => {
  passwordVisible = !passwordVisible;
  const el = $("#detail-password");
  if (passwordVisible && currentCredential?.password) {
    el.textContent = currentCredential.password;
    el.classList.remove("masked");
  } else {
    el.textContent = "••••••••";
    el.classList.add("masked");
  }
});

// ── Autofill ─────────────────────────────────────────────────────────────────

$("#btn-autofill").addEventListener("click", async () => {
  if (!currentCredential) return;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    chrome.tabs.sendMessage(tab.id, {
      type: "autofill",
      username: currentCredential.username,
      password: currentCredential.password,
    });
    window.close();
  }
});

// ── Copy ─────────────────────────────────────────────────────────────────────

$$(".btn-copy").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const targetId = btn.dataset.copy;
    const el = $(`#${targetId}`);
    if (!el) return;

    let text = el.textContent;
    // For password, copy actual value not dots
    if (targetId === "detail-password" && currentCredential?.password) {
      text = currentCredential.password;
    }

    await navigator.clipboard.writeText(text);
    const orig = btn.textContent;
    btn.textContent = "✓";
    setTimeout(() => (btn.textContent = orig), 1500);
  });
});

// ── Add Credential ───────────────────────────────────────────────────────────

function showAddScreen() {
  $("#edit-title").textContent = "New Credential";
  $("#edit-form").reset();
  // Pre-fill URL from active tab
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (tab?.url) {
      $("#edit-url").value = tab.url;
      try {
        const host = new URL(tab.url).hostname;
        $("#edit-cred-title").value = host.replace("www.", "");
      } catch {}
    }
  });
  showScreen("#edit-screen");
}

$("#btn-add").addEventListener("click", showAddScreen);
$("#btn-add-first").addEventListener("click", showAddScreen);
$("#btn-edit-back").addEventListener("click", () => showScreen("#main-screen"));

$("#edit-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  await sendMessage({
    type: "save_credential",
    title: $("#edit-cred-title").value,
    username: $("#edit-username").value,
    password: $("#edit-password").value,
    url: $("#edit-url").value || null,
    notes: $("#edit-notes").value || null,
  });

  showScreen("#main-screen");
  setTimeout(loadCredentials, 500);
});

// ── Password Generator ───────────────────────────────────────────────────────

$("#btn-generate").addEventListener("click", () => {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=";
  const length = 20;
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  const password = Array.from(array, (b) => charset[b % charset.length]).join("");
  $("#edit-password").value = password;
  $("#edit-password").type = "text";
  setTimeout(() => ($("#edit-password").type = "password"), 3000);
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ── Start ────────────────────────────────────────────────────────────────────

init();
