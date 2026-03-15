// Plures Vault — Content Script
// Handles autofill injection and login form detection

(() => {
  // ── Autofill ─────────────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "autofill") {
      fillCredentials(msg.username, msg.password);
    }
  });

  function fillCredentials(username, password) {
    const forms = findLoginForms();

    for (const form of forms) {
      if (form.usernameField && username) {
        setInputValue(form.usernameField, username);
      }
      if (form.passwordField && password) {
        setInputValue(form.passwordField, password);
      }
    }

    if (forms.length === 0) {
      // Try standalone fields (no form)
      const pwFields = document.querySelectorAll('input[type="password"]');
      for (const pw of pwFields) {
        setInputValue(pw, password);
        // Look for username sibling
        const usernameField = findUsernameNear(pw);
        if (usernameField && username) {
          setInputValue(usernameField, username);
        }
      }
    }
  }

  function setInputValue(input, value) {
    // Use native setter to trigger React/Vue/Angular change detection
    const nativeSetter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value"
    )?.set;

    if (nativeSetter) {
      nativeSetter.call(input, value);
    } else {
      input.value = value;
    }

    // Dispatch events to notify frameworks
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
  }

  // ── Form Detection ───────────────────────────────────────────────────────

  function findLoginForms() {
    const results = [];
    const forms = document.querySelectorAll("form");

    for (const form of forms) {
      const passwordField = form.querySelector('input[type="password"]');
      if (!passwordField) continue;

      const usernameField = findUsernameInForm(form);

      results.push({
        form,
        usernameField,
        passwordField,
      });
    }

    return results;
  }

  function findUsernameInForm(form) {
    // Priority: explicit username/email inputs
    const selectors = [
      'input[type="email"]',
      'input[name="username"]',
      'input[name="user"]',
      'input[name="login"]',
      'input[name="email"]',
      'input[autocomplete="username"]',
      'input[autocomplete="email"]',
      'input[type="text"]',
    ];

    for (const sel of selectors) {
      const field = form.querySelector(sel);
      if (field && isVisible(field)) return field;
    }

    return null;
  }

  function findUsernameNear(passwordField) {
    // Walk backwards through siblings and parent to find text/email input
    let el = passwordField;
    for (let i = 0; i < 10; i++) {
      el = el.previousElementSibling || el.parentElement;
      if (!el) break;

      const input = el.matches?.("input") ? el : el.querySelector?.('input[type="text"], input[type="email"]');
      if (input && isVisible(input) && input !== passwordField) {
        return input;
      }
    }
    return null;
  }

  function isVisible(el) {
    return el.offsetParent !== null && !el.hidden && el.type !== "hidden";
  }

  // ── Login Form Detection (for save prompt) ───────────────────────────────

  function detectFormSubmission() {
    document.addEventListener("submit", (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;

      const pwField = form.querySelector('input[type="password"]');
      if (!pwField || !pwField.value) return;

      const usernameField = findUsernameInForm(form);
      const username = usernameField?.value || "";
      const password = pwField.value;

      // Notify background to offer save
      chrome.runtime.sendMessage({
        type: "form_submitted",
        url: window.location.href,
        title: document.title,
        username,
        password,
      });
    });
  }

  detectFormSubmission();
})();
