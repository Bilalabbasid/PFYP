// Shared UI behaviour. No inline scripts are used, so the Content-Security-Policy stays strict.
(function () {
  "use strict";
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var hasBS = typeof window.bootstrap !== "undefined";

  /* ------------------------------------------------------------ toasts */
  var ICONS = { success: "check-circle-fill", danger: "x-circle-fill", warning: "exclamation-triangle-fill", info: "info-circle-fill" };
  var TITLES = { success: "Done", danger: "Something needs attention", warning: "Heads up", info: "Notice" };

  function showToast(el) {
    var delay = el.classList.contains("pg-toast-danger") ? 8000 : 5000;
    var bar = $(".pg-toast-bar", el);
    if (bar) bar.style.animationDuration = delay + "ms";
    if (hasBS) {
      var t = new bootstrap.Toast(el, { delay: delay, autohide: true });
      // Bootstrap pauses auto-hide while the pointer is over the toast
      el.addEventListener("hidden.bs.toast", function () { el.remove(); });
      t.show();
    } else {
      el.classList.add("show");
    }
  }

  // Public helper: window.pgToast("Copied!", "success")
  window.pgToast = function (message, type, title) {
    type = ICONS[type] ? type : "info";
    var el = document.createElement("div");
    el.className = "toast pg-toast pg-toast-" + type;
    el.setAttribute("role", type === "danger" ? "alert" : "status");
    el.innerHTML =
      '<div class="toast-body"><span class="pg-toast-icon"><i class="bi bi-' + ICONS[type] + '"></i></span>' +
      '<div class="flex-grow-1"><div class="pg-toast-title"></div><div class="pg-toast-msg"></div></div>' +
      '<button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button></div>' +
      '<div class="pg-toast-bar"></div>';
    $(".pg-toast-title", el).textContent = title || TITLES[type];
    $(".pg-toast-msg", el).textContent = message;   // textContent: never interpreted as HTML
    $("#toasts").appendChild(el);
    showToast(el);
  };
  $$("[data-pg-flash]").forEach(showToast);

  /* ------------------------------------------------------------- theme */
  var themeBtn = $("#theme-toggle");
  function syncThemeIcon() {
    var dark = document.documentElement.getAttribute("data-bs-theme") === "dark";
    if (themeBtn) themeBtn.innerHTML = '<i class="bi bi-' + (dark ? "sun" : "moon-stars") + '"></i>';
  }
  if (themeBtn) {
    syncThemeIcon();
    themeBtn.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-bs-theme", next);
      try { localStorage.setItem("pg-theme", next); } catch (e) { /* ignore */ }
      syncThemeIcon();
      document.dispatchEvent(new CustomEvent("pg-theme-change"));
    });
  }

  /* ------------------------------------------------- confirm dialogs */
  var modalEl = $("#confirm-modal");
  var pendingForm = null;
  if (modalEl && hasBS) {
    var modal = new bootstrap.Modal(modalEl);
    $("#confirm-ok").addEventListener("click", function () {
      if (pendingForm) { var f = pendingForm; pendingForm = null; modal.hide(); f.submit(); }
    });
    $$("form[data-confirm]").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        e.preventDefault();
        pendingForm = f;
        $("#confirm-message").textContent = f.dataset.confirm;
        $("#confirm-ok").textContent = f.dataset.confirmLabel || "Delete";
        modal.show();
      });
    });
  } else {
    $$("form[data-confirm]").forEach(function (f) {
      f.addEventListener("submit", function (e) { if (!window.confirm(f.dataset.confirm)) e.preventDefault(); });
    });
  }

  /* --------------------------------------------------------- scan box */
  var scanForm = $("#scan-form");
  if (scanForm) {
    var input = $("input[name='url']", scanForm);
    var box = $(".pg-scanbox", scanForm);
    $$(".pg-example").forEach(function (btn) {
      btn.addEventListener("click", function () { input.value = btn.dataset.url; input.focus(); box.classList.remove("is-invalid"); });
    });
    var paste = $("#paste-btn");
    if (paste) {
      if (!navigator.clipboard || !navigator.clipboard.readText) { paste.classList.add("d-none"); }
      paste.addEventListener("click", function () {
        navigator.clipboard.readText().then(function (text) {
          input.value = (text || "").trim(); input.focus(); box.classList.remove("is-invalid");
        }).catch(function () { pgToast("Your browser blocked clipboard access. Paste with Ctrl+V instead.", "warning"); });
      });
    }
    input.addEventListener("input", function () { box.classList.remove("is-invalid"); });
    scanForm.addEventListener("submit", function (e) {
      if (!input.value.trim()) {
        e.preventDefault();
        box.classList.add("is-invalid");
        pgToast("Paste or type a link to analyse.", "warning", "No link entered");
        input.focus();
        return;
      }
      var btn = $("#scan-btn");
      if (btn) {
        btn.disabled = true;
        $(".spinner-border", btn).classList.remove("d-none");
        $(".btn-label", btn).textContent = "Analysing…";
      }
    });
  }

  /* ------------------------------------------------- copy to clipboard */
  $$("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.dataset.copy;
      var done = function () { pgToast(btn.dataset.copyMsg || "Copied to clipboard.", "success", "Copied"); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { pgToast("Could not copy automatically.", "warning"); });
      } else {
        var ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta);
        ta.select(); try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ } ta.remove();
      }
    });
  });

  /* ------------------------------------------- password show / strength */
  $$("input[type='password']").forEach(function (pw) {
    var wrap = document.createElement("div");
    wrap.className = "pg-pw-wrap";
    pw.parentNode.insertBefore(wrap, pw);
    wrap.appendChild(pw);
    // keep validation messages visible after the input
    var fb = wrap.nextElementSibling;
    if (fb && fb.classList.contains("invalid-feedback") && pw.classList.contains("is-invalid")) fb.style.display = "block";
    var btn = document.createElement("button");
    btn.type = "button"; btn.className = "pg-pw-toggle"; btn.setAttribute("aria-label", "Show password");
    btn.innerHTML = '<i class="bi bi-eye"></i>';
    btn.addEventListener("click", function () {
      var show = pw.type === "password";
      pw.type = show ? "text" : "password";
      btn.innerHTML = '<i class="bi bi-eye' + (show ? "-slash" : "") + '"></i>';
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
    wrap.appendChild(btn);
  });

  var meter = $("#pw-strength");
  if (meter) {
    var target = $("#" + meter.dataset.for);
    var bar = $("span", meter), label = $("#pw-strength-label");
    var LEVELS = [["Too weak", "#dc2626", 15], ["Weak", "#f97316", 35], ["Fair", "#f59e0b", 60], ["Good", "#22c55e", 80], ["Strong", "#16a34a", 100]];
    target.addEventListener("input", function () {
      var v = target.value, s = 0;
      if (v.length >= 8) s++;
      if (v.length >= 12) s++;
      if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
      if (/\d/.test(v)) s++;
      if (/[^A-Za-z0-9]/.test(v)) s++;
      if (!(/[A-Za-z]/.test(v) && /\d/.test(v)) || v.length < 8) s = Math.min(s, 1);
      var lvl = LEVELS[Math.min(s, 4)];
      bar.style.width = v ? lvl[2] + "%" : "0";
      bar.style.background = lvl[1];
      label.textContent = v ? lvl[0] : "At least 8 characters with letters and numbers.";
    });
  }
})();
