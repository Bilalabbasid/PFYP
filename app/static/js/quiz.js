// "Spot the Phish" awareness quiz. All messages and links are illustrative examples.
(function () {
  "use strict";
  var root = document.getElementById("quiz");
  if (!root) return;

  var CHANNELS = {
    sms: { icon: "phone", label: "SMS" },
    email: { icon: "envelope", label: "Email" },
    whatsapp: { icon: "whatsapp", label: "WhatsApp" },
    social: { icon: "people", label: "Social media" },
    web: { icon: "globe", label: "Web search / browsing" }
  };

  var POOL = [
    // ---- phishing --------------------------------------------------------
    { ch: "sms", from: "+92 3xx xxxxxxx", text: "DHL: Your parcel could not be delivered due to an unpaid fee of Rs. 150. Pay within 24h or it will be returned:",
      url: "http://dhl-parcel-redelivery.top/pay", answer: "phish",
      why: "DHL's real domain is dhl.com. This one joins words with hyphens, uses the cheap '.top' ending, has no HTTPS and pushes you with a 24-hour deadline." },
    { ch: "email", from: "Google Security <no-reply@google-alerts.info>", text: "Unusual sign-in detected on your account. Verify your identity now to avoid suspension.",
      url: "https://accounts.google.com.security-check-login.info/verify", answer: "phish",
      why: "Read the host from the right: the real domain is security-check-login.info. 'accounts.google.com' is only a subdomain the attacker chose." },
    { ch: "social", from: "Pop-up advert", text: "Congratulations! You won a free iPhone 16. Claim within 10 minutes!",
      url: "http://192.168.45.12/apple/claim-prize.php", answer: "phish",
      why: "A raw IP address instead of a domain name, a 'prize', and a countdown timer are classic phishing signs." },
    { ch: "email", from: "PayPal <service@paypa1-support.com>", text: "Your account has been limited. Please sign in to restore full access.",
      url: "https://www.paypa1.com/signin", answer: "phish",
      why: "Look closely: 'paypa1' uses the number 1 instead of the letter l. This is typosquatting." },
    { ch: "whatsapp", from: "Unknown number", text: "OMG see who viewed your profile today 👀 login here:",
      url: "https://www.facebook.com@fb-viewers.xyz/login", answer: "phish",
      why: "Browsers ignore everything before '@' in an address — this actually opens fb-viewers.xyz." },
    { ch: "sms", from: "EasyPaisa-Info", text: "Dear customer, you have received a Rs. 25,000 reward. Complete KYC to claim:",
      url: "https://easypaisa-reward-claim.xyz/kyc", answer: "phish",
      why: "EasyPaisa's official domain is easypaisa.com.pk. Rewards that need 'KYC' via a .xyz link are a common local scam." },
    { ch: "email", from: "Microsoft 365 <admin@m365-mail.net>", text: "Your mailbox is full. Re-validate your account to keep receiving email.",
      url: "https://microsoft365-login.web.app/outlook/verify", answer: "phish",
      why: "web.app is a free hosting platform anyone can use. Microsoft sign-in happens on microsoft.com / microsoftonline.com." },
    { ch: "email", from: "Netflix <billing@netflix-billing-update.com>", text: "We couldn't process your last payment. Update your card details to avoid interruption.",
      url: "https://netflix-billing-update.com/payment", answer: "phish",
      why: "Netflix only uses netflix.com. A brand name glued to 'billing-update' on a different domain is impersonation." },
    { ch: "sms", from: "AMZN", text: "Your order #4471 is on hold. Track and confirm your address:",
      url: "https://arnazon-orders.com/track", answer: "phish",
      why: "'arnazon' uses 'rn' to look like 'm' at a glance. The real site is amazon.com." },
    { ch: "sms", from: "HBL-Alert", text: "Your HBL account is blocked. Share the OTP on this page to unblock:",
      url: "https://hbl-account-verify.tk/otp", answer: "phish",
      why: "Banks never ask for your OTP. The '.tk' ending is free and heavily abused; HBL's domain is hbl.com." },
    // ---- legitimate ------------------------------------------------------
    { ch: "email", from: "HBL <alerts@hbl.com>", text: "Your new credit card statement is ready. You can view card offers on our website.",
      url: "https://www.hbl.com/personal/cards", answer: "legit",
      why: "The registered domain is exactly hbl.com, the bank's official site, over HTTPS — and nothing asks for secrets." },
    { ch: "whatsapp", from: "Classmate (saved contact)", text: "Here's the Flask repo we'll use for the FYP backend:",
      url: "https://github.com/pallets/flask", answer: "legit",
      why: "github.com is the genuine domain and the path points to a well-known public project." },
    { ch: "web", from: "Search result", text: "Official Python tutorial",
      url: "https://docs.python.org/3/tutorial/", answer: "legit",
      why: "python.org is the official domain; 'docs' is a normal subdomain that belongs to it." },
    { ch: "web", from: "Gmail sign-in page", text: "You clicked 'Sign in' on gmail.com and were taken to:",
      url: "https://accounts.google.com/signin", answer: "legit",
      why: "Here the real domain is google.com (read from the right). This is Google's genuine sign-in page." },
    { ch: "email", from: "Amazon <shipment-tracking@amazon.com>", text: "Your package has shipped. View your orders:",
      url: "https://www.amazon.com/gp/your-account/order-history", answer: "legit",
      why: "The domain is exactly amazon.com and the link goes to the normal order-history page." },
    { ch: "web", from: "University notice board", text: "Admissions for Fall are open — details on the official site:",
      url: "https://nust.edu.pk/admissions/", answer: "legit",
      why: "'.edu.pk' addresses can only be registered by verified Pakistani education institutions." },
    { ch: "email", from: "Daraz <no-reply@daraz.pk>", text: "Thanks for your order! Track it in your account:",
      url: "https://www.daraz.pk/customer/order/index/", answer: "legit",
      why: "daraz.pk is the official domain and the link only leads to your orders — no urgency, no requests for secrets." },
    { ch: "web", from: "Office 365 sign-in", text: "You opened outlook.office.com and were redirected to:",
      url: "https://login.microsoftonline.com/", answer: "legit",
      why: "microsoftonline.com is Microsoft's real sign-in domain used by Office 365." }
  ];

  var ROUND = 8;
  var $ = function (id) { return document.getElementById(id); };
  var questions = [], i = 0, score = 0, answered = false, answers = [];

  function shuffle(a) {
    for (var k = a.length - 1; k > 0; k--) { var j = Math.floor(Math.random() * (k + 1)); var t = a[k]; a[k] = a[j]; a[j] = t; }
    return a;
  }
  function newRound() {
    var phish = shuffle(POOL.filter(function (q) { return q.answer === "phish"; })).slice(0, ROUND / 2);
    var legit = shuffle(POOL.filter(function (q) { return q.answer === "legit"; })).slice(0, ROUND / 2);
    questions = shuffle(phish.concat(legit));
    i = 0; score = 0; answers = [];
    $("quiz-score").textContent = "0";
    $("quiz-total").textContent = ROUND;
    var dots = $("quiz-dots"); dots.innerHTML = "";
    for (var k = 0; k < ROUND; k++) { var d = document.createElement("span"); d.className = "pg-dot"; dots.appendChild(d); }
    $("quiz-done").classList.add("d-none");
    $("quiz-question").classList.remove("d-none");
    render();
  }

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

  function render() {
    var q = questions[i], ch = CHANNELS[q.ch];
    answered = false;
    $("quiz-progress").textContent = "Question " + (i + 1) + " of " + ROUND;
    var dots = $("quiz-dots").children;
    for (var k = 0; k < dots.length; k++) dots[k].classList.toggle("current", k === i);
    $("quiz-channel-icon").innerHTML = '<i class="bi bi-' + ch.icon + '"></i>';
    $("quiz-sender").textContent = q.from;
    $("quiz-channel").textContent = ch.label;
    $("quiz-text").textContent = q.text;
    $("quiz-url").textContent = q.url;
    $("quiz-feedback").classList.add("d-none");
    $("quiz-answers").classList.remove("d-none");
    root.querySelectorAll("[data-answer]").forEach(function (b) { b.disabled = false; });
    $("quiz-next").innerHTML = i + 1 < ROUND ? 'Next question <i class="bi bi-arrow-right"></i>' : 'See my results <i class="bi bi-flag"></i>';
  }

  // Splits a URL into coloured parts and highlights the real (registered) domain.
  function renderAnatomy(url, anatomy) {
    var box = $("quiz-anatomy"); box.innerHTML = "";
    var schemeEnd = url.indexOf("://") + 3;
    var rest = url.slice(schemeEnd);
    var hostEnd = rest.search(/[\/?#]/); if (hostEnd < 0) hostEnd = rest.length;
    var hostPart = rest.slice(0, hostEnd), path = rest.slice(hostEnd);
    box.appendChild(el("span", "pg-an-scheme", url.slice(0, schemeEnd)));
    var at = hostPart.lastIndexOf("@");
    if (at >= 0) { box.appendChild(el("span", "pg-an-trick", hostPart.slice(0, at + 1))); hostPart = hostPart.slice(at + 1); }
    var reg = anatomy && anatomy.registered_domain ? anatomy.registered_domain : "";
    var idx = reg ? hostPart.toLowerCase().lastIndexOf(reg) : -1;
    if (idx > 0) box.appendChild(el("span", "pg-an-sub", hostPart.slice(0, idx)));
    box.appendChild(el("span", "pg-an-domain", idx >= 0 ? hostPart.slice(idx) : hostPart));
    if (path) box.appendChild(el("span", "pg-an-path", path));
    var note = $("quiz-anatomy-note");
    note.textContent = reg ? "Real owner of this link: " + reg + (at >= 0 ? " — the part before '@' is ignored by the browser." : "") : "";
  }

  function renderEngine(data) {
    var box = $("quiz-engine"); box.innerHTML = "";
    var head = el("div", "d-flex align-items-center gap-2 mb-2");
    head.appendChild(el("span", "small fw-semibold", "PhishGuard's analysis:"));
    head.appendChild(el("span", "pg-badge pg-badge-" + data.css_class, data.classification));
    head.appendChild(el("span", "small text-body-secondary ms-auto", "risk " + data.score + "/100"));
    box.appendChild(head);
    if (data.reasons.length) {
      var ul = el("ul", "small mb-0 ps-3");
      data.reasons.slice(0, 3).forEach(function (r) { ul.appendChild(el("li", "", r.title)); });
      box.appendChild(ul);
    } else {
      box.appendChild(el("div", "small text-body-secondary", data.good_signs[0] || "No risk indicators found."));
    }
  }

  function answer(choice) {
    if (answered) return;
    answered = true;
    var q = questions[i], ok = choice === q.answer;
    if (ok) score++;
    answers.push({ q: q, ok: ok, choice: choice });
    $("quiz-score").textContent = score;
    $("quiz-dots").children[i].classList.add(ok ? "ok" : "bad");
    root.querySelectorAll("[data-answer]").forEach(function (b) { b.disabled = true; });
    $("quiz-answers").classList.add("d-none");

    var box = $("quiz-feedback-box");
    box.className = "pg-feedback " + (ok ? "pg-feedback-ok" : "pg-feedback-bad");
    $("quiz-feedback-title").innerHTML = '<i class="bi bi-' + (ok ? "check-circle-fill" : "x-circle-fill") + '"></i>';
    $("quiz-feedback-title").appendChild(document.createTextNode(
      (ok ? " Correct — " : " Not quite — ") + "this link is " + (q.answer === "phish" ? "phishing." : "legitimate.")));
    $("quiz-feedback-why").textContent = q.why;
    $("quiz-feedback").classList.remove("d-none");
    renderAnatomy(q.url, null);
    $("quiz-engine").innerHTML = '<div class="small text-body-secondary"><span class="spinner-border spinner-border-sm me-1"></span> PhishGuard is analysing the link…</div>';
    $("quiz-next").focus();

    fetch(root.dataset.analyzeUrl, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: q.url })
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (questions[i] !== q || data.error) return;
      renderAnatomy(q.url, data.anatomy);
      renderEngine(data);
    }).catch(function () {
      $("quiz-engine").innerHTML = "";
      $("quiz-engine").appendChild(el("div", "small text-body-secondary", "PhishGuard's analysis is unavailable right now."));
    });
  }

  function finish() {
    $("quiz-question").classList.add("d-none");
    $("quiz-done").classList.remove("d-none");
    $("quiz-final").textContent = score;
    $("quiz-final-total").textContent = ROUND;
    var pct = Math.round(score / ROUND * 100);
    var tone = pct >= 85 ? "safe" : pct >= 60 ? "suspicious" : "phishing";
    $("quiz-final-gauge").className = "pg-gauge mb-3 pg-gauge-" + tone;
    $("quiz-final-ring").setAttribute("stroke-dasharray", Math.max(pct, 0.5) + ", 100");
    $("quiz-final-gauge").setAttribute("aria-label", score + " of " + ROUND + " correct");
    $("quiz-verdict-title").textContent = pct >= 85 ? "Excellent — sharp eye!" : pct >= 60 ? "Good effort" : "Phishing can be tricky";
    $("quiz-verdict").textContent = pct >= 85 ? "You spotted almost every trick. Keep checking the real domain before you click."
      : pct >= 60 ? "Review the ones you missed below — the explanations show what to look for."
      : "Read the guide on identifying suspicious URLs, then try a new round.";
    var list = $("quiz-review"); list.innerHTML = "";
    answers.forEach(function (a) {
      var li = el("li", "list-group-item d-flex gap-3 align-items-start");
      var ic = el("i", "bi bi-" + (a.ok ? "check-circle-fill text-success" : "x-circle-fill text-danger") + " mt-1");
      var body = el("div", "flex-grow-1 min-w-0");
      body.style.minWidth = "0";
      body.appendChild(el("div", "font-monospace small text-break", a.q.url));
      body.appendChild(el("div", "small text-body-secondary", (a.q.answer === "phish" ? "Phishing" : "Legitimate") + " — " + a.q.why));
      li.appendChild(ic); li.appendChild(body);
      list.appendChild(li);
    });
    $("quiz-restart").focus();
  }

  function next() {
    if (!answered) return;
    i++;
    if (i < ROUND) render(); else finish();
  }

  root.querySelectorAll("[data-answer]").forEach(function (b) {
    b.addEventListener("click", function () { answer(b.dataset.answer); });
  });
  $("quiz-next").addEventListener("click", next);
  $("quiz-restart").addEventListener("click", newRound);
  document.addEventListener("keydown", function (e) {
    if (e.target.matches("input, textarea") || e.ctrlKey || e.metaKey || e.altKey) return;
    if ($("quiz-question").classList.contains("d-none")) return;
    var k = e.key.toLowerCase();
    if (k === "l" && !answered) answer("legit");
    else if (k === "p" && !answered) answer("phish");
  });
  newRound();
})();
