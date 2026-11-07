// Combines the URL verdict with the user's answers about how the link arrived.
(function () {
  "use strict";
  var root = document.getElementById("context-check");
  if (!root) return;
  var verdict = root.dataset.verdict; // safe | suspicious | phishing
  var WEIGHTS = { expected: 2, urgent: 2, secrets: 3, prize: 2, verified: 1 };
  var FLAGS = {
    expected: "You weren't expecting this message.",
    urgent: "It uses urgency or threats — a classic pressure tactic.",
    secrets: "It asks for secrets. Legitimate organisations never ask for passwords or OTP codes by message.",
    prize: "It offers something too good to be true.",
    verified: "You can't confirm who really sent it."
  };
  var qs = Array.prototype.slice.call(root.querySelectorAll(".pg-ctx-q"));
  var $ = function (id) { return document.getElementById(id); };

  function evaluate() {
    var answered = 0, score = 0, flags = [];
    qs.forEach(function (q) {
      var checked = q.querySelector("input:checked");
      if (!checked) return;
      answered++;
      var key = q.dataset.key, v = checked.value;
      if (v === q.dataset.risky) { score += WEIGHTS[key]; flags.push(FLAGS[key]); }
      else if (v === "unsure") { score += WEIGHTS[key] / 2; }
    });
    $("ctx-progress").textContent = answered + " of " + qs.length + " answered";
    $("ctx-reset").classList.toggle("d-none", answered === 0);
    if (answered < qs.length) { $("ctx-result").classList.add("d-none"); return; }

    var tone, icon, title, text;
    if (verdict === "phishing") {
      tone = "bad"; icon = "x-octagon-fill"; title = "Treat this as phishing";
      text = flags.length ? "Both the link and the message show phishing signs. Do not interact — report and delete it."
                          : "Even though the message seemed normal to you, the link itself has strong phishing indicators. Do not open it.";
    } else if (verdict === "suspicious") {
      if (score >= 3) { tone = "bad"; icon = "x-octagon-fill"; title = "Very likely a phishing attempt"; text = "A suspicious link combined with these message warning signs is a strong phishing pattern. Do not open it."; }
      else { tone = "warn"; icon = "exclamation-triangle-fill"; title = "Stay cautious"; text = "The message itself looks low-risk, but the link has warning signs. Open the official website yourself instead of using this link."; }
    } else {
      if (score >= 5) { tone = "warn"; icon = "exclamation-triangle-fill"; title = "The link looks clean — the message doesn't"; text = "Attackers also use hacked legitimate sites, or send a clean link and then call or message you for codes. Verify the sender before doing anything."; }
      else if (score >= 2) { tone = "info"; icon = "info-circle-fill"; title = "Probably fine, with some caution"; text = "No strong warning signs in the link. Keep the points below in mind before sharing any information."; }
      else { tone = "ok"; icon = "shield-fill-check"; title = "No red flags found"; text = "Neither the link nor the message shows common phishing signs. Still check the address bar before entering personal details."; }
    }
    var box = $("ctx-result");
    box.className = "pg-feedback mt-3 pg-feedback-" + tone;
    $("ctx-result-title").innerHTML = '<i class="bi bi-' + icon + '"></i>';
    $("ctx-result-title").appendChild(document.createTextNode(" " + title));
    $("ctx-result-text").textContent = text;
    var ul = $("ctx-result-flags"); ul.innerHTML = "";
    flags.forEach(function (f) { var li = document.createElement("li"); li.textContent = f; ul.appendChild(li); });
    box.classList.remove("d-none");
  }

  root.addEventListener("change", evaluate);
  $("ctx-reset").addEventListener("click", function () {
    root.querySelectorAll("input:checked").forEach(function (i) { i.checked = false; });
    evaluate();
  });
})();
