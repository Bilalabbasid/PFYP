// Applies the saved/system colour theme before the page paints (loaded in <head>).
(function () {
  "use strict";
  var saved = null;
  try { saved = localStorage.getItem("pg-theme"); } catch (e) { /* storage blocked */ }
  var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.setAttribute("data-bs-theme", saved || (prefersDark ? "dark" : "light"));
})();
