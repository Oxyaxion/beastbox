// Beastbox: interface theme chosen in "Account" (browser local storage). Loaded without `defer` in
// <head> to set `data-theme` before the first render (no flash of the old theme). Without it: white (always light),
// the default.
"use strict";
// JavaScript is on: set here, before the first paint. Set only by the deferred app.js, the page first showed its
// no-script layout (the selection bar in the page) and the bar flashed away at every page change.
document.documentElement.classList.add("avecjs");
try {
  // Old themes renamed (bleu → nord, prune → catppuccin, noir → graphite).
  const old = { bleu: "nord", prune: "catppuccin", noir: "graphite" };
  let t = localStorage.getItem("bb-theme");
  if (t && old[t]) localStorage.setItem("bb-theme", (t = old[t]));
  if (t && /^[a-z]+$/.test(t)) document.documentElement.dataset.theme = t;
  // Mode: light by default; "sombre" or "systeme" remembered.
  const m = localStorage.getItem("bb-mode");
  if (m === "sombre" || m === "systeme") document.documentElement.dataset.mode = m;
  // Text size: normal by default; "grand" or "tres-grand" remembered.
  const z = localStorage.getItem("bb-taille");
  if (z === "grand" || z === "tres-grand") document.documentElement.dataset.taille = z;
} catch (e) { /* storage unavailable: default theme */ }
