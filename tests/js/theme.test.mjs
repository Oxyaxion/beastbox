// static/theme.js, run as the browser runs it (before the first paint) on a fake page and storage: what it sets on
// <html> for each stored value. `node --test tests/js/`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const src = readFileSync(new URL("../../static/theme.js", import.meta.url), "utf8");

// Runs theme.js with `stored` in localStorage (or a storage that throws, as in a private window); returns <html>'s state.
function run(stored, { blocked = false } = {}) {
  const store = new Map(Object.entries(stored));
  const classes = new Set();
  const html = { dataset: {}, classList: { add: (c) => classes.add(c) } };
  const localStorage = {
    getItem: (k) => { if (blocked) throw new Error("blocked"); return store.has(k) ? store.get(k) : null; },
    setItem: (k, v) => { if (blocked) throw new Error("blocked"); store.set(k, String(v)); },
  };
  vm.runInNewContext(src, { document: { documentElement: html }, localStorage });
  return { classes: [...classes], theme: html.dataset.theme, mode: html.dataset.mode, size: html.dataset.taille, store };
}

test("script mode is set first, even when storage is refused", () => {
  assert.deepEqual(run({}).classes, ["avecjs"]);
  const r = run({ "bb-theme": "nord" }, { blocked: true });
  assert.deepEqual(r.classes, ["avecjs"]);
  assert.equal(r.theme, undefined);
});

test("no theme stored: no data-theme (the stylesheet's default, White)", () => {
  const r = run({});
  assert.equal(r.theme, undefined);
  assert.equal(r.mode, undefined);
  assert.equal(r.size, undefined);
});

test("a stored theme is applied; Green is a choice like the others; old names renamed", () => {
  assert.equal(run({ "bb-theme": "vert" }).theme, "vert");
  assert.equal(run({ "bb-theme": "gruvbox" }).theme, "gruvbox");
  const r = run({ "bb-theme": "noir" });
  assert.equal(r.theme, "graphite");
  assert.equal(r.store.get("bb-theme"), "graphite");
});

test("a hostile stored value is never put on the page", () => {
  for (const v of ['nord" onload="x', "a b", "<script>", "", "Nord"]) {
    assert.equal(run({ "bb-theme": v }).theme, undefined, v);
  }
});

test("mode and text size: only the known values", () => {
  assert.equal(run({ "bb-mode": "sombre" }).mode, "sombre");
  assert.equal(run({ "bb-mode": "systeme" }).mode, "systeme");
  assert.equal(run({ "bb-mode": "clair" }).mode, undefined);
  assert.equal(run({ "bb-taille": "grand" }).size, "grand");
  assert.equal(run({ "bb-taille": "tres-grand" }).size, "tres-grand");
  for (const v of ["normal", "enorme", "grand ", "<b>"]) {
    assert.equal(run({ "bb-taille": v }).size, undefined, v);
  }
});
