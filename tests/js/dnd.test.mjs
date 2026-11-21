// Rules of moving by drag and drop (`dnd` at the top of static/app.js), run on the real file without a browser:
// `node --test tests/js/`. Optional in scripts/check.sh (skipped when node is absent).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const src = readFileSync(new URL("../../static/app.js", import.meta.url), "utf8");
// No `document` here: app.js only defines `dnd`, the page part returns at once.
const dnd = vm.runInNewContext(`${src}\n;dnd`, {});
// Values made in the other context: compared by contents.
const plain = (v) => JSON.parse(JSON.stringify(v));
const A = { dav: "/web/dav/A", name: "A" };

test("only dnd, frozen, and nothing touches a page", () => {
  assert.ok(Object.isFrozen(dnd));
  assert.equal(dnd.DAV, "/web/dav/");
});

test("slash and parent", () => {
  assert.equal(dnd.slash("/web/dav/A"), "/web/dav/A/");
  assert.equal(dnd.slash("/web/dav/A/"), "/web/dav/A/");
  assert.equal(dnd.parent("/web/dav/A/f.txt"), "/web/dav/A/");
  assert.equal(dnd.parent("/web/dav/A/B/"), "/web/dav/A/");
  assert.equal(dnd.parent("/web/dav/f.txt"), "/web/dav/");
});

test("a checked row carries the selection, an unchecked one goes alone", () => {
  const [r1, r2, r3] = [{}, {}, {}];
  assert.deepEqual([...dnd.carried(r1, [r1, r2])], [r1, r2]);
  assert.deepEqual([...dnd.carried(r3, [r1, r2])], [r3]);
  assert.deepEqual([...dnd.carried(r1, [])], [r1]);
  assert.deepEqual([...dnd.carried(r1, [r1])], [r1]);
});

test("count beside the dragged name", () => {
  assert.equal(dnd.more([]), "");
  assert.equal(dnd.more([A]), "");
  assert.equal(dnd.more([A, A]), "+1");
  assert.equal(dnd.more(Array(10).fill(A)), "+9");
});

test("tree links: the root never moves, names decoded", () => {
  assert.equal(dnd.treeItem("/web/files/"), null);
  assert.deepEqual(plain(dnd.treeItem("/web/files/A/")), { dav: "/web/dav/A/", name: "A" });
  assert.deepEqual(plain(dnd.treeItem("/web/files/Mes%20docs/caf%C3%A9/")), {
    dav: "/web/dav/Mes%20docs/caf%C3%A9/",
    name: "café",
  });
  assert.equal(dnd.treeFolder("/web/files/"), "/web/dav/");
  assert.equal(dnd.treeFolder("/web/files/A/"), "/web/dav/A/");
});

test("a folder never receives itself nor goes into its own subfolders", () => {
  assert.equal(dnd.refused([A], "/web/dav/A/"), true);
  assert.equal(dnd.refused([A], "/web/dav/A/B/"), true);
  // A sibling whose name starts the same is not inside.
  assert.equal(dnd.refused([A], "/web/dav/AB/"), false);
  assert.equal(dnd.refused([A], "/web/dav/"), false);
  assert.equal(dnd.refused([{ dav: "/web/dav/B/", name: "B" }, A], "/web/dav/A/x/"), true);
  assert.equal(dnd.refused([], "/web/dav/A/"), false);
});

test("items already in the target stay", () => {
  const f = { dav: "/web/dav/A/f.txt", name: "f.txt" };
  const g = { dav: "/web/dav/g.txt", name: "g.txt" };
  assert.deepEqual(plain(dnd.moving([f, g], "/web/dav/A/")), [g]);
  assert.deepEqual(plain(dnd.moving([f, g], "/web/dav/")), [f]);
  assert.deepEqual(plain(dnd.moving([f, g], "/web/dav/C/")), [f, g]);
  assert.deepEqual(plain(dnd.moving([A], "/web/dav/")), []);
});

test("a page inside a moved folder follows it", () => {
  assert.equal(dnd.follow("/web/files/A/", A, "/web/dav/C/"), "/web/files/C/A/");
  assert.equal(dnd.follow("/web/files/A/B/", A, "/web/dav/C/"), "/web/files/C/A/B/");
  assert.equal(dnd.follow("/web/view/A/f.txt", { dav: "/web/dav/A/", name: "A" }, "/web/dav/C/"), "/web/view/C/A/f.txt");
  const docs = { dav: "/web/dav/Mes%20docs/", name: "Mes docs" };
  assert.equal(dnd.follow("/web/files/Mes%20docs/x/", docs, "/web/dav/C/"), "/web/files/C/Mes%20docs/x/");
  // Not inside: nothing to follow.
  assert.equal(dnd.follow("/web/files/AB/", A, "/web/dav/C/"), null);
  assert.equal(dnd.follow("/web/files/", A, "/web/dav/C/"), null);
  assert.equal(dnd.follow("/web/shares", A, "/web/dav/C/"), null);
});
