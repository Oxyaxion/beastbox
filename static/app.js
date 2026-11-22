// Beastbox: native JavaScript, no dependency or build. Everything here is an enhancement: browsing,
// downloading and bulk actions work without JavaScript (classic forms).
// - upload (drag and drop of files and folders, progress, cancel, retry) through /web/dav/ + CSRF token;
// - actions (new folder, rename, delete, move by dragging) with native dialogs;
// - selection (select all, Shift+click), preview panel (P), keyboard gallery, partial refresh;
// - tree and "Move to…" dialog: rendered by the server (<details>, popover), subfolders loaded on opening;
// - public drop (/s/<token>/drop/).
"use strict";
// Moving by drag and drop, without the page (tests/js/dnd.test.mjs runs them with `node --test`). Items: { dav, name },
// `dav` their WebDAV URL; folders as WebDAV URLs ending with "/".
const dnd = (() => {
  const DAV = "/web/dav/";
  const slash = (u) => u.replace(/\/?$/, "/");
  const parent = (url) => url.replace(/\/[^/]+\/?$/, "/");
  // A WebDAV URL as the path the forms take ("" = root): "/web/dav/A/b%20c/" → "A/b c".
  const rel = (url) => decodeURIComponent(url.slice(DAV.length).replace(/\/$/, ""));
  return Object.freeze({
    DAV, slash, parent, rel,
    // Count shown beside the first name while dragging: "" alone, "+9" for ten items.
    more: (items) => (items.length > 1 ? `+${items.length - 1}` : ""),
    // What a row carries: the whole selection if the row is part of it, otherwise the row alone.
    carried: (row, picked) => (picked.includes(row) ? picked : [row]),
    // A tree link (/web/files/…) as an item; null for the root, which never moves.
    treeItem: (href) => {
      const dav = slash(href.replace(/^\/web\/files\//, DAV));
      return dav === DAV ? null : { dav, name: decodeURIComponent(dav.slice(0, -1).split("/").pop()) };
    },
    treeFolder: (href) => slash(href.replace(/^\/web\/files\//, DAV)),
    // A folder that cannot receive the items: one of them, or inside a dragged folder.
    refused: (items, to) => items.some((x) => to.startsWith(slash(x.dav))),
    // The items that actually move: those already in `to` stay.
    moving: (items, to) => items.filter((x) => slash(parent(x.dav)) !== to),
    // Form of the move (POST /web/bulk, the rule of the "Move" dialog: a taken name gives the next free one). The items
    // share a folder: a selection of the listing, or one tree link.
    bulkMove: (items, to, csrf) => {
      const f = (k, v) => `&${k}=${encodeURIComponent(v)}`;
      return `csrf=${encodeURIComponent(csrf)}${f("dir", rel(parent(items[0].dav)))}&op=move${f("dest", rel(to))}` +
        items.map((x) => f("item", x.name)).join("");
    },
    // Spring-loaded folders: a target held for `delay` ms runs `open` once; another target, leaving or the end of the drag
    // cancels it. Timers injected (`setTimeout`, `clearTimeout` in the page).
    spring: (delay, later, cancel) => {
      let at = null, t = null;
      const stop = () => { if (t !== null) cancel(t); at = null; t = null; };
      return Object.freeze({
        over: (target, open) => {
          if (target === at) return;
          stop();
          at = target;
          t = later(() => { at = null; t = null; open(); }, delay);
        },
        leave: (target) => { if (target === at) stop(); },
        stop,
      });
    },
    // New address of the page at `path` once `x` moved into `to`; null if the page is not inside `x`.
    follow: (path, x, to) => {
      const page = path.match(/^(\/web\/(?:files|view)\/)(.*)$/);
      const from = slash(x.dav).slice(DAV.length);
      if (!page || !slash(page[2]).startsWith(from)) return null;
      return page[1] + to.slice(DAV.length) + encodeURIComponent(x.name) + "/" + page[2].slice(from.length);
    },
  });
})();
(function () {
  if (typeof document === "undefined") return; // loaded by the tests: only `dnd` above
  document.documentElement.classList.add("avecjs"); // already set by theme.js before the first paint; kept for pages without it
  const $ = (s, root) => (root || document).querySelector(s);
  const $$ = (s, root) => [...(root || document).querySelectorAll(s)];
  const meta = (n) => { const m = $(`meta[name="${n}"]`); return m ? m.content : null; };
  const csrf = meta("csrf"), dav = meta("dav"), drop = meta("drop");
  const enc = (p) => p.split("/").map(encodeURIComponent).join("/");
  // Messages written by this script follow the language the server put in <html lang>.
  const tr = (en, french) => (document.documentElement.lang.startsWith("fr") ? french : en);

  // ------------------------------------------------------------- dialog (replaces alert/confirm/prompt)
  const dlg = $("[data-dialog]");
  function ask(text, value) {
    return new Promise((done) => {
      if (!dlg || !dlg.showModal) { // old browser: native fallback
        done(value === undefined ? (confirm(text) ? "" : null) : prompt(text, value));
        return;
      }
      const input = $("[data-dialog-input]", dlg);
      $("[data-dialog-text]", dlg).textContent = text;
      input.hidden = value === undefined;
      input.required = value !== undefined;
      input.value = value || "";
      dlg.returnValue = "";
      dlg.onclose = () => done(dlg.returnValue === "oui" ? input.value : null);
      // Enter in the field: the form's default button would be the first one, "Cancel" (it cancelled silently).
      input.onkeydown = (e) => {
        if (e.key !== "Enter" || e.isComposing) return;
        e.preventDefault();
        if (input.reportValidity()) dlg.close("oui");
      };
      dlg.showModal();
      (value === undefined ? $("[data-dialog-ok]", dlg) : input).focus();
    });
  }
  const tell = (text) => {
    const p = document.createElement("p");
    p.className = "alerte"; p.setAttribute("role", "alert"); p.textContent = text;
    const main = $("main");
    main.insertBefore(p, main.firstChild.nextSibling);
    setTimeout(() => p.remove(), 8000);
  };

  function send(method, url, extra) {
    const h = Object.assign({ "X-CSRF-Token": csrf }, extra || {});
    return fetch(url, { method, headers: h, credentials: "same-origin" }).then((r) => {
      if (r.status === 507) throw new Error(tr("not enough space", "espace insuffisant"));
      if (r.status === 412) throw new Error(tr("that name already exists at the destination", "ce nom existe déjà à destination"));
      if (r.status === 409) throw new Error(tr("not possible here", "impossible à cet endroit"));
      if (!r.ok) throw new Error(tr("error ", "erreur ") + r.status);
      return r;
    });
  }
  const fail = (e) => tell(tr("Failed: ", "Échec : ") + e.message);

  // ------------------------------------------------------------- partial refresh
  async function refresh(url) {
    // Also used as `send(…).then(refresh)`: the argument is then the response, not an address.
    if (typeof url !== "string") url = location.href;
    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) { location.assign(url); return; }
    const doc = new DOMParser().parseFromString(await r.text(), "text/html");
    const fresh = $("[data-contenu]", doc), old = $("[data-contenu]");
    if (!fresh || !old) { location.assign(url); return; }
    old.replaceWith(fresh);
    $$("[data-arbre]", doc).forEach((t, i) => { const o = $$("[data-arbre]")[i]; if (o) o.replaceWith(t); });
    // Links that carry the sort order (view switch, pager, page size) follow it.
    [".entete-droite", ".pied"].forEach((s) => { const n = $(s, doc), o = $(s); if (n && o) o.replaceWith(n); });
    wire(); counter();
  }

  // Sorting (column header or the Sort menu, list and grid): only the list is replaced (no flash of the whole page,
  // "Recent activity" stays put).
  document.addEventListener("click", (e) => {
    const a = e.target.closest("thead th a, .menu-tri a");
    if (!a || !$("[data-contenu]") || e.button || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    history.pushState(null, "", a.href);
    refresh(a.href).catch(() => location.assign(a.href));
  });
  window.addEventListener("popstate", () => { if ($("[data-contenu]")) refresh().catch(() => location.reload()); });

  // ------------------------------------------------------------- uploads
  const list = $("[data-uploads]");
  const queue = [];
  let running = 0, done = 0;
  const PARALLEL = 3;
  const target = (rel) => (drop ? drop + encodeURIComponent(rel.split("/").pop()) : dav + enc(rel));

  function enqueue(file, rel) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "nom"; name.textContent = rel;
    const bar = document.createElement("progress");
    bar.max = 1; bar.value = 0;
    const state = document.createElement("span");
    const cancel = document.createElement("button");
    cancel.type = "button"; cancel.textContent = tr("Cancel", "Annuler");
    li.append(name, bar, state, cancel);
    list.append(li);
    const job = { file, rel, bar, state, cancel, xhr: null };
    cancel.onclick = () => {
      if (job.xhr) job.xhr.abort();
      else { queue.splice(queue.indexOf(job), 1); state.textContent = tr("cancelled", "annulé"); cancel.remove(); }
    };
    queue.push(job);
    pump();
  }

  function pump() { while (running < PARALLEL && queue.length) start(queue.shift()); }

  function start(job) {
    running++;
    const xhr = new XMLHttpRequest();
    job.xhr = xhr;
    xhr.open("PUT", target(job.rel));
    if (csrf) xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.setRequestHeader("X-OC-Mtime", String(Math.floor(job.file.lastModified / 1000)));
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) job.bar.value = e.loaded / e.total; };
    const finish = (msg, ok) => {
      running--; job.xhr = null; job.state.textContent = msg; job.cancel.remove();
      if (ok) { done++; setTimeout(() => job.bar.closest("li").remove(), 1500); }
      else if (msg !== tr("cancelled", "annulé")) {
        const retry = document.createElement("button");
        retry.type = "button"; retry.textContent = tr("Retry", "Réessayer");
        retry.onclick = () => {
          retry.remove(); job.state.textContent = ""; job.bar.value = 0;
          job.cancel = document.createElement("button");
          job.cancel.type = "button"; job.cancel.textContent = tr("Cancel", "Annuler");
          job.cancel.onclick = () => job.xhr && job.xhr.abort();
          job.bar.after(job.cancel);
          queue.push(job); pump();
        };
        job.state.after(retry);
      }
      pump();
      if (!running && !queue.length && done && dav) { done = 0; refresh(); }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) { job.bar.value = 1; finish(tr("uploaded", "envoyé"), true); }
      else if (xhr.status === 507) finish(tr("not enough space", "espace insuffisant"), false);
      else if (xhr.status === 413) finish(tr("file too large", "fichier trop gros"), false);
      else finish(tr("error ", "erreur ") + xhr.status, false);
    };
    xhr.onerror = () => finish(tr("network error", "erreur réseau"), false);
    xhr.onabort = () => finish(tr("cancelled", "annulé"), false);
    xhr.send(job.file);
  }

  // Dragged folders: subfolders created (MKCOL; 405 = already exists) before the files are uploaded.
  async function walk(entry, prefix, files, dirs) {
    if (entry.isFile) {
      files.push([await new Promise((ok, ko) => entry.file(ok, ko)), prefix + entry.name]);
    } else if (entry.isDirectory) {
      const path = prefix + entry.name;
      dirs.push(path);
      const reader = entry.createReader();
      for (;;) {
        const batch = await new Promise((ok, ko) => reader.readEntries(ok, ko));
        if (!batch.length) break;
        for (const e of batch) await walk(e, path + "/", files, dirs);
      }
    }
  }

  async function mkdirs(dirs) {
    for (const d of [...new Set(dirs)].sort((a, b) => a.split("/").length - b.split("/").length)) {
      const r = await fetch(dav + enc(d), { method: "MKCOL", headers: { "X-CSRF-Token": csrf }, credentials: "same-origin" });
      if (!r.ok && r.status !== 405) throw new Error(tr("folder creation ", "création du dossier ") + d + " : " + r.status);
    }
  }

  async function accept(pairs, dirs) {
    try {
      if (dav && dirs.length) await mkdirs(dirs);
      for (const [f, rel] of pairs) enqueue(f, rel);
    } catch (e) { fail(e); }
  }

  $$("[data-upload]").forEach((input) => input.addEventListener("change", () => {
    const pairs = [], dirs = [];
    for (const f of input.files) {
      const rel = (!drop && f.webkitRelativePath) || f.name;
      pairs.push([f, rel]);
      const parts = rel.split("/");
      for (let i = 1; i < parts.length; i++) dirs.push(parts.slice(0, i).join("/"));
    }
    input.value = "";
    accept(pairs, dirs);
  }));

  const zone = $("[data-dropzone]");
  if (zone) {
    document.body.addEventListener("dragover", (e) => {
      if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); zone.classList.add("actif"); }
    });
    document.body.addEventListener("dragleave", (e) => { if (!e.relatedTarget) zone.classList.remove("actif"); });
    document.body.addEventListener("drop", async (e) => {
      if (!e.dataTransfer.types.includes("Files")) return;
      e.preventDefault(); zone.classList.remove("actif");
      const files = [], dirs = [];
      const entries = [...e.dataTransfer.items].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
      if (entries.length && !drop) { for (const en of entries) await walk(en, "", files, dirs); }
      else { for (const f of e.dataTransfer.files) files.push([f, f.name]); }
      accept(files, dirs);
    });
  }

  // ------------------------------------------------------------- selection
  const form = $("[data-bulk]");
  const boxes = () => $$('input[name="item"]', form || document);
  function counter() {
    if (!form) return;
    const n = boxes().filter((b) => b.checked).length;
    $("[data-count]", form).textContent = n === 1 ? tr("1 selected", "1 sélectionné") : tr(`${n} selected`, `${n} sélectionnés`);
    $("[data-bulkbar]", form).classList.toggle("active", n > 0);
    const rename = $("[data-renommer-un]", form); // renaming: one item at a time
    if (rename) rename.hidden = n !== 1;
    const all = $("[data-all]", form);
    if (all) { all.checked = n > 0 && n === boxes().length; all.indeterminate = n > 0 && n < boxes().length; }
  }
  let last = null;
  if (form) {
    form.addEventListener("click", (e) => {
      const b = e.target.closest('input[name="item"]');
      if (!b) return;
      if (e.shiftKey && last && last !== b) { // Shift+click: range
        const all = boxes(), [i, j] = [all.indexOf(last), all.indexOf(b)].sort((x, y) => x - y);
        all.slice(i, j + 1).forEach((x) => { x.checked = b.checked; });
      }
      last = b;
    });
    form.addEventListener("change", (e) => {
      if (e.target.matches("[data-all]")) boxes().forEach((b) => { b.checked = e.target.checked; });
      counter();
    });
    form.addEventListener("submit", async (e) => {
      const btn = e.submitter;
      if (!btn || !btn.dataset.confirm || btn.dataset.ok) return;
      e.preventDefault();
      const n = boxes().filter((b) => b.checked).length;
      if (!n) { tell(tr("Tick at least one item.", "Cochez au moins un élément.")); return; }
      if ((await ask(`${btn.dataset.confirm} (` + tr(`${n} item(s), recoverable from the trash`, `${n} élément(s), récupérables dans la corbeille`) + ")")) !== null) {
        btn.dataset.ok = "1"; form.requestSubmit(btn);
      }
    });
    counter();
  }

  // ------------------------------------------------------------- favorite: one click from the listing, no page reload
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-etoile]");
    if (!b) return;
    const row = b.closest("[data-details]");
    // The path is the item's view URL without its prefix.
    const path = decodeURIComponent(row.dataset.details.replace(/^\/web\/view\//, ""));
    const on = b.getAttribute("aria-pressed") !== "true";
    b.disabled = true;
    try {
      const body = new URLSearchParams({ csrf, path, on: on ? "1" : "0" });
      // The server answers 303 towards the item's page: the listing does not need it.
      const r = await fetch("/web/favorite", { method: "POST", body, credentials: "same-origin", redirect: "manual" });
      if (!r.ok && r.type !== "opaqueredirect") throw new Error(tr("error ", "erreur ") + r.status);
      b.setAttribute("aria-pressed", String(on));
      b.textContent = on ? "★" : "☆";
    } catch (err) { fail(err); } finally { b.disabled = false; }
  });

  // ------------------------------------------------------------- copy a link
  // Clipboard API only on HTTPS (secure context); on plain HTTP, the old execCommand. If both fail, the link's bubble
  // opens with the URL selected, to copy by hand.
  function copy(b) {
    const done = () => {
      const t = b.textContent;
      b.textContent = tr("Copied ✓", "Copié ✓");
      setTimeout(() => { b.textContent = t; }, 1600);
    };
    const show = () => { const pop = b.dataset.url && document.getElementById(b.dataset.url); if (pop) pop.showPopover(); };
    const legacy = () => {
      const t = document.createElement("textarea");
      t.value = b.dataset.copy; t.readOnly = true; t.style.position = "fixed"; t.style.opacity = "0";
      document.body.append(t); t.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (_) { /* refused */ }
      t.remove();
      if (ok) done(); else show();
    };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(b.dataset.copy).then(done, legacy);
    else legacy();
  }
  // Link bubble opened: the URL is selected, ready for Ctrl+C.
  document.addEventListener("toggle", (e) => {
    if (e.newState !== "open" || !e.target.matches?.(".bulle-url")) return;
    const i = $("input", e.target); i.focus(); i.select();
  }, true);

  // ------------------------------------------------------------- actions on an item
  const parent = dnd.parent;
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-action],[data-copy],[data-panel-close]");
    if (!b) return;
    if (b.dataset.copy) { copy(b); return; }
    if (b.hasAttribute("data-panel-close")) { closePanel(); return; }
    // From the selection bar ("Rename", one item checked): the checked row.
    const row = b.closest("[data-dav]") || (b.closest("[data-bulkbar]") && $$("[data-dav]").find((x) => $('input[name="item"]:checked', x)));
    const act = b.dataset.action;
    if (act === "mkdir" || act === "mkfile") b.closest("[popover]")?.hidePopover();
    if (act === "mkdir") {
      const n = await ask(tr("Name of the new folder", "Nom du nouveau dossier"), "");
      if (n) send("MKCOL", dav + encodeURIComponent(n)).then(refresh, fail);
    } else if (act === "mkfile") {
      // Created by the server (text name checked, never over an existing item), which then opens the editor.
      let n = await ask(tr("Name of the new text file (.txt, .md, .json…)", "Nom du nouveau fichier texte (.txt, .md, .json…)"), "notes.txt");
      if (!n) return;
      if (!/\.[^./]+$/.test(n)) n += ".txt";
      const f = document.createElement("form");
      f.method = "post";
      f.action = dav.replace(/^\/web\/dav\//, "/web/edit/") + encodeURIComponent(n);
      for (const [k, v] of [["csrf", csrf], ["create", "1"]]) {
        const i = document.createElement("input");
        i.type = "hidden"; i.name = k; i.value = v; f.append(i);
      }
      document.body.append(f);
      f.submit();
    } else if (act === "rename") {
      const n = await ask(tr("New name", "Nouveau nom"), row.dataset.name);
      if (n && n !== row.dataset.name) {
        send("MOVE", row.dataset.dav, { Destination: parent(row.dataset.dav) + encodeURIComponent(n), Overwrite: "F" }).then(refresh, fail);
      }
    } else if (act === "delete") {
      if ((await ask(tr(`Move « ${row.dataset.name} » to the trash?`, `Mettre « ${row.dataset.name} » à la corbeille ?`))) !== null) send("DELETE", row.dataset.dav).then(refresh, fail);
    } else if (act === "move") { // "Move" on a row: the selection becomes this item, then the dialog opens
      boxes().forEach((x) => { x.checked = x.value === row.dataset.name; });
      counter();
    } else if (act === "unselect") {
      boxes().forEach((x) => { x.checked = false; });
      counter();
    } else if (act === "preview") {
      openPanel(row.dataset.details, row);
    }
  });

  // ------------------------------------------------------------- preview panel (the details page, rendered by the server)
  const panel = $("[data-panel]");
  let lastFocus = null, shown = null;
  async function openPanel(url, row) {
    if (!panel) { location.href = url; return; }
    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) { location.href = url; return; }
    shown = row || null;
    $$("[data-dav].apercu").forEach((x) => x.classList.remove("apercu"));
    if (shown) { shown.classList.add("apercu"); shown.scrollIntoView({ block: "nearest" }); }
    const doc = new DOMParser().parseFromString(await r.text(), "text/html");
    const body = $("[data-panel-body]", panel);
    body.replaceChildren(...[$("h1", doc), $(".meta", doc), $("#apercu", doc)].filter(Boolean).map((n) => document.adoptNode(n)));
    $("[data-panel-open]", panel).href = url;
    panel.scrollTop = 0; // a new document starts at its top
    if (panel.hidden) lastFocus = document.activeElement;
    panel.hidden = false;
    $("[data-panel-close]", panel).focus();
  }
  function closePanel() {
    if (!panel || panel.hidden) return;
    panel.hidden = true;
    $("[data-panel-body]", panel).replaceChildren(); // stops video and audio
    if (shown) shown.classList.remove("apercu");
    shown = null;
    if (lastFocus) lastFocus.focus();
  }

  // Panel open: ← → show the previous / next file of the listing; ↑ ↓ scroll the document shown.
  function step(d) {
    const rows = $$("[data-dav]:not([data-dir])");
    const next = rows[rows.indexOf(shown) + d];
    if (next) openPanel(next.dataset.details, next);
  }

  // ------------------------------------------------------------- keyboard: Esc closes the panel; arrows in the panel and the gallery
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closePanel();
    if (e.target.closest("input,textarea,select,[contenteditable],video,audio") || e.altKey || e.ctrlKey || e.metaKey) return;
    // P: preview of the focused, else the first selected, else the first file (empty if it has none); again: close.
    if (e.key === "p" && panel) {
      e.preventDefault();
      if (!panel.hidden) { closePanel(); return; }
      const files = $$("[data-dav]:not([data-dir])");
      const row = files.find((x) => x.contains(document.activeElement)) || files.find((x) => $("input:checked", x)) || files[0];
      if (row) openPanel(row.dataset.details, row);
      return;
    }
    if (shown && panel && !panel.hidden) {
      const d = { ArrowRight: 1, ArrowLeft: -1 }[e.key], v = { ArrowDown: 1, ArrowUp: -1 }[e.key];
      if (d) { e.preventDefault(); step(d); return; }
      if (v) { e.preventDefault(); panel.scrollBy({ top: v * 60 }); return; }
    }
    const link = $(`[data-gallery] [data-key="${e.key}"]`);
    if (link) { e.preventDefault(); location.href = link.href; }
  });

  // ------------------------------------------------------------- forms to confirm (trash): without JavaScript, an "I confirm" box
  document.addEventListener("submit", async (e) => {
    const f = e.target.closest("[data-confirm-form]");
    if (!f || f.dataset.ok) return;
    e.preventDefault();
    if ((await ask(f.dataset.confirmForm)) === null) return;
    const c = f.querySelector('[name="confirm"]');
    if (c) c.checked = true;
    f.dataset.ok = "1"; f.requestSubmit(e.submitter);
  });

  // ------------------------------------------------------------- search as you type (page rendered by the server)
  const box = $("[data-search]");
  if (box) {
    let timer = null, ctrl = null;
    box.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        if (ctrl) ctrl.abort();
        ctrl = new AbortController();
        const url = "/web/search?" + new URLSearchParams(new FormData(box.form));
        try {
          const r = await fetch(url, { credentials: "same-origin", signal: ctrl.signal });
          if (!r.ok) return;
          const fresh = $("[data-resultats]", new DOMParser().parseFromString(await r.text(), "text/html"));
          if (fresh) { $("[data-resultats]").replaceWith(fresh); history.replaceState(null, "", url); }
        } catch (e) { if (e.name !== "AbortError") fail(e); }
      }, 200);
    });
  }

  // ------------------------------------------------------------- tree: a folder loads its subfolders when first opened
  document.addEventListener("toggle", async (e) => {
    const d = e.target;
    if (!(d instanceof HTMLDetailsElement) || !d.open || !d.dataset.src || "loaded" in d.dataset) return;
    d.dataset.loaded = "";
    const r = await fetch(d.dataset.src + (d.closest("[data-pick]") ? "?pick=1" : ""), { credentials: "same-origin" });
    // Nothing to show (empty "Recent activity" box): the element disappears.
    if (r.status === 204) { d.hidden = true; return; }
    if (!r.ok) { delete d.dataset.loaded; fail(new Error(tr("error ", "erreur ") + r.status)); return; }
    const node = new DOMParser().parseFromString(await r.text(), "text/html").body.firstElementChild;
    if (node) d.append(document.adoptNode(node));
    forbid();
  }, true);

  // "Recent activity" box: open or closed, like last time (remembered by this browser). Closed, it
  // loads nothing; it loads when first opened.
  const act = $("[data-activite]");
  if (act) {
    try { if (localStorage.getItem("bb-activite") === "0") act.open = false; } catch (_) { /* storage unavailable */ }
    act.addEventListener("toggle", () => {
      try { if (act.open) localStorage.removeItem("bb-activite"); else localStorage.setItem("bb-activite", "0"); } catch (_) { /* private */ }
    });
  }


  // "Move or copy to…" dialog: a folder goes neither into itself nor into one of its subfolders. The folder the
  // selection is in stays offered: chosen, it only offers "Duplicate" (app.css, `data-ici`).
  const mover = $("#deplacer");
  const here = form ? form.elements.dir.value : "";
  function forbid() {
    if (!mover) return;
    const moving = boxes().filter((b) => b.checked).map((b) => (here ? here + "/" : "") + b.value);
    $$('input[name="dest"]', mover).forEach((r) => {
      const p = r.value.slice(1);
      r.disabled = moving.some((m) => p === m || p.startsWith(m + "/"));
      if (r.disabled) r.checked = false;
    });
    const chosen = !!$('input[name="dest"]:checked', mover);
    $$("[data-move]", mover).forEach((b) => { b.disabled = !chosen; });
  }
  if (mover) mover.addEventListener("change", forbid);
  if (mover) mover.addEventListener("toggle", (e) => {
    if (e.newState !== "open") return;
    const n = boxes().filter((b) => b.checked).length;
    if (!n) { mover.hidePopover(); tell(tr("Tick at least one item to move or copy.", "Cochez au moins un élément à déplacer ou copier.")); return; }
    $("[data-move-count]", mover).textContent = n === 1 ? tr("1 selected item", "1 élément sélectionné") : tr(`${n} selected items`, `${n} éléments sélectionnés`);
    forbid();
  });

  // ------------------------------------------------------------- page size: applied as soon as it is chosen
  // Delegated: the footer is replaced when sorting.
  document.addEventListener("change", (e) => { const f = e.target.closest("[data-par-page]"); if (f) f.submit(); });

  // ------------------------------------------------------------- theme (Account page): see theme.js
  const themes = $("select[data-themes]");
  if (themes) {
    // No theme set: Blanc, the default.
    themes.value = document.documentElement.dataset.theme || "blanc";
    if (!themes.value) themes.value = "blanc";
    const modes = $("[data-modes]");
    const fixe = $("[data-mode-fixe]");
    // Graphite and Blanc have a fixed mode: the mode choice is greyed out.
    const sync = () => {
      const f = themes.value === "graphite" || themes.value === "blanc";
      modes.disabled = f;
      fixe.hidden = !f;
    };
    const cur = document.documentElement.dataset.mode || "clair";
    const box = $(`input[value="${cur}"]`, modes);
    if (box) box.checked = true;
    sync();
    themes.addEventListener("change", () => {
      const t = themes.value;
      if (t === "blanc") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
      try { if (t === "blanc") localStorage.removeItem("bb-theme"); else localStorage.setItem("bb-theme", t); } catch (_) { /* private */ }
      sync();
    });
    // Text size: same as the mode (an attribute on <html>, remembered by this browser).
    const sizes = $("[data-tailles]");
    if (sizes) {
      const box2 = $(`input[value="${document.documentElement.dataset.taille || "normal"}"]`, sizes);
      if (box2) box2.checked = true;
      sizes.addEventListener("change", (e) => {
        const z = e.target.value;
        if (z === "normal") delete document.documentElement.dataset.taille; else document.documentElement.dataset.taille = z;
        try { if (z === "normal") localStorage.removeItem("bb-taille"); else localStorage.setItem("bb-taille", z); } catch (_) { /* private */ }
      });
    }
    modes.addEventListener("change", (e) => {
      const m = e.target.value;
      if (m === "clair") delete document.documentElement.dataset.mode; else document.documentElement.dataset.mode = m;
      try { if (m === "clair") localStorage.removeItem("bb-mode"); else localStorage.setItem("bb-mode", m); } catch (_) { /* private */ }
    });
  }

  // ------------------------------------------------------------- move: drag items onto a folder (listing or tree)
  // Rules in `dnd` (top of this file); here only the page: what is dragged, the targets, the refresh.
  let dragged = [];
  const refused = (to) => dnd.refused(dragged, to);
  // The server moves (same rule and message as the "Move" dialog), then the page shows its message: the address it
  // answers carries what happened (`?op=move&ok=…&to=…&name=…`).
  async function moveTo(to) {
    const items = dnd.moving(dragged, to);
    dragged = [];
    if (!items.length) return;
    let r;
    try {
      r = await fetch("/web/bulk", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: dnd.bulkMove(items, to, csrf),
      });
    } catch (e) { fail(e); return; }
    if (!r.ok) { fail(new Error(tr("error ", "erreur ") + r.status)); return; }
    const done = new URL(r.url, location.href).searchParams;
    // The page shows a moved folder or something inside it: follow it to its new place (and its new name).
    if (done.get("ok") === "1") {
      const x = { ...items[0], name: done.get("name") || items[0].name };
      const next = items.length === 1 && dnd.follow(location.pathname, x, to);
      if (next) { location.assign(next); return; }
    }
    // A folder's page: its message (with the links); elsewhere, the tree is enough.
    if ($("[data-contenu]")) location.assign(location.pathname + "?" + done.toString());
    else location.reload();
  }
  // Drag image: a small label beside the pointer instead of the row (which hid the target); several items: a stack.
  const grab = (e, items) => {
    dragged = items;
    e.dataTransfer.effectAllowed = "move";
    // A link's own data (its URL) dropped: otherwise Chrome takes it for a link to open, beside the page (split view)
    // when the pointer nears the window's edge, where the tree is.
    e.dataTransfer.clearData();
    e.dataTransfer.setData("text/plain", items.map((x) => x.name).join("\n"));
    const box = document.createElement("div"), tag = document.createElement("span"), name = document.createElement("span");
    box.className = items.length > 1 ? "glisse pile" : "glisse";
    name.className = "nom"; name.textContent = items[0].name;
    tag.append(name);
    if (items.length > 1) { const n = document.createElement("b"); n.textContent = dnd.more(items); tag.append(n); }
    box.append(tag);
    document.body.append(box);
    e.dataTransfer.setDragImage(box, 0, 0); // the box's transparent top-left margin keeps the label off the pointer
    setTimeout(() => box.remove()); // the browser has taken its picture
  };
  function dropOn(el, to) {
    el.addEventListener("dragover", (e) => { if (dragged.length && !refused(to())) { e.preventDefault(); el.classList.add("cible"); } });
    el.addEventListener("dragleave", () => el.classList.remove("cible"));
    el.addEventListener("drop", (e) => {
      el.classList.remove("cible");
      if (!dragged.length || refused(to())) return;
      e.preventDefault(); e.stopPropagation();
      moveTo(to());
    });
  }
  function wire() {
    $$("[data-dav]").forEach((el) => {
      el.addEventListener("dragstart", (e) => {
        const picked = $$("[data-dav]").filter((x) => $('input[name="item"]:checked', x));
        grab(e, dnd.carried(el, picked).map((x) => ({ dav: x.dataset.dav, name: x.dataset.name })));
      });
      el.addEventListener("dragend", () => { dragged = []; });
      if (el.hasAttribute("data-dir")) dropOn(el, () => dnd.slash(el.dataset.dav));
    });
  }
  wire();
  // Tree on the left: its folders are links to /web/files/…, loaded as they open (hence on the document, not per link).
  // Each one is a target, and every one but the root can be dragged itself.
  const treeLink = (e) => e.target.closest?.('.cote a.dossier[href^="/web/files/"]');
  const folderOf = (a) => dnd.treeFolder(a.getAttribute("href"));
  document.addEventListener("dragstart", (e) => {
    const a = treeLink(e), it = a && dnd.treeItem(a.getAttribute("href"));
    if (it) grab(e, [it]);
  });
  // A closed folder of the tree held under the dragged items opens (its subfolders load, `toggle` above).
  const spring = dnd.spring(700, setTimeout, clearTimeout);
  document.addEventListener("dragend", (e) => { spring.stop(); if (treeLink(e)) dragged = []; });
  document.addEventListener("dragover", (e) => {
    const a = treeLink(e);
    if (a && dragged.length && !refused(folderOf(a))) {
      e.preventDefault(); a.classList.add("cible");
      const d = a.closest("details");
      if (d && !d.open) spring.over(a, () => { d.open = true; });
    }
  });
  document.addEventListener("dragleave", (e) => { const a = treeLink(e); if (a) { a.classList.remove("cible"); spring.leave(a); } });
  document.addEventListener("drop", (e) => {
    spring.stop();
    const a = treeLink(e);
    if (!a) return;
    a.classList.remove("cible");
    if (!dragged.length || refused(folderOf(a))) return;
    e.preventDefault(); e.stopPropagation();
    moveTo(folderOf(a));
  }, true);
})();
