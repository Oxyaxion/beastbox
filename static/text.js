// Text files (pages that show or edit one): syntax colouring of JSON, shell and Markdown.
// - Reading: `pre[data-lang]` and the code blocks of a rendered Markdown (`code.language-…`).
// - Editing: a <pre> behind a transparent <textarea>, which stays the real field; Ctrl+S; warning before leaving with
//   unsaved changes; Markdown preview rendered by the server.
// Without this script the pages work, without colours. The text is only ever put in text nodes.
"use strict";
(() => {
  // [class, regex] by language. Earlier rules win; capturing groups inside a rule must be named or non-capturing.
  // Linear on any text (a file may come from a guest's drop link): a rule that scans either always matches (an
  // unterminated string runs to the end of the line or text) or scans a bounded length, so a failed attempt never
  // rescans the rest of the text from every position.
  const RULES = {
    json: [
      ["c-cle", /"(?:[^"\\\n]|\\.){0,1024}"(?=[ \t]{0,64}:)/],
      ["c-str", /"(?:[^"\\\n]|\\.){0,1024}"?/],
      ["c-num", /-?\b\d{1,64}(?:\.\d{1,64})?(?:[eE][+-]?\d{1,8})?\b/],
      ["c-mot", /\b(?:true|false|null)\b/],
    ],
    sh: [
      ["c-com", /(?<=^|[\s;])#.*/],
      ["c-str", /'[^']{0,4096}'?|"(?:[^"\\]|\\[\s\S]){0,4096}"?/],
      ["c-var", /\$(?:\{[^}\n]{0,256}\}?|[A-Za-z_]\w{0,64}|[0-9@#?$!*-])/],
      ["c-mot", /\b(?:if|then|else|elif|fi|for|while|until|do|done|case|esac|in|function|return|local|export|readonly|exit|break|continue|set|shift)\b/],
    ],
    md: [
      ["c-code", /^(?<fence>`{3,16}|~{3,16})[^\n]*\n[\s\S]*?(?:^\k<fence>[ \t]*$|(?![\s\S]))/],
      ["c-titre", /^#{1,6}[ \t].*/],
      ["c-cit", /^>.*/],
      ["c-liste", /^[ \t]{0,16}(?:[-*+]|\d{1,9}[.)])(?=[ \t])/],
      ["c-code", /`[^`\n]{1,512}`/],
      ["c-lien", /!?\[[^\]\n]{0,64}\]\([^)\n]{0,256}\)/],
      ["c-gras", /\*\*[^*\n]{1,256}\*\*|(?<!\w)__[^_\n]{1,256}__(?!\w)/],
      ["c-ital", /\*[^*\n]{1,256}\*|(?<!\w)_[^_\n]{1,256}_(?!\w)/],
    ],
  };

  // Code block names of Markdown (```sh) → language.
  const ALIASES = { json: "json", sh: "sh", bash: "sh", shell: "sh", zsh: "sh", console: "sh", md: "md", markdown: "md" };
  const MAX = 512 * 1024;
  const compiled = {};
  const span = (cls, text) => { const s = document.createElement("span"); s.className = cls; s.textContent = text; return s; };
  // Text cut into text nodes and coloured spans; `null` if the language is unknown or the text too large.
  const colour = (text, lang) => {
    // Own keys only (a code block named `constructor` or `__proto__` is not a language).
    const rules = Object.hasOwn(RULES, lang) ? RULES[lang] : null;
    if (!rules || text.length > MAX) return null;
    const re = compiled[lang] ||= new RegExp(rules.map(([, r], i) => `(?<r${i}>${r.source})`).join("|"), "gm");
    const out = [];
    let at = 0, m;
    re.lastIndex = 0;
    while ((m = re.exec(text))) {
      if (m[0] === "") { re.lastIndex++; continue; }
      const i = rules.findIndex((_, k) => m.groups[`r${k}`] !== undefined);
      if (m.index > at) out.push(text.slice(at, m.index));
      out.push(span(rules[i][0], m[0]));
      at = m.index + m[0].length;
    }
    out.push(text.slice(at));
    return out;
  };

  // Reading.
  for (const pre of document.querySelectorAll("pre[data-lang]")) {
    const nodes = colour(pre.textContent, pre.dataset.lang);
    if (nodes) pre.replaceChildren(...nodes);
  }
  for (const code of document.querySelectorAll(".md pre > code[class^='language-']")) {
    const name = code.className.slice(9).toLowerCase();
    const nodes = colour(code.textContent, Object.hasOwn(ALIASES, name) ? ALIASES[name] : "");
    if (nodes) code.replaceChildren(...nodes);
  }

  // Copy the file (the server's bytes: Markdown source, line ends kept). The ClipboardItem is created inside the click
  // with a pending blob, so the browser keeps the permission while the file loads.
  for (const b of document.querySelectorAll("button[data-copier]")) {
    const state = b.querySelector("[role=status]");
    b.addEventListener("click", async () => {
      const get = () => fetch(b.dataset.copier, { credentials: "same-origin" })
        .then((r) => { if (!r.ok) throw new Error(r.status); return r.text(); });
      let ok = true;
      try {
        if (window.ClipboardItem && navigator.clipboard?.write) {
          const blob = get().then((t) => new Blob([t], { type: "text/plain" }));
          await navigator.clipboard.write([new ClipboardItem({ "text/plain": blob })]);
        } else {
          await navigator.clipboard.writeText(await get());
        }
      } catch (_) { ok = false; }
      b.classList.add(ok ? "fait" : "rate");
      state.textContent = ok ? b.dataset.ok : b.dataset.ko;
      setTimeout(() => { b.classList.remove("fait", "rate"); state.textContent = ""; }, 1600);
    });
  }

  // Editing.
  const form = document.querySelector("[data-editeur]");
  const ta = form && form.querySelector("textarea");
  if (!ta) return;
  // The layer is always built (the language can change with the name); without rules it shows the plain field.
  let paint = () => {};
  {
    const box = document.createElement("div");
    box.className = "calque";
    const pre = document.createElement("pre");
    pre.setAttribute("aria-hidden", "true");
    ta.before(box);
    box.append(pre, ta);
    paint = () => {
      const nodes = colour(ta.value, ta.dataset.lang);
      // Very large text: no colouring (the plain field stays usable).
      box.classList.toggle("sans-couleur", !nodes);
      if (!nodes) { pre.textContent = ""; return; }
      // A final newline needs one more line in the <pre> to keep both heights equal.
      nodes.push("\n");
      pre.replaceChildren(...nodes);
      pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft;
    };
    let queued = false;
    ta.addEventListener("input", () => { if (!queued) { queued = true; requestAnimationFrame(() => { queued = false; paint(); }); } });
    ta.addEventListener("scroll", () => { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; });
    paint();
  }

  // The name being typed: icon and colouring follow its extension (map sent by the server; unknown → plain file).
  const nameField = form.querySelector("input[data-types]");
  const icon = form.querySelector("[data-icone-nom]");
  if (nameField && icon) {
    let types = {};
    try { types = JSON.parse(nameField.dataset.types); } catch (_) { /* no map: nothing follows */ }
    nameField.addEventListener("input", () => {
      const ext = (nameField.value.match(/\.([^./]+)$/) || [])[1]?.toLowerCase() || "";
      const [ico, lang] = Object.hasOwn(types, ext) ? types[ext] : ["file", ""];
      icon.src = `/static/icons/${ico}.svg`;
      if (ta.dataset.lang !== lang) { ta.dataset.lang = lang; paint(); }
    });
  }

  // Unsaved changes: warning before leaving, cleared by a submit.
  const initial = ta.value;
  let sending = false;
  window.addEventListener("beforeunload", (e) => { if (!sending && ta.value !== initial) e.preventDefault(); });
  form.addEventListener("submit", (e) => { if (e.submitter?.name !== "apercu") sending = true; });
  // Back to an editor left untouched: the details page instead (history would otherwise reopen the editor).
  window.addEventListener("pageshow", (e) => {
    const back = e.persisted || performance.getEntriesByType("navigation")[0]?.type === "back_forward";
    if (back && ta.value === initial && form.dataset.vue) location.replace(form.dataset.vue);
  });

  // Ctrl+S (⌘S): save.
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "s") {
      e.preventDefault();
      sending = true;
      form.requestSubmit(form.querySelector("[data-enregistrer]"));
    }
  });

  // Markdown preview: the server renders the text (same sanitizing as the details page); only the preview area changes.
  const btn = form.querySelector("button[name=apercu]");
  if (btn) {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      // Shown: the button hides it.
      if (form.classList.contains("avec-apercu")) {
        form.querySelector("[data-apercu]").hidden = true;
        form.classList.remove("avec-apercu");
        btn.setAttribute("aria-pressed", "false");
        return;
      }
      const body = new URLSearchParams(new FormData(form, btn));
      try {
        const r = await fetch(form.action, { method: "POST", body, credentials: "same-origin" });
        if (!r.ok) throw new Error(r.status);
        const fresh = new DOMParser().parseFromString(await r.text(), "text/html").querySelector("[data-apercu]");
        const here = form.querySelector("[data-apercu]");
        if (fresh && here) {
          here.replaceWith(document.adoptNode(fresh));
          form.classList.add("avec-apercu");
          btn.setAttribute("aria-pressed", "true");
        }
      } catch (_) { sending = true; form.requestSubmit(btn); }
    });
  }
})();
