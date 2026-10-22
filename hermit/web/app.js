// Mantha Hermit local web app. No framework, no build step.
// Rule names and rule text come from the internet: everything is inserted as text (h()), never as HTML.

const TOKEN = document.querySelector('meta[name="hermit-token"]').content;
const $ = (id) => document.getElementById(id);

const state = {
  status: null,
  packs: [],
  held: {},            // pack id -> held proposal (also for packs that don't exist yet)
  chats: [],
  chatId: null,
  chat: null,
  pack: null,          // pack detail
  packId: null,
  rule: null,          // { key, text, ... }
  groupBy: "family",
  filter: "",
  job: null,           // live job view
  jobLog: [],
  openFamilies: new Set(),
};

// ------------------------------------------------------------------ helpers

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(`/api/${path}`, {
    method,
    headers: { "X-Hermit-Token": TOKEN, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false || v === "") continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k === "style") el.style.cssText = v;  // CSSOM, allowed by the page's CSP (style attributes are not)
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const SVG_NS = "http://www.w3.org/2000/svg";
function icon(name, size = 14) {
  const paths = {
    chat: "M5 5h14v10H9l-4 4z",
    pack: "M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12v9M12 12 4 7.5",
    check: "M5 12.5l4.5 4.5L19 7.5",
    warn: "M12 4 2.5 20h19zM12 10v4.5M12 17.4v.1",
    chev: "M9 6l6 6-6 6",
    down: "M6 9l6 6 6-6",
    copy: "M9 9h10v10H9zM5 15V5h10",
    close: "M6 6l12 12M18 6 6 18",
    expand: "M4 10V4h6M20 14v6h-6M4 4l6 6M20 20l-6-6",
    file: "M7 3h7l4 4v14H7zM14 3v4h4",
    link: "M14 5h5v5M19 5l-8 8M17 13v6H5V7h6",
    branch: "M7 4v16M7 8a4 4 0 0 0 4 4h2a4 4 0 0 1 4 4v4M17 4v.1",
    hold: "M12 7v5l3 2M12 3a9 9 0 1 0 .1 0z",
  };
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", size); svg.setAttribute("height", size);
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor"); svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round"); svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(SVG_NS, "path");
  p.setAttribute("d", paths[name] || "");
  svg.append(p);
  return svg;
}

const plural = (n, w, pl) => `${n} ${n === 1 ? w : (pl || w + "s")}`;
const fmtNum = (n) => Number(n || 0).toLocaleString();

function timeLabel(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const today = new Date();
  const y = new Date(); y.setDate(today.getDate() - 1);
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  if (d.toDateString() === today.toDateString()) return hm;
  if (d.toDateString() === y.toDateString()) return `Yesterday ${hm}`;
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}
function dayGroup(iso) {
  const d = new Date(iso), t = new Date(), y = new Date(); y.setDate(t.getDate() - 1);
  if (d.toDateString() === t.toDateString()) return "Today";
  if (d.toDateString() === y.toDateString()) return "Yesterday";
  return "Earlier";
}
function relTime(iso) {
  if (!iso) return "";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

let toastTimer;
function toast(msg, err = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = err ? "toast err" : "toast";
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, err ? 7000 : 4000);
}

function openDialog(title, body, buttons = []) {
  const dlg = $("dialog");
  $("dlg-title").textContent = title;
  $("dlg-body").replaceChildren(...[].concat(body));
  const foot = $("dlg-foot");
  foot.replaceChildren(...buttons);
  foot.hidden = buttons.length === 0;
  if (!dlg.open) dlg.showModal();
}
const closeDialog = () => $("dialog").close();

function confirmDialog(title, text, actionLabel, danger = false) {
  return new Promise((resolve) => {
    const done = (v) => { closeDialog(); resolve(v); };
    openDialog(title, h("p", { text }), [
      h("button", { class: "btn", type: "button", onclick: () => done(false) }, "Cancel"),
      h("button", { class: danger ? "btn btn-danger" : "btn btn-primary", type: "button", onclick: () => done(true) }, actionLabel),
    ]);
    $("dialog").addEventListener("close", () => resolve(false), { once: true });
  });
}

// ------------------------------------------------------------------ loading

async function loadStatus() {
  try {
    state.status = await api("status");
  } catch (e) {
    state.status = null;
    toast(e.message, true);
  }
  renderStatus();
}
async function loadPacks() {
  const r = await api("packs");
  state.packs = r.packs;
  state.held = r.held || {};
  renderPackList();
}
async function loadChats() {
  state.chats = (await api("chats")).chats;
  renderChatList();
}
async function loadChat(id) {
  state.chatId = id;
  state.chat = id ? await api(`chats/${id}`) : null;
  renderChatList();
  renderThread();
}
async function loadPack(id, { keepRule = false } = {}) {
  state.packId = id;
  if (!keepRule) state.rule = null;
  if (!id) { state.pack = null; renderPackPanel(); return; }
  if (!state.packs.some((p) => p.id === id)) {  // a new pack waiting for approval
    state.pack = null; renderPackList(); renderPackPanel(); return;
  }
  try {
    state.pack = await api(`packs/${id}`);
  } catch (e) {
    state.pack = null;
    toast(e.message, true);
  }
  renderPackList();
  renderPackPanel();
}

// ------------------------------------------------------------------ status, sidebar

function renderStatus() {
  const s = state.status;
  const ok = s && s.ollama_ok;
  $("conn-dot").className = ok ? "dot on" : "dot warn";
  $("local-dot").className = ok ? "dot on" : "dot warn";
  $("conn-text").textContent = !s ? "Hermit isn't responding"
    : !s.llm_enabled ? "Model turned off"
    : ok ? "Ollama connected" : "Ollama offline: rules-only mode";
  $("endpoint").textContent = s ? s.endpoint.replace(/^https?:\/\//, "") : "";
  const sel = $("model-select");
  const models = s && s.models.length ? s.models : (s ? [s.model] : []);
  sel.replaceChildren(...models.map((m) => h("option", { value: m, selected: s && m === s.model }, m)));
  sel.disabled = !ok;
  const useModel = $("opt-model");
  useModel.disabled = !ok;
  if (!ok) useModel.checked = false;
  const sources = s ? s.sources : [];
  $("chat-sub").textContent = sources.length
    ? `Rules from ${sources.map((x) => x.name).join(", ")}`
    : "No rule sources yet. Turn on “Fetch sources first” for your first request.";
  if (!sources.length) $("opt-fetch").checked = true;
}

function renderChatList() {
  const q = $("chat-search").value.trim().toLowerCase();
  const list = $("chat-list");
  const chats = state.chats.filter((c) => !q || c.title.toLowerCase().includes(q));
  if (!chats.length) {
    list.replaceChildren(h("p", { class: "side-group", text: q ? "No chats match." : "Your requests will appear here." }));
    return;
  }
  const out = [];
  let group = null;
  for (const c of chats) {
    const g = dayGroup(c.updated || c.created);
    if (g !== group) { out.push(h("div", { class: "side-group", text: g })); group = g; }
    out.push(h("button", {
      class: "item", type: "button", "aria-current": c.id === state.chatId ? "true" : "false",
      onclick: () => { closeDrawers(); loadChat(c.id); },
    }, icon("chat", 15), h("span", {},
      h("span", { class: "t", text: c.title }),
      h("span", { class: "s" }, h("span", { class: "mono", text: timeLabel(c.updated || c.created) }),
        `  ${plural(Math.ceil(c.messages / 2), "request")}`))));
  }
  list.replaceChildren(...out);
}

function pendingPacks() {
  return Object.entries(state.held).filter(([id]) => !state.packs.some((p) => p.id === id));
}

function renderPackList() {
  $("pack-count").textContent = state.packs.length ? String(state.packs.length) : "";
  const list = $("pack-list");
  const pending = pendingPacks().map(([id, hd]) => h("button", {
    class: "item", type: "button", "aria-current": id === state.packId ? "true" : "false",
    onclick: () => { closeDrawers(); loadPack(id); openPackDrawer(); },
  }, icon("hold", 15), h("span", {},
    h("span", { class: "t", text: id }),
    h("span", { class: "s" }, `new pack, ${plural(hd.changes || 0, "rule")} `,
      h("span", { class: "flag", text: "needs OK" })))));
  if (!state.packs.length && !pending.length) {
    list.replaceChildren(h("p", { class: "side-group", text: "No packs yet. Ask for one, for example “add new core threats”." }));
    return;
  }
  list.replaceChildren(...pending, ...state.packs.map((p) => h("button", {
    class: "item", type: "button", "aria-current": p.id === state.packId ? "true" : "false",
    onclick: () => { closeDrawers(); loadPack(p.id); openPackDrawer(); },
  }, icon("pack", 15), h("span", {},
    h("span", { class: "t", text: p.id }),
    h("span", { class: "s" }, `${fmtNum(p.rules)} rules  v${p.version}`,
      p.held ? h("span", { class: "flag", style: "margin-left:6px", text: "needs OK" }) : null)))));
}

// ------------------------------------------------------------------ thread

const STEP_ORDER = ["understand", "fetch", "probation", "load", "score", "judge", "clean", "apply", "report"];

function pipelineCard(steps, { running = false, elapsed = null, error = null, log = [] } = {}) {
  const sorted = [...steps].sort((a, b) => STEP_ORDER.indexOf(a.key) - STEP_ORDER.indexOf(b.key));
  const doneCount = sorted.filter((s) => s.state !== "running").length;
  const card = h("div", { class: "pipeline", dataset: { open: running || error ? "true" : "false" } });
  const title = error ? "Stopped" : running ? "Working" : "Steps";
  const meta = error ? "" : running ? `${plural(doneCount, "step")} done` : `${plural(sorted.length, "step")}${elapsed != null ? `  ${elapsed}s` : ""}`;
  const head = h("button", { class: "pipeline-head", type: "button", "aria-expanded": card.dataset.open,
    onclick: () => {
      card.dataset.open = card.dataset.open === "true" ? "false" : "true";
      head.setAttribute("aria-expanded", card.dataset.open);
    } },
    icon(error ? "warn" : running ? "hold" : "check", 15), title, h("span", { class: "meta", text: meta }), h("span", { class: "chev" }, icon("down", 14)));
  const list = h("ol", { class: "steps" });
  const track = h("span", { class: "track", "aria-hidden": "true" });
  list.append(track);
  for (const s of sorted) {
    const mark = s.state === "done" ? icon("check", 11) : s.state === "warn" ? icon("warn", 11) : s.state === "held" ? icon("hold", 11) : null;
    list.append(h("li", { class: "step", dataset: { state: s.state } },
      h("span", { class: "mark" }, mark), h("span", { class: "label", text: s.label }),
      h("span", { class: "detail", text: s.detail || "" })));
  }
  requestAnimationFrame(() => {
    const items = list.querySelectorAll(".step");
    if (!items.length) return;
    const lastDone = [...items].filter((li) => li.dataset.state !== "running").pop() || items[0];
    const target = running ? (list.querySelector('.step[data-state="running"]') || lastDone) : items[items.length - 1];
    track.style.height = `${target.offsetTop + target.offsetHeight / 2 - 4}px`;
  });
  card.append(head, list);
  if (log && log.length) {
    const pre = h("pre", { hidden: true, text: log.join("\n") });
    const btn = h("button", { class: "btn btn-ghost", type: "button", onclick: () => {
      pre.hidden = !pre.hidden; btn.textContent = pre.hidden ? "Show log" : "Hide log";
      if (!pre.hidden) pre.scrollTop = pre.scrollHeight;
    } }, "Show log");
    card.append(h("div", { class: "log-wrap" }, btn, pre));
  }
  return card;
}

function familyTable(entries) {
  const fam = new Map();
  for (const e of entries) {
    const f = fam.get(e.family) || { n: 0, threat: 0, suspicious: 0, info: 0 };
    f.n += 1; f[e.proposed_severity] = (f[e.proposed_severity] || 0) + 1;
    fam.set(e.family, f);
  }
  const rows = [...fam.entries()].sort((a, b) => b[1].n - a[1].n);
  const shown = rows.slice(0, 8);
  return h("table", { class: "summary" },
    h("thead", {}, h("tr", {}, h("th", { text: "Family" }), h("th", { text: "Rules" }), h("th", { text: "Planned severity" }))),
    h("tbody", {}, ...shown.map(([name, f]) => h("tr", {},
      h("td", { text: name }), h("td", { class: "num", text: String(f.n) }),
      h("td", { class: "sev", text: [f.threat && `${f.threat} threat`, f.suspicious && `${f.suspicious} suspicious`, f.info && `${f.info} info`].filter(Boolean).join(", ") }))),
      rows.length > shown.length ? h("tr", { class: "more" }, h("td", { colspan: "3", text: `and ${plural(rows.length - shown.length, "more family", "more families")}` })) : null));
}

function cleanNote(r) {
  const n = (r.additions || []).length + (r.updates || []).length;
  if (!r.clean || !n) return null;
  if (!r.clean.tested) {
    return h("div", { class: "note warn" }, icon("warn", 15),
      h("span", { text: "Not clean-set tested. Add known-clean folders (clean_dirs in config/hermit.toml) before ending probation." }));
  }
  const dropped = (r.drops || []).length;
  return h("div", { class: "note ok" }, icon("check", 15),
    h("span", { text: `Clean-set tested against ${plural(r.clean.files, "file")}. ${r.clean.fired ? `${plural(r.clean.fired, "rule")} fired and ${r.clean.fired === 1 ? "was" : "were"} demoted${dropped ? ` or dropped (${dropped} dropped)` : ""}.` : "No rule fired."}` }));
}

function answer(msg) {
  const r = msg.result || {};
  const out = h("div", { class: "answer" });
  if (msg.state === "error" || msg.error) {
    out.append(h("h3", { text: "That didn't finish" }),
      h("div", { class: "note err", text: msg.error || "Something went wrong." }),
      h("p", { text: "Nothing was changed. Fix the cause above and send the request again." }));
    return out;
  }
  const pack = r.pack || "the pack";
  const adds = r.additions || [], upd = r.updates || [], rem = r.removals || [], drops = r.drops || [];
  const n = adds.length + upd.length + rem.length;

  if (r.outcome === "report") {
    out.append(h("h3", { text: r.exists ? `${pack}: ${plural((r.history || []).length, "version")}` : `${pack} has no versions yet` }));
    if ((r.history || []).length) {
      out.append(h("ul", {}, ...r.history.slice().reverse().map((x) => h("li", {},
        h("strong", { text: `v${x.version}` }), ` ${timeLabel(x.at)}  ${x.summary}`))));
    }
    out.append(actionsFor(msg));
    return out;
  }
  let headline;
  if (r.outcome === "applied") headline = rem.length && !adds.length ? `Removed ${plural(rem.length, "rule")} from ${pack}.` : `${plural(adds.length, "rule")} added to ${pack}.`;
  else if (r.outcome === "held") headline = `${plural(n, "change")} ready for ${pack}.`;
  else if (r.outcome === "dry-run") headline = `Dry run: ${plural(n, "change")} for ${pack}.`;
  else if (r.outcome === "nothing") headline = `Nothing new for ${pack}.`;
  else headline = `Planned changes for ${pack}.`;
  out.append(h("h3", { text: headline }));

  const bits = [];
  if (r.considered != null) bits.push(`Looked at ${plural(r.considered, "rule")}.`);
  const decided = {};
  for (const e of [...adds, ...upd]) decided[e.decided_by] = (decided[e.decided_by] || 0) + 1;
  const dd = Object.entries(decided).map(([k, v]) => `${v} by ${k === "llm" ? "the model" : k === "rules" ? "scoring" : k}`);
  if (dd.length) bits.push(`Decided ${dd.join(", ")}.`);
  if (upd.length) bits.push(`${plural(upd.length, "rule")} changed upstream and will be updated.`);
  const prob = [...adds, ...upd].filter((e) => e.status === "probation");
  if (prob.length) bits.push(`New rules stay at info until ${prob[0].probation_until}, then move to their planned severity if they stay quiet on clean files.`);
  const unsure = [...adds, ...upd].filter((e) => e.uncertain).length;
  if (unsure) bits.push(`The model wasn't sure about ${plural(unsure, "rule")}; those stay at info.`);
  const skipped = Object.entries(r.skipped || {}).map(([k, v]) => `${v} ${k}`);
  if (skipped.length) bits.push(`Skipped: ${skipped.join(", ")}.`);
  if (bits.length) out.append(h("p", { text: bits.join(" ") }));

  if (adds.length + upd.length) out.append(familyTable([...adds, ...upd]));
  if (rem.length) out.append(h("ul", {}, ...rem.slice(0, 12).map((x) => h("li", { text: `${x.name}: ${x.reason}` }))));
  if (drops.length) {
    out.append(h("p", { text: `Dropped after firing on clean files: ${drops.slice(0, 6).map((d) => d.name).join(", ")}${drops.length > 6 ? ` and ${drops.length - 6} more` : ""}.` }));
  }
  if ((r.missing || []).length) out.append(h("p", { text: `Named but not found: ${r.missing.join(", ")}.` }));
  const cn = cleanNote(r);
  if (cn) out.append(cn);
  if (r.outcome === "held") {
    out.append(h("div", { class: "note held" }, icon("hold", 15),
      h("span", { text: `Waiting for your OK: ${(r.gates || []).join("; ") || "safety check"}.` })));
  }
  out.append(actionsFor(msg));
  return out;
}

function actionsFor(msg) {
  const r = msg.result || {};
  const row = h("div", { class: "actions" });
  const pack = state.packs.find((p) => p.id === r.pack);
  if (r.outcome === "held" && state.held[r.pack]) {
    row.append(h("button", { class: "btn btn-primary", type: "button", onclick: () => applyHeld(r.pack) }, `Apply to ${r.pack}`));
  }
  if (pack) row.append(h("button", { class: "btn btn-outline", type: "button", onclick: () => { loadPack(r.pack); openPackDrawer(); } }, "Open pack"));
  if (r.outcome === "applied" && pack && pack.version === r.to_version) {
    row.append(h("button", { class: "btn btn-ghost", type: "button", onclick: () => rollback(r.pack) }, "Undo"));
  }
  row.append(h("button", { class: "icon-btn", type: "button", "aria-label": "Copy run log", title: "Copy run log",
    onclick: async () => {
      const text = msg.log ? msg.log.join("\n") : "";
      try { await navigator.clipboard.writeText(text); toast("Copied the run log."); } catch { toast("Couldn't copy.", true); }
    } }, icon("copy", 15)));
  return row;
}

function messageEl(msg) {
  if (msg.role === "user") {
    return h("div", { class: "msg" },
      h("div", { class: "msg-meta" }, "You", h("time", { text: timeLabel(msg.at) })),
      h("div", { class: "bubble", text: msg.text }));
  }
  return h("div", { class: "msg" },
    pipelineCard(msg.steps || [], { elapsed: msg.elapsed, error: msg.error, log: msg.log }),
    h("div", { class: "msg-meta" }, "Hermit", h("span", { class: "badge", text: "local" }), h("time", { text: timeLabel(msg.at) })),
    answer(msg));
}

function emptyState() {
  const examples = [
    "Update rule list to include all new rules related to video games",
    "Add new core threats",
    "Add everything about Lumma stealer to cracked-software",
    "What changed in games this week?",
  ];
  return h("div", { class: "empty" },
    h("h2", { text: "What should go into your packs?" }),
    h("p", { text: "Describe the rules you want. Hermit finds them, scores them, asks your local model about the unclear ones, tests them against clean files and saves a new pack version you can undo." }),
    h("div", { class: "suggestions" }, ...examples.map((x) => h("button", { class: "suggestion", type: "button",
      onclick: () => { $("prompt").value = x; $("prompt").focus(); autosize(); } }, x))));
}

function renderThread() {
  const thread = $("thread");
  const msgs = state.chat ? state.chat.messages : [];
  $("chat-title").textContent = state.chat ? state.chat.title : "New chat";
  $("crumb-here").textContent = state.chat ? state.chat.title : "Rule research";
  const items = msgs.map(messageEl);
  const j = state.job;
  if (j && j.state === "running" && j.chat_id && j.chat_id === state.chatId) {
    items.push(h("div", { class: "msg" }, pipelineCard(j.steps, { running: true, log: state.jobLog })));
  }
  thread.replaceChildren(...(items.length ? items : [emptyState()]));
  const box = $("messages");
  box.scrollTop = box.scrollHeight;
}

// ------------------------------------------------------------------ pack panel

function groupRules(rules) {
  const key = state.groupBy === "severity" ? (r) => r.severity : (r) => r.family;
  const groups = new Map();
  const q = state.filter.toLowerCase();
  for (const r of rules) {
    if (q && !r.name.toLowerCase().includes(q) && !r.family.toLowerCase().includes(q)) continue;
    const k = key(r);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  }
  const order = { threat: 0, suspicious: 1, info: 2 };
  let out = [...groups.entries()].sort((a, b) => state.groupBy === "severity"
    ? order[a[0]] - order[b[0]] : b[1].length - a[1].length || a[0].localeCompare(b[0]));
  if (state.groupBy === "family" && out.length > 15) {   // fold one-rule families together
    const singles = out.filter(([, rs]) => rs.length === 1).flatMap(([, rs]) => rs);
    if (singles.length > 1) {
      out = out.filter(([, rs]) => rs.length > 1);
      out.push([`Families with one rule`, singles.sort((x, y) => x.family.localeCompare(y.family))]);
    }
  }
  return out;
}

function ruleRow(r) {
  const flag = r.status === "probation" ? "probation" : r.uncertain ? "unsure" : r.demoted ? "demoted" : null;
  return h("button", { class: "rule-row", type: "button", "aria-current": state.rule && state.rule.key === r.key ? "true" : "false",
    title: r.name, onclick: () => selectRule(r) },
    h("span", { class: `sev-dot ${r.severity}`, title: r.severity }), h("span", { class: "nm", text: r.name }),
    flag ? h("span", { class: "flag", text: flag }) : null);
}

function ruleTree(p) {
  const groups = groupRules(p.rules_list);
  const tree = h("div", { class: "tree" });
  if (!groups.length) { tree.append(h("p", { class: "more-row", text: "No rules match." })); return tree; }
  const MAX_GROUPS = 60, MAX_ROWS = 80;
  for (const [name, rules] of groups.slice(0, MAX_GROUPS)) {
    const id = `${state.groupBy}:${name}`;
    const hasSelected = !!state.rule && rules.some((r) => r.key === state.rule.key);
    const det = h("details", { open: state.openFamilies.has(id) || hasSelected || (!!state.filter && groups.length < 6) });
    const body = h("div", {});
    const fill = () => {
      if (body.childElementCount) return;
      for (const r of rules.slice(0, MAX_ROWS)) {
        body.append(ruleRow(r));
        if (state.rule && state.rule.key === r.key) body.append(rulePreview(state.rule));
      }
      if (rules.length > MAX_ROWS) body.append(h("div", { class: "more-row", text: `and ${rules.length - MAX_ROWS} more; filter to narrow down` }));
    };
    det.addEventListener("toggle", () => {
      if (det.open) { state.openFamilies.add(id); fill(); } else state.openFamilies.delete(id);
    });
    if (det.open) fill();
    det.append(h("summary", {}, h("span", { class: "chev" }, icon("chev", 12)), h("span", { text: name }),
      h("span", { class: "n", text: String(rules.length) })), body);
    tree.append(det);
  }
  if (groups.length > MAX_GROUPS) tree.append(h("p", { class: "more-row", text: `and ${groups.length - MAX_GROUPS} more groups; filter to narrow down` }));
  return tree;
}

async function selectRule(r) {
  try {
    const t = await api(`packs/${state.packId}/rule?key=${encodeURIComponent(r.key)}`);
    state.rule = { ...r, ...t };
  } catch (e) { toast(e.message, true); return; }
  renderPackPanel();
  const pv = $("pack-panel").querySelector(".preview");
  if (pv) pv.scrollIntoView({ block: "nearest" });
}

function shortLicence(l) {
  if (!l) return "unknown";
  const m = /^https?:\/\/github\.com\/([^/]+\/[^/]+)\//.exec(l);
  return m ? `${m[1]} licence file` : l;
}

function rulePreview(r) {
  const why = h("dl", {},
    h("dt", { text: "Severity" }), h("dd", { text: r.severity === r.proposed_severity ? r.severity : `${r.severity} now, ${r.proposed_severity} planned` }),
    h("dt", { text: "Why that" }), h("dd", { text: r.demoted || (r.status === "probation" ? `on probation until ${r.probation_until}` : r.severity_reason || "") }),
    h("dt", { text: "Chosen by" }), h("dd", { text: r.decided_by === "llm" ? "the local model" : r.decided_by === "rules" ? "scoring" : r.decided_by }),
    h("dt", { text: "Source" }), h("dd", { text: r.source || "" }),
    h("dt", { text: "Licence" }), h("dd", { text: shortLicence(r.licence), title: r.licence || "" }),
    r.description ? h("dt", { text: "Describes" }) : null, r.description ? h("dd", { text: r.description }) : null);
  const reasons = (r.reasons || []).length ? h("ul", { style: "margin-top:8px" }, ...r.reasons.slice(0, 6).map((x) => h("li", { text: x }))) : null;
  return h("div", { class: "preview" },
    h("div", { class: "preview-head" }, h("span", { class: `sev-dot ${r.severity}` }), h("b", { text: r.name }),
      h("button", { class: "icon-btn", type: "button", "aria-label": "Open full rule", title: "Open full rule",
        onclick: () => openDialog(r.name, [h("pre", { text: r.text }),
          r.support.length ? h("p", { text: `Also shipped with it: ${r.support.join(", ")}` }) : null].filter(Boolean)) }, icon("expand", 13))),
    h("pre", { text: r.text }),
    h("div", { class: "why" }, why, r.llm_reason ? h("p", { style: "margin:8px 0 0", text: `Model: ${r.llm_reason}` }) : null, reasons));
}

function renderPackPanel() {
  const panel = $("pack-panel");
  const prevScroll = panel.querySelector(".pack-scroll");
  const keepScroll = { id: panel.dataset.pack, top: prevScroll ? prevScroll.scrollTop : 0 };
  panel.dataset.pack = state.pack ? state.pack.id : "";
  const head = h("div", { class: "pack-head" },
    h("div", {}, h("h2", { text: "Current rule pack" }), h("p", { text: "What Mantha Ray will load" })),
    h("button", { class: "icon-btn only-mid", type: "button", "aria-label": "Close pack panel", onclick: closeDrawers }, icon("close", 15)));
  const p = state.pack;
  const pendingHeld = !p && state.packId ? state.held[state.packId] : null;
  if (pendingHeld) {
    panel.replaceChildren(head, h("div", { class: "pack-scroll" },
      h("div", { class: "pack-status" }, h("span", { class: "state-tag held", text: "Waiting for OK" }),
        h("span", { class: "mono", text: "new pack" }), h("span", { class: "when", text: relTime(pendingHeld.created) })),
      h("h2", { class: "pack-title", text: state.packId }),
      h("p", { class: "pack-path mono", text: `packs/${state.packId}/  \u2002not created yet` }),
      h("div", { class: "stats" }, h("div", { class: "stat" }, h("b", { text: fmtNum(pendingHeld.changes || 0) }), h("span", { text: "Rules proposed" }))),
      h("div", { class: "note held" }, icon("hold", 15), h("span", { text: (pendingHeld.gates || []).join("; ") || "Waiting for your OK." })),
      h("div", { class: "pack-actions" },
        h("button", { class: "btn btn-primary", type: "button", onclick: () => applyHeld(state.packId) }, "Create the pack"))));
    return;
  }
  if (!p) {
    panel.replaceChildren(head, h("div", { class: "panel-empty" },
      h("h3", { text: state.packs.length ? "Pick a pack" : "No packs yet" }),
      h("p", { text: state.packs.length ? "Choose one from the list on the left, or open it from an answer." : "Send a request such as “add new core threats” to build your first pack." })));
    return;
  }
  const sev = p.severity;
  const total = Math.max(1, p.rules);
  const status = h("div", { class: "pack-status" },
    p.held ? h("span", { class: "state-tag held", text: "Waiting for OK" }) : h("span", { class: "state-tag live", text: "Live" }),
    h("span", { class: "mono", text: `v${p.version}` }),
    h("span", { class: "when", text: relTime(p.updated_at) }));
  const stats = h("div", { class: "stats" },
    h("div", { class: "stat" }, h("b", { text: fmtNum(p.rules) }), h("span", { text: "Rules" })),
    h("div", { class: "stat" }, h("b", { text: fmtNum(p.families) }), h("span", { text: "Families" })),
    h("div", { class: "stat" }, h("b", { text: fmtNum(Math.round(p.size_bytes / 1024)) }), h("span", { text: "KB of rules" })));
  const bar = h("div", { class: "sevbar", role: "img", "aria-label": `${sev.threat} threat, ${sev.suspicious} suspicious, ${sev.info} info` },
    h("i", { class: "threat", style: `width:${(sev.threat / total) * 100}%` }),
    h("i", { class: "suspicious", style: `width:${(sev.suspicious / total) * 100}%` }),
    h("i", { class: "info", style: `width:${(sev.info / total) * 100}%` }));
  const legend = h("div", { class: "legend" },
    h("span", { class: "threat" }, h("b", { text: fmtNum(sev.threat) }), " threat"),
    h("span", { class: "suspicious" }, h("b", { text: fmtNum(sev.suspicious) }), " suspicious"),
    h("span", { class: "info" }, h("b", { text: fmtNum(sev.info) }), " info"),
    p.probation ? h("span", {}, h("b", { text: fmtNum(p.probation) }), " on probation") : null);

  const actions = h("div", { class: "pack-actions" },
    p.held ? h("button", { class: "btn btn-primary", type: "button", onclick: () => applyHeld(p.id) }, "Apply held changes") : null,
    h("button", { class: p.held ? "btn" : "btn btn-primary", type: "button", onclick: exportBundle }, icon("file", 14), "Export bundle"),
    h("button", { class: "btn btn-outline", type: "button", onclick: publishDialog }, "Publish"),
    h("button", { class: "btn", type: "button", onclick: () => showManifest(p.id) }, "Manifest"),
    p.probation ? h("button", { class: "btn btn-ghost", type: "button", onclick: () => promote(p.id, p.probation) }, "End probation") : null,
    p.version > 1 ? h("button", { class: "btn btn-ghost", type: "button", onclick: () => rollback(p.id) }, "Undo last change") : null);

  const filter = h("input", { class: "field", type: "search", placeholder: "Filter rules", value: state.filter, "aria-label": "Filter rules",
    oninput: (e) => { state.filter = e.target.value; const t = panel.querySelector(".tree"); t.replaceWith(ruleTree(p)); } });
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Group rules by" },
    ...["family", "severity"].map((g) => h("button", { type: "button", "aria-pressed": state.groupBy === g ? "true" : "false",
      onclick: () => { state.groupBy = g; renderPackPanel(); } }, g === "family" ? "Family" : "Severity")));

  const check = p.check ? h("div", { class: p.check.ok ? "check" : "check bad" }, icon(p.check.ok ? "check" : "warn", 14), h("span", { text: p.check.message })) : null;

  const repo = h("div", { class: "repo" }, h("h3", { text: "Where the rules come from" }),
    ...p.sources.map((s) => h("div", { class: "src" }, icon("branch", 13), h("b", { text: s.name }),
      h("span", { text: `${s.revision ? s.revision.slice(0, 8) : "local"}  ${fmtNum(s.rules)}` }))));

  const history = p.history.length ? [h("div", { class: "section-head" }, h("h3", { text: "Versions" })),
    h("ul", { class: "history" }, ...p.history.slice(0, 5).map((x) => h("li", {}, h("b", { text: `v${x.version}` }), x.summary)))] : [];

  panel.replaceChildren(head, h("div", { class: "pack-scroll" },
    status, h("h2", { class: "pack-title", text: p.id }),
    h("p", { class: "pack-path mono", text: `packs/${p.id}/   ${p.kind}   ${p.editions.join(", ")}` }),
    p.description ? h("p", { class: "pack-desc", text: p.description }) : null,
    stats, bar, legend, actions,
    h("div", { class: "section-head" }, h("h3", { text: "Included rules" }), h("span", { class: "right" }, seg)),
    filter, ruleTree(p),
    check, ...history, repo));
  const scroller = panel.querySelector(".pack-scroll");
  if (scroller && keepScroll.id === p.id) scroller.scrollTop = keepScroll.top;
}

async function showManifest(id) {
  try {
    const m = await api(`packs/${id}/manifest`);
    openDialog(`${id}: pack.json and severities.json`, [
      h("p", { text: "These files are what Mantha Ray validates and loads (bundle contract v1)." }),
      h("pre", { text: JSON.stringify(m.pack_json, null, 2).slice(0, 60000) }),
      h("pre", { text: JSON.stringify(m.severities_json, null, 2).slice(0, 60000) })]);
  } catch (e) { toast(e.message, true); }
}

// ------------------------------------------------------------------ jobs

let pollTimer = null;
async function watchJob(id, { onDone } = {}) {
  state.jobLog = [];
  clearTimeout(pollTimer);
  const tick = async () => {
    let j;
    try { j = await api(`jobs/${id}?since=${state.jobLog.length}`); } catch (e) { toast(e.message, true); return; }
    state.jobLog.push(...j.log);
    state.job = j;
    setBusy(j.state === "running");
    if (j.chat_id && j.chat_id === state.chatId) renderThread();
    if (j.state === "running") { pollTimer = setTimeout(tick, 600); return; }
    state.job = null;
    setBusy(false);
    await Promise.all([loadPacks(), loadChats(), loadStatus()]);
    if (j.chat_id && j.chat_id === state.chatId) await loadChat(state.chatId);
    const packId = j.pack || (j.result && j.result.pack) || state.packId;
    if (packId && (state.packs.some((p) => p.id === packId) || state.held[packId])) await loadPack(packId, { keepRule: packId === state.packId });
    if (onDone) onDone(j);
  };
  tick();
}

function setBusy(busy) {
  $("send").disabled = busy;
  $("prompt").placeholder = busy ? "Hermit is working on your request" : "Ask Hermit to add, remove or report on rules";
}

async function send(text) {
  if (!text.trim()) return;
  try {
    const res = await api("ask", { method: "POST", body: {
      text, chat_id: state.chatId,
      options: { use_model: $("opt-model").checked, fetch: $("opt-fetch").checked, dry_run: $("opt-dry").checked },
    } });
    $("prompt").value = ""; autosize();
    state.chatId = res.chat_id;
    await loadChats();
    await loadChat(res.chat_id);
    watchJob(res.job);
  } catch (e) { toast(e.message, true); }
}

async function applyHeld(pack) {
  const hd = state.held[pack];
  const isNew = !state.packs.some((x) => x.id === pack);
  const ok = await confirmDialog(isNew ? `Create ${pack}?` : `Apply the held changes to ${pack}?`,
    `${hd ? (hd.gates || []).join("; ") : "A safety check stopped these changes"}. ${isNew ? "Applying creates the pack as version 1" : `Applying saves a new version of ${pack}`}; you can undo it afterwards.`, "Apply changes");
  if (!ok) return;
  try {
    const res = await api("apply", { method: "POST", body: { pack } });
    if (res.chat_id) { state.chatId = res.chat_id; await loadChat(res.chat_id); }
    watchJob(res.job);
  } catch (e) { toast(e.message, true); }
}

async function rollback(pack) {
  const ok = await confirmDialog(`Undo the last change to ${pack}?`,
    "Hermit restores the previous version's rules and saves that as a new version, so this can be undone too.", "Undo change", true);
  if (!ok) return;
  try { const r = await api(`packs/${pack}/rollback`, { method: "POST", body: {} });
    watchJob(r.job, { onDone: (j) => toast(j.error || `Restored ${pack} to v${j.result.restored}.`, !!j.error) }); }
  catch (e) { toast(e.message, true); }
}

async function promote(pack, n) {
  const clean = state.status && state.status.clean_dirs.length;
  const ok = await confirmDialog(`End probation for ${plural(n, "rule")} in ${pack}?`,
    clean ? "Each rule is scanned against your clean folders first. Rules that fire there stay at info or are dropped; the rest move to their planned severity."
      : "No clean folders are set, so rules will move to their planned severity without a clean-set test. Set clean_dirs in config/hermit.toml first if you can.",
    "End probation");
  if (!ok) return;
  try { const r = await api(`packs/${pack}/promote`, { method: "POST", body: { now: true } });
    watchJob(r.job, { onDone: (j) => toast(j.error || `${plural((j.result.promoted || []).length, "rule")} reviewed in ${pack}.`, !!j.error) }); }
  catch (e) { toast(e.message, true); }
}

async function exportBundle() {
  try {
    const r = await api("export", { method: "POST", body: {} });
    toast("Exporting packs");
    watchJob(r.job, { onDone: (j) => {
      if (j.error) { toast(j.error, true); return; }
      openDialog("Bundle exported", [
        h("p", { text: "An unsigned bundle folder in contract v1 layout, ready for Mantha Ray to load:" }),
        h("pre", { text: j.result.dir }),
        h("p", { text: j.result.manifest.changes })]);
    } });
  } catch (e) { toast(e.message, true); }
}

function publishDialog() {
  const s = state.status || {};
  const push = h("input", { type: "checkbox", id: "pub-push", checked: !!s.release_repo, disabled: !s.release_repo });
  const ready = s.has_secret_key && s.has_public_key;
  openDialog("Publish a signed bundle", [
    h("p", { text: "Hermit builds a bundle of every live pack, leaves out rules without a known licence, signs it with your minisign key and verifies it the way Mantha Ray will." }),
    h("dl", {},
      h("dt", { text: "Signing key" }), h("dd", { text: ready ? "ready" : "missing: run hermit keygen" }),
      h("dt", { text: "Release repo" }), h("dd", { text: s.release_repo || "not set ([bundle] release_repo)" })),
    h("label", { class: "toggle" }, push, "Create a GitHub release")],
  [h("button", { class: "btn", type: "button", onclick: closeDialog }, "Cancel"),
    h("button", { class: "btn btn-primary", type: "button", disabled: !ready, onclick: async () => {
      closeDialog();
      try {
        const r = await api("publish", { method: "POST", body: { push: push.checked } });
        toast("Publishing");
        watchJob(r.job, { onDone: (j) => {
          if (j.error) { toast(j.error, true); return; }
          openDialog(`Published ${j.result.version}`, [
            h("p", { text: j.result.changes }),
            h("dl", {}, h("dt", { text: "Bundle" }), h("dd", { text: j.result.tarball }),
              h("dt", { text: "SHA-256" }), h("dd", { class: "mono", text: j.result.sha256 }),
              j.result.url ? h("dt", { text: "Release" }) : null, j.result.url ? h("dd", { text: j.result.url }) : null)]);
        } });
      } catch (e) { toast(e.message, true); }
    } }, "Publish")]);
}

function settingsDialog() {
  const s = state.status || {};
  openDialog("Settings", [
    h("p", { text: "Hermit reads these from config/hermit.toml. Edit that file and restart hermit serve to change them." }),
    h("dl", {},
      h("dt", { text: "Version" }), h("dd", { text: s.version || "" }),
      h("dt", { text: "Model" }), h("dd", { text: `${s.model || ""}${s.ollama_ok ? "" : " (Ollama not reachable)"}` }),
      h("dt", { text: "Ollama endpoint" }), h("dd", { text: s.endpoint || "" }),
      h("dt", { text: "Clean folders" }), h("dd", { text: (s.clean_dirs || []).join(", ") || "none: rules aren't tested against clean files" }),
      h("dt", { text: "Rule sources" }), h("dd", { text: (s.sources || []).map((x) => `${x.name}${x.revision ? ` (${x.revision})` : ""}`).join(", ") || "none fetched" }),
      h("dt", { text: "Signing key" }), h("dd", { text: s.has_secret_key ? "present" : "missing (hermit keygen)" }),
      h("dt", { text: "Release repo" }), h("dd", { text: s.release_repo || "not set" }))]);
}

// ------------------------------------------------------------------ drawers, composer

function closeDrawers() {
  $("sidebar").dataset.open = "false";
  $("pack-panel").dataset.open = "false";
  $("menu-btn").setAttribute("aria-expanded", "false");
  $("pack-toggle").setAttribute("aria-expanded", "false");
}
function openPackDrawer() {
  $("pack-panel").dataset.open = "true";
  $("pack-toggle").setAttribute("aria-expanded", "true");
}
function autosize() {
  const t = $("prompt");
  t.style.height = "auto";
  t.style.height = `${Math.min(200, t.scrollHeight)}px`;
}

function wire() {
  $("composer").addEventListener("submit", (e) => { e.preventDefault(); send($("prompt").value); });
  $("prompt").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); if (!$("send").disabled) send($("prompt").value); }
  });
  $("prompt").addEventListener("input", autosize);
  $("new-chat").addEventListener("click", () => { state.chatId = null; state.chat = null; renderChatList(); renderThread(); $("prompt").focus(); });
  $("settings-btn").addEventListener("click", settingsDialog);
  $("dlg-close").addEventListener("click", closeDialog);
  $("search-btn").addEventListener("click", () => {
    const f = $("chat-search"); f.hidden = !f.hidden;
    $("search-btn").setAttribute("aria-expanded", String(!f.hidden));
    if (!f.hidden) f.focus(); else { f.value = ""; renderChatList(); }
  });
  $("chat-search").addEventListener("input", renderChatList);
  $("menu-btn").addEventListener("click", () => {
    const s = $("sidebar"); const open = s.dataset.open !== "true";
    closeDrawers(); s.dataset.open = String(open); $("menu-btn").setAttribute("aria-expanded", String(open));
  });
  $("pack-toggle").addEventListener("click", () => {
    const open = $("pack-panel").dataset.open !== "true";
    closeDrawers(); if (open) openPackDrawer();
  });
  $("model-select").addEventListener("change", async (e) => {
    try { await api("model", { method: "POST", body: { model: e.target.value } }); toast(`Using ${e.target.value} for new requests.`); await loadStatus(); }
    catch (err) { toast(err.message, true); }
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawers(); });
}

async function init() {
  wire();
  renderThread();
  await loadStatus();
  await Promise.all([loadPacks(), loadChats()]);
  if (state.chats.length) await loadChat(state.chats[0].id);
  const pend = pendingPacks()[0];
  const first = state.packs.find((p) => p.held) || state.packs[0];
  await loadPack(pend ? pend[0] : first ? first.id : null);
  const busy = state.status && state.status.busy;
  if (busy && busy.state === "running") watchJob(busy.id);
}
init();
