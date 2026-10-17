/* sigma-generator web UI.
 *
 * Plain JavaScript, no dependencies, no network access beyond this server.
 * All text that originates from ATT&CK, SigmaHQ or rule content is inserted with
 * textContent (via the h() helper) - never innerHTML - so external data cannot
 * inject markup into the page.
 */
"use strict";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const $ = (selector, root = document) => root.querySelector(selector);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else if (key === "href" && !/^(https?:\/\/|blob:)/i.test(String(value))) continue; // no javascript: URLs
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

/** replaceChildren() that skips null/false instead of rendering the text "null". */
function fill(el, ...children) {
  el.replaceChildren(...children.flat().filter((child) => child !== null && child !== undefined && child !== false));
  return el;
}

async function api(path, { method = "GET", body } = {}) {
  const options = { method, headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.headers["X-Requested-With"] = "sigma-generator";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const contentType = response.headers.get("Content-Type") || "";
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    if (contentType.includes("application/json")) {
      const payload = await response.json().catch(() => null);
      if (payload && payload.error) message = payload.error;
    }
    throw new Error(message);
  }
  if (contentType.includes("application/json")) return response.json();
  return response.blob();
}

function debounce(fn, wait = 160) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), wait); };
}

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 2400);
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const link = h("a", { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadText(filename, text, type) {
  downloadBlob(filename, new Blob([text], { type: `${type};charset=utf-8` }));
}

function loading(message) {
  return h("p", { class: "loading" }, h("span", { class: "spinner", "aria-hidden": "true" }), message);
}

function svgIcon(path) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  const attrs = { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
    "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" };
  for (const [key, value] of Object.entries(attrs)) svg.setAttribute(key, String(value));
  const line = document.createElementNS(ns, "path");
  line.setAttribute("d", path);
  svg.append(line);
  return svg;
}

const cap = (word) => (word ? word.charAt(0).toUpperCase() + word.slice(1) : "");
const titleCase = (slug) => String(slug || "").split("-").map(cap).join(" ");
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

const TIER_ORDER = { strong: 0, moderate: 1, weak: 2, placeholder: 3 };
const GRADE_SENTENCE = {
  strong: "Two or more independent signals. Level follows the tactic.",
  moderate: "One concrete signal. Level is lowered one step. Review for noise.",
  weak: "Broad activity only. Tagged for hunting and capped at low.",
  placeholder: "No concrete values yet. Matches nothing until completed.",
};

function gradePill(tier) {
  if (!tier) return h("span", { class: "pill t-none" }, "No values");
  return h("span", { class: `pill t-${tier}` }, tier === "placeholder" ? "Skeleton" : cap(tier));
}

function bestTier(tiers) {
  return [...tiers].sort((a, b) => TIER_ORDER[a] - TIER_ORDER[b])[0] || null;
}

/** YAML or JSON as highlighted DOM nodes: keys in the accent colour, comments muted. */
function codeBlock(text, json, label) {
  const pre = h("pre", { class: "code", tabindex: "0", "aria-label": label });
  for (const line of text.replace(/\n$/, "").split("\n")) {
    if (!json && /^\s*#/.test(line)) {
      pre.append(h("span", { class: "c" }, line), "\n");
      continue;
    }
    const match = json ? line.match(/^(\s*)("[^"]+")(:)(.*)$/) : line.match(/^(\s*(?:- )?)([A-Za-z0-9_.|-]+)(:)(.*)$/);
    if (match) pre.append(match[1], h("span", { class: "k" }, match[2]), match[3], match[4], "\n");
    else pre.append(line, "\n");
  }
  return pre;
}

function firstSentence(text, max = 170) {
  const sentence = String(text || "").split(/(?<=\.)\s/)[0].trim();
  return sentence.length > max ? `${sentence.slice(0, max - 1).trimEnd()}…` : sentence;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const STARTERS = ["T1003.001", "T1547.001", "T1621", "T1059.001", "T1110.003", "T1053.005",
  "T1003.002", "T1047", "T1105", "T1112", "T1566.001", "T1078.004"];
const EXAMPLES = ["T1003.001", "T1547.001", "T1621", "T1059.001"];
const THREAT_STARTERS = {
  group: ["G0016", "G0032", "G0034", "G0007", "G0046"],
  software: ["S0002", "S0154", "S0029", "S0363"],
  campaign: ["C0024", "C0025", "C0022"],
};
const PLACEHOLDERS = { group: "APT29, Cozy Bear, G0016", software: "Mimikatz, S0002", campaign: "SolarWinds, C0024" };
/** Pack totals for the three example packs, as generated from ATT&CK v19.2 with SigmaHQ r2026-07-01. */
const PUBLISHED_PACKS = {
  attack: "19.2",
  sigmahq: "r2026-07-01",
  packs: [
    { id: "G0016", kind: "group", name: "APT29", strong: 14, moderate: 39, weak: 31, gaps: 13 },
    { id: "S0002", kind: "software", name: "Mimikatz", strong: 11, moderate: 3, weak: 9, gaps: 2 },
    { id: "C0024", kind: "campaign", name: "SolarWinds Compromise", strong: 23, moderate: 48, weak: 29, gaps: 13 },
  ],
};

const state = {
  mode: "technique",
  runtime: "server",
  status: null,
  grades: {},               // technique ID -> grade summary from /api/grades
  tech: {
    query: "",
    results: [],            // [{id, name, tactics}]
    selected: null,
    detail: null,
    draft: null,
    activeFile: null,
    recipe: { chains: true, gaps_only: false, all_analytics: false, banner: true, level: "", tlp: "clear" },
    request: 0,
  },
  threat: {
    kind: "group",
    query: "",
    results: [],
    selected: null,
    pack: null,
    deployable: false,
    gaps: {},               // threat ID -> techniques with no SigmaHQ rule, once its pack is built
    request: 0,
  },
};

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------
const VIEWS = ["view-tech-overview", "view-tech-open", "view-pack-overview", "view-pack-open"];
let currentView = "view-tech-overview";

function showView(id) {
  for (const name of VIEWS) $(`#${name}`).hidden = name !== id;
  const el = $(`#${id}`);
  if (id !== currentView) {
    el.classList.remove("enter");
    void el.offsetWidth;     // restart the animation
    el.classList.add("enter");
    $("#main").scrollTop = 0;
  }
  currentView = id;
}

function setMode(mode) {
  state.mode = mode;
  for (const tab of document.querySelectorAll(".tab")) {
    const on = tab.dataset.view === mode;
    tab.classList.toggle("on", on);
    tab.setAttribute("aria-pressed", String(on));
  }
  $("#rail-technique").hidden = mode !== "technique";
  $("#rail-pack").hidden = mode !== "pack";
  if (mode === "technique") showView(state.tech.selected ? "view-tech-open" : "view-tech-overview");
  else showView(state.threat.selected ? "view-pack-open" : "view-pack-overview");
  history.replaceState(null, "", `#${mode}`);
}

// ---------------------------------------------------------------------------
// Header and dataset status
// ---------------------------------------------------------------------------
async function loadStatus() {
  const status = await api("/api/status");
  state.status = status;
  const sigmahq = status.sigmahq;
  // The spaces are where the line may wrap; each part itself never breaks.
  const sep = () => [" ", h("span", { class: "sep" }, "/"), " "];
  const part = (text, cls = "v") => h("span", { class: cls }, text);
  fill($("#datasets"),
    part(`ATT&CK v${status.attack.version}`), sep(),
    sigmahq.available ? part(`SigmaHQ ${sigmahq.release}`) : part("SigmaHQ not downloaded", "v off"), sep(),
    part(`v${status.version}`), sep(), part("Local"));

  const notice = $("#sigmahq-notice");
  if (!sigmahq.available) {
    const button = h("button", { class: "btn btn-outline", type: "button", disabled: status.offline }, "Download SigmaHQ index (3 MB)");
    button.addEventListener("click", async () => {
      button.disabled = true;
      button.textContent = "Downloading…";
      try {
        const result = await api("/api/sigmahq/update", { method: "POST", body: {} });
        toast(`SigmaHQ ${result.release}: ${result.rules} rules indexed`);
        state.grades = {};
        await loadStatus();
        searchTechniques();
        renderExamples();
        if (state.tech.selected) selectTechnique(state.tech.selected);
      } catch (error) {
        button.disabled = false;
        button.textContent = "Retry download";
        toast(error.message);
      }
    });
    fill(notice,
      h("span", {}, status.offline
        ? "SigmaHQ coverage is off: the index is not downloaded and the UI was started offline. Run `python -m src.main update --sigmahq-only` once."
        : "SigmaHQ coverage is off until its rule index is downloaded."),
      status.offline ? null : button);
    notice.hidden = false;
  } else {
    notice.hidden = true;
  }

  const levels = $("#level-select");
  levels.replaceChildren(h("option", { value: "" }, "From tactic"),
    ...status.choices.levels.map((level) => h("option", { value: level }, level)));
  levels.value = state.tech.recipe.level;
  // "clear" and "white" are the same marking; offer the current name only.
  const tlpChoices = status.choices.tlp.filter((tlp) => tlp !== "white" || !status.choices.tlp.includes("clear"));
  const tlps = $("#tlp-select");
  tlps.replaceChildren(...tlpChoices.map((tlp) => h("option", { value: tlp }, tlp.toUpperCase())));
  tlps.value = state.tech.recipe.tlp;
  renderPackCards();
}

// ---------------------------------------------------------------------------
// Grades (the pills in the rail and the worked examples)
// ---------------------------------------------------------------------------
async function ensureGrades(ids) {
  const missing = [...new Set(ids)].filter((id) => !state.grades[id]);
  for (let i = 0; i < missing.length; i += 40) {
    const chunk = missing.slice(i, i + 40);
    try {
      const result = await api(`/api/grades?ids=${encodeURIComponent(chunk.join(","))}`);
      Object.assign(state.grades, result.grades);
    } catch (error) {
      for (const id of chunk) state.grades[id] = { id, error: error.message };
    }
  }
}

// ---------------------------------------------------------------------------
// Technique rail
// ---------------------------------------------------------------------------
async function searchTechniques() {
  const query = state.tech.query;
  if (!query.trim()) {
    if (STARTERS.some((id) => !state.grades[id])) fill($("#technique-list"), loading("Grading starters…"));
    await ensureGrades(STARTERS);
    if (state.tech.query !== query) return;
    state.tech.results = STARTERS.map((id) => state.grades[id]).filter((grade) => grade && !grade.error)
      .map((grade) => ({ id: grade.id, name: grade.name, tactics: grade.tactics }));
    renderTechniqueList();
    return;
  }
  let results;
  try {
    results = (await api(`/api/search?kind=technique&limit=25&q=${encodeURIComponent(query.trim())}`)).results;
  } catch (error) {
    if (state.tech.query === query) fill($("#technique-list"), h("p", { class: "empty-list" }, error.message));
    return;
  }
  if (state.tech.query !== query) return;
  state.tech.results = results;
  renderTechniqueList();
  await ensureGrades(results.map((technique) => technique.id));
  if (state.tech.query === query) renderTechniqueList();
}

function renderTechniqueList() {
  const { results, selected, query } = state.tech;
  const n = results.length;
  $("#technique-count").textContent = query.trim()
    ? `${n} ${n === 1 ? "match" : "matches"} · on this machine only`
    : `${n} to start with · on this machine only`;
  fill($("#technique-list"), n ? results.map((technique) => {
    const grade = state.grades[technique.id];
    const pill = !grade ? h("span", { class: "pill pending", "aria-hidden": "true" })
      : grade.error ? null : gradePill(grade.tier);
    const isSelected = technique.id === selected;
    return h("button", {
      class: isSelected ? "row sel" : "row", type: "button", "aria-current": isSelected ? "true" : null,
      onclick: () => selectTechnique(technique.id),
    },
    h("span", { class: "row-top" }, h("span", { class: "rid mono" }, technique.id), pill),
    h("span", { class: "rname" }, technique.name),
    h("span", { class: "rmeta" }, (technique.tactics || []).map(titleCase).join(", ")));
  }) : h("p", { class: "empty-list" }, "No technique matches."));
}

// ---------------------------------------------------------------------------
// Technique overview
// ---------------------------------------------------------------------------
async function renderExamples() {
  const container = $("#examples");
  const draw = () => fill(container, EXAMPLES.map((id) => {
    const grade = state.grades[id] || {};
    const coverage = grade.coverage;
    let facts = " ";
    if (grade.tier) {
      facts = [plural(grade.signals, "signal"), `confidence ${grade.confidence.toFixed(2)}`,
        coverage ? `SigmaHQ ${coverage.status} (${Math.round(coverage.ratio * 100)}% of log sources, ${plural(coverage.rules, "rule")})`
          : "SigmaHQ not downloaded"].join(" · ");
    } else if (grade.status === "insufficient") {
      facts = "ATT&CK gives no concrete values";
    } else if (grade.status === "unmappable") {
      facts = "Not expressible as Sigma";
    } else if (grade.error) {
      facts = grade.error;
    }
    return h("button", { class: "card", type: "button", onclick: () => selectTechnique(id) },
      h("span", { class: "card-top" }, h("span", { class: "card-id mono" }, id),
        grade.status ? gradePill(grade.tier) : h("span", { class: "pill pending", "aria-hidden": "true" })),
      h("span", { class: "card-name" }, grade.name || id),
      h("span", { class: "card-src mono" }, grade.logsource ? grade.logsource.replace("/", " / ") : " "),
      h("span", { class: "card-facts" }, facts));
  }));
  draw();
  await ensureGrades(EXAMPLES);
  draw();
}

// ---------------------------------------------------------------------------
// Open technique
// ---------------------------------------------------------------------------
async function selectTechnique(id) {
  const tech = state.tech;
  tech.selected = id;
  tech.detail = null;
  tech.draft = null;
  tech.activeFile = null;
  renderTechniqueList();
  if (state.mode !== "technique") setMode("technique");
  showView("view-tech-open");
  fill($("#tech-meta"), h("span", { class: "mono" }, id));
  $("#tech-name").textContent = (state.grades[id] && state.grades[id].name) || id;
  $("#tech-note").textContent = "";
  fill($("#telemetry"), loading("Reading what ATT&CK says to monitor…"));
  $("#coverage-note").textContent = "";
  fill($("#doc"), loading("Drafting…"));
  setFileActions(null);
  try {
    const [detail] = await Promise.all([api(`/api/technique/${encodeURIComponent(id)}`), regenerate(true)]);
    if (tech.selected !== id) return;
    tech.detail = detail;
    renderTechniqueHeader();
    renderTelemetry();
  } catch (error) {
    if (tech.selected === id) fill($("#telemetry"), h("p", { class: "t-gap" }, error.message));
  }
}

const scheduleRegenerate = debounce(() => regenerate(false), 120);

async function regenerate(initial) {
  const tech = state.tech;
  const id = tech.selected;
  if (!id) return;
  const request = ++tech.request;
  const doc = $("#doc");
  if (!initial) doc.classList.add("updating");
  try {
    const draft = await api("/api/generate", { method: "POST", body: { technique: id, deterministic: true, ...tech.recipe } });
    if (request !== tech.request || tech.selected !== id) return;
    tech.draft = draft;
    renderDraft();
    if (tech.detail) renderTelemetry();
  } catch (error) {
    if (request === tech.request) {
      setFileActions(null);
      fill(doc, h("p", { class: "t-gap" }, error.message));
    }
  } finally {
    if (request === tech.request) doc.classList.remove("updating");
  }
}

function renderTechniqueHeader() {
  const detail = state.tech.detail;
  const strategy = detail.detection_strategies[0];
  fill($("#tech-meta"), h("span", { class: "mono" }, detail.id),
    detail.tactics.length ? ` · ${detail.tactics.map(titleCase).join(", ")}` : null,
    strategy ? [" · ", h("span", { class: "mono" }, strategy.id)] : null);
  $("#tech-name").textContent = detail.name;
  $("#tech-note").textContent = `${detail.platforms.join(", ") || "No platform listed"}. `
    + "Drafts stay status: experimental. Values are mined from ATT&CK, not from your telemetry.";
}

function draftFiles() {
  const draft = state.tech.draft;
  if (!draft) return [];
  const files = [...draft.rules, ...draft.chains].map((rule) => ({ name: rule.filename, text: rule.yaml, json: false, rule }));
  if (draft.bundle) files.push({ name: draft.bundle.filename, text: draft.bundle.json, json: true, bundle: draft.bundle });
  return files;
}

function activeFile() {
  const files = draftFiles();
  return files.find((file) => file.name === state.tech.activeFile) || files[0] || null;
}

function setFileActions(file) {
  $("#copy-btn").disabled = !file;
  $("#download-btn").disabled = !file;
}

function coveragePill(coverage, sources) {
  if (!coverage) return h("span", { class: "pill t-none" }, "No SigmaHQ index");
  const usable = sources.filter((source) => source.coverage && source.coverage.usable);
  if (!usable.length) return h("span", { class: "pill t-none" }, "Not in Sigma");
  const covered = usable.filter((source) => source.coverage.covered_by.length).length;
  if (covered === usable.length) return h("span", { class: "pill t-strong" }, "Covered");
  if (covered) return h("span", { class: "pill t-moderate" }, "Partial");
  return h("span", { class: "pill t-gap" }, "Gap");
}

function renderTelemetry() {
  const { detail, draft } = state.tech;
  const grades = (detail.grade && detail.grade.analytics) || {};
  const coverage = detail.sigmahq;
  const covered = new Map();
  for (const source of (coverage && coverage.sources) || []) covered.set(`${source.analytic}|${source.attack_log_source}`, source);
  const inDraft = new Set(draft ? [...draft.rules, ...draft.chains].map((rule) => rule.analytic) : []);

  const blocks = [];
  for (const strategy of detail.detection_strategies) {
    for (const analytic of strategy.analytics) {
      const sources = analytic.log_sources.map((source) => {
        const label = source.channel ? `${source.name} (${source.channel})` : source.name;
        return { ...source, label, coverage: covered.get(`${analytic.id}|${label}`) };
      });
      const primary = sources.filter((source) => source.mappable).sort((a, b) => b.confidence - a.confidence)[0] || sources[0];
      const grade = grades[analytic.id];
      const confidence = primary ? primary.confidence : 0;
      const bar = h("span", { class: "fill" });
      bar.style.width = `${Math.round(confidence * 100)}%`;
      const logsource = primary && Object.values(primary.sigma_logsource || {}).join(" / ");
      const more = sources.length > 1 ? `  (+${sources.length - 1} more)` : "";
      blocks.push(h("div", { class: "tel" },
        h("div", { class: "tel-top" }, h("span", { class: "tel-id mono" }, analytic.id), gradePill(grade ? grade.tier : null)),
        h("p", { class: "tel-sum" }, firstSentence(analytic.description) || `${analytic.platforms.join(", ")} analytic.`),
        h("p", { class: "tel-src mono" }, primary
          ? `${primary.label} → ${logsource || "no Sigma log source"}${more}`
          : "No log source named"),
        h("div", { class: "conf" }, h("span", { class: "track", "aria-hidden": "true" }, bar),
          h("span", { class: "conf-n mono", title: "Mapping confidence" }, confidence.toFixed(2))),
        h("div", { class: "tel-foot" }, coveragePill(coverage, sources),
          h("span", {}, grade ? plural(grade.signals, "signal") : "No concrete values"),
          inDraft.has(analytic.id) ? h("span", { class: "indraft" }, "in this draft") : null)));
    }
  }
  fill($("#telemetry"), blocks.length ? blocks : h("p", { class: "cov-note" }, "ATT&CK attaches no detection analytic to this technique."));
  $("#coverage-note").textContent = coverage
    ? `SigmaHQ ${coverage.sigmahq_release} has ${plural(coverage.sigmahq_rules.length, "rule")} tagged ${detail.id}. `
      + `${Math.round(coverage.coverage_ratio * 100)}% of the log sources MITRE names are covered (${coverage.status.replace("-", " ")}).`
    : "SigmaHQ coverage is off until its rule index is downloaded.";
}

function renderDraft() {
  const draft = state.tech.draft;
  const doc = $("#doc");
  const files = draftFiles();
  const file = activeFile();
  setFileActions(file);

  if (!file) {
    const id = draft.technique ? draft.technique.id : state.tech.selected;
    const messages = {
      covered: ["Gaps only", "SigmaHQ already covers this",
        `Every log source ATT&CK names for ${id} already has a SigmaHQ rule, so there is no gap to fill. Turn Gaps only off to see the draft.`],
      insufficient: ["No draft", "ATT&CK gives no concrete values", draft.reason],
      unmappable: ["No draft", "Not expressible as Sigma", draft.reason],
    };
    const [kind, title, text] = messages[draft.status] || ["No draft", "Nothing was generated", draft.reason || ""];
    fill(doc, h("p", { class: "doc-kind" }, kind), h("h2", { class: "doc-title" }, title), h("p", { class: "doc-foot" }, text));
    return;
  }

  let header;
  if (file.json) {
    const indicators = file.bundle.objects.indicator || 0;
    header = [h("p", { class: "doc-kind" }, "STIX 2.1 bundle"),
      h("h2", { class: "doc-title" }, `${plural(indicators, "indicator")} for ${draft.technique.id}`),
      h("p", { class: "doc-grade" }, `Each indicator carries one rule as pattern_type sigma, marked TLP:${state.tech.recipe.tlp.toUpperCase()}.`),
      file.bundle.problems.length ? h("p", { class: "doc-check bad" }, file.bundle.problems.join("; ")) : null];
  } else {
    const rule = file.rule;
    const kind = rule.kind === "chain"
      ? `${rule.correlation_kind === "count" ? "Count threshold" : "Attack chain"} · ${rule.correlation_type}`
      : "Sigma rule";
    header = [h("p", { class: "doc-kind" }, kind), h("h2", { class: "doc-title" }, rule.title),
      h("div", { class: "doc-grade" }, gradePill(rule.quality.tier), h("span", {}, GRADE_SENTENCE[rule.quality.tier] || "")),
      rule.problems.length
        ? h("p", { class: "doc-check bad" }, rule.problems.join("; "))
        : h("p", { class: "doc-check" }, rule.pysigma_checked ? "Valid Sigma, checked with pySigma." : "Valid Sigma.")];
  }

  const chips = h("div", { class: "chips", role: "group", "aria-label": "Files" }, files.map((entry) => h("button", {
    class: entry.name === file.name ? "chip on" : "chip", type: "button", title: entry.name,
    "aria-pressed": String(entry.name === file.name),
    onclick: () => { state.tech.activeFile = entry.name; renderDraft(); },
  }, entry.name)));

  // A browser tab has no output folder to write to.
  const saveRow = state.runtime === "browser" ? null : h("p", { class: "doc-save" },
    h("button", { class: "linkish", type: "button", id: "save-technique-btn", onclick: saveTechnique }, "Save every file to the output folder"));

  fill(doc, header,
    draft.warnings.length ? h("ul", { class: "doc-notes" }, draft.warnings.map((warning) => h("li", {}, warning))) : null,
    chips, codeBlock(file.text, file.json, file.name),
    h("p", { class: "doc-foot" }, "Check field names, replace mined values with what you have actually seen, then measure false positives."),
    saveRow);
}

async function saveTechnique() {
  const tech = state.tech;
  try {
    const result = await api("/api/generate", { method: "POST", body: { technique: tech.selected, deterministic: true, ...tech.recipe, save: true } });
    toast(result.saved.length ? `Saved ${plural(result.saved.length, "file")} to the output folder` : "Nothing to save");
  } catch (error) {
    toast(error.message);
  }
}

async function copyActive() {
  const file = activeFile();
  if (!file) return;
  const button = $("#copy-btn");
  try {
    await navigator.clipboard.writeText(file.text);
  } catch (error) {
    toast("Copy failed: select the text in the draft instead");
    return;
  }
  button.replaceChildren(svgIcon("m5 12 5 5L20 7"), "Copied");
  clearTimeout(copyActive.timer);
  copyActive.timer = setTimeout(() => { button.replaceChildren("Copy"); }, 1600);
}

function downloadActive() {
  const file = activeFile();
  if (file) downloadText(file.name, file.text, file.json ? "application/json" : "text/yaml");
}

// ---------------------------------------------------------------------------
// Threat rail
// ---------------------------------------------------------------------------
async function searchThreats() {
  const { kind, query } = state.threat;
  let results;
  try {
    if (!query.trim()) {
      const lists = await Promise.all(THREAT_STARTERS[kind].map((id) =>
        api(`/api/search?kind=${kind}&limit=1&q=${encodeURIComponent(id)}`).then((response) => response.results)));
      results = lists.flat();
    } else {
      results = (await api(`/api/search?kind=${kind}&limit=25&q=${encodeURIComponent(query.trim())}`)).results;
    }
  } catch (error) {
    if (state.threat.kind === kind && state.threat.query === query) fill($("#threat-list"), h("p", { class: "empty-list" }, error.message));
    return;
  }
  if (state.threat.kind !== kind || state.threat.query !== query) return;
  state.threat.results = results;
  renderThreatList();
}

function renderThreatList() {
  const { results, selected, query } = state.threat;
  const n = results.length;
  $("#threat-count").textContent = query.trim()
    ? `${n} ${n === 1 ? "match" : "matches"} · on this machine only`
    : `${n} to start with · on this machine only`;
  fill($("#threat-list"), n ? results.map((profile) => {
    const gaps = state.threat.gaps[profile.id];
    const isSelected = profile.id === selected;
    return h("button", {
      class: isSelected ? "row sel" : "row", type: "button", "aria-current": isSelected ? "true" : null,
      onclick: () => selectThreat(profile.id),
    },
    h("span", { class: "rname" }, profile.name),
    h("span", { class: "rid mono" }, profile.id),
    h("span", { class: "rmeta" }, plural(profile.techniques, "technique")
      + (gaps === undefined ? "" : ` · ${plural(gaps, "SigmaHQ gap")}`)));
  }) : h("p", { class: "empty-list" }, "Nothing matches."));
}

function setKind(kind) {
  state.threat.kind = kind;
  state.threat.query = "";
  for (const seg of document.querySelectorAll(".kind")) {
    const on = seg.dataset.kind === kind;
    seg.classList.toggle("on", on);
    seg.setAttribute("aria-pressed", String(on));
  }
  $("#threat-kind-label").textContent = kind;
  const input = $("#threat-search");
  input.value = "";
  input.placeholder = PLACEHOLDERS[kind];
  searchThreats();
}

// ---------------------------------------------------------------------------
// Threat pack overview and open pack
// ---------------------------------------------------------------------------
function renderPackCards() {
  const status = state.status;
  // The totals are only true for the dataset versions they were measured on.
  const published = Boolean(status && status.attack.version === PUBLISHED_PACKS.attack
    && status.sigmahq.available && status.sigmahq.release === PUBLISHED_PACKS.sigmahq);
  fill($("#pack-cards"), PUBLISHED_PACKS.packs.map((pack) => h("button", {
    class: "card", type: "button", onclick: () => { setKind(pack.kind); selectThreat(pack.id); },
  },
  h("span", { class: "card-top" }, h("span", { class: "card-id mono" }, pack.id), h("span", { class: "pill" }, cap(pack.kind))),
  h("span", { class: "card-name" }, pack.name),
  published
    ? h("span", { class: "card-facts" }, h("span", { class: "t-strong" }, `${pack.strong} strong`), " · ",
      h("span", { class: "t-moderate" }, `${pack.moderate} moderate`), " · ", h("span", { class: "t-weak" }, `${pack.weak} weak`))
    : h("span", { class: "card-facts" }, "Open to build the pack"),
  published ? h("span", { class: "card-src" }, `${plural(pack.gaps, "technique")} with no SigmaHQ rule`) : null)));
  $("#pack-cards-caption").textContent = published
    ? `Published pack totals for ATT&CK v${PUBLISHED_PACKS.attack} and SigmaHQ ${PUBLISHED_PACKS.sigmahq}.`
    : "";
}

function packGaps(pack) {
  return pack.techniques.filter((technique) => technique.sigmahq
    && technique.sigmahq.sources.some((source) => source.usable) && !technique.sigmahq.sigmahq_rules.length).length;
}

async function selectThreat(id) {
  const threat = state.threat;
  threat.selected = id;
  threat.pack = null;
  threat.deployable = false;
  if (state.mode !== "pack") setMode("pack");
  renderThreatList();
  showView("view-pack-open");
  const request = ++threat.request;
  const known = threat.results.find((result) => result.id === id);
  fill($("#view-pack-open"), loading(`Building the pack for ${known ? known.name : id}…`));
  try {
    const pack = await api("/api/pack", { method: "POST", body: { query: id, kind: threat.kind, chains: true, deterministic: true } });
    if (request !== threat.request) return;
    threat.pack = pack;
    threat.gaps[id] = packGaps(pack);
    renderThreatList();
    renderPack();
  } catch (error) {
    if (request === threat.request) fill($("#view-pack-open"), h("p", { class: "t-gap" }, error.message));
  }
}

/** A pack technique's grade: the best of its rules and correlation rules. */
function techniqueTier(technique) {
  return bestTier(technique.rules.map((rule) => rule.quality).concat(technique.chains.map((chain) => chain.quality)));
}

function packRow(technique) {
  const coverage = technique.sigmahq;
  const usable = coverage && coverage.sources.some((source) => source.usable);
  let sigmahq;
  if (!coverage) sigmahq = h("span", { class: "t-none" }, "-");
  else if (!usable) sigmahq = h("span", { class: "t-none" }, "Not in Sigma");
  else if (!coverage.sigmahq_rules.length) sigmahq = h("span", { class: "t-gap" }, "No rules");
  else sigmahq = h("span", {}, plural(coverage.sigmahq_rules.length, "rule") + (coverage.gaps.length ? `, ${plural(coverage.gaps.length, "gap")}` : ""));
  return h("tr", {},
    h("td", {}, h("span", { class: "td-id mono" }, technique.id), h("span", { class: "td-name" }, technique.name)),
    h("td", {}, gradePill(techniqueTier(technique))),
    h("td", {}, sigmahq),
    h("td", { class: "num mono" }, String(technique.rules.length + technique.chains.length)),
    h("td", {}, h("button", { class: "btn btn-outline", type: "button", onclick: () => openDraft(technique.id) }, "Open draft")));
}

function renderPack() {
  const pack = state.threat.pack;
  const profile = pack.profile;
  const summary = pack.summary;
  const quality = summary.quality;
  const segment = (cls, n) => { const el = h("span", { class: cls }); el.style.flex = `${n} 1 0`; return el; };
  const stat = (label, value) => h("div", { class: "stat" }, h("span", { class: "stat-l" }, label), h("span", { class: "stat-v mono" }, String(value)));

  const rows = pack.techniques.filter((technique) => !state.threat.deployable
    || ["strong", "moderate"].includes(techniqueTier(technique)));
  const deployable = h("button", {
    class: state.threat.deployable ? "tog on" : "tog", type: "button", "aria-pressed": String(state.threat.deployable),
    onclick: () => { state.threat.deployable = !state.threat.deployable; renderPack(); },
  }, "Deployable only");

  const aliases = profile.aliases.filter((alias) => alias !== profile.name).slice(0, 6);
  const unmatched = summary.insufficient_evidence + summary.unmappable;
  const saveButton = state.runtime === "browser" ? null
    : h("button", { class: "btn btn-outline", type: "button", id: "pack-save-btn", onclick: savePack }, "Save to output folder");

  fill($("#view-pack-open"),
    h("div", { class: "title-row" },
      h("div", {},
        h("p", { class: "title-meta" }, h("span", { class: "mono" }, profile.id),
          ` · ${aliases.length ? aliases.join(", ") : cap(profile.kind)}`),
        h("h1", { class: "h1" }, profile.name),
        h("p", { class: "title-note" }, firstSentence(profile.description, 320))),
      h("div", { class: "title-actions" }, saveButton,
        h("button", { class: "btn btn-primary", type: "button", id: "pack-zip-btn", onclick: downloadPack }, "Download pack"))),
    h("div", { class: "stats" },
      stat("Techniques", summary.techniques), stat("Sigma rules", summary.rules),
      stat("Correlations", summary.correlation_rules), stat("SigmaHQ gaps", pack.sigmahq_release ? packGaps(pack) : "-")),
    h("div", { class: "section" },
      h("h2", { class: "h2" }, "Quality split"),
      h("div", { class: "qbar", role: "img", "aria-label": `${quality.strong} strong, ${quality.moderate} moderate, ${quality.weak} weak` },
        segment("q-s", quality.strong), segment("q-m", quality.moderate), segment("q-w", quality.weak)),
      h("div", { class: "q-counts" },
        h("span", {}, h("span", { class: "t-strong mono" }, String(quality.strong)), " strong"),
        h("span", {}, h("span", { class: "t-moderate mono" }, String(quality.moderate)), " moderate"),
        h("span", {}, h("span", { class: "mono" }, String(quality.weak)), " weak")),
      h("p", { class: "caption" }, "Pack totals, generated on this machine. Rules and correlation rules are graded alike."),
      summary.insufficient_evidence
        ? h("p", { class: "sub" }, `${plural(summary.insufficient_evidence, "technique")} skipped — ATT&CK gives no concrete values.`)
        : null),
    h("div", { class: "section panel" },
      h("div", { class: "tbl-head" }, h("h2", { class: "h2" }, "Techniques in this pack"), deployable),
      h("div", { class: "tbl-wrap" },
        h("table", { class: "pack" },
          h("thead", {}, h("tr", {},
            h("th", { scope: "col" }, "Technique"), h("th", { scope: "col" }, "Grade"), h("th", { scope: "col" }, "SigmaHQ"),
            h("th", { scope: "col", class: "num" }, "Rules"), h("th", { scope: "col" }, h("span", { class: "sr-only" }, "Open")))),
          h("tbody", {}, rows.map(packRow)))),
      h("p", { class: "tbl-foot" }, unmatched
        ? `${plural(unmatched, "attributed technique")} ${unmatched === 1 ? "has" : "have"} no rule: `
          + `${summary.insufficient_evidence} with no concrete values in ATT&CK, ${summary.unmappable} not expressible as Sigma.`
        : "Every attributed technique has a rule.")));
}

function openDraft(id) {
  state.tech.query = "";
  $("#technique-search").value = "";
  setMode("technique");
  searchTechniques();
  selectTechnique(id);
}

function packBody(save) {
  return { query: state.threat.selected, kind: state.threat.kind, chains: true, deterministic: true, save };
}

async function downloadPack() {
  const button = $("#pack-zip-btn");
  button.disabled = true;
  button.textContent = "Preparing ZIP…";
  try {
    const blob = await api("/api/pack.zip", { method: "POST", body: packBody(false) });
    downloadBlob(`${state.threat.pack.slug}.zip`, blob);
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Download pack";
  }
}

async function savePack() {
  try {
    const pack = await api("/api/pack", { method: "POST", body: packBody(true) });
    toast(pack.saved_to ? `Saved to ${pack.saved_to}` : "Nothing to save");
  } catch (error) {
    toast(error.message);
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
function goHome() {
  state.tech.selected = null;
  state.tech.query = "";
  $("#technique-search").value = "";
  setMode("technique");
  searchTechniques();
}

function init() {
  state.runtime = document.body.dataset.wheel ? "browser" : "server";
  for (const tab of document.querySelectorAll(".tab")) tab.addEventListener("click", () => setMode(tab.dataset.view));
  $("#brand").addEventListener("click", goHome);
  for (const button of document.querySelectorAll("[data-open-technique]")) {
    button.addEventListener("click", () => selectTechnique(button.dataset.openTechnique));
  }

  const runTechniqueSearch = debounce(searchTechniques, 160);
  $("#technique-search").addEventListener("input", (event) => { state.tech.query = event.target.value; runTechniqueSearch(); });
  $("#technique-search").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && state.tech.results[0]) { event.preventDefault(); selectTechnique(state.tech.results[0].id); }
  });
  const runThreatSearch = debounce(searchThreats, 160);
  $("#threat-search").addEventListener("input", (event) => { state.threat.query = event.target.value; runThreatSearch(); });
  $("#threat-search").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && state.threat.results[0]) { event.preventDefault(); selectThreat(state.threat.results[0].id); }
  });
  for (const seg of document.querySelectorAll(".kind")) seg.addEventListener("click", () => setKind(seg.dataset.kind));

  for (const toggle of document.querySelectorAll("#recipe .tog")) {
    toggle.addEventListener("click", () => {
      const key = toggle.dataset.option;
      state.tech.recipe[key] = !state.tech.recipe[key];
      toggle.classList.toggle("on", state.tech.recipe[key]);
      toggle.setAttribute("aria-pressed", String(state.tech.recipe[key]));
      scheduleRegenerate();
    });
  }
  $("#level-select").addEventListener("change", (event) => { state.tech.recipe.level = event.target.value; scheduleRegenerate(); });
  $("#tlp-select").addEventListener("change", (event) => { state.tech.recipe.tlp = event.target.value; scheduleRegenerate(); });
  $("#copy-btn").addEventListener("click", copyActive);
  $("#download-btn").addEventListener("click", downloadActive);

  // "/" focuses the active search, unless the user is already typing somewhere.
  document.addEventListener("keydown", (event) => {
    if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
    const target = event.target;
    if (target && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))) return;
    event.preventDefault();
    $(state.mode === "technique" ? "#technique-search" : "#threat-search").focus();
  });

  if (location.hash === "#pack") setMode("pack");
  loadStatus().catch((error) => { fill($("#datasets"), h("span", { class: "off" }, error.message)); });
  searchTechniques();
  searchThreats();
  renderExamples();
  renderPackCards();
}

document.addEventListener("DOMContentLoaded", init);
