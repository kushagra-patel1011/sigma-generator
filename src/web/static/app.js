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
    else if (key === "text") el.textContent = value;
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

function debounce(fn, wait = 180) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), wait); };
}

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 2200);
}

function downloadText(filename, text, type = "text/yaml") {
  downloadBlob(filename, new Blob([text], { type: `${type};charset=utf-8` }));
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const link = h("a", { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied to clipboard");
  } catch {
    toast("Copy failed - select the text manually");
  }
}

function loading(message) {
  return h("div", { class: "loading" }, h("span", { class: "spinner", "aria-hidden": "true" }), message);
}

function alertBox(kind, message) {
  return h("div", { class: `alert ${kind}`, role: kind === "error" ? "alert" : null }, message);
}

function levelPill(level) {
  return h("span", { class: "level" }, `level ${level}`);
}

const TIER_HELP = {
  strong: "Two or more independent behavioural signals",
  moderate: "One behavioural signal - review for noise",
  weak: "Matches broad activity - for threat hunting, not alerting",
  placeholder: "Skeleton - no concrete values yet; matches nothing until completed",
};

function tierPill(tier, reasons) {
  const title = [TIER_HELP[tier], ...(reasons || [])].filter(Boolean).join(" \u2014 ");
  return h("span", { class: `pill tier-${tier}`, title }, tier === "placeholder" ? "skeleton" : tier);
}


/** Minimal YAML highlighting built from DOM nodes (no innerHTML). */
function yamlBlock(text) {
  const pre = h("pre", { class: "yaml", tabindex: "0" });
  for (const line of text.split("\n")) {
    if (line.trimStart().startsWith("#")) {
      pre.append(h("span", { class: "c" }, line), "\n");
      continue;
    }
    if (line === "---") {
      pre.append(h("span", { class: "sep" }, line), "\n");
      continue;
    }
    const match = line.match(/^(\s*(?:- )?)([A-Za-z0-9_.|\-]+)(:)(.*)$/);
    if (match) {
      const [, indent, key, colon, rest] = match;
      pre.append(indent, h("span", { class: "k" }, key), colon);
      pre.append(/^\s*'.*'$/.test(rest) ? h("span", { class: "s" }, rest) : rest, "\n");
    } else {
      const item = line.match(/^(\s*- )('.*')$/);
      if (item) pre.append(item[1], h("span", { class: "s" }, item[2]), "\n");
      else pre.append(line, "\n");
    }
  }
  return pre;
}

function setOptions(select, values, keepFirst = true) {
  const first = keepFirst ? select.options[0] : null;
  select.replaceChildren(...(first ? [first] : []));
  for (const value of values) {
    const [val, label] = Array.isArray(value) ? value : [value, value];
    select.append(h("option", { value: val }, label));
  }
}

function formValues(form) {
  const values = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    values[el.name] = el.type === "checkbox" ? el.checked : el.value;
  }
  return values;
}

// ---------------------------------------------------------------------------
// Search box with keyboard navigation
// ---------------------------------------------------------------------------
function attachSearch({ input, list, fetchResults, renderItem, onPick }) {
  let items = [];
  let active = -1;

  const close = () => { list.hidden = true; active = -1; input.setAttribute("aria-expanded", "false"); };
  const highlight = () => {
    [...list.children].forEach((li, index) => li.setAttribute("aria-selected", String(index === active)));
  };
  const pick = (item) => { close(); onPick(item); };

  const run = debounce(async () => {
    const query = input.value.trim();
    if (!query) { close(); return; }
    try {
      items = await fetchResults(query);
    } catch (error) {
      items = [];
      list.replaceChildren(h("li", { class: "empty" }, error.message));
      list.hidden = false;
      return;
    }
    active = items.length ? 0 : -1;
    list.replaceChildren(...(items.length
      ? items.map((item, index) => {
          const li = renderItem(item);
          li.setAttribute("role", "option");
          li.addEventListener("mousedown", (event) => { event.preventDefault(); pick(items[index]); });
          return li;
        })
      : [h("li", { class: "empty" }, "No matches")]));
    highlight();
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
  });

  input.addEventListener("input", run);
  input.addEventListener("focus", () => { if (input.value.trim()) run(); });
  input.addEventListener("blur", () => setTimeout(close, 120));
  input.addEventListener("keydown", (event) => {
    if (list.hidden || !items.length) {
      if (event.key === "Enter") { event.preventDefault(); run(); }
      return;
    }
    if (event.key === "ArrowDown") { active = (active + 1) % items.length; highlight(); event.preventDefault(); }
    else if (event.key === "ArrowUp") { active = (active - 1 + items.length) % items.length; highlight(); event.preventDefault(); }
    else if (event.key === "Enter") { event.preventDefault(); if (active >= 0) pick(items[active]); }
    else if (event.key === "Escape") close();
  });
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------
const state = {
  status: null,
  technique: null,       // detail payload for the selected technique
  lastTechniqueRequest: null,
  threatKind: "group",
  threat: null,
  lastPackRequest: null,
};

// ---------------------------------------------------------------------------
// Header / dataset status
// ---------------------------------------------------------------------------
async function loadStatus() {
  const status = await api("/api/status");
  state.status = status;
  const sigmahq = status.sigmahq;
  $("#datasets").replaceChildren(
    h("span", {}, `ATT&CK v${status.attack.version}`),
    h("span", { class: sigmahq.available ? null : "off" },
      sigmahq.available ? `SigmaHQ ${sigmahq.release}` : "SigmaHQ not downloaded"),
    h("span", {}, `v${status.version}`),
  );

  const notice = $("#sigmahq-notice");
  if (!sigmahq.available) {
    const button = h("button", { class: "btn small", type: "button", disabled: status.offline }, "Download SigmaHQ index (3 MB)");
    button.addEventListener("click", async () => {
      button.disabled = true;
      button.textContent = "Downloading...";
      try {
        const result = await api("/api/sigmahq/update", { method: "POST", body: {} });
        toast(`SigmaHQ ${result.release}: ${result.rules} rules indexed`);
        await loadStatus();
        if (state.technique) selectTechnique(state.technique.id);
      } catch (error) {
        button.disabled = false;
        button.textContent = "Retry download";
        toast(error.message);
      }
    });
    fill(notice,
      h("span", {}, status.offline
        ? "SigmaHQ gap checks are unavailable offline. Run `python -m src.main update --sigmahq-only` once."
        : "Gap checks compare ATT&CK's recommended telemetry with SigmaHQ's community rules."),
      status.offline ? null : button,
    );
    notice.hidden = false;
  } else {
    notice.hidden = true;
  }
  for (const form of [$("#technique-form"), $("#pack-form")]) {
    const gaps = form.elements.gaps_only;
    gaps.disabled = !sigmahq.available && status.offline;
    setOptions(form.elements.level, status.choices.levels);
    setOptions(form.elements.tlp, status.choices.tlp.filter((t) => t !== "white").map((t) => [t, `TLP:${t.toUpperCase()}`]), false);
    form.elements.tlp.value = "amber";
  }
}

// ---------------------------------------------------------------------------
// Technique view
// ---------------------------------------------------------------------------
function coverageFor(detail) {
  const map = new Map();
  const coverage = detail.sigmahq;
  if (!coverage) return map;
  for (const source of coverage.sources) {
    map.set(`${source.analytic}|${source.attack_log_source}`, source);
  }
  return map;
}

function clampable(text) {
  const description = h("p", { class: "desc clamped" }, text);
  const more = h("button", { class: "linkish", type: "button" }, "Show more");
  more.addEventListener("click", () => {
    description.classList.toggle("clamped");
    more.textContent = description.classList.contains("clamped") ? "Show more" : "Show less";
  });
  return [description, more];
}

function renderTechniqueDetail(detail) {
  const container = $("#technique-detail");
  container.classList.remove("empty-state");
  const coverage = coverageFor(detail);
  const [description, more] = clampable(detail.description.split("\n")[0]);

  const telemetry = h("div", { class: "telemetry" });
  for (const strategy of detail.detection_strategies) {
    for (const analytic of strategy.analytics) {
      const rows = h("ul", { class: "tel-list" });
      for (const source of analytic.log_sources) {
        const label = source.channel ? `${source.name} (${source.channel})` : source.name;
        const verdict = coverage.get(`${analytic.id}|${label}`);
        let status = null;
        if (!source.mappable) status = h("span", { class: "pill" }, "not Sigma");
        else if (!detail.sigmahq) status = null;
        else if (verdict && verdict.covered_by.length) {
          status = h("span", { class: "pill ok", title: "SigmaHQ rules watch this log source" },
            `${verdict.covered_by.length} SigmaHQ`);
        } else status = h("span", { class: "pill gap", title: "No SigmaHQ rule for this technique on this log source" }, "gap");
        const logsource = Object.values(source.sigma_logsource).join(" / ");
        rows.append(h("li", { class: "tel-row" },
          h("div", { class: "tel-text" },
            h("div", { class: "tel-src" }, label),
            h("div", { class: "tel-map" }, source.mappable
              ? [h("code", {}, logsource || "no Sigma log source"), ` · ${Math.round(source.confidence * 100)}% confidence`]
              : "no Sigma log source")),
          status));
      }
      telemetry.append(
        h("p", { class: "analytic-head" }, h("code", {}, analytic.id), ` ${analytic.platforms.join(", ") || "any platform"}`),
        rows);
    }
  }

  const sigmahq = detail.sigmahq;
  const coverageSummary = sigmahq
    ? h("p", { class: "status-line" },
        h("span", { class: `pill ${sigmahq.status === "covered" ? "ok" : sigmahq.status === "partial" ? "warn" : "gap"}` },
          sigmahq.status),
        ` ${Math.round(sigmahq.coverage_ratio * 100)}% of these covered by SigmaHQ · `
          + `${sigmahq.sigmahq_rules.length} rule(s) tagged ${detail.id}`)
    : null;

  fill(container,
    h("p", { class: "eyebrow" }, detail.id, detail.parent ? ` · sub-technique of ${detail.parent.id}` : ""),
    h("h2", { class: "detail-title" }, detail.name),
    h("p", { class: "tags" },
      detail.tactics.map((t) => h("span", { class: "tag" }, t)),
      detail.platforms.map((p) => h("span", { class: "tag plain" }, p))),
    detail.revoked ? alertBox("warn", `Revoked in ATT&CK${detail.revoked_by ? ` - replaced by ${detail.revoked_by}` : ""}.`) : null,
    description,
    h("p", { class: "desc-links" }, more, " · ",
      h("a", { href: detail.url, target: "_blank", rel: "noopener noreferrer" }, "ATT&CK page")),
    telemetry.childElementCount
      ? h("details", { class: "tel-details", open: window.matchMedia("(min-width: 960px)").matches },
          h("summary", { class: "section-title" }, "Recommended log sources ",
            h("span", { class: "muted" }, `(${telemetry.querySelectorAll(".tel-row").length})`)),
          coverageSummary, telemetry)
      : [h("h3", { class: "section-title" }, "Recommended log sources"), coverageSummary,
         h("p", { class: "muted" }, "ATT&CK attaches no detection analytic to this technique.")],
  );

  const form = $("#technique-form");
  const analytics = detail.detection_strategies.flatMap((s) => s.analytics);
  setOptions(form.elements.platform, detail.platforms);
  setOptions(form.elements.analytic, analytics.map((a) => [a.id, `${a.id} · ${a.platforms.join(", ") || "any"}`]));
  form.hidden = false;
  $("#save-technique-btn").disabled = true;
}

async function selectTechnique(id) {
  $("#technique-detail").replaceChildren(loading(`Loading ${id}...`));
  try {
    const detail = await api(`/api/technique/${encodeURIComponent(id)}`);
    state.technique = detail;
    $("#technique-search").value = `${detail.id} ${detail.name}`;
    renderTechniqueDetail(detail);
    $("#technique-output").replaceChildren(h("p", { class: "hint" },
      `Choose options, then press Generate rules to build the rules for ${detail.id}.`));
  } catch (error) {
    $("#technique-detail").replaceChildren(alertBox("error", error.message));
  }
}

function matchList(matches) {
  if (!matches || !matches.length) return null;
  const rows = matches.map((row) => {
    const values = row.values.map((v, i) => [i ? h("span", { class: "or" }, " or ") : null, h("code", {}, v)]).flat().filter(Boolean);
    if (row.more) values.push(h("span", { class: "or" }, ` +${row.more} more`));
    return h("tr", { class: row.event ? "is-event" : null },
      h("th", { scope: "row" }, h("code", {}, row.field)),
      h("td", {}, ...values, row.optional ? h("span", { class: "note" }, "any of these") : null));
  });
  return h("div", { class: "matches" },
    h("h4", {}, "What it matches"),
    h("div", { class: "scroll-x" }, h("table", { class: "kv" }, h("tbody", {}, rows))));
}

function fileActions(filename, text, type) {
  return h("div", { class: "result-actions" },
    h("button", { class: "btn small", type: "button", onclick: () => copyText(text) }, "Copy"),
    h("button", { class: "btn small", type: "button", onclick: () => downloadText(filename, text, type) }, "Download"));
}

function ruleCard(rule) {
  const isChain = rule.kind === "chain";
  const isCount = isChain && rule.correlation_kind === "count";
  const valid = rule.problems.length === 0;
  const tier = rule.quality.tier;
  const kind = isCount ? "Count threshold" : isChain ? "Attack chain" : "Sigma rule";

  const card = h("article", { class: "result" },
    h("div", { class: "result-head" },
      h("div", { class: "result-heading" },
        h("p", { class: "result-kind" }, isChain ? `${kind} · ${rule.correlation_type}` : kind),
        h("h3", {}, rule.title)),
      fileActions(rule.filename, rule.yaml)),
    h("p", { class: "result-meta" },
      tierPill(tier, rule.quality.reasons),
      valid
        ? h("span", { class: "pill ok", title: rule.pysigma_checked ? "Passed the built-in validator and pySigma" : "Passed the built-in validator" },
            rule.pysigma_checked ? "valid (pySigma)" : "valid")
        : h("span", { class: "pill gap" }, `${rule.problems.length} problem(s)`),
      h("span", {}, "Level ", h("strong", {}, rule.level)),
      h("span", {}, "Log source ", h("code", {}, rule.logsource)),
      rule.analytic ? h("span", {}, "Analytic ", h("code", {}, rule.analytic)) : null,
      h("span", {}, `Confidence ${Math.round(rule.confidence * 100)}%`)),
    h("p", { class: "result-why" }, `${tier === "placeholder" ? "Skeleton" : tier[0].toUpperCase() + tier.slice(1)}: `
      + (rule.quality.reasons.join("; ") || rule.quality.meaning)),
  );

  if (isCount) {
    const condition = rule.condition || {};
    const counted = condition.field ? `distinct ${condition.field} values` : "matching events";
    card.append(h("p", { class: "chain-summary" },
      `Fires when ${condition.gte} or more ${counted} occur within ${rule.timespan}, per ${rule.group_by.join(", ")}. Counted event: `,
      h("code", {}, rule.steps[0].logsource), "."));
    card.append(matchList(rule.steps[0].matches));
  } else if (isChain) {
    card.append(h("p", { class: "chain-summary" },
      `Fires when all ${rule.steps.length} steps occur within ${rule.timespan} on the same ${rule.group_by.join(", ")}.`));
    card.append(h("ol", { class: "steps" }, rule.steps.map((step) => {
      const example = step.matches[0] && step.matches[0].values[0];
      return h("li", {}, h("code", {}, step.logsource), example ? h("span", { class: "step-value" }, example) : null);
    })));
  } else {
    card.append(matchList(rule.matches));
  }
  if (!valid) card.append(alertBox("error", rule.problems.join("; ")));
  if (rule.notes.length) card.append(h("ul", { class: "notes" }, rule.notes.map((n) => h("li", {}, n))));

  const lines = rule.yaml.split("\n").length;
  const details = h("details", { class: "yaml-details" },
    h("summary", {}, "YAML ", h("code", {}, rule.filename), h("span", { class: "muted" }, ` · ${lines} lines`)));
  details.addEventListener("toggle", () => {
    if (details.open && details.childElementCount === 1) details.append(yamlBlock(rule.yaml));
  });
  card.append(details);
  return card;
}

function bundleCard(bundle) {
  const counts = Object.entries(bundle.objects).map(([type, count]) => `${count} ${type}`).join(", ");
  return h("article", { class: "result" },
    h("div", { class: "result-head" },
      h("div", { class: "result-heading" },
        h("p", { class: "result-kind" }, "STIX 2.1 bundle"),
        h("h3", {}, bundle.filename)),
      fileActions(bundle.filename, bundle.json, "application/json")),
    h("p", { class: "result-meta" },
      bundle.problems.length ? h("span", { class: "pill gap" }, `${bundle.problems.length} problem(s)`)
        : h("span", { class: "pill ok" }, "valid STIX 2.1"),
      h("span", {}, "Indicators use pattern type ", h("code", {}, "sigma"))),
    h("p", { class: "result-why" }, `Objects: ${counts}`));
}

function renderTechniqueResult(result) {
  const output = $("#technique-output");
  const parts = [];
  for (const warning of result.warnings) parts.push(alertBox("warn", warning));
  if (result.status === "covered") parts.push(alertBox("ok", result.reason));
  if (result.status === "insufficient") parts.push(alertBox("warn", result.reason));
  if (result.status === "unmappable" || result.status === "error") parts.push(alertBox("error", result.reason));
  if (result.saved.length) parts.push(alertBox("ok", `Saved ${result.saved.length} file(s) to the output folder.`));
  const files = result.chains.length + result.rules.length + (result.bundle ? 1 : 0);
  if (files) parts.push(h("h2", { class: "results-title" }, `${files} file${files === 1 ? "" : "s"}`));
  for (const chain of result.chains) parts.push(ruleCard(chain));
  for (const rule of result.rules) parts.push(ruleCard(rule));
  if (result.bundle) parts.push(bundleCard(result.bundle));
  if (!parts.length) parts.push(alertBox("warn", "Nothing was generated."));
  output.replaceChildren(...parts);
  $("#save-technique-btn").disabled = !(result.rules.length || result.chains.length);
}

async function generateTechnique(save = false) {
  if (!state.technique) return;
  const values = formValues($("#technique-form"));
  const body = { technique: state.technique.id, ...values, save };
  state.lastTechniqueRequest = body;
  $("#generate-btn").disabled = true;
  $("#technique-output").replaceChildren(loading(save ? "Saving..." : `Generating detections for ${state.technique.id}...`));
  try {
    renderTechniqueResult(await api("/api/generate", { method: "POST", body }));
    if (save) toast("Saved to the output folder");
  } catch (error) {
    $("#technique-output").replaceChildren(alertBox("error", error.message));
  } finally {
    $("#generate-btn").disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Threat pack view
// ---------------------------------------------------------------------------
function renderThreatDetail(profile) {
  const container = $("#threat-detail");
  container.classList.remove("empty-state");
  const [description, more] = clampable(profile.description);
  const techniques = h("p", { class: "tags" },
    profile.techniques.slice(0, 40).map((t) => h("span", { class: "tag plain mono", title: t.name }, t.id)),
    profile.techniques.length > 40 ? h("span", { class: "muted" }, ` +${profile.techniques.length - 40} more`) : null);
  fill(container,
    h("p", { class: "eyebrow" }, `${profile.id} · ${profile.kind}`),
    h("h2", { class: "detail-title" }, profile.name),
    profile.aliases.length ? h("p", { class: "muted" }, `Also known as ${profile.aliases.slice(0, 10).join(", ")}`) : null,
    description,
    h("p", { class: "desc-links" }, more, " · ",
      h("a", { href: profile.url, target: "_blank", rel: "noopener noreferrer" }, "ATT&CK page")),
    h("h3", { class: "section-title" }, `${profile.techniques.length} techniques attributed`),
    techniques,
    profile.campaigns.length ? h("p", { class: "muted" }, `Attributed campaigns: ${profile.campaigns.join(", ")}`) : null,
  );
  $("#pack-form").hidden = false;
  $("#with-campaigns-toggle").hidden = profile.kind !== "group" || !profile.campaigns.length;
  $("#pack-zip-btn").disabled = true;
  $("#pack-save-btn").disabled = true;
  $("#pack-output").replaceChildren(h("p", { class: "hint" },
    `Press Build pack to generate detections for all ${profile.techniques.length} techniques.`));
}

async function selectThreat(item) {
  $("#threat-detail").replaceChildren(loading(`Loading ${item.id}...`));
  try {
    const profile = await api(`/api/threat/${encodeURIComponent(item.id)}?kind=${state.threatKind}`);
    state.threat = profile;
    $("#threat-search").value = `${profile.id} ${profile.name}`;
    renderThreatDetail(profile);
  } catch (error) {
    $("#threat-detail").replaceChildren(alertBox("error", error.message));
  }
}

function statTile(label, value, tone = "") {
  return h("div", { class: `stat ${tone}` }, h("dt", {}, label), h("dd", {}, String(value)));
}

const STATUS_TEXT = {
  "generated": "Rules written",
  "insufficient evidence": "No concrete values",
  "unmappable": "Not expressible as Sigma",
};

function statusText(status) {
  if (STATUS_TEXT[status]) return STATUS_TEXT[status];
  const text = status.replace(/_/g, " ");
  return text[0].toUpperCase() + text.slice(1);
}

function renderPack(pack) {
  const summary = pack.summary;
  const noSigmahq = pack.techniques.filter((t) => t.sigmahq && t.sigmahq.sources.some((s) => s.usable) && t.sigmahq.sigmahq_rules.length === 0).length;
  const parts = [];
  if (pack.saved_to) parts.push(alertBox("ok", `Saved to ${pack.saved_to}`));
  if (pack.bundle_errors.length) parts.push(alertBox("error", `STIX bundle problems: ${pack.bundle_errors.join("; ")}`));

  parts.push(h("dl", { class: "stats" },
    statTile("Techniques", summary.techniques),
    statTile("Sigma rules", summary.rules),
    statTile("Correlation rules", summary.correlation_rules),
    statTile("Strong / moderate / weak", `${summary.quality.strong} / ${summary.quality.moderate} / ${summary.quality.weak}`),
    pack.sigmahq_release ? statTile("No SigmaHQ rule", noSigmahq, noSigmahq ? "danger" : "") : null,
    pack.options.gaps_only ? statTile("Fully covered, skipped", summary.covered_by_sigmahq) : null,
    statTile("No concrete values", summary.insufficient_evidence),
    statTile("Not expressible as Sigma", summary.unmappable),
  ));

  const columns = ["Technique", "Name", "Rule quality", "Correlations", "SigmaHQ", "Status"];
  const tbody = h("tbody");
  let filter = "all";
  const rows = [];
  for (const technique of pack.techniques) {
    const cov = technique.sigmahq;
    const sigmahqCell = !cov ? h("span", { class: "muted" }, "-")
      : !cov.sources.some((s) => s.usable) ? h("span", { class: "muted" }, "n/a")
      : cov.sigmahq_rules.length === 0 ? h("span", { class: "text-danger" }, "No rules")
      : h("span", { class: cov.gaps.length ? "text-warn" : "text-ok" },
          `${cov.sigmahq_rules.length} rule${cov.sigmahq_rules.length === 1 ? "" : "s"}`
          + (cov.gaps.length ? `, ${cov.gaps.length} gap${cov.gaps.length === 1 ? "" : "s"}` : ""));
    const cell = (index, ...content) => h("td", { "data-label": columns[index] }, ...content);
    const row = h("tr", { class: "row", tabindex: "0", "aria-expanded": "false" },
      cell(0, h("span", { class: "chev", "aria-hidden": "true" }), h("code", {}, technique.id)),
      cell(1, technique.name, h("div", { class: "muted small" }, technique.tactics.join(", "))),
      cell(2, technique.rules.length ? technique.rules.map((r) => tierPill(r.quality)) : h("span", { class: "muted" }, "-")),
      cell(3, String(technique.chains.length)),
      cell(4, sigmahqCell),
      cell(5, h("span", { class: technique.status === "generated" ? null : "muted" }, statusText(technique.status))));
    const filesRow = h("tr", { class: "expanded", hidden: true }, h("td", { class: "files", colspan: "6" }));

    const toggle = () => {
      const open = filesRow.hidden;
      filesRow.hidden = !open;
      row.setAttribute("aria-expanded", String(open));
      if (open && !filesRow.firstChild.childElementCount) {
        const target = filesRow.firstChild;
        for (const procedure of technique.procedures.slice(0, 2)) {
          target.append(h("blockquote", { class: "procedure" }, procedure));
        }
        if (technique.reason) target.append(h("p", { class: "muted" }, technique.reason));
        for (const file of [...technique.chains, ...technique.rules]) {
          const path = `sigma/${file.file}`;
          const text = pack.rule_files[path] || "";
          target.append(h("div", { class: "file-block" },
            h("div", { class: "file-head" },
              h("div", { class: "file-name" }, tierPill(file.quality), levelPill(file.level), h("code", {}, file.file)),
              fileActions(file.file, text)),
            yamlBlock(text)));
        }
      }
    };
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggle(); } });
    rows.push({ technique, row, filesRow });
    tbody.append(row, filesRow);
  }

  const applyFilter = () => {
    for (const { technique, row, filesRow } of rows) {
      const cov = technique.sigmahq;
      const show = filter === "all"
        || (filter === "generated" && (technique.rules.length || technique.chains.length))
        || (filter === "chains" && technique.chains.length)
        || (filter === "deployable" && technique.rules.some((r) => r.quality === "strong" || r.quality === "moderate"))
        || (filter === "gaps" && cov && cov.sources.some((s) => s.usable) && cov.sigmahq_rules.length === 0)
        || (filter === "skipped" && technique.status !== "generated");
      row.hidden = !show;
      if (!show) filesRow.hidden = true;
    }
  };
  const filters = [["all", "All"], ["generated", "With rules"], ["deployable", "Strong or moderate"], ["chains", "With correlations"],
    ...(pack.sigmahq_release ? [["gaps", "No SigmaHQ rule"]] : []), ["skipped", "Not generated"]];
  const group = h("div", { class: "filter", role: "group", "aria-label": "Show techniques" });
  for (const [key, label] of filters) {
    const button = h("button", { class: `filter-btn${key === filter ? " is-active" : ""}`, type: "button",
      "aria-pressed": String(key === filter) }, label);
    button.addEventListener("click", () => {
      filter = key;
      for (const other of group.children) {
        other.classList.toggle("is-active", other === button);
        other.setAttribute("aria-pressed", String(other === button));
      }
      applyFilter();
    });
    group.append(button);
  }

  parts.push(h("div", { class: "panel pack-table" },
    h("div", { class: "filter-bar" }, group,
      h("span", { class: "muted small" }, `ATT&CK v${pack.attack_version}${pack.sigmahq_release ? ` · SigmaHQ ${pack.sigmahq_release}` : ""}`)),
    h("table", { class: "pack" },
      h("thead", {}, h("tr", {}, columns.map((c) => h("th", { scope: "col" }, c)))),
      tbody)));
  $("#pack-output").replaceChildren(...parts);
}

function packBody(save = false) {
  return { query: state.threat.id, kind: state.threatKind, ...formValues($("#pack-form")), save };
}

async function buildPack(save = false) {
  if (!state.threat) return;
  const body = packBody(save);
  state.lastPackRequest = body;
  $("#pack-btn").disabled = true;
  $("#pack-output").replaceChildren(loading(`${save ? "Saving" : "Building"} the detection pack for ${state.threat.name}...`));
  try {
    const pack = await api("/api/pack", { method: "POST", body });
    renderPack(pack);
    $("#pack-zip-btn").disabled = !pack.summary.techniques_with_rules;
    $("#pack-save-btn").disabled = !pack.summary.techniques_with_rules;
    if (save) toast("Pack saved to the output folder");
  } catch (error) {
    $("#pack-output").replaceChildren(alertBox("error", error.message));
  } finally {
    $("#pack-btn").disabled = false;
  }
}

async function downloadPackZip() {
  if (!state.threat) return;
  const button = $("#pack-zip-btn");
  button.disabled = true;
  button.textContent = "Preparing ZIP...";
  try {
    const blob = await api("/api/pack.zip", { method: "POST", body: packBody(false) });
    const slug = `${state.threat.id}_${state.threat.name}`.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
    downloadBlob(`${slug}.zip`, blob);
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Download ZIP";
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
function switchView(view) {
  for (const tab of document.querySelectorAll(".tab")) {
    const active = tab.dataset.view === view;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  }
  $("#view-technique").hidden = view !== "technique";
  $("#view-pack").hidden = view !== "pack";
  history.replaceState(null, "", `#${view}`);
}

function exampleButtons(container, examples, onPick) {
  container.replaceChildren(h("span", { class: "muted" }, "Examples: "),
    ...examples.map(([id, label], index) => [index ? ", " : null,
      h("button", { class: "linkish", type: "button", onclick: () => onPick(id) }, label)]).flat().filter(Boolean));
}

function init() {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  }
  if (location.hash === "#pack") switchView("pack");

  attachSearch({
    input: $("#technique-search"),
    list: $("#technique-results"),
    fetchResults: async (q) => (await api(`/api/search?kind=technique&q=${encodeURIComponent(q)}`)).results,
    renderItem: (t) => h("li", {}, h("span", { class: "rid" }, t.id), h("span", { class: "rname" }, t.name),
      h("span", { class: "rmeta" }, t.tactics.join(", "))),
    onPick: (t) => selectTechnique(t.id),
  });
  exampleButtons($("#technique-examples"),
    [["T1003.001", "LSASS dumping"], ["T1547.001", "Run keys"], ["T1621", "MFA fatigue"], ["T1059.001", "PowerShell"]],
    selectTechnique);

  attachSearch({
    input: $("#threat-search"),
    list: $("#threat-results"),
    fetchResults: async (q) => (await api(`/api/search?kind=${state.threatKind}&q=${encodeURIComponent(q)}`)).results,
    renderItem: (p) => h("li", {}, h("span", { class: "rid" }, p.id), h("span", { class: "rname" }, p.name),
      h("span", { class: "rmeta" }, `${p.techniques} techniques`)),
    onPick: selectThreat,
  });
  const threatExamples = {
    group: [["G0016", "APT29"], ["G0032", "Lazarus Group"], ["G0034", "Sandworm Team"]],
    software: [["S0002", "Mimikatz"], ["S0154", "Cobalt Strike"]],
    campaign: [["C0024", "SolarWinds Compromise"]],
  };
  const setKind = (kind) => {
    state.threatKind = kind;
    for (const seg of document.querySelectorAll(".seg")) {
      const active = seg.dataset.kind === kind;
      seg.classList.toggle("is-active", active);
      seg.setAttribute("aria-checked", String(active));
    }
    $("#threat-kind-label").textContent = kind;
    $("#threat-search").value = "";
    $("#threat-search").placeholder = { group: "APT29, Cozy Bear, G0016...", software: "Mimikatz, S0002...", campaign: "SolarWinds, C0024..." }[kind];
    exampleButtons($("#threat-examples"), threatExamples[kind], (id) => selectThreat({ id }));
  };
  for (const seg of document.querySelectorAll(".seg")) seg.addEventListener("click", () => setKind(seg.dataset.kind));
  setKind("group");

  $("#technique-form").addEventListener("submit", (event) => { event.preventDefault(); generateTechnique(false); });
  $("#save-technique-btn").addEventListener("click", () => generateTechnique(true));
  $("#pack-form").addEventListener("submit", (event) => { event.preventDefault(); buildPack(false); });
  $("#pack-save-btn").addEventListener("click", () => buildPack(true));
  $("#pack-zip-btn").addEventListener("click", downloadPackZip);

  loadStatus().catch((error) => {
    $("#datasets").replaceChildren(h("span", { class: "off" }, error.message));
  });
}

document.addEventListener("DOMContentLoaded", init);
