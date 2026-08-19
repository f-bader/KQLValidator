(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const state = {
    environment: "xdr",
    kind: "table",
    query: "",
    cursor: null,
    items: [],
    lintRules: [],
    schemaRequest: 0,
    schemaLoading: false,
    searchTimer: null,
    lastChecked: null,
  };

  const kindNames = { table: "Tables", column: "Columns", function: "Functions", "": "All kinds" };

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function localUrl(path) {
    return path.startsWith("http") ? path : new URL(path, window.location.origin).href;
  }

  function mcpEndpoint() {
    const endpoint = new URL("/mcp", window.location.origin);
    if (["127.0.0.1", "0.0.0.0", "host.docker.internal"].includes(endpoint.hostname)) endpoint.hostname = "localhost";
    return endpoint.href;
  }

  function renderMcpCommands() {
    const endpoint = mcpEndpoint();
    $("#claude-mcp-command").textContent = `claude mcp add --transport http kql-validator ${endpoint}`;
    $("#codex-mcp-command").textContent = `codex mcp add kql-validator --url ${endpoint}`;
    $("#opencode-mcp-command").textContent = `opencode mcp add kql-validator --url ${endpoint}`;
  }

  async function copyText(text) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    if (!copied) throw new Error("Clipboard unavailable");
  }

  function setCopyState(button, copied) {
    button.dataset.copied = copied ? "true" : "false";
    button.setAttribute("aria-label", copied ? "Copied MCP command" : button.dataset.copyAriaLabel);
  }

  async function copyCommand(button) {
    const command = document.getElementById(button.dataset.copyTarget)?.textContent || "";
    button.dataset.copyAriaLabel ||= button.getAttribute("aria-label") || "Copy MCP command";
    try {
      await copyText(command);
      setCopyState(button, true);
      window.setTimeout(() => setCopyState(button, false), 1600);
    } catch {
      setCopyState(button, false);
      button.setAttribute("aria-label", "Copy unavailable");
      window.setTimeout(() => setCopyState(button, false), 1600);
    }
  }

  async function getJson(path) {
    const response = await fetch(path, { headers: { Accept: "application/json" }, cache: "no-store" });
    const body = await response.text();
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return body ? JSON.parse(body) : null;
  }

  async function getReadiness() {
    const response = await fetch("/health/ready", { cache: "no-store" });
    return { ok: response.ok, status: response.status };
  }

  function setNotice(message) {
    const notice = $("#global-notice");
    notice.textContent = message || "";
    notice.hidden = !message;
  }

  function setHeroStatus(readiness, discoveryOk = true) {
    const hero = $("#hero-status");
    const value = $("#hero-status-value");
    if (!discoveryOk) {
      hero.dataset.state = "down";
      value.textContent = "Service metadata unavailable";
      return;
    }
    if (readiness.ok) {
      hero.dataset.state = "up";
      value.textContent = "Operational";
    } else {
      hero.dataset.state = "down";
      value.textContent = `Readiness unavailable (${readiness.status})`;
    }
  }

  function formatTime(date) {
    return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
  }

  function renderOverview(discovery, environments, lintRules) {
    $("#service-version").textContent = discovery.version || "unknown";
    $("#service-revision").textContent = discovery.version?.includes("+") ? "Immutable build revision" : "Published service build";
    $("#environment-count").textContent = environments.length;
    $("#lint-count").textContent = lintRules.length;
    state.lastChecked = new Date();
    $("#last-checked").textContent = formatTime(state.lastChecked);
    $("#github-link").href = discovery.documentation || "https://github.com/fabian/kql-validator";
    const restPath = discovery.rest && discovery.rest !== "/api/v1" ? discovery.rest : "/api/v1/environments";
    $("#rest-link").href = localUrl(restPath);
    $("#mcp-link").href = localUrl(discovery.mcp || "/mcp");
    $("#openapi-link").href = localUrl(discovery.openApi || "/openapi/v1.json");
    renderSchemaCards(environments);
  }

  function renderSchemaCards(environments) {
    const container = $("#schema-cards");
    container.innerHTML = environments.map((environment) => `
      <article class="schema-card">
        <div class="schema-card-head"><h3>${escapeHtml(environment.name)}</h3><span class="schema-badge">LIVE</span></div>
        <div class="schema-card-stats">
          <div class="schema-stat"><strong>${environment.tableCount}</strong><span>tables</span></div>
          <div class="schema-stat"><strong>${environment.functionCount}</strong><span>functions</span></div>
          <div class="schema-stat"><strong>${environment.profiles?.length || 0}</strong><span>profiles</span></div>
        </div>
        <div class="schema-hash" title="${escapeHtml(environment.schemaVersion)}">${escapeHtml(environment.schemaVersion)}</div>
      </article>`).join("");
  }

  function renderSchemaResults() {
    const results = $("#schema-results");
    $("#result-heading").textContent = `${kindNames[state.kind]} in ${state.environment.toUpperCase()}`;
    $("#result-count").textContent = state.items.length ? `${state.items.length} loaded` : "0 results";
    $("#load-more").hidden = !state.cursor;
    if (!state.items.length) {
      results.innerHTML = `<div class="empty-state"><div><span class="detail-symbol" aria-hidden="true">⌕</span><p>No catalog entries matched this search.</p></div></div>`;
      return;
    }
    results.innerHTML = state.items.map((item) => {
      const table = item.kind === "table" ? item.name : item.parent;
      const resultType = item.kind === "function" ? "function" : (item.type || item.kind || "table");
      const content = `<span class="result-name">${escapeHtml(item.name)}${item.parent ? `<span class="result-parent">${escapeHtml(item.parent)}</span>` : ""}</span><span class="result-type">${escapeHtml(resultType)}</span>`;
      return table
        ? `<button class="schema-result" type="button" data-table="${escapeHtml(table)}">${content}</button>`
        : `<div class="schema-result">${content}</div>`;
    }).join("");
  }

  function schemaItemKey(item) {
    return [item.environment, item.kind, item.parent || "", item.name, item.type || ""].join("|");
  }

  async function loadSchema(reset = true) {
    if (!reset && (state.schemaLoading || !state.cursor)) return;
    const requestId = ++state.schemaRequest;
    if (reset) { state.cursor = null; state.items = []; renderSchemaResults(); }
    state.schemaLoading = true;
    if (!reset) $("#load-more").disabled = true;
    $("#schema-results").setAttribute("aria-busy", "true");
    const params = new URLSearchParams({ limit: "50" });
    if (state.kind) params.set("kind", state.kind);
    if (state.query.trim()) params.set("query", state.query.trim());
    if (state.cursor) params.set("cursor", state.cursor);
    try {
      const result = await getJson(`/api/v1/environments/${encodeURIComponent(state.environment)}/schema?${params}`);
      if (requestId !== state.schemaRequest) return;
      if (reset) {
        state.items = result.items;
      } else {
        const existing = new Set(state.items.map(schemaItemKey));
        state.items = state.items.concat(result.items.filter((item) => !existing.has(schemaItemKey(item))));
      }
      state.cursor = result.nextCursor;
      renderSchemaResults();
    } catch (error) {
      if (requestId !== state.schemaRequest) return;
      $("#schema-results").innerHTML = `<div class="error-state"><div><span class="detail-symbol" aria-hidden="true">!</span><p>Schema search could not be loaded. Refresh to try again.</p></div></div>`;
      $("#load-more").hidden = true;
    } finally {
      if (requestId === state.schemaRequest) {
        state.schemaLoading = false;
        $("#load-more").disabled = false;
        $("#schema-results").setAttribute("aria-busy", "false");
      }
    }
  }

  async function loadTable(table) {
    const detail = $("#table-detail");
    detail.innerHTML = `<div class="empty-detail"><span class="detail-symbol" aria-hidden="true">…</span><p>Loading ${escapeHtml(table)}…</p></div>`;
    try {
      const result = await getJson(`/api/v1/environments/${encodeURIComponent(state.environment)}/tables/${encodeURIComponent(table)}`);
      detail.innerHTML = `
        <div class="detail-header"><div class="eyebrow">${escapeHtml(state.environment)} table</div><h3 id="detail-heading">${escapeHtml(result.name)}</h3><p>${result.columns.length} columns in the current catalog</p></div>
        <div class="column-list">${result.columns.map((column) => `<div class="column-row"><span>${escapeHtml(column.name)}</span><span>${escapeHtml(column.type)}</span></div>`).join("")}</div>`;
    } catch (error) {
      detail.innerHTML = `<div class="error-state"><div><span class="detail-symbol" aria-hidden="true">!</span><p>That table could not be loaded.</p></div></div>`;
    }
  }

  function populateRuleSets(rules) {
    const select = $("#lint-ruleset");
    const current = select.value;
    const values = [...new Set(rules.map((rule) => rule.ruleSet).filter(Boolean))].sort();
    select.innerHTML = `<option value="">All rule sets</option>${values.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("")}`;
    select.value = values.includes(current) ? current : "";
  }

  function renderLintRules() {
    const query = $("#lint-search").value.trim().toLowerCase();
    const ruleSet = $("#lint-ruleset").value;
    const severity = $("#lint-severity").value;
    const rules = state.lintRules.filter((rule) => {
      const haystack = [rule.ruleId, rule.title, rule.description, rule.category, rule.ruleSet].join(" ").toLowerCase();
      return (!query || haystack.includes(query)) && (!ruleSet || rule.ruleSet === ruleSet) && (!severity || rule.defaultSeverity === severity);
    });
    $("#lint-caption").textContent = `${rules.length} of ${state.lintRules.length} rules`;
    $("#lint-list").innerHTML = rules.length ? rules.map((rule) => `
      <article class="lint-card">
        <div class="lint-card-head"><div><span class="lint-id">${escapeHtml(rule.ruleId)}</span><h3>${escapeHtml(rule.title)}</h3></div><span class="severity severity-${String(rule.defaultSeverity).toLowerCase()}">${escapeHtml(rule.defaultSeverity)}</span></div>
        <p class="lint-description">${escapeHtml(rule.description)}</p>
        <div class="lint-meta"><span class="meta-chip">${escapeHtml(rule.category)}</span><span class="meta-chip">${escapeHtml(rule.ruleSet)}</span>${(rule.profiles || []).slice(0, 2).map((profile) => `<span class="meta-chip">${escapeHtml(profile)}</span>`).join("")}</div>
        ${rule.documentationUrl ? `<a class="lint-source" href="${escapeHtml(rule.documentationUrl)}" target="_blank" rel="noopener noreferrer">Original guidance ↗</a>` : ""}
      </article>`).join("") : `<div class="empty-state"><div><span class="detail-symbol" aria-hidden="true">⌕</span><p>No lint rules matched these filters.</p></div></div>`;
  }

  async function loadOverview() {
    document.body.classList.add("is-refreshing");
    $("#refresh-button").disabled = true;
    setNotice("");
    const [discoveryResult, readinessResult, environmentsResult, lintResult] = await Promise.allSettled([
      getJson("/"), getReadiness(), getJson("/api/v1/environments"), getJson("/api/v1/lint-rules"),
    ]);
    const readiness = readinessResult.status === "fulfilled" ? readinessResult.value : { ok: false, status: "error" };
    setHeroStatus(readiness, discoveryResult.status === "fulfilled");
    if (discoveryResult.status === "fulfilled" && environmentsResult.status === "fulfilled" && lintResult.status === "fulfilled") {
      state.lintRules = lintResult.value.items || [];
      renderOverview(discoveryResult.value, environmentsResult.value, state.lintRules);
      populateRuleSets(state.lintRules);
      renderLintRules();
    } else {
      setNotice("Some service metadata could not be loaded. Use Refresh to try again.");
      if (environmentsResult.status === "fulfilled") renderSchemaCards(environmentsResult.value);
    }
    await loadSchema(true);
    document.body.classList.remove("is-refreshing");
    $("#refresh-button").disabled = false;
  }

  $("#refresh-button").addEventListener("click", loadOverview);
  $("#environment-tabs").addEventListener("click", (event) => {
    const tab = event.target.closest("[data-environment]");
    if (!tab) return;
    state.environment = tab.dataset.environment;
    document.querySelectorAll(".tab").forEach((item) => { item.classList.toggle("is-active", item === tab); item.setAttribute("aria-selected", item === tab ? "true" : "false"); });
    loadSchema(true);
  });
  $("#schema-kind").addEventListener("change", (event) => { state.kind = event.target.value; loadSchema(true); });
  $("#schema-search").addEventListener("input", (event) => {
    state.query = event.target.value;
    clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(() => loadSchema(true), 280);
  });
  $("#load-more").addEventListener("click", () => loadSchema(false));
  $("#schema-results").addEventListener("click", (event) => {
    const row = event.target.closest("[data-table]");
    if (row) loadTable(row.dataset.table);
  });
  ["#lint-search", "#lint-ruleset", "#lint-severity"].forEach((selector) => $(selector).addEventListener("input", renderLintRules));
  $("#lint-ruleset").addEventListener("change", renderLintRules);
  document.querySelectorAll(".copy-button").forEach((button) => button.addEventListener("click", () => copyCommand(button)));
  renderMcpCommands();
  loadOverview();
})();
