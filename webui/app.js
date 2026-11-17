(() => {
  const $ = (id) => document.getElementById(id);
  const text = (id, value) => { $(id).textContent = value == null || value === "" ? "—" : String(value); };
  const number = (value) => new Intl.NumberFormat("ru-RU").format(Number(value || 0));
  const when = (value) => value ? new Date(value).toLocaleString("ru-RU") : "—";
  let configState = null;
  const sourceState = { doh: [], checks: [] };
  let autoHostsState = null;

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body != null) headers.set("Content-Type", "application/json");
    const response = await fetch(path, {
      ...options, headers, cache: "no-store", credentials: "same-origin"
    });
    let payload = {};
    try { payload = await response.json(); } catch (_) { /* handled below */ }
    if (!response.ok) throw new Error(payload.error || ("HTTP " + response.status));
    return payload;
  }

  function notice(id, message, good) {
    const node = $(id);
    node.textContent = message || "";
    node.classList.toggle("success", Boolean(good));
    node.classList.toggle("error", Boolean(message) && !good);
  }

  function renderGroups(groups) {
    const root = $("groups");
    const expandedUpstreams = new Set(
      Array.from(root.querySelectorAll("details[data-upstream-key]"))
        .filter((details) => details.open)
        .map((details) => details.dataset.upstreamKey)
    );
    root.replaceChildren();
    const entries = Object.entries(groups || {});
    if (!entries.length) {
      root.textContent = "Нет данных о группах.";
      return;
    }

    for (const [id, group] of entries) {
      const section = document.createElement("section");
      section.className = "group";
      const heading = document.createElement("h3");
      heading.textContent = id;
      const active = document.createElement("p");
      active.textContent = "Активный upstream: " + (group.active_upstream || "—");
      const list = document.createElement("ul");
      list.className = "upstream-list";

      for (const [upstreamID, state] of Object.entries(group.upstreams || {})) {
        const item = document.createElement("li");
        item.className = "upstream";
        const details = document.createElement("details");
        const expansionKey = JSON.stringify([id, upstreamID]);
        details.dataset.upstreamKey = expansionKey;
        details.open = expandedUpstreams.has(expansionKey);
        const summary = document.createElement("summary");
        const duration = state.check_duration_ms == null ? "" : " · Check duration: " + number(state.check_duration_ms) + " мс";
        const stateValue = String(state.state || "unknown");
        const stateLabel = document.createElement("span");
        stateLabel.className = "upstream-state";
        stateLabel.textContent = stateValue === "up" || stateValue === "down" ? stateValue.toUpperCase() : stateValue;
        if (stateValue.toLowerCase() === "up") stateLabel.classList.add("upstream-state-up");
        if (stateValue.toLowerCase() === "down") stateLabel.classList.add("upstream-state-down");
        summary.append(document.createTextNode(upstreamID + ": "), stateLabel, document.createTextNode(duration));
        const meta = document.createElement("p");
        meta.className = "muted";
        meta.textContent = "Последняя проверка: " + when(state.last_check) +
          " · Успешных подряд: " + number(state.success_streak) +
          " · Неуспешных подряд: " + number(state.failure_streak);
        details.append(summary, meta);

        const checks = Array.isArray(state.checks) ? state.checks : [];
        if (checks.length) {
          const checkTitle = document.createElement("p");
          checkTitle.className = "check-title";
          checkTitle.textContent = "Результаты проверок";
          const checkList = document.createElement("ul");
          checkList.className = "check-list";
          for (const check of checks) {
            const checkItem = document.createElement("li");
            const requirement = check.required ? "обязательная" : "дополнительная";
            let result = check.domain + " · " + requirement + " · DNS: " + (check.dns_ok ? "OK" : "ошибка");
            if (check.http_checked) {
              result += " · HTTP: " + (check.http_ok ? "OK" : "ошибка");
              if (check.http_status) result += " (" + check.http_status + ")";
            } else {
              result += " · HTTP: не проверялся";
            }
            checkItem.textContent = result;
            checkList.append(checkItem);
          }
          details.append(checkTitle, checkList);
        } else {
          const noChecks = document.createElement("p");
          noChecks.className = "muted";
          noChecks.textContent = "Детальные DNS/HTTP-проверки не настроены.";
          details.append(noChecks);
        }
        item.append(details);
        list.append(item);
      }
      section.append(heading, active, list);
      root.append(section);
    }
  }

  async function loadAutoHosts() {
    const s = await api("/api/v1/autohosts/status"); autoHostsState = s;
    const cfg = s.config || {}; $("autohosts-enabled").checked = Boolean(cfg.enabled); $("autohosts-mode").value = cfg.mode || "auto";
    text("autohosts-active", s.active_server); text("autohosts-state-emergency", cfg.emergency_off ? "ВКЛЮЧЁН" : "выключен");
    $("autohosts-domains").textContent = Object.keys(s.domains || {}).join(", ") || "Нет доменов";
    $("autohosts-results").textContent = Object.values(s.probe_results || {}).map(x => x.server_id + " × " + x.domain + " · " + (x.success ? "OK" : "FAIL")).join("\n") || "Нет проверок";
  }
  async function saveAutoHosts() {
    const mode = $("autohosts-mode").value; const pinned = mode === "pinned" ? $("autohosts-pinned").value : "";
    await api("/api/v1/autohosts/config", {method:"POST", body:JSON.stringify({enabled:$("autohosts-enabled").checked, pinned_server_id:pinned})}); await loadAutoHosts();
  }
  async function toggleAutoHostsEmergency() {
    const off = Boolean(autoHostsState && autoHostsState.config && autoHostsState.config.emergency_off);
    await api("/api/v1/autohosts/config", {method:"POST", body:JSON.stringify({emergency_off:!off})}); await loadAutoHosts();
  }
  async function runAutoHostsDryRun() {
    const p = await api("/api/v1/autohosts/dry-run", {method:"POST", body:"{}"}); $("autohosts-preview").textContent = JSON.stringify(p, null, 2);
  }
  async function loadStatus() {
    $("refresh").disabled = true;
    text("updated", "Загрузка…");
    try {
      const status = await api("/api/v1/status");
      text("version", status.version);
      text("daemon", "Доступен");
      text("started", when(status.started_at));
      text("dns-udp", status.dns_udp);
      text("dns-tcp", status.dns_tcp);
      text("queries", number(status.queries));
      text("failures", number(status.failures));
      text("cache-hits", number(status.cache_hits));
      text("active-udp", number(status.active_udp));
      text("active-tcp", number(status.active_tcp));
      text("udp-dropped", number(status.udp_dropped));
      text("cache", status.cache && status.cache.enabled
        ? number(status.cache.entries) + " / " + number(status.cache.max_entries) + " записей"
        : "Выключен");
      text("gemini", status.gemini_api);
      text("updated", when(status.updated_at));
      renderGroups(status.groups);
      $("error").textContent = "";
    } catch (error) {
      text("daemon", "Недоступен");
      $("error").textContent = "Не удалось получить состояние: " + error.message;
      text("updated", "Ошибка обновления");
    } finally {
      $("refresh").disabled = false;
    }
  }

  function setPath(object, path, value) {
    const parts = path.split(".");
    let target = object;
    for (const part of parts.slice(0, -1)) target = target[part];
    target[parts[parts.length - 1]] = value;
  }

  function addConfigField(container, labelText, path, value, kind = "text") {
    if (kind === "checkbox") {
      const label = document.createElement("label");
      label.className = "check-field";
      const input = document.createElement("input");
      input.type = "checkbox";
      input.checked = Boolean(value);
      input.dataset.path = path;
      input.dataset.kind = kind;
      const span = document.createElement("span");
      span.textContent = labelText;
      label.append(input, span);
      container.append(label);
      return;
    }
    const label = document.createElement("label");
    label.className = "field";
    label.textContent = labelText;
    const input = document.createElement("input");
    input.type = kind === "number" ? "number" : "text";
    input.value = value == null ? "" : String(value);
    input.dataset.path = path;
    input.dataset.kind = kind;
    label.append(input);
    container.append(label);
  }

  function renderConfig(config) {
    configState = config;
    $("config-general").replaceChildren();
    $("config-health").replaceChildren();
    $("config-cache").replaceChildren();
    $("config-gemini").replaceChildren();

    const general = $("config-general");
    addConfigField(general, "DNS UDP listener", "dns_listen_udp", config.dns_listen_udp);
    addConfigField(general, "DNS TCP listener", "dns_listen_tcp", config.dns_listen_tcp);
    addConfigField(general, "HTTP listener", "http_listen", config.http_listen);
    addConfigField(general, "Reload interval (сек.)", "reload_interval_seconds", config.reload_interval_seconds, "number");
    addConfigField(general, "DNS query timeout (сек.)", "dns_query_timeout_seconds", config.dns_query_timeout_seconds, "number");
    addConfigField(general, "DoH timeout (сек.)", "doh_timeout_seconds", config.doh_timeout_seconds, "number");
    addConfigField(general, "DNS max concurrent", "dns_max_concurrent", config.dns_max_concurrent, "number");

    const health = $("config-health");
    addConfigField(health, "Interval (сек.)", "health.interval_seconds", config.health.interval_seconds, "number");
    addConfigField(health, "Timeout (сек.)", "health.timeout_seconds", config.health.timeout_seconds, "number");
    addConfigField(health, "Failure threshold", "health.failure_threshold", config.health.failure_threshold, "number");
    addConfigField(health, "Success threshold", "health.success_threshold", config.health.success_threshold, "number");

    const cache = $("config-cache");
    addConfigField(cache, "Enabled", "cache.enabled", config.cache.enabled, "checkbox");
    addConfigField(cache, "Min TTL (сек.)", "cache.min_ttl_seconds", config.cache.min_ttl_seconds, "number");
    addConfigField(cache, "Max TTL (сек.)", "cache.max_ttl_seconds", config.cache.max_ttl_seconds, "number");
    addConfigField(cache, "Negative TTL (сек.)", "cache.negative_ttl_seconds", config.cache.negative_ttl_seconds, "number");
    addConfigField(cache, "Max entries", "cache.max_entries", config.cache.max_entries, "number");
    addConfigField(cache, "Max bytes", "cache.max_bytes", config.cache.max_bytes, "number");
    $("config-bootstrap").value = (config.bootstrap_resolvers || []).join("\n");

    const gemini = $("config-gemini");
    addConfigField(gemini, "Enabled", "gemini_api.enabled", config.gemini_api.enabled, "checkbox");
    addConfigField(gemini, "Required for group", "gemini_api.required_for_group", config.gemini_api.required_for_group, "checkbox");
    addConfigField(gemini, "Group ID", "gemini_api.group_id", config.gemini_api.group_id);
    addConfigField(gemini, "Model", "gemini_api.model", config.gemini_api.model);
    addConfigField(gemini, "Interval (сек.)", "gemini_api.interval_seconds", config.gemini_api.interval_seconds, "number");
    addConfigField(gemini, "Key file (relative path)", "gemini_api.key_file", config.gemini_api.key_file);
    addConfigField(gemini, "Max output tokens", "gemini_api.max_output_tokens", config.gemini_api.max_output_tokens, "number");
    const promptLabel = document.createElement("label");
    promptLabel.className = "field";
    promptLabel.style.gridColumn = "1 / -1";
    promptLabel.textContent = "Prompt";
    const prompt = document.createElement("textarea");
    prompt.rows = 2;
    prompt.dataset.path = "gemini_api.prompt";
    prompt.dataset.kind = "text";
    prompt.value = config.gemini_api.prompt || "";
    promptLabel.append(prompt);
    gemini.append(promptLabel);
    text("config-note", config.integration ? "Интеграция включена" : "Интеграция выключена");
    $("integration-add").disabled = Boolean(config.integration);
    $("integration-remove").disabled = !config.integration;
    $("integration-add").setAttribute("aria-pressed", String(!config.integration));
    $("integration-remove").setAttribute("aria-pressed", String(Boolean(config.integration)));
  }

  async function loadConfig() {
    const config = await api("/api/v1/config");
    renderConfig(config);
  }

  function collectConfig() {
    if (!configState) throw new Error("Конфигурация ещё не загружена");
    const next = JSON.parse(JSON.stringify(configState));
    for (const input of document.querySelectorAll("[data-path]")) {
      let value;
      if (input.dataset.kind === "checkbox") value = input.checked;
      else if (input.dataset.kind === "number") value = Number(input.value);
      else value = input.value;
      setPath(next, input.dataset.path, value);
    }
    next.bootstrap_resolvers = $("config-bootstrap").value.split(/\r?\n/).map(v => v.trim()).filter(Boolean);
    return next;
  }

  async function saveConfig() {
    const button = $("save-config");
    button.disabled = true;
    notice("config-note", "Сохранение…", false);
    try {
      const result = await api("/api/v1/config", { method: "POST", body: JSON.stringify(collectConfig()) });
      renderConfig(result.config);
      const message = result.restart_required
        ? "Сохранено. Изменение listener/dns_max_concurrent вступит в силу после перезапуска плагина."
        : "Конфигурация сохранена. Новые значения будут применены механизмом reload.";
      notice("config-note", message, true);
    } catch (error) {
      notice("config-note", error.message, false);
    } finally {
      button.disabled = false;
    }
  }

  async function resetConfigSection(section) {
    const button = document.querySelector('[data-default-section="' + section + '"]');
    if (button) button.disabled = true;
    try {
      const result = await api("/api/v1/config/defaults", { method: "POST", body: JSON.stringify({ section }) });
      renderConfig(result.config);
      notice("config-note", "Раздел " + section + " восстановлен по умолчанию и сохранён.", true);
    } catch (error) {
      notice("config-note", error.message, false);
    } finally {
      if (button) button.disabled = false;
    }
  }

  const sourceFields = {
    doh: ["ID", "HTTPS URL"],
    checks: ["Domain", "QTypes", "Required (0/1)", "HTTP URL", "Expected status", "Verify OIDC (0/1)"]
  };

  function renderSource(kind) {
    const body = $(kind === "doh" ? "doh-rows" : "check-rows");
    body.replaceChildren();
    sourceState[kind].forEach((row, index) => {
      const tr = document.createElement("tr");
      if (kind === "doh" && row.system) tr.classList.add("source-system");
      if (!row.editable) {
        const td = document.createElement("td");
        td.colSpan = kind === "doh" ? 4 : 8;
        td.className = "source-comment";
        td.textContent = row.raw || "#";
        tr.append(td);
        body.append(tr);
        return;
      }

      const enabledCell = document.createElement("td");
      const enabled = document.createElement("input");
      enabled.type = "checkbox";
      enabled.checked = Boolean(row.active);
      enabled.setAttribute("aria-label", "Активировать строку " + (index + 1));
      enabled.addEventListener("change", () => { row.active = enabled.checked; });
      enabledCell.append(enabled);
      tr.append(enabledCell);

      sourceFields[kind].forEach((fieldName, fieldIndex) => {
        const td = document.createElement("td");
        if (kind === "doh" && row.system && fieldIndex === 1) {
          const note = document.createElement("span");
          note.className = "source-system-note";
          note.textContent = "Системные DNS VPS из /etc/resolv.conf";
          td.append(note);
        } else {
          const input = document.createElement("input");
          input.type = "text";
          input.value = row.fields[fieldIndex] || "";
          input.placeholder = fieldName;
          input.setAttribute("aria-label", fieldName + ", строка " + (index + 1));
          if (kind === "doh" && row.system) input.readOnly = true;
          else input.addEventListener("input", () => { row.fields[fieldIndex] = input.value; });
          if (!row.active) input.style.opacity = ".65";
          td.append(input);
        }
        tr.append(td);
      });

      const actionCell = document.createElement("td");
      if (kind === "doh" && row.system) {
        const protectedLabel = document.createElement("span");
        protectedLabel.className = "source-protected";
        protectedLabel.textContent = "Защищён";
        actionCell.append(protectedLabel);
      } else {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "danger small";
        remove.textContent = "del";
        remove.setAttribute("aria-label", "Удалить строку " + (index + 1));
        remove.addEventListener("click", () => {
          sourceState[kind].splice(index, 1);
          renderSource(kind);
        });
        actionCell.append(remove);
      }
      tr.append(actionCell);
      body.append(tr);
    });
  }

  async function loadSources() {
    const data = await api("/api/v1/sources");
    sourceState.doh = data.doh || [];
    sourceState.checks = data.checks || [];
    renderSource("doh");
    renderSource("checks");
  }

  function addSourceRow(kind) {
    const count = kind === "doh" ? 2 : 6;
    sourceState[kind].push({ active: true, editable: true, fields: Array(count).fill("") });
    renderSource(kind);
    const body = $(kind === "doh" ? "doh-rows" : "check-rows");
    const last = body.querySelector("tr:last-child");
    const firstInput = last && last.querySelector("input[type=text]");
    if (firstInput) firstInput.focus();
  }

  async function saveSources(kind) {
    const button = $(kind === "doh" ? "doh-save" : "check-save");
    const note = kind === "doh" ? "doh-note" : "check-note";
    button.disabled = true;
    notice(note, "Проверка и сохранение…", false);
    try {
      await api("/api/v1/sources", {
        method: "POST",
        body: JSON.stringify({ kind, rows: sourceState[kind] })
      });
      await loadSources();
      notice(note, "Список сохранён. Демон перечитает его автоматически в течение 30 секунд.", true);
    } catch (error) {
      notice(note, error.message, false);
    } finally {
      button.disabled = false;
    }
  }

  function renderTests(summary) {
    const root = $("test-results");
    root.replaceChildren();
    const label = summary.status + " · OK: " + number(summary.passed) + " · NotOK: " + number(summary.failed) +
      " · " + when(summary.run_at);
    text("tests-summary", label);
    for (const test of summary.tests || []) {
      const card = document.createElement("details");
      card.className = "result";

      const head = document.createElement("summary");
      head.className = "result-summary";
      const name = document.createElement("span");
      name.className = "result-name";
      name.textContent = test.name || "Проверка";

      const state = document.createElement("span");
      const passed = test.status === "OK";
      state.className = "result-status " + (passed ? "ok" : "bad");
      state.textContent = passed ? "OK" : (test.status || "NotOK");

      const toggle = document.createElement("span");
      toggle.className = "result-toggle";
      toggle.setAttribute("aria-hidden", "true");
      toggle.textContent = passed ? "✓" : "›";
      head.append(name, state, toggle);
      card.append(head);

      const content = document.createElement("div");
      content.className = "result-details";
      if (test.domain) {
        const meta = document.createElement("p");
        meta.className = "muted";
        meta.textContent = test.domain + " · " + test.qtype + " · " + number(test.duration_ms) + " мс";
        content.append(meta);
      } else if (test.duration_ms) {
        const meta = document.createElement("p");
        meta.className = "muted";
        meta.textContent = number(test.duration_ms) + " мс";
        content.append(meta);
      }
      if (test.answer) {
        const answer = document.createElement("pre");
        answer.textContent = test.answer;
        content.append(answer);
      }
      if (test.reason) {
        const reason = document.createElement("pre");
        reason.textContent = test.reason;
        content.append(reason);
      }
      if (!content.childNodes.length) {
        const empty = document.createElement("p");
        empty.className = "muted";
        empty.textContent = "Дополнительные сведения отсутствуют.";
        content.append(empty);
      }
      card.append(content);
      root.append(card);
    }
  }

  async function runTests() {
    const button = $("run-tests");
    button.disabled = true;
    text("tests-summary", "Проверки выполняются…");
    try {
      const summary = await api("/api/v1/tests/run", { method: "POST", body: "{}" });
      renderTests(summary);
    } catch (error) {
      text("tests-summary", "Не удалось запустить проверки: " + error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function loadIntegrationLog() {
    const node = $("integration-log");
    if (!node) return;
    node.textContent = "Загрузка журнала операций…";
    try {
      const result = await api("/api/v1/integration/logs");
      node.textContent = (result.lines || []).join("\\n");
    } catch (error) {
      node.textContent = "Не удалось прочитать журнал операций: " + error.message;
    }
  }

  async function integrationAction(action) {
    const button = $(action === "integrate" ? "integration-add" : "integration-remove");
    const prompt = action === "integrate"
      ? "Выполнить DNS-интеграцию в LucX-UI/Xray? Операция изменит настройки панели."
      : "Удалить DNS-интеграцию из LucX-UI/Xray? Операция изменит настройки панели.";
    if (!window.confirm(prompt)) return;

    button.disabled = true;
    notice("integration-result", action === "integrate" ? "Выполняется Integrate…" : "Выполняется DeIntegrate…", false);
    try {
      const result = await api("/api/v1/integration", {
        method: "POST",
        body: JSON.stringify({ action, confirmed: true })
      });
      if (result.ok) {
        notice("integration-result", action === "integrate" ? "Интеграция выполнена." : "Деинтеграция выполнена.", true);
      } else {
        notice("integration-result", (action === "integrate" ? "Ошибка Integrate: " : "Ошибка DeIntegrate: ") + (result.error || "неизвестная ошибка"), false);
      }
      await loadIntegrationLog();
      try { await loadConfig(); } catch (_) { /* preserve operation result */ }
      setPageOpen("logs", true);
    } catch (error) {
      notice("integration-result", error.message, false);
      await loadIntegrationLog();
      setPageOpen("logs", true);
    } finally {
      if (configState) {
        $("integration-add").disabled = Boolean(configState.integration);
        $("integration-remove").disabled = !configState.integration;
      } else {
        button.disabled = false;
      }
    }
  }

  function setPageOpen(name, open) {
    const panels = Array.from(document.querySelectorAll("[data-page-panel]"));
    const targetPanels = panels.filter(panel => panel.dataset.pagePanel === name);
    if (!targetPanels.length) return;

    const currentlyOpen = targetPanels.some(panel => !panel.hidden);
    const shouldOpen = open == null ? !currentlyOpen : Boolean(open);

    // Only one management page may be active. Clicking the current tab closes it;
    // clicking another tab replaces the previous page instead of stacking panels.
    panels.forEach(panel => {
      panel.hidden = !shouldOpen || panel.dataset.pagePanel !== name;
    });
    document.querySelectorAll("[data-page]").forEach(button => {
      const selected = shouldOpen && button.dataset.page === name;
      button.setAttribute("aria-selected", String(selected));
      button.setAttribute("aria-expanded", String(selected));
    });
    if (shouldOpen && name === "logs") {
      loadLogs();
      loadIntegrationLog();
    }
  }

  function activatePage(name) {
    setPageOpen(name);
  }

  async function saveGeminiKey() {
    const button = $("save-gemini-key");
    const key = $("gemini-key").value.trim();
    if (!key) {
      notice("config-note", "Сначала введите новый Gemini API key.", false);
      return;
    }
    button.disabled = true;
    try {
      const result = await api("/api/v1/gemini-key", { method: "POST", body: JSON.stringify({ key }) });
      $("gemini-key").value = "";
      notice("config-note", result.message || "Ключ сохранён.", true);
    } catch (error) {
      notice("config-note", error.message, false);
    } finally {
      button.disabled = false;
    }
  }

  async function loadLogs() {
    const button = $("refresh-logs");
    button.disabled = true;
    $("logs").textContent = "Загрузка…";
    try {
      const result = await api("/api/v1/logs?lines=250");
      text("logs-source", "Источник: " + result.source);
      $("logs").textContent = (result.lines || []).join("\n");
    } catch (error) {
      $("logs").textContent = "Не удалось прочитать логи: " + error.message;
    } finally {
      button.disabled = false;
    }
  }

  $("refresh").addEventListener("click", () => {
    loadStatus();
    loadConfig().catch(error => notice("config-note", error.message, false));
  });
  $("save-config").addEventListener("click", saveConfig);
  $("save-gemini-key").addEventListener("click", saveGeminiKey);
  $("doh-add").addEventListener("click", () => addSourceRow("doh"));
  $("check-add").addEventListener("click", () => addSourceRow("checks"));
  $("doh-save").addEventListener("click", () => saveSources("doh"));
  $("check-save").addEventListener("click", () => saveSources("checks"));
  $("run-tests").addEventListener("click", runTests);
  $("integration-add").addEventListener("click", () => integrationAction("integrate"));
  $("integration-remove").addEventListener("click", () => integrationAction("remove"));
  $("refresh-logs").addEventListener("click", loadLogs);
  $("refresh-integration-log").addEventListener("click", loadIntegrationLog);
  document.querySelectorAll("[data-page]").forEach(button => {
    button.addEventListener("click", () => activatePage(button.dataset.page));
  });
  document.querySelectorAll("[data-default-section]").forEach(button => {
    button.addEventListener("click", () => resetConfigSection(button.dataset.defaultSection));
  });

  loadStatus();
  loadConfig().catch(error => notice("config-note", error.message, false));
  loadSources().catch(error => {
    notice("doh-note", error.message, false);
    notice("check-note", error.message, false);
  });
  loadIntegrationLog();
  window.setInterval(loadStatus, 15000);
})();
