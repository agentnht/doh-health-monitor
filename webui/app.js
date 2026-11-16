(() => {
  const $ = (id) => document.getElementById(id);
  const text = (id, value) => { $(id).textContent = value == null || value === "" ? "—" : String(value); };
  const number = (value) => new Intl.NumberFormat("ru-RU").format(Number(value || 0));
  const when = (value) => value ? new Date(value).toLocaleString("ru-RU") : "—";

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
        const latency = state.latency_ms == null ? "" : " · " + number(state.latency_ms) + " мс";
        summary.textContent = upstreamID + ": " + (state.state || "unknown") + latency;
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
            let result = check.domain + " · " + requirement +
              " · DNS: " + (check.dns_ok ? "OK" : "ошибка");
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

  async function load() {
    $("refresh").disabled = true;
    text("updated", "Загрузка…");
    try {
      const response = await fetch("/api/v1/status", { cache: "no-store", credentials: "same-origin" });
      if (!response.ok) throw new Error(response.status === 503 ? "DNS-демон недоступен" : "HTTP " + response.status);
      const status = await response.json();
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

  $("refresh").addEventListener("click", load);
  load();
  window.setInterval(load, 15000);
})();