(() => {
  const $ = (id) => document.getElementById(id);
  const text = (id, value) => { $(id).textContent = value == null || value === "" ? "—" : String(value); };
  const number = (value) => new Intl.NumberFormat("ru-RU").format(Number(value || 0));
  const when = (value) => value ? new Date(value).toLocaleString("ru-RU") : "—";

  function renderGroups(groups) {
    const root = $("groups");
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
      for (const [upstreamID, state] of Object.entries(group.upstreams || {})) {
        const item = document.createElement("li");
        item.textContent = upstreamID + ": " + (state.state || "unknown") +
          (state.latency_ms ? " · " + state.latency_ms + " мс" : "");
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