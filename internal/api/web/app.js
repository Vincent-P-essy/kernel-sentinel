const state = { stats: null, rules: [], alerts: [], events: [], kind: "all" };

const text = (selector, value) => { document.querySelector(selector).textContent = String(value); };
const timeLabel = (value) => new Date(value).toLocaleTimeString([], { hour12: false });
const latencyLabel = (nanoseconds) => `${(nanoseconds / 1_000_000).toFixed(2)} ms`;

async function getJSON(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

async function refresh() {
  const button = document.querySelector("#refresh");
  button.disabled = true;
  try {
    const [stats, rules, alerts, events] = await Promise.all([
      getJSON("/api/v1/stats"),
      getJSON("/api/v1/rules"),
      getJSON("/api/v1/alerts?limit=100"),
      getJSON("/api/v1/events?limit=100"),
    ]);
    Object.assign(state, { stats, rules, alerts, events });
    render();
  } catch (error) {
    const status = document.querySelector("#source-state");
    status.className = "source-state error";
    status.querySelector("span").textContent = "Unavailable";
    console.error(error);
  } finally {
    button.disabled = false;
  }
}

function render() {
  const stats = state.stats;
  text("#events-total", stats.event_count.toLocaleString());
  text("#alerts-total", stats.alert_count.toLocaleString());
  text("#critical-total", `${stats.alerts_by_severity.critical || 0} critical`);
  text("#latency", `${stats.p95_detection_latency_ms.toFixed(2)} ms`);
  text("#rules-total", state.rules.length);
  const techniques = new Set(state.rules.flatMap((rule) => rule.mitre));
  text("#techniques-total", `${techniques.size} MITRE techniques`);
  text("#coverage-count", techniques.size);
  if (stats.probe.available) {
    text("#ring-failures", stats.probe.ring_buffer_output_failures.toLocaleString());
    text("#probe-detail", `${stats.probe.pending_lookup_misses.toLocaleString()} pending misses`);
  } else {
    text("#ring-failures", "n/a");
    text("#probe-detail", "replay source");
  }
  const source = document.querySelector("#source-state");
  source.className = stats.source_status === "error" ? "source-state error" : "source-state";
  source.querySelector("span").textContent = stats.source_status;
  renderSeverities();
  renderAlerts();
  renderEvents();
  drawEvents(stats.events_by_kind);
}

function renderSeverities() {
  const counts = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const rule of state.rules) counts[rule.severity] = (counts[rule.severity] || 0) + 1;
  const list = document.querySelector("#severity-list");
  list.replaceChildren();
  for (const severity of ["critical", "high", "medium", "low"]) {
    const row = document.createElement("div");
    row.className = `severity-row ${severity}`;
    const label = document.createElement("span");
    label.textContent = severity;
    const value = document.createElement("strong");
    value.textContent = counts[severity];
    row.append(label, value);
    list.append(row);
  }
}

function renderAlerts() {
  const body = document.querySelector("#alert-body");
  body.replaceChildren();
  text("#alert-caption", `${state.alerts.length} retained alerts`);
  if (!state.alerts.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty";
    cell.textContent = "No detections";
    row.append(cell);
    body.append(row);
    return;
  }
  for (const alert of state.alerts) {
    const row = document.createElement("tr");
    const values = [
      timeLabel(alert.detected_at),
      alert.severity,
      `${alert.rule_id} / ${alert.title}`,
      alert.entity,
      alert.mitre.join(", "),
      latencyLabel(alert.detection_latency_ns),
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      if (index === 1) {
        const badge = document.createElement("span");
        badge.className = `severity ${alert.severity}`;
        badge.textContent = value;
        cell.append(badge);
      } else {
        cell.textContent = value;
      }
      row.append(cell);
    });
    body.append(row);
  }
}

function eventTarget(event) {
  if (event.file) return event.file.path;
  if (event.network) return `${event.network.address}:${event.network.port}`;
  if (event.privilege) return `target uid ${event.privilege.target_uid}`;
  return event.process.command_line || event.process.executable || "-";
}

function renderEvents() {
  const list = document.querySelector("#event-list");
  list.replaceChildren();
  const filtered = state.kind === "all" ? state.events : state.events.filter((event) => event.kind === state.kind);
  for (const event of filtered) {
    const row = document.createElement("div");
    row.className = "event-row";
    const values = [
      ["event-time", timeLabel(event.timestamp)],
      ["event-kind", event.kind],
      ["event-process", `${event.process.name || "unknown"} / ${event.process.pid}`],
      ["event-target", eventTarget(event)],
      [`event-outcome ${event.outcome.success ? "success" : "failure"}`, event.outcome.success ? "success" : "failed"],
    ];
    for (const [className, value] of values) {
      const cell = document.createElement("span");
      cell.className = className;
      cell.textContent = value;
      cell.title = value;
      row.append(cell);
    }
    list.append(row);
  }
}

function drawEvents(counts) {
  const canvas = document.querySelector("#event-chart");
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.floor(rect.width * ratio));
  canvas.height = Math.max(1, Math.floor(rect.height * ratio));
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  const data = [
    ["Exec", counts["process.exec"] || 0, "#087f5b"],
    ["Fork", counts["process.fork"] || 0, "#6b5ca5"],
    ["Files", counts["file.open"] || 0, "#c47a00"],
    ["Network", counts["network.connect"] || 0, "#4d7ea8"],
    ["Privilege", counts["privilege.setuid"] || 0, "#d9485f"],
  ];
  const margin = { top: 14, right: 48, bottom: 30, left: 74 };
  const width = rect.width - margin.left - margin.right;
  const height = rect.height - margin.top - margin.bottom;
  const maximum = Math.max(1, ...data.map((item) => item[1]));
  context.clearRect(0, 0, rect.width, rect.height);
  context.font = "11px system-ui";
  data.forEach(([label, value, color], index) => {
    const rowHeight = height / data.length;
    const y = margin.top + index * rowHeight + rowHeight * 0.2;
    const barHeight = rowHeight * 0.56;
    context.fillStyle = "#edf0ec";
    context.fillRect(margin.left, y, width, barHeight);
    context.fillStyle = color;
    context.fillRect(margin.left, y, width * (value / maximum), barHeight);
    context.fillStyle = "#596159";
    context.textAlign = "right";
    context.textBaseline = "middle";
    context.fillText(label, margin.left - 10, y + barHeight / 2);
    context.textAlign = "left";
    context.fillStyle = "#242824";
    context.fillText(String(value), margin.left + width + 10, y + barHeight / 2);
  });
}

function connectStream() {
  const stream = new EventSource("/api/v1/stream");
  stream.addEventListener("alert", (message) => {
    state.alerts.unshift(JSON.parse(message.data));
    state.alerts = state.alerts.slice(0, 100);
    renderAlerts();
  });
  stream.onerror = () => {
    // EventSource applies its own bounded reconnect delay.
  };
}

document.querySelector("#refresh").addEventListener("click", refresh);
document.querySelectorAll("#kind-filter button").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll("#kind-filter button").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    state.kind = button.dataset.kind;
    renderEvents();
  });
});
window.addEventListener("resize", () => { if (state.stats) drawEvents(state.stats.events_by_kind); });
refresh();
connectStream();
