"use strict";
const NAV = [
  ["Home", "home", [["overview", "Overview"], ["uplinks", "Uplinks"]]],
  ["Devices", "devices", [["devices", "Connected Devices"]]],
  ["Network", "network", [["interfaces", "Interfaces"], ["routes", "Routing"], ["queues", "QoS & Queues"]]],
  ["Security", "security", [["firewall", "Firewall (NAT)"]]],
  ["Insights", "insights", [["bandwidth", "Realtime Graphs"], ["log", "System Log"]]],
  ["Settings", "settings", [["config", "Configuration"], ["admin", "Administration"], ["restart", "Restart Service"]]],
];
let csrf = null, timer = null, routeVersion = 0;
const $ = (id) => document.getElementById(id);
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) k === "class" ? (e.className = v) : k.startsWith("on") ? e.addEventListener(k.slice(2), v) : e.setAttribute(k, v);
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
async function api(path, body) {
  const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf || "" }, body: JSON.stringify(body) };
  const r = await fetch("/api/" + path, opt);
  if (r.status === 401 && path !== "login") { csrf = null; await boot(); throw new Error("login required"); }
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}
const fmtBytes = (n) => n == null ? "—" : n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KiB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MiB" : (n / 1073741824).toFixed(2) + " GiB";
const kv = (rows) => h("table", { class: "kv" }, rows.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, v))));
const grid = (head, rows, cls) => h("table", {}, h("tr", {}, head.map((c) => h("th", {}, c))), rows.map((r) => h("tr", { class: cls ? cls(r) : "" }, r.map((c) => h("td", {}, c)))));
const pct = (v, label) => h("div", { class: "bar" }, h("i", { style: "" }), h("span", {}, label));
function bar(frac, label) { const b = pct(); b.firstChild.style.width = Math.max(0, Math.min(1, frac)) * 100 + "%"; b.lastChild.textContent = label; return b; }
const err = (e) => h("p", { class: "bad" }, "Unavailable: " + (e.error || e));

function renderNav(current) {
  const nav = $("nav"); nav.replaceChildren();
  if (!csrf) return;
  for (const [title, slug, items] of NAV) nav.append(h("div", { class: "item" }, h("button", { class: "top", type: "button" }, title + " ▾"),
    h("div", { class: "menu" }, items.map(([id, label]) => h("a", { href: "#/" + slug + "/" + id, class: current === id ? "on" : "" }, label)))));
  nav.append(h("a", { class: "top", href: "#/logout" }, "Logout"));
}

async function login() {
  const view = $("view"); view.replaceChildren();
  const pw = h("input", { type: "password", autocomplete: "current-password" }), msg = h("p", { class: "bad" });
  const go = async () => { const r = await api("login", { password: pw.value }); if (r.ok) { csrf = r.data.csrf; location.hash = "#/home/overview"; route(); } else msg.textContent = r.data.error || "Login failed"; };
  pw.addEventListener("keydown", (e) => e.key === "Enter" && go());
  view.append(h("h2", {}, "Authorization Required"), h("p", {}, "Please enter the administrator password."), h("div", { class: "row" }, h("label", {}, "Password"), pw), h("div", { class: "row" }, h("button", { class: "primary", onclick: go }, "Login")), msg);
  pw.focus();
}

const pages = {
  async overview(active = () => true) {
    const s = (await api("status")).data, t = s.transport, paths = t.paths || [], up = paths.filter((p) => p.healthy).length;
    if (active()) $("notice").replaceChildren(...(up < paths.length ? [h("div", { class: "notice" }, h("b", {}, up ? "Degraded" : "No client connected"), `${up} of ${paths.length} uplinks healthy.`)] : []));
    return [h("h2", {}, "Status"), h("h3", {}, "System"), kv([["Version", s.version], ["Process ID", s.pid], ["Observed", s.observed_at], ["Bonding mode", s.config.bonding_mode ? "enabled" : "disabled"], ["Tunnel MTU", s.config.mtu]]),
      h("h3", {}, "Tunnel"), kv([["Uplinks healthy", `${up} / ${paths.length}`], ["Client tunnel address", s.config.client_tunnel_ip], ["Listening", s.config.bind.map((b) => b.join(":")).join(", ")],
        ["Dropped (wrong address)", s.packets.wrong_tunnel_address], ["Dropped (no path)", s.packets.no_path_drops], ["Malformed", s.packets.malformed]])];
  },
  async uplinks() {
    const t = (await api("status")).data.transport;
    return [h("h2", {}, "Uplinks"), grid(["Slot", "Remote", "State", "RTT", "Jitter", "TX", "RX", "Errors"], (t.paths || []).map((p) => [p.slot, p.remote ? p.remote.join(":") : "—", p.healthy ? "healthy" : p.available ? "unhealthy" : "unavailable", p.rtt_ms == null ? "—" : p.rtt_ms.toFixed(1) + " ms", p.rtt_jitter_ms == null ? "—" : p.rtt_jitter_ms.toFixed(1) + " ms", fmtBytes(p.wire_tx_bytes), fmtBytes(p.wire_rx_bytes), JSON.stringify(p.errors || {})]), (r) => r[2] === "healthy" ? "" : "bad")];
  },
  async queues() {
    const s = (await api("status")).data, q = s.queues, stats = q.per_dscp_stats || {};
    return [h("h2", {}, "QoS & Queues"), h("h3", {}, "Scheduler"), kv([["Queued packets", `${q.queued_packets ?? q.queued} / ${q.capacity_packets ?? "—"}`], ["Mean residence", (q.residence_ms?.mean ?? 0).toFixed(2) + " ms"]]),
      h("h3", {}, "Per DSCP"), grid(["DSCP", "Enqueued", "Dequeued", "Stale drops", "Full drops", "Queued"], Object.entries(stats).map(([d, v]) => [d, v.enqueued, v.dequeued, v.dropped_stale, v.dropped_full, v.queued])),
      h("h3", {}, "Configured queues"), h("pre", {}, JSON.stringify(s.config.queues, null, 2)), h("p", { class: "muted" }, "Game UDP ports: " + (s.config.game_udp_ports.join(", ") || "none"))];
  },
  async bandwidth(active = () => true) {
    const cv = h("canvas", { width: 900, height: 200 }), info = h("p", { class: "muted" }, "Sampling…");
    drawBw(cv, info, active);
    return [h("h2", {}, "Realtime Graphs"), h("h3", {}, "Bandwidth (all uplinks, wire bytes)"), cv, info];
  },
  async firewall() { const r = (await api("nat")).data; return [h("h2", {}, "Firewall (NAT)"), r.error ? err(r) : h("pre", {}, r.text)]; },
  async log() { const r = (await api("log")).data; return [h("h2", {}, "System Log"), h("p", { class: "muted" }, "Portal events and uplink health samples since the last service start."), h("pre", {}, r.lines.join("\n") || "(empty)")]; },
  async interfaces() { const r = (await api("interfaces")).data; return [h("h2", {}, "Interfaces"), r.error ? err(r) : grid(["Name", "State", "MTU", "Addresses", "RX", "TX"], r.data.map((i) => [i.name, i.state, i.mtu, i.addresses.join(", "), fmtBytes(i.rx_bytes), fmtBytes(i.tx_bytes)]))]; },
  async devices() {
    const s = (await api("status")).data, ips = s.config.lan_tunnel_ips;
    return [h("h2", {}, "Connected Devices"), h("p", { class: "muted" }, "Addresses the server accepts and NATs besides the client. Per-device counters are not collected by the server."),
      grid(["Tunnel address", "Role"], [[s.config.client_tunnel_ip, "Client (workstation)"], ...ips.map((ip) => [ip, "Connected device"])])];
  },
  async routes() { const r = (await api("routes")).data; return [h("h2", {}, "Routing"), r.error ? err(r) : grid(["Destination", "Gateway", "Device", "Protocol", "Source"], r.data.map((x) => [x.destination, x.gateway || "—", x.device, x.protocol || "—", x.source || "—"]))]; },
  async config() {
    const ta = h("textarea", { spellcheck: "false" }), out = h("p", {});
    ta.value = (await api("config")).data.text;
    const run = async (path) => { const r = await api(path, { text: ta.value }); out.className = r.data.ok ? "ok" : "bad"; out.textContent = r.data.ok ? (path === "config" ? "Saved. Restart the service to apply." : "Valid.") : r.data.error; };
    return [h("h2", {}, "Configuration"), h("p", { class: "muted" }, "The admin block is excluded from this editor. Changes take effect after a restart."), ta,
      h("div", { class: "row" }, h("button", { onclick: () => run("config/validate") }, "Validate"), h("button", { class: "primary", onclick: () => run("config") }, "Save")), out];
  },
  async admin() {
    const cur = h("input", { type: "password", autocomplete: "current-password" }), nw = h("input", { type: "password", autocomplete: "new-password" }), out = h("p", {});
    const go = async () => { const r = await api("password", { current: cur.value, new: nw.value }); out.className = r.data.ok ? "ok" : "bad"; out.textContent = r.data.ok ? "Password changed. Signing out…" : r.data.error; if (r.data.ok) setTimeout(() => location.reload(), 1200); };
    return [h("h2", {}, "Administration"), h("h3", {}, "Router Password"), h("div", { class: "row" }, h("label", {}, "Current"), cur), h("div", { class: "row" }, h("label", {}, "New (10+ characters)"), nw), h("button", { class: "primary", onclick: go }, "Save"), out];
  },
  async restart() {
    const out = h("p", {});
    const go = async () => { if (!confirm("Restart the GameBond service? The tunnel drops for a few seconds.")) return; const r = await api("restart", { confirm: true }); out.textContent = r.ok ? "Restart requested. Reconnecting…" : (r.data.error || "failed"); if (r.ok) waitBack(); };
    return [h("h2", {}, "Restart Service"), h("p", {}, "Restarts the tunnel process inside the container so saved configuration takes effect. Connected clients reconnect automatically once it is back."), h("button", { class: "danger", onclick: go }, "Restart now"), out];
  },
};

function waitBack() {
  const tick = async () => { try { const r = await fetch("/api/session"); if (r.ok) return location.reload(); } catch (_) {} setTimeout(tick, 2000); };
  setTimeout(tick, 3000);
}
function drawBw(cv, info, active = () => true) {
  const history = [];
  const ctx = cv.getContext("2d"); let last = null, sampling = false;
  const sample = async () => {
    if (!active() || !cv.isConnected || sampling) return;
    sampling = true;
    try {
      const response = await api("status");
      if (!active() || !cv.isConnected) return;
      const t = response.data.transport, tx = t.paths.reduce((a, p) => a + p.wire_tx_bytes, 0), rx = t.paths.reduce((a, p) => a + p.wire_rx_bytes, 0), now = performance.now();
      if (last) { const dt = (now - last.now) / 1000; history.push([(tx - last.tx) * 8 / dt / 1e6, (rx - last.rx) * 8 / dt / 1e6]); if (history.length > 120) history.shift(); }
      last = { tx, rx, now };
      const max = Math.max(1, ...history.flat()), css = getComputedStyle(document.body);
      ctx.clearRect(0, 0, cv.width, cv.height);
      [[0, "#d9534f"], [1, "#0069d6"]].forEach(([i, color]) => { ctx.strokeStyle = color; ctx.beginPath(); history.forEach((p, x) => { const px = x * cv.width / 120, py = cv.height - 4 - p[i] / max * (cv.height - 12); x ? ctx.lineTo(px, py) : ctx.moveTo(px, py); }); ctx.stroke(); });
      ctx.fillStyle = css.color; ctx.fillText(max.toFixed(2) + " Mbit/s", 4, 12);
      const p = history[history.length - 1] || [0, 0]; info.textContent = `Upload ${p[0].toFixed(2)} Mbit/s (red) · Download ${p[1].toFixed(2)} Mbit/s (blue) — from the server's view: TX is toward the client.`;
    } catch (error) {
      if (active() && cv.isConnected && error.message !== "login required") info.textContent = "Unavailable: " + error.message;
    } finally { sampling = false; }
  };
  sample(); cv._t = setInterval(sample, 2000); const stop = () => clearInterval(cv._t); window.addEventListener("hashchange", stop, { once: true });
}

async function route() {
  const version = ++routeVersion, hash = location.hash;
  clearInterval(timer); timer = null;
  if (!csrf) return login();
  const active = () => version === routeVersion && hash === location.hash && csrf !== null;
  const [, , id = "overview"] = hash.split("/");
  if (hash === "#/logout") { await api("logout", {}); csrf = null; location.hash = ""; return boot(); }
  $("notice").replaceChildren(); renderNav(id);
  const page = pages[id] || pages.overview, view = $("view");
  let drawing = false;
  const draw = async () => {
    if (!active() || drawing) return;
    drawing = true;
    try {
      const content = await page(active);
      if (active()) view.replaceChildren(...content);
    } catch (error) {
      if (active() && error.message !== "login required") view.replaceChildren(err(error.message));
    } finally { drawing = false; }
  };
  await draw();
  if (!active()) return;
  const live = ["overview", "uplinks", "queues", "devices"].includes(id); $("refresh").hidden = !live;
  if (live) timer = setInterval(draw, 5000);
}

async function boot() {
  const s = (await api("session")).data; csrf = s.authenticated ? s.csrf : null;
  $("refresh").hidden = true; renderNav(); route();
}
window.addEventListener("hashchange", route);
boot();
