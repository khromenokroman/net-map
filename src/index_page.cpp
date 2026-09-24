#include "index_page.hpp"

namespace {

constexpr std::string_view PAGE = R"HTML(<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Карта сети</title>
<style>
:root {
  --bg: #f4f6fa; --panel: #ffffff; --text: #1b2130; --muted: #6b7385; --border: #e2e6ee;
  --ok: #1f9d55; --ok-bg: #e5f6ec; --warn: #c27c0e; --warn-bg: #fdf1dc;
  --fail: #d23f3f; --fail-bg: #fbe7e7; --off: #9aa1b0; --off-bg: #eceef3;
  --accent: #3d63dd; --line: #cfd5e0; --shadow: 0 1px 2px rgba(20,30,50,.06), 0 4px 16px rgba(20,30,50,.05);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f131b; --panel: #171c27; --text: #e6e9f0; --muted: #8b93a7; --border: #262d3b;
    --ok: #3ccf7a; --ok-bg: #13301f; --warn: #f0b340; --warn-bg: #33270f;
    --fail: #ff6b6b; --fail-bg: #3a1a1c; --off: #6b7385; --off-bg: #232937;
    --accent: #7b9bff; --line: #2e3647; --shadow: none;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif; }
.wrap { max-width: 1280px; margin: 0 auto; padding: 24px 16px 48px; }
header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 16px; margin-bottom: 20px; }
h1 { font-size: 22px; margin: 0; font-weight: 650; }
h2 { font-size: 16px; margin: 28px 0 12px; font-weight: 650; }
.host { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.conn { margin-left: auto; display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 13px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); }
.conn.lost .dot { background: var(--fail); } .conn.lost { color: var(--fail); }
.summary { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 20px; }
.tile.dhcp-bad .n { color: var(--fail); }
.tile { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; box-shadow: var(--shadow); }
.tile .n { font-size: 28px; font-weight: 700; font-variant-numeric: tabular-nums; line-height: 1.1; }
.tile .l { color: var(--muted); font-size: 13px; }
.tile.ok .n { color: var(--ok); } .tile.off .n { color: var(--off); } .tile.fail .n { color: var(--fail); }
.warnings { background: var(--warn-bg); color: var(--warn); border-radius: 10px; padding: 10px 14px; margin-bottom: 16px; font-size: 13px; }
.warnings:empty { display: none; }
.group { margin-bottom: 16px; }
#dhcp-group { margin-top: 28px; }
.group-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 10px; width: 100%; padding: 10px 14px;
  background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--c, var(--accent)); border-radius: 12px;
  box-shadow: var(--shadow); color: inherit; font: inherit; cursor: pointer; text-align: left; }
.group-head.fail { --c: var(--fail); }
.chev { flex: none; width: 16px; color: var(--muted); transition: transform .15s; }
.group.collapsed .chev { transform: rotate(-90deg); }
.group.collapsed .gbody { display: none; }
.gt { flex: 1 1 auto; min-width: 120px; font-weight: 650; font-size: 16px; }
.gt small { color: var(--muted); font-weight: 400; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; margin-left: 8px; }
.gs { flex: 0 1 auto; display: flex; flex-wrap: wrap; justify-content: flex-end; margin-left: auto; gap: 6px; font-size: 12px; font-weight: 600; }
.pill { padding: 2px 8px; border-radius: 999px; white-space: nowrap; }
.pill.ok { color: var(--ok); background: var(--ok-bg); } .pill.off { color: var(--muted); background: var(--off-bg); }
.pill.fail { color: var(--fail); background: var(--fail-bg); }
.map { margin-top: 12px; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow); padding: 8px; }
.map .scroll { overflow: auto; max-height: 80vh; }
.map svg { display: block; width: 100%; height: auto; margin: 0 auto; }
.map .link { stroke: var(--line); stroke-width: 1.5; }
.map .link.fail { stroke: var(--fail); stroke-dasharray: 4 3; }
.map .node { cursor: pointer; }
.map .node circle { stroke: var(--panel); stroke-width: 3; }
.map .node.ok circle { fill: var(--ok); } .map .node.off circle { fill: var(--off); } .map .node.fail circle { fill: var(--fail); }
.map .node.self circle { stroke: var(--accent); stroke-width: 4; }
.map .node.gw circle { fill: var(--accent); }
.map .node.hub circle { fill: var(--off-bg); stroke: var(--line); stroke-width: 2; }
.map .node.off { opacity: .6; }
.map .node:hover circle { stroke: var(--text); }
.map .oct { fill: #fff; font-size: 11px; font-weight: 700; text-anchor: middle; dominant-baseline: central; pointer-events: none; }
.map .node.hub .oct { fill: var(--muted); }
.map .lbl { fill: var(--text); font-size: 11px; text-anchor: middle; pointer-events: none; }
.map .lbl2 { fill: var(--muted); font-size: 10px; text-anchor: middle; pointer-events: none; }
.map .node.fail .lbl2 { fill: var(--fail); font-weight: 600; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; color: var(--muted); font-size: 12px; margin: 8px 6px 2px; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; vertical-align: -1px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px 12px; margin-bottom: 12px; align-items: center; }
.toolbar input { flex: 1 1 260px; min-width: 0; padding: 9px 12px; border-radius: 10px; border: 1px solid var(--border);
  background: var(--panel); color: var(--text); font: inherit; }
.toolbar input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { padding: 6px 12px; border-radius: 999px; border: 1px solid var(--border); background: var(--panel); color: var(--text); font: inherit;
  font-size: 13px; cursor: pointer; }
.chip.active { border-color: var(--accent); color: var(--accent); font-weight: 600; }
.tablewrap { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow); overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12px; padding: 10px 12px; border-bottom: 1px solid var(--border);
  white-space: nowrap; cursor: pointer; user-select: none; }
th.sorted::after { content: " \25B4"; } th.sorted.desc::after { content: " \25BE"; }
td { padding: 8px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
tr:last-child td { border-bottom: none; }
tr.sel td { background: var(--ok-bg); }
td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
td.muted { color: var(--muted); }
.st { display: inline-flex; align-items: center; gap: 6px; font-weight: 600; font-size: 12px; }
.st i { width: 8px; height: 8px; border-radius: 50%; background: var(--c); }
.st.ok { --c: var(--ok); color: var(--ok); } .st.off { --c: var(--off); color: var(--muted); } .st.fail { --c: var(--fail); color: var(--fail); }
.tag { display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 6px; border-radius: 6px; margin-left: 6px;
  color: var(--accent); background: var(--off-bg); }
.events { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow); max-height: 360px; overflow-y: auto; }
.ev { display: flex; gap: 12px; padding: 8px 14px; border-bottom: 1px solid var(--border); font-size: 13px; }
.ev:last-child { border-bottom: none; }
.ev time { flex: none; color: var(--muted); font-variant-numeric: tabular-nums; width: 118px; }
.ev.warn { color: var(--warn); } .ev.fail { color: var(--fail); } .ev.ok { color: var(--ok); }
.empty { color: var(--muted); padding: 24px; text-align: center; }
.dstatus { display: flex; flex-wrap: wrap; gap: 4px 18px; color: var(--muted); font-size: 13px; margin: 12px 2px; }
.dstatus b { color: var(--text); font-weight: 600; }
.alerts { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
.alert { background: var(--fail-bg); color: var(--fail); border-radius: 10px; padding: 10px 14px; font-size: 13px; overflow-wrap: anywhere; }
.alert.warn { background: var(--warn-bg); color: var(--warn); }
.subh { font-size: 13px; font-weight: 600; color: var(--muted); margin: 16px 2px 8px; text-transform: uppercase; letter-spacing: .04em; }
tr.bad td { background: var(--warn-bg); }
td.cid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
footer { margin-top: 24px; color: var(--muted); font-size: 12px; text-align: center; }
@media (max-width: 640px) {
  .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .summary .tile:last-child { grid-column: 1 / -1; }
  .ev { flex-direction: column; gap: 2px; }
}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Карта сети</h1>
    <span class="host" id="host"></span>
    <span class="conn" id="conn"><span class="dot"></span><span id="conn-text">Подключение…</span></span>
  </header>
  <div class="summary">
    <div class="tile ok"><div class="n" id="n-online">–</div><div class="l">В сети</div></div>
    <div class="tile off"><div class="n" id="n-offline">–</div><div class="l">Не отвечают</div></div>
    <div class="tile fail"><div class="n" id="n-conflict">–</div><div class="l">Конфликты IP</div></div>
    <div class="tile"><div class="n" id="n-subnets">–</div><div class="l">Подсети</div></div>
    <div class="tile" id="t-dhcp"><div class="n" id="n-dhcp">–</div><div class="l">DHCP-серверы</div></div>
  </div>
  <div class="warnings" id="warnings"></div>
  <div id="maps"></div>

  <h2>Хосты</h2>
  <div class="toolbar">
    <input id="search" type="search" placeholder="Поиск по IP, MAC, имени, производителю…" autocomplete="off">
    <div class="chips" id="chips">
      <button class="chip active" data-f="all">Все</button>
      <button class="chip" data-f="online">В сети</button>
      <button class="chip" data-f="offline">Не отвечают</button>
      <button class="chip" data-f="conflict">Конфликты</button>
    </div>
  </div>
  <div class="tablewrap">
    <table>
      <thead><tr id="thead">
        <th data-k="status">Статус</th><th data-k="ip" class="sorted">IP</th><th data-k="mac">MAC</th><th data-k="vendor">Производитель</th>
        <th data-k="hostname">Имя</th><th data-k="iface">Интерфейс</th><th data-k="last_seen">Последний ответ</th><th data-k="first_seen">Впервые</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>

  <section class="group" id="dhcp-group">
    <button class="group-head" id="dhcp-head" type="button">
      <span class="chev">&#9662;</span><span class="gt">DHCP</span><span class="gs" id="dhcp-pills"></span>
    </button>
    <div class="gbody" id="dhcp"></div>
  </section>

  <h2>События</h2>
  <div class="events" id="events"></div>
  <footer id="footer"></footer>
</div>
<script>
"use strict";
let data = null, filter = "all", sortKey = "ip", sortDesc = false, selected = "";
const $ = id => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const sv = (tag, attrs, cls) => { const e = document.createElementNS(SVG, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (cls) e.setAttribute("class", cls); return e; };

const ipNum = ip => ip.split(".").reduce((a, o) => a * 256 + +o, 0);
const status = h => h.conflict ? "fail" : h.online ? "ok" : "off";
const STATUS_TEXT = { ok: "В сети", off: "Не отвечает", fail: "Конфликт IP" };
const vendorText = h => h.vendor || (h.local_mac ? "локальный MAC" : "");
const short = (s, n) => s.length > n ? s.slice(0, n - 1) + "…" : s;

function ago(ms) {
  if (!ms) return "—";
  const s = Math.max(0, (data.time - ms) / 1000);
  if (s < 60) return Math.floor(s) + " с назад";
  if (s < 3600) return Math.floor(s / 60) + " мин назад";
  if (s < 86400) return Math.floor(s / 3600) + " ч " + Math.floor(s % 3600 / 60) + " мин назад";
  return Math.floor(s / 86400) + " д назад";
}
function clock(ms) {
  const d = new Date(ms);
  return d.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" }) + " " + d.toLocaleTimeString("ru-RU");
}

const displayName = h => h.hostname || h.dhcp_hostname || "";

function hostTitle(h) {
  return [h.ip + "  " + h.mac, h.hostname, h.dhcp_hostname && h.dhcp_hostname !== h.hostname ? "DHCP: " + h.dhcp_hostname : "",
          h.client_id ? "Client-ID: " + h.client_id : "", vendorText(h), STATUS_TEXT[status(h)] + (h.self ? " · эта машина" : "") + (h.gateway ? " · шлюз" : ""),
          "Последний ответ: " + ago(h.last_seen)].filter(Boolean).join("\n");
}

function node(g, x, y, r, cls, octet, label, label2, title, onClick) {
  const n = sv("g", { transform: `translate(${x.toFixed(1)},${y.toFixed(1)})` }, "node " + cls);
  n.append(sv("circle", { r }));
  const t = sv("text", {}, "oct"); t.textContent = octet; n.append(t);
  if (label) { const l = sv("text", { y: r + 14 }, "lbl"); l.textContent = label; n.append(l); }
  if (label2) { const l = sv("text", { y: r + 27 }, "lbl2"); l.textContent = label2; n.append(l); }
  const tt = sv("title"); tt.textContent = title; n.append(tt);
  if (onClick) n.addEventListener("click", onClick);
  g.append(n);
}

function drawMap(subnet, hosts) {
  const gwHost = subnet.gateway ? hosts.find(h => h.ip === subnet.gateway) : null;
  const ring = hosts.filter(h => h !== gwHost).sort((a, b) => ipNum(a.ip) - ipNum(b.ip) || a.mac.localeCompare(b.mac));
  const groups = [];
  for (const h of ring) {
    const last = groups[groups.length - 1];
    if (last && last[0].ip === h.ip) last.push(h); else groups.push([h]);
  }
  const SPACING = 100, R0 = 160, RD = 115, MIN_SCALE = 0.75;
  const rings = [];
  for (let g = 0, k = 0; g < groups.length; k++) {
    const r = R0 + k * RD, cap = Math.max(6, Math.floor(2 * Math.PI * r / SPACING)), items = [];
    let count = 0;
    while (g < groups.length && (count + groups[g].length <= cap || !items.length)) {
      count += groups[g].length;
      items.push(groups[g++]);
    }
    rings.push({ r, items });
  }
  const outer = (rings.length ? rings[rings.length - 1].r : R0) + 60;
  const svg = sv("svg", { viewBox: `${-outer} ${-outer} ${2 * outer} ${2 * outer}`, role: "img" });
  svg.style.minWidth = Math.round(2 * outer * MIN_SCALE) + "px";
  svg.style.maxWidth = Math.round(2 * outer) + "px";
  const links = sv("g"), nodes = sv("g");
  svg.append(links, nodes);

  rings.forEach((rg, k) => {
    const count = rg.items.reduce((n, g) => n + g.length, 0), unit = 2 * Math.PI / count, inner = Math.min(unit, SPACING / rg.r);
    const placed = [];
    let cursor = -Math.PI / 2 + (k % 2 ? unit / 2 : 0);
    for (const group of rg.items) {
      const center = cursor + unit * (group.length - 1) / 2;
      group.forEach((h, j) => placed.push([h, center + inner * (j - (group.length - 1) / 2)]));
      cursor += unit * group.length;
    }
    placed.forEach(([h, a]) => {
      const x = rg.r * Math.cos(a), y = rg.r * Math.sin(a);
      links.append(sv("line", { x1: 0, y1: 0, x2: x.toFixed(1), y2: y.toFixed(1) }, "link" + (h.conflict ? " fail" : "")));
      const cls = status(h) + (h.self ? " self" : "");
      const name = displayName(h), main = name || h.vendor || "";
      const sub = h.conflict ? "конфликт IP" : h.self ? "эта машина" : name ? h.vendor || (h.local_mac ? "лок. MAC" : "") : h.local_mac ? "лок. MAC" : "";
      node(nodes, x, y, 16, cls, "." + h.ip.split(".")[3], short(main, 18), short(sub, 20), hostTitle(h), () => select(h));
    });
  });

  if (gwHost) {
    node(nodes, 0, 0, 24, "gw" + (gwHost.self ? " self" : ""), "." + gwHost.ip.split(".")[3], "шлюз " + gwHost.ip,
         short(gwHost.hostname || vendorText(gwHost), 22), hostTitle(gwHost), () => select(gwHost));
  } else {
    node(nodes, 0, 0, 24, "hub", "/" + subnet.subnet.split("/")[1], subnet.subnet, subnet.gateway ? "шлюз " + subnet.gateway + " не отвечает" : "",
         subnet.iface + " " + subnet.subnet);
  }
  return svg;
}

const collapsed = new Set();
try { for (const k of JSON.parse(localStorage.getItem("netmap-collapsed") || "[]")) collapsed.add(k); } catch (e) {}
const saveCollapsed = () => { try { localStorage.setItem("netmap-collapsed", JSON.stringify([...collapsed])); } catch (e) {} };

function renderMaps() {
  const scrolls = {};
  for (const sc of document.querySelectorAll(".map .scroll")) scrolls[sc.dataset.key] = [sc.scrollLeft, sc.scrollTop];
  const out = [];
  for (const s of data.subnets) {
    const hosts = data.hosts.filter(h => h.subnet === s.subnet && h.iface === s.iface);
    const key = s.iface + " " + s.subnet;
    const sec = el("section", "group" + (collapsed.has(key) ? " collapsed" : ""));
    const others = hosts.filter(h => !h.self), on = others.filter(h => h.online).length, off = others.length - on, bad = new Set(hosts.filter(h => h.conflict).map(h => h.ip)).size;
    const head = el("button", "group-head" + (bad ? " fail" : ""));
    head.type = "button";
    const title = el("span", "gt", s.iface); title.append(el("small", "", s.subnet + " · " + s.addr));
    const pills = el("span", "gs");
    pills.append(el("span", "pill ok", "в сети: " + on));
    if (off) pills.append(el("span", "pill off", "не отвечают: " + off));
    if (bad) pills.append(el("span", "pill fail", "конфликтов: " + bad));
    head.append(el("span", "chev", "▾"), title, pills);
    head.addEventListener("click", () => {
      if (sec.classList.toggle("collapsed")) collapsed.add(key); else collapsed.delete(key);
      saveCollapsed();
    });
    const body = el("div", "gbody"), map = el("div", "map"), scroll = el("div", "scroll");
    scroll.dataset.key = key;
    scroll.append(drawMap(s, hosts));
    map.append(scroll);
    const lg = el("div", "legend");
    for (const [c, t] of [["var(--accent)", "шлюз"], ["var(--ok)", "в сети"], ["var(--off)", "не отвечает"], ["var(--fail)", "конфликт IP"]]) {
      const i = el("span"); const d = el("i"); d.style.background = c; i.append(d, t); lg.append(i);
    }
    const me = el("span"); const d = el("i"); d.style.background = "transparent"; d.style.border = "2px solid var(--accent)"; me.append(d, "эта машина");
    lg.append(me);
    map.append(lg);
    body.append(map);
    sec.append(head, body);
    out.push(sec);
  }
  $("maps").replaceChildren(...out);
  for (const sc of document.querySelectorAll(".map .scroll")) {
    const saved = scrolls[sc.dataset.key];
    if (saved) [sc.scrollLeft, sc.scrollTop] = saved;
    else { sc.scrollLeft = (sc.scrollWidth - sc.clientWidth) / 2; sc.scrollTop = (sc.scrollHeight - sc.clientHeight) / 2; }
  }
  if (!out.length) $("maps").append(el("div", "empty", data.scans ? "Нет подсетей для сканирования" : "Идёт первое сканирование…"));
}

function select(h) {
  selected = h.ip + "|" + h.mac;
  $("search").value = h.ip;
  filter = "all";
  for (const c of document.querySelectorAll(".chip")) c.classList.toggle("active", c.dataset.f === "all");
  renderTable();
  const row = document.querySelector("tr.sel");
  if (row) row.scrollIntoView({ behavior: "smooth", block: "center" });
}

function nameCell(h) {
  const td = el("td", displayName(h) ? "" : "muted", displayName(h) || "—");
  if (!h.hostname && h.dhcp_hostname) td.append(el("span", "tag", "DHCP"));
  return td;
}

function sortValue(h, k) {
  if (k === "ip") return ipNum(h.ip);
  if (k === "status") return { fail: 0, ok: 1, off: 2 }[status(h)];
  if (k === "vendor") return vendorText(h).toLowerCase();
  if (k === "hostname") return displayName(h).toLowerCase();
  if (k === "last_seen" || k === "first_seen") return h[k];
  return String(h[k] || "").toLowerCase();
}

function renderTable() {
  const q = $("search").value.trim().toLowerCase();
  const rows = data.hosts.filter(h =>
    (filter === "all" || (filter === "online" && h.online) || (filter === "offline" && !h.online) || (filter === "conflict" && h.conflict)) &&
    (!q || [h.ip, h.mac, h.hostname, h.dhcp_hostname, h.client_id, vendorText(h), h.iface].some(v => v.toLowerCase().includes(q))));
  rows.sort((a, b) => {
    const x = sortValue(a, sortKey), y = sortValue(b, sortKey);
    const r = x < y ? -1 : x > y ? 1 : ipNum(a.ip) - ipNum(b.ip);
    return sortDesc ? -r : r;
  });
  const tb = $("tbody");
  tb.replaceChildren(...rows.map(h => {
    const tr = el("tr", selected === h.ip + "|" + h.mac ? "sel" : "");
    const st = status(h), stc = el("td"), s = el("span", "st " + st); s.append(el("i"), STATUS_TEXT[st]); stc.append(s);
    const ipc = el("td", "mono", h.ip);
    if (h.self) ipc.append(el("span", "tag", "эта машина"));
    if (h.gateway) ipc.append(el("span", "tag", "шлюз"));
    tr.append(stc, ipc, el("td", "mono", h.mac), el("td", h.vendor ? "" : "muted", vendorText(h) || "—"), nameCell(h),
              el("td", "mono", h.iface), el("td", "muted", h.self ? "—" : ago(h.last_seen)), el("td", "muted", ago(h.first_seen)));
    tr.title = hostTitle(h);
    return tr;
  }));
  if (!rows.length) { const tr = el("tr"), td = el("td", "empty", "Нет хостов, подходящих под фильтр"); td.colSpan = 8; tr.append(td); tb.append(tr); }
}

const EV_CLASS = { ip_conflict: "fail", mac_changed: "warn", host_lost: "", host_back: "ok", new_host: "", conflict_resolved: "ok",
                   dhcp_server: "", dhcp_multiple_servers: "fail", dhcp_shared_client_id: "warn" };

function table(headers, rows) {
  const wrap = el("div", "tablewrap"), t = el("table"), head = el("tr");
  for (const h of headers) head.append(el("th", "", h));
  const thead = el("thead"); thead.append(head);
  const tb = el("tbody"); tb.append(...rows);
  t.append(thead, tb); wrap.append(t);
  return wrap;
}

function serversBySegment(d) {
  const seg = {};
  for (const s of d.servers) (seg[s.iface] = seg[s.iface] || []).push(s);
  return seg;
}

function renderDhcp() {
  const d = data.dhcp, box = $("dhcp");
  const seg = serversBySegment(d), multi = Object.entries(seg).filter(([, l]) => l.length > 1), shared = Object.entries(d.shared_client_ids);
  $("n-dhcp").textContent = d.servers.length;
  $("t-dhcp").classList.toggle("dhcp-bad", multi.length > 0);
  const head = $("dhcp-head");
  head.className = "group-head" + (multi.length ? " fail" : "");
  const pills = [el("span", "pill ok", "серверов: " + d.servers.length), el("span", "pill off", "клиентов: " + d.clients.length)];
  if (multi.length) pills.push(el("span", "pill fail", "несколько серверов"));
  if (shared.length) pills.push(el("span", "pill fail", "общих Client-ID: " + shared.length));
  $("dhcp-pills").replaceChildren(...pills);

  const status = el("div", "dstatus");
  const item = (k, v) => { const s = el("span"); s.append(k + " ", el("b", "", v)); return s; };
  status.append(item("Прослушивание:", d.watching ? "идёт" : "выключено"),
                item("Активный поиск серверов:", d.probing ? "включён" + (d.last_probe ? ", последний " + ago(d.last_probe) : "") : "выключен"));

  const alerts = el("div", "alerts");
  for (const [iface, list] of multi)
    alerts.append(el("div", "alert", "⚠ В сегменте " + iface + " отвечают несколько DHCP-серверов: " + list.map(s => s.ip + " (" + s.mac + (s.vendor ? ", " + s.vendor : "") + ")").join(", ")));
  for (const [id, macs] of shared)
    alerts.append(el("div", "alert warn", "⚠ Client-ID " + id + " используют несколько MAC: " + macs.join(", ") +
                     ". DHCP-сервер считает такие узлы одним клиентом и может выдать им один адрес (часто это клоны с одинаковым /etc/machine-id)."));

  const srows = d.servers.map(s => {
    const tr = el("tr", multi.some(([i]) => i === s.iface) ? "bad" : "");
    tr.append(el("td", "mono", s.ip), el("td", "mono", s.mac), el("td", s.vendor ? "" : "muted", s.vendor || "—"), el("td", "mono", s.iface),
              el("td", "mono", s.router || "—"), el("td", "", s.lease ? Math.round(s.lease / 60) + " мин" : "—"),
              el("td", "mono", s.last_offered || "—"), el("td", "", s.answered_probe ? "да" : "—"), el("td", "muted", ago(s.last_seen)));
    return tr;
  });
  const crows = d.clients.slice().sort((a, b) => b.last_seen - a.last_seen).map(c => {
    const tr = el("tr", c.shared_client_id ? "bad" : "");
    const cid = el("td", "cid", c.client_id || "—"); cid.title = c.client_id;
    tr.append(el("td", "mono", c.mac), cid, el("td", c.hostname ? "" : "muted", c.hostname || "—"), el("td", "mono", c.requested_ip || "—"),
              el("td", "mono", c.server_id || "—"), el("td", "", c.last_type), el("td", "muted", ago(c.last_seen)));
    return tr;
  });

  const parts = [status, alerts, el("div", "subh", "Серверы")];
  parts.push(srows.length ? table(["IP", "MAC", "Производитель", "Интерфейс", "Шлюз", "Аренда", "Выдал", "Ответил на поиск", "Последний ответ"], srows)
                          : el("div", "empty", d.probing ? "DHCP-серверы не ответили" : "Серверы не замечены. Их ответы обычно адресные и не видны; включите dhcp_probe для активного поиска"));
  parts.push(el("div", "subh", "Клиенты"));
  parts.push(crows.length ? table(["MAC", "Client-ID", "Имя", "Запрошенный адрес", "Сервер", "Сообщение", "Замечен"], crows)
                          : el("div", "empty", "DHCP-запросы клиентов пока не замечены"));
  box.replaceChildren(...parts);
}
function renderEvents() {
  const list = data.events.slice().reverse().map(e => {
    const r = el("div", "ev " + (EV_CLASS[e.kind] || ""));
    r.append(el("time", "", clock(e.time)), el("span", "", e.text));
    return r;
  });
  $("events").replaceChildren(...list);
  if (!list.length) $("events").append(el("div", "empty", "Событий пока нет"));
}

function render() {
  const others = data.hosts.filter(h => !h.self);
  $("n-online").textContent = others.filter(h => h.online).length;
  $("n-offline").textContent = others.filter(h => !h.online).length;
  const conflicts = new Set(data.hosts.filter(h => h.conflict).map(h => h.ip)).size;
  $("n-conflict").textContent = conflicts;
  $("n-subnets").textContent = data.subnets.length;
  $("host").textContent = data.hostname;
  $("warnings").textContent = data.warnings.length ? "⚠ " + data.warnings.join(" · ") : "";
  document.title = (conflicts ? "(" + conflicts + " конфл.) " : "") + "Карта сети — " + data.hostname;
  renderMaps();
  renderTable();
  renderDhcp();
  renderEvents();
}

function setConn(ok, text) { $("conn").classList.toggle("lost", !ok); $("conn-text").textContent = text; }

let timer = null;
async function refresh() {
  let interval = 10;
  try {
    const r = await fetch("api/network", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    data = await r.json();
    interval = Math.min(10, data.scan_interval_sec);
    setConn(true, data.last_scan ? "Сканирование " + ago(data.last_scan) : "Идёт первое сканирование…");
    $("footer").textContent = "Сканирование каждые " + data.scan_interval_sec + " с · циклов: " + data.scans;
    render();
  } catch (e) {
    setConn(false, "Нет связи с сервером (" + e.message + ")");
  }
  clearTimeout(timer);
  timer = setTimeout(refresh, interval * 1000);
}

for (const c of document.querySelectorAll(".chip")) {
  c.addEventListener("click", () => {
    filter = c.dataset.f;
    for (const o of document.querySelectorAll(".chip")) o.classList.toggle("active", o === c);
    if (data) renderTable();
  });
}
for (const th of document.querySelectorAll("#thead th")) {
  th.addEventListener("click", () => {
    if (sortKey === th.dataset.k) sortDesc = !sortDesc; else { sortKey = th.dataset.k; sortDesc = false; }
    for (const o of document.querySelectorAll("#thead th")) { o.classList.toggle("sorted", o === th); o.classList.toggle("desc", o === th && sortDesc); }
    if (data) renderTable();
  });
}
$("dhcp-head").addEventListener("click", () => {
  const on = $("dhcp-group").classList.toggle("collapsed");
  try { localStorage.setItem("netmap-dhcp-collapsed", on ? "1" : "0"); } catch (e) {}
});
try { if (localStorage.getItem("netmap-dhcp-collapsed") === "1") $("dhcp-group").classList.add("collapsed"); } catch (e) {}
$("search").addEventListener("input", () => { selected = ""; if (data) renderTable(); });
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
refresh();
</script>
</body>
</html>
)HTML";

} // namespace

std::string_view index_page() { return PAGE; }
