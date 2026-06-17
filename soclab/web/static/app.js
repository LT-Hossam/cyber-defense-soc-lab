/* =================================================================
   CYBER DEFENSE SOC — tactical console front-end
   Polls the Flask API and renders the six operational views.
   ================================================================= */
"use strict";

const API = "";
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const state = {
  view: "overview",
  alerts: [],
  events: [],
  stats: {},
  artifacts: {},
  sevFilter: "all",
  scenarios: [],
};

/* ---------------------------------------------------------------- fetch */
async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) throw new Error(path + " → " + r.status);
  return r.json();
}
function linkDown() { $("#status-dot").style.background = "#ff4d4d"; $("#status-dot").style.boxShadow = "0 0 10px #ff4d4d"; }
function linkUp()   { $("#status-dot").style.background = "#3ddc84"; $("#status-dot").style.boxShadow = "0 0 10px #3ddc84"; }

/* ---------------------------------------------------------------- clock */
function tickClock() {
  const d = new Date();
  $("#clock").textContent = d.toISOString().slice(11, 19) + " UTC";
}
setInterval(tickClock, 1000); tickClock();

/* ---------------------------------------------------------------- nav */
$$(".nav-item").forEach(btn => btn.addEventListener("click", () => {
  $$(".nav-item").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  const v = btn.dataset.view;
  state.view = v;
  $$(".view").forEach(s => s.classList.remove("active"));
  $("#view-" + v).classList.add("active");
  render();
}));

/* ---------------------------------------------------------------- poll */
async function poll() {
  try {
    const [stats, alerts, events, arts] = await Promise.all([
      api("/api/stats"),
      api("/api/alerts?limit=80"),
      api("/api/events?limit=40"),
      api("/api/forensics/artifacts"),
    ]);
    state.stats = stats; state.alerts = alerts;
    state.events = events; state.artifacts = arts;
    linkUp(); render();
  } catch (e) { linkDown(); console.warn(e); }
}

/* ================================================================ RENDER */
function render() {
  renderHeader();
  renderRail();
  if (state.view === "overview")   renderOverview();
  if (state.view === "threats")    renderThreats();
  if (state.view === "incidents")  renderIncidents();
  if (state.view === "users")      renderUsers();
  if (state.view === "forensics")  renderForensicsPanels();
}

function renderHeader() {
  const s = state.stats;
  const r = $("#readiness");
  r.className = "readiness lvl-" + (s.readiness_level || 5);
  $("#readiness-value").textContent = s.readiness || "DEFCON 5";
}

function renderRail() {
  const s = state.stats;
  $("#rail-events").textContent = s.events || 0;
  $("#rail-alerts").textContent = s.alerts || 0;
  const open = (s.status && s.status.open) || 0;
  const tcount = state.alerts.length;
  setBadge("#badge-threats", tcount);
  setBadge("#badge-incidents", open);
}
function setBadge(sel, n) {
  const el = $(sel);
  el.textContent = n;
  el.classList.toggle("show", n > 0);
}

/* ----------------------------------------------------------- OVERVIEW */
function renderOverview() {
  const s = state.stats;
  $("#kpi-events").textContent = s.events || 0;
  $("#kpi-alerts").textContent = s.alerts || 0;
  $("#kpi-crit").textContent   = (s.severity && s.severity.critical) || 0;
  $("#kpi-open").textContent   = (s.status && s.status.open) || 0;

  // severity bars
  const sev = s.severity || {};
  const max = Math.max(1, ...Object.values(sev));
  const order = ["critical", "high", "medium", "low"];
  $("#sevbars").innerHTML = order.map(k => {
    const n = sev[k] || 0;
    return `<div class="sevrow">
      <span class="lab ${k}">${k.toUpperCase()}</span>
      <span class="track"><span class="fill ${k}" style="width:${(n/max)*100}%"></span></span>
      <span class="num">${n}</span></div>`;
  }).join("");

  // mitre chips
  const tech = s.techniques || [];
  $("#mitre-chips").innerHTML = tech.length
    ? tech.map(([t, c]) => `<span class="mchip">${t}<b>${c}</b></span>`).join("")
    : `<span class="mchip" style="color:var(--txt-faint)">No techniques observed — run a simulation</span>`;

  renderRadar();
  renderTicker();
}

function renderRadar() {
  const wrap = $("#radar-blips");
  const sevClass = { critical: "crit", high: "high", medium: "med", low: "low" };
  // newest 14 alerts become blips; severity → radius from centre
  const radius = { crit: 0.22, high: 0.40, med: 0.58, low: 0.76 };
  wrap.innerHTML = state.alerts.slice(0, 14).map((a, i) => {
    const c = sevClass[a.severity] || "low";
    // deterministic angle from alert id so blips don't jump every poll
    const seed = (a._id || ("x" + i)).split("").reduce((h, ch) => h + ch.charCodeAt(0), 0);
    const ang = (seed * 47) % 360 * Math.PI / 180;
    const rr = radius[c] * 140;
    const x = 140 + Math.cos(ang) * rr;
    const y = 140 + Math.sin(ang) * rr;
    return `<div class="blip ${c}" style="left:${x}px;top:${y}px;animation-delay:${i*0.12}s"></div>`;
  }).join("");
}

function renderTicker() {
  const rows = [];
  // interleave recent alerts (highlighted) with events
  state.alerts.slice(0, 6).forEach(a => rows.push({
    t: (a.detected_at || "").slice(11, 19), s: a.rule_id,
    d: a.summary, alert: true, time: a.detected_at,
  }));
  state.events.slice(0, 18).forEach(e => rows.push({
    t: (e.timestamp || e.ingested_at || "").slice(11, 19),
    s: (e.source || "").split(":").pop(),
    d: (e.message || "").slice(0, 90), alert: false, time: e.timestamp || e.ingested_at,
  }));
  rows.sort((a, b) => (b.time || "").localeCompare(a.time || ""));
  $("#ticker").innerHTML = rows.slice(0, 22).map(r =>
    `<div class="tick ${r.alert ? "alert" : ""}">
       <span class="t">${r.t}</span><span class="s">${r.s}</span><span>${esc(r.d)}</span></div>`
  ).join("");
}

/* ----------------------------------------------------------- THREATS */
$$(".chip-f").forEach(c => c.addEventListener("click", () => {
  $$(".chip-f").forEach(x => x.classList.remove("active"));
  c.classList.add("active");
  state.sevFilter = c.dataset.sev;
  renderThreats();
}));

function renderThreats() {
  let data = state.alerts;
  if (state.sevFilter !== "all") data = data.filter(a => a.severity === state.sevFilter);
  const list = $("#alert-list");
  if (!data.length) {
    list.innerHTML = `<div style="padding:40px;text-align:center;color:var(--txt-faint);font-family:var(--mono)">
      NO ALERTS // launch a scenario from the DETECTIONS view</div>`;
    return;
  }
  list.innerHTML = data.map(a => `
    <div class="alert-row ${a.severity}" data-id="${a._id}">
      <span class="sevbar"></span>
      <span class="a-sev">${a.severity.toUpperCase()}</span>
      <div class="a-main">
        <div class="a-name">${esc(a.rule_name)}</div>
        <div class="a-sum">${esc(a.summary)}</div>
      </div>
      <div class="a-meta">${esc((a.mitre_techniques||[])[0]||"")}<br>${esc(a.host)}</div>
      <span class="a-status ${a.status}">${(a.status||"open").toUpperCase()}</span>
    </div>`).join("");
  $$(".alert-row", list).forEach(row =>
    row.addEventListener("click", () => openDrawer(row.dataset.id)));
}

/* --------------------------------------------------------- INCIDENTS */
function renderIncidents() {
  // group open/active alerts into incidents by rule + host
  const groups = {};
  state.alerts.forEach(a => {
    const k = a.rule_id + "|" + a.host;
    (groups[k] = groups[k] || []).push(a);
  });
  const incidents = Object.entries(groups).map(([k, arr], i) => {
    const lead = arr[0];
    return { id: "INC-" + String(i + 1).padStart(3, "0"), lead, count: arr.length,
             alerts: arr, status: lead.status || "open" };
  });

  const stageCount = { identification: 0, containment: 0, eradication: 0, recovery: 0, closed: 0 };
  incidents.forEach(inc => {
    const map = { open: "identification", investigating: "identification",
                  contained: "containment", eradicated: "eradication",
                  recovering: "recovery", closed: "closed" };
    stageCount[map[inc.status] || "identification"]++;
  });
  $("#ir-id").textContent = stageCount.identification;
  $("#ir-cont").textContent = stageCount.containment;
  $("#ir-erad").textContent = stageCount.eradication;
  $("#ir-rec").textContent = stageCount.recovery;
  $("#ir-closed").textContent = stageCount.closed;

  const grid = $("#incident-grid");
  if (!incidents.length) {
    grid.innerHTML = `<div style="padding:30px;color:var(--txt-faint);font-family:var(--mono)">
      No active incidents. Launch a simulation to populate the queue.</div>`;
    return;
  }
  grid.innerHTML = incidents.map(inc => `
    <div class="inc-card">
      <div class="inc-head">
        <span class="inc-id">${inc.id}</span>
        <span class="inc-sev ${inc.lead.severity}">${inc.lead.severity.toUpperCase()}</span>
      </div>
      <div class="inc-body">
        <div class="inc-title">${esc(inc.lead.rule_name)}</div>
        <div class="inc-line">HOST &nbsp;<b>${esc(inc.lead.host)}</b></div>
        <div class="inc-line">ACTOR&nbsp;<b>${esc(inc.lead.user)}</b> · SRC ${esc(inc.lead.src_ip)}</div>
        <div class="inc-line">ALERTS <b>${inc.count}</b> · MITRE ${esc((inc.lead.mitre_techniques||[])[0]||"")}</div>
        <div class="inc-line">STAGE <b>${(inc.status||"open").toUpperCase()}</b></div>
        <div class="inc-actions">
          ${["investigating","contained","eradicated","recovering","closed"].map(st =>
            `<button class="inc-btn" data-ids="${inc.alerts.map(a=>a._id).join(',')}" data-st="${st}">${st.toUpperCase()}</button>`
          ).join("")}
        </div>
      </div>
    </div>`).join("");

  $$(".inc-btn", grid).forEach(b => b.addEventListener("click", async () => {
    const ids = b.dataset.ids.split(",");
    for (const id of ids) await setStatus(id, b.dataset.st);
    await poll();
  }));
}

/* ------------------------------------------------------------- USERS */
function renderUsers() {
  const accounts = state.artifacts.involved_accounts || [];
  const ips = state.artifacts.suspicious_ips || [];
  // accounts touched by alerts are higher risk
  const alertUsers = new Set(state.alerts.map(a => (a.user || "").toLowerCase()));
  $("#user-tbody").innerHTML = accounts.map(([u, c]) => {
    const risk = alertUsers.has(u.toLowerCase()) ? (c > 5 ? "high" : "med") : "low";
    const flagged = alertUsers.has(u.toLowerCase());
    return `<tr>
      <td>${esc(u)}</td><td>${c}</td>
      <td><span class="risk-pill ${risk}">${risk.toUpperCase()}</span></td>
      <td>${flagged ? '⚑ FLAGGED' : 'nominal'}</td></tr>`;
  }).join("") || emptyRow(4);

  const alertIps = new Set(state.alerts.map(a => a.src_ip));
  $("#ip-tbody").innerHTML = ips.map(([ip, c]) => {
    const hostile = alertIps.has(ip);
    return `<tr><td>${esc(ip)}</td><td>${c}</td>
      <td>${hostile ? '<span class="risk-pill high">HOSTILE</span>' : 'benign'}</td></tr>`;
  }).join("") || emptyRow(3);
}
function emptyRow(cols){return `<tr><td colspan="${cols}" style="color:var(--txt-faint)">No data — run a simulation</td></tr>`;}

/* --------------------------------------------------------- DETECTIONS */
async function loadDetections() {
  const [rules, scenarios] = await Promise.all([api("/api/rules"), api("/api/scenarios")]);
  state.scenarios = scenarios;

  // scenario launcher
  const map = [
    ["spray", "PASSWORD SPRAY", "T1110.003 · Credential Access"],
    ["nmap", "NMAP RECON", "T1046 · Discovery"],
    ["powershell", "SUSPICIOUS POWERSHELL", "T1059.001 · Execution"],
    ["privesc", "PRIVILEGE ESCALATION", "T1078 · Priv-Esc"],
    ["malware", "MALWARE (EICAR)", "T1204 · Execution"],
  ];
  $("#sim-buttons").innerHTML = map.map(([k, label, sub]) =>
    `<button class="sim-btn" data-sc="${k}">▶ ${label}<small>${sub}</small></button>`).join("");
  $$(".sim-btn").forEach(b => b.addEventListener("click", () => runScenario(b.dataset.sc, b)));

  // rule catalogue
  $("#rule-grid").innerHTML = rules.map(r => `
    <div class="rule-card ${r.severity}">
      <div class="rc-id">${r.id} · ${r.severity.toUpperCase()} · WAZUH ${r.wazuh_rule_id}</div>
      <div class="rc-name">${esc(r.name)}</div>
      <div class="rc-desc">${esc(r.description)}</div>
      <div class="rc-mitre">${(r.mitre_techniques||[]).map(t=>`<span>${esc(t)}</span>`).join("")}</div>
    </div>`).join("");
}

async function runScenario(key, btn) {
  const log = $("#sim-log");
  log.textContent = `> launching scenario "${key}" ...\n`;
  if (btn) { btn.disabled = true; btn.style.opacity = .6; }
  try {
    const res = await api("/api/simulate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: key }),
    });
    log.textContent += `> scenarios fired: ${res.scenarios.join(", ")}\n`;
    log.textContent += `> alerts raised : ${res.alerts_raised}\n`;
    res.alerts.forEach(a =>
      log.textContent += `  [${a.severity.toUpperCase()}] ${a.rule_id} ${a.summary}\n`);
    log.textContent += "> done.\n";
  } catch (e) { log.textContent += "! error: " + e.message + "\n"; }
  if (btn) { btn.disabled = false; btn.style.opacity = 1; }
  await poll();
}

/* --------------------------------------------------------- FORENSICS */
function renderForensicsPanels() {
  const a = state.artifacts;
  const cols = [
    ["SUSPICIOUS IPs", a.suspicious_ips],
    ["ACCOUNTS", a.involved_accounts],
    ["AFFECTED HOSTS", a.affected_hosts],
    ["MITRE TECHNIQUES", a.mitre_techniques],
  ];
  $("#ioc-cols").innerHTML = cols.map(([title, items]) => `
    <div class="ioc-group"><h4>${title}</h4><ul>
      ${(items||[]).slice(0,8).map(([k,v]) => `<li>${esc(String(k))}<b>${v}</b></li>`).join("")
        || '<li style="color:var(--txt-faint)">—</li>'}
    </ul></div>`).join("");
  loadTimeline();
}

async function loadTimeline() {
  try {
    const tl = await api("/api/timeline?limit=120");
    $("#timeline").innerHTML = tl.slice().reverse().map(r => `
      <div class="tl-row ${r.kind === 'ALERT' ? 'alert' : ''}">
        <span class="tl-time">${(r.time||'').slice(0,19).replace('T',' ')}</span>
        <span class="tl-kind">${r.kind}</span>
        <span>${esc(r.host)}</span>
        <span>${esc((r.detail||'').slice(0,80))}</span></div>`).join("");
  } catch (e) { /* ignore */ }
}

$("#btn-report").addEventListener("click", async () => {
  const pre = $("#report-pre");
  pre.textContent = "compiling case file ...";
  try {
    const res = await api("/api/forensics/report?analyst=SOC%20Analyst");
    pre.textContent = res.markdown;
  } catch (e) { pre.textContent = "error: " + e.message; }
});

/* ------------------------------------------------------------ DRAWER */
function openDrawer(id) {
  const a = state.alerts.find(x => x._id === id);
  if (!a) return;
  const body = $("#drawer-body");
  const sevColor = { critical: "#ff4d4d", high: "#ff8c42", medium: "#ffd34e", low: "#3ddc84" }[a.severity];
  body.innerHTML = `
    <span class="dk-sev" style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}">
      ${a.severity.toUpperCase()} · ${a.rule_id}</span>
    <h3 class="dk-title">${esc(a.rule_name)}</h3>
    <div class="dk-sum">${esc(a.summary)}</div>

    <div class="dk-block"><h5>TRIAGE</h5>
      <div class="dk-kv"><span>Host</span>${esc(a.host)}</div>
      <div class="dk-kv"><span>Source IP</span>${esc(a.src_ip)}</div>
      <div class="dk-kv"><span>Account</span>${esc(a.user)}</div>
      <div class="dk-kv"><span>Events correlated</span>${a.event_count}</div>
      <div class="dk-kv"><span>Wazuh rule</span>${a.wazuh_rule_id}</div>
      <div class="dk-kv"><span>Status</span>${(a.status||'open').toUpperCase()}</div>
      <div class="dk-kv"><span>Detected</span>${(a.detected_at||'').slice(0,19).replace('T',' ')}</div>
    </div>

    <div class="dk-block"><h5>MITRE ATT&CK</h5>
      <div class="dk-mitre">${(a.mitre_techniques||[]).map(t=>`<span>${esc(t)}</span>`).join("")}</div>
      <div class="dk-mitre">${(a.mitre_tactics||[]).map(t=>`<span>${esc(t)}</span>`).join("")}</div>
    </div>

    <div class="dk-block"><h5>SAMPLE EVENT</h5>
      <div class="dk-json">${esc(JSON.stringify(a.sample_event, null, 2))}</div>
    </div>

    <div class="dk-block"><h5>RESPONSE</h5>
      <div class="dk-actions">
        ${["investigating","contained","eradicated","closed"].map(st =>
          `<button class="inc-btn" data-st="${st}">${st.toUpperCase()}</button>`).join("")}
      </div>
    </div>`;
  $$(".dk-actions .inc-btn", body).forEach(b => b.addEventListener("click", async () => {
    await setStatus(id, b.dataset.st); await poll(); closeDrawer();
  }));
  $("#drawer").classList.add("open");
}
function closeDrawer(){ $("#drawer").classList.remove("open"); }
$("#drawer-close").addEventListener("click", closeDrawer);
$("#drawer").addEventListener("click", e => { if (e.target.id === "drawer") closeDrawer(); });

async function setStatus(id, status) {
  try {
    await api(`/api/alerts/${id}/status`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
  } catch (e) { console.warn(e); }
}

/* ------------------------------------------------------------ GLOBAL BTNS */
$("#btn-sim-all").addEventListener("click", async () => {
  const btn = $("#btn-sim-all");
  btn.disabled = true; btn.textContent = "▶ SIMULATING…";
  try {
    await api("/api/simulate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: "all" }),
    });
  } catch (e) { console.warn(e); }
  btn.disabled = false; btn.textContent = "▶ RUN FULL SIMULATION";
  await poll();
});
$("#btn-reset").addEventListener("click", async () => {
  if (!confirm("Clear all events and alerts?")) return;
  await api("/api/reset", { method: "POST" });
  await poll();
});

/* ------------------------------------------------------------- util */
function esc(s){ return String(s==null?"":s)
  .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }

/* ------------------------------------------------------------- boot */
loadDetections();
poll();
setInterval(poll, 4000);
