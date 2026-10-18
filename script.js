/* ================================================================
   script.js — CyberSim v2
   Handles: stage system, access control, SVG connections,
            packet animations, dynamic objectives, alert log
   ================================================================ */

'use strict';

// ── DOM refs ──────────────────────────────────────────────────
const termOutput  = document.getElementById('terminal-output');
const termInput   = document.getElementById('term-input');
const termTitle   = document.getElementById('term-title');
const stageBadge  = document.getElementById('stage-badge');
const panelTitle  = document.getElementById('panel-title');
const panelTag    = document.getElementById('panel-tag');
const tutScroll   = document.getElementById('tutorial-scroll');
const vizLabel    = document.getElementById('viz-label');
const alertEntries= document.getElementById('alert-entries');
const overlay     = document.getElementById('stage-overlay');
const overlayFill = document.getElementById('overlay-fill');
const connSvg     = document.getElementById('conn-svg');
const canvas      = document.getElementById('packet-canvas');
const ctx         = canvas.getContext('2d');
const vizArea     = document.getElementById('viz-area');

// ── Global state ──────────────────────────────────────────────
const state = {
  stage:        1,
  currentNode:  'attacker',    // where attacker currently "is"
  hydraSuccess: false,         // brute force completed?
  transitioning:false,
  completedKeys: new Set(),
  currentStep:  0,
  history:      [],
  histIdx:      -1,
  packets:      [],
  animFrame:    null,
  powerOffline: false,
  insight:      '',
  endShown:     false,
};

// ── Insight panel ──────────────────────────────────────────────
const INSIGHTS = {
  ping:   'Ping checks if a host is reachable over the network. It helps you confirm a target is online before you scan or attack it.',
  nmap:   'Nmap is a port scanner. It tells you which services are listening so you know what kinds of attacks might work.',
  gobust: 'Directory brute-forcing guesses hidden web paths like /admin. It is a common way to find exposed panels and files on websites.',
  hydra:  'Hydra simulates a brute-force attack by trying many passwords quickly. In real systems, rate limits and lockouts help defend against this.',
  ssh:    'SSH is a remote shell. Attackers use it for stable access after credentials are found or stolen.',
  scan:   'Internal scanning maps devices inside a network. This is often the first step before moving sideways to other machines.',
  pivot:  'Pivoting is lateral movement: you use one compromised system to reach others. Networks often trust internal traffic more than external traffic.',
  ddos:   'A DDoS flood overwhelms a service with too much traffic. The goal is to make systems slow or unavailable, not to “hack” a password.',
};

function renderInsight() {
  const panel = document.getElementById('insight-panel');
  const text  = document.getElementById('insight-text');
  if (!panel || !text) return;
  const has = !!state.insight;
  panel.style.display = has ? '' : 'none';
  if (has) text.textContent = state.insight;
}

function setInsight(key) {
  const msg = INSIGHTS[key];
  if (!msg) return;
  state.insight = msg;
  renderInsight();
}

function showEndPopup() {
  if (state.endShown) return;
  state.endShown = true;
  const el = document.getElementById('end-popup');
  if (!el) return;
  el.classList.add('show');
  el.setAttribute('aria-hidden', 'false');
}

function hideEndPopup() {
  const el = document.getElementById('end-popup');
  if (!el) return;
  el.classList.remove('show');
  el.setAttribute('aria-hidden', 'true');
}

// ── Node positions: % of viz-area width/height ────────────────
//    Defined per stage. Recalculated to px on layout/resize.
const LAYOUTS = {
  1: {
    'node-attacker':  { x:.20, y:.50 },
    'node-webserver': { x:.70, y:.50 },
  },
  2: {
    'node-attacker':  { x:.08, y:.50 },
    'node-webserver': { x:.25, y:.50 },
    'node-router':    { x:.45, y:.50 },
    'node-hospital':  { x:.65, y:.20 },
    'node-police':    { x:.65, y:.42 },
    'node-powerplant':{ x:.65, y:.65 },
    // Residential areas (stacked under the plant)
    'node-residential-1': { x:.55, y:.86 },
    'node-residential-2': { x:.65, y:.86 },
    'node-residential-3': { x:.75, y:.86 },
    'node-dam':       { x:.85, y:.78 },
    'node-scada':     { x:.85, y:.52 },
  },
};

// ── Connection definitions ────────────────────────────────────
//    Each entry: { from, to, style, label, stage }
//    style: 'solid' | 'dashed'
const CONNECTIONS = [
  // Stage 1
  { from:'node-attacker',   to:'node-webserver',  style:'solid',  label:'Internet Access',      stage:1 },
  // Stage 2
  { from:'node-attacker',   to:'node-webserver',  style:'solid',  label:'Backdoor Tunnel',       stage:2 },
  { from:'node-webserver',  to:'node-router',     style:'dashed', label:'Internal Network Link', stage:2 },
  { from:'node-router',     to:'node-hospital',   style:'dashed', label:'LAN Segment A',         stage:2 },
  { from:'node-router',     to:'node-police',     style:'dashed', label:'LAN Segment A',         stage:2 },
  { from:'node-router',     to:'node-powerplant', style:'dashed', label:'LAN Segment B',         stage:2 },
  { from:'node-powerplant', to:'node-residential-1', style:'dashed', label:'Distribution',       stage:2 },
  { from:'node-powerplant', to:'node-residential-2', style:'dashed', label:'Distribution',       stage:2 },
  { from:'node-powerplant', to:'node-residential-3', style:'dashed', label:'Distribution',       stage:2 },
  { from:'node-powerplant', to:'node-dam',        style:'dashed', label:'SCADA Connection',      stage:2 },
  { from:'node-powerplant', to:'node-scada',      style:'dashed', label:'OPC-UA Bus',            stage:2 },
];

function setPowerOffline(isOffline) {
  state.powerOffline = !!isOffline;
  document.querySelectorAll('.res-shortage').forEach(el => {
    el.style.display = state.powerOffline ? 'flex' : 'none';
  });
  if (state.powerOffline) addAlert('Electrical shortages reported in residential areas', 'danger');
}

// ── Stage / objective definitions ─────────────────────────────
const STAGES = {
  1: {
    badge:   'STAGE 1 — RECON',
    panelH:  '// Mission Briefing',
    tag:     'Stage 1',
    vizLbl:  '// Network Topology — Stage 1',
    user:    'guest@kali',
    story: {
      title:  'Scenario: Operation Nightwatch',
      body:   'You are a <b>penetration tester</b> auditing a small DMZ. A single web server is exposed on the internet. Your goal: gain shell access.',
      target: 'Target: <b>10.0.0.5</b>. Nothing else is reachable from the outside yet.',
      hint:   'Start with <code>ping 10.0.0.5</code> to confirm the host is alive.',
    },
    steps: [
      { key:'ping',    label:'Confirm host is alive',        cmd:'ping 10.0.0.5',                              hint:'Check reachability' },
      { key:'nmap',    label:'Scan for open ports',          cmd:'nmap 10.0.0.5',                              hint:'Discover running services' },
      { key:'gobust',  label:'Discover hidden directories',  cmd:'gobuster dir -u http://10.0.0.5',            hint:'Find the admin panel' },
      { key:'hydra',   label:'Brute-force SSH credentials',  cmd:'hydra -l admin -P passwords.txt ssh://10.0.0.5', hint:'Crack the password' },
      { key:'ssh',     label:'Gain SSH shell access',        cmd:'ssh admin@10.0.0.5',                         hint:'Only works after hydra' },
    ],
  },
  2: {
    badge:   'STAGE 2 — ANYTOWN BREACH',
    panelH:  '// AnyTown Infrastructure',
    tag:     'Stage 2',
    vizLbl:  '// AnyTown Municipal Network — 192.168.x.x',
    user:    'root@anytown-router',
    story: {
      title:  'Stage 2: Critical Infrastructure',
      body:   'You pivoted through the web server into <b>AnyTown\'s municipal network</b>. The internal router connects the hospital, power plant, water dam, and SCADA systems.',
      target: '<b>Note:</b> The Water Dam is only reachable <b>through the Power Plant</b>. Access control is enforced.',
      hint:   'Run <code>scan internal</code>, then <code>pivot router</code> to access internal segments. From there, use <code>pivot</code> and <code>exploit</code>.',
    },
    steps: [
      { key:'scan',     label:'Enumerate internal network',    cmd:'scan internal',     hint:'Map all reachable hosts' },
      { key:'router',   label:'Connect to municipal router',   cmd:'pivot router',      hint:'Establish internal foothold (required for lateral movement)' },
      { key:'hospital', label:'Pivot to hospital',             cmd:'pivot hospital',    hint:'Lateral movement via EternalBlue' },
      { key:'police',   label:'Compromise police comms',       cmd:'pivot police',      hint:'Telnet with default creds' },
      { key:'power',    label:'Pivot to power plant',          cmd:'pivot powerplant',  hint:'Modbus TCP — unauthenticated' },
      { key:'scada',    label:'Exploit SCADA controls',        cmd:'exploit scada',     hint:'OPC-UA write access' },
      { key:'dam',      label:'Access water dam via power plant', cmd:'pivot dam',      hint:'Only reachable via Power Plant' },
      { key:'ddos',     label:'Simulate DDoS on power plant',  cmd:'ddos powerplant',  hint:'Flood from compromised nodes' },
    ],
  },
};

// ── ACCESS CONTROL MAP ────────────────────────────────────────
//    Defines what node you must currently BE AT to reach the target
const ACCESS_RULES = {
  // Stage 1
  'node-webserver': ['attacker'],
  // Stage 2
  'node-router':    ['webserver'],
  'node-hospital':  ['router'],
  'node-police':    ['router'],
  'node-powerplant':['router'],
  'node-scada':     ['powerplant'],
  'node-dam':       ['powerplant'],   // ← ONLY via power plant
};

function canReach(targetNode) {
  const required = ACCESS_RULES[targetNode];
  if (!required) return true;
  return required.includes(state.currentNode);
}

// ── Alert log ─────────────────────────────────────────────────
function addAlert(text, type = '') {
  const icons = { warn:'⚠', danger:'🔴', good:'✅', '':'ℹ' };
  const div = document.createElement('div');
  div.className = `alert-entry ${type}`;
  div.innerHTML = `<span class="alert-icon">${icons[type]||'ℹ'}</span><span class="alert-text">${text}</span>`;
  alertEntries.prepend(div);
  // cap at 8
  while (alertEntries.children.length > 8) alertEntries.removeChild(alertEntries.lastChild);
}

// ── Render left panel ─────────────────────────────────────────
function renderPanel() {
  const s = STAGES[state.stage];
  stageBadge.textContent = s.badge;
  panelTitle.textContent = s.panelH;
  panelTag.textContent   = s.tag;
  vizLabel.textContent   = s.vizLbl;
  termTitle.textContent  = `bash — ${s.user}`;

  tutScroll.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.innerHTML = `
    <div class="story-block">
      <h2>${s.story.title}</h2>
      <p>${s.story.body}</p>
      <p style="margin-top:.55rem">${s.story.target}</p>
      <div class="hint-box">💡 ${s.story.hint}</div>
      <h2 style="margin-top:1.1rem">Objectives</h2>
      <ul class="step-list" id="step-list"></ul>
      <div class="insight-panel" id="insight-panel" style="display:none">
        <div class="insight-title">// Insight Panel</div>
        <div class="insight-text" id="insight-text"></div>
      </div>
    </div>
    <div class="story-block">
      <h2>Disclaimer</h2>
      <p>All actions are <b>simulated</b>. No real traffic is generated. For educational use only.</p>
    </div>
  `;
  tutScroll.appendChild(wrap);
  renderSteps();
  renderInsight();
}

function renderSteps() {
  const list = document.getElementById('step-list');
  if (!list) return;
  list.innerHTML = '';
  STAGES[state.stage].steps.forEach((step, i) => {
    const isDone   = state.completedKeys.has(step.key);
    const isActive = !isDone && i === state.currentStep;
    const li = document.createElement('li');
    li.className = `step-item${isActive?' active':''}${isDone?' done':''}`;
    li.innerHTML = `
      <span class="step-num">${isDone ? '✓' : i+1}</span>
      <span class="step-text">
        ${step.label}
        <code class="step-cmd">${isDone ? '✓ done' : step.cmd}</code>
        <span class="step-hint">${step.hint}</span>
      </span>
    `;
    list.appendChild(li);
  });
}

function completeStep(key) {
  if (state.completedKeys.has(key)) return;
  state.completedKeys.add(key);
  const steps = STAGES[state.stage].steps;
  while (state.currentStep < steps.length && state.completedKeys.has(steps[state.currentStep].key)) {
    state.currentStep++;
  }
  renderSteps();
  const allDone = steps.every(s => state.completedKeys.has(s.key));
  if (allDone && state.stage === 1) setTimeout(doStageTransition, 900);
  if (allDone && state.stage === 2) setTimeout(showEndPopup, 2200);
}

// ── Stage transition ──────────────────────────────────────────
function doStageTransition() {
  if (state.transitioning) return;
  state.transitioning = true;
  termInput.disabled  = true;
  printLine('[SYSTEM] All objectives complete. Installing backdoor and pivoting…', 'line-system');
  scrollBot();

  setTimeout(() => {
    overlay.classList.add('visible');
    requestAnimationFrame(() => { overlayFill.style.width = '100%'; });

    setTimeout(() => {
      overlay.classList.remove('visible');
      setTimeout(() => {
        state.stage       = 2;
        state.currentStep = 0;
        state.currentNode = 'webserver';
        setPowerOffline(false);

        // Show stage-2 nodes
        document.querySelectorAll('.s2-node').forEach(n => n.style.display = '');

        renderPanel();
        placeNodes();
        drawConnections();

        termInput.disabled = false;
        termInput.focus();
        state.transitioning = false;

        printLine('', 'line-response');
        printLine('[SYSTEM] Connected to AnyTown municipal network (192.168.1.1).', 'line-system');
        printLine('[SYSTEM] New commands available. Type "help" for the updated list.', 'line-system');
        scrollBot();
        addAlert('Lateral movement to internal network — tunnel active', 'good');
      }, 600);
    }, 3400);
  }, 600);
}

// ── Node positioning ──────────────────────────────────────────
function getVizSize() {
  return { w: vizArea.clientWidth, h: vizArea.clientHeight };
}

function placeNodes() {
  const layout = LAYOUTS[state.stage];
  const { w, h } = getVizSize();
  for (const [id, pos] of Object.entries(layout)) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.style.left = `${pos.x * w}px`;
    el.style.top  = `${pos.y * h}px`;
  }
}

function nodeCenter(id) {
  const el = document.getElementById(id);
  if (!el) return null;
  const box = el.querySelector('.node-box');
  const bx  = box.getBoundingClientRect();
  const svgR = connSvg.getBoundingClientRect();
  return {
    x: bx.left + bx.width / 2 - svgR.left,
    y: bx.top  + bx.height/ 2 - svgR.top,
  };
}

// ── SVG connection lines ───────────────────────────────────────
function drawConnections() {
  connSvg.innerHTML = '';
  const stageCons = CONNECTIONS.filter(c => c.stage === state.stage);
  const defs = document.createElementNS('http://www.w3.org/2000/svg','defs');
  // Arrow marker
  defs.innerHTML = `
    <marker id="arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L6,3 L0,6 Z" fill="#2a3545"/>
    </marker>
    <marker id="arr-accent" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L6,3 L0,6 Z" fill="rgba(0,255,136,0.5)"/>
    </marker>
  `;
  connSvg.appendChild(defs);

  stageCons.forEach(c => {
    const A = nodeCenter(c.from);
    const B = nodeCenter(c.to);
    if (!A || !B) return;

    const line = document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1', A.x); line.setAttribute('y1', A.y);
    line.setAttribute('x2', B.x); line.setAttribute('y2', B.y);
    line.setAttribute('stroke', '#2a3545');
    line.setAttribute('stroke-width', '1.5');
    if (c.style === 'dashed') line.setAttribute('stroke-dasharray','5 4');
    line.setAttribute('marker-end','url(#arr)');
    line.dataset.connFrom = c.from;
    line.dataset.connTo   = c.to;
    connSvg.appendChild(line);

    // Label at midpoint
    const mx = (A.x + B.x) / 2;
    const my = (A.y + B.y) / 2;
    const bg = document.createElementNS('http://www.w3.org/2000/svg','rect');
    const pad = 4;
    const tw  = c.label.length * 5.2 + pad * 2;
    bg.setAttribute('x',  mx - tw/2); bg.setAttribute('y', my - 9);
    bg.setAttribute('width', tw);     bg.setAttribute('height', 14);
    bg.setAttribute('rx','2');        bg.setAttribute('fill','#0a0c0f');
    bg.setAttribute('fill-opacity','.85');
    connSvg.appendChild(bg);

    const txt = document.createElementNS('http://www.w3.org/2000/svg','text');
    txt.setAttribute('x', mx); txt.setAttribute('y', my + 1.5);
    txt.setAttribute('text-anchor','middle');
    txt.setAttribute('dominant-baseline','middle');
    txt.setAttribute('font-size','8');
    txt.setAttribute('fill','#556070');
    txt.setAttribute('font-family','Courier New, monospace');
    txt.textContent = c.label;
    connSvg.appendChild(txt);
  });
}

// ── Packet animation ──────────────────────────────────────────
function resizeCanvas() {
  canvas.width  = vizArea.clientWidth;
  canvas.height = vizArea.clientHeight;
}

function spawnPackets(fromId, toId, opts = {}) {
  const color  = opts.color  || '#00ff88';
  const count  = opts.count  || 5;
  const isDdos = opts.ddos   || false;
  const size   = isDdos ? 3 : 4;

  function centre(id) {
    const el  = document.getElementById(id);
    if (!el) return null;
    const box = el.querySelector('.node-box');
    const br  = box.getBoundingClientRect();
    const cr  = canvas.getBoundingClientRect();
    return { x: br.left + br.width/2 - cr.left, y: br.top + br.height/2 - cr.top };
  }

  const realCount = isDdos ? 35 : count;
  for (let i = 0; i < realCount; i++) {
    const delay = isDdos ? i * 70 : i * 160;
    setTimeout(() => {
      const A = centre(fromId);
      const B = centre(toId);
      if (!A || !B) return;
      state.packets.push({
        x: A.x, y: A.y, tx: B.x, ty: B.y,
        progress: 0,
        speed: isDdos ? 0.03 + Math.random()*.04 : 0.014 + Math.random()*.014,
        color, size,
        jx: isDdos ? (Math.random()-.5)*28 : 0,
        jy: isDdos ? (Math.random()-.5)*28 : 0,
        alive: true,
      });
      if (!state.animFrame) animLoop();
    }, delay);
  }
}

function animLoop() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  state.packets = state.packets.filter(p => p.alive);
  state.packets.forEach(p => {
    p.progress += p.speed;
    if (p.progress >= 1) { p.alive = false; return; }
    const t = p.progress;
    const x = p.x + (p.tx + p.jx - p.x) * t;
    const y = p.y + (p.ty + p.jy - p.y) * t;
    ctx.beginPath();
    ctx.arc(x, y, p.size, 0, Math.PI * 2);
    ctx.fillStyle   = p.color;
    ctx.shadowBlur  = 10;
    ctx.shadowColor = p.color;
    ctx.fill();
    ctx.shadowBlur  = 0;
  });
  state.animFrame = state.packets.length > 0 ? requestAnimationFrame(animLoop) : null;
}

// ── Node state helpers ────────────────────────────────────────
function nodeBox(id) { return document.getElementById(id)?.querySelector('.node-box') || null; }
function hlNode(id)   { nodeBox(id)?.classList.add('highlighted'); }
function pwNode(id)   { const b = nodeBox(id); if(b){b.classList.remove('highlighted');b.classList.add('compromised');} }
function atkNode(id)  { const b = nodeBox(id); if(b){b.classList.add('attacking'); setTimeout(()=>b.classList.remove('attacking'),4500);} }
function curNode(id)  {
  document.querySelectorAll('.node-box.current').forEach(b=>b.classList.remove('current'));
  nodeBox(id)?.classList.add('current');
}

// ── Terminal helpers ──────────────────────────────────────────
function printCmd(cmd) {
  const d = document.createElement('div');
  d.className = 'line-cmd';
  d.innerHTML = `<span class="prompt">$&nbsp;</span>${esc(cmd)}`;
  termOutput.appendChild(d);
}
function printLine(txt, cls = 'line-response') {
  if (txt === null) return;
  const d = document.createElement('div');
  d.className = cls;
  d.textContent = txt;
  termOutput.appendChild(d);
}
function printLines(arr) { arr.forEach(([t,c])=> printLine(t,c)); }
function scrollBot() { termOutput.scrollTop = termOutput.scrollHeight; }
function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ── COMMAND TABLE ─────────────────────────────────────────────
// ── Command parsing helpers ─────────────────────────────────────
//    Real argv-style parsing instead of matching the whole line as
//    one exact string: flexible whitespace, flags in any order,
//    and specific usage errors instead of a blind "command not found".
const TARGET_HOST = '10.0.0.5';

function tokenize(raw) {
  return raw.trim().split(/\s+/).filter(Boolean);
}

// Which flags take a following value, per verb — everything else (e.g. nmap's
// -sV, -A, -Pn) is a boolean switch, so it never swallows the host/target
// that comes after it.
const VALUE_FLAGS = {
  ping:     ['c', 'i'],
  nmap:     ['p', 't', 'o'],
  gobuster: ['u', 'w', 'x', 't'],
  hydra:    ['l', 'p'],
  ssh:      ['p'],
};

// '-u http://x -w list.txt -Pn' → { positional:[], flags:{u:'http://x', w:'list.txt', pn:true} }
// Only keys listed in valueFlags consume the next token as their value;
// any other '-flag' is treated as a boolean switch.
function parseArgs(tokens, valueFlags = []) {
  const valueSet = new Set(valueFlags);
  const positional = [];
  const flags = {};
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (/^-{1,2}[A-Za-z]/.test(t)) {
      const key = t.replace(/^-+/, '').toLowerCase();
      const next = tokens[i + 1];
      if (valueSet.has(key) && next !== undefined && !/^-{1,2}[A-Za-z]/.test(next)) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(t);
    }
  }
  return { positional, flags };
}

function stripProtocol(s) { return String(s).replace(/^[a-zA-Z]+:\/\//, ''); }
function normalizeHost(s) { return stripProtocol(s).replace(/\/+$/, '').toLowerCase(); }
function isTarget(s) { return !!s && normalizeHost(s) === TARGET_HOST; }
function usage(line) { return [[`usage: ${line}`, 'line-warn']]; }

// ── VERB TABLE ────────────────────────────────────────────────
//    Each verb owns its own argument validation. A typo in a flag
//    or an extra space no longer looks identical to an unknown
//    command — it gets a specific usage/error message instead.
const VERBS = {

  // ─── Shared ───────────────────────────────────────
  clear: () => { termOutput.innerHTML = ''; return []; },

  whoami: () => [[ state.stage===1 ? 'guest' : 'root', 'line-response' ]],

  ls: () => [[ 'index.html  config.txt  backup.zip  .htpasswd  README.md', 'line-response' ]],

  help: () => {
    if (state.stage === 1) return [
      ['Available commands (Stage 1):', 'line-info'],
      ['  ping <host>                                — check host reachability', 'line-response'],
      ['  nmap [options] <host>                      — scan for open ports', 'line-response'],
      ['  gobuster dir -u <url> [-w wordlist]        — directory brute-force', 'line-response'],
      ['  hydra -l <user> -P <wordlist> ssh://<host> — brute-force SSH', 'line-response'],
      ['  ssh <user>@<host>                          — open shell (requires hydra)', 'line-response'],
      ['  whoami / ls / clear                        — misc utilities', 'line-response'],
      ['  Target: 10.0.0.5 — flags can be in any order, extra spaces are fine.', 'line-response'],
    ];
    return [
      ['Available commands (Stage 2 — AnyTown):', 'line-info'],
      ['  scan internal                                   — enumerate internal hosts', 'line-response'],
      ['  pivot <router|hospital|police|powerplant|dam>   — lateral movement', 'line-response'],
      ['  exploit scada                                   — exploit SCADA control system', 'line-response'],
      ['  ddos powerplant                                 — simulate flood attack', 'line-response'],
      ['  whoami / clear                                  — misc utilities', 'line-response'],
    ];
  },

  // ─── Stage 1 ──────────────────────────────────────
  ping(args) {
    const host = args.positional[0];
    if (!host) return usage('ping <host>');
    if (!isTarget(host)) {
      addAlert(`Ping to unknown host ${host} — no response`, 'warn');
      return [
        [`PING ${host} 56 bytes of data.`, 'line-response'],
        ['Request timeout for icmp_seq 0', 'line-error'],
        ['Request timeout for icmp_seq 1', 'line-error'],
        [`[!] ${host} is unreachable. Confirm the target address and retry.`, 'line-warn'],
      ];
    }
    hlNode('node-webserver');
    spawnPackets('node-attacker','node-webserver',{color:'#38b2ff',count:3});
    completeStep('ping');
    setInsight('ping');
    addAlert('ICMP packets detected from 10.0.0.1 → 10.0.0.5','warn');
    return [
      ['PING 10.0.0.5 56 bytes of data.','line-response'],
      ['64 bytes from 10.0.0.5: icmp_seq=1 ttl=64 time=0.812 ms','line-response'],
      ['64 bytes from 10.0.0.5: icmp_seq=2 ttl=64 time=0.764 ms','line-response'],
      ['64 bytes from 10.0.0.5: icmp_seq=3 ttl=64 time=0.799 ms','line-response'],
      ['','line-response'],
      ['3 packets transmitted, 3 received, 0% packet loss','line-response'],
      ['[+] Host is alive.','line-response'],
    ];
  },

  nmap(args) {
    const host = args.positional[0];
    if (!host) return usage('nmap [options] <host>');
    if (!isTarget(host)) {
      return [[`[!] ${host} appears down or filtered — no route to host.`, 'line-warn']];
    }
    spawnPackets('node-attacker','node-webserver',{color:'#00ff88',count:5});
    completeStep('nmap');
    setInsight('nmap');
    addAlert('Port scan detected on 10.0.0.5 — 22, 80 exposed','warn');
    return [
      ['Starting Nmap 7.94 scan on 10.0.0.5 …','line-response'],
      ['','line-response'],
      ['Host is up (0.0009s latency).','line-response'],
      ['','line-response'],
      ['PORT   STATE  SERVICE  VERSION','line-response'],
      ['22/tcp open   ssh      OpenSSH 8.9p1 (Ubuntu)','line-response'],
      ['80/tcp open   http     Apache httpd 2.4.55','line-response'],
      ['','line-response'],
      ['Nmap done: 1 IP address scanned in 1.34 seconds','line-response'],
    ];
  },

  gobuster(args) {
    const { positional, flags } = args;
    if (positional[0] !== 'dir') return usage('gobuster dir -u <url> [-w wordlist]');
    const url = flags.u;
    if (!url || url === true) return usage('gobuster dir -u <url> [-w wordlist]');
    if (!isTarget(url)) {
      return [[`[!] Could not resolve host in URL: ${url}`, 'line-warn']];
    }
    if (!state.completedKeys.has('nmap')) return [['[!] Scan ports first with nmap.','line-warn']];
    spawnPackets('node-attacker','node-webserver',{color:'#38b2ff',count:6});
    completeStep('gobust');
    setInsight('gobust');
    addAlert('Directory fuzzing on 10.0.0.5 — /admin discovered','warn');
    return [
      ['Gobuster v3.6 — directory brute-force','line-response'],
      ['[+] URL:        http://10.0.0.5','line-response'],
      ['[+] Wordlist:   /usr/share/wordlists/dirb/common.txt','line-response'],
      ['','line-response'],
      ['/index.html           (Status: 200) [Size: 3041]','line-response'],
      ['/images               (Status: 301) [→ /images/]','line-response'],
      ['/admin                (Status: 200) [Size: 1187]  ← FOUND','line-warn'],
      ['/backup               (Status: 403)','line-response'],
      ['','line-response'],
      ['[+] Hidden path /admin discovered. May contain login form.','line-response'],
    ];
  },

  hydra(args) {
    const { positional, flags } = args;
    const login = flags.l;                // -l admin
    const passFile = flags.p;              // -p or -P both collapse to key 'p'
    const target = positional[0];          // ssh://10.0.0.5 (or bare host)
    if (!login || login === true || !passFile || passFile === true || !target) {
      return usage('hydra -l <user> -P <wordlist> ssh://<host>');
    }
    if (!isTarget(target.replace(/^ssh:\/\//, ''))) {
      return [[`[!] Could not connect to ${target} — connection refused.`, 'line-warn']];
    }
    return _hydra();
  },

  ssh(args) {
    const target = args.positional.find(t => t.includes('@')) || args.positional[0];
    if (!target || !target.includes('@')) return usage('ssh <user>@<host>');
    const atIdx = target.indexOf('@');
    const user = target.slice(0, atIdx);
    const host = target.slice(atIdx + 1);
    if (!isTarget(host)) {
      return [[`ssh: connect to host ${host} port 22: No route to host`, 'line-error']];
    }
    if (user.toLowerCase() !== 'admin') {
      addAlert(`Failed SSH attempt as ${user}`, 'warn');
      return [
        [`${user}@${TARGET_HOST}: Permission denied (publickey,password).`, 'line-error'],
        [`[!] Unknown user '${user}'. Target account is admin.`, 'line-warn'],
      ];
    }
    if (!state.completedKeys.has('hydra')) {
      addAlert('Failed SSH attempt from 10.0.0.1 — bad credentials','warn');
      return [
        ['Connecting to admin@10.0.0.5 port 22 …','line-response'],
        ['admin@10.0.0.5: Permission denied (publickey,password).','line-error'],
        ['[!] Access denied. Run hydra first to crack the credentials.','line-warn'],
      ];
    }
    spawnPackets('node-attacker','node-webserver',{color:'#ff4455',count:4});
    setTimeout(()=>{ pwNode('node-webserver'); curNode('node-webserver'); state.currentNode='webserver'; },1000);
    completeStep('ssh');
    setInsight('ssh');
    addAlert('SSH session established — 10.0.0.1 → 10.0.0.5','danger');
    return [
      ['Connecting to admin@10.0.0.5 port 22 …','line-response'],
      ['Warning: Permanently added 10.0.0.5 to known hosts.','line-warn'],
      ['admin@10.0.0.5\'s password: ••••••••','line-response'],
      ['','line-response'],
      ['Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)','line-response'],
      ['','line-response'],
      ['admin@webserver:~$ ','line-response'],
      ['[+] Shell obtained on 10.0.0.5','line-response'],
      ['[+] Deploying persistence backdoor …','line-warn'],
      ['[+] Backdoor installed. Pivoting to internal network.','line-response'],
    ];
  },

  // ─── Stage 2 ──────────────────────────────────────
  scan(args) {
    if (state.stage !== 2) return [['[!] Command not available in Stage 1.','line-warn']];
    if (args.positional[0] !== 'internal') return usage('scan internal');
    hlNode('node-router');
    ['node-hospital','node-police','node-powerplant'].forEach((n,i)=>{
      setTimeout(()=> spawnPackets('node-router',n,{color:'#38b2ff',count:3}), i*250);
    });
    completeStep('scan');
    setInsight('scan');
    addAlert('ARP sweep detected on 192.168.0.0/16','warn');
    return [
      ['Running internal sweep (192.168.0.0/16) …','line-response'],
      ['','line-response'],
      ['HOST             OPEN PORTS              NOTES','line-response'],
      ['192.168.1.1    — [gateway]               Municipal Router','line-response'],
      ['192.168.10.5   — 80,445,3389,3306        AnyTown General Hospital','line-response'],
      ['192.168.10.8   — 23,22,80                Police Comms Server','line-response'],
      ['192.168.20.2   — 502,80,161              Power Plant (Modbus)','line-response'],
      ['192.168.20.10  — 4840,5900               SCADA OPC-UA Controller','line-response'],
      ['192.168.30.4   — 21,80  [via 20.2 only]  Water Dam — restricted path','line-response'],
      ['','line-response'],
      ['[+] 5 hosts found. Poor network segmentation detected.','line-response'],
      ['[!] Note: 192.168.30.4 (Dam) only routable through Power Plant.','line-warn'],
    ];
  },

  pivot(args) {
    if (state.stage !== 2) return [['[!] Stage 2 only.','line-warn']];
    const handlers = {
      router: _pivotRouter,
      hospital: _pivotHospital,
      police: _pivotPolice,
      powerplant: _pivotPowerplant,
      dam: _pivotDam,
    };
    const fn = handlers[args.positional[0]];
    if (!fn) return usage('pivot <router|hospital|police|powerplant|dam>');
    return fn();
  },

  exploit(args) {
    if (state.stage !== 2) return [['[!] Stage 2 only.','line-warn']];
    if (args.positional[0] !== 'scada') return usage('exploit scada');
    if (!canReach('node-scada')) return _accessDenied('node-scada');
    if (!state.completedKeys.has('power')) return [['[!] Pivot to Power Plant first.','line-warn']];
    spawnPackets('node-powerplant','node-scada',{color:'#ff4455',count:6});
    setTimeout(()=>{ pwNode('node-scada'); }, 1800);
    setPowerOffline(true);
    completeStep('scada');
    setInsight('pivot');
    addAlert('OPC-UA write to SCADA EmergencyShutdown node','danger');
    return [
      ['Connecting to 192.168.20.10 via OPC-UA (port 4840) …','line-response'],
      ['OPC-UA server: no authentication required.','line-warn'],
      ['Enumerating node IDs …','line-response'],
      ['','line-response'],
      ['  ns=2;i=1001  TurbineSpeed        [READ/WRITE]','line-response'],
      ['  ns=2;i=1002  CoolantPressure     [READ/WRITE]','line-response'],
      ['  ns=2;i=1003  EmergencyShutdown   [READ/WRITE]  ← CRITICAL','line-warn'],
      ['','line-response'],
      ['Writing TRUE to EmergencyShutdown …','line-warn'],
      ['[+] Command accepted. Shutdown sequence initiated.','line-response'],
      ['','line-response'],
      ['[!] REAL-WORLD IMPACT: Unplanned SCADA shutdown can cause','line-warn'],
      ['[!] turbine damage, cascading grid failures, and outages.','line-warn'],
    ];
  },

  ddos(args) {
    if (state.stage !== 2) return [['[!] Stage 2 only.','line-warn']];
    if (args.positional[0] !== 'powerplant') return usage('ddos powerplant');
    atkNode('node-powerplant');
    setPowerOffline(true);
    const sources = ['node-hospital','node-police','node-router','node-webserver'];
    sources.forEach((s,i)=> setTimeout(()=> spawnPackets(s,'node-powerplant',{color:'#ffb830',count:9,ddos:true}), i*180));
    completeStep('ddos');
    setInsight('ddos');
    addAlert('DDoS flood on 192.168.20.2 — 50k req/s sustained','danger');
    return [
      ['Launching DDoS on 192.168.20.2 (Power Plant HTTP mgmt) …','line-response'],
      ['','line-response'],
      ['Sources: hospital-dc, police-comms, dam-ctrl, router','line-warn'],
      ['Sending SYN flood + HTTP GET flood simultaneously …','line-warn'],
      ['','line-response'],
      ['Target CPU:     ████████████████ 99%','line-response'],
      ['Target MEM:     ████████████████ 98%','line-response'],
      ['Open connections: 65535 / 65535 (maxed)','line-response'],
      ['','line-response'],
      ['[+] Power Plant HTTP console: UNREACHABLE','line-response'],
      ['[+] Operator workstations:    TIMED OUT','line-response'],
      ['[+] SCADA HMI panels:         CONNECTION LOST','line-response'],
      ['','line-response'],
      ['[!] REAL-WORLD IMPACT: Operators lose visibility into plant.','line-warn'],
      ['[!] Emergency manual shutdown requires on-site personnel.','line-warn'],
      ['[!] Thousands of residents may lose power for hours.','line-warn'],
      ['','line-response'],
      ['[SYSTEM] All Stage 2 objectives complete. Simulation ended.','line-system'],
    ];
  },
};

// ── Helpers ───────────────────────────────────────────────────
function _hydra() {
  if (!state.completedKeys.has('gobust')) return [['[!] Discover attack surface first: gobuster dir …','line-warn']];
  spawnPackets('node-attacker','node-webserver',{color:'#ffb830',count:8});
  state.hydraSuccess = true;
  completeStep('hydra');
  setInsight('hydra');
  addAlert('SSH brute-force from 10.0.0.1 — 4823 attempts','danger');
  return [
    ['Hydra v9.5 — SSH brute-force on admin@10.0.0.5 …','line-response'],
    ['[DATA] 16 tasks, 1 server, 14344399 login tries','line-response'],
    ['','line-response'],
    ['[ATTEMPT] target 10.0.0.5 – login "admin" – pass "password"  → FAIL','line-response'],
    ['[ATTEMPT] target 10.0.0.5 – login "admin" – pass "admin123"  → FAIL','line-response'],
    ['[ATTEMPT] target 10.0.0.5 – login "admin" – pass "letmein"   → FAIL','line-response'],
    ['[ATTEMPT] target 10.0.0.5 – login "admin" – pass "sunshine1" → FAIL','line-response'],
    ['… (4819 more attempts) …','line-response'],
    ['','line-response'],
    ['[22][ssh] host: 10.0.0.5   login: admin   password: sunshine1','line-warn'],
    ['[+] VALID CREDENTIALS FOUND: admin / sunshine1','line-response'],
    ['[+] SSH access now available. Run: ssh admin@10.0.0.5','line-response'],
  ];
}

function _accessDenied(targetNode) {
  const required = ACCESS_RULES[targetNode];
  const nodeNames = { router:'router', hospital:'router', police:'router', powerplant:'router', dam:'power plant', scada:'power plant' };
  const need = required?.map(r => nodeNames[r] || r).join(' or ') || 'previous node';
  addAlert(`Access denied — must be at ${need} to reach ${targetNode.replace('node-','')}`, 'danger');
  return [
    [`[!] Access denied: ${targetNode.replace('node-','')} is not reachable from your current position.`, 'line-error'],
    [`[!] You must pivot to: ${need} first.`, 'line-warn'],
  ];
}

function _pivotRouter() {
  if (!state.completedKeys.has('scan')) return [['[!] Enumerate the network first: scan internal','line-warn']];
  if (!canReach('node-router')) return _accessDenied('node-router');
  spawnPackets('node-webserver','node-router',{color:'#ff4455',count:5});
  setTimeout(()=>{ curNode('node-router'); state.currentNode='router'; }, 1400);
  completeStep('router');
  setInsight('pivot');
  addAlert('Pivot to municipal router — internal gateway access acquired','danger');
  return [
    ['Pivoting to 192.168.1.1 (Municipal Router) via tunnel …','line-response'],
    ['Establishing route to internal LAN segments …','line-warn'],
    ['','line-response'],
    ['[+] Gateway access confirmed. Current node updated → router','line-response'],
    ['[+] Lateral movement commands unlocked: hospital, police, powerplant','line-response'],
  ];
}

function _pivotHospital() {
  if (!canReach('node-hospital')) return _accessDenied('node-hospital');
  if (!state.completedKeys.has('scan')) return [['[!] Enumerate the network first: scan internal','line-warn']];
  spawnPackets('node-router','node-hospital',{color:'#ff4455',count:6});
  setTimeout(()=>{ pwNode('node-hospital'); }, 1800);
  completeStep('hospital');
  setInsight('pivot');
  addAlert('EternalBlue exploit on 192.168.10.5 — SMB pwned','danger');
  return [
    ['Pivoting to 192.168.10.5 (Hospital) via SMB (port 445) …','line-response'],
    ['Sending MS17-010 (EternalBlue) payload …','line-warn'],
    ['','line-response'],
    ['[+] Buffer overflow triggered — shellcode executed','line-response'],
    ['[+] SYSTEM shell on ANYTOWNHOSPITAL-DC','line-response'],
    ['[+] Domain: ANYTOWN.LOCAL — Domain Admin hash extracted','line-response'],
    ['','line-response'],
    ['[!] REAL-WORLD IMPACT: Patient records exposed; electronic','line-warn'],
    ['[!] medical records offline; life-support scheduling at risk.','line-warn'],
  ];
}

function _pivotPolice() {
  if (!canReach('node-police'))  return _accessDenied('node-police');
  if (!state.completedKeys.has('scan')) return [['[!] Run scan internal first.','line-warn']];
  spawnPackets('node-router','node-police',{color:'#ff4455',count:5});
  setTimeout(()=>{ pwNode('node-police'); }, 1800);
  completeStep('police');
  setInsight('pivot');
  addAlert('Telnet login to Police Comms — default creds used','danger');
  return [
    ['Connecting to 192.168.10.8 (Police) via Telnet (port 23) …','line-response'],
    ['Username: admin   Password: admin  ← default credentials','line-warn'],
    ['','line-response'],
    ['[+] Login successful on ANYTOWNPD-DISPATCH','line-response'],
    ['[+] Access to radio dispatch scheduling confirmed','line-response'],
    ['','line-response'],
    ['[!] REAL-WORLD IMPACT: Emergency dispatch comms disrupted;','line-warn'],
    ['[!] 911 routing could be rerouted or silenced.','line-warn'],
  ];
}

function _pivotPowerplant() {
  if (!canReach('node-powerplant'))  return _accessDenied('node-powerplant');
  if (!state.completedKeys.has('scan')) return [['[!] Run scan internal first.','line-warn']];
  spawnPackets('node-router','node-powerplant',{color:'#ff4455',count:6});
  setTimeout(()=>{ pwNode('node-powerplant'); curNode('node-powerplant'); state.currentNode='powerplant'; }, 1800);
  completeStep('power');
  setInsight('pivot');
  addAlert('Modbus write access to Power Plant — unauthenticated','danger');
  return [
    ['Connecting to 192.168.20.2 (Power Plant) via Modbus TCP (port 502) …','line-response'],
    ['Modbus has no authentication layer.','line-warn'],
    ['Sending READ HOLDING REGISTERS request …','line-response'],
    ['','line-response'],
    ['[+] Register map obtained.','line-response'],
    ['[+] Write access confirmed to relay controllers.','line-response'],
    ['[+] Current node updated → power plant','line-response'],
    ['','line-response'],
    ['[!] REAL-WORLD IMPACT: Relay controller writes could trigger','line-warn'],
    ['[!] grid faults, equipment damage, or regional blackouts.','line-warn'],
  ];
}

function _pivotDam() {
  if (!canReach('node-dam'))   return _accessDenied('node-dam');
  spawnPackets('node-powerplant','node-dam',{color:'#ff4455',count:5});
  setTimeout(()=>{ pwNode('node-dam'); }, 1800);
  completeStep('dam');
  setInsight('pivot');
  addAlert('Unauthorised FTP access to Water Dam — via Power Plant','danger');
  return [
    ['Routing through Power Plant (192.168.20.2) → Dam (192.168.30.4) …','line-response'],
    ['FTP connection on port 21 — anonymous login accepted','line-warn'],
    ['','line-response'],
    ['[+] Shell on DAM-SCADA-CTRL','line-response'],
    ['[+] Water level sensors and sluice gate controls readable','line-response'],
    ['','line-response'],
    ['[!] REAL-WORLD IMPACT: Unauthorised gate commands could cause','line-warn'],
    ['[!] flooding or water supply contamination downstream.','line-warn'],
  ];
}

// ── Command dispatcher ────────────────────────────────────────
function handleCommand(raw) {
  const cmd = raw.trim();
  if (!cmd) return;

  state.history.unshift(cmd);
  if (state.history.length > 60) state.history.pop();
  state.histIdx = -1;

  printCmd(cmd);

  const tokens = tokenize(cmd);
  const verb = tokens[0]?.toLowerCase();
  const handler = VERBS[verb];

  if (handler) {
    const { positional, flags } = parseArgs(tokens.slice(1), VALUE_FLAGS[verb] || []);
    const lines = handler({ positional, flags, raw: cmd });
    if (Array.isArray(lines)) printLines(lines);
  } else {
    printLine(`bash: ${verb || cmd}: command not found`, 'line-error');
  }
  scrollBot();
}

// ── Key events ────────────────────────────────────────────────
termInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    const v = termInput.value; termInput.value = ''; handleCommand(v);
  } else if (e.key === 'ArrowUp') {
    if (state.histIdx < state.history.length-1) { state.histIdx++; termInput.value = state.history[state.histIdx]; }
    e.preventDefault();
  } else if (e.key === 'ArrowDown') {
    if (state.histIdx > 0) { state.histIdx--; termInput.value = state.history[state.histIdx]; }
    else { state.histIdx = -1; termInput.value = ''; }
    e.preventDefault();
  }
});
document.querySelector('.terminal-wrap')?.addEventListener('click', () => termInput.focus());

// ── Resize handler ────────────────────────────────────────────
function onResize() {
  resizeCanvas();
  placeNodes();
  // Small delay to let DOM settle before reading positions
  setTimeout(drawConnections, 50);
}
window.addEventListener('resize', onResize);

// ── Init ──────────────────────────────────────────────────────
resizeCanvas();
renderPanel();

// End popup close handlers
document.getElementById('end-popup-close')?.addEventListener('click', hideEndPopup);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') hideEndPopup();
});

// Wait one frame for DOM layout, then position nodes and draw connections
requestAnimationFrame(() => {
  placeNodes();
  setTimeout(drawConnections, 80);
});