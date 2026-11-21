/* 임시 대시보드. 백엔드와 주고받는 일은 전부 wifiguard-client.js 가 하고, 여기서는 그리기만 한다.
 * 서버 문자열(SSID 등)은 주변 AP가 정할 수 있으므로 innerHTML 을 쓰지 않고 textContent 로만 넣는다. */
"use strict";
const KO = WifiGuard.LEVEL_KO;
const MOD = { arp: "ARP 스푸핑", ap: "가짜 AP", dns: "DNS 응답 이상", system: "시스템" };
const MSG = {
  normal: "지금까지 이상한 점이 보이지 않습니다.",
  unknown: "일부 모듈이 동작하지 않아 안전하다고 단정할 수 없습니다.",
  caution: "의심스러운 신호가 있습니다. 중요한 로그인·결제는 미뤄 두세요.",
  warning: "공격으로 보이는 신호가 있습니다. 아래 권장 대응을 확인하세요.",
};
const FIELD = {
  target_mac: "의심 MAC", suspect: "공격자 추정", score: "점수", claimed_ips: "주장한 IP", real_macs: "원래 MAC",
  frames: "프레임 범위", ssid: "SSID", bssid: "BSSID", auth: "보안", signal: "신호(%)", qname: "질의 도메인",
  client: "질의한 기기", server: "응답한 서버", answers: "응답 주소", rules: "해당 규칙", module: "모듈",
};

const $ = (id) => document.getElementById(id);
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
const badge = (lv) => el("span", KO[lv] || lv, "badge " + lv);
const hhmmss = (ts) => (ts || "").slice(11, 19);

let events = [];          // 최신순
let filter = "all";
let selected = null;
let lastStatus = null;
let trustedKey = null;

// ---------- 상태 ----------
function renderStatus(s) {
  lastStatus = s;
  $("hero").dataset.level = s.overall;
  $("overall").textContent = s.overall_ko;
  $("overallMsg").textContent = MSG[s.overall];
  // 지금 유효한 경보: 근거가 계속 보이는 동안 유지, 10분 동안 새 근거가 없으면 서버가 뺀다
  $("active").replaceChildren(...(s.active || []).map((a) => {
    const li = el("li");
    li.append(badge(a.level), el("span", a.title), el("span", "마지막 근거 " + hhmmss(a.last_seen), "sub"));
    li.style.cursor = "pointer";
    li.onclick = () => { const ev = events.find((e) => e.id === a.event_id); if (ev) select(ev); };
    return li;
  }));
  $("btnAck").hidden = !(s.active && s.active.length);
  if (s.trusted_ssids && s.trusted_ssids.join("|") !== trustedKey) {
    trustedKey = s.trusted_ssids.join("|");
    loadTrust();
  }

  const sc = s.score;
  const ring = $("ring");
  ring.style.setProperty("--p", sc.score);
  ring.style.setProperty("--c", sc.score >= 80 ? "var(--normal)" : sc.score >= 50 ? "var(--caution)" : "var(--warning)");
  $("score").textContent = sc.score;
  $("grade").textContent = sc.grade;
  $("scoreWhy").replaceChildren(...sc.reasons.map((r) => el("li", r)));

  const c = s.connection;
  $("ssid").textContent = c ? c.ssid : "연결 정보 없음";
  $("auth").textContent = c ? c.auth || "?" : "–";
  $("bssid").textContent = c ? c.bssid || "?" : "–";
  $("gw").textContent = s.gateway ? `${s.gateway.ip || "?"} · ${s.gateway.mac || "MAC 모름"}` : "–";
  renderModules();
}

function renderModules() {
  if (!lastStatus) return;
  const box = $("modules");
  box.replaceChildren();
  for (const name of ["arp", "ap", "dns"]) {
    const m = lastStatus.modules[name];
    if (!m) continue;
    // 모듈 카드의 색은 '모듈이 동작하는지' + '그 모듈의 지금 유효한 경보'를 함께 보여 준다
    const last = events.find((e) => e.module === name);
    const act = (lastStatus.active || []).find((a) => a.module === name);     // 서버가 높은 단계부터 준다
    const lv = act && WifiGuard.RANK[act.level] > WifiGuard.RANK[m.level] ? act.level : m.level;
    const card = el("div", null, "mod");
    card.dataset.level = lv;
    const head = el("div", null, "mod-head");
    head.append(el("span", MOD[name], "mod-name"), badge(lv));
    card.append(head, el("div", m.detail, "mod-detail"));
    if (last) {
      const l = el("div", null, "mod-last");
      l.append(el("span", hhmmss(last.timestamp) + " ", "sub"), el("span", last.title));
      l.style.cursor = "pointer";
      l.onclick = () => select(last);
      card.append(l);
    }
    box.append(card);
  }
}

// ---------- 기록 ----------
function visible(e) {
  if (filter === "all") return true;
  if (filter in KO) return e.level === filter;
  return e.module === filter;
}

function row(e, isNew) {
  const li = el("li", null, isNew ? "new" : "");
  li.dataset.id = e.id;
  if (selected && selected.id === e.id) li.classList.add("sel");
  const mid = el("div");
  mid.append(el("div", MOD[e.module] || e.module, "t-mod"), el("div", e.title, "t-title"), el("div", e.reason, "t-reason"));
  li.append(el("div", hhmmss(e.timestamp), "t-time"), mid, badge(e.level));
  li.onclick = () => select(e);
  return li;
}

function renderLog() {
  const list = events.filter(visible);
  $("timeline").replaceChildren(...list.map((e) => row(e, false)));
  $("empty").hidden = list.length > 0;
}

function addEvent(e) {
  events.unshift(e);
  if (events.length > 500) events.length = 500;
  if (visible(e)) {
    $("timeline").prepend(row(e, true));
    $("empty").hidden = true;
  }
  renderModules();
  if (e.level === "warning" || e.level === "caution") toast(`${KO[e.level]} · ${e.title}`, e.level);
}

// ---------- 상세 ----------
function fmt(v) {
  if (Array.isArray(v)) return v.length ? v.join(", ") : "–";
  if (v && typeof v === "object") return Object.entries(v).map(([k, x]) => `${k} → ${x}`).join(", ");
  return v == null || v === "" ? "–" : String(v);
}

function select(e) {
  selected = e;
  document.querySelectorAll(".timeline li").forEach((li) => li.classList.toggle("sel", li.dataset.id == e.id));
  const d = $("detail");
  d.replaceChildren();
  const top = el("div");
  top.append(badge(e.level), el("span", "  " + (MOD[e.module] || e.module) + " · " + e.timestamp.replace("T", " ").slice(0, 19), "sub"));
  d.append(top, el("h3", e.title), el("p", e.reason, "reason"));

  const keys = Object.keys(e.evidence || {});
  if (keys.length) {
    d.append(el("h4", "판단 근거"));
    const t = el("table", null, "ev-table");
    for (const k of keys) {
      const tr = el("tr");
      tr.append(el("th", FIELD[k] || k), el("td", fmt(e.evidence[k])));
      t.append(tr);
    }
    d.append(t);
  }

  d.append(el("h4", "권장 대응"));
  if (e.advice && e.advice.length) {
    const ul = el("ul", null, "advice");
    for (const a of e.advice) {
      const li = el("li");
      const copy = el("button", "복사");
      copy.type = "button";
      copy.onclick = async () => {
        try { await navigator.clipboard.writeText(a); copy.textContent = "복사됨"; }
        catch { copy.textContent = "복사 실패"; }
      };
      li.append(el("code", a), copy);
      ul.append(li);
    }
    d.append(ul, el("p", "프로그램은 명령을 실행하지 않습니다. 내용을 확인하고 필요할 때 직접 실행하세요. "
      + "정적 ARP 등록은 관리자 권한이 필요하고, 공유기 MAC은 미리 저장한 기준값일 때만 고정하세요.", "note"));
  } else {
    d.append(el("p", e.level === "warning" ? "따로 제시된 명령이 없습니다." : "아직 조치할 단계는 아닙니다. 계속 지켜봅니다.", "note"));
  }
}

// ---------- 환경 점검 · 기준값 ----------
async function loadDiag() {
  const box = $("diag");
  box.replaceChildren(el("li", "점검 중…", "sub"));
  try {
    const d = await guard.diagnostics();
    box.replaceChildren(...Object.values(d).map((c) => {
      const li = el("li");
      const [txt, cls] = c.ok === true ? ["✓", "ok"] : c.ok === false ? ["!", "bad"] : ["–", "na"];
      li.append(el("span", txt, "mark " + cls), el("b", c.label), el("span", c.detail));
      return li;
    }));
  } catch (e) { box.replaceChildren(el("li", "점검 실패: " + e.message, "sub")); }
}

async function loadTrust() {
  const box = $("trust");
  try {
    const list = await guard.trust();
    if (!list.length) { box.replaceChildren(el("li", "저장한 기준값이 없습니다.", "empty-row")); return; }
    box.replaceChildren(...list.map((t) => {
      const li = el("li");
      const info = el("div");
      info.append(el("b", t.ssid),
        el("div", `BSSID ${t.bssids.join(", ") || "–"} · 공유기 ${t.gateway_ip || "?"} ${t.gateway_mac || "MAC 없음"}`, "sub mono"));
      const del = el("button", "지우기", "small");
      del.type = "button";
      del.onclick = () => busy(del, async () => {
        if (!confirm(`'${t.ssid}' 기준값을 지울까요?`)) return;
        const r = await guard.forget(t.ssid);
        toast(r.ok ? `기준값 삭제: ${t.ssid}` : r.reason, r.ok ? "" : "warning");
        loadTrust();
      });
      li.append(info, del);
      return li;
    }));
  } catch (e) { box.replaceChildren(el("li", "불러오기 실패: " + e.message, "empty-row")); }
}

// ---------- 알림 ----------
let toastTimer;
function toast(text, level) {
  const t = $("toast");
  t.textContent = text;
  t.className = "toast show " + (level || "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = "toast"), 3500);
}

// ---------- 연결 ----------
const LINK = { socket: "실시간 연결됨", polling: "3초마다 새로 읽는 중", offline: "백엔드 연결 끊김" };
const guard = WifiGuard.connect({
  onStatus: renderStatus,
  onEvents: (list) => { events = list; renderLog(); renderModules(); if (list[0]) select(list[0]); },
  onEvent: addEvent,
  onLink: (s) => { $("link").textContent = LINK[s]; $("link").className = "pill " + s; },
});
guard.meta().then((m) => { $("btnDemo").hidden = !m.demo; }).catch(() => {});

$("chips").onclick = (ev) => {
  const b = ev.target.closest("button");
  if (!b) return;
  filter = b.dataset.f;
  document.querySelectorAll("#chips button").forEach((x) => x.classList.toggle("on", x === b));
  renderLog();
};

async function busy(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { toast("실패: " + e.message, "warning"); } finally { btn.disabled = false; }
}
$("btnScan").onclick = () => busy($("btnScan"), async () => {
  const r = await guard.scan();
  toast(r.alerts ? `가짜 AP 의심 ${r.alerts}개` : "주변 AP 스캔 완료 — 새 의심 없음");
});
$("btnLearn").onclick = () => busy($("btnLearn"), async () => {
  if (!confirm("지금 연결된 와이파이가 안전하다고 확신할 때만 저장하세요.\n(처음 본 값이 진짜라는 보장은 없습니다) 저장할까요?")) return;
  const r = await guard.learn();
  toast(r.ok ? `기준값 저장: ${r.ssid}` : r.reason, r.ok ? "" : "warning");
});
$("btnAck").onclick = () => busy($("btnAck"), async () => {
  const r = await guard.ack();
  toast(`경보 ${r.cleared}개를 확인 처리했습니다. 근거가 계속 보이면 다시 알립니다.`);
});
$("btnDiag").onclick = () => busy($("btnDiag"), loadDiag);
loadDiag();
loadTrust();

$("btnDemo").onclick = () => busy($("btnDemo"), async () => {
  const r = await guard.demo();
  toast(r.ok ? `데모 재생 시작: ${r.files.join(", ")}` : r.reason);
});
