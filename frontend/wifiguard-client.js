/* 와이파이 지킴이 백엔드 클라이언트 — 프론트엔드는 이 파일 하나만 가져다 쓰면 된다.
 *
 *   <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>  (없어도 됨)
 *   <script src="wifiguard-client.js"></script>
 *   const guard = WifiGuard.connect({
 *     base: "",                         // 같은 서버에서 열면 "". Vite 등 다른 포트면 "http://127.0.0.1:5000"
 *     onStatus(status) {},              // 전체 상태가 바뀔 때마다 (형식: docs/API.md)
 *     onEvent(event) {},                // 새 탐지 이벤트 하나
 *     onEvents(list) {},                // 처음 접속할 때 최근 이벤트 목록 (최신순)
 *     onLink(state) {},                 // "socket" | "polling" | "offline"
 *   });
 *   guard.scan(); guard.learn(); guard.ack(); guard.demo(); guard.close();
 *   guard.events({module:"arp"}); guard.trust(); guard.forget("Cafe"); guard.diagnostics();
 *
 * POST에는 X-WifiGuard: 1 헤더가 꼭 붙어야 한다 (다른 사이트가 몰래 부르는 것을 막는 장치). 이 파일이 붙여 준다.
 *
 * Socket.IO 스크립트를 못 불러오면(인터넷 없는 실험망) 3초마다 since=마지막 id 로 새 이벤트만 읽는다.
 * 서버가 보내는 문자열(SSID 등)은 주변 AP가 마음대로 정할 수 있다. 화면에 넣을 때는 textContent 를 쓴다.
 */
(function (global) {
  "use strict";

  function connect(opts) {
    opts = opts || {};
    const base = (opts.base || "").replace(/\/$/, "");
    const noop = function () {};
    const on = {
      status: opts.onStatus || noop, event: opts.onEvent || noop,
      events: opts.onEvents || noop, link: opts.onLink || noop,
    };
    const pollMs = opts.pollMs || 3000;
    let lastId = 0, socket = null, timer = null, closed = false;

    async function api(path, method, body) {
      const init = { method: method || "GET", headers: {} };
      if (init.method !== "GET") init.headers["X-WifiGuard"] = "1";
      if (body !== undefined) {
        init.headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
      }
      const r = await fetch(base + path, init);
      const data = await r.json().catch(function () { return {}; });
      if (!r.ok && r.status !== 409 && r.status !== 404) throw Object.assign(new Error(data.reason || r.statusText), { body: data });
      return data;
    }
    function seen(ev) { if (ev.id > lastId) lastId = ev.id; }

    async function poll() {
      try {
        on.status(await api("/api/status"));
        const fresh = await api("/api/events?limit=200&since=" + lastId);
        fresh.reverse().forEach(function (ev) { seen(ev); on.event(ev); });   // 오래된 것부터 전달
        on.link("polling");
      } catch (e) { on.link("offline"); }
    }

    async function start() {
      try {
        on.status(await api("/api/status"));
        const list = await api("/api/events?limit=100");
        list.forEach(seen);
        on.events(list);
      } catch (e) { on.link("offline"); }
      if (closed) return;
      if (global.io) {
        socket = global.io(base || undefined, { transports: ["websocket", "polling"] });
        socket.on("connect", function () {
          on.link("socket");
          // 끊겼다 다시 붙으면 그 사이 놓친 이벤트를 since 로 채운다
          api("/api/events?limit=200&since=" + lastId).then(function (fresh) {
            fresh.reverse().forEach(function (ev) { if (ev.id > lastId) { seen(ev); on.event(ev); } });
          }).catch(function () {});
        });
        socket.on("disconnect", function () { on.link("offline"); });
        socket.on("status", function (s) { on.status(s); });
        socket.on("event", function (ev) { if (ev.id > lastId) { seen(ev); on.event(ev); } });
      } else {
        on.link("polling");
        timer = setInterval(poll, pollMs);
      }
    }
    start();

    return {
      meta: function () { return api("/api/meta"); },
      status: function () { return api("/api/status"); },
      events: function (q) {
        const qs = new URLSearchParams(q || {}).toString();
        return api("/api/events" + (qs ? "?" + qs : ""));
      },
      scan: function () { return api("/api/scan", "POST"); },
      learn: function () { return api("/api/learn", "POST"); },     // 409면 {ok:false, reason}
      ack: function () { return api("/api/ack", "POST"); },
      trust: function () { return api("/api/trust"); },
      forget: function (ssid) { return api("/api/trust/forget", "POST", { ssid: ssid }); },
      diagnostics: function () { return api("/api/diagnostics"); },
      demo: function () { return api("/api/demo", "POST"); },
      close: function () { closed = true; if (socket) socket.close(); if (timer) clearInterval(timer); },
    };
  }

  const LEVEL_KO = { normal: "정상", unknown: "확인 불가", caution: "주의", warning: "경고" };
  const RANK = { normal: 0, unknown: 1, caution: 2, warning: 3 };
  global.WifiGuard = { connect: connect, LEVEL_KO: LEVEL_KO, RANK: RANK };
})(window);
