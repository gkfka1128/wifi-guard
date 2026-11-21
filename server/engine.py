"""탐지 엔진 — 수집(패킷·AP 목록) → 모듈별 판단 → 공통 이벤트 → 기록·실시간 전달.

스레드 두 개가 돈다.
  capture  Scapy로 ARP·DNS 패킷을 받아 ArpDetector·DnsDetector에 넣는다
  ap       ap_interval초마다 netsh로 주변 AP를 읽어 가짜 AP를 판단하고, 접속한 공유기 MAC을 확인한다
수집이 실패하면 그 모듈은 '정상'이 아니라 '확인 불가'가 된다.

'지금 유효한 경보'(active)
  같은 대상(ARP는 의심 MAC, AP는 SSID+BSSID, DNS는 도메인+기기)의 경보는 하나로 묶는다.
  근거가 계속 보이면 유지되고, ACTIVE_WINDOW초 동안 새 근거가 없으면 빠진다.
  사용자가 '확인함'(ack)을 누르면 모두 비운다. 공격이 계속되면 다음 근거가 보일 때 다시 경보가 뜬다.
  전체 단계(overall)는 active 중 가장 높은 단계다. active는 DB에서 복원되므로 서버를 다시 켜도 유지된다.
"""
import json
import threading
import time
from pathlib import Path

from guard import ap_watch, arp_watch, capture, events
from guard.dns_watch import DnsDetector
from guard.score import safety_score

AP_CAUTION_AT = 30      # 가짜 AP 점수 30 이상 '주의', 50 이상 '경고' (ap_watch.ALERT_AT)
AP_WARNING_AT = ap_watch.ALERT_AT
RANK = {"normal": 0, "unknown": 1, "caution": 2, "warning": 3}
ACTIVE_WINDOW = 600     # 이 시간(초) 동안 새 근거가 없으면 경보가 '지금 유효'에서 빠진다
DNS_SILENCE = 120       # 실시간 수집 중 UDP 53 DNS가 이만큼 안 보이면 DoH 사용을 의심
CAPTURE_HINT = "Npcap 설치, 관리자 권한, 인터페이스 이름(--iface)을 확인하세요"
DOH_HINT = ("UDP 53 DNS가 {s}초째 보이지 않음 — 브라우저나 Windows의 보안 DNS(DoH)를 쓰면 DNS 모듈은 "
            "질문을 볼 수 없음. 실험할 때는 보안 DNS를 끄세요")


def key_for(ev):
    """같은 대상의 경보를 묶는 열쇠."""
    e = ev.get("evidence") or {}
    if ev["module"] == "arp" and e.get("target_mac"):
        return ("arp", e["target_mac"])
    if ev["module"] == "ap" and e.get("bssid"):
        return ("ap", e.get("ssid"), e["bssid"])
    if ev["module"] == "dns" and e.get("qname"):
        return ("dns", e["qname"], e.get("client"))
    return ("event", ev.get("id"))


class Engine:
    def __init__(self, store, trust_path="trust.json", iface=None, gateway=None, ap_interval=30,
                 scanner=ap_watch.scan_text, connection=ap_watch.current_connection,
                 gateway_probe=ap_watch.current_gateway, dns_reference=None, keep_days=30, clock=time.time):
        self.store = store
        self.clock = clock
        self.publish = lambda kind, data: None      # app.py가 SocketIO 전달 함수로 바꾼다
        self.trust_path = Path(trust_path)
        self.trust = self._load_trust()
        self.iface = iface
        self.ap_interval = ap_interval
        self.scanner, self.connection, self.gateway_probe = scanner, connection, gateway_probe
        self.dns_reference = dns_reference
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.modules = {m: {"level": "unknown", "detail": "시작 전"} for m in ("arp", "dns", "ap")}
        self.conn = None
        self.gateway = {"ip": gateway, "mac": None} if gateway else None
        self.arp = arp_watch.ArpDetector(gateway_ip=gateway, trusted=self.trust.get("arp"))
        self.dns = DnsDetector(reference=dns_reference)
        self.ap_alerts = []         # 마지막 스캔의 가짜 AP 의심 목록
        self.live = False           # 실시간 수집 중인가 (DoH 판단용)
        self.dns_last = None        # 마지막으로 DNS 패킷을 본 실제 시각
        self.bad_packets = 0        # 처리하다 오류가 난 패킷 수
        self._doh_logged = False    # DoH 안내는 기록에 한 번만 남긴다 (조용한 망에서 반복 방지)
        self.pruned = store.prune(keep_days) if keep_days else 0
        self.ack_id = store.get("ack_id", 0)
        self.active = {}            # key_for(ev) -> {level, module, title, event_id, seen}
        for ev in store.alerts_after(self.ack_id, self.clock() - ACTIVE_WINDOW):
            self._activate(ev, ev["received_at"])

    # ---------- 시작 / 종료 ----------
    def start(self, live_capture=True):
        if not self.gateway:
            self._refresh_gateway()
        if live_capture:
            threading.Thread(target=self._capture_loop, name="capture", daemon=True).start()
        threading.Thread(target=self._ap_loop, name="ap", daemon=True).start()

    def stop(self):
        self.stop_event.set()

    def _capture_loop(self):
        where = self.iface or "기본 인터페이스"
        self.live, self.dns_last = True, self.clock()
        self.set_module("arp", "normal", f"패킷 수집 중 ({where})")
        self.set_module("dns", "normal", f"패킷 수집 중 ({where}, UDP 53)")
        try:
            capture.sniff_live(self.iface, self.on_item, self.stop_event, on_error=self._packet_error)
        except Exception as e:     # noqa: BLE001 — 어떤 실패든 '확인 불가'로 알리는 것이 목적
            self.live = False
            for m in ("arp", "dns"):
                self.set_module(m, "unknown", f"패킷 수집 불가: {type(e).__name__}: {e} — {CAPTURE_HINT}")

    def _packet_error(self, e):
        """패킷 하나를 처리하다 난 오류. 수집은 계속하고, 처음 한 번만 기록에 남긴다."""
        self.bad_packets += 1
        if self.bad_packets == 1:
            self.emit(events.make("system", "unknown", "처리하지 못한 패킷이 있음",
                                  f"{type(e).__name__}: {e} — 수집은 계속합니다 (이후 같은 오류는 개수만 셉니다)."))

    def _ap_loop(self):
        while not self.stop_event.is_set():
            self.scan_ap()
            self.check_dns_silence()
            self.stop_event.wait(self.ap_interval)

    def replay(self, path, delay=0.0):
        """저장된 pcap을 처음부터 끝까지 탐지 모듈에 넣는다 (Npcap 없이 실험 결과 확인용).
        delay: 패킷 사이에 쉬는 초 — 화면에서 단계가 바뀌는 모습을 보이려고 쓴다."""
        n = 0
        for m in ("arp", "dns"):
            self.set_module(m, "normal", f"pcap 재생 중 ({Path(path).name})")
        for kind, p in capture.read_pcap(path):
            self.on_item(kind, p)
            n += 1
            if delay:
                time.sleep(delay)
        for m in ("arp", "dns"):
            self.set_module(m, "normal", f"pcap 재생 완료 ({Path(path).name}, ARP·DNS 패킷 {n}개)")
        return n

    def reset_detectors(self, gateway=None, keep_active=False):
        """ARP·DNS 판단 상태를 비운다. 기록(DB)과 기준값은 그대로 둔다.
        gateway: 재생할 pcap이 찍힌 망의 공유기 IP (이 PC의 공유기와 다를 때).
        keep_active: 지금 유효한 경보는 남긴다 (데모가 끝난 뒤 결과를 계속 보여 줄 때)."""
        with self.lock:
            self.arp = arp_watch.ArpDetector(gateway_ip=gateway or self.arp.gateway_ip, trusted=self.trust.get("arp"))
            self.dns = DnsDetector(reference=self.dns_reference)
            if not keep_active:
                self.active.clear()
        self.publish("status", self.status())

    def run_demo(self, paths, gateway=None, delay=0.05):
        """데모 pcap을 재생하고, 끝나면 판단 상태·공유기 주소·모듈 표시를 재생 전으로 되돌린다.
        (실시간 감시 중에 데모를 눌러도 감시 설정이 데모 값으로 바뀐 채 남지 않게)"""
        with self.lock:
            before_gw = self.arp.gateway_ip
            before_mod = {m: dict(self.modules[m]) for m in ("arp", "dns")}
        try:
            self.reset_detectors(gateway=gateway)
            for path in paths:
                self.replay(path, delay=delay)
        finally:
            with self.lock:
                self.arp.gateway_ip = before_gw
            self.reset_detectors(keep_active=True)
            for m, old in before_mod.items():
                self.set_module(m, old["level"], old["detail"], log=False)

    # ---------- 판단 결과 처리 ----------
    def on_item(self, kind, p):
        with self.lock:
            if kind == "arp":
                alert = self.arp.feed(p)
                if alert:
                    self.raise_alert(events.from_arp(alert, self._arp_advice(alert)))
                else:
                    self._arp_still(p)
            elif kind == "dns":
                self._dns_seen()
                alert = self.dns.feed(p)
                if alert:
                    self.raise_alert(events.from_dns(alert))

    def _arp_advice(self, alert):
        return arp_watch.defense_commands(alert, self.iface or "Wi-Fi")

    def _arp_still(self, p):
        """이미 경보가 난 MAC이 같은 IP를 계속 주장하면 근거가 계속되는 것으로 본다."""
        alert = self.arp.alerts.get(p["mac"])
        if not alert or p["src_ip"] not in alert["claimed_ips"]:
            return
        key = ("arp", p["mac"])
        if key in self.active:
            self.active[key]["seen"] = self.clock()
        else:                       # '확인함' 이후 또는 오래 조용하다가 다시 보임 → 다시 알린다
            ev = events.from_arp(alert, self._arp_advice(alert))
            ev["title"] += " (확인 후에도 계속됨)"
            self.raise_alert(ev)

    def raise_alert(self, ev):
        """같은 대상의 경보가 이미 같은 단계 이상으로 유효하면 기록을 늘리지 않고 시각만 갱신한다."""
        with self.lock:
            cur = self.active.get(key_for(ev))
            if cur and RANK[cur["level"]] >= RANK[ev["level"]]:
                cur["seen"] = self.clock()
                return None
            return self.emit(ev)

    def emit(self, ev):
        with self.lock:
            saved = self.store.add(ev)
            if saved["module"] != "system" and saved["level"] in ("caution", "warning"):
                self._activate(saved, self.clock())
        self.publish("event", saved)
        self.publish("status", self.status())
        return saved

    def _activate(self, ev, seen):
        self.active[key_for(ev)] = {"level": ev["level"], "module": ev["module"], "title": ev["title"],
                                    "event_id": ev["id"], "seen": seen}

    def _expire_active(self):
        cutoff = self.clock() - ACTIVE_WINDOW
        for k in [k for k, a in self.active.items() if a["seen"] < cutoff]:
            del self.active[k]

    def ack(self):
        """사용자가 경보를 확인함 — 지금 유효한 경보를 비운다. 공격이 계속되면 다시 뜬다."""
        with self.lock:
            n = len(self.active)
            ev = self.emit(events.make("system", "normal", "사용자가 경보를 확인함",
                                       f"유효하던 경보 {n}개를 비움. 근거가 계속 보이면 다시 알립니다."))
            self.active.clear()
            self.ack_id = ev["id"]
            self.store.put("ack_id", self.ack_id)
        self.publish("status", self.status())
        return {"ok": True, "cleared": n, "ack_id": self.ack_id}

    def set_module(self, module, level, detail, log=True):
        with self.lock:
            old = self.modules[module]
            if old == {"level": level, "detail": detail}:
                return
            self.modules[module] = {"level": level, "detail": detail}
            # '확인 불가'로 처음 바뀔 때만 기록에 남긴다 (시작 전 상태도 unknown이므로 따로 본다)
            if log and level == "unknown" and (old["level"] != "unknown" or old["detail"] == "시작 전"):
                self.emit(events.module_state(module, "unknown", detail))
            else:
                self.publish("status", self.status())

    # ---------- DNS가 보이는지 (DoH) ----------
    def _dns_seen(self):
        self.dns_last = self.clock()
        if self.live and self.modules["dns"]["level"] == "unknown":
            self.set_module("dns", "normal", f"패킷 수집 중 ({self.iface or '기본 인터페이스'}, UDP 53)")

    def check_dns_silence(self):
        if not self.live or self.dns_last is None:
            return
        quiet = self.clock() - self.dns_last
        if quiet >= DNS_SILENCE and self.modules["dns"]["level"] == "normal":
            self.set_module("dns", "unknown", DOH_HINT.format(s=int(quiet)), log=not self._doh_logged)
            self._doh_logged = True

    # ---------- 가짜 AP ----------
    def scan_ap(self):
        try:
            aps = ap_watch.parse_networks(self.scanner())
        except Exception as e:     # noqa: BLE001
            self.set_module("ap", "unknown", f"AP 목록 조회 실패: {e}")
            return []
        if not aps:
            self.set_module("ap", "unknown", "주변 AP 목록을 읽지 못함 — 와이파이가 꺼져 있거나 "
                                             "Windows 위치 권한이 꺼져 있을 수 있음 (화면의 '환경 점검' 참고)")
            return []
        alerts = ap_watch.detect(aps, self.trust.get("ap"), alert_at=AP_CAUTION_AT)
        self.conn = self.connection()
        self._refresh_gateway()
        gw_alert = None
        if self.conn and self.gateway and self.gateway.get("mac"):
            gw_alert = ap_watch.check_gateway(self.conn["ssid"], self.gateway["mac"], self.trust.get("gw", {}))
        with self.lock:
            self.ap_alerts = alerts + ([gw_alert] if gw_alert else [])
            for a in self.ap_alerts:
                self.raise_alert(events.from_ap(a, AP_CAUTION_AT, AP_WARNING_AT))
        self.set_module("ap", "normal", f"주변 AP {len(aps)}개 확인, 의심 {len(alerts)}개")
        return alerts

    def _refresh_gateway(self):
        try:
            gw = self.gateway_probe()
        except Exception:          # noqa: BLE001
            gw = None
        if not gw:
            return
        if not self.gateway or not self.gateway.get("ip"):
            self.gateway = gw
            self.arp.gateway_ip = gw["ip"]
        elif gw["ip"] == self.gateway["ip"]:
            self.gateway["mac"] = gw["mac"]

    # ---------- 기준값(신뢰 목록) ----------
    def _load_trust(self):
        if self.trust_path.exists():
            return json.loads(self.trust_path.read_text(encoding="utf-8"))
        return {}

    def _save_trust(self):
        self.trust_path.write_text(json.dumps(self.trust, ensure_ascii=False, indent=2), encoding="utf-8")

    def learn(self):
        """지금 연결된 와이파이를 안전하다고 보고 BSSID와 공유기 MAC을 기준값으로 저장한다.
        처음 본 값이 진짜라는 보장은 없으므로, 사용자가 안전하다고 확신할 때만 부른다."""
        conn, gw = self.connection(), self.gateway_probe()
        if not conn:
            return {"ok": False, "reason": "연결된 와이파이가 없습니다."}
        with self.lock:
            t = self.trust
            bssids = t.setdefault("ap", {}).setdefault(conn["ssid"], [])
            if conn.get("bssid") and conn["bssid"] not in bssids:
                bssids.append(conn["bssid"])
            if gw and gw.get("mac"):
                t.setdefault("gw", {})[conn["ssid"]] = gw["mac"]
                t.setdefault("arp", {})[gw["ip"]] = gw["mac"]
            self._save_trust()
            # 사용자가 지금 상태를 안전하다고 했으므로 ARP 판단을 새 기준값에서 다시 시작한다.
            # (공유기를 교체해서 뜬 '주의'가 저장 뒤에도 계속 남거나 '확인함' 뒤 되살아나지 않게)
            self.arp = arp_watch.ArpDetector(gateway_ip=self.arp.gateway_ip, trusted=t.get("arp"))
            for k in [k for k in self.active if k[0] == "arp"]:
                del self.active[k]
        self.publish("status", self.status())
        return {"ok": True, "ssid": conn["ssid"], "bssid": conn.get("bssid"), "gateway": gw}

    def trust_view(self):
        """저장된 기준값을 와이파이 이름별로 묶어 보여 준다."""
        t = self.trust
        gw_ip = {mac: ip for ip, mac in t.get("arp", {}).items()}
        names = sorted(set(t.get("ap", {})) | set(t.get("gw", {})))
        return [{"ssid": s, "bssids": list(t.get("ap", {}).get(s, [])),
                 "gateway_mac": t.get("gw", {}).get(s),
                 "gateway_ip": gw_ip.get(t.get("gw", {}).get(s))} for s in names]

    def forget(self, ssid):
        """와이파이 하나의 기준값을 지운다 (잘못 저장했을 때)."""
        with self.lock:
            t = self.trust
            if ssid not in t.get("ap", {}) and ssid not in t.get("gw", {}):
                return {"ok": False, "reason": f"저장된 기준값이 없습니다: {ssid}"}
            t.get("ap", {}).pop(ssid, None)
            mac = t.get("gw", {}).pop(ssid, None)
            still_used = mac in t.get("gw", {}).values()
            if mac and not still_used:
                for ip in [ip for ip, m in t.get("arp", {}).items() if m == mac]:
                    del t["arp"][ip]
                    self.arp.trusted.pop(ip, None)
            self._save_trust()
        self.publish("status", self.status())
        return {"ok": True, "ssid": ssid}

    # ---------- 상태 ----------
    def status(self):
        with self.lock:
            self._expire_active()
            act = sorted(self.active.values(), key=lambda a: (-RANK[a["level"]], -a["event_id"]))
            arp_warn = [a for a in act if a["module"] == "arp" and a["level"] == "warning"]
            ap_live = [a for a in self.ap_alerts if ("ap", a["ssid"], a["bssid"]) in self.active]
            score = safety_score(self.conn, ap_live, arp_warn)
            unknown = any(m["level"] == "unknown" for m in self.modules.values())
            overall = act[0]["level"] if act else ("unknown" if unknown else "normal")
            return {"overall": overall, "overall_ko": events.LEVEL_KO[overall],
                    "modules": {k: dict(v) for k, v in self.modules.items()},
                    "active": [{"module": a["module"], "level": a["level"], "title": a["title"],
                                "event_id": a["event_id"], "last_seen": events.now_iso(a["seen"])} for a in act],
                    "ack_id": self.ack_id,
                    "connection": self.conn, "gateway": self.gateway,
                    "score": score, "counts": self.store.counts(),
                    "trusted_ssids": sorted(set(self.trust.get("ap", {})) | set(self.trust.get("gw", {})))}
