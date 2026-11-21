"""백엔드·탐지 엔진 테스트.  .venv\\Scripts\\python -m unittest discover tests

pcap 테스트는 메모리에서 만든 패킷을 임시 파일에 쓰고 다시 읽기만 한다 (네트워크로 보내지 않는다).
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guard import capture, dns_reference, events  # noqa: E402
from guard.dns_watch import DnsDetector  # noqa: E402
from server.app import create_app  # noqa: E402
from server import engine as engine_mod  # noqa: E402
from server.engine import Engine  # noqa: E402
from server.store import Store  # noqa: E402
from test_guard import KO  # noqa: E402

ME, DNS_SRV, OTHER = "192.168.0.10", "192.168.0.1", "192.168.0.66"
H = {"X-WifiGuard": "1"}            # POST에 필요한 헤더
ROOT = Path(__file__).resolve().parent.parent


def q(t, txid=7, name="bank.example", server=DNS_SRV):
    return {"time": t, "src": ME, "dst": server, "sport": 50000, "dport": 53, "id": txid,
            "qr": 0, "qname": name, "answers": []}


def r(t, ans, src=DNS_SRV, txid=7, name="bank.example"):
    return {"time": t, "src": src, "dst": ME, "sport": 53, "dport": 50000, "id": txid,
            "qr": 1, "qname": name, "answers": ans}


def engine(tmp, **kw):
    kw.setdefault("scanner", lambda: KO)
    kw.setdefault("connection", lambda: {"ssid": "Cafe", "bssid": "88:36:6c:00:00:01", "auth": "WPA2-개인"})
    kw.setdefault("gateway_probe", lambda: {"ip": "192.168.0.1", "mac": "88:36:6c:00:00:01", "iface": "Wi-Fi"})
    return Engine(Store(":memory:"), trust_path=Path(tmp) / "trust.json", **kw)


class DnsTest(unittest.TestCase):
    def test_normal_answer_no_alert(self):
        d = DnsDetector()
        d.feed(q(0.0))
        self.assertIsNone(d.feed(r(0.02, ["93.184.216.34"])))

    def test_two_different_answers_is_caution(self):
        d = DnsDetector()
        d.feed(q(0.0))
        self.assertIsNone(d.feed(r(0.01, ["10.0.0.5"])))
        alert = d.feed(r(0.03, ["93.184.216.34"]))
        self.assertEqual((alert["level"], alert["rules"]), ("caution", ["D1"]))

    def test_race_from_other_host_is_warning(self):
        d = DnsDetector()
        d.feed(q(0.0))
        self.assertIsNone(d.feed(r(0.01, ["10.0.0.5"], src=OTHER)))     # D2만으로는 주의 미만
        alert = d.feed(r(0.03, ["93.184.216.34"]))
        self.assertEqual(alert["level"], "warning")
        self.assertEqual(sorted(alert["rules"]), ["D1", "D2"])

    def test_reference_mismatch_alone_is_not_alert(self):
        d = DnsDetector(reference=lambda name: {"1.1.1.1"})
        d.feed(q(0.0))
        self.assertIsNone(d.feed(r(0.02, ["93.184.216.34"])))           # CDN일 수 있다

    def test_response_without_query_is_ignored(self):
        self.assertIsNone(DnsDetector().feed(r(0.0, ["10.0.0.5"], src=OTHER)))


    def test_resolver_fallback_is_not_race(self):
        d = DnsDetector()                                               # 두 서버에 같은 질문, CDN 답이 서로 다름
        d.feed(q(0.0))
        d.feed(q(1.0, server="168.126.63.1"))
        self.assertIsNone(d.feed(r(1.02, ["203.0.1.1"], src="168.126.63.1")))
        self.assertIsNone(d.feed(r(1.1, ["203.0.1.2"])))

    def test_retransmit_round_robin_is_not_race(self):
        d = DnsDetector()                                               # 질문 두 번 → 답 두 번은 설명된다
        d.feed(q(0.0))
        d.feed(q(1.0))
        self.assertIsNone(d.feed(r(1.02, ["203.0.1.1"])))
        self.assertIsNone(d.feed(r(1.03, ["203.0.1.2"])))
        self.assertEqual(d.feed(r(1.04, ["198.51.100.66"]))["rules"], ["D1"])   # 세 번째 다른 답은 설명 안 됨

    def test_reference_only_for_suspicious(self):
        asked = []
        d = DnsDetector(reference=lambda name: asked.append(name) or {"203.0.113.50"})
        d.feed(q(0.0))
        d.feed(r(0.01, ["203.0.113.50"]))
        self.assertEqual(asked, [])                                     # 평소 질문은 바깥으로 다시 묻지 않는다
        d.feed(q(1.0, txid=8))
        self.assertIsNone(d.feed(r(1.001, ["198.51.100.66"], txid=8)))
        alert = d.feed(r(1.02, ["203.0.113.50"], txid=8))               # D1 40 + D3 20 = 경고
        self.assertEqual((alert["level"], sorted(alert["rules"])), ("warning", ["D1", "D3"]))
        self.assertEqual(asked, ["bank.example"])


class ReferenceTest(unittest.TestCase):
    def test_build_and_parse(self):
        from scapy.all import DNS, DNSQR, DNSRR
        raw = dns_reference.build_query("bank.example", 0x1234)
        self.assertEqual(DNS(raw).qd[0].qname, b"bank.example.")
        resp = bytes(DNS(id=0x1234, qr=1, qd=DNSQR(qname="bank.example"),
                         an=[DNSRR(rrname="bank.example", rdata="203.0.113.50"),
                             DNSRR(rrname="bank.example", rdata="203.0.113.51")]))
        self.assertEqual(dns_reference.parse_answers(resp, 0x1234), {"203.0.113.50", "203.0.113.51"})
        self.assertIsNone(dns_reference.parse_answers(resp, 0x9999))   # 다른 ID는 버린다


class EventTest(unittest.TestCase):
    def test_format(self):
        ev = events.make("arp", "caution", "제목", "이유")
        self.assertEqual(set(ev), {"module", "level", "title", "reason", "evidence", "advice", "timestamp"})
        self.assertRaises(ValueError, events.make, "arp", "주의", "t", "r")

    def test_ap_levels(self):
        base = {"type": "evil_twin", "ssid": "Cafe", "bssid": "x", "auth": "Open", "signal": 90, "reasons": ["r"]}
        self.assertEqual(events.from_ap({**base, "risk": 30}, 30, 50)["level"], "caution")
        self.assertEqual(events.from_ap({**base, "risk": 50}, 30, 50)["level"], "warning")


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_ap_scan_emits_once(self):
        e = engine(self.tmp)
        e.scan_ap()
        e.scan_ap()                                         # 같은 경고는 스캔마다 반복하지 않는다
        evs = e.store.recent(module="ap")
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["level"], evs[0]["evidence"]["bssid"]), ("warning", "00:1a:2b:00:00:09"))
        self.assertEqual(e.modules["ap"]["level"], "normal")
        self.assertEqual(e.status()["overall"], "warning")

    def test_empty_scan_is_unknown_not_normal(self):
        e = engine(self.tmp, scanner=lambda: "")
        e.scan_ap()
        self.assertEqual(e.modules["ap"]["level"], "unknown")
        self.assertEqual(e.store.recent()[0]["module"], "system")

    def test_capture_failure_is_unknown(self):
        e = engine(self.tmp)
        with mock.patch.object(capture, "sniff_live", side_effect=RuntimeError("Npcap 없음")):
            e._capture_loop()
        self.assertEqual({e.modules[m]["level"] for m in ("arp", "dns")}, {"unknown"})
        self.assertEqual(e.status()["overall"], "unknown")

    def test_learn_writes_trust(self):
        e = engine(self.tmp)
        self.assertTrue(e.learn()["ok"])
        self.assertEqual(e.trust["gw"]["Cafe"], "88:36:6c:00:00:01")
        self.assertEqual(e.arp.trusted["192.168.0.1"], "88:36:6c:00:00:01")
        self.assertFalse(engine(self.tmp, connection=lambda: None).learn()["ok"])

    def test_pcap_replay(self):
        from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, UDP, Ether, wrpcap
        gw, real, odd = "192.168.0.1", "88:36:6c:00:00:01", "00:1a:2b:00:00:66"
        pkts = [Ether(dst="ff:ff:ff:ff:ff:ff", src=real) / ARP(op=2, hwsrc=real, psrc=gw, pdst=ME)]
        for i in range(3):
            pkts.append(Ether(dst="aa:aa:aa:00:00:10", src=odd) / ARP(op=2, hwsrc=odd, psrc=gw, pdst=ME))
        qd = DNSQR(qname="bank.example")
        eth = Ether(src=real, dst="aa:aa:aa:00:00:10")
        resp = eth / IP(src=DNS_SRV, dst=ME) / UDP(sport=53, dport=50000)
        pkts += [eth / IP(src=ME, dst=DNS_SRV) / UDP(sport=50000, dport=53) / DNS(id=9, qd=qd),
                 resp / DNS(id=9, qr=1, qd=qd, an=DNSRR(rrname="bank.example", rdata="10.0.0.5")),
                 resp / DNS(id=9, qr=1, qd=qd, an=DNSRR(rrname="bank.example", rdata="93.184.216.34"))]
        for i, p in enumerate(pkts):
            p.time = 1793600000.0 + i
        path = Path(self.tmp) / "t.pcap"
        wrpcap(str(path), pkts)

        e = engine(self.tmp, gateway="192.168.0.1")
        self.assertEqual(e.replay(path), len(pkts))
        arp = e.store.recent(module="arp")
        self.assertEqual(arp[0]["level"], "warning")
        self.assertEqual(arp[0]["evidence"]["target_mac"], odd)
        dns = e.store.recent(module="dns")
        self.assertEqual((dns[0]["level"], dns[0]["evidence"]["qname"]), ("caution", "bank.example"))


class ApiTest(unittest.TestCase):
    def test_api_and_socket(self):
        e = engine(tempfile.mkdtemp())
        app, socketio = create_app(e)
        web = app.test_client()
        sock = socketio.test_client(app, flask_test_client=web)
        self.assertEqual(sock.get_received()[0]["name"], "status")     # 접속하자마자 상태를 받는다

        self.assertEqual(web.post("/api/scan", headers=H).get_json()["alerts"], 1)
        names = [m["name"] for m in sock.get_received()]
        self.assertIn("event", names)

        self.assertEqual(web.get("/api/events?module=ap").get_json()[0]["level"], "warning")
        self.assertEqual(web.get("/api/status").get_json()["overall"], "warning")
        self.assertEqual(web.get("/").status_code, 200)
        self.assertEqual(web.post("/api/learn", headers=H).status_code, 200)

    def test_frontend_contract(self):
        e = engine(tempfile.mkdtemp())
        front = ROOT / "frontend"
        app, _ = create_app(e, frontend_dir=front, allowed_origins=["http://localhost:5173"],
                            diagnostics=lambda: {"npcap": {"label": "Npcap", "ok": False, "detail": "없음"}})
        web = app.test_client()
        meta = web.get("/api/meta").get_json()
        self.assertEqual(meta["levels"], ["normal", "unknown", "caution", "warning"])
        self.assertFalse(meta["demo"])

        e.scan_ap()
        first = web.get("/api/events").get_json()[0]["id"]
        e.emit(events.make("dns", "caution", "t", "r"))
        newer = web.get(f"/api/events?since={first}").get_json()       # 폴링: 새 이벤트만
        self.assertEqual([ev["module"] for ev in newer], ["dns"])

        ok = web.get("/api/status", headers={"Origin": "http://localhost:5173"})
        self.assertEqual(ok.headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        bad = web.get("/api/status", headers={"Origin": "http://evil.example"})
        self.assertIsNone(bad.headers.get("Access-Control-Allow-Origin"))
        pre = web.open("/api/scan", method="OPTIONS", headers={"Origin": "http://localhost:5173"})
        self.assertIn("POST", pre.headers.get("Access-Control-Allow-Methods"))

        self.assertIn("wifiguard-client.js", web.get("/").get_data(as_text=True))
        self.assertEqual(web.get("/wifiguard-client.js").status_code, 200)
        self.assertEqual(web.get("/debug").status_code, 200)
        self.assertEqual(web.post("/api/demo", headers=H).status_code, 404)
        self.assertEqual(web.get("/api/nope").get_json()["ok"], False)

    def test_reset_detectors(self):
        e = engine(tempfile.mkdtemp())
        e.emit(events.make("arp", "warning", "t", "r"))
        self.assertEqual(e.status()["overall"], "warning")
        e.reset_detectors()
        self.assertNotEqual(e.status()["overall"], "warning")


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def arp(t, mac, op=2, src_ip="192.168.0.1", dst_ip=ME, frame=1):
    return {"frame": frame, "time": t, "eth_dst": "aa:aa:aa:00:00:10", "op": op, "mac": mac,
            "src_ip": src_ip, "dst_ip": dst_ip}


REAL, ODD = "88:36:6c:00:00:01", "00:1a:2b:00:00:66"


def attack(e, t0=1793600000.0, n=3):
    e.on_item("arp", arp(t0, REAL))
    for i in range(n):
        e.on_item("arp", arp(t0 + 1 + i, ODD, frame=2 + i))


class ActiveAlertTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.clock = Clock()

    def make(self, store=None, **kw):
        return Engine(store or Store(":memory:", clock=self.clock), trust_path=Path(self.tmp) / "trust.json",
                      gateway="192.168.0.1", scanner=lambda: "", connection=lambda: None,
                      gateway_probe=lambda: None, clock=self.clock, **kw)

    def test_ack_clears_but_ongoing_attack_returns(self):
        e = self.make()
        attack(e)
        self.assertEqual(e.status()["overall"], "warning")
        n = len(e.store.recent(module="arp"))
        attack(e, n=2)                                      # 같은 공격이 계속돼도 기록은 늘지 않는다
        self.assertEqual(len(e.store.recent(module="arp")), n)

        self.assertEqual(e.ack()["cleared"], 1)
        self.assertNotEqual(e.status()["overall"], "warning")
        e.on_item("arp", arp(1793600100.0, ODD, frame=50))  # 확인 후에도 근거가 보이면 다시 경보
        st = e.status()
        self.assertEqual(st["overall"], "warning")
        self.assertIn("확인 후에도 계속됨", st["active"][0]["title"])

    def test_alert_expires_without_new_evidence(self):
        e = self.make()
        attack(e)
        self.clock.t += engine_mod.ACTIVE_WINDOW - 1
        self.assertEqual(e.status()["overall"], "warning")
        self.clock.t += 2
        self.assertNotEqual(e.status()["overall"], "warning")
        self.assertEqual(e.status()["active"], [])

    def test_state_survives_restart(self):
        db = Path(self.tmp) / "e.db"
        e = self.make(Store(db, clock=self.clock))
        attack(e)
        again = self.make(Store(db, clock=self.clock))      # 서버를 다시 켬
        self.assertEqual(again.status()["overall"], "warning")
        again.ack()
        third = self.make(Store(db, clock=self.clock))
        self.assertEqual(third.status()["active"], [])      # '확인함'도 유지된다

    def test_prune_old_events(self):
        db = Path(self.tmp) / "p.db"
        s = Store(db, clock=self.clock)
        s.add(events.make("dns", "caution", "old", "r"))
        self.clock.t += 31 * 86400
        s.add(events.make("dns", "caution", "new", "r"))
        self.make(Store(db, clock=self.clock), keep_days=30)
        self.assertEqual([ev["title"] for ev in Store(db).recent()], ["new"])

    def test_dns_silence_means_unknown(self):
        e = self.make()
        e.live, e.dns_last = True, self.clock()
        e.set_module("dns", "normal", "수집 중")
        self.clock.t += engine_mod.DNS_SILENCE + 1
        e.check_dns_silence()
        self.assertEqual(e.modules["dns"]["level"], "unknown")
        self.assertIn("DoH", e.modules["dns"]["detail"])
        e.on_item("dns", q(1.0))                            # DNS가 다시 보이면 정상으로
        self.assertEqual(e.modules["dns"]["level"], "normal")


class ReviewFixTest(unittest.TestCase):
    """검토에서 찾은 문제들이 다시 생기지 않는지."""

    def test_learn_clears_arp_alert(self):
        e = engine(tempfile.mkdtemp(), gateway="192.168.0.1")
        attack(e)
        self.assertEqual(e.status()["overall"], "warning")
        e.learn()                                           # 사용자가 지금 상태를 안전하다고 함
        self.assertEqual([a for a in e.status()["active"] if a["module"] == "arp"], [])
        e.on_item("arp", arp(1793600200.0, REAL, frame=90)) # 기준값과 같은 MAC은 다시 경보가 되지 않는다
        self.assertEqual(e.status()["active"], [])

    def test_demo_restores_live_settings(self):
        e = engine(tempfile.mkdtemp(), gateway="10.0.0.1", scanner=lambda: "")
        e.set_module("arp", "unknown", "수집 끔")
        e.run_demo([ROOT / "eval" / "demo" / "victim_view.pcap", ROOT / "eval" / "demo" / "dns_race.pcap"],
                   gateway="192.168.0.1", delay=0)
        self.assertEqual(e.arp.gateway_ip, "10.0.0.1")      # 데모 값이 남지 않는다
        self.assertEqual(e.modules["arp"], {"level": "unknown", "detail": "수집 끔"})
        self.assertEqual({a["module"] for a in e.status()["active"]}, {"arp", "dns"})   # 결과는 계속 보인다
        self.assertEqual(e.arp.alerts, {})

    def test_bad_packet_does_not_stop_capture(self):
        import scapy.all
        stop, got, errors = mock.Mock(), [], []
        stop.is_set.side_effect = [False, True]

        def fake_sniff(prn, **kw):
            prn("깨진 패킷")
            prn("정상 패킷")
        with mock.patch.object(scapy.all, "sniff", fake_sniff), \
                mock.patch.object(capture, "convert", side_effect=[ValueError("x"), ("arp", {"n": 1})]):
            capture.sniff_live(None, lambda kind, p: got.append(kind), stop, on_error=errors.append)
        self.assertEqual((got, len(errors)), (["arp"], 1))

    def test_d3_sees_fake_answer_even_if_it_came_second(self):
        d = DnsDetector(reference=lambda name: {"203.0.113.50"})
        d.feed(q(0.0))
        d.feed(r(0.01, ["203.0.113.50"]))                   # 진짜 답이 먼저
        alert = d.feed(r(0.02, ["198.51.100.66"]))          # 같은 서버 주소로 다른 답
        self.assertEqual(sorted(alert["rules"]), ["D1", "D3"])

    def test_reference_survives_bad_name(self):
        ref = dns_reference.Reference("192.0.2.1", timeout=0.01)
        self.assertIsNone(ref("a" * 80 + ".example"))       # 규격에 안 맞는 이름 (라벨 63자 초과)


class TrustTest(unittest.TestCase):
    def test_view_and_forget(self):
        e = engine(tempfile.mkdtemp())
        e.learn()
        view = e.trust_view()
        self.assertEqual((view[0]["ssid"], view[0]["gateway_ip"]), ("Cafe", "192.168.0.1"))
        self.assertTrue(e.forget("Cafe")["ok"])
        self.assertEqual(e.trust_view(), [])
        self.assertNotIn("192.168.0.1", e.arp.trusted)
        self.assertFalse(e.forget("Cafe")["ok"])
        self.assertEqual(json.loads(e.trust_path.read_text(encoding="utf-8")), {"ap": {}, "gw": {}, "arp": {}})


class SecurityTest(unittest.TestCase):
    def setUp(self):
        app, _ = create_app(engine(tempfile.mkdtemp()), allowed_origins=["http://localhost:5173"],
                            diagnostics=lambda: {})
        self.web = app.test_client()

    def test_post_needs_header(self):
        self.assertEqual(self.web.post("/api/learn").status_code, 403)          # 다른 사이트의 단순 POST
        self.assertEqual(self.web.post("/api/learn", headers=H).status_code, 200)

    def test_post_from_other_origin_is_denied(self):
        r = self.web.post("/api/ack", headers={**H, "Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)
        ok = self.web.post("/api/ack", headers={**H, "Origin": "http://localhost:5173"})
        self.assertEqual(ok.status_code, 200)

    def test_dns_rebinding_host_is_denied(self):
        self.assertEqual(self.web.get("/api/status", headers={"Host": "evil.example:5000"}).status_code, 403)
        self.assertEqual(self.web.get("/api/status", headers={"Host": "127.0.0.1:5000"}).status_code, 200)

    def test_new_endpoints(self):
        self.assertEqual(self.web.get("/api/diagnostics").get_json(), {})
        self.assertEqual(self.web.get("/api/trust").get_json(), [])
        self.assertEqual(self.web.post("/api/trust/forget", headers=H, json={}).status_code, 400)
        self.assertEqual(self.web.post("/api/trust/forget", headers=H, json={"ssid": "없음"}).status_code, 404)


class PcapImportOrderTest(unittest.TestCase):
    def test_read_pcap_in_fresh_process(self):
        """scapy.all을 먼저 불러오지 않은 프로세스에서도 Ether 패킷을 읽어야 한다 (예전 버그)."""
        code = "from guard import capture; print(sum(1 for _ in capture.read_pcap('eval/demo/dns_race.pcap')))"
        out = subprocess.run([sys.executable, "-W", "ignore", "-c", code], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(out.stdout.strip().splitlines()[-1], "15")


class ContractTest(unittest.TestCase):
    """docs/openapi.json(프론트와 맞춘 규격)과 실제 서버가 어긋나지 않는지 본다.
    응답을 바꾸면 이 테스트가 깨진다 → 규격 문서와 프론트 담당에게 먼저 알린다."""
    TYPES = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}

    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads((ROOT / "docs/openapi.json").read_text(encoding="utf-8"))

    def resolve(self, s):
        while "$ref" in s:
            s = self.spec["components"]["schemas"][s["$ref"].rsplit("/", 1)[1]]
        return s

    def check(self, value, schema, where="$"):
        s = self.resolve(schema)
        if "oneOf" in s:
            errs = []
            for opt in s["oneOf"]:
                try:
                    return self.check(value, opt, where)
                except AssertionError as e:
                    errs.append(str(e))
            self.fail(f"{where}: oneOf 어느 것에도 맞지 않음 {errs}")
        if value is None:
            self.assertTrue(s.get("nullable"), f"{where}: null이 허용되지 않음")
            return
        t = s.get("type")
        if t:
            self.assertIsInstance(value, self.TYPES[t], f"{where}: {t} 이어야 함")
            self.assertFalse(t == "integer" and isinstance(value, bool), where)
        if "enum" in s:
            self.assertIn(value, s["enum"], where)
        if t == "object":
            for k in s.get("required", []):
                self.assertIn(k, value, f"{where}: 필수 키 {k} 없음")
            for k, v in value.items():
                sub = s.get("properties", {}).get(k) or s.get("additionalProperties")
                if isinstance(sub, dict):
                    self.check(v, sub, f"{where}.{k}")
        if t == "array":
            for i, v in enumerate(value):
                self.check(v, s["items"], f"{where}[{i}]")

    def test_every_route_is_in_spec(self):
        app, _ = create_app(engine(tempfile.mkdtemp()))
        routes = {(r.rule, m.lower()) for r in app.url_map.iter_rules() if r.rule.startswith("/api/")
                  for m in r.methods - {"HEAD", "OPTIONS"}}
        documented = {(p, m) for p, ops in self.spec["paths"].items() for m in ops}
        self.assertEqual(routes, documented)

    def test_real_responses_match_spec(self):
        tmp = tempfile.mkdtemp()
        eng = engine(tmp)
        demos = [ROOT / "eval/demo/victim_view.pcap", ROOT / "eval/demo/dns_race.pcap"]
        app, _ = create_app(eng, demo_pcap=demos, demo_gateway="192.168.0.1",
                            diagnostics=lambda: {k: {"label": k, "ok": None, "detail": "-"}
                                                 for k in ("npcap", "admin", "wlan", "location", "networks")})
        c = app.test_client()
        calls = [("get", "/api/health", None), ("get", "/api/meta", None), ("post", "/api/scan", None),
                 ("post", "/api/learn", None), ("get", "/api/trust", None), ("get", "/api/diagnostics", None),
                 ("post", "/api/trust/forget", {}), ("post", "/api/trust/forget", {"ssid": "없음"})]
        eng.run_demo(demos, gateway="192.168.0.1", delay=0)
        calls += [("get", "/api/status", None), ("get", "/api/events?limit=500", None),
                  ("post", "/api/ack", None), ("get", "/api/events?module=system", None),
                  ("post", "/api/trust/forget", {"ssid": "Cafe"}), ("post", "/api/ack", "no-header")]
        for method, url, body in calls:
            headers = {} if body == "no-header" else H
            r = getattr(c, method)(url, headers=headers, json=body if isinstance(body, dict) else None)
            path = url.split("?")[0]
            op = self.spec["paths"][path][method]
            self.assertIn(str(r.status_code), op["responses"], f"{method} {url}: 규격에 없는 상태 코드 {r.status_code}")
            schema = op["responses"][str(r.status_code)]["content"]["application/json"]["schema"]
            with self.subTest(url=url, code=r.status_code):
                self.check(r.get_json(), schema, f"{method} {url}")


if __name__ == "__main__":
    unittest.main()
