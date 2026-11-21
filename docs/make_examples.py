"""데모 pcap을 실제로 재생해 각 API의 응답 예시를 docs/examples/에 저장한다 (네트워크는 쓰지 않는다).

  .venv\Scripts\python docs\make_examples.py
"""
import json, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent; sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tests"))
from server.app import create_app
from server.engine import Engine
from server.store import Store
from test_guard import KO

tmp = tempfile.mkdtemp()
eng = Engine(Store(":memory:"), trust_path=Path(tmp) / "trust.json", scanner=lambda: KO,
             connection=lambda: {"ssid": "Cafe", "bssid": "88:36:6c:00:00:01", "auth": "WPA2-개인"},
             gateway_probe=lambda: {"ip": "192.168.0.1", "mac": "88:36:6c:00:00:01", "iface": "Wi-Fi"})
demos = [ROOT / "eval/demo/victim_view.pcap", ROOT / "eval/demo/dns_race.pcap"]
diag = lambda: {"npcap": {"label": "Npcap 드라이버", "ok": False, "detail": "Npcap이 없습니다. https://npcap.com 에서 설치하세요 (설치 옵션: 'WinPcap API-compatible Mode' 체크)."},
                "admin": {"label": "관리자 권한", "ok": True, "detail": "관리자 권한으로 실행 중"},
                "wlan": {"label": "와이파이", "ok": True, "detail": "무선 랜카드 켜짐, 와이파이 연결됨"},
                "location": {"label": "위치 권한", "ok": True, "detail": "위치 권한 허용됨"},
                "networks": {"label": "주변 AP 목록", "ok": True, "detail": "주변 AP(BSSID) 12개 읽힘"}}
# 실시간 수집 중일 때 보이는 모듈 상태로 맞춘다 (엔진을 시작하지 않으면 '시작 전'으로 남는다)
eng.set_module("arp", "normal", "패킷 수집 중 (Wi-Fi)", log=False)
eng.set_module("dns", "normal", "패킷 수집 중 (Wi-Fi, UDP 53만 — DoH는 보이지 않음)", log=False)
app, sio = create_app(eng, demo_pcap=demos, demo_gateway="192.168.0.1", diagnostics=diag)
c = app.test_client(); H = {"X-WifiGuard": "1"}
out = ROOT / "docs/examples"; out.mkdir(parents=True, exist_ok=True)
def save(name, resp):
    data = resp.get_json()
    (out / f"{name}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(name, resp.status_code)
save("health", c.get("/api/health")); save("meta", c.get("/api/meta"))
save("status_start", c.get("/api/status"))
save("scan", c.post("/api/scan", headers=H))
save("learn", c.post("/api/learn", headers=H))
eng.run_demo(demos, gateway="192.168.0.1", delay=0)
save("status_alert", c.get("/api/status"))
save("events", c.get("/api/events?limit=20"))
save("trust", c.get("/api/trust")); save("diagnostics", c.get("/api/diagnostics"))
save("error_403_no_header", c.post("/api/ack"))
save("error_400_forget", c.post("/api/trust/forget", headers=H, json={}))
save("forget_404", c.post("/api/trust/forget", headers=H, json={"ssid": "없는와이파이"}))
save("ack", c.post("/api/ack", headers=H))
save("status_after_ack", c.get("/api/status"))
