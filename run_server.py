"""와이파이 지킴이 백엔드 실행.

  .venv\\Scripts\\python run_server.py                        실시간 감시 (Npcap·관리자 권한 필요)
  .venv\\Scripts\\python run_server.py --iface Wi-Fi --gateway 192.168.0.1
  .venv\\Scripts\\python run_server.py --replay 캡처.pcap      pcap 재생 (Npcap 없이)
  .venv\\Scripts\\python run_server.py --no-capture            AP 감시만
  .venv\\Scripts\\python run_server.py --no-capture --demo     화면 확인용 ('데모 재생' 버튼 → ARP·DNS 데모 pcap)
  .venv\\Scripts\\python run_server.py --dns-reference 1.1.1.1 DNS D3 기준 조회 켜기 (의심 질문에만)
  .venv\\Scripts\\python -m guard.diagnose                     '확인 불가'일 때 환경 점검

브라우저에서 http://127.0.0.1:5000 을 연다 (프론트엔드 = frontend/, 백엔드 확인 화면 = /debug).
프론트를 다른 포트에서 개발하면 3000·5173·5500·8080 은 기본 허용, 그 밖은 --allow-origin 으로 추가.
"""
import argparse
import threading
from pathlib import Path

from guard.dns_reference import Reference
from server.app import create_app, local_origins
from server.engine import Engine
from server.store import Store

ROOT = Path(__file__).parent
DEMO_PCAPS = [ROOT / "eval" / "demo" / "victim_view.pcap", ROOT / "eval" / "demo" / "dns_race.pcap"]


def main():
    ap = argparse.ArgumentParser(description="와이파이 지킴이 백엔드")
    ap.add_argument("--iface", help="패킷을 받을 인터페이스 이름 (예: Wi-Fi). 없으면 Scapy 기본값")
    ap.add_argument("--gateway", help="공유기 IP. 없으면 Windows 라우팅 표에서 읽는다")
    ap.add_argument("--replay", help="실시간 수집 대신 재생할 pcap 파일")
    ap.add_argument("--no-capture", action="store_true", help="패킷 수집 없이 AP 감시만")
    ap.add_argument("--ap-interval", type=int, default=30, help="AP 스캔 간격(초)")
    ap.add_argument("--trust", default=str(ROOT / "trust.json"))
    ap.add_argument("--db", default=str(ROOT / "out" / "wifiguard.db"))
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--frontend", default=str(ROOT / "frontend"), help="/ 에서 보여 줄 프론트엔드 폴더")
    ap.add_argument("--allow-origin", action="append", default=[], metavar="URL",
                    help="API·소켓을 허용할 프론트 개발 서버 주소 (예: http://localhost:4200). 여러 번 가능")
    ap.add_argument("--demo", nargs="*", metavar="PCAP",
                    help="POST /api/demo 로 재생할 pcap (값 없이 쓰면 eval/demo 의 ARP·DNS 데모 두 개)")
    ap.add_argument("--demo-gateway", default="192.168.0.1",
                    help="데모 pcap이 찍힌 망의 공유기 IP (기본 192.168.0.1 = 기본 데모 pcap)")
    ap.add_argument("--dns-reference", metavar="IP",
                    help="DNS D3 기준 조회 서버 (예: 1.1.1.1). 의심 질문에만 다시 물어본다. 기본은 끔")
    ap.add_argument("--keep-days", type=int, default=30, help="이 기간(일)보다 오래된 기록은 시작할 때 지운다 (0=안 지움)")
    a = ap.parse_args()
    demos = None if a.demo is None else [str(p) for p in (a.demo or DEMO_PCAPS) if Path(p).exists()]

    engine = Engine(Store(a.db), trust_path=a.trust, iface=a.iface, gateway=a.gateway,
                    ap_interval=a.ap_interval, keep_days=a.keep_days,
                    dns_reference=Reference(a.dns_reference) if a.dns_reference else None)
    app, socketio = create_app(engine, frontend_dir=a.frontend,
                               allowed_origins=local_origins(a.port, a.allow_origin), demo_pcap=demos,
                               demo_gateway=a.demo_gateway)
    engine.start(live_capture=not (a.replay or a.no_capture))
    if a.replay:
        threading.Thread(target=engine.replay, args=(a.replay,), daemon=True).start()
    elif a.no_capture:
        for m in ("arp", "dns"):
            engine.set_module(m, "unknown", "패킷 수집을 끄고 실행함 (--no-capture)")
    print(f"와이파이 지킴이: http://127.0.0.1:{a.port}   (백엔드 확인 화면 /debug, API 문서 docs/API.md)")
    socketio.run(app, host="127.0.0.1", port=a.port, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
