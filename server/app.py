"""Flask 백엔드 — REST API + Socket.IO 실시간 전달.  계약 문서: docs/API.md

  GET  /api/health        살아 있는지 확인
  GET  /api/meta          판정 단계·모듈 이름·한글 표기 (프론트가 하드코딩하지 않도록)
  GET  /api/status        전체 단계, 모듈 상태, 지금 유효한 경보, 연결 정보, 안전 점수
  GET  /api/events        최근 이벤트, 최신순 (?limit=50&module=arp&level=warning&since=12)
  GET  /api/trust         저장된 기준값 (와이파이별 BSSID·공유기 MAC)
  GET  /api/diagnostics   실행 환경 점검 (Npcap, 관리자 권한, 와이파이, 위치 권한, AP 목록)
  POST /api/scan          가짜 AP 스캔 즉시 실행
  POST /api/learn         지금 연결된 와이파이를 기준값으로 저장
  POST /api/trust/forget  기준값 하나 지우기 {"ssid": "..."}
  POST /api/ack           지금 유효한 경보를 '확인함'으로 비우기
  POST /api/demo          저장된 데모 pcap 재생 (탐지 상태를 비우고 처음부터)
  Socket.IO 'event'       새 이벤트 하나 (events.py 형식 + id)
  Socket.IO 'status'      /api/status 와 같은 내용

  GET  /                  프론트엔드 (--frontend 폴더, 기본 frontend/)
  GET  /debug             백엔드 확인용 화면 (static/index.html)
  GET  /vendor/socket.io.min.js  Socket.IO 클라이언트 (CDN 없이)

보안
  - 127.0.0.1에만 연다 (run_server.py). 같은 와이파이의 다른 사람은 접속할 수 없다.
  - 내 브라우저에 열린 다른 사이트가 이 서버를 부르는 것을 막는다.
      Host 검사       주소창이 127.0.0.1/localhost 가 아니면 거절 (DNS 리바인딩 방지)
      POST 헤더       X-WifiGuard: 1 이 없으면 거절. 이 헤더를 붙이려면 브라우저가 사전 확인(preflight)을
                      해야 하고, 허용 목록에 없는 사이트는 거기서 막힌다 (CORS만으로는 단순 POST를 못 막는다)
      Origin 검사     POST에 Origin이 있으면 허용 목록에 있어야 한다
"""
import threading
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory
from flask_socketio import SocketIO

from guard import diagnose, events

API_VERSION = "1"
STATIC = Path(__file__).parent / "static"
DEV_PORTS = (3000, 5173, 5500, 8080)     # React·Vite·Live Server 등 자주 쓰는 개발 서버 포트
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
CSRF_HEADER = "X-WifiGuard"


def local_origins(port, extra=()):
    ports = (port, *DEV_PORTS)
    return sorted({f"http://{h}:{p}" for h in ("127.0.0.1", "localhost") for p in ports} | set(extra))


def _hostname(host):
    host = host.lower()
    if host.startswith("["):                     # [::1]:5000
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0]


def create_app(engine, frontend_dir=None, allowed_origins=None, demo_pcap=None, demo_gateway=None,
               diagnostics=diagnose.run):
    app = Flask(__name__, static_folder=None)
    app.json.ensure_ascii = False
    app.json.sort_keys = False          # 환경 점검 순서(Npcap → 권한 → 와이파이 → 위치 → AP)를 그대로
    origins = allowed_origins if allowed_origins is not None else local_origins(5000)
    # 목록에 없는 사이트(인터넷의 다른 페이지)가 이 서버로 소켓을 열지 못하게 한다
    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins=origins)
    engine.publish = lambda kind, data: socketio.emit(kind, data)
    front = Path(frontend_dir) if frontend_dir else None
    demos = [demo_pcap] if isinstance(demo_pcap, (str, Path)) else list(demo_pcap or [])
    demo_lock = threading.Lock()

    def deny(reason):
        return jsonify({"ok": False, "reason": reason}), 403

    @app.before_request
    def guard_request():
        if _hostname(request.host) not in LOCAL_HOSTS:
            return deny("로컬 주소(127.0.0.1)로만 접속할 수 있습니다.")
        if request.method == "POST" and request.path.startswith("/api/"):
            origin = request.headers.get("Origin")
            if origin and origin not in origins:
                return deny(f"허용되지 않은 출처입니다: {origin}")
            if request.headers.get(CSRF_HEADER) != "1":
                return deny(f"{CSRF_HEADER}: 1 헤더가 필요합니다.")
        return None

    @app.after_request
    def cors(resp):
        origin = request.headers.get("Origin")
        if origin in origins and request.path.startswith("/api/"):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = f"Content-Type, {CSRF_HEADER}"
            resp.headers["Vary"] = "Origin"
        return resp

    # ---------- 읽기 ----------
    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "version": API_VERSION})

    @app.get("/api/meta")
    def meta():
        return jsonify({
            "version": API_VERSION,
            "levels": list(events.LEVELS),                  # 낮은 단계 → 높은 단계
            "level_ko": events.LEVEL_KO,
            "modules": {"arp": "인터넷 해킹", "ap": "가짜 와이파이", "dns": "가짜 사이트 유도", "system": "시스템"},
            "event_fields": ["id", "module", "level", "title", "reason", "evidence", "advice", "timestamp"],
            "demo": bool(demos),
            "csrf_header": CSRF_HEADER,
        })

    @app.get("/api/status")
    def status():
        return jsonify(engine.status())

    @app.get("/api/events")
    def recent():
        limit = max(1, min(request.args.get("limit", 50, type=int), 500))
        return jsonify(engine.store.recent(limit, request.args.get("module"), request.args.get("level"),
                                           since=request.args.get("since", type=int)))

    @app.get("/api/trust")
    def trust():
        return jsonify(engine.trust_view())

    @app.get("/api/diagnostics")
    def diag():
        return jsonify(diagnostics())

    # ---------- 동작 ----------
    @app.post("/api/scan")
    def scan():
        return jsonify({"alerts": len(engine.scan_ap()), "status": engine.status()})

    @app.post("/api/learn")
    def learn():
        result = engine.learn()
        return jsonify(result), 200 if result["ok"] else 409

    @app.post("/api/trust/forget")
    def forget():
        ssid = (request.get_json(silent=True) or {}).get("ssid")
        if not isinstance(ssid, str) or not ssid:
            return jsonify({"ok": False, "reason": "ssid가 필요합니다."}), 400
        result = engine.forget(ssid)
        return jsonify(result), 200 if result["ok"] else 404

    @app.post("/api/ack")
    def ack():
        return jsonify(engine.ack())

    @app.post("/api/demo")
    def demo():
        if not demos:
            return jsonify({"ok": False, "reason": "데모 pcap이 설정되지 않았습니다."}), 404
        if not demo_lock.acquire(blocking=False):
            return jsonify({"ok": False, "reason": "데모를 이미 재생하고 있습니다."}), 409

        def run():
            try:
                engine.run_demo(demos, gateway=demo_gateway)
            finally:
                demo_lock.release()
        threading.Thread(target=run, name="demo", daemon=True).start()
        return jsonify({"ok": True, "files": [Path(p).name for p in demos]}), 202

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "reason": "없는 API입니다."}), 404
        return e

    # ---------- 화면 ----------
    @app.get("/debug")
    def debug_page():
        return send_from_directory(STATIC, "index.html")

    @app.get("/")
    def index():
        if front and (front / "index.html").exists():
            return send_from_directory(front, "index.html")
        return send_from_directory(STATIC, "index.html")

    @app.get("/vendor/socket.io.min.js")
    def vendor_socketio():
        return send_from_directory(STATIC, "socket.io.min.js")      # 인터넷 없는 실험망에서도 실시간 연결

    @app.get("/<path:name>")
    def front_file(name):
        if not front:
            abort(404)
        return send_from_directory(front, name)      # 폴더 밖 경로(../)는 Flask가 막는다

    @socketio.on("connect")
    def on_connect():
        socketio.emit("status", engine.status(), to=request.sid)

    return app, socketio
