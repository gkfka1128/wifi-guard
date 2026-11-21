"""실행 환경 점검 — '확인 불가'가 뜰 때 무엇이 빠졌는지 알려 준다. 읽기만 하고 아무것도 바꾸지 않는다.

  .venv\\Scripts\\python -m guard.diagnose

  npcap     실시간 패킷 수집에 필요한 Npcap 드라이버가 설치돼 있는가
  admin     관리자 권한으로 실행 중인가 (Npcap 설정에 따라 필요)
  wlan      무선 랜카드가 있고 켜져 있는가
  location  Windows 위치 권한 — Windows 11 24H2부터 주변 AP 목록(netsh wlan show networks)에 필요
  networks  지금 주변 AP 목록이 실제로 읽히는가
"""
import ctypes
import os
import re
import subprocess
import sys
from pathlib import Path

LOCATION_KEY = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"


def _netsh(*args):
    try:
        r = subprocess.run(["netsh", "wlan", *args], capture_output=True, timeout=10,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, str(e)
    for enc in ("utf-8", "cp949"):
        try:
            return r.returncode, r.stdout.decode(enc)
        except UnicodeDecodeError:
            continue
    return r.returncode, r.stdout.decode("utf-8", "replace")


def check_npcap():
    root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    found = [p for p in (root / "Npcap" / "wpcap.dll", root / "wpcap.dll") if p.exists()]
    if found:
        return {"ok": True, "detail": f"설치됨 ({found[0]})"}
    return {"ok": False, "detail": "Npcap이 없습니다. https://npcap.com 에서 설치하세요 "
                                   "(설치 옵션: 'WinPcap API-compatible Mode' 체크)."}


def check_admin():
    try:
        ok = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return {"ok": None, "detail": "Windows가 아니라 확인하지 않음"}
    return {"ok": ok, "detail": "관리자 권한으로 실행 중" if ok else
            "일반 권한입니다. Npcap을 '관리자만 접근' 옵션으로 설치했다면 관리자 권한으로 실행하세요."}


def check_wlan():
    code, out = _netsh("show", "interfaces")
    if code is None:
        return {"ok": False, "detail": f"netsh 실행 실패: {out}"}
    if "State" not in out and "상태" not in out:
        return {"ok": False, "detail": "무선 랜카드를 찾지 못했습니다 (꺼져 있거나 없음)."}
    if re.search(r"(Hardware|하드웨어)\s*(Off|끔)", out):
        return {"ok": False, "detail": "무선 랜카드가 하드웨어 스위치로 꺼져 있습니다 (노트북의 무선 키·스위치 확인)."}
    if re.search(r"(Software|소프트웨어)\s*(Off|끔)", out):
        return {"ok": False, "detail": "와이파이가 꺼져 있습니다. 작업 표시줄 오른쪽 아래의 와이파이 버튼을 켜세요 "
                                       "(비행기 모드면 해제)."}
    connected = re.search(r"^\s*(State|상태)\s*:\s*(connected|연결됨)\s*$", out, re.M | re.I)
    return {"ok": True, "detail": "무선 랜카드 켜짐, " + ("와이파이 연결됨" if connected else "와이파이 연결 안 됨")}


def check_location():
    try:
        import winreg
    except ImportError:
        return {"ok": None, "detail": "Windows가 아니라 확인하지 않음"}
    values = {}
    for name, hive in (("시스템", winreg.HKEY_LOCAL_MACHINE), ("사용자", winreg.HKEY_CURRENT_USER)):
        try:
            with winreg.OpenKey(hive, LOCATION_KEY) as k:
                values[name] = winreg.QueryValueEx(k, "Value")[0]
        except OSError:
            values[name] = None
    denied = [n for n, v in values.items() if v == "Deny"]
    if denied:
        return {"ok": False, "detail": f"위치 권한이 꺼져 있습니다 ({', '.join(denied)}). "
                                       "설정 → 개인 정보 및 보안 → 위치 → '위치 서비스'와 "
                                       "'데스크톱 앱이 위치에 액세스하도록 허용'을 켜세요."}
    return {"ok": True, "detail": "위치 권한 허용됨" if values.get("사용자") == "Allow"
            else "위치 권한 값을 찾지 못함 (이전 Windows 버전이면 필요 없음)"}


def check_networks():
    code, out = _netsh("show", "networks", "mode=bssid")
    if code is None:
        return {"ok": False, "detail": f"netsh 실행 실패: {out}"}
    n = sum(1 for line in out.splitlines() if line.strip().startswith("BSSID"))
    if n:
        return {"ok": True, "detail": f"주변 AP(BSSID) {n}개 읽힘"}
    hint = " ".join(out.split())[:160]
    return {"ok": False, "detail": "주변 AP 목록이 비어 있습니다. " + (f"netsh 메시지: {hint}" if hint else "")}


CHECKS = {"npcap": ("Npcap", check_npcap), "admin": ("관리자 권한", check_admin),
          "wlan": ("무선 랜카드", check_wlan), "location": ("위치 권한", check_location),
          "networks": ("주변 AP 목록", check_networks)}


def run():
    out = {}
    for key, (label, fn) in CHECKS.items():
        try:
            r = fn()
        except Exception as e:     # noqa: BLE001 — 점검 하나가 실패해도 나머지는 보여 준다
            r = {"ok": None, "detail": f"점검 실패: {e}"}
        out[key] = {"label": label, **r}
    return out


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    for key, r in run().items():
        mark = {True: "OK ", False: "!! ", None: "-- "}[r["ok"]]
        print(f"{mark}{r['label']:<8} {r['detail']}")
