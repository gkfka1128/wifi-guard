"""F3  가짜 AP(이블 트윈) 탐지.

`netsh wlan show networks mode=bssid` 결과를 읽어 같은 이름(SSID)의 AP끼리 비교한다.
  A1  같은 이름인데 보안 방식이 다름 (하나만 개방형이면 위험도가 크다)
  A2  신뢰 목록에 있는 이름인데 처음 보는 BSSID
  A3  같은 이름의 다른 AP들과 제조사(OUI)가 다르거나, 임의 생성 MAC(로컬 관리 비트)임
  A4  신뢰 AP보다 비정상적으로 강한 신호
"""
import json
import re
import subprocess
from collections import Counter, defaultdict

W_OPEN_TWIN = 50
W_AUTH_DIFF = 20
W_UNKNOWN_BSSID = 30
W_OUI = 20
W_LOCAL_MAC = 20
W_SIGNAL = 10
ALERT_AT = 50
SIGNAL_GAP = 25         # 신뢰 AP 중 가장 강한 신호보다 이만큼(%p) 이상 강하면 의심

OPEN = {"open", "개방"}

# 영문/한글 Windows 모두의 netsh 출력 항목 이름
KEYS = {"ssid": r"SSID \d+", "auth": r"Authentication|인증", "enc": r"Encryption|암호화",
        "bssid": r"BSSID \d+", "signal": r"Signal|신호", "channel": r"Channel|채널"}
LINE = re.compile(r"^\s*(?P<k>[^:]+?)\s*:\s*(?P<v>.*)$")


def scan_text():
    out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    return out.stdout


def parse_networks(text):
    """netsh 출력 → AP 목록 [{ssid, auth, enc, bssid, signal, channel}]"""
    aps, net, cur = [], {}, None
    for raw in text.splitlines():
        m = LINE.match(raw)
        if not m:
            continue
        k, v = m["k"], m["v"].strip()
        key = next((name for name, pat in KEYS.items() if re.fullmatch(pat, k)), None)
        if key == "ssid":
            net, cur = {"ssid": v}, None
        elif key in ("auth", "enc"):
            net[key] = v
        elif key == "bssid":
            cur = {**net, "bssid": v.lower(), "signal": 0, "channel": ""}
            aps.append(cur)
        elif cur is not None and key == "signal":
            cur["signal"] = int(v.rstrip("%"))
        elif cur is not None and key == "channel":
            cur["channel"] = v
    return aps


def is_open(ap):
    return ap.get("auth", "").lower() in OPEN


def local_admin(mac):
    return int(mac[:2], 16) & 0x02 != 0


def detect(aps, trust=None, alert_at=ALERT_AT):
    """trust: {ssid: [신뢰 BSSID...]}. 위험도 alert_at 이상인 AP를 경고로 돌려준다."""
    trust = trust or {}
    groups = defaultdict(list)
    for ap in aps:
        if ap["ssid"]:
            groups[ap["ssid"]].append(ap)

    alerts = []
    for ssid, group in groups.items():
        trusted = [a for a in group if a["bssid"] in trust.get(ssid, [])]
        base = trusted or group                             # 비교 기준: 신뢰 AP, 없으면 전체
        # AP가 두 대뿐이면 어느 쪽이 '다수'인지 알 수 없으므로, 다수결 규칙은
        # 신뢰 목록이 있거나 세 대 이상일 때만 쓴다
        majority_ok = bool(trusted) or len(group) >= 3
        secured = Counter(a.get("auth", "") for a in base if not is_open(a))
        auth_major = secured.most_common(1)[0][0] if secured else None
        oui_major = Counter(a["bssid"][:8] for a in base).most_common(1)[0][0]
        strongest = max((a["signal"] for a in trusted), default=None)

        for ap in group:
            if ap in trusted:
                continue
            risk, why = 0, []
            if auth_major and is_open(ap):
                risk += W_OPEN_TWIN
                why.append(f"같은 이름의 다른 AP는 {auth_major}인데 이 AP만 개방형")
            elif majority_ok and auth_major and ap.get("auth", "") != auth_major:
                risk += W_AUTH_DIFF
                why.append(f"보안 방식이 다름 ({ap.get('auth')} / 다른 AP {auth_major})")
            if ssid in trust:
                risk += W_UNKNOWN_BSSID
                why.append("신뢰 목록에 없는 BSSID")
            if majority_ok and ap["bssid"][:8] != oui_major:
                risk += W_OUI
                why.append(f"제조사(OUI) {ap['bssid'][:8]}가 다른 AP({oui_major})와 다름")
            if local_admin(ap["bssid"]) and not local_admin(oui_major):
                risk += W_LOCAL_MAC
                why.append("임의 생성 MAC(로컬 관리 비트) — 핫스팟·소프트웨어 AP에서 흔함")
            if strongest is not None and ap["signal"] - strongest >= SIGNAL_GAP:
                risk += W_SIGNAL
                why.append(f"신뢰 AP보다 신호가 {ap['signal'] - strongest}%p 강함")
            if risk >= alert_at:
                alerts.append({"type": "evil_twin", "ssid": ssid, "bssid": ap["bssid"],
                               "auth": ap.get("auth"), "signal": ap["signal"],
                               "risk": min(risk, 100), "reasons": why})
    return alerts


def check_gateway(ssid, gateway_mac, trust_gw):
    """접속 후 확인: 이 SSID에서 예전에 본 공유기 MAC과 지금 공유기 MAC이 다르면 경고.
    스캔 정보가 진짜와 똑같은 가짜 AP도, 공격자 기기가 공유기 역할을 하면 여기서 드러난다."""
    expected = trust_gw.get(ssid)
    if not expected or not gateway_mac or gateway_mac == expected:
        return None
    return {"type": "evil_twin_gateway", "ssid": ssid, "bssid": "", "auth": "", "signal": 0, "risk": 80,
            "reasons": [f"이 와이파이의 공유기 MAC이 예전({expected})과 다름 ({gateway_mac})"]}


def current_connection():
    """지금 연결된 AP {ssid, bssid, auth}. 연결이 없으면 None."""
    out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    info = {}
    for raw in out.splitlines():
        m = LINE.match(raw)
        if not m:
            continue
        k, v = m["k"], m["v"].strip()
        if k == "SSID":
            info["ssid"] = v
        elif k in ("BSSID", "AP BSSID"):
            info["bssid"] = v.lower()
        elif re.fullmatch(KEYS["auth"], k):
            info["auth"] = v
    return info if "ssid" in info else None


def current_gateway():
    """기본 경로의 공유기 (IP, MAC). Windows의 라우팅 표와 ARP 표(이웃 표)를 읽기만 한다."""
    ps = ("$r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | "
          "Sort-Object RouteMetric | Select-Object -First 1; "
          "if ($r) { $n = Get-NetNeighbor -IPAddress $r.NextHop -InterfaceIndex $r.ifIndex "
          "-ErrorAction SilentlyContinue; "
          "@{ip = $r.NextHop; mac = $n.LinkLayerAddress; iface = $r.InterfaceAlias} | ConvertTo-Json }")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    if not out.strip():
        return None
    info = json.loads(out)
    mac = (info.get("mac") or "").replace("-", ":").lower() or None
    return {"ip": info.get("ip"), "mac": mac, "iface": info.get("iface")}