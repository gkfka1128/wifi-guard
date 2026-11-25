"""탐지 모듈 → 백엔드 공통 이벤트 형식.

모든 모듈의 결과를 같은 모양의 dict로 바꿔 백엔드(저장·실시간 전달·대시보드)가 모듈을 몰라도 되게 한다.

  {
    "module":    "arp" | "ap" | "dns" | "system",
    "level":     "normal" | "unknown" | "caution" | "warning",   정상 / 확인 불가 / 주의 / 경고
    "title":     대시보드 한 줄 제목,
    "reason":    사용자에게 보여 줄 설명 (쉬운 말),
    "evidence":  판단 근거 (점수, 규칙, MAC 등 — 나중에 왜 그렇게 판단했는지 확인용),
    "advice":    권장 대응 (보여 주기만 한다, 실행은 사용자가),
    "timestamp": ISO 8601 (+09:00)
  }
"""
from datetime import datetime

LEVELS = ("normal", "unknown", "caution", "warning")
LEVEL_KO = {"normal": "정상", "unknown": "확인 불가", "caution": "주의", "warning": "경고"}
_FROM_KO = {"주의": "caution", "경고": "warning"}


LOCAL_TZ = datetime.now().astimezone().tzinfo     # 고정 시간대 (Windows는 오래된 시각의 시간대 변환에 실패한다)


def now_iso(epoch=None):
    t = datetime.fromtimestamp(epoch, LOCAL_TZ) if epoch else datetime.now(LOCAL_TZ)
    return t.isoformat(timespec="seconds")


def make(module, level, title, reason, evidence=None, advice=None, epoch=None):
    if level not in LEVELS:
        raise ValueError(f"알 수 없는 단계: {level}")
    return {"module": module, "level": level, "title": title, "reason": reason,
            "evidence": evidence or {}, "advice": advice or [], "timestamp": now_iso(epoch)}


def from_arp(alert, advice=None):
    who = alert.get("suspect") or "확인 필요"
    return make("arp", _FROM_KO[alert["level"]], "인터넷 해킹 의심",
                " / ".join(alert["reasons"]),
                {"target_mac": alert["mac"], "suspect": who, "score": alert["risk"],
                 "claimed_ips": alert["claimed_ips"], "real_macs": alert["real_macs"],
                 "frames": [alert["first_frame"], alert["last_frame"]]},
                advice, epoch=alert.get("time"))


def from_ap(alert, caution_at, warning_at):
    gw = alert["type"] == "evil_twin_gateway"
    level = "warning" if gw or alert["risk"] >= warning_at else "caution"
    if not gw and alert["risk"] < caution_at:
        raise ValueError("임계값 미만 AP는 이벤트가 아니다")
    title = "접속한 와이파이의 공유기가 예전과 다름" if gw else f"가짜 와이파이 의심: {alert['ssid']}"
    return make("ap", level, title, " / ".join(alert["reasons"]),
                {"ssid": alert["ssid"], "bssid": alert["bssid"], "auth": alert["auth"],
                 "signal": alert["signal"], "score": alert["risk"]},
                ["netsh wlan disconnect  (연결 끊기)"] if level == "warning" else [])


def from_dns(alert):
    return make("dns", alert["level"], f"가짜 사이트 유도 의심: {alert['qname']}",
                " / ".join(alert["reasons"]),
                {k: alert[k] for k in ("qname", "client", "server", "answers", "score", "rules")},
                ["다른 네트워크(휴대폰 데이터 등)에서 같은 주소로 접속해 비교해 보기"]
                if alert["level"] == "warning" else [], epoch=alert.get("time"))


def module_state(module, level, reason):
    """모듈 자체의 상태 변화 (예: 패킷 수집 실패 → 확인 불가)."""
    return make("system", level, f"{module.upper()} 모듈 {LEVEL_KO[level]}", reason, {"module": module})
