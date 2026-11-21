"""F1  네트워크 안전 점수 (100점 만점)."""


def safety_score(conn, ap_alerts, arp_alerts):
    """conn: 지금 연결된 AP {ssid, bssid, auth} 또는 None.
    ap_alerts에는 스캔 경고와 접속 후 공유기 확인 경고(evil_twin_gateway)가 함께 들어온다.
    같은 이름 AP가 많은 것 자체는 감점하지 않는다 (학교·역처럼 AP 여러 대가 정상인 곳이 많다)."""
    score, why = 100, []
    if conn:
        auth = conn.get("auth", "").lower()
        if auth in ("open", "개방"):
            score -= 40
            why.append("암호가 없는 개방형 와이파이 (−40)")
        elif "wep" in auth:
            score -= 30
            why.append("오래된 WEP 암호화 (−30)")
        if any(a["type"] == "evil_twin_gateway" and a["ssid"] == conn.get("ssid") for a in ap_alerts):
            score -= 60
            why.append("공유기 MAC이 예전과 달라 가짜 AP에 접속했을 수 있음 (−60)")
        elif any(a["bssid"] == conn.get("bssid") for a in ap_alerts):
            score -= 50
            why.append("지금 연결된 AP가 가짜 AP로 의심됨 (−50)")
        elif any(a["ssid"] == conn.get("ssid") for a in ap_alerts):
            score -= 20
            why.append("같은 이름의 가짜 AP가 주변에 있음 (−20)")
    if arp_alerts:
        score -= 60
        why.append("ARP 스푸핑 경고가 있음 (−60)")
    score = max(score, 0)
    grade = "안전" if score >= 80 else "주의" if score >= 50 else "위험"
    return {"score": score, "grade": grade, "reasons": why}
