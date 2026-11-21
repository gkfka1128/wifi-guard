"""F4  공공 와이파이 실태 조사.

AP가 공개적으로 알리는 정보(이름, BSSID, 보안 방식, 신호, 채널)만 기록한다.
장소는 실제 이름 대신 유형(카페, 도서관 ...)과 팀이 붙인 짧은 코드(C01 ...)로만 적는다.
"""
import csv
import time
from collections import defaultdict
from pathlib import Path

COLUMNS = ["time", "place_type", "place_id", "ssid", "bssid", "auth", "enc", "signal", "channel"]


def record(path, aps, place_type, place_id, when=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    when = when or time.strftime("%Y-%m-%d %H:%M")
    with open(path, "a", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, COLUMNS)
        if new:
            w.writeheader()
        for ap in aps:
            w.writerow({"time": when, "place_type": place_type, "place_id": place_id,
                        **{k: ap.get(k, "") for k in COLUMNS[3:]}})
    return len(aps)


def load(path):
    with open(path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["signal"] = int(r["signal"] or 0)
    return rows


def mask(bssid):
    """공개용: 뒤 3바이트를 가린다 (OUI는 제조사 분석에 필요해 남긴다)."""
    return bssid[:8] + ":xx:xx:xx"


def trust_from_survey(rows, min_visits=2):
    """같은 장소에서 서로 다른 날 min_visits번 이상 보인 BSSID를 그 이름의 신뢰 AP로 본다.
    가짜 AP는 잠깐 나타나므로 여러 날 꾸준히 보인 AP가 진짜일 가능성이 높다."""
    days = defaultdict(set)
    for r in rows:
        days[(r["ssid"], r["bssid"])].add(r["time"][:10])
    trust = defaultdict(list)
    for (ssid, bssid), d in days.items():
        if ssid and len(d) >= min_visits:
            trust[ssid].append(bssid)
    return dict(trust)
