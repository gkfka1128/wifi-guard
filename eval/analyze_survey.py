"""F4  실태 조사 분석: 장소 유형별 보안 현황과, 탐지 기준값을 데이터로 정하기 위한 분포.

  py eval/analyze_survey.py data/survey.csv
    → data/survey_summary.json  (통계, 기준값 제안)
    → data/survey_public.csv    (공개용: BSSID 뒷자리 가림)
    → data/trust_survey.json    (여러 날 꾸준히 보인 AP로 만든 신뢰 목록, main.py ap --trust 로 사용)
"""
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guard import survey  # noqa: E402
from guard.ap_watch import is_open, local_admin  # noqa: E402


def percentile(xs, q):
    xs = sorted(xs)
    return xs[min(int(q * len(xs)), len(xs) - 1)] if xs else None


def analyze(rows):
    by_type = defaultdict(list)
    for r in rows:
        by_type[r["place_type"]].append(r)

    def stats(rs):
        aps = {r["bssid"]: r for r in rs}.values()          # 같은 AP를 여러 번 쟀으면 한 번만
        n = len(aps)
        return {"places": len({r["place_id"] for r in rs}), "aps": n,
                "open_ratio": round(sum(is_open(a) for a in aps) / n, 3) if n else None,
                "local_mac_ratio": round(sum(local_admin(a["bssid"]) for a in aps) / n, 3) if n else None,
                "auth": dict(Counter(a["auth"] for a in aps).most_common())}

    # 같은 장소 · 같은 시각의 스캔 하나 안에서 이름이 같은 AP 묶음
    groups = defaultdict(list)
    for r in rows:
        if r["ssid"]:
            groups[(r["place_id"], r["time"], r["ssid"])].append(r)
    sizes = [len(g) for g in groups.values()]
    gaps = [sorted((a["signal"] for a in g), reverse=True)[0] - sorted((a["signal"] for a in g), reverse=True)[1]
            for g in groups.values() if len(g) >= 2]
    mixed = sorted({(k[0], k[2]) for k, g in groups.items()
                    if len(g) >= 2 and any(is_open(a) for a in g) and not all(is_open(a) for a in g)})
    return {
        "total": stats(rows),
        "by_place_type": {t: stats(rs) for t, rs in by_type.items()},
        "same_name_group_sizes": dict(sorted(Counter(sizes).items())),
        "mixed_security_names": len(mixed),
        # 정상 환경에서 같은 이름 AP끼리 신호 차이의 95번째 백분위수. 탐지 기준 A4(SIGNAL_GAP)의 근거로 쓴다
        "signal_gap_p95": percentile(gaps, 0.95),
        "note": "mixed_security_names: 같은 이름 안에 개방형과 암호 AP가 섞인 경우 (가짜 AP 또는 게스트망 확인 필요)",
    }


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "data/survey.csv")
    rows = survey.load(src)
    result = analyze(rows)
    out = src.parent
    (out / "survey_summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    with open(out / "survey_public.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, survey.COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({**r, "bssid": survey.mask(r["bssid"])})
    (out / "trust_survey.json").write_text(
        json.dumps({"ap": survey.trust_from_survey(rows)}, ensure_ascii=False, indent=2), encoding="utf-8")
    t = result["total"]
    print(f"장소 {t['places']}곳, AP {t['aps']}개, 개방형 {t['open_ratio']:.0%}, 임의 MAC {t['local_mac_ratio']:.0%}")
    for name, s in result["by_place_type"].items():
        print(f"  {name:6s} 장소 {s['places']}곳  AP {s['aps']}개  개방형 {s['open_ratio']:.0%}")
    print(f"같은 이름 AP 묶음 크기 분포 {result['same_name_group_sizes']}, 신호 차이 95% {result['signal_gap_p95']}%p, "
          f"보안 방식이 섞인 이름 {result['mixed_security_names']}개")
    print(f"→ {out / 'survey_summary.json'}, {out / 'survey_public.csv'}, {out / 'trust_survey.json'}")


if __name__ == "__main__":
    main()
