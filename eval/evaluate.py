"""시나리오 재생 평가: 탐지율(95% 신뢰구간), 오탐, 탐지 시간, 임계값별 결과.

ARP는 세 관측 지점에서 따로 평가한다.
  전체     망의 모든 ARP를 본다고 가정 (스위치 미러링 포트 같은 이상적인 경우, 참고용)
  피해자   공격받는 노트북에서 실행. 자기 앞 유니캐스트 + 브로드캐스트 + 자기가 보낸 것만 보인다
  다른 사용자  공격 대상이 아닌 노트북에서 실행
와이파이 카드는 목적지 MAC이 자기 것이거나 브로드캐스트인 프레임만 위로 올리므로(5장 MAC 필터링),
실제 사용 환경은 '피해자' 지점이다.

  py eval/evaluate.py      → 화면 출력, eval/eval_result.json, out/results.json 의 evaluation
"""
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from guard import ap_watch, arp_watch, report  # noqa: E402
from make_scenarios import DURATION, GW_IP  # noqa: E402

SC = Path(__file__).parent / "scenarios"
BCAST = "ff:ff:ff:ff:ff:ff"
THRESHOLDS = list(range(20, 101, 10))
VIEWS = {"all": "전체 관측", "victim": "피해자 노트북", "bystander": "다른 사용자 노트북"}


def wilson(k, n, z=1.96):
    """이항 비율의 95% 신뢰구간 (표본이 작을 때도 쓸 수 있는 Wilson 방식)."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    mid = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(mid - half, 0.0), min(mid + half, 1.0)


def seen_by(packets, me):
    if me is None:
        return packets
    return [p for p in packets if p["eth_dst"] in (me, BCAST) or p["mac"] == me]


def replay(packets, weights=None):
    det = arp_watch.ArpDetector(gateway_ip=GW_IP, weights=weights)
    for p in packets:
        det.feed(p)
    return det


def crossings(history, after=None):
    """임계값마다 처음 넘은 (시각, mac). after가 있으면 그 시각 이후만 본다."""
    out = {}
    for t, mac, risk in history:
        if after is not None and t < after - 1e-6:
            continue
        for th in THRESHOLDS:
            if risk >= th and th not in out:
                out[th] = (t, mac)
    return out


def eval_arp(cases, weights=None, th0=arp_watch.ALERT_AT, views=VIEWS):
    res = {}
    for view in views:
        per = defaultdict(lambda: {"runs": 0, "hit": defaultdict(int), "right": 0, "unsure": 0,
                                   "delays": [], "caution": []})
        normal = {"normal": defaultdict(int), "gateway_replaced": defaultdict(int)}
        n_normal = defaultdict(int)
        for t, packets in cases:
            if t["variant"] in normal:
                me = None if view == "all" else t["observer"]
                cx = crossings(replay(seen_by(packets, me), weights).history)
                n_normal[t["variant"]] += 1
                for th in cx:
                    normal[t["variant"]][th] += 1
                continue
            me = {"all": None, "victim": t["victim"], "bystander": t["bystander"]}[view]
            det = replay(seen_by(packets, me), weights)
            cx = crossings(det.history, after=t["start"])
            s = per[t["variant"]]
            s["runs"] += 1
            for th, (when, mac) in cx.items():
                s["hit"][th] += 1
                if th == th0:
                    s["delays"].append(max(when - t["start"], 0.0))
                    suspects = {a["suspect"] for a in det.alerts.values()}
                    s["right"] += t["attacker"] in suspects
                    s["unsure"] += suspects == {None}
                if th == arp_watch.CAUTION_AT:
                    s["caution"].append(max(when - t["start"], 0.0))
        runs = sum(s["runs"] for s in per.values())
        hits = {th: sum(s["hit"][th] for s in per.values()) for th in THRESHOLDS}
        delays = [d for s in per.values() for d in s["delays"]]
        cautions = [d for s in per.values() for d in s["caution"]]
        k = hits[th0]
        res[view] = {
            "view": VIEWS[view], "runs": runs, "hit": k, "detection_rate": k / runs, "ci95": wilson(k, runs),
            "false_alarms": normal["normal"][th0], "normal_runs": n_normal["normal"],
            "normal_hours": n_normal["normal"] * DURATION / 3600,
            "replaced_alarms": normal["gateway_replaced"][th0], "replaced_runs": n_normal["gateway_replaced"],
            "mean_delay_s": sum(delays) / len(delays) if delays else None,
            "max_delay_s": max(delays) if delays else None,
            "caution_rate": hits[arp_watch.CAUTION_AT] / runs,
            "caution_mean_delay_s": sum(cautions) / len(cautions) if cautions else None,
            "caution_false": normal["normal"][arp_watch.CAUTION_AT],
            "caution_replaced": normal["gateway_replaced"][arp_watch.CAUTION_AT],
            "sweep": {th: {"detection_rate": hits[th] / runs,
                           "false_alarms": normal["normal"][th],
                           "replaced_alarms": normal["gateway_replaced"][th]} for th in THRESHOLDS},
            "by_variant": {v: {"runs": s["runs"], "hit": s["hit"][th0], "right_mac": s["right"], "unsure": s["unsure"],
                               "mean_delay_s": round(sum(s["delays"]) / len(s["delays"]), 2) if s["delays"] else None,
                               "max_delay_s": round(max(s["delays"]), 2) if s["delays"] else None}
                           for v, s in per.items()},
        }
    return res


def eval_ap(truth):
    res = {}
    for use_trust in (False, True):
        per = defaultdict(lambda: {"runs": 0, "scan_hit": 0, "exposed": 0, "after_connect": 0})
        fa = defaultdict(int)
        n_normal = 0
        sweep_hit = defaultdict(int)
        for t in truth:
            aps = ap_watch.parse_networks((SC / t["file"]).read_text(encoding="utf-8"))
            trust_ap = t.get("trust_ap", {}) if use_trust else {}
            if t["variant"] == "normal":
                n_normal += 1
                for th in THRESHOLDS:
                    fa[th] += bool(ap_watch.detect(aps, trust_ap, alert_at=th))
                continue
            for th in THRESHOLDS:
                sweep_hit[th] += any(a["bssid"] == t["twin"] for a in ap_watch.detect(aps, trust_ap, alert_at=th))
            flagged = {a["bssid"] for a in ap_watch.detect(aps, trust_ap)}
            s = per[t["variant"]]
            s["runs"] += 1
            s["scan_hit"] += t["twin"] in flagged
            # 사용자가 경고받지 않은 AP 중 신호가 가장 강한 것에 접속한다고 가정
            cands = [a for a in aps if a["ssid"] == "Cafe_Free_WiFi" and a["bssid"] not in flagged]
            joined = max(cands, key=lambda a: a["signal"])["bssid"] if cands else None
            if joined == t["twin"]:
                trust_gw = t["trust_gw"] if use_trust else {}
                if ap_watch.check_gateway("Cafe_Free_WiFi", t["gateway"][joined], trust_gw):
                    s["after_connect"] += 1
                else:
                    s["exposed"] += 1
        runs = sum(s["runs"] for s in per.values())
        k = sum(s["scan_hit"] for s in per.values())
        exposed = sum(s["exposed"] for s in per.values())
        key = "trust" if use_trust else "no_trust"
        res[key] = {"view": "신뢰 목록 있음" if use_trust else "신뢰 목록 없음",
                    "runs": runs, "hit": k, "detection_rate": k / runs, "ci95": wilson(k, runs),
                    "false_alarms": fa[ap_watch.ALERT_AT], "normal_runs": n_normal,
                    "exposed": exposed, "protected_rate": 1 - exposed / runs,
                    "protected_ci95": wilson(runs - exposed, runs),
                    "sweep": {th: {"detection_rate": sweep_hit[th] / runs, "false_alarms": fa[th]} for th in THRESHOLDS},
                    "by_variant": dict(per)}
    return res


def pct(x):
    return f"{x:.0%}"


def main():
    truth = json.loads((SC / "truth.json").read_text(encoding="utf-8"))
    cases = [(t, list(arp_watch.read_packets(pcap=str(SC / t["file"])))) for t in truth["arp"]]
    arp = eval_arp(cases)
    v1 = eval_arp(cases, arp_watch.WEIGHTS_V1, th0=50, views={"victim": VIEWS["victim"]})["victim"]
    ap = eval_ap(truth["ap"])
    (Path(__file__).parent / "eval_result.json").write_text(
        json.dumps({"seed": truth["seed"], "arp": arp, "arp_v1_victim": v1, "ap": ap},
                   ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"[ARP 스푸핑]  공격 {arp['all']['runs']}개 · 정상 {arp['all']['normal_runs']}개"
          f"({arp['all']['normal_hours']:.1f}시간) · 공유기 교체 {arp['all']['replaced_runs']}개, 임계값 {arp_watch.ALERT_AT}")
    for r in arp.values():
        lo, hi = r["ci95"]
        print(f"  {r['view']:10s} 탐지율 {pct(r['detection_rate'])} (95% CI {pct(lo)}~{pct(hi)})  "
              f"오탐 {r['false_alarms']}/{r['normal_runs']}  공유기 교체 경고 {r['replaced_alarms']}/{r['replaced_runs']}  "
              f"평균 {r['mean_delay_s'] or 0:.2f}초 최대 {r['max_delay_s'] or 0:.2f}초")
        print(f"  {'':10s} 주의 단계: 탐지율 {pct(r['caution_rate'])}, 평균 {r['caution_mean_delay_s'] or 0:.2f}초, "
              f"정상 {r['caution_false']}/{r['normal_runs']}, 공유기 교체 {r['caution_replaced']}/{r['replaced_runs']}")
        for v, s in r["by_variant"].items():
            print(f"      {v:15s} {s['hit']:2d}/{s['runs']}  공격자 지목 {s['right_mac']:2d} 확인 필요 {s['unsure']:2d}  평균 {s['mean_delay_s']}초 최대 {s['max_delay_s']}초")
    lo, hi = v1["ci95"]
    print(f"  (비교) 1차 규칙, 피해자 노트북: 탐지율 {pct(v1['detection_rate'])} (95% CI {pct(lo)}~{pct(hi)})  "
          f"오탐 {v1['false_alarms']}/{v1['normal_runs']}  공유기 교체 경고 {v1['replaced_alarms']}/{v1['replaced_runs']}  "
          f"평균 {v1['mean_delay_s'] or 0:.2f}초")
    print("\n[가짜 AP]")
    for r in ap.values():
        lo, hi = r["ci95"]
        print(f"  {r['view']}  스캔 탐지 {pct(r['detection_rate'])} (95% CI {pct(lo)}~{pct(hi)})  오탐 {r['false_alarms']}/{r['normal_runs']}"
              f"  → 접속 후 확인까지 포함한 보호율 {pct(r['protected_rate'])} (가짜 AP에 남은 경우 {r['exposed']}/{r['runs']})")
        for v, s in r["by_variant"].items():
            print(f"      {v:17s} {s}")

    v = arp["victim"]
    rows = [{"threat": "ARP 스푸핑 (피해자 노트북)", "runs": v["runs"], "detection_rate": v["detection_rate"],
             "false_alarms": v["false_alarms"], "normal_runs": v["normal_runs"], "mean_delay_s": v["mean_delay_s"]}]
    for r in ap.values():
        rows.append({"threat": f"가짜 AP ({r['view']}, 접속 후 확인 포함 보호율)", "runs": r["runs"],
                     "detection_rate": r["protected_rate"], "false_alarms": r["false_alarms"],
                     "normal_runs": r["normal_runs"], "mean_delay_s": None})
    report.write_results(ROOT / "out", {"evaluation": rows})


if __name__ == "__main__":
    main()
