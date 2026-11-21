"""와이파이 지킴이 — 공공 와이파이 보안 위협 탐지·방어 (7조)

  py main.py arp --pcap 캡처.pcap --gateway 192.168.0.1   pcap 재생으로 ARP 스푸핑 탐지
  py main.py arp --iface Wi-Fi --gateway 192.168.0.1      실시간 탐지 (Npcap 필요)
  py main.py ap                                           주변 AP를 스캔해 가짜 AP 탐지
  py main.py ap --file scan.txt                           저장해 둔 netsh 출력으로 탐지
  py main.py learn                                        지금 연결된 AP와 공유기 MAC을 신뢰 목록에 추가
  py main.py check                                        접속 후 확인: 공유기 MAC이 신뢰 값과 같은지
  py main.py score                                        안전 점수 계산 후 대시보드 갱신
  py main.py survey --place-type 카페 --place-id C01      실태 조사: 주변 AP 공개 정보를 data/survey.csv에 추가

방어 명령은 기본으로 화면에 보여 주기만 한다. --defend 를 주면 실제로 실행한다
(정적 ARP 등록에는 관리자 권한이 필요하다).
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from guard import ap_watch, arp_watch, report, survey
from guard.score import safety_score

OUT = Path(__file__).parent / "out"


def load_json(path, default):
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default


def run_defense(cmds, really):
    for c in cmds:
        print(("  실행: " if really else "  (권장) ") + c)
        if really:
            subprocess.run(c, shell=True)


def show(alert):
    who = alert.get("suspect") or "확인 필요 (두 MAC 중 어느 쪽인지 근거 부족)"
    print(f"[{alert['level']}] ARP 스푸핑 의심  프레임 {alert['last_frame']}  점수 {alert['risk']}  공격자 추정 {who}")
    for r in alert["reasons"]:
        print("   -", r)


def cmd_arp(a):
    trust = load_json(a.trust, {}).get("arp", {})
    det = arp_watch.ArpDetector(gateway_ip=a.gateway, trusted=trust)
    for p in arp_watch.read_packets(pcap=a.pcap, iface=a.iface):
        alert = det.feed(p)
        if alert:
            show(alert)
    alerts = list(det.alerts.values())        # 경고 이후 들어온 근거까지 반영된 최종 상태
    for alert in alerts:
        print(f"최종 [{alert['level']}] 대상 {alert['mac']}  점수 {alert['risk']}  "
              f"공격자 추정 {alert.get('suspect') or '확인 필요'}")
        alert["defense"] = arp_watch.defense_commands(alert, a.iface or "Wi-Fi")
        run_defense(alert["defense"], a.defend)
        if a.pcap:
            ev = OUT / "evidence" / f"arp_{alert['mac'].replace(':', '')}_{alert['first_frame']}.pcap"
            ev.parent.mkdir(parents=True, exist_ok=True)
            alert["evidence"] = report.save_evidence(a.pcap, alert["first_frame"], alert["last_frame"], ev)
        report.log_event(OUT, alert)
    report.write_results(OUT, {"arp_alerts": alerts, "arp_source": a.pcap or a.iface})
    print(f"ARP 경고 {sum(x['level'] == '경고' for x in alerts)}건, 주의 {sum(x['level'] == '주의' for x in alerts)}건. "
          f"대시보드: {OUT / 'dashboard.html'}")


def cmd_ap(a):
    trust = load_json(a.trust, {}).get("ap", {})
    text = Path(a.file).read_text(encoding="utf-8") if a.file else ap_watch.scan_text()
    aps = ap_watch.parse_networks(text)
    alerts = ap_watch.detect(aps, trust)
    for al in alerts:
        print(f"[경고] 가짜 AP 의심  {al['ssid']}  {al['bssid']}  점수 {al['risk']}")
        for r in al["reasons"]:
            print("   -", r)
        report.log_event(OUT, al)
    conn = None if a.file else ap_watch.current_connection()
    if conn and any(al["bssid"] == conn.get("bssid") for al in alerts):
        run_defense(["netsh wlan disconnect"], a.defend)
    report.write_results(OUT, {"ap_scan_count": len(aps), "ap_alerts": alerts})
    print(f"AP {len(aps)}개 확인, 가짜 AP 경고 {len(alerts)}건. 대시보드: {OUT / 'dashboard.html'}")


def cmd_learn(a):
    """처음 안전하게 접속했을 때 한 번 실행: 이 와이파이의 BSSID와 공유기 MAC을 기억한다."""
    conn, gw = ap_watch.current_connection(), ap_watch.current_gateway()
    if not conn:
        sys.exit("연결된 와이파이가 없습니다.")
    t = load_json(a.trust, {})
    bssids = t.setdefault("ap", {}).setdefault(conn["ssid"], [])
    if conn.get("bssid") and conn["bssid"] not in bssids:
        bssids.append(conn["bssid"])
    if gw and gw["mac"]:
        t.setdefault("gw", {})[conn["ssid"]] = gw["mac"]
        t.setdefault("arp", {})[gw["ip"]] = gw["mac"]
    Path(a.trust).write_text(json.dumps(t, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"신뢰 목록에 추가: {conn['ssid']}  AP {conn.get('bssid')}  공유기 {gw and gw['mac']}")


def gateway_alert(trust_file):
    conn, gw = ap_watch.current_connection(), ap_watch.current_gateway()
    if not conn or not gw:
        return conn, None
    return conn, ap_watch.check_gateway(conn["ssid"], gw["mac"], load_json(trust_file, {}).get("gw", {}))


def cmd_check(a):
    conn, alert = gateway_alert(a.trust)
    if not conn:
        sys.exit("연결된 와이파이가 없습니다.")
    if alert:
        print(f"[경고] {alert['reasons'][0]}  → 가짜 AP에 접속했을 수 있습니다.")
        report.log_event(OUT, alert)
        run_defense(["netsh wlan disconnect"], a.defend)
    else:
        print(f"{conn['ssid']}: 공유기 MAC이 신뢰 값과 같거나, 아직 신뢰 값이 없습니다 (py main.py learn).")
    report.write_results(OUT, {"gateway_alerts": [alert] if alert else []})


def cmd_score(a):
    r = load_json(OUT / "results.json", {})
    conn, gw_alert = gateway_alert(a.trust)
    ap_alerts = r.get("ap_alerts", []) + ([gw_alert] if gw_alert else [])
    arp_alerts = [x for x in r.get("arp_alerts", []) if x.get("level") == "경고"]
    s = safety_score(conn, ap_alerts, arp_alerts)
    report.write_results(OUT, {"score": s, "connection": conn})
    print(f"안전 점수 {s['score']}점 ({s['grade']})")
    for x in s["reasons"]:
        print("   -", x)


def cmd_survey(a):
    text = Path(a.file).read_text(encoding="utf-8") if a.file else ap_watch.scan_text()
    n = survey.record(a.out, ap_watch.parse_networks(text), a.place_type, a.place_id)
    print(f"{a.place_type} {a.place_id}: AP {n}개 기록 → {a.out}")


def main():
    ap = argparse.ArgumentParser(description="와이파이 지킴이")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("arp", help="ARP 스푸핑 탐지")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap")
    src.add_argument("--iface")
    p.add_argument("--gateway", help="공유기 IP (예: 192.168.0.1)")
    p.set_defaults(func=cmd_arp)
    p = sub.add_parser("ap", help="가짜 AP 탐지")
    p.add_argument("--file")
    p.set_defaults(func=cmd_ap)
    p = sub.add_parser("learn", help="지금 연결된 와이파이를 신뢰 목록에 추가")
    p.set_defaults(func=cmd_learn)
    p = sub.add_parser("check", help="접속 후 공유기 MAC 확인")
    p.set_defaults(func=cmd_check)
    p = sub.add_parser("score", help="안전 점수")
    p.set_defaults(func=cmd_score)
    p = sub.add_parser("survey", help="실태 조사 기록")
    p.add_argument("--place-type", required=True, help="장소 유형 (카페, 도서관, 역 ...)")
    p.add_argument("--place-id", required=True, help="팀이 붙인 장소 코드 (C01 ...), 실제 상호는 적지 않는다")
    p.add_argument("--file")
    p.add_argument("--out", default="data/survey.csv")
    p.set_defaults(func=cmd_survey)
    for p in sub.choices.values():
        p.add_argument("--trust", default="trust.json")
        p.add_argument("--defend", action="store_true")
    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
