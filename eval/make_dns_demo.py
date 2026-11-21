"""DNS 데모 pcap 만들기 → eval/demo/dns_race.pcap   (.venv\\Scripts\\python eval/make_dns_demo.py)

메모리에서 패킷을 만들어 파일에만 쓴다. 네트워크로 보내지 않는다.
ARP 데모(victim_view.pcap)와 같은 실험망(192.168.0.0/24, 공유기 = DNS 서버 192.168.0.1)을 가정하고,
피해자 노트북에서 본 장면만 담는다.

  1. 평소 조회 몇 개 — 질문 하나에 공유기가 답 하나 (경보 없어야 함)
  2. 같은 질문을 다시 보냄(재전송) — 공유기가 같은 답을 두 번 (경보 없어야 함)
  3. 경쟁 응답 — 질문 하나에 같은 망의 다른 기기가 먼저 다른 답을 보내고, 뒤이어 공유기의 진짜 답이 옴
     → D2(질문하지 않은 곳의 응답) + D1(다른 답 두 번) = 70점 '경고'
도메인은 예약된 example 이름, 주소는 문서용 대역(203.0.113.0/24, 198.51.100.0/24)만 쓴다.
"""
import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether, wrpcap

ROOT = Path(__file__).resolve().parent
VICTIM_IP, VICTIM_MAC = "192.168.0.34", "aa:aa:aa:00:00:34"
GW_IP, GW_MAC = "192.168.0.1", "00:26:66:4d:ca:18"            # victim_view.pcap 의 진짜 공유기
OTHER_IP, OTHER_MAC = "192.168.0.66", "88:36:6c:6a:c0:4c"     # victim_view.pcap 의 의심 MAC
T0 = 1793000130.0                                              # ARP 데모가 끝난 뒤


def query(t, txid, name, sport):
    p = (Ether(src=VICTIM_MAC, dst=GW_MAC) / IP(src=VICTIM_IP, dst=GW_IP) /
         UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name)))
    p.time = t
    return p


def answer(t, txid, name, sport, ip, src_ip=GW_IP, src_mac=GW_MAC):
    p = (Ether(src=src_mac, dst=VICTIM_MAC) / IP(src=src_ip, dst=VICTIM_IP) /
         UDP(sport=53, dport=sport) /
         DNS(id=txid, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=300, rdata=ip)))
    p.time = t
    return p


def build():
    pk, t = [], T0
    normal = [("www.school.example", "203.0.113.10"), ("mail.school.example", "203.0.113.11"),
              ("news.example", "203.0.113.20"), ("cdn.example", "203.0.113.30")]
    for i, (name, ip) in enumerate(normal):
        txid, sport = 0x1000 + i, 50000 + i
        pk += [query(t, txid, name, sport), answer(t + 0.018, txid, name, sport, ip)]
        t += 1.5
    # 재전송: 같은 질문 두 번, 같은 답 두 번
    pk += [query(t, 0x2000, "portal.example", 50100), query(t + 1.0, 0x2000, "portal.example", 50100),
           answer(t + 1.02, 0x2000, "portal.example", 50100, "203.0.113.40"),
           answer(t + 1.05, 0x2000, "portal.example", 50100, "203.0.113.40")]
    t += 3
    # 경쟁 응답: 다른 기기의 답이 먼저, 진짜 답이 뒤에
    name, txid, sport = "bank.example", 0x3000, 50200
    pk += [query(t, txid, name, sport),
           answer(t + 0.004, txid, name, sport, "198.51.100.66", src_ip=OTHER_IP, src_mac=OTHER_MAC),
           answer(t + 0.021, txid, name, sport, "203.0.113.50")]
    return pk


def main(out=ROOT / "demo" / "dns_race.pcap"):
    pk = build()
    wrpcap(str(out), pk)
    print(f"{out} ({len(pk)}개 패킷)")


if __name__ == "__main__":
    main(*sys.argv[1:])
