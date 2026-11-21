"""Scapy 패킷 수집 — ARP와 DNS(UDP 53)만 읽어서 탐지 모듈이 쓰는 dict로 바꾼다.

읽기만 하고 패킷을 보내지 않는다. 실시간 수집은 Windows에서 Npcap과 관리자 권한이 필요하고,
저장된 pcap 재생은 Npcap 없이도 된다. dict 모양은 arp_watch.read_packets(tshark)와 같다.
"""
FILTER = "arp or udp port 53"


def _scapy():
    # scapy는 처음 불러올 때 느리고 경고를 출력하므로 실제로 쓸 때만 불러온다
    from scapy.all import ARP, DNS, DNSRR, IP, UDP, Ether, IPv6
    return ARP, DNS, DNSRR, IP, UDP, Ether, IPv6


def to_arp(pkt, frame):
    ARP, _, _, _, _, Ether, _ = _scapy()
    a = pkt[ARP]
    return {"frame": frame, "time": float(pkt.time), "eth_dst": pkt[Ether].dst.lower() if Ether in pkt else "",
            "op": int(a.op), "mac": a.hwsrc.lower(), "src_ip": a.psrc, "dst_ip": a.pdst}


def _answers(dns, DNSRR):
    rr = dns.an
    items = list(rr) if isinstance(rr, list) else []
    if not items:                       # 옛 scapy는 응답 레코드를 payload로 이어 붙인다
        while rr is not None and isinstance(rr, DNSRR):
            items.append(rr)
            rr = rr.payload if isinstance(rr.payload, DNSRR) else None
    out = []
    for r in items:
        if r.type in (1, 28):           # A, AAAA
            v = r.rdata
            out.append(v.decode() if isinstance(v, bytes) else str(v))
    return out


def to_dns(pkt, frame):
    _, DNS, DNSRR, IP, UDP, _, IPv6 = _scapy()
    d, u = pkt[DNS], pkt[UDP]
    ip = pkt[IP] if IP in pkt else pkt[IPv6]
    qname = d.qd.qname if d.qd else b""
    if isinstance(qname, bytes):
        qname = qname.decode(errors="replace")
    return {"frame": frame, "time": float(pkt.time), "src": ip.src, "dst": ip.dst,
            "sport": int(u.sport), "dport": int(u.dport), "id": int(d.id), "qr": int(d.qr),
            "qname": qname.rstrip(".").lower(), "answers": _answers(d, DNSRR) if d.qr else []}


def convert(pkt, frame):
    """패킷 하나 → ("arp" | "dns", dict) 또는 None."""
    ARP, DNS, _, _, UDP, _, _ = _scapy()
    if ARP in pkt:
        return "arp", to_arp(pkt, frame)
    if DNS in pkt and UDP in pkt and pkt[DNS].qd:
        return "dns", to_dns(pkt, frame)
    return None


def read_pcap(path):
    _scapy()        # 계층(Ether 등)을 먼저 등록해야 한다 — 안 그러면 PcapReader가 모든 패킷을 Raw로 읽는다
    from scapy.utils import PcapReader
    with PcapReader(str(path)) as r:
        for i, pkt in enumerate(r, 1):
            try:
                item = convert(pkt, i)
            except Exception:       # noqa: BLE001 — 깨진 패킷 하나 때문에 재생 전체가 멈추면 안 된다
                continue
            if item:
                yield item


def sniff_live(iface, on_item, stop_event, on_error=None):
    """실시간 수집. 수집 자체가 안 되면 예외를 그대로 올려 호출한 쪽이 '확인 불가'로 처리하게 한다.
    패킷 하나를 처리하다 난 오류는 on_error로 알리고 계속 수집한다 — 같은 망의 누군가가
    이상한 패킷 하나를 보내 탐지를 멈추게 할 수 없어야 한다."""
    from scapy.all import sniff
    count = [0]

    def handle(pkt):
        count[0] += 1
        try:
            item = convert(pkt, count[0])
            if item:
                on_item(*item)
        except Exception as e:      # noqa: BLE001
            if on_error:
                on_error(e)

    while not stop_event.is_set():
        sniff(iface=iface, filter=FILTER, prn=handle, store=False, timeout=2)
