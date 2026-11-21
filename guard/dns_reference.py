"""D3 기준 조회 — 의심스러운 질문 하나를 '다른 경로의 DNS 서버'에 다시 물어 답을 비교한다.

  - 기본은 꺼져 있다 (run_server.py --dns-reference 1.1.1.1 로 켠다).
  - dns_watch는 D1·D2가 이미 나온 질문에만 이 함수를 부른다. 평소 질문을 바깥으로 다시 보내지 않는다.
  - 일반 DNS A 레코드 조회 하나(UDP 53)일 뿐이다. 표준 라이브러리만 쓴다.
  - 한계: 같은 와이파이에서 중간자 공격이 이미 진행 중이면 이 조회도 같은 경로를 지나므로
    기준 조회 역시 오염될 수 있다. 그래서 D3는 보조 근거(20점)이고 단독으로 경보를 만들지 않는다.
"""
import random
import socket
import struct
import time

TIMEOUT = 1.0
CACHE_TTL = 300


def build_query(qname, txid):
    labels = b"".join(bytes([len(p)]) + p.encode("idna") for p in qname.rstrip(".").split(".") if p)
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)


def _skip_name(buf, i):
    while True:
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:          # 압축 포인터
            return i + 2
        i += n + 1


def parse_answers(buf, txid):
    """응답에서 A 레코드 IP만 꺼낸다. ID가 다르거나 형식이 깨졌으면 None."""
    if len(buf) < 12:
        return None
    rid, flags, qd, an = struct.unpack(">HHHH", buf[:8])
    if rid != txid or not flags & 0x8000:
        return None
    i = 12
    for _ in range(qd):
        i = _skip_name(buf, i) + 4
    ips = set()
    for _ in range(an):
        i = _skip_name(buf, i)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.add(socket.inet_ntoa(buf[i:i + 4]))
        i += rdlen
    return ips


class Reference:
    def __init__(self, server, timeout=TIMEOUT):
        self.server = server
        self.timeout = timeout
        self.cache = {}     # qname -> (시각, ip 집합 또는 None)

    def __call__(self, qname):
        hit = self.cache.get(qname)
        if hit and time.time() - hit[0] < CACHE_TTL:
            return hit[1]
        ips = self._ask(qname)
        self.cache[qname] = (time.time(), ips)
        return ips

    def _ask(self, qname):
        txid = random.randrange(1 << 16)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(build_query(qname, txid), (self.server, 53))
                buf, src = s.recvfrom(2048)
            if src[0] != self.server:
                return None
            return parse_answers(buf, txid) or None
        except (OSError, ValueError, struct.error, IndexError):
            # ValueError: 도메인 이름이 규격에 안 맞음 (이름은 패킷에서 온 값이라 믿을 수 없다)
            return None          # 실패하면 D3를 판단하지 않는다
