"""DNS 모듈 합성 평가   (.venv\\Scripts\\python eval/dns_eval.py [시드])

capture.to_dns()가 만드는 것과 같은 dict를 메모리에서 만들어 DnsDetector에 넣는다.
패킷을 만들거나 보내지 않는다. 결과 → eval/dns_eval_result.json

세션 하나 = 노트북 한 대가 몇 분 동안 30–60개 도메인을 조회한 기록 (DNS 서버 2개, 첫 서버가 가끔 늦음).
위협 세션은 정상 세션 중간에 의심 응답 한 번을 끼워 넣는다. 위협은 판단 근거의 모양만 흉내 낸다.

정상
  basic        질문 하나에 답 하나, 같은 도메인도 질문마다 CDN 주소가 바뀜
  fallback     첫 서버가 늦어 같은 질문을 두 번째 서버에 다시 보냄 → 두 서버가 서로 다른 CDN 주소로 답함
  retransmit   같은 질문 재전송 → 같은 서버가 같은 답을 두 번
  rr_retrans   재전송에 같은 서버가 라운드로빈으로 '다른' 답을 줌 (드물지만 정상, 세션마다 한 번)
위협
  race_lan     같은 망의 다른 기기가 먼저 다른 답, 뒤에 진짜 답            (근거 D2+D1)
  race_spoof   DNS 서버 주소로 위장한 답이 먼저, 뒤에 진짜 답              (근거 D1)
  only_lan     같은 망 다른 기기의 답만 오고 진짜 답은 안 보임            (근거 D2)
  mitm_only    서버 주소로 위장한 답만 오고 진짜 답은 안 보임 (중간자)    (근거 없음, D3는 D1·D2가 있어야 조회)
"""
import json
import random
import zlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guard.dns_watch import DnsDetector  # noqa: E402

ROOT = Path(__file__).resolve().parent
ME, DNS1, DNS2, LAN = "192.168.0.34", "192.168.0.1", "168.126.63.1", "192.168.0.66"
N = 100                 # 정상 세션 수 (종류별)
N_ATTACK = 20           # 위협 세션 수 (종류별)


def cdn_ip(rng, name):
    """도메인마다 정해진 주소 묶음에서 1–2개를 고른다 (CDN·라운드로빈)."""
    pool = [f"203.0.{zlib.crc32(name.encode()) % 200}.{i}" for i in range(1, 9)]
    return sorted(rng.sample(pool, rng.choice((1, 2))))


class Session:
    def __init__(self, rng):
        self.rng, self.t, self.items, self.truth = rng, 1_800_000_000.0, [], {}
        self.txid = rng.randrange(1 << 16)

    def q(self, name, sport, txid, server):
        self.items.append({"time": self.t, "src": ME, "dst": server, "sport": sport, "dport": 53, "id": txid,
                           "qr": 0, "qname": name, "answers": []})

    def r(self, name, sport, txid, src, answers, dt):
        self.items.append({"time": self.t + dt, "src": src, "dst": ME, "sport": 53, "dport": sport, "id": txid,
                           "qr": 1, "qname": name, "answers": answers})

    def lookup(self, kind="basic"):
        rng = self.rng
        name = f"site{rng.randrange(40)}.example"
        sport, self.txid = rng.randrange(49152, 65535), (self.txid + rng.randrange(1, 999)) % 65536
        ans = cdn_ip(rng, name)
        self.truth[name] = set(f"203.0.{zlib.crc32(name.encode()) % 200}.{i}" for i in range(1, 9))
        self.q(name, sport, self.txid, DNS1)
        if kind == "basic":
            self.r(name, sport, self.txid, DNS1, ans, rng.uniform(.005, .08))
        elif kind == "fallback":
            self.t += 1.0
            self.q(name, sport, self.txid, DNS2)
            self.r(name, sport, self.txid, DNS2, cdn_ip(rng, name), rng.uniform(.01, .05))
            self.r(name, sport, self.txid, DNS1, ans, rng.uniform(.06, .3))
        elif kind == "retransmit":
            self.t += 1.0
            self.q(name, sport, self.txid, DNS1)
            self.r(name, sport, self.txid, DNS1, ans, .02)
            self.r(name, sport, self.txid, DNS1, ans, .03)
        elif kind == "rr_retrans":
            self.t += 1.0
            self.q(name, sport, self.txid, DNS1)
            other = ans
            while other == ans:
                other = cdn_ip(rng, name)
            self.r(name, sport, self.txid, DNS1, ans, .02)
            self.r(name, sport, self.txid, DNS1, other, .03)
        self.t += rng.uniform(.5, 6)

    def attack(self, kind):
        rng = self.rng
        name, sport = "bank.example", rng.randrange(49152, 65535)
        self.txid = (self.txid + 7) % 65536
        real, fake = ["203.0.113.50"], ["198.51.100.66"]
        self.truth[name] = set(real)
        self.q(name, sport, self.txid, DNS1)
        if kind in ("race_lan", "only_lan"):
            self.r(name, sport, self.txid, LAN, fake, rng.uniform(.001, .006))
        else:
            self.r(name, sport, self.txid, DNS1, fake, rng.uniform(.001, .006))
        if kind in ("race_lan", "race_spoof"):
            self.r(name, sport, self.txid, DNS1, real, rng.uniform(.01, .08))
        self.t += rng.uniform(.5, 6)


def run(items, reference):
    d = DnsDetector(reference=reference)
    worst = None
    for p in sorted(items, key=lambda x: x["time"]):
        a = d.feed(p)
        if a and (worst is None or a["level"] == "warning"):
            worst = a["level"]
    return worst


def session(rng, normal_kind, attack=None):
    s = Session(rng)
    n = rng.randint(30, 60)
    at = rng.randrange(5, n - 5)
    for i in range(n):
        if attack and i == at:
            s.attack(attack)
        if normal_kind == "rr_retrans":         # 드문 일이므로 세션마다 한 번만
            s.lookup("rr_retrans" if i == at else "basic")
        else:
            s.lookup(normal_kind if rng.random() < 0.3 else "basic")
    return s


def reference_for(s, rng):
    """기준 조회 흉내: 진짜 주소 묶음 중 일부를 돌려준다 (CDN이라 사용자가 받은 답과 다를 수 있음)."""
    def ref(name):
        pool = sorted(s.truth.get(name, ()))
        return set(rng.sample(pool, min(2, len(pool)))) if pool else None
    return ref


def main(seed=7):
    rng = random.Random(int(seed))
    out = {"seed": int(seed), "normal": {}, "attack": {}}
    for kind in ("basic", "fallback", "retransmit", "rr_retrans"):
        res = {"no_ref": [], "ref": []}
        for _ in range(N):
            s = session(rng, kind)
            res["no_ref"].append(run(s.items, None))
            res["ref"].append(run(s.items, reference_for(s, rng)))
        out["normal"][kind] = {k: {"sessions": N, "caution_or_more": sum(v is not None for v in vs),
                                   "warning": sum(v == "warning" for v in vs)} for k, vs in res.items()}
    for kind in ("race_lan", "race_spoof", "only_lan", "mitm_only"):
        res = {"no_ref": [], "ref": []}
        for _ in range(N_ATTACK):
            s = session(rng, "basic", attack=kind)
            res["no_ref"].append(run(s.items, None))
            res["ref"].append(run(s.items, reference_for(s, rng)))
        out["attack"][kind] = {k: {"sessions": N_ATTACK, "caution_or_more": sum(v is not None for v in vs),
                                   "warning": sum(v == "warning" for v in vs)} for k, vs in res.items()}
    (ROOT / "dns_eval_result.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"DNS 합성 평가 (시드 {seed})  —  주의 이상 / 경고   [기준 조회 없음 | 있음]")
    for group, rows in (("정상", out["normal"]), ("위협", out["attack"])):
        for kind, r in rows.items():
            a, b = r["no_ref"], r["ref"]
            print(f"  {group} {kind:<11} {a['caution_or_more']:>3}/{a['warning']:<3} of {a['sessions']:<3} | "
                  f"{b['caution_or_more']:>3}/{b['warning']:<3}")
    return out


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main(*sys.argv[1:])
