"""F6  DNS 스푸핑 의심 탐지.

내 노트북이 보낸 DNS 질문과 돌아온 응답을 짝지어 본다 (UDP 53번 포트만, DoH는 보이지 않는다).
  D1  같은 질문(같은 트랜잭션 ID)에 서로 다른 답이 두 번 이상 옴 — 먼저 온 답을 믿는 점을 노린 경쟁
  D2  질문을 보낸 DNS 서버가 아닌 다른 주소가 응답함
  D3  기준 조회(신뢰 경로)의 답과 겹치는 IP가 하나도 없음 — CDN·지역 차이로 정상일 수 있어 보조 근거

정상 예외 (D1로 보지 않음)
  - Windows는 첫 DNS 서버가 늦으면 같은 질문을 두 번째 서버에도 보낸다. 두 서버가 CDN 때문에
    서로 다른 답을 주는 것은 정상이다 → '질문한 서버 두 곳이 각자 다른 답'은 제외.
  - 같은 질문을 재전송하면 서버가 라운드로빈으로 다른 답을 줄 수 있다 → 한 서버에서 온 답의 수가
    그 서버에 보낸 질문 수 이하이면 제외. 질문 하나에 답이 둘 이상 와야 경쟁으로 본다.

D3만으로는 '주의'가 되지 않는다 (설계: 'DNS 주소가 다르다는 이유만으로 공격으로 판단하지 않음').
그래서 기준 조회는 D1·D2가 이미 나온 질문에만 한다 (모든 질문마다 바깥으로 조회하지 않는다).
기준 조회가 없거나 실패하면 D3는 판단하지 않는다.
"""
WEIGHTS = {"D1": 40, "D2": 30, "D3": 20}
CAUTION_AT = 40
ALERT_AT = 60
PAIR_TTL = 5.0      # 질문 후 이 시간 안의 응답만 짝짓는다


def level(risk):
    return "warning" if risk >= ALERT_AT else "caution" if risk >= CAUTION_AT else None


class DnsDetector:
    def __init__(self, reference=None):
        """reference: qname -> 신뢰 경로로 조회한 IP 집합, 모르면 None (선택)."""
        self.reference = reference
        self.queries = {}       # (client, port, id, qname) -> {time, servers: {서버: 질문 수}, replies: {출처: 답 수}}
        self.answered = {}      # 같은 키 -> [(출처 IP, 답), ...] 서로 다른 것만
        self.cases = {}         # 같은 키 -> {risk, rules, reasons, level, ...}

    def feed(self, p):
        """p: capture.to_dns()가 만든 dict. 새로 생기거나 단계가 올라간 경고를 돌려준다."""
        now = p["time"]
        self._expire(now)
        if not p["qr"]:
            key = (p["src"], p["sport"], p["id"], p["qname"])
            q = self.queries.setdefault(key, {"time": now, "servers": {}, "replies": {}})
            q["time"] = now     # 재전송하면 짝짓는 시간도 다시 센다
            q["servers"][p["dst"]] = q["servers"].get(p["dst"], 0) + 1
            return None

        key = (p["dst"], p["dport"], p["id"], p["qname"])
        q = self.queries.get(key)
        if q is None:           # 캡처 시작 전의 질문이거나 내 질문이 아님 — 판단하지 않는다
            return None
        answers = sorted(set(p["answers"]))
        servers = q["servers"]
        q["replies"][p["src"]] = q["replies"].get(p["src"], 0) + 1
        case = self.cases.setdefault(key, {"qname": p["qname"], "client": p["dst"],
                                           "server": ", ".join(sorted(servers)),
                                           "answers": answers, "risk": 0, "rules": [], "reasons": [],
                                           "level": None, "time": now})

        if p["src"] not in servers:
            self._add(case, "D2", f"사이트 주소를 물어본 곳({', '.join(sorted(servers))})이 아닌 {p['src']}가 답함")
        got = self.answered.setdefault(key, [])
        for src, prev in got:
            if prev == answers:
                continue
            both_queried = src != p["src"] and src in servers and p["src"] in servers
            retransmitted = src == p["src"] and q["replies"][src] <= servers.get(src, 0)
            if not (both_queried or retransmitted):
                self._add(case, "D1", f"같은 사이트 주소에 다른 답이 두 번 옴 ({', '.join(prev) or '없음'} / "
                                      f"{', '.join(answers) or '없음'})")
                case["answers"] = sorted(set(prev) | set(answers) | set(case["answers"]))
        if (p["src"], answers) not in got:
            got.append((p["src"], answers))

        if self.reference and case["rules"] and "D3" not in case["rules"]:
            ref = self.reference(p["qname"])
            # 기준 조회 결과와 겹치는 답이 하나도 없는 응답이 있었는지 본다
            if ref and any(a and not set(a) & set(ref) for _, a in got):
                self._add(case, "D3", f"믿을 수 있는 다른 경로로 확인한 주소({', '.join(sorted(ref))})와 겹치지 않는 답이 있음 "
                                      "(정상일 수도 있음)")

        lv = level(case["risk"])
        if lv and lv != case["level"]:
            case["level"] = lv
            case["time"] = now
            return dict(case, score=min(case["risk"], 100))
        return None

    def _add(self, case, rule, text):
        if rule in case["rules"]:
            return
        case["rules"].append(rule)
        case["risk"] += WEIGHTS[rule]
        case["reasons"].append(text)

    def _expire(self, now):
        for key in [k for k, q in self.queries.items() if now - q["time"] > PAIR_TTL]:
            del self.queries[key]
            self.answered.pop(key, None)
            self.cases.pop(key, None)
