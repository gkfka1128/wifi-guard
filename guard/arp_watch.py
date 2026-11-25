"""F2  ARP 스푸핑 탐지.

tshark가 뽑아 준 ARP 필드를 한 줄씩 받아 규칙별 점수를 MAC마다 더한다.
  R1  같은 IP를 다른 MAC이 주장함 (공유기 IP면 점수가 크다)
  R2  요청하지 않은 ARP 응답, 또는 나에게 직접 온 ARP 요청이 10초에 3번 이상 (반복 주장)
  R3  MAC 하나가 여러 IP를 주장함
  R4  같은 IP를 주장하는 MAC의 OUI(제조사 앞 3바이트)가 다름
  R5  원래 MAC이 그 IP를 다시 주장함 (두 MAC이 번갈아 주장 = 공유기 교체가 아니라 충돌)

점수가 CAUTION_AT 이상이면 '주의', ALERT_AT 이상이면 '경고'.
공유기 MAC이 바뀐 것(R1)만으로는 '주의'에 그친다. 공유기를 교체해도 MAC은 바뀌기 때문이다.
반복 주장(R2)이나 원래 MAC의 재등장(R5)처럼 공격에서만 나오는 근거가 붙어야 '경고'가 된다.
"""
import os
import shutil
import subprocess
from collections import defaultdict, deque

FIELDS = ["frame.number", "frame.time_epoch", "eth.dst", "arp.opcode",
          "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.proto_ipv4"]
BCAST = "ff:ff:ff:ff:ff:ff"

WEIGHTS = {"gw_conflict": 40, "host_conflict": 20, "unsolicited": 30, "multi_ip": 30,
           "oui": 10, "flipflop_gw": 30, "flipflop_host": 10}
# 중간발표 1차 버전의 점수 (비교용): 공유기 MAC 변경만으로 경고했다
WEIGHTS_V1 = {"gw_conflict": 60, "host_conflict": 20, "unsolicited": 30, "multi_ip": 30,
              "oui": 20, "flipflop_gw": 0, "flipflop_host": 0}
CAUTION_AT = 40
ALERT_AT = 60

REQUEST_TTL = 3.0       # 요청 후 이 시간 안에 온 응답은 '요청한 응답'으로 본다
UNSOLICITED_WINDOW = 10.0
UNSOLICITED_COUNT = 3


def tshark_path():
    found = shutil.which("tshark")
    if found:
        return found
    default = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(default):
        return default
    raise SystemExit("tshark를 찾을 수 없습니다. Wireshark를 설치하세요.")


def read_packets(pcap=None, iface=None):
    """pcap 파일이나 실시간 인터페이스에서 ARP 패킷을 dict로 하나씩 돌려준다."""
    cmd = [tshark_path(), "-Y", "arp", "-T", "fields", "-E", "separator=,"]
    for f in FIELDS:
        cmd += ["-e", f]
    cmd += ["-r", pcap] if pcap else ["-i", iface, "-l"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    try:
        for line in proc.stdout:
            num, t, edst, op, mac, sip, dip = line.rstrip("\n").split(",")
            yield {"frame": int(num), "time": float(t), "eth_dst": edst.lower(), "op": int(op),
                   "mac": mac.lower(), "src_ip": sip, "dst_ip": dip}
    finally:
        proc.terminate()


def oui(mac):
    return mac[:8]


def level(risk):
    return "경고" if risk >= ALERT_AT else "주의" if risk >= CAUTION_AT else None


class ArpDetector:
    def __init__(self, gateway_ip=None, trusted=None, weights=None):
        self.gateway_ip = gateway_ip
        self.w = {**WEIGHTS, **(weights or {})}
        self.trusted = dict(trusted or {})      # 미리 확인해 둔 ip -> mac (신뢰 목록)
        self.binding = dict(self.trusted)       # ip -> 처음 본(또는 신뢰하는) mac
        self.requests = {}                      # (질의한 ip, 물은 ip) -> 마지막 질의 시각
        self.repeats = defaultdict(deque)       # mac -> 요청 없는 주장 시각들
        self.mac_ips = defaultdict(set)
        self.rivals = defaultdict(set)          # ip -> 이 ip를 처음 MAC과 다르게 주장한 MAC들
        self.history = []                       # (시각, mac, 누적 점수) — 임계값 분석용
        self.risk = defaultdict(int)
        self.reasons = defaultdict(list)
        self.fired = defaultdict(set)           # mac -> 이미 점수를 준 규칙
        self.alerts = {}                        # mac -> 경고 (mac당 하나, 이후 갱신)
        self._now = 0.0

    def _add(self, mac, rule, key, text):
        if rule in self.fired[mac] or not self.w[key]:
            return
        self.fired[mac].add(rule)
        self.risk[mac] += self.w[key]
        self.reasons[mac].append(text)
        self.history.append((self._now, mac, self.risk[mac]))

    def feed(self, p):
        """패킷 하나를 반영하고, 새로 생기거나 '경고'로 올라간 경고가 있으면 돌려준다."""
        mac, ip, now = p["mac"], p["src_ip"], p["time"]
        self._now = now
        if p["op"] == 1:
            self.requests[(ip, p["dst_ip"])] = now
        if not ip or ip == "0.0.0.0":           # ARP 프로브는 주소를 주장하지 않는다
            return None
        is_gw = ip == self.gateway_ip

        known = self.binding.setdefault(ip, mac)
        if known != mac:
            self._add(mac, "R1:" + ip, "gw_conflict" if is_gw else "host_conflict",
                      f"{'공유기 ' if is_gw else ''}{ip}의 기기 고유번호가 {known} → {mac}로 바뀜")
            if oui(known) != oui(mac):
                self._add(mac, "R4", "oui", f"기기 제조사 번호대가 {oui(known)} → {oui(mac)}로 다름")
            self.rivals[ip].add(mac)
        elif self.rivals[ip]:                   # 원래 MAC이 다시 나타남: 교체가 아니라 두 MAC의 충돌
            for rival in self.rivals[ip]:
                self._add(rival, "R5:" + ip, "flipflop_gw" if is_gw else "flipflop_host",
                          f"원래 기기 {mac}이 {ip}를 다시 주장함 (두 기기가 번갈아 나타남)")

        # 응답의 대상 IP(dst_ip)가 그 주소(ip)를 실제로 물었는지 본다. 남이 물은 것은 근거가 안 된다
        unsolicited_reply = p["op"] == 2 and now - self.requests.get((p["dst_ip"], ip), -1e9) > REQUEST_TTL
        direct_request = p["op"] == 1 and p.get("eth_dst") not in (None, "", BCAST)
        if unsolicited_reply or direct_request:
            q = self.repeats[mac]
            q.append(now)
            while q and now - q[0] > UNSOLICITED_WINDOW:
                q.popleft()
            if len(q) >= UNSOLICITED_COUNT:
                self._add(mac, "R2", "unsolicited",
                          f"묻지도 않았는데 '내가 공유기다'라는 신호가 {UNSOLICITED_WINDOW:.0f}초에 {len(q)}번")

        self.mac_ips[mac].add(ip)
        if len(self.mac_ips[mac]) >= 2:
            self._add(mac, "R3", "multi_ip",
                      f"MAC 하나가 IP {len(self.mac_ips[mac])}개를 주장 ({', '.join(sorted(self.mac_ips[mac]))})")

        if self.rivals[ip]:                     # 다툼이 있는 IP: 공격 행동을 보인 쪽은 먼저 배운 MAC이어도 점수를 받는다
            owner = self.binding[ip]
            if owner == mac and {"R2", "R3"} & self.fired[mac]:
                self._add(mac, "R1:" + ip, "gw_conflict" if is_gw else "host_conflict",
                          f"{'공유기 ' if is_gw else ''}{ip}를 다른 MAC({', '.join(sorted(self.rivals[ip]))})과 함께 주장")

        new = self._alert_for(mac, p)
        for rival in self.rivals[ip] - {mac}:   # R5로 경쟁 MAC의 점수가 올랐을 수 있다
            new = self._alert_for(rival, p) or new
        return new

    def _suspect(self, mac):
        """경고 대상 MAC과 같은 IP를 다투는 MAC들 중 공격 행동(R2 반복 주장, R3 여러 IP)이 더 많은 쪽.
        먼저 본 MAC을 진짜로 배우므로, 공격이 먼저 보이면 진짜 공유기가 경고 대상이 될 수 있다.
        이때 행동 근거로 공격자를 다시 고른다. 근거가 같으면 None (어느 쪽인지 확인 필요)."""
        ips = {i for i, rs in self.rivals.items() if mac in rs or (rs and self.binding.get(i) == mac)}
        cands = {mac} | {m for i in ips for m in self.rivals[i] | {self.binding[i]}}

        def acts(m):
            return ("R2" in self.fired[m]) + ("R3" in self.fired[m])
        best = max(cands, key=acts)
        if acts(best) == 0 or sum(acts(m) == acts(best) for m in cands) > 1:
            return mac if acts(mac) and len(cands) == 1 else None
        return best

    def _alert_for(self, mac, p):
        lv = level(self.risk[mac])
        if lv is None:
            return None
        alert = self.alerts.get(mac)
        changed = alert is None or alert["level"] != lv
        if alert is None:
            alert = self.alerts[mac] = {"type": "arp_spoofing", "mac": mac,
                                        "first_frame": p["frame"], "time": p["time"]}
        claimed = [i for i in self.mac_ips[mac] if self.binding.get(i) != mac]
        alert.update(level=lv, risk=min(self.risk[mac], 100), reasons=list(self.reasons[mac]),
                     suspect=self._suspect(mac),
                     last_frame=p["frame"], claimed_ips=sorted(claimed),
                     real_macs={i: self.binding[i] for i in claimed},
                     trusted={i: self.trusted[i] for i in claimed if i in self.trusted})
        return alert if changed else None


def defense_commands(alert, iface="Wi-Fi"):
    """방어 명령. '주의'는 확인만 권하고, '경고'일 때 신뢰 목록에 있는 IP만 원래 MAC으로 고정한다.
    처음 본 MAC이 진짜라는 보장은 없으므로(공격이 먼저 시작됐을 수 있다), 신뢰 목록이
    없으면 고정하지 않고 연결 끊기만 권한다."""
    if alert["level"] != "경고":
        return []
    pinned = {ip: mac for ip, mac in alert["real_macs"].items() if alert["trusted"].get(ip) == mac}
    cmds = [f'netsh interface ipv4 set neighbors interface="{iface}" '
            f'address={ip} neighbor={mac.replace(":", "-")} store=active'
            for ip, mac in pinned.items()]
    if alert["risk"] >= 80 or not pinned:
        cmds.append("netsh wlan disconnect")
    return cmds
