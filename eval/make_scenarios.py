"""평가용 시나리오 생성기.

ARP 시나리오는 pcap 파일로, 가짜 AP 시나리오는 netsh 출력 형식의 텍스트로만 만든다.
만든 패킷은 파일에 쓰기만 하고 네트워크로 보내지 않는다 (탐지기 재생 평가용).

  py eval/make_scenarios.py            → eval/scenarios/ 에 위협·정상 시나리오 생성
"""
import json
import random
import struct
import sys
from pathlib import Path

OUT = Path(__file__).parent / "scenarios"
NET = "192.168.0."
GW_IP = NET + "1"
DURATION = 120.0
RUNS = 20                       # 공격 종류마다
NORMAL_RUNS = 100
HARD_RUNS = 20                  # 어려운 정상 (공유기 교체)
ARP_VARIANTS = ["basic", "two_way", "slow", "same_oui", "early", "request_poison", "broadcast", "gateway_only"]
AP_VARIANTS = ["open_twin", "random_oui", "diff_oui_multi", "hotspot_twin", "same_vendor_twin"]

VENDOR_OUIS = ["00:1a:2b", "88:36:6c", "f4:f2:6d", "3c:84:6a", "b0:be:76", "00:26:66",
               "a4:2b:b0", "d8:07:b6", "70:5d:cc", "e4:5f:01"]


def mac(rng, prefix=None):
    p = prefix or rng.choice(VENDOR_OUIS)
    return p + ":" + ":".join(f"{rng.randrange(256):02x}" for _ in range(3))


def local_mac(rng):
    first = (rng.randrange(256) | 0x02) & 0xFE          # 로컬 관리 비트 1, 유니캐스트
    return f"{first:02x}:" + ":".join(f"{rng.randrange(256):02x}" for _ in range(5))


# ---------- ARP pcap ----------

def b_mac(m):
    return bytes.fromhex(m.replace(":", ""))


def b_ip(ip):
    return bytes(int(x) for x in ip.split("."))


def arp_frame(op, smac, sip, tmac, tip, eth_dst=None):
    dst = eth_dst or ("ff:ff:ff:ff:ff:ff" if op == 1 else tmac)
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + b_mac(smac) + b_ip(sip) + \
        b_mac(tmac if op == 2 else "00:00:00:00:00:00") + b_ip(tip)
    frame = b_mac(dst) + b_mac(smac) + b"\x08\x06" + body
    return frame + b"\x00" * (60 - len(frame))


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, data in sorted(packets, key=lambda x: x[0]):
            sec, usec = int(t), int((t % 1) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)) + data)


def normal_arp(rng, base_t, replace_gateway=False):
    """정상 망. replace_gateway면 중간에 공유기가 교체되어 MAC이 한 번 바뀐다 (어려운 정상)."""
    gw_macs = [mac(rng)]
    swap_at = DURATION + 1
    if replace_gateway:
        gw_macs.append(mac(rng))
        swap_at = rng.uniform(30, 80)

    def gw(t):
        return gw_macs[-1] if t >= swap_at else gw_macs[0]

    hosts = {NET + str(i): mac(rng) for i in rng.sample(range(10, 200), rng.randint(5, 20))}
    pk = []

    def at(t, *a, **k):
        pk.append((base_t + t, arp_frame(*a, **k)))

    for ip, m in hosts.items():
        t = rng.uniform(0, 30)
        while t < DURATION:                              # 호스트가 공유기 MAC을 묻고 공유기가 답함
            at(t, 1, m, ip, "00:00:00:00:00:00", GW_IP)
            if not (swap_at <= t < swap_at + 5):         # 교체 중 몇 초는 공유기가 응답하지 않음
                at(t + rng.uniform(0.001, 0.02), 2, gw(t), GW_IP, m, ip)
            if rng.random() < 0.3:                       # 가끔 다른 호스트끼리도 묻고 답함
                oip, om = rng.choice(list(hosts.items()))
                if oip != ip:
                    at(t + 0.5, 1, m, ip, "00:00:00:00:00:00", oip)
                    at(t + 0.51, 2, om, oip, m, ip)
            t += rng.uniform(20, 60)
    if replace_gateway:                                  # 새 공유기가 켜지며 자기 주소를 알림
        at(swap_at + 5, 1, gw_macs[-1], GW_IP, "00:00:00:00:00:00", GW_IP)
        at(swap_at + 6, 1, gw_macs[-1], GW_IP, "00:00:00:00:00:00", GW_IP)
    for _ in range(rng.randint(0, 3)):                   # 새 기기 접속: 프로브 + 알림(gratuitous) 2번
        ip, m = NET + str(rng.randrange(200, 250)), mac(rng)
        t = rng.uniform(5, DURATION - 5)
        at(t, 1, m, "0.0.0.0", "00:00:00:00:00:00", ip)
        at(t + 1, 1, m, ip, "00:00:00:00:00:00", ip)
        at(t + 2, 1, m, ip, "00:00:00:00:00:00", ip)
    if rng.random() < 0.3:                               # DHCP 재할당: 나간 기기의 IP를 새 기기가 받음
        ip = rng.choice(list(hosts))
        old, m = b_mac(hosts[ip]), mac(rng)
        t = rng.uniform(40, DURATION - 5)
        pk[:] = [(tt, d) for tt, d in pk                 # 나간 기기는 그 뒤로 보내지도 받지도 않는다
                 if tt < base_t + t or (d[6:12] != old and d[0:6] != old)]
        hosts[ip] = m
        at(t, 1, m, ip, "00:00:00:00:00:00", ip)
        at(t + 0.4, 1, m, ip, "00:00:00:00:00:00", GW_IP)
        at(t + 0.41, 2, gw(t), GW_IP, m, ip)
    if rng.random() < 0.5:                               # 공유기의 정상 gratuitous ARP
        t = rng.uniform(1, DURATION)
        at(t, 1, gw(t), GW_IP, "00:00:00:00:00:00", GW_IP)
    return pk, gw_macs[0], hosts


def attack_arp(rng, variant, base_t):
    pk, gw_mac, hosts = normal_arp(rng, base_t)
    (victim_ip, victim_mac), (_, other_mac) = rng.sample(list(hosts.items()), 2)
    att_mac = mac(rng, gw_mac[:8]) if variant == "same_oui" else mac(rng)
    start = 0.5 if variant == "early" else rng.uniform(20, 80)
    gap = {"slow": 15.0, "broadcast": rng.uniform(2.0, 5.0)}.get(variant, rng.uniform(1.0, 2.0))
    if variant == "early":                               # 캡처 시작 전부터 공격 중: 공유기 첫 응답을 늦춘다
        pk = [(t, d) for t, d in pk if t - base_t > 3 or d[6:12] != b_mac(gw_mac)]
    t = start
    while t < DURATION:
        if variant == "request_poison":                  # 응답 대신 '요청'의 보낸 사람 칸을 위조 (피해자 앞 유니캐스트)
            frame = arp_frame(1, att_mac, GW_IP, "00:00:00:00:00:00", victim_ip, eth_dst=victim_mac)
        elif variant == "broadcast":                     # 망 전체에 "공유기 IP는 내 MAC" 방송
            frame = arp_frame(2, att_mac, GW_IP, "ff:ff:ff:ff:ff:ff", GW_IP)
        elif variant == "gateway_only":                  # 공유기 쪽만 속임: 피해자 앞으로는 아무것도 안 감
            frame = arp_frame(2, att_mac, victim_ip, gw_mac, GW_IP)
        else:
            frame = arp_frame(2, att_mac, GW_IP, victim_mac, victim_ip)
        pk.append((base_t + t, frame))
        if variant == "two_way":
            pk.append((base_t + t + 0.01, arp_frame(2, att_mac, victim_ip, gw_mac, GW_IP)))
        t += gap
    return pk, {"attacker": att_mac, "gateway_mac": gw_mac, "start": base_t + start,
                "victim": victim_mac, "bystander": other_mac}

# ---------- 가짜 AP (netsh 텍스트) ----------

def netsh_text(aps):
    by = {}                                              # netsh는 이름이 같아도 보안 방식이 다르면 따로 적는다
    for ap in aps:
        by.setdefault((ap["ssid"], ap["auth"]), []).append(ap)
    lines = ["", "Interface name : Wi-Fi ", f"There are {len(by)} networks currently visible. ", ""]
    for n, ((ssid, _), group) in enumerate(by.items(), 1):
        lines += [f"SSID {n} : {ssid}", "    Network type            : Infrastructure",
                  f"    Authentication          : {group[0]['auth']}",
                  f"    Encryption              : {'None' if group[0]['auth'] == 'Open' else 'CCMP'} "]
        for k, ap in enumerate(group, 1):
            lines += [f"    BSSID {k}                 : {ap['bssid']}",
                      f"         Signal             : {ap['signal']}%  ",
                      "         Radio type         : 802.11ax",
                      f"         Channel            : {ap['channel']} ", ""]
    return "\n".join(lines)


def normal_aps(rng):
    aps = []
    for n in range(rng.randint(3, 12)):
        kind = rng.random()
        ssid = f"NET_{n:02d}_{rng.randrange(1000):03d}"
        if kind < 0.25:                                  # 같은 업체 AP 여러 대 (학교·역)
            o = rng.choice(VENDOR_OUIS)
            for _ in range(rng.randint(3, 6)):
                aps.append({"ssid": ssid, "auth": "WPA2-Enterprise", "bssid": mac(rng, o),
                            "signal": rng.randint(20, 90), "channel": rng.choice([1, 6, 11, 36, 149])})
        elif kind < 0.45:                                # 혼자 있는 개방형 (카페 공개 와이파이)
            aps.append({"ssid": ssid, "auth": "Open", "bssid": mac(rng), "signal": rng.randint(20, 90),
                        "channel": rng.choice([1, 6, 11])})
        elif kind < 0.55:                                # 휴대폰 핫스팟 (임의 MAC)
            aps.append({"ssid": ssid, "auth": "WPA2-Personal", "bssid": local_mac(rng),
                        "signal": rng.randint(20, 90), "channel": 6})
        else:
            aps.append({"ssid": ssid, "auth": rng.choice(["WPA2-Personal", "WPA3-Personal"]),
                        "bssid": mac(rng), "signal": rng.randint(20, 90), "channel": rng.choice([1, 6, 11, 36])})
    return aps


def attack_aps(rng, variant):
    aps = normal_aps(rng)
    o = rng.choice(VENDOR_OUIS)
    real = [{"ssid": "Cafe_Free_WiFi", "auth": "WPA2-Personal", "bssid": mac(rng, o),
             "signal": rng.randint(40, 70), "channel": 6}]
    if variant == "diff_oui_multi":
        real += [{**real[0], "bssid": mac(rng, o), "signal": rng.randint(30, 70)} for _ in range(2)]
    twin = {**real[0], "signal": min(real[0]["signal"] + rng.randint(5, 35), 99), "channel": 11}
    twin["bssid"] = {"open_twin": mac(rng), "random_oui": mac(rng),
                     "diff_oui_multi": mac(rng, rng.choice([x for x in VENDOR_OUIS if x != o])),
                     "hotspot_twin": local_mac(rng), "same_vendor_twin": mac(rng, o)}[variant]
    if variant == "open_twin":
        twin["auth"] = "Open"
    gw_real, gw_twin = mac(rng), mac(rng)               # 가짜 AP는 공격자 노트북이 공유기 역할을 한다
    info = {"twin": twin["bssid"],
            "trust_ap": {"Cafe_Free_WiFi": [r["bssid"] for r in real]},  # 예전에 진짜 AP에 접속했던 경우
            "trust_gw": {"Cafe_Free_WiFi": gw_real},
            "gateway": {**{r["bssid"]: gw_real for r in real}, twin["bssid"]: gw_twin}}
    return aps + real + [twin], info


def main():
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*"):
        old.unlink()
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    rng = random.Random(seed)
    truth = {"seed": seed, "arp": [], "ap": []}
    base_t = 1_793_000_000.0

    def arp_case(name, pk, **info):
        write_pcap(OUT / f"{name}.pcap", pk)
        truth["arp"].append({"file": f"{name}.pcap", **info})

    for v in ARP_VARIANTS:
        for i in range(RUNS):
            pk, info = attack_arp(rng, v, base_t)
            arp_case(f"arp_{v}_{i:02d}", pk, variant=v, **info)
    for i in range(NORMAL_RUNS):
        pk, _, hosts = normal_arp(rng, base_t)
        arp_case(f"arp_normal_{i:03d}", pk, variant="normal", observer=rng.choice(list(hosts.values())))
    for i in range(HARD_RUNS):
        pk, _, hosts = normal_arp(rng, base_t, replace_gateway=True)
        arp_case(f"arp_replaced_{i:02d}", pk, variant="gateway_replaced",
                 observer=rng.choice(list(hosts.values())))

    for v in AP_VARIANTS:
        for i in range(RUNS):
            aps, info = attack_aps(rng, v)
            (OUT / f"ap_{v}_{i:02d}.txt").write_text(netsh_text(aps), encoding="utf-8")
            truth["ap"].append({"file": f"ap_{v}_{i:02d}.txt", "variant": v, **info})
    for i in range(NORMAL_RUNS):
        (OUT / f"ap_normal_{i:03d}.txt").write_text(netsh_text(normal_aps(rng)), encoding="utf-8")
        truth["ap"].append({"file": f"ap_normal_{i:03d}.txt", "variant": "normal"})
    (OUT / "truth.json").write_text(json.dumps(truth, indent=1), encoding="utf-8")
    print(f"시나리오 생성 (시드 {seed}): ARP {len(truth['arp'])}개, AP {len(truth['ap'])}개 → {OUT}")

if __name__ == "__main__":
    main()
