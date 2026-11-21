"""py -m unittest discover tests"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guard import ap_watch, arp_watch, survey  # noqa: E402
from guard.score import safety_score  # noqa: E402

KO = """
인터페이스 이름 : Wi-Fi
SSID 1 : Cafe
    네트워크 종류           : 인프라
    인증                    : WPA2-개인
    암호화                  : CCMP
    BSSID 1                 : 88:36:6C:00:00:01
         신호               : 70%
         채널               : 6
SSID 2 : Cafe
    네트워크 종류           : 인프라
    인증                    : 개방
    암호화                  : 없음
    BSSID 1                 : 00:1a:2b:00:00:09
         신호               : 95%
         채널               : 11
"""


def pkt(frame, t, op, mac, sip, dip):
    return {"frame": frame, "time": t, "op": op, "mac": mac, "src_ip": sip, "dst_ip": dip}


class ApTest(unittest.TestCase):
    def test_korean_netsh(self):
        aps = ap_watch.parse_networks(KO)
        self.assertEqual([a["bssid"] for a in aps], ["88:36:6c:00:00:01", "00:1a:2b:00:00:09"])
        self.assertEqual(aps[1]["signal"], 95)
        alerts = ap_watch.detect(aps)
        self.assertEqual([a["bssid"] for a in alerts], ["00:1a:2b:00:00:09"])

    def test_lone_open_network_is_fine(self):
        self.assertEqual(ap_watch.detect([{"ssid": "Free", "auth": "Open", "bssid": "00:1a:2b:00:00:01",
                                           "signal": 80, "channel": "1"}]), [])


class ArpTest(unittest.TestCase):
    GW, REAL, EVIL = "192.168.0.1", "88:36:6c:00:00:01", "00:1a:2b:00:00:66"

    def spoof(self, d, start=1.0, n=3):
        """공격자가 1초 간격으로 요청 없는 응답을 n번 보낸다. 마지막으로 바뀐 경고를 돌려준다."""
        last = None
        for i in range(n):
            last = d.feed(pkt(10 + i, start + i, 2, self.EVIL, self.GW, "192.168.0.10")) or last
        return last

    def test_gateway_mac_change_is_caution_then_alert(self):
        d = arp_watch.ArpDetector(gateway_ip=self.GW)
        self.assertIsNone(d.feed(pkt(1, 0.0, 2, self.REAL, self.GW, "192.168.0.10")))
        alert = d.feed(pkt(2, 1.0, 2, self.EVIL, self.GW, "192.168.0.10"))
        self.assertEqual((alert["mac"], alert["level"]), (self.EVIL, "주의"))
        self.assertEqual(alert["claimed_ips"], [self.GW])
        self.assertEqual(self.spoof(d, start=2.0)["level"], "경고")    # 반복 주장(R2)이 붙으면 경고

    def test_gateway_replacement_stays_caution(self):
        d = arp_watch.ArpDetector(gateway_ip=self.GW)
        d.feed(pkt(1, 0.0, 2, self.REAL, self.GW, "192.168.0.10"))
        d.feed(pkt(2, 50.0, 1, self.EVIL, self.GW, "0.0.0.0"))       # 새 공유기의 알림 (방송 요청)
        d.feed(pkt(3, 80.0, 1, "aa:aa:aa:00:00:10", "192.168.0.10", self.GW))
        d.feed(pkt(4, 80.01, 2, self.EVIL, self.GW, "192.168.0.10"))
        self.assertEqual(d.alerts[self.EVIL]["level"], "주의")

    def test_flipflop_raises_alert(self):
        d = arp_watch.ArpDetector(gateway_ip=self.GW)
        d.feed(pkt(1, 0.0, 2, self.REAL, self.GW, "192.168.0.10"))
        d.feed(pkt(2, 15.0, 2, self.EVIL, self.GW, "192.168.0.10"))
        d.feed(pkt(3, 30.0, 1, "aa:aa:aa:00:00:10", "192.168.0.10", self.GW))
        alert = d.feed(pkt(4, 30.01, 2, self.REAL, self.GW, "192.168.0.10"))
        self.assertEqual((alert["mac"], alert["level"]), (self.EVIL, "경고"))

    def test_pin_only_trusted(self):
        d = arp_watch.ArpDetector(gateway_ip=self.GW, trusted={self.GW: self.REAL})
        cmds = arp_watch.defense_commands(self.spoof(d))
        self.assertIn("neighbor=88-36-6c-00-00-01", cmds[0])

        d = arp_watch.ArpDetector(gateway_ip=self.GW)
        self.spoof(d, start=0.0)                                       # 공격이 먼저, 진짜가 나중
        d.feed(pkt(20, 5.0, 1, "aa:aa:aa:00:00:10", "192.168.0.10", self.GW))
        d.feed(pkt(21, 5.01, 2, self.REAL, self.GW, "192.168.0.10"))
        d.feed(pkt(22, 6.0, 2, self.EVIL, self.GW, "192.168.0.10"))
        alert = d.alerts[self.REAL]                                    # 신뢰 값이 없으면 진짜를 의심할 수 있다
        self.assertEqual(arp_watch.defense_commands(alert), ["netsh wlan disconnect"])

    def test_probe_and_dhcp_reuse_no_alert(self):
        d = arp_watch.ArpDetector(gateway_ip=self.GW)
        d.feed(pkt(1, 0.0, 1, "aa:aa:aa:00:00:01", "0.0.0.0", "192.168.0.50"))
        d.feed(pkt(2, 1.0, 1, "aa:aa:aa:00:00:01", "192.168.0.50", "192.168.0.50"))
        self.assertIsNone(d.feed(pkt(3, 60.0, 1, "bb:bb:bb:00:00:02", "192.168.0.50", "192.168.0.50")))


class GatewayAndSurveyTest(unittest.TestCase):
    def test_gateway_check(self):
        trust = {"Cafe": "88:36:6c:00:00:01"}
        self.assertIsNone(ap_watch.check_gateway("Cafe", "88:36:6c:00:00:01", trust))
        self.assertIsNone(ap_watch.check_gateway("Other", "00:1a:2b:00:00:09", trust))
        self.assertEqual(ap_watch.check_gateway("Cafe", "00:1a:2b:00:00:09", trust)["type"], "evil_twin_gateway")

    def test_trust_needs_two_days(self):
        rows = [{"time": "2026-11-02 10:00", "ssid": "Cafe", "bssid": "a"},
                {"time": "2026-11-03 10:00", "ssid": "Cafe", "bssid": "a"},
                {"time": "2026-11-03 10:05", "ssid": "Cafe", "bssid": "b"}]
        self.assertEqual(survey.trust_from_survey(rows), {"Cafe": ["a"]})
        self.assertEqual(survey.mask("88:36:6c:12:34:56"), "88:36:6c:xx:xx:xx")


class ScoreTest(unittest.TestCase):
    def test_open_network_is_caution(self):
        s = safety_score({"ssid": "Free", "bssid": "x", "auth": "Open"}, [], [])
        self.assertEqual((s["score"], s["grade"]), (60, "주의"))


if __name__ == "__main__":
    unittest.main()
