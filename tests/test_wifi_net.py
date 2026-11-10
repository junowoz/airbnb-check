import ipaddress
import unittest

import _path  # noqa: F401

from airbnb_check.net import ScanError, check_target
from airbnb_check.wifi import flag_ssid, parse_macos, parse_nmcli

MAC_SP = """Wi-Fi:
      Interfaces:
        en0:
          Status: Connected
          Current Network Information:
            HomeNet:
              PHY Mode: 802.11ax
              Signal / Noise: -48 dBm / -90 dBm
          Other Local Wi-Fi Networks:
            HDWiFiCam_1234:
              PHY Mode: 802.11n
              Signal / Noise: -50 dBm / -92 dBm
            <redacted>:
              Signal / Noise: -80 dBm / -92 dBm
        awdl0:
          Status: Inactive
"""


class WifiTests(unittest.TestCase):
    def test_ssid_flags(self):
        for s in ("IPC-8812", "HDWiFiCam_1234", "CAM-01", "V380_xyz", "Yoosee123", "ESP_A1B2", "SmartLife-9F", "MV1234", "my camera"):
            self.assertIsNotNone(flag_ssid(s), s)
        for s in ("HomeNet", "Vivo-5G", "Escape Room", "NETGEAR42"):
            self.assertIsNone(flag_ssid(s), s)

    def test_parse_macos(self):
        nets = parse_macos(MAC_SP)
        self.assertEqual([n.ssid for n in nets], ["HomeNet", "HDWiFiCam_1234", "<redacted>"])
        self.assertEqual(nets[1].signal_dbm, -50)
        self.assertTrue(nets[1].strong)
        self.assertFalse(nets[2].strong)

    def test_parse_nmcli(self):
        nets = parse_nmcli("Foo:AA\\:BB\\:CC\\:DD\\:EE\\:FF:80\nIPC-1:11\\:22\\:33\\:44\\:55\\:66:30\n")
        self.assertEqual(nets[0].ssid, "Foo")
        self.assertEqual(nets[0].bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(nets[1].signal_pct, 30)


class CidrTests(unittest.TestCase):
    def ok(self, c):
        check_target(ipaddress.ip_network(c))

    def test_allowed(self):
        for c in ("192.168.0.0/24", "10.1.2.0/25", "172.16.5.0/24", "172.31.0.0/28"):
            self.ok(c)

    def test_refused(self):
        for c in ("192.168.0.0/16", "10.0.0.0/8", "8.8.8.0/24", "172.32.0.0/24", "169.254.0.0/24", "127.0.0.0/24", "fd00::/64"):
            with self.assertRaises(ScanError, msg=c):
                self.ok(c)


if __name__ == "__main__":
    unittest.main()
