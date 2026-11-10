import unittest

import _path  # noqa: F401

from airbnb_check.score import HIGH, INFO, LOW, MEDIUM, Device, banner_signal, score, vendor_signal, verdict


class ScoreTests(unittest.TestCase):
    def test_onvif_is_high(self):
        self.assertEqual(score(Device("192.168.0.9", onvif="")).level, HIGH)

    def test_rtsp_banner_is_high(self):
        d = Device("192.168.0.9", ports=[554], banners={554: {"proto": "rtsp", "status": "RTSP/1.0 200 OK"}})
        self.assertEqual(score(d).level, HIGH)

    def test_vendor_levels(self):
        self.assertEqual(vendor_signal("Hangzhou Hikvision Digital Technology")[0], HIGH)
        self.assertEqual(vendor_signal("TP-Link Systems Inc")[0], MEDIUM)
        self.assertEqual(vendor_signal("Shenzhen Foo Ltd")[0], LOW)
        self.assertIsNone(vendor_signal("Samsung Electronics Co.,Ltd"))
        self.assertIsNone(vendor_signal("Spring Taxis Ltd"))  # no substring false positives

    def test_two_mediums_escalate(self):
        d = Device("192.168.0.9", vendor="Espressif Inc.", ports=[554])
        self.assertEqual(score(d).level, HIGH)

    def test_single_medium_stays(self):
        self.assertEqual(score(Device("192.168.0.9", vendor="Xiaomi Communications")).level, MEDIUM)

    def test_samsung_tv_is_info(self):
        self.assertEqual(score(Device("192.168.0.7", vendor="Samsung Electronics", ports=[8000])).level, LOW)
        self.assertEqual(score(Device("192.168.0.7", vendor="Samsung Electronics")).level, INFO)

    def test_router_not_flagged_by_vendor(self):
        d = score(Device("192.168.0.1", vendor="TP-Link", is_gateway=True, ports=[80]))
        self.assertEqual(d.label, "ROUTER")
        self.assertEqual(d.level, INFO)

    def test_banner_keywords(self):
        self.assertEqual(banner_signal("Dahua Web Server")[0], HIGH)
        self.assertEqual(banner_signal("Living room webcam")[0], MEDIUM)
        self.assertIsNone(banner_signal("lighttpd"))

    def test_verdict(self):
        self.assertIn("NOT prove", verdict([Device("1.1.1.1")]))
        self.assertIn("HIGH", verdict([score(Device("192.168.0.9", onvif=""))]))


if __name__ == "__main__":
    unittest.main()
