import unittest

import _path  # noqa: F401

from airbnb_check import reexec
from airbnb_check.i18n import detect_lang, limits, t
from airbnb_check.score import HIGH, INFO, LOW, MEDIUM, Device
from airbnb_check.verdict import aggregate


class LangTests(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(detect_lang({"LANG": "pt_BR.UTF-8"}), "pt")
        self.assertEqual(detect_lang({"LANG": "es_ES.UTF-8"}), "es")
        self.assertEqual(detect_lang({"LANG": "en_US.UTF-8"}), "en")
        self.assertEqual(detect_lang({"LANG": "fr_FR.UTF-8"}), "en")
        self.assertEqual(detect_lang({}), "en")

    def test_lc_all_wins_and_c_is_skipped(self):
        self.assertEqual(detect_lang({"LC_ALL": "pt_PT", "LANG": "en_US"}), "pt")
        self.assertEqual(detect_lang({"LC_ALL": "C", "LANG": "es_MX.UTF-8"}), "es")

    def test_catalogues_complete(self):
        from airbnb_check.i18n import MSG
        for lang in ("pt", "es"):
            self.assertEqual(set(MSG[lang]), set(MSG["en"]))
            self.assertEqual(len(limits(lang)), 4)
        self.assertIn("2", t("en", "passes", n=2, gap=5))


def dev(ip, level, self_=False, vendor=""):
    d = Device(ip, vendor=vendor, is_self=self_)
    d.level = level
    d.reasons = [(level, "reason")] if level else []
    return d


class VerdictTests(unittest.TestCase):
    def test_clear(self):
        v = aggregate([dev("1", INFO), dev("2", INFO)], [])
        self.assertEqual((v.level, v.flags, v.key), (INFO, [], "v_clear"))

    def test_worst_device_wins_and_self_ignored(self):
        v = aggregate([dev("1", HIGH, self_=True), dev("2", LOW), dev("3", MEDIUM)], [])
        self.assertEqual(v.level, MEDIUM)
        self.assertEqual([f.subject for f in v.flags], ["3", "2"])

    def test_ssid_raises_level(self):
        self.assertEqual(aggregate([dev("1", INFO)], [("IPC-123", "IPC", False)]).level, MEDIUM)
        self.assertEqual(aggregate([dev("1", LOW)], [("IPC-123", "IPC", True)]).level, HIGH)

    def test_ssid_does_not_lower_high_device(self):
        v = aggregate([dev("1", HIGH, vendor="Hikvision")], [("cam", "CAM", False)])
        self.assertEqual(v.level_name, "HIGH")
        self.assertEqual(len(v.flags), 2)
        self.assertIn("Hikvision", v.flags[0].subject)


class ReexecTests(unittest.TestCase):
    def test_decision(self):
        f = reexec.should_reexec
        self.assertTrue(f("darwin", "/opt/homebrew/bin/python3", False, {}))
        self.assertFalse(f("darwin", "/opt/homebrew/bin/python3", True, {}))          # MACs readable
        self.assertFalse(f("darwin", "/usr/bin/python3", False, {}))                  # already Apple's
        self.assertFalse(f("darwin", "/Library/Developer/CommandLineTools/usr/bin/python3", False, {}))
        self.assertFalse(f("linux", "/usr/bin/python3.11", False, {}))
        self.assertFalse(f("darwin", "/opt/homebrew/bin/python3", False, {reexec.ENV_FLAG: "1"}))  # loop guard
        self.assertFalse(f("darwin", "/opt/homebrew/bin/python3", False, {}, apple_exists=False))


if __name__ == "__main__":
    unittest.main()
