import unittest

import _path  # noqa: F401

from airbnb_check.net import norm_mac
from airbnb_check.oui import is_locally_administered, lookup, parse_oui

CSV = """Registry,Assignment,Organization Name,Organization Address
MA-L,001A2B,"Example, Cameras Inc",Somewhere
MA-L,F0E1D2,Acme Corp,Elsewhere
MA-L,BAD,Short Row,x
"""


class OuiTests(unittest.TestCase):
    def test_parse_and_lookup(self):
        t = parse_oui(CSV)
        self.assertEqual(len(t), 2)
        self.assertEqual(lookup("00:1a:2b:11:22:33", t), "Example, Cameras Inc")
        self.assertEqual(lookup("f0-e1-d2-00-00-01", t), "Acme Corp")
        self.assertEqual(lookup("aa:bb:cc:00:00:00", t), "")

    def test_locally_administered(self):
        self.assertTrue(is_locally_administered("da:a1:19:00:00:00"))
        self.assertFalse(is_locally_administered("00:1a:2b:00:00:00"))

    def test_norm_mac_macos_short_form(self):
        self.assertEqual(norm_mac("0:0:0:a1:0:3"), "00:00:00:a1:00:03")


if __name__ == "__main__":
    unittest.main()
