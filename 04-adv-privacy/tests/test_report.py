import json
import unittest

from bleprivacy import analyze, report

from .helpers import Air, address, service_data

TOKEN = bytes.fromhex("4a17234c575944113241706600")


def capture():
    air = Air()
    pub = air.device(address(0, 7), 0, 600, (0x01, b"\x05"), (0x09, b"Kitchen-Lamp"),
                     addr_type=0x00)
    old = air.device(address(0, 1), 0, 300, service_data(0xFEF3, TOKEN))
    new = air.device(address(0, 2), 300.5, 600, service_data(0xFEF3, TOKEN))
    return air.capture(t1=900), (pub, old, new)


class Privacy(unittest.TestCase):
    def test_no_address_or_name_leaks_by_default(self):
        cap, addrs = capture()
        for fmt in ("text", "md", "json"):
            out = report.render(cap, fmt)
            with self.subTest(fmt=fmt):
                for a in addrs:
                    self.assertNotIn(a, out)
                    self.assertNotIn(a.replace(":", ""), out)
                self.assertNotIn("Kitchen", out)

    def test_opt_in_reveals(self):
        cap, (pub, _, _) = capture()
        out = report.render(cap, "text", show_addresses=True, show_names=True)
        self.assertIn(pub, out)
        self.assertIn("Kitchen-Lamp", out)

    def test_same_salt_same_labels(self):
        cap, _ = capture()
        self.assertEqual(report.render(cap, "json", salt="x"), report.render(cap, "json", salt="x"))
        self.assertNotEqual(report.render(cap, "json", salt="x"),
                            report.render(cap, "json", salt="y"))


class Content(unittest.TestCase):
    def test_json_shape(self):
        cap, _ = capture()
        d = json.loads(report.render(cap, "json", salt="s"))
        self.assertEqual(d["addresses"], {"nrpa": 2, "public": 1})
        self.assertEqual([c["links"] for c in d["chains"]], [["identical"]])
        self.assertEqual({f["rule"] for f in d["findings"]}, {"P001", "P004", "S001"})
        self.assertTrue(all(f["subject"].split("#")[0] in ("public", "nrpa")
                            for f in d["findings"]))


if __name__ == "__main__":
    unittest.main()
