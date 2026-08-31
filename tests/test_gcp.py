import os, json, unittest
from raqib import audit
from raqib.models import gcp

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(HERE, "samples", "gcp", name)) as fh:
        return json.load(fh)


class TestGcpModel(unittest.TestCase):
    def test_owner_detected(self):
        acct = gcp.load(load("vulnerable.json"))
        self.assertTrue(any(acct.is_owner(p) for p in acct.principals))

    def test_custom_role_permissions_read(self):
        acct = gcp.load(load("clean.json"))
        p = [p for p in acct.principals if "reporting" in p.member][0]
        self.assertTrue(acct.has_permission(p, "compute.instances.get"))
        self.assertFalse(acct.has_permission(p, "storage.objects.get"))

    def test_public_member_flagged_kind(self):
        acct = gcp.load(load("vulnerable.json"))
        pub = [p for p in acct.principals if p.is_public]
        self.assertTrue(pub)
        self.assertEqual(pub[0].kind, "public")


class TestGcpFindings(unittest.TestCase):
    def test_vulnerable_covers_tactics(self):
        findings, summary, _ = audit(load("vulnerable.json"))
        self.assertEqual(summary["cloud"], "gcp")
        tactics = {f["tactic"] for f in findings}
        for t in ["privilege escalation", "lateral movement", "persistence", "exfiltration", "defense evasion", "reconnaissance"]:
            self.assertIn(t, tactics)

    def test_setiampolicy_is_high(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("rewrite the project IAM policy" in f["title"] and f["severity"] == "high" for f in findings))

    def test_public_is_critical(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("granted to everyone" in f["title"] and f["severity"] == "critical" for f in findings))

    def test_clean_has_no_findings(self):
        findings, summary, _ = audit(load("clean.json"))
        self.assertEqual(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
