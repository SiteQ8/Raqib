import unittest, os, json
from raqib import audit
from raqib.models import gcp

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(HERE, "samples", "gcp", name), "r", encoding="utf-8") as fh:
        return json.load(fh)


class TestGcpModel(unittest.TestCase):
    def test_owner_role_is_owner(self):
        acct = gcp.load(load("vulnerable.json"))
        owner = [p for p in acct.principals if p.name == "founder@example.com"][0]
        self.assertTrue(acct.is_owner(owner))

    def test_custom_role_permissions_resolve(self):
        acct = gcp.load({"bindings": [{"role": "projects/p/roles/r", "members": ["user:a@b.com"]}],
                         "customRoles": [{"name": "projects/p/roles/r", "includedPermissions": ["storage.objects.get"]}]})
        p = acct.principals[0]
        self.assertTrue(acct.has_permission(p, "storage.objects.get"))

    def test_public_member_detected(self):
        acct = gcp.load(load("vulnerable.json"))
        self.assertTrue(any(p.is_public for p in acct.principals))


class TestGcpFindings(unittest.TestCase):
    def test_vulnerable_covers_the_key_tactics(self):
        findings, _, _ = audit(load("vulnerable.json"), cloud="gcp")
        tactics = {f["tactic"] for f in findings}
        for t in ["privilege escalation", "lateral movement", "persistence", "exfiltration", "defense evasion", "reconnaissance"]:
            self.assertIn(t, tactics)

    def test_public_binding_is_critical(self):
        findings, _, _ = audit(load("vulnerable.json"), cloud="gcp")
        pub = [f for f in findings if f["principal"]["name"] in ("allUsers",)][0]
        self.assertEqual(pub["severity"], "critical")

    def test_clean_has_no_findings(self):
        _, summary, _ = audit(load("clean.json"), cloud="gcp")
        self.assertEqual(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
