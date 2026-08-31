import unittest, os, json
from raqib import audit
from raqib.models import k8s

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(HERE, "samples", "k8s", name), "r", encoding="utf-8") as fh:
        return json.load(fh)


class TestK8sModel(unittest.TestCase):
    def test_cluster_admin_detected(self):
        acct = k8s.load(load("vulnerable.json"))
        admin = [p for p in acct.principals if p.name == "break-glass"][0]
        self.assertTrue(acct.is_cluster_admin(admin))

    def test_binding_resolves_rules_to_subject(self):
        acct = k8s.load(load("vulnerable.json"))
        sa = [p for p in acct.principals if p.name == "audit-sa"][0]
        self.assertTrue(acct.can(sa, "get", "secrets", cluster_wide_only=True))

    def test_namespaced_role_is_not_cluster_wide(self):
        acct = k8s.load(load("clean.json"))
        for p in acct.principals:
            self.assertFalse(acct.can(p, "get", "pods", cluster_wide_only=True))


class TestK8sFindings(unittest.TestCase):
    def test_vulnerable_covers_every_tactic(self):
        findings, _, _ = audit(load("vulnerable.json"), cloud="k8s")
        tactics = {f["tactic"] for f in findings}
        for t in ["reconnaissance", "privilege escalation", "persistence", "lateral movement", "exfiltration", "defense evasion"]:
            self.assertIn(t, tactics)

    def test_cluster_admin_is_critical(self):
        findings, _, _ = audit(load("vulnerable.json"), cloud="k8s")
        admin = [f for f in findings if f["principal"]["name"] == "break-glass"][0]
        self.assertEqual(admin["severity"], "critical")

    def test_clean_has_no_findings(self):
        _, summary, _ = audit(load("clean.json"), cloud="k8s")
        self.assertEqual(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
