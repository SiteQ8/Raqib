import os, json, unittest
from raqib import audit
from raqib.models import k8s

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(HERE, "samples", "k8s", name)) as fh:
        return json.load(fh)


class TestK8sModel(unittest.TestCase):
    def test_cluster_admin_detected(self):
        acct = k8s.load(load("vulnerable.json"))
        admins = [p for p in acct.principals if acct.is_cluster_admin(p)]
        self.assertTrue(admins)

    def test_namespaced_role_is_not_cluster_wide(self):
        acct = k8s.load(load("clean.json"))
        for p in acct.principals:
            self.assertFalse(acct.can(p, "get", "pods", cluster_wide_only=True))

    def test_secret_read_resolves(self):
        acct = k8s.load(load("vulnerable.json"))
        sa = [p for p in acct.principals if p.name == "audit-sa"][0]
        self.assertTrue(acct.can(sa, "get", "secrets", cluster_wide_only=True))


class TestK8sFindings(unittest.TestCase):
    def test_vulnerable_covers_all_tactics(self):
        findings, summary, _ = audit(load("vulnerable.json"))
        self.assertEqual(summary["cloud"], "k8s")
        tactics = {f["tactic"] for f in findings}
        for t in ["privilege escalation", "persistence", "lateral movement", "exfiltration", "defense evasion", "reconnaissance"]:
            self.assertIn(t, tactics)

    def test_cluster_admin_is_critical(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("cluster-admin" in f["title"] and f["severity"] == "critical" for f in findings))

    def test_escalate_and_bind_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        titles = " ".join(f["title"] for f in findings)
        self.assertIn("escalate", titles)
        self.assertIn("bind", titles)

    def test_clean_has_no_findings(self):
        findings, summary, _ = audit(load("clean.json"))
        self.assertEqual(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
