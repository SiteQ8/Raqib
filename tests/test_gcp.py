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

    def test_actas_deploy_is_high(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("deploy a Cloud Function as a service account" in f["title"] and f["severity"] == "high" for f in findings))

    def test_generic_actas_is_medium_fallback(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any(f["title"] == "Can act as service accounts" and f["severity"] == "medium" for f in findings))

    def test_custom_role_rewrite_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("rewrite a custom role" in f["title"] and f["severity"] == "high" for f in findings))

    def test_cloud_build_service_account_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("Cloud Build service account" in f["title"] and f["severity"] == "high" for f in findings))

    def test_deployment_manager_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("Google APIs service account" in f["title"] and f["severity"] == "high" for f in findings))

    def test_impersonation_covers_signing(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any(f["title"] == "Can impersonate service accounts"
                            and f["principal"]["name"] == "token-signer@example.com" for f in findings))

    def test_clean_has_no_findings(self):
        findings, summary, _ = audit(load("clean.json"))
        self.assertEqual(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
