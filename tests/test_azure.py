import os, json, unittest
from raqib import audit
from raqib.models import azure

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(HERE, "samples", "azure", name)) as fh:
        return json.load(fh)


class TestAzureModel(unittest.TestCase):
    def test_owner_is_resolved(self):
        acct = azure.load(load("vulnerable.json"))
        owners = [p for p in acct.principals if acct.is_owner(p)]
        self.assertTrue(owners)

    def test_role_assignment_write_detected(self):
        acct = azure.load(load("vulnerable.json"))
        p = [p for p in acct.principals if p.name == "ci-sp"][0]
        self.assertTrue(acct.allows(p, "microsoft.authorization/roleassignments/write"))

    def test_reader_does_not_grant_data_read(self):
        acct = azure.load(load("vulnerable.json"))
        reader = [p for p in acct.principals if p.name == "read-only"][0]
        self.assertFalse(acct.allows_data(reader, "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"))


class TestAzureFindings(unittest.TestCase):
    def test_vulnerable_covers_key_tactics(self):
        findings, summary, _ = audit(load("vulnerable.json"))
        self.assertEqual(summary["cloud"], "azure")
        tactics = {f["tactic"] for f in findings}
        for t in ["privilege escalation", "exfiltration", "defense evasion", "persistence", "reconnaissance"]:
            self.assertIn(t, tactics)

    def test_owner_is_critical(self):
        findings, _, _ = audit(load("vulnerable.json"))
        crit = [f for f in findings if f["severity"] == "critical"]
        self.assertTrue(any("Owner" in f["title"] for f in crit))

    def test_managed_identity_execution_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("run code on a VM as its managed identity" in f["title"] and f["severity"] == "high" for f in findings))
        self.assertTrue(any("Automation runbook as its managed identity" in f["title"] and f["severity"] == "high" for f in findings))
        self.assertTrue(any("assign a managed identity to a resource" in f["title"] and f["severity"] == "high" for f in findings))

    def test_role_definition_write_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("write custom role definitions" in f["title"] and f["severity"] == "medium" for f in findings))

    def test_federated_credential_persistence_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("federated credential to a managed identity" in f["title"] and f["severity"] == "high" and f["tactic"] == "persistence" for f in findings))

    def test_automation_account_persistence_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("create an Automation account" in f["title"] and f["tactic"] == "persistence" for f in findings))

    def test_multi_subscription_reach_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("spans multiple subscriptions" in f["title"] and f["tactic"] == "lateral movement" for f in findings))

    def test_multiple_assignments_accumulate(self):
        acct = azure.load(load("vulnerable.json"))
        sp = [p for p in acct.principals if p.name == "cross-sub-sp"][0]
        self.assertGreaterEqual(len(sp.assignments), 2)

    def test_sas_and_disk_and_cosmos_exfil_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        details = " ".join(f["detail"] for f in findings if f["tactic"] == "exfiltration")
        self.assertIn("SAS token", details)
        self.assertIn("disk or snapshot", details)
        self.assertIn("Cosmos DB keys", details)

    def test_clean_has_no_findings(self):
        findings, summary, _ = audit(load("clean.json"))
        self.assertEqual(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
