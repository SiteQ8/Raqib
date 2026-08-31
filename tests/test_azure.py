import unittest, os, json
from raqib import audit
from raqib.models import azure

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(HERE, "samples", "azure", name), "r", encoding="utf-8") as fh:
        return json.load(fh)


class TestAzureModel(unittest.TestCase):
    def test_resolves_owner_from_builtin_id(self):
        acct = azure.load(load("vulnerable.json"))
        owner = [p for p in acct.principals if p.name == "ops-lead"][0]
        self.assertTrue(acct.is_owner(owner))

    def test_role_assignment_write_is_seen(self):
        acct = azure.load(load("vulnerable.json"))
        sp = [p for p in acct.principals if p.name == "ci-sp"][0]
        self.assertTrue(acct.allows(sp, "microsoft.authorization/roleassignments/write"))

    def test_reader_does_not_grant_data_read(self):
        acct = azure.load(load("vulnerable.json"))
        reader = [p for p in acct.principals if p.name == "read-only"][0]
        self.assertFalse(acct.allows_data(reader, "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"))


class TestAzureFindings(unittest.TestCase):
    def test_vulnerable_covers_the_key_tactics(self):
        findings, summary, _ = audit(load("vulnerable.json"), cloud="azure")
        tactics = {f["tactic"] for f in findings}
        for t in ["privilege escalation", "persistence", "exfiltration", "defense evasion", "reconnaissance"]:
            self.assertIn(t, tactics)

    def test_owner_is_critical(self):
        findings, _, _ = audit(load("vulnerable.json"), cloud="azure")
        owner = [f for f in findings if f["principal"]["name"] == "ops-lead"][0]
        self.assertEqual(owner["severity"], "critical")

    def test_clean_has_no_findings(self):
        _, summary, _ = audit(load("clean.json"), cloud="azure")
        self.assertEqual(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
