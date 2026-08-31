import unittest
from raqib.models import aws as model
from raqib.modules import recon_aws as recon, exfil_aws as exfil, persist_aws as persist


def acct_user(statements, arn="arn:aws:iam::111122223333:user/u"):
    return model.load({"UserDetailList": [{"UserName": "u", "Arn": arn,
        "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": statements}}],
        "GroupList": [], "AttachedManagedPolicies": []}]})


def titles(findings):
    return [f["title"] for f in findings]


class TestRecon(unittest.TestCase):
    def test_authorization_details_export_is_flagged(self):
        f = recon.check_reconnaissance(acct_user([{"Effect": "Allow", "Action": "iam:GetAccountAuthorizationDetails", "Resource": "*"}]))
        self.assertTrue(any("export the entire IAM configuration" in t for t in titles(f)))
        self.assertEqual(f[0]["severity"], "medium")

    def test_broad_enumeration_is_low(self):
        f = recon.check_reconnaissance(acct_user([{"Effect": "Allow", "Action": ["iam:ListUsers", "iam:ListRoles", "iam:ListPolicies"], "Resource": "*"}]))
        self.assertTrue(any("enumerate identities" in t for t in titles(f)))
        self.assertEqual(f[0]["severity"], "low")

    def test_admin_is_not_recon_flagged(self):
        f = recon.check_reconnaissance(acct_user([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
        self.assertEqual(f, [])

    def test_narrow_read_is_not_flagged(self):
        f = recon.check_reconnaissance(acct_user([{"Effect": "Allow", "Action": "iam:GetUser", "Resource": "arn:aws:iam::111122223333:user/u"}]))
        self.assertEqual(f, [])


class TestExfil(unittest.TestCase):
    def test_read_all_secrets_is_high(self):
        f = exfil.check_exfiltration(acct_user([{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]))
        self.assertTrue(any("read or move data broadly" in t for t in titles(f)))
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["technique"]["id"] if "technique" in f[0] else None, None)  # technique applied later by run

    def test_scoped_read_is_not_flagged(self):
        f = exfil.check_exfiltration(acct_user([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]))
        self.assertEqual(f, [])

    def test_kms_decrypt_all_is_medium(self):
        f = exfil.check_exfiltration(acct_user([{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]))
        self.assertEqual(f[0]["severity"], "medium")

    def test_snapshot_sharing_is_flagged(self):
        f = exfil.check_exfiltration(acct_user([{"Effect": "Allow", "Action": "ec2:ModifySnapshotAttribute", "Resource": "*"}]))
        self.assertTrue(any("read or move data broadly" in t for t in titles(f)))

    def test_service_wildcard_is_left_to_its_own_finding(self):
        f = exfil.check_exfiltration(acct_user([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]))
        self.assertEqual(f, [])  # full control of s3 is reported by the wildcard check


class TestPersist(unittest.TestCase):
    def test_create_user_with_grant_is_high(self):
        f = persist.check_persistence(acct_user([{"Effect": "Allow", "Action": ["iam:CreateUser", "iam:CreateAccessKey"], "Resource": "*"}]))
        self.assertTrue(any("back door user" in t for t in titles(f)))
        self.assertEqual([x for x in f if "back door user" in x["title"]][0]["severity"], "high")

    def test_create_user_alone_is_medium(self):
        f = persist.check_persistence(acct_user([{"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"}]))
        self.assertTrue(any("Can create IAM users" in t for t in titles(f)))
        self.assertEqual(f[0]["severity"], "medium")

    def test_create_role_with_grant_is_flagged(self):
        f = persist.check_persistence(acct_user([{"Effect": "Allow", "Action": ["iam:CreateRole", "iam:AttachRolePolicy"], "Resource": "*"}]))
        self.assertTrue(any("create a role and grant" in t for t in titles(f)))

    def test_admin_is_not_persist_flagged(self):
        f = persist.check_persistence(acct_user([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
        self.assertEqual(f, [])


class TestAllSixTacticsPresent(unittest.TestCase):
    def test_the_vulnerable_sample_exercises_every_tactic(self):
        import os, json
        from raqib import audit
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        findings, _, _ = audit(json.load(open(os.path.join(here, "samples", "aws", "vulnerable.json"))))
        tactics = {f["tactic"] for f in findings}
        for expected in ["reconnaissance", "privilege escalation", "persistence", "lateral movement", "exfiltration", "defense evasion"]:
            self.assertIn(expected, tactics)


if __name__ == "__main__":
    unittest.main()
