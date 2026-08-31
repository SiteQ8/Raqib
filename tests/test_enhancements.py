import unittest
from raqib import model, rules, report


def acct_user(statements, boundary_arn=None, policies=None, arn="arn:aws:iam::111122223333:user/u"):
    user = {"UserName": "u", "Arn": arn,
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": statements}}],
            "GroupList": [], "AttachedManagedPolicies": []}
    if boundary_arn:
        user["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": boundary_arn}
    raw = {"UserDetailList": [user]}
    if policies:
        raw["Policies"] = policies
    return model.load(raw)


def titles(findings):
    return [f["title"] for f in findings]


class TestLogTampering(unittest.TestCase):
    def test_stop_logging_is_flagged_high(self):
        f = rules.run(acct_user([{"Effect": "Allow", "Action": ["cloudtrail:StopLogging"], "Resource": "*"}]))
        hit = [x for x in f if "weaken the audit trail" in x["title"]]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["severity"], "high")
        self.assertEqual(hit[0]["technique"]["id"], "T1562.008")

    def test_scoped_tamper_is_medium(self):
        f = rules.run(acct_user([{"Effect": "Allow", "Action": ["guardduty:DeleteDetector"], "Resource": "arn:aws:guardduty:us-east-1:111122223333:detector/x"}]))
        hit = [x for x in f if "weaken the audit trail" in x["title"]]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["severity"], "medium")

    def test_admin_is_not_double_reported_for_tampering(self):
        f = rules.run(acct_user([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
        self.assertFalse(any("weaken the audit trail" in t for t in titles(f)))

    def test_multiple_capabilities_are_grouped(self):
        f = rules.run(acct_user([{"Effect": "Allow", "Action": ["cloudtrail:StopLogging", "config:StopConfigurationRecorder"], "Resource": "*"}]))
        hit = [x for x in f if "weaken the audit trail" in x["title"]]
        self.assertEqual(len(hit), 1)
        self.assertIn("Config", hit[0]["detail"])


class TestBoundaryAwareness(unittest.TestCase):
    BOUNDARY = [{"PolicyName": "s3only", "Arn": "arn:aws:iam::111122223333:policy/s3only",
                 "DefaultVersionId": "v1", "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
                 "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}]}]

    def test_boundary_downgrades_admin(self):
        f = rules.run(acct_user([{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                                 boundary_arn="arn:aws:iam::111122223333:policy/s3only", policies=self.BOUNDARY))
        admin = [x for x in f if "Administrator" in x["title"]][0]
        self.assertEqual(admin["severity"], "high")
        self.assertIn("permissions boundary", admin["detail"])

    def test_boundary_downgrades_a_path(self):
        f = rules.run(acct_user([{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}],
                                 boundary_arn="arn:aws:iam::111122223333:policy/s3only", policies=self.BOUNDARY))
        hit = [x for x in f if "rewrite an attached policy" in x["title"]][0]
        self.assertEqual(hit["severity"], "medium")  # lowered from high by the boundary

    def test_boundary_that_permits_does_not_downgrade(self):
        allow_iam = [{"PolicyName": "iamok", "Arn": "arn:aws:iam::111122223333:policy/iamok",
                      "DefaultVersionId": "v1", "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
                      "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}]
        f = rules.run(acct_user([{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}],
                                 boundary_arn="arn:aws:iam::111122223333:policy/iamok", policies=allow_iam))
        hit = [x for x in f if "rewrite an attached policy" in x["title"]][0]
        self.assertEqual(hit["severity"], "high")

    def test_boundary_not_in_export_is_not_assumed(self):
        # boundary arn set but no document present -> cannot claim it caps anything
        f = rules.run(acct_user([{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                                 boundary_arn="arn:aws:iam::111122223333:policy/unknown"))
        admin = [x for x in f if "Administrator" in x["title"]][0]
        self.assertEqual(admin["severity"], "critical")


class TestTechniques(unittest.TestCase):
    def test_every_finding_has_a_technique(self):
        f = rules.run(acct_user([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
        self.assertTrue(all(x.get("technique", {}).get("id") for x in f))

    def test_trust_maps_to_trusted_relationship(self):
        acct = model.load({"RoleDetailList": [{"RoleName": "r", "Arn": "arn:aws:iam::1:role/r",
            "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]},
            "RolePolicyList": [], "AttachedManagedPolicies": []}]})
        f = rules.run(acct)
        self.assertEqual(f[0]["technique"]["id"], "T1199")


class TestSarif(unittest.TestCase):
    def _findings(self):
        return rules.run(acct_user([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))

    def test_sarif_is_valid_2_1_0(self):
        import json
        out = report.sarif(self._findings(), {"source": "export.json"})
        d = json.loads(out)
        self.assertEqual(d["version"], "2.1.0")
        self.assertEqual(d["runs"][0]["tool"]["driver"]["name"], "Raqib")
        self.assertTrue(d["runs"][0]["results"])

    def test_sarif_levels_map_severity(self):
        import json
        d = json.loads(report.sarif(self._findings(), {"source": "x"}))
        self.assertEqual(d["runs"][0]["results"][0]["level"], "error")


class TestPersistenceCredentials(unittest.TestCase):
    def test_two_active_keys_flagged(self):
        from raqib import credentials
        import datetime
        header = ("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
                  "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
                  "access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
                  "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
                  "access_key_2_last_used_region,access_key_2_last_used_service")
        row = "dev,arn:aws:iam::1:user/dev,2022-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2025-08-01T00:00:00+00:00,N/A,N/A,N/A,true,2025-08-01T00:00:00+00:00,N/A,N/A,N/A"
        f = credentials.check(header + "\n" + row + "\n", now=datetime.datetime(2025, 8, 31))
        self.assertTrue(any("two active access keys" in x["title"] for x in f))


if __name__ == "__main__":
    unittest.main()
