import unittest
from raqib.models import aws as model
from raqib.modules import aws_checks


def acct_from_user_policy(statements, groups=None, arn="arn:aws:iam::111122223333:user/u"):
    return model.load({"UserDetailList": [{"UserName": "u", "Arn": arn,
        "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": statements}}],
        "GroupList": groups or [], "AttachedManagedPolicies": []}]})


def rule_ids(findings):
    return [f["id"][0] for f in findings]  # first letter marks the family


def titles(findings):
    return [f["title"] for f in findings]


class TestAdmin(unittest.TestCase):
    def test_wildcard_admin_is_critical(self):
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "critical")

    def test_wildcard_admin_subsumes_the_narrow_paths(self):
        # a full admin should not also list every escalation path
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
        self.assertEqual(len([x for x in f if x["tactic"] == "privilege escalation"]), 1)

    def test_attached_admin_is_critical(self):
        acct = model.load({"UserDetailList": [{"UserName": "u", "Arn": "arn:aws:iam::1:user/u", "UserPolicyList": [],
            "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}]})
        f = aws_checks(acct)
        self.assertEqual(f[0]["severity"], "critical")
        self.assertIn("attached policy", f[0]["title"])


class TestPrivescPaths(unittest.TestCase):
    def test_create_policy_version(self):
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]))
        self.assertTrue(any("rewrite an attached policy" in t for t in titles(f)))
        self.assertEqual(f[0]["severity"], "high")

    def test_passrole_lambda_needs_all_three_actions(self):
        two = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction"], "Resource": "*"}]))
        self.assertFalse(any("Lambda function and run it" in t for t in titles(two)))
        three = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}]))
        self.assertTrue(any("Lambda function and run it" in t for t in titles(three)))

    def test_passrole_ec2_via_group(self):
        acct = model.load({
            "UserDetailList": [{"UserName": "u", "Arn": "arn:aws:iam::1:user/u", "GroupList": ["g"],
                "UserPolicyList": [], "AttachedManagedPolicies": []}],
            "GroupDetailList": [{"GroupName": "g", "GroupPolicyList": [{"PolicyName": "gp", "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": ["ec2:RunInstances", "iam:PassRole"], "Resource": "*"}]}}],
                "AttachedManagedPolicies": []}],
        })
        self.assertTrue(any("new EC2 instance" in t for t in titles(aws_checks(acct))))

    def test_iam_star_reported_once_not_as_every_path(self):
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]))
        privesc = [x for x in f if x["tactic"] == "privilege escalation"]
        # the service wildcard is the single privilege escalation signal, not a dozen paths
        self.assertEqual(len([x for x in f if "service wildcard" in x["title"]]), 1)
        self.assertLessEqual(len(privesc), 1)

    def test_resource_scoped_grant_is_medium(self):
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": "iam:UpdateLoginProfile", "Resource": "arn:aws:iam::1:user/other"}]))
        hit = [x for x in f if "console password" in x["title"]]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["severity"], "medium")

    def test_least_privilege_user_has_no_findings(self):
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}]))
        self.assertEqual(f, [])


class TestTrust(unittest.TestCase):
    def _role(self, trust):
        return model.load({"RoleDetailList": [{"RoleName": "r", "Arn": "arn:aws:iam::111122223333:role/r",
            "AssumeRolePolicyDocument": {"Statement": trust}, "RolePolicyList": [], "AttachedManagedPolicies": []}]})

    def test_public_role_is_critical(self):
        f = aws_checks(self._role([{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]))
        self.assertTrue(any("assumed by anyone" in t for t in titles(f)))
        self.assertEqual([x for x in f if "assumed by anyone" in x["title"]][0]["severity"], "critical")

    def test_cross_account_trust_is_flagged(self):
        f = aws_checks(self._role([{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]))
        self.assertTrue(any("external account" in t for t in titles(f)))

    def test_same_account_trust_is_not_flagged(self):
        f = aws_checks(self._role([{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:role/other"}, "Action": "sts:AssumeRole"}]))
        self.assertFalse(any("external account" in t for t in titles(f)))

    def test_service_trust_is_not_flagged(self):
        f = aws_checks(self._role([{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]))
        self.assertEqual(f, [])

    def test_federated_without_condition_is_flagged(self):
        f = aws_checks(self._role([{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::111122223333:saml-provider/x"}, "Action": "sts:AssumeRoleWithSAML"}]))
        self.assertTrue(any("Federated trust" in t for t in titles(f)))


class TestWildcards(unittest.TestCase):
    def test_iam_service_wildcard_is_high(self):
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]))
        hit = [x for x in f if "Full control of iam" in x["title"]]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["severity"], "high")

    def test_s3_service_wildcard_is_medium(self):
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]))
        hit = [x for x in f if "Full control of s3" in x["title"]]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["severity"], "medium")

    def test_non_sensitive_wildcard_is_ignored(self):
        f = aws_checks(acct_from_user_policy([{"Effect": "Allow", "Action": "cloudwatch:*", "Resource": "*"}]))
        self.assertEqual(f, [])


class TestOrdering(unittest.TestCase):
    def test_sorted_by_severity(self):
        acct = model.load({
            "UserDetailList": [
                {"UserName": "admin", "Arn": "arn:aws:iam::1:user/admin",
                 "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]},
                {"UserName": "esc", "Arn": "arn:aws:iam::1:user/esc",
                 "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]}}]},
            ]})
        f = aws_checks(acct)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sev = [order[x["severity"]] for x in f]
        self.assertEqual(sev, sorted(sev))


if __name__ == "__main__":
    unittest.main()
