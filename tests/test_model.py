import unittest
from raqib import model


class TestDocumentParsing(unittest.TestCase):
    def test_reads_a_decoded_document(self):
        acct = model.load({"UserDetailList": [{
            "UserName": "u", "Arn": "arn:aws:iam::1:user/u",
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}}],
        }]})
        p = acct.principals[0]
        self.assertTrue(acct.allows(p, "s3:GetObject"))

    def test_reads_a_url_encoded_document(self):
        acct = model.load({"UserDetailList": [{
            "UserName": "u", "Arn": "arn:aws:iam::1:user/u",
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument":
                "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D"}],
        }]})
        self.assertTrue(acct.allows(acct.principals[0], "s3:GetObject"))

    def test_single_action_becomes_a_list(self):
        acct = model.load({"UserDetailList": [{"UserName": "u", "Arn": "arn:aws:iam::1:user/u",
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {
                "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}}]}]})
        self.assertTrue(acct.allows(acct.principals[0], "s3:GetObject"))


class TestActionMatching(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(model._match("iam:passrole", "iam:PassRole"))
        self.assertFalse(model._match("iam:passrole", "iam:GetRole"))

    def test_full_star(self):
        self.assertTrue(model._match("*", "anything:AtAll"))

    def test_service_star(self):
        self.assertTrue(model._match("iam:*", "iam:CreateUser"))
        self.assertFalse(model._match("iam:*", "s3:GetObject"))

    def test_prefix_star(self):
        self.assertTrue(model._match("iam:Get*", "iam:GetRole"))
        self.assertFalse(model._match("iam:Get*", "iam:PutRolePolicy"))


class TestPermissionLogic(unittest.TestCase):
    def _acct(self, statements):
        return model.load({"UserDetailList": [{"UserName": "u", "Arn": "arn:aws:iam::1:user/u",
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": statements}}]}]})

    def test_wildcard_grants_specific_action(self):
        a = self._acct([{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}])
        self.assertTrue(a.allows(a.principals[0], "iam:CreatePolicyVersion"))

    def test_explicit_deny_overrides_allow(self):
        a = self._acct([
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:CreateUser", "Resource": "*"},
        ])
        self.assertFalse(a.allows(a.principals[0], "iam:CreateUser"))
        self.assertTrue(a.allows(a.principals[0], "s3:GetObject"))

    def test_require_unscoped_ignores_resource_scoped_grants(self):
        a = self._acct([{"Effect": "Allow", "Action": "iam:UpdateLoginProfile", "Resource": "arn:aws:iam::1:user/u"}])
        self.assertTrue(a.allows(a.principals[0], "iam:UpdateLoginProfile"))
        self.assertFalse(a.allows(a.principals[0], "iam:UpdateLoginProfile", require_unscoped=True))

    def test_not_action_allow_grants_everything_else(self):
        a = self._acct([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
        self.assertTrue(a.allows(a.principals[0], "s3:GetObject"))
        self.assertFalse(a.allows(a.principals[0], "iam:CreateUser"))

    def test_admin_statement_detects_star_star(self):
        a = self._acct([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        self.assertIsNotNone(a.admin_statement(a.principals[0]))


class TestGroupsAndManaged(unittest.TestCase):
    def test_group_policies_reach_the_user(self):
        acct = model.load({
            "UserDetailList": [{"UserName": "u", "Arn": "arn:aws:iam::1:user/u",
                "GroupList": ["g"], "UserPolicyList": [], "AttachedManagedPolicies": []}],
            "GroupDetailList": [{"GroupName": "g", "GroupPolicyList": [
                {"PolicyName": "gp", "PolicyDocument": {"Statement": [
                    {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]}}],
                "AttachedManagedPolicies": []}],
        })
        self.assertTrue(acct.allows(acct.principals[0], "ec2:RunInstances"))

    def test_attached_managed_policy_document_is_resolved(self):
        acct = model.load({
            "UserDetailList": [{"UserName": "u", "Arn": "arn:aws:iam::1:user/u", "UserPolicyList": [],
                "AttachedManagedPolicies": [{"PolicyName": "m", "PolicyArn": "arn:aws:iam::1:policy/m"}]}],
            "Policies": [{"PolicyName": "m", "Arn": "arn:aws:iam::1:policy/m", "DefaultVersionId": "v1",
                "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": {
                    "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]}}]}],
        })
        self.assertTrue(acct.allows(acct.principals[0], "lambda:InvokeFunction"))

    def test_attached_administrator_access_is_flagged(self):
        acct = model.load({"UserDetailList": [{"UserName": "u", "Arn": "arn:aws:iam::1:user/u", "UserPolicyList": [],
            "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}]})
        self.assertIn("AdministratorAccess", acct.principals[0].attached_admin)


if __name__ == "__main__":
    unittest.main()
