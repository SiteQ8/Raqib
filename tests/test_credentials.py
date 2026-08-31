import unittest
import datetime
from raqib import credentials

NOW = datetime.datetime(2025, 8, 31)
HEADER = ("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
          "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
          "access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
          "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
          "access_key_2_last_used_region,access_key_2_last_used_service")


def row(**kw):
    base = {"user": "u", "arn": "arn:aws:iam::1:user/u", "user_creation_time": "2022-01-01T00:00:00+00:00",
            "password_enabled": "false", "password_last_used": "N/A", "password_last_changed": "N/A",
            "password_next_rotation": "N/A", "mfa_active": "false", "access_key_1_active": "false",
            "access_key_1_last_rotated": "N/A", "access_key_1_last_used_date": "N/A",
            "access_key_1_last_used_region": "N/A", "access_key_1_last_used_service": "N/A",
            "access_key_2_active": "false", "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A",
            "access_key_2_last_used_region": "N/A", "access_key_2_last_used_service": "N/A"}
    base.update(kw)
    cols = HEADER.split(",")
    return HEADER + "\n" + ",".join(base[c] for c in cols) + "\n"


def titles(findings):
    return [f["title"] for f in findings]


class TestCredentials(unittest.TestCase):
    def test_stale_active_key_is_flagged(self):
        csv = row(access_key_1_active="true", access_key_1_last_rotated="2020-01-01T00:00:00+00:00")
        f = credentials.check(csv, max_key_age_days=90, now=NOW)
        self.assertTrue(any("old and still active" in t for t in titles(f)))

    def test_recent_key_is_not_flagged(self):
        csv = row(access_key_1_active="true", access_key_1_last_rotated="2025-08-01T00:00:00+00:00")
        f = credentials.check(csv, max_key_age_days=90, now=NOW)
        self.assertFalse(any("old and still active" in t for t in titles(f)))

    def test_inactive_key_is_ignored(self):
        csv = row(access_key_1_active="false", access_key_1_last_rotated="2019-01-01T00:00:00+00:00")
        f = credentials.check(csv, max_key_age_days=90, now=NOW)
        self.assertEqual(f, [])

    def test_console_user_without_mfa_is_high(self):
        csv = row(password_enabled="true", mfa_active="false")
        f = credentials.check(csv, now=NOW)
        hit = [x for x in f if "without multi factor" in x["title"]]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["severity"], "high")

    def test_console_user_with_mfa_is_fine(self):
        csv = row(password_enabled="true", mfa_active="true")
        f = credentials.check(csv, now=NOW)
        self.assertEqual(f, [])

    def test_root_active_key_is_critical(self):
        csv = row(user="<root_account>", access_key_1_active="true", access_key_1_last_rotated="2021-01-01T00:00:00+00:00")
        f = credentials.check(csv, now=NOW)
        self.assertTrue(any("Root account has an active access key" in t for t in titles(f)))
        self.assertEqual([x for x in f if "active access key" in x["title"]][0]["severity"], "critical")

    def test_root_without_mfa_is_critical(self):
        csv = row(user="<root_account>", mfa_active="false")
        f = credentials.check(csv, now=NOW)
        self.assertTrue(any("no multi factor" in t for t in titles(f)))


if __name__ == "__main__":
    unittest.main()
