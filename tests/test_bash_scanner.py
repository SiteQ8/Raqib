"""The bash scanner must produce the same findings as the Python engine.

These tests drive raqib.sh in offline mode over each sample and compare the finding
count with what the audit() engine returns for the same export. They are skipped when
jq is not installed, since the bash scanner needs it. This locks the two paths together
so a change to one that drifts from the other is caught.
"""
import json
import os
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAQIB_SH = os.path.join(HERE, "raqib.sh")
HAVE_JQ = shutil.which("jq") is not None

from raqib import audit


def scan(cloud, scenario, extra=None):
    cmd = ["bash", RAQIB_SH, "scan", "--offline",
           os.path.join(HERE, "samples", cloud, scenario + ".json"),
           "--cloud", cloud, "--json"]
    if extra:
        cmd += extra
    env = dict(os.environ, NO_COLOR="1")
    out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout
    return json.loads(out)


def engine_total(cloud, scenario, credential_csv=None):
    with open(os.path.join(HERE, "samples", cloud, scenario + ".json")) as fh:
        export = json.load(fh)
    csv_text = None
    if credential_csv:
        with open(credential_csv) as fh:
            csv_text = fh.read()
    findings, summary, _ = audit(export, credential_report_csv=csv_text)
    return summary["total"]


@unittest.skipUnless(HAVE_JQ, "jq is required for the bash scanner")
class TestBashParity(unittest.TestCase):
    def test_each_cloud_vulnerable_matches_engine(self):
        for cloud in ["aws", "azure", "gcp", "k8s"]:
            with self.subTest(cloud=cloud):
                self.assertEqual(len(scan(cloud, "vulnerable")),
                                 engine_total(cloud, "vulnerable"),
                                 f"{cloud} vulnerable count drifted")

    def test_each_cloud_clean_is_empty(self):
        for cloud in ["aws", "azure", "gcp", "k8s"]:
            with self.subTest(cloud=cloud):
                self.assertEqual(len(scan(cloud, "clean")), 0, f"{cloud} clean should be empty")

    def test_aws_with_credential_report_matches_engine(self):
        csv = os.path.join(HERE, "samples", "aws", "credential-report.csv")
        bash_total = len(scan("aws", "vulnerable", ["--credential-report", csv]))
        self.assertEqual(bash_total, engine_total("aws", "vulnerable", credential_csv=csv))

    def test_max_key_age_drops_old_key_findings(self):
        csv = os.path.join(HERE, "samples", "aws", "credential-report.csv")
        strict_age = len(scan("aws", "vulnerable", ["--credential-report", csv, "--max-key-age", "5000"]))
        default_age = len(scan("aws", "vulnerable", ["--credential-report", csv]))
        self.assertLess(strict_age, default_age)

    def test_resource_policies_add_public_exposure(self):
        rp = os.path.join(HERE, "samples", "aws", "resource-policies.json")
        base = len(scan("aws", "vulnerable"))
        findings = scan("aws", "vulnerable", ["--resource-policies", rp])
        exposure = [f for f in findings if f["tactic"] == "public exposure"]
        self.assertEqual(len(exposure), 12)
        self.assertEqual(len(findings), base + 12)
        self.assertEqual(sorted(f["severity"] for f in exposure),
                         ["critical", "critical", "high", "high", "high", "high", "high", "high",
                          "medium", "medium", "medium", "medium"])
        titles = " ".join(f["title"] for f in exposure)
        self.assertIn("open to the public", titles)
        self.assertIn("grants another account access", titles)
        self.assertIn("Secret is readable by the public", titles)
        self.assertIn("Lambda function can be invoked by anyone", titles)
        self.assertIn("SQS queue is open to the public", titles)


if __name__ == "__main__":
    unittest.main()
