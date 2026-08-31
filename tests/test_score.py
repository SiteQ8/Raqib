"""The score command rates a scan and ranks what to fix first.

The bash scanner and the Python engine must produce the same score, grade, and
severity counts for a given export, since both read the same findings. These tests
drive both and compare, and check the score stays in range and the top list is
ranked by severity.
"""
import json
import os
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAQIB_SH = os.path.join(HERE, "raqib.sh")
HAVE_JQ = shutil.which("jq") is not None

from raqib.__main__ import compute_score
from raqib import audit


def _sample(cloud):
    return os.path.join(HERE, "samples", cloud, "vulnerable.json")


def py_score(cloud):
    findings, _, _ = audit(json.load(open(_sample(cloud))), cloud=cloud)
    return compute_score(findings)


def bash_score(cloud):
    out = subprocess.run(["bash", RAQIB_SH, "score", "--offline", _sample(cloud), "--cloud", cloud, "--json"],
                         capture_output=True, text=True, env=dict(os.environ, NO_COLOR="1")).stdout
    return json.loads(out)


class TestScore(unittest.TestCase):
    def test_score_in_range_and_ranked(self):
        for cloud in ["aws", "azure", "gcp", "k8s"]:
            with self.subTest(cloud=cloud):
                s = py_score(cloud)
                self.assertTrue(0 <= s["score"] <= 100)
                self.assertIn(s["grade"], ["A", "B", "C", "D", "F"])
                order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                worsts = [order[t["worst"]] for t in s["top"]]
                self.assertEqual(worsts, sorted(worsts), "top principals not ranked by severity")

    def test_clean_scores_full(self):
        findings, _, _ = audit(json.load(open(os.path.join(HERE, "samples", "aws", "clean.json"))), cloud="aws")
        s = compute_score(findings)
        self.assertEqual(s["score"], 100)
        self.assertEqual(s["grade"], "A")

    @unittest.skipUnless(HAVE_JQ, "jq is required for the bash scanner")
    def test_bash_and_python_score_agree(self):
        for cloud in ["aws", "azure", "gcp", "k8s"]:
            with self.subTest(cloud=cloud):
                b = bash_score(cloud)
                p = py_score(cloud)
                self.assertEqual(b["score"], p["score"])
                self.assertEqual(b["grade"], p["grade"])
                self.assertEqual(b["counts"], p["counts"])
                self.assertEqual(b["total"], p["total"])


if __name__ == "__main__":
    unittest.main()
