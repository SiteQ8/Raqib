import unittest
import os
import json
from raqib import audit
from raqib.lib import report

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(*parts):
    with open(os.path.join(HERE, "samples", *parts), "r", encoding="utf-8") as fh:
        return json.load(fh)


class TestSamples(unittest.TestCase):
    def test_clean_sample_has_no_findings(self):
        findings, summary, acct = audit(load("aws", "clean.json"))
        self.assertEqual(summary["total"], 0)

    def test_vulnerable_sample_finds_the_expected_shape(self):
        findings, summary, acct = audit(load("aws", "vulnerable.json"))
        self.assertGreaterEqual(summary["counts"]["critical"], 3)
        self.assertGreaterEqual(summary["counts"]["high"], 4)
        found = {f["title"] for f in findings}
        self.assertTrue(any("assumed by anyone" in t for t in found))
        self.assertTrue(any("attached policy" in t for t in found))
        self.assertTrue(any("Lambda function" in t for t in found))

    def test_credential_report_adds_findings(self):
        with open(os.path.join(HERE, "samples", "aws", "credential-report.csv")) as fh:
            csv = fh.read()
        base, _, _ = audit(load("aws", "vulnerable.json"))
        enriched, summary, _ = audit(load("aws", "vulnerable.json"), credential_report_csv=csv)
        self.assertGreater(len(enriched), len(base))
        self.assertTrue(any("Root account" in f["title"] for f in enriched))


class TestReports(unittest.TestCase):
    def test_json_is_valid_and_complete(self):
        findings, summary, acct = audit(load("aws", "vulnerable.json"))
        out = report.as_json(findings, summary, {"title": "t", "source": "s"})
        parsed = json.loads(out)
        self.assertEqual(len(parsed["findings"]), summary["total"])
        self.assertIn("summary", parsed)

    def test_html_is_self_contained(self):
        findings, summary, acct = audit(load("aws", "vulnerable.json"))
        html = report.html_report(findings, summary, {"title": "t", "source": "s"})
        self.assertNotIn('src="http', html)
        self.assertNotIn('href="http', html)
        self.assertIn("Raqib", html)

    def test_html_escapes_content(self):
        findings = [{"id": "x", "severity": "high", "title": "a <script>", "principal": None,
                     "detail": "d & d", "fix": "f", "tactic": "exposure", "refs": []}]
        html = report.html_report(findings, {"counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "total": 1, "principals": 1, "principals_with_findings": 0}, {"title": "t"})
        self.assertNotIn("<script>", html.split("<style>")[1])
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
