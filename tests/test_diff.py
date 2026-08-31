"""The diff command scans two exports and reports findings that appeared or resolved.

These tests drive both the bash scanner (raqib.sh diff) and the Python engine
(python -m raqib diff) over the GCP samples and check the added, removed, and
unchanged counts. Diffing clean against vulnerable is all additions; the reverse is
all removals; a file against itself is all unchanged. The two engines must agree.
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


def gtotal(scenario):
    with open(os.path.join(HERE, "samples", "gcp", scenario + ".json")) as fh:
        return audit(json.load(fh))[1]["total"]


def _sample(name):
    return os.path.join(HERE, "samples", "gcp", name + ".json")


def bash_diff(a, b):
    out = subprocess.run(["bash", RAQIB_SH, "diff", _sample(a), _sample(b), "--cloud", "gcp", "--json"],
                         capture_output=True, text=True, env=dict(os.environ, NO_COLOR="1")).stdout
    return json.loads(out)


def py_diff(a, b):
    out = subprocess.run(["python3", "-m", "raqib", "diff", _sample(a), _sample(b), "--cloud", "gcp", "--json"],
                         capture_output=True, text=True, cwd=HERE).stdout
    return json.loads(out)


@unittest.skipUnless(HAVE_JQ, "jq is required for the bash scanner")
class TestBashDiff(unittest.TestCase):
    def test_all_added(self):
        d = bash_diff("clean", "vulnerable")
        self.assertEqual(len(d["added"]), gtotal("vulnerable"))
        self.assertEqual(len(d["removed"]), 0)

    def test_all_removed(self):
        d = bash_diff("vulnerable", "clean")
        self.assertEqual(len(d["removed"]), gtotal("vulnerable"))
        self.assertEqual(len(d["added"]), 0)

    def test_all_unchanged(self):
        d = bash_diff("vulnerable", "vulnerable")
        self.assertEqual(d["unchanged"], gtotal("vulnerable"))
        self.assertEqual(len(d["added"]), 0)
        self.assertEqual(len(d["removed"]), 0)


class TestPyDiff(unittest.TestCase):
    def test_all_added(self):
        d = py_diff("clean", "vulnerable")
        self.assertEqual(len(d["added"]), gtotal("vulnerable"))
        self.assertEqual(len(d["removed"]), 0)

    def test_all_removed(self):
        d = py_diff("vulnerable", "clean")
        self.assertEqual(len(d["removed"]), gtotal("vulnerable"))
        self.assertEqual(len(d["added"]), 0)

    @unittest.skipUnless(HAVE_JQ, "jq is required for the bash scanner")
    def test_python_matches_bash(self):
        b = bash_diff("clean", "vulnerable")
        p = py_diff("clean", "vulnerable")
        self.assertEqual(len(b["added"]), len(p["added"]))
        self.assertEqual(len(b["removed"]), len(p["removed"]))
        self.assertEqual(b["unchanged"], p["unchanged"])


if __name__ == "__main__":
    unittest.main()
