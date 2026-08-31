import unittest
from raqib.lib import detect


class TestDetect(unittest.TestCase):
    def test_aws(self):
        self.assertEqual(detect.detect_cloud({"UserDetailList": []}), "aws")

    def test_azure(self):
        self.assertEqual(detect.detect_cloud({"roleAssignments": [], "roleDefinitions": []}), "azure")

    def test_gcp(self):
        self.assertEqual(detect.detect_cloud({"bindings": []}), "gcp")

    def test_k8s(self):
        self.assertEqual(detect.detect_cloud({"items": [{"kind": "ClusterRole"}]}), "k8s")

    def test_unknown(self):
        self.assertIsNone(detect.detect_cloud({"something": 1}))


if __name__ == "__main__":
    unittest.main()
