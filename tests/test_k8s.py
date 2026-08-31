import os, json, unittest
from raqib import audit
from raqib.models import k8s

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(HERE, "samples", "k8s", name)) as fh:
        return json.load(fh)


class TestK8sModel(unittest.TestCase):
    def test_cluster_admin_detected(self):
        acct = k8s.load(load("vulnerable.json"))
        admins = [p for p in acct.principals if acct.is_cluster_admin(p)]
        self.assertTrue(admins)

    def test_namespaced_role_is_not_cluster_wide(self):
        acct = k8s.load(load("clean.json"))
        for p in acct.principals:
            self.assertFalse(acct.can(p, "get", "pods", cluster_wide_only=True))

    def test_secret_read_resolves(self):
        acct = k8s.load(load("vulnerable.json"))
        sa = [p for p in acct.principals if p.name == "audit-sa"][0]
        self.assertTrue(acct.can(sa, "get", "secrets", cluster_wide_only=True))


class TestK8sFindings(unittest.TestCase):
    def test_vulnerable_covers_all_tactics(self):
        findings, summary, _ = audit(load("vulnerable.json"))
        self.assertEqual(summary["cloud"], "k8s")
        tactics = {f["tactic"] for f in findings}
        for t in ["privilege escalation", "persistence", "lateral movement", "exfiltration", "defense evasion", "reconnaissance"]:
            self.assertIn(t, tactics)

    def test_cluster_admin_is_critical(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("cluster-admin" in f["title"] and f["severity"] == "critical" for f in findings))

    def test_escalate_and_bind_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        titles = " ".join(f["title"] for f in findings)
        self.assertIn("escalate", titles)
        self.assertIn("bind", titles)

    def test_workload_creation_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("create workloads that run pods" in f["title"] and f["severity"] == "high" for f in findings))

    def test_exec_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("exec into running pods" in f["title"] and f["severity"] == "high" for f in findings))

    def test_token_minting_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("mint tokens for service accounts" in f["title"] and f["severity"] == "high" for f in findings))

    def test_csr_self_approval_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("client certificates to authenticate as anyone" in f["title"] and f["severity"] == "high" for f in findings))

    def test_rolebindings_persistence_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("role bindings across namespaces" in f["title"] and f["tactic"] == "persistence" for f in findings))

    def test_serviceaccount_creation_persistence_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any(f["title"] == "Can create service accounts" and f["tactic"] == "persistence" for f in findings))

    def test_node_proxy_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("reach the kubelet on nodes" in f["title"] and f["severity"] == "high" for f in findings))

    def test_port_forward_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("port forward to pods" in f["title"] and f["severity"] == "medium" for f in findings))

    def test_pod_logs_exfil_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("read pod logs" in f["detail"] and f["tactic"] == "exfiltration" for f in findings))

    def test_read_rbac_recon_flagged(self):
        findings, _, _ = audit(load("vulnerable.json"))
        self.assertTrue(any("read the cluster RBAC" in f["title"] and f["tactic"] == "reconnaissance" for f in findings))

    def test_clean_has_no_findings(self):
        findings, summary, _ = audit(load("clean.json"))
        self.assertEqual(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
